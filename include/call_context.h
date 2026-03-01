#pragma once

// ============================================================================
// Call-Context Hardening
// ============================================================================
// Multi-layer call-context hardening for syscall return frames:
//
// 1. Return Address Harvesting: scans .text sections of system DLLs for
//    post-CALL instruction addresses (E8/FF15 + 5/6 bytes). These are
//    legitimate return addresses that stack walkers expect to see.
//
// 2. Thread Context: obtains CONTEXT from a sibling thread (or cross-process
//    from a system process). The non-volatile registers (RBP, RBX, etc.)
//    make the synthetic frame look like a real suspended thread.
//
// 3. CET/HSP Detection: checks for Intel CET shadow stack enforcement.
//    If active, synthesizes .pdata entries via RtlAddFunctionTable so
//    the Windows unwinder treats our frames as legitimate.
//
// 4. VEH Handler: registered via runtime-resolved RtlAddVectoredExceptionHandler.
//    On exception, overlays stored context onto the faulting thread.
//
// The DoSyscallSpoofed ASM stub builds a synthetic RBP frame using
// g_spoof_ret (harvested return address) and optionally g_proxy_frame
// (for CET shadow stack synchronization).
// ============================================================================

#include <windows.h>
#include <stdint.h>

// ============================================================================
// ASM Stub (implemented in syscall_stub.asm)
// ============================================================================

extern "C" {
    // Indirect syscall with synthetic RBP frame (call-context hardening)
    //   RCX = syscall number (SSN)
    //   RDX = trampoline address
    //   R8  = 1st actual NT arg
    //   R9  = 2nd actual NT arg
    //   [rsp+28h]... = remaining NT args
    NTSTATUS DoSyscallSpoofed(DWORD SyscallNumber, PVOID Trampoline, ...);
}

namespace CallContext {

    // Active protocol
    enum Protocol {
        PROTOCOL_VEH_FALLBACK,      // Standard VEH-based RBP frame
        PROTOCOL_SDIE_CET           // CET-aware with .pdata synthesis
    };

    // Initialization result
    struct InitResult {
        bool     Success;
        Protocol ActiveProtocol;
        int      ReturnAddresses;   // Number of harvested return addresses
        bool     ContextStolen;     // Whether thread context was obtained
        bool     CetDetected;       // Whether CET/HSP is active
    };

    // ========================================================================
    // Core API
    // ========================================================================

    // Initialize: harvest return addresses, obtain context, detect CET, register VEH.
    // Call once after SyscallManager::Initialize().
    InitResult Initialize();

    // Get a random legitimate return address for call-context hardening.
    PVOID GetLegitimateReturnAddress();

    // Check if CET hardware stack protection is active.
    bool IsCetActive();

    // Get the active protocol.
    Protocol GetActiveProtocol();

    // Shutdown: remove VEH handler, zero all sensitive state.
    void Shutdown();

    // ========================================================================
    // ASM Stub Globals (set before each indirect syscall)
    // ========================================================================
    // Process-global. Current design is single-threaded.

    extern "C" extern PVOID g_spoof_ret;

    extern "C" extern PVOID g_proxy_frame;

} // namespace CallContext
