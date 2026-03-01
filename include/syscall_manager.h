#pragma once

// ============================================================================
// Syscall Manager - Indirect Syscall Execution
// ============================================================================
// Harvests legitimate "syscall; ret" gadgets from ntdll .text section,
// quality-scores them, and provides random rotation for each call (hardening).
//
// Combined with Tartarus Gate SSNs, this enables fully indirect syscalls:
//   1. Tartarus provides the SSN (mov eax, SSN)
//   2. SyscallManager provides the trampoline (jmp to syscall;ret gadget)
//   3. DoSyscall ASM stub wires it all together
//
// The call stack shows the return address inside ntdll .text (legitimate),
// not inside our module — reduces stack-inspection surface (source protection).
// ============================================================================

#include <windows.h>
#include <stdint.h>

// ============================================================================
// ASM Stub (implemented in syscall_stub.asm)
// ============================================================================

extern "C" {
    // Indirect syscall: shuffles args, sets EAX=SSN, jumps to trampoline
    //   RCX = syscall number (SSN)
    //   RDX = trampoline address (points to "syscall; ret" in ntdll)
    //   R8  = 1st actual NT arg
    //   R9  = 2nd actual NT arg
    //   [rsp+28h]... = remaining NT args
    NTSTATUS DoSyscall(DWORD SyscallNumber, PVOID Trampoline, ...);
}

namespace SyscallManager {

    // Result of initialization
    struct InitResult {
        bool Success;
        int  TotalGadgets;      // Total syscall;ret gadgets found
        int  QualityGadgets;    // Gadgets that passed quality scoring
    };

    // ========================================================================
    // Core API
    // ========================================================================

    // Scan ntdll .text for syscall;ret gadgets, score and rank them.
    // Call once after Tartarus::Initialize().
    InitResult Initialize();

    // Get a random high-quality trampoline address.
    // Rotates selection each call for unpredictability.
    // Returns nullptr if not initialized or no gadgets available.
    PVOID GetRandomTrampoline();

    // Get total number of available trampolines.
    int GetTrampolineCount();

    // Shutdown: zero all trampoline data and PRNG state.
    void Shutdown();

} // namespace SyscallManager
