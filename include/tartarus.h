#pragma once

// ============================================================================
// Tartarus Gate - Syscall Service Number Extraction
// ============================================================================
// Extracts SSNs directly from in-memory ntdll.dll syscall stubs.
// No disk reads, no file mapping — works entirely from the PEB-located
// ntdll image that's already mapped into every Windows process.
//
// Hook detection strategy (Tartarus Gate):
//   1. Check if stub starts with the expected mov r10, rcx; mov eax, SSN
//   2. If hooked (JMP/CALL at stub start), walk to neighbor stubs ±N
//   3. If neighbor is clean, derive our SSN from theirs (SSN ± offset)
//   4. Keep walking until a clean neighbor is found or max distance hit
//
// Resolves SSNs even when stubs are hooked (e.g. by runtime inspection) because:
//   - Hooks rarely cover all stubs (cost)
//   - Adjacent stubs have sequential SSNs (SSN[i+1] = SSN[i] + 1)
//   - We can reconstruct any hooked SSN from a clean neighbor
// ============================================================================

#include <windows.h>
#include <stdint.h>

namespace Tartarus {

    // SSN entry: maps an API name hash to its syscall number + stub address
    struct SyscallEntry {
        uint32_t Hash;              // DJB2 hash of the export name
        DWORD    Ssn;               // Syscall Service Number
        PVOID    StubAddress;       // Address of the stub in ntdll .text
        bool     WasHooked;         // True if SSN was derived from a neighbor
    };

    // Result of the initialization
    struct InitResult {
        bool     Success;
        int      TotalExtracted;    // Number of SSNs successfully extracted
        int      HookedStubs;       // Number of stubs that were hooked (SSN derived from neighbor)
        int      FailedStubs;       // Number of stubs where SSN could not be determined
    };

    // ========================================================================
    // Core API
    // ========================================================================

    // Initialize: scan ntdll exports, extract SSNs, build the syscall map.
    // Call once at startup. Returns detailed result.
    InitResult Initialize();

    // Look up an SSN by API name hash.
    // Returns nullptr if the hash wasn't found in the map.
    const SyscallEntry* GetSyscall(uint32_t apiHash);

    // Get the total number of extracted syscalls.
    int GetSyscallCount();

    // Shutdown: zero all syscall entries and reset state.
    // Call during cleanup before process exit.
    void Shutdown();

} // namespace Tartarus
