#pragma once

// ============================================================================
// PEB-Based Module and Function Resolution
// ============================================================================
// Stealth resolution of modules and exports without using GetModuleHandle
// or GetProcAddress, avoiding IAT entries and API monitoring.

#include <windows.h>
#include <stdint.h>

namespace Resolver {

    // ========================================================================
    // Module Resolution
    // ========================================================================
    
    // Get module handle by hash (walks PEB InMemoryOrderModuleList)
    // Returns nullptr if module not found
    HMODULE GetModuleByHash(uint32_t moduleHash);
    
    // ========================================================================
    // Export Resolution
    // ========================================================================
    
    // Get export address by hash (walks module export table)
    // Returns nullptr if export not found
    PVOID GetExportByHash(HMODULE hModule, uint32_t exportHash);
    
    // ========================================================================
    // Convenience Functions
    // ========================================================================
    
    // Combined: resolve module then export in one call
    // Returns nullptr if either lookup fails
    inline PVOID ResolveAPI(uint32_t moduleHash, uint32_t exportHash) {
        HMODULE hModule = GetModuleByHash(moduleHash);
        if (!hModule) return nullptr;
        return GetExportByHash(hModule, exportHash);
    }

} // namespace Resolver
