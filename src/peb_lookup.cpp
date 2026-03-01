// ============================================================================
// PEB-Based Module and Function Resolution - Implementation
// ============================================================================
// v2: Module cache (1.1), forwarded export resolution (1.2),
//     export cache (1.3). No STL, no CRT heap.
// ============================================================================

#include "peb_lookup.h"
#include "nt_types.h"
#include "hashing.h"
#include "config.h"
#include <intrin.h>

namespace Resolver {

    // ========================================================================
    // Module Cache (1.1) — avoids repeated PEB walks
    // ========================================================================

    struct ModuleCacheEntry {
        uint32_t Hash;
        HMODULE  Handle;
    };

    static ModuleCacheEntry s_ModuleCache[16];
    static int s_ModuleCacheCount = 0;

    // ========================================================================
    // Export Cache (1.3) — avoids repeated EAT walks
    // ========================================================================

    struct ExportCacheEntry {
        uint32_t ModuleHash;
        uint32_t ExportHash;
        PVOID    Address;
    };

    static ExportCacheEntry s_ExportCache[64];
    static int s_ExportCacheCount = 0;

    // ========================================================================
    // Internal: resolve export with forwarding support (1.2)
    // ========================================================================

    static PVOID ResolveExportInternal(HMODULE hModule, uint32_t exportHash, int depth);

    // ========================================================================
    // GetModuleByHash - Walk PEB to find module by name hash
    // ========================================================================

    HMODULE GetModuleByHash(uint32_t moduleHash) {
        // Check cache first
        for (int i = 0; i < s_ModuleCacheCount; i++) {
            if (s_ModuleCache[i].Hash == moduleHash) {
                return s_ModuleCache[i].Handle;
            }
        }

        // Cache miss — walk PEB
        PMY_PEB pPeb = (PMY_PEB)__readgsqword(0x60);
        if (!pPeb || !pPeb->Ldr) return nullptr;

        PLIST_ENTRY pListHead = &pPeb->Ldr->InMemoryOrderModuleList;
        PLIST_ENTRY pListEntry = pListHead->Flink;

        while (pListEntry != pListHead) {
            PMY_LDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
                pListEntry, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            if (pEntry->BaseDllName.Buffer && pEntry->BaseDllName.Length > 0) {
                size_t nameLen = pEntry->BaseDllName.Length / sizeof(wchar_t);
                uint32_t hash = Hash::RuntimeHashW(pEntry->BaseDllName.Buffer, nameLen);

                if (hash == moduleHash) {
                    HMODULE hMod = (HMODULE)pEntry->DllBase;
                    LOG("Found module: %p (hash: 0x%08X)", hMod, moduleHash);

                    // Insert into cache
                    if (s_ModuleCacheCount < 16) {
                        s_ModuleCache[s_ModuleCacheCount].Hash = moduleHash;
                        s_ModuleCache[s_ModuleCacheCount].Handle = hMod;
                        s_ModuleCacheCount++;
                    }

                    return hMod;
                }
            }

            pListEntry = pListEntry->Flink;
        }

        LOG_ERROR("Module not found (hash: 0x%08X)", moduleHash);
        return nullptr;
    }

    // ========================================================================
    // GetExportByHash - Walk export table with forwarding + caching
    // ========================================================================

    PVOID GetExportByHash(HMODULE hModule, uint32_t exportHash) {
        if (!hModule) return nullptr;

        // Compute a module hash for cache lookup by scanning the module cache
        // (we need the module hash for the export cache key)
        uint32_t modHash = 0;
        for (int i = 0; i < s_ModuleCacheCount; i++) {
            if (s_ModuleCache[i].Handle == hModule) {
                modHash = s_ModuleCache[i].Hash;
                break;
            }
        }

        // Check export cache
        if (modHash != 0) {
            for (int i = 0; i < s_ExportCacheCount; i++) {
                if (s_ExportCache[i].ModuleHash == modHash &&
                    s_ExportCache[i].ExportHash == exportHash) {
                    return s_ExportCache[i].Address;
                }
            }
        }

        // Cache miss — resolve with forwarding support
        PVOID result = ResolveExportInternal(hModule, exportHash, 0);

        // Insert into export cache
        if (result && modHash != 0 && s_ExportCacheCount < 64) {
            s_ExportCache[s_ExportCacheCount].ModuleHash = modHash;
            s_ExportCache[s_ExportCacheCount].ExportHash = exportHash;
            s_ExportCache[s_ExportCacheCount].Address = result;
            s_ExportCacheCount++;
        }

        return result;
    }

    // ========================================================================
    // Internal: resolve export with forwarded export chain following (1.2)
    // ========================================================================

    static PVOID ResolveExportInternal(HMODULE hModule, uint32_t exportHash, int depth) {
        if (depth > 3) {
            LOG_ERROR("Export forwarding depth exceeded (>3)");
            return nullptr;
        }

        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        DWORD exportRva  = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DWORD exportSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (exportRva == 0) return nullptr;

        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportRva);
        PDWORD pNames     = (PDWORD)((BYTE*)hModule + pExport->AddressOfNames);
        PWORD  pOrdinals  = (PWORD)((BYTE*)hModule + pExport->AddressOfNameOrdinals);
        PDWORD pFunctions = (PDWORD)((BYTE*)hModule + pExport->AddressOfFunctions);

        ULONG_PTR exportStart = (ULONG_PTR)hModule + exportRva;
        ULONG_PTR exportEnd   = exportStart + exportSize;

        for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
            const char* szName = (const char*)((BYTE*)hModule + pNames[i]);
            uint32_t hash = Hash::RuntimeHashA(szName);

            if (hash != exportHash) continue;

            WORD ordinal = pOrdinals[i];
            DWORD funcRva = pFunctions[ordinal];
            PVOID funcAddr = (PVOID)((BYTE*)hModule + funcRva);

            // Check for forwarded export
            if ((ULONG_PTR)funcAddr >= exportStart && (ULONG_PTR)funcAddr < exportEnd) {
                // Forwarder string: "MODULE.ExportName" or "MODULE.#Ordinal"
                const char* fwd = (const char*)funcAddr;

                // Find the dot separator
                int dotPos = -1;
                for (int k = 0; fwd[k] != '\0' && k < 256; k++) {
                    if (fwd[k] == '.') { dotPos = k; break; }
                }
                if (dotPos <= 0) {
                    LOG_ERROR("Malformed forwarder string for %s", szName);
                    return nullptr;
                }

                // Build wide module name for hashing (append .dll)
                wchar_t modName[128];
                int mi = 0;
                for (int k = 0; k < dotPos && mi < 120; k++) {
                    modName[mi++] = (wchar_t)fwd[k];
                }
                modName[mi++] = L'.'; modName[mi++] = L'd';
                modName[mi++] = L'l'; modName[mi++] = L'l';
                modName[mi] = L'\0';

                uint32_t targetModHash = Hash::RuntimeHashW(modName);
                uint32_t targetExpHash = Hash::RuntimeHashA(&fwd[dotPos + 1]);

                HMODULE hTarget = GetModuleByHash(targetModHash);
                if (!hTarget) {
                    LOG_ERROR("Forwarded module not loaded: %s (from %s)", fwd, szName);
                    return nullptr;
                }

                LOG("Following forwarder: %s -> %s", szName, fwd);
                return ResolveExportInternal(hTarget, targetExpHash, depth + 1);
            }

            LOG("Found export: %s @ %p (hash: 0x%08X)", szName, funcAddr, exportHash);
            return funcAddr;
        }

        LOG_ERROR("Export not found (hash: 0x%08X)", exportHash);
        return nullptr;
    }

} // namespace Resolver
