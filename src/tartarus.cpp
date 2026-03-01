// ============================================================================
// Tartarus Gate - SSN Extraction from In-Memory ntdll
// ============================================================================
// Extracts syscall service numbers directly from the ntdll image already
// mapped into the process address space (via PEB). No disk reads.
//
// Hook detection: if a stub starts with JMP (0xE9) or JMP [rip] (0xFF 25)
// instead of the expected mov r10, rcx (0x4C 0x8B 0xD1), it's hooked.
// We walk neighbor stubs ±N to find a clean one and derive the SSN.
// ============================================================================

#include "tartarus.h"
#include "peb_lookup.h"
#include "hashing.h"
#include "nt_types.h"
#include "config.h"

#include <intrin.h>

namespace Tartarus {

    // ========================================================================
    // Constants
    // ========================================================================

    static constexpr int MAX_SYSCALLS           = 1024;  // ntdll has ~470 Zw + ~470 Nt exports
    static constexpr int MAX_NEIGHBOR_DISTANCE  = 32;    // max stubs to walk when resolving hooked SSN
    static constexpr int SYSCALL_STUB_SIZE      = 32;    // approximate size of a syscall stub

    // x64 syscall stub signature:
    //   4C 8B D1        mov r10, rcx
    //   B8 xx xx 00 00  mov eax, <SSN>
    static constexpr BYTE STUB_MOV_R10_RCX[] = { 0x4C, 0x8B, 0xD1 };
    static constexpr BYTE STUB_MOV_EAX       = 0xB8;

    // Hook signatures (inline hooks on syscall stubs)
    static constexpr BYTE HOOK_JMP_REL32     = 0xE9;       // jmp rel32
    static constexpr BYTE HOOK_JMP_RIP_0     = 0xFF;       // ff 25 = jmp [rip+disp32]
    static constexpr BYTE HOOK_JMP_RIP_1     = 0x25;

    // ========================================================================
    // Internal State
    // ========================================================================

    // Unsorted collection phase: we collect stubs here first
    struct RawStubEntry {
        uint32_t Hash;
        PVOID    StubAddress;
        DWORD    Ssn;           // 0xFFFFFFFF if hooked (needs resolution)
        bool     IsHooked;
        int      SortOrder;     // position in the sorted-by-address array
    };

    static SyscallEntry s_Syscalls[MAX_SYSCALLS];
    static int          s_SyscallCount = 0;
    static bool         s_Initialized  = false;

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    // Check if a stub address looks like a clean (unhooked) syscall stub
    static bool IsCleanStub(const BYTE* stub) {
        // Clean stub starts with: 4C 8B D1 B8 xx xx 00 00
        return (stub[0] == STUB_MOV_R10_RCX[0] &&
                stub[1] == STUB_MOV_R10_RCX[1] &&
                stub[2] == STUB_MOV_R10_RCX[2] &&
                stub[3] == STUB_MOV_EAX);
    }

    // Check if a stub has been hooked (JMP at the start)
    // Used during second-pass detection of hooked stubs within the stub region
    static bool IsHookedStub(const BYTE* stub) {
        // jmp rel32
        if (stub[0] == HOOK_JMP_REL32) return true;
        // jmp [rip+disp32]
        if (stub[0] == HOOK_JMP_RIP_0 && stub[1] == HOOK_JMP_RIP_1) return true;
        // Some EDRs use mov rax, addr; jmp rax (48 B8 ... FF E0)
        if (stub[0] == 0x48 && stub[1] == 0xB8) return true;
        return false;
    }

    // Extract SSN from a clean stub (bytes 4-7 after mov r10, rcx; mov eax, SSN)
    static DWORD ExtractSsnFromCleanStub(const BYTE* stub) {
        // stub[3] = 0xB8, stub[4..7] = SSN (little-endian DWORD)
        return *(DWORD*)(stub + 4);
    }

    // ========================================================================
    // Sorting: sort stubs by address (for SSN extraction) or by hash (for lookup)
    // ========================================================================

    static void SortStubsByAddress(RawStubEntry* entries, int count) {
        // Simple insertion sort — we're sorting ~470 entries, no need for qsort overhead
        for (int i = 1; i < count; i++) {
            RawStubEntry key = entries[i];
            int j = i - 1;
            while (j >= 0 && (ULONG_PTR)entries[j].StubAddress > (ULONG_PTR)key.StubAddress) {
                entries[j + 1] = entries[j];
                j--;
            }
            entries[j + 1] = key;
        }
    }

    static void SortSyscallsByHash(SyscallEntry* entries, int count) {
        for (int i = 1; i < count; i++) {
            SyscallEntry key = entries[i];
            int j = i - 1;
            while (j >= 0 && entries[j].Hash > key.Hash) {
                entries[j + 1] = entries[j];
                j--;
            }
            entries[j + 1] = key;
        }
    }

    // ========================================================================
    // Core: Initialize
    // ========================================================================

    InitResult Initialize() {
        InitResult result = { false, 0, 0, 0 };

        if (s_Initialized) {
            result.Success = true;
            result.TotalExtracted = s_SyscallCount;
            return result;
        }

        // Step 1: Get ntdll base from PEB
        HMODULE hNtdll = Resolver::GetModuleByHash(HASH_MODULE(L"ntdll.dll"));
        if (!hNtdll) {
            LOG_ERROR("Tartarus: Failed to locate ntdll via PEB");
            return result;
        }

        LOG("Tartarus: ntdll base = %p", hNtdll);

        // Step 2: Parse ntdll PE headers to get export directory
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
            LOG_ERROR("Tartarus: Invalid DOS signature");
            return result;
        }

        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) {
            LOG_ERROR("Tartarus: Invalid NT signature");
            return result;
        }

        DWORD exportRva  = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (exportRva == 0) {
            LOG_ERROR("Tartarus: No export directory in ntdll");
            return result;
        }

        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hNtdll + exportRva);

        PDWORD pNames     = (PDWORD)((BYTE*)hNtdll + pExport->AddressOfNames);
        PWORD  pOrdinals  = (PWORD)((BYTE*)hNtdll + pExport->AddressOfNameOrdinals);
        PDWORD pFunctions = (PDWORD)((BYTE*)hNtdll + pExport->AddressOfFunctions);

        // Step 3: Collect all Zw* exports (Zw and Nt share the same stub, but Zw
        // names sort alphabetically in a way that matches SSN order on most builds)
        // We use Zw* because their sorted order correlates with SSN assignment.
        // We also collect Nt* to build the hash map for lookups.

        // Temporary buffer for raw stub collection
        static RawStubEntry rawStubs[MAX_SYSCALLS];
        int rawCount = 0;

        for (DWORD i = 0; i < pExport->NumberOfNames && rawCount < MAX_SYSCALLS; i++) {
            const char* szName = (const char*)((BYTE*)hNtdll + pNames[i]);

            // We want both Nt* and Zw* syscall stubs
            bool isNt = (szName[0] == 'N' && szName[1] == 't');
            bool isZw = (szName[0] == 'Z' && szName[1] == 'w');

            if (!isNt && !isZw) continue;

            // Filter out non-syscall Nt-prefixed functions:
            // "Ntdll*" (NtdllDefWindowProc_A, etc.) are regular functions, not syscalls
            if (szName[0] == 'N' && szName[1] == 't' && szName[2] == 'd' && szName[3] == 'l' && szName[4] == 'l') {
                continue;
            }

            WORD ordinal = pOrdinals[i];
            DWORD funcRva = pFunctions[ordinal];
            BYTE* pStub = (BYTE*)hNtdll + funcRva;

            // Only accept stubs that match the clean syscall pattern.
            // We do NOT blindly accept "hooked-looking" stubs because many
            // Nt* exports (NtGetTickCount, NtQuerySystemTime, etc.) are
            // inlined wrapper functions that naturally start with JMP or
            // other non-syscall opcodes. Including them would corrupt the
            // SSN sequence.
            //
            // For hooked stubs: the hook replaces the first bytes
            // of a real syscall stub. We detect these in a second pass by
            // checking if a stub address falls within the contiguous syscall
            // stub region but doesn't match the clean pattern.
            if (!IsCleanStub(pStub)) {
                continue;  // First pass: only collect clean stubs
            }

            uint32_t hash = Hash::RuntimeHashA(szName);

            rawStubs[rawCount].Hash        = hash;
            rawStubs[rawCount].StubAddress  = pStub;
            rawStubs[rawCount].IsHooked     = false;
            rawStubs[rawCount].SortOrder    = 0;
            rawStubs[rawCount].Ssn          = ExtractSsnFromCleanStub(pStub);

            rawCount++;
        }

        LOG("Tartarus: Found %d clean syscall stubs", rawCount);

        if (rawCount == 0) {
            LOG_ERROR("Tartarus: No syscall stubs found");
            return result;
        }

        // Step 4: Sort clean stubs by address to establish the stub region
        SortStubsByAddress(rawStubs, rawCount);

        // Determine the contiguous syscall stub region boundaries
        ULONG_PTR stubRegionStart = (ULONG_PTR)rawStubs[0].StubAddress;
        ULONG_PTR stubRegionEnd   = (ULONG_PTR)rawStubs[rawCount - 1].StubAddress + SYSCALL_STUB_SIZE;

        LOG("Tartarus: Stub region: %p - %p", (PVOID)stubRegionStart, (PVOID)stubRegionEnd);

        // Step 5: Second pass — find hooked stubs within the stub region
        // Re-walk exports and look for Nt*/Zw* functions whose address falls
        // within the stub region but didn't match the clean pattern.
        for (DWORD i = 0; i < pExport->NumberOfNames && rawCount < MAX_SYSCALLS; i++) {
            const char* szName = (const char*)((BYTE*)hNtdll + pNames[i]);

            bool isNt = (szName[0] == 'N' && szName[1] == 't');
            bool isZw = (szName[0] == 'Z' && szName[1] == 'w');
            if (!isNt && !isZw) continue;
            if (szName[0] == 'N' && szName[1] == 't' && szName[2] == 'd' && szName[3] == 'l' && szName[4] == 'l') continue;

            WORD ordinal = pOrdinals[i];
            DWORD funcRva = pFunctions[ordinal];
            BYTE* pStub = (BYTE*)hNtdll + funcRva;

            // Skip if already collected (clean stub)
            if (IsCleanStub(pStub)) continue;

            // Check if this stub falls within the syscall stub region
            ULONG_PTR stubAddr = (ULONG_PTR)pStub;
            if (stubAddr < stubRegionStart || stubAddr >= stubRegionEnd) continue;

            // Verify it actually looks like a hooked stub (not just some random function)
            if (!IsHookedStub(pStub)) continue;

            // This is a hooked syscall stub
            uint32_t hash = Hash::RuntimeHashA(szName);

            rawStubs[rawCount].Hash        = hash;
            rawStubs[rawCount].StubAddress  = pStub;
            rawStubs[rawCount].IsHooked     = true;
            rawStubs[rawCount].SortOrder    = 0;
            rawStubs[rawCount].Ssn          = 0xFFFFFFFF;
            rawCount++;
            result.HookedStubs++;

            LOG("Tartarus: Hooked stub detected: %s @ %p", szName, pStub);
        }

        // Re-sort with hooked stubs included
        SortStubsByAddress(rawStubs, rawCount);

        // Assign sort positions
        for (int i = 0; i < rawCount; i++) {
            rawStubs[i].SortOrder = i;
        }

        // Step 5: Tartarus Gate — resolve hooked stubs by walking neighbors
        // If stub[i] is hooked, walk to stub[i±1], stub[i±2], ... until we
        // find a clean neighbor. Then: our SSN = neighbor SSN ± offset.
        for (int i = 0; i < rawCount; i++) {
            if (rawStubs[i].Ssn != 0xFFFFFFFF) continue;  // Already resolved

            bool resolved = false;

            for (int dist = 1; dist <= MAX_NEIGHBOR_DISTANCE && !resolved; dist++) {
                // Check neighbor above (lower address = lower SSN)
                int up = i - dist;
                if (up >= 0 && rawStubs[up].Ssn != 0xFFFFFFFF) {
                    rawStubs[i].Ssn = rawStubs[up].Ssn + (DWORD)dist;
                    resolved = true;
                    LOG("Tartarus: Resolved hooked stub at index %d via neighbor -%d (SSN=%d)",
                        i, dist, rawStubs[i].Ssn);
                }

                // Check neighbor below (higher address = higher SSN)
                int down = i + dist;
                if (!resolved && down < rawCount && rawStubs[down].Ssn != 0xFFFFFFFF) {
                    rawStubs[i].Ssn = rawStubs[down].Ssn - (DWORD)dist;
                    resolved = true;
                    LOG("Tartarus: Resolved hooked stub at index %d via neighbor +%d (SSN=%d)",
                        i, dist, rawStubs[i].Ssn);
                }
            }

            if (!resolved) {
                LOG_ERROR("Tartarus: FAILED to resolve SSN for stub at index %d (addr=%p)",
                    i, rawStubs[i].StubAddress);
                result.FailedStubs++;
            }
        }

        // Step 6: Build the final syscall map
        s_SyscallCount = 0;
        for (int i = 0; i < rawCount; i++) {
            if (rawStubs[i].Ssn == 0xFFFFFFFF) continue;  // Unresolved, skip

            s_Syscalls[s_SyscallCount].Hash        = rawStubs[i].Hash;
            s_Syscalls[s_SyscallCount].Ssn         = rawStubs[i].Ssn;
            s_Syscalls[s_SyscallCount].StubAddress  = rawStubs[i].StubAddress;
            s_Syscalls[s_SyscallCount].WasHooked    = rawStubs[i].IsHooked;
            s_SyscallCount++;
        }

        // Step 7: Validate SSN sequence integrity
        // After sorting by address, clean SSNs should form a monotonic sequence.
        // Nt* and Zw* exports share the same stub address and SSN, so we
        // skip duplicates (same address as previous entry) during validation.
        {
            int gaps = 0;
            DWORD prevSsn = 0xFFFFFFFF;
            PVOID prevAddr = nullptr;
            for (int i = 0; i < rawCount; i++) {
                if (rawStubs[i].Ssn == 0xFFFFFFFF) continue;

                // Skip Nt/Zw duplicates (same stub address)
                if (rawStubs[i].StubAddress == prevAddr) continue;

                if (prevSsn != 0xFFFFFFFF && rawStubs[i].Ssn != prevSsn + 1) {
                    gaps++;
                    LOG("Tartarus: SSN gap at index %d: expected %d, got %d (addr=%p, prev_addr=%p)",
                        i, prevSsn + 1, rawStubs[i].Ssn, rawStubs[i].StubAddress, prevAddr);
                }
                prevSsn = rawStubs[i].Ssn;
                prevAddr = rawStubs[i].StubAddress;
            }

            if (gaps > 0) {
                // Small gaps (1-3) are normal on some Windows builds where certain
                // Nt* functions have optimized inline stubs instead of real syscalls
                // (e.g., NtQuerySystemTime reads SharedUserData directly)
                if (gaps <= 3) {
                    LOG_INFO("Tartarus: %d minor SSN gap(s) — normal for this Windows build", gaps);
                } else {
                    LOG_ERROR("Tartarus: WARNING — %d SSN sequence gaps detected (possible ntdll tampering)", gaps);
                }
            } else {
                LOG_SUCCESS("Tartarus: SSN integrity check PASSED (%d entries, monotonic sequence verified)",
                    s_SyscallCount);
            }
        }

        result.Success = true;
        result.TotalExtracted = s_SyscallCount;
        s_Initialized = true;

        // Sort final map by hash for O(log n) binary search lookups
        SortSyscallsByHash(s_Syscalls, s_SyscallCount);

        LOG_SUCCESS("Tartarus: Initialized — %d syscalls extracted (%d hooked, %d failed)",
            result.TotalExtracted, result.HookedStubs, result.FailedStubs);

        return result;
    }

    // ========================================================================
    // Lookup: GetSyscall
    // ========================================================================

    const SyscallEntry* GetSyscall(uint32_t apiHash) {
        // Binary search — map is sorted by hash after initialization
        int lo = 0, hi = s_SyscallCount - 1;
        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            if (s_Syscalls[mid].Hash == apiHash) return &s_Syscalls[mid];
            if (s_Syscalls[mid].Hash < apiHash) lo = mid + 1;
            else hi = mid - 1;
        }
        return nullptr;
    }

    // ========================================================================
    // GetSyscallCount
    // ========================================================================

    int GetSyscallCount() {
        return s_SyscallCount;
    }

    // ========================================================================
    // Shutdown: zero all sensitive state
    // ========================================================================

    void Shutdown() {
        // Zero the syscall map — volatile writes prevent optimization
        volatile unsigned char* p = (volatile unsigned char*)s_Syscalls;
        for (size_t i = 0; i < sizeof(s_Syscalls); i++) {
            p[i] = 0;
        }

        s_SyscallCount = 0;
        s_Initialized  = false;

        LOG("Tartarus: Shutdown — syscall map zeroed");
    }

} // namespace Tartarus
