// ============================================================================
// Syscall Manager - Trampoline Harvesting + Indirect Syscall Support
// ============================================================================
// Scans ntdll .text section for "syscall; ret" (0F 05 C3) gadgets,
// quality-scores each one, and provides random rotation (hardening).
//
// No STL, no CRT allocations — static arrays only.
// ============================================================================

#include "syscall_manager.h"
#include "peb_lookup.h"
#include "hashing.h"
#include "config.h"
#include "prng.h"

#include <intrin.h>

namespace SyscallManager {

    // ========================================================================
    // Constants
    // ========================================================================

    static constexpr int MAX_TRAMPOLINES = 256;

    // Gadget bytes: syscall (0F 05) + ret (C3)
    static constexpr BYTE GADGET_SYSCALL_0 = 0x0F;
    static constexpr BYTE GADGET_SYSCALL_1 = 0x05;
    static constexpr BYTE GADGET_RET       = 0xC3;

    // ========================================================================
    // Internal State
    // ========================================================================

    struct TrampolineEntry {
        PVOID Address;
        int   Score;        // Quality score (higher = better)
    };

    static TrampolineEntry s_Trampolines[MAX_TRAMPOLINES];
    static int             s_TrampolineCount = 0;
    static int             s_QualityCount    = 0;
    static bool            s_Initialized     = false;

    // ========================================================================
    // Gadget Quality Scoring
    // ========================================================================
    // Ranks gadgets by how "natural" they look in context:
    //   +30  Near padding bytes (CC/90) — indicates function boundary
    //   +20  Deep inside .text (not at edges)
    //   -50  Near a JMP (E9) — possible hook trampoline
    //   -30  Near INT3 breakpoint cluster — possible debugger artifact

    static int ScoreGadget(const BYTE* textBase, DWORD textSize, DWORD offset) {
        int score = 10;  // Base score — every gadget starts positive

        // Bonus: confirmed syscall stub — preceded by mov eax, imm32 (B8 xx xx xx xx)
        // This proves the gadget is at a real syscall stub ending, not a coincidental byte pattern
        if (offset >= 7) {
            for (int lookback = 5; lookback <= 7; lookback++) {
                if (textBase[offset - lookback] == 0xB8) {
                    score += 50;
                    break;
                }
            }
        }

        // Bonus: near function padding (CC = int3 padding, 90 = nop sled)
        if (offset > 10) {
            for (int k = 1; k <= 8; k++) {
                BYTE b = textBase[offset - k];
                if (b == 0xCC || b == 0x90) {
                    score += 30;
                    break;
                }
            }
        }

        // Bonus: deep inside .text section (not at boundaries)
        if (offset > 0x1000 && offset < textSize - 0x1000) {
            score += 20;
        }

        // Penalty: JMP rel32 nearby (possible hook landing zone)
        if (offset > 5 && textBase[offset - 5] == 0xE9) {
            score -= 50;
        }

        // Penalty: preceded by a cluster of INT3s (debugger breakpoints)
        if (offset > 16) {
            int ccCount = 0;
            for (int k = 1; k <= 16; k++) {
                if (textBase[offset - k] == 0xCC) ccCount++;
            }
            if (ccCount > 8) score -= 30;
        }

        return score;
    }

    // ========================================================================
    // Simple insertion sort by score (descending)
    // ========================================================================

    static void SortByScore(TrampolineEntry* entries, int count) {
        for (int i = 1; i < count; i++) {
            TrampolineEntry key = entries[i];
            int j = i - 1;
            while (j >= 0 && entries[j].Score < key.Score) {
                entries[j + 1] = entries[j];
                j--;
            }
            entries[j + 1] = key;
        }
    }

    // ========================================================================
    // Initialize
    // ========================================================================

    InitResult Initialize() {
        InitResult result = { false, 0, 0 };

        if (s_Initialized) {
            result.Success = true;
            result.TotalGadgets = s_TrampolineCount;
            result.QualityGadgets = s_QualityCount;
            return result;
        }

        // Get ntdll base
        HMODULE hNtdll = Resolver::GetModuleByHash(HASH_MODULE(L"ntdll.dll"));
        if (!hNtdll) {
            LOG_ERROR("SyscallMgr: Failed to locate ntdll");
            return result;
        }

        // Parse PE to find .text section
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
        PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + pDos->e_lfanew);
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

        BYTE* pText     = nullptr;
        DWORD textSize  = 0;

        for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSection++) {
            // Match ".text" by comparing first 5 bytes of section name
            if (pSection->Name[0] == '.' &&
                pSection->Name[1] == 't' &&
                pSection->Name[2] == 'e' &&
                pSection->Name[3] == 'x' &&
                pSection->Name[4] == 't') {
                pText    = (BYTE*)hNtdll + pSection->VirtualAddress;
                textSize = pSection->Misc.VirtualSize;
                break;
            }
        }

        if (!pText || textSize < 3) {
            LOG_ERROR("SyscallMgr: Failed to locate ntdll .text section");
            return result;
        }

        LOG("SyscallMgr: ntdll .text @ %p, size = 0x%X", pText, textSize);

        // Scan for syscall;ret gadgets (0F 05 C3)
        int totalFound = 0;
        s_TrampolineCount = 0;

        for (DWORD j = 0; j < textSize - 2; j++) {
            if (pText[j]     == GADGET_SYSCALL_0 &&
                pText[j + 1] == GADGET_SYSCALL_1 &&
                pText[j + 2] == GADGET_RET) {

                totalFound++;

                int score = ScoreGadget(pText, textSize, j);

                // Only keep positive-score gadgets (up to MAX_TRAMPOLINES)
                if (score > 0 && s_TrampolineCount < MAX_TRAMPOLINES) {
                    s_Trampolines[s_TrampolineCount].Address = &pText[j];
                    s_Trampolines[s_TrampolineCount].Score   = score;
                    s_TrampolineCount++;
                }
            }
        }

        result.TotalGadgets = totalFound;

        LOG("SyscallMgr: Found %d total gadgets, %d passed quality filter",
            totalFound, s_TrampolineCount);

        if (s_TrampolineCount == 0) {
            // Fallback: accept ALL gadgets regardless of score
            LOG_ERROR("SyscallMgr: No quality gadgets — falling back to unfiltered mode");

            for (DWORD j = 0; j < textSize - 2 && s_TrampolineCount < MAX_TRAMPOLINES; j++) {
                if (pText[j]     == GADGET_SYSCALL_0 &&
                    pText[j + 1] == GADGET_SYSCALL_1 &&
                    pText[j + 2] == GADGET_RET) {
                    s_Trampolines[s_TrampolineCount].Address = &pText[j];
                    s_Trampolines[s_TrampolineCount].Score   = 0;
                    s_TrampolineCount++;
                }
            }
        }

        // Sort by quality (best first)
        SortByScore(s_Trampolines, s_TrampolineCount);

        // Count quality gadgets (score > 20)
        s_QualityCount = 0;
        for (int i = 0; i < s_TrampolineCount; i++) {
            if (s_Trampolines[i].Score > 20) s_QualityCount++;
        }

        result.QualityGadgets = s_QualityCount;
        result.Success = (s_TrampolineCount > 0);
        s_Initialized = true;

        LOG_SUCCESS("SyscallMgr: %d trampolines ready (%d high-quality)",
            s_TrampolineCount, s_QualityCount);

        return result;
    }

    // ========================================================================
    // GetRandomTrampoline
    // ========================================================================

    PVOID GetRandomTrampoline() {
        if (s_TrampolineCount == 0) return nullptr;

        // Full pool rotation — all quality-filtered gadgets participate
        int index = (int)(Prng::Next32() % (uint32_t)s_TrampolineCount);
        return s_Trampolines[index].Address;
    }

    // ========================================================================
    // GetTrampolineCount
    // ========================================================================

    int GetTrampolineCount() {
        return s_TrampolineCount;
    }

    // ========================================================================
    // Shutdown — zero sensitive state
    // ========================================================================

    void Shutdown() {
        volatile BYTE* p = (volatile BYTE*)s_Trampolines;
        for (size_t i = 0; i < sizeof(s_Trampolines); i++) p[i] = 0;
        s_TrampolineCount = 0;
        s_QualityCount = 0;
        s_Initialized = false;
        LOG("SyscallMgr: Shutdown complete");
    }

} // namespace SyscallManager
