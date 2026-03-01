#pragma once

// ============================================================================
// Compile-Time and Runtime Hashing — Multi-Algorithm
// ============================================================================
// Per-build algorithm selection via POLY_HASH_ALGO. All callers use the same
// HashStep function — compile-time (constexpr) and runtime are identical.
//
// Algorithms:
//   0 = DJB2       — ((hash << 5) + hash) + c
//   1 = FNV-1a     — (hash ^ c) * 0x01000193
//   2 = SDBM       — c + (hash << 6) + (hash << 16) - hash
//   3 = Rotate-XOR — hash ^= c; ROL(hash, 7)
//   4 = Jenkins OAT — hash += c; hash += (hash << 10); hash ^= (hash >> 6)
//
// Seed is always POLY_HASH_SEED (randomized per build).
// ============================================================================

#include <stdint.h>

// Include polymorphic config if available (per-build unique constants)
#if __has_include("polymorphic_config.h")
#include "polymorphic_config.h"
#endif

#ifndef POLY_HASH_SEED
#define POLY_HASH_SEED 5381u
#endif

#ifndef POLY_HASH_ALGO
#define POLY_HASH_ALGO 0
#endif

namespace Hash {

    constexpr uint32_t HASH_SEED = POLY_HASH_SEED;

    // ========================================================================
    // Hash step function — selected at compile time by POLY_HASH_ALGO
    // ========================================================================

    constexpr uint32_t HashStep(uint32_t hash, uint32_t c) {
#if POLY_HASH_ALGO == 0   // DJB2
        return ((hash << 5) + hash) + c;
#elif POLY_HASH_ALGO == 1  // FNV-1a
        return (hash ^ c) * 0x01000193u;
#elif POLY_HASH_ALGO == 2  // SDBM
        return c + (hash << 6) + (hash << 16) - hash;
#elif POLY_HASH_ALGO == 3  // Rotate-XOR
        hash ^= c;
        return (hash << 7) | (hash >> 25);
#elif POLY_HASH_ALGO == 4  // Jenkins one-at-a-time
        hash += c;
        hash += (hash << 10);
        hash ^= (hash >> 6);
        return hash;
#else
        return ((hash << 5) + hash) + c;  // Default: DJB2
#endif
    }

    // ========================================================================
    // Jenkins finalization (only used when POLY_HASH_ALGO == 4)
    // ========================================================================

    constexpr uint32_t HashFinalize(uint32_t hash) {
#if POLY_HASH_ALGO == 4
        hash += (hash << 3);
        hash ^= (hash >> 11);
        hash += (hash << 15);
#endif
        return hash;
    }

    // ========================================================================
    // Compile-Time Hash (constexpr)
    // ========================================================================

    constexpr uint32_t CompileTimeHashA(const char* str) {
        uint32_t hash = HASH_SEED;
        while (*str) {
            char c = *str++;
            if (c >= 'a' && c <= 'z') c -= 32;
            hash = HashStep(hash, (uint32_t)(unsigned char)c);
        }
        return HashFinalize(hash);
    }

    constexpr uint32_t CompileTimeHashW(const wchar_t* str) {
        uint32_t hash = HASH_SEED;
        while (*str) {
            wchar_t c = *str++;
            if (c >= L'a' && c <= L'z') c -= 32;
            hash = HashStep(hash, (uint32_t)c);
        }
        return HashFinalize(hash);
    }

    // ========================================================================
    // Runtime Hash
    // ========================================================================

    inline uint32_t RuntimeHashA(const char* str) {
        uint32_t hash = HASH_SEED;
        while (*str) {
            char c = *str++;
            if (c >= 'a' && c <= 'z') c -= 32;
            hash = HashStep(hash, (uint32_t)(unsigned char)c);
        }
        return HashFinalize(hash);
    }

    inline uint32_t RuntimeHashW(const wchar_t* str, size_t len) {
        uint32_t hash = HASH_SEED;
        for (size_t i = 0; i < len; i++) {
            wchar_t c = str[i];
            if (c >= L'a' && c <= L'z') c -= 32;
            hash = HashStep(hash, (uint32_t)c);
        }
        return HashFinalize(hash);
    }

    inline uint32_t RuntimeHashW(const wchar_t* str) {
        uint32_t hash = HASH_SEED;
        while (*str) {
            wchar_t c = *str++;
            if (c >= L'a' && c <= L'z') c -= 32;
            hash = HashStep(hash, (uint32_t)c);
        }
        return HashFinalize(hash);
    }

} // namespace Hash

// ============================================================================
// Convenience Macros
// ============================================================================

#define HASH_API(str) (Hash::CompileTimeHashA(str))
#define HASH_MODULE(str) (Hash::CompileTimeHashW(str))
