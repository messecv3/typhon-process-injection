// ============================================================================
// Shared PRNG — xorshift64 implementation
// ============================================================================

#include "prng.h"
#include <intrin.h>

// Include polymorphic config if available
#if __has_include("polymorphic_config.h")
#include "polymorphic_config.h"
#endif

#ifndef POLY_PRNG_FALLBACK
#define POLY_PRNG_FALLBACK 0xDEADBEEFCAFEBABEULL
#endif

namespace Prng {

    static uint64_t s_State = 0;

    void Seed(uint64_t s) {
        s_State = s;
        if (s_State == 0) s_State = POLY_PRNG_FALLBACK;
    }

    void SeedFromHardware() {
        uint64_t e1 = __rdtsc();
        volatile int dummy = 0;
        for (volatile int i = 0; i < 50; i++) dummy += i;
        uint64_t e2 = __rdtsc();
        uint64_t stackEntropy = (uint64_t)&dummy;
        Seed(e1 ^ (e2 << 7) ^ stackEntropy);
    }

    uint32_t Next32() {
        uint64_t x = s_State;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s_State = x;
        return (uint32_t)(x >> 16);
    }

} // namespace Prng
