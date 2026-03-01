#pragma once

// ============================================================================
// Shared PRNG — xorshift64 with hardware entropy seeding
// ============================================================================
// Single shared PRNG for all engine components. Seeded once from RDTSC +
// stack ASLR. Better period (2^64-1) and distribution than xorshift32.
// NOT thread-safe — single-threaded engine only.
// ============================================================================

#include <stdint.h>

namespace Prng {

    void Seed(uint64_t s);
    void SeedFromHardware();
    uint32_t Next32();

} // namespace Prng
