#pragma once

// ============================================================================
// Inline Cryptographic Primitives
// ============================================================================
// Self-contained RC4 implementation. No SystemFunction032, no advapi32,
// no CRT dependencies. Works entirely with static buffers.
//
// RC4 is used because:
//   - Symmetric: same operation encrypts and decrypts (XOR stream)
//   - Fast: minimal CPU overhead for large memory regions
//   - Simple: ~30 lines of code, no lookup tables beyond S-box
//   - Sufficient: we only need to make memory unrecognizable during sleep
// ============================================================================

#include <stdint.h>
#include <stddef.h>

namespace Crypto {

    // Secure memory zeroing — volatile writes prevent compiler optimization.
    // MSVC /O2 will eliminate plain memset/loop zeroing of dead locals.
    // This version forces every byte write to actually execute.
    inline void SecureZero(void* ptr, size_t len) {
        volatile unsigned char* p = (volatile unsigned char*)ptr;
        for (size_t i = 0; i < len; i++) p[i] = 0;
    }

    // RC4 state (256-byte S-box)
    struct Rc4State {
        uint8_t S[256];
        uint8_t i;
        uint8_t j;
    };

    // Initialize RC4 state from key material
    inline void Rc4Init(Rc4State* state, const uint8_t* key, size_t keyLen) {
        for (int k = 0; k < 256; k++) {
            state->S[k] = (uint8_t)k;
        }

        uint8_t j = 0;
        for (int k = 0; k < 256; k++) {
            j = j + state->S[k] + key[k % keyLen];
            // Swap
            uint8_t tmp = state->S[k];
            state->S[k] = state->S[j];
            state->S[j] = tmp;
        }

        state->i = 0;
        state->j = 0;
    }

    // RC4 encrypt/decrypt in-place (XOR stream — same operation for both)
    inline void Rc4Process(Rc4State* state, uint8_t* data, size_t dataLen) {
        for (size_t n = 0; n < dataLen; n++) {
            state->i++;
            state->j += state->S[state->i];

            // Swap S[i] and S[j]
            uint8_t tmp = state->S[state->i];
            state->S[state->i] = state->S[state->j];
            state->S[state->j] = tmp;

            // XOR with keystream byte
            uint8_t k = state->S[(uint8_t)(state->S[state->i] + state->S[state->j])];
            data[n] ^= k;
        }
    }

    // Convenience: one-shot RC4 encrypt/decrypt
    inline void Rc4(const uint8_t* key, size_t keyLen, uint8_t* data, size_t dataLen) {
        Rc4State state;
        Rc4Init(&state, key, keyLen);
        Rc4Process(&state, data, dataLen);

        // Zero state to prevent key recovery from memory
        // Uses volatile writes — compiler cannot optimize this away
        SecureZero(&state, sizeof(state));
    }

} // namespace Crypto
