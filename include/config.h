#pragma once

// ============================================================================
// THREAD SAFETY: This engine is NOT thread-safe.
// All components use process-global mutable state without synchronization.
// The engine must be initialized and used from a single thread.
// If the payload spawns threads, those threads must NOT call any engine API.
// ============================================================================

// ============================================================================
// v5 Engine Configuration
// ============================================================================

#include <windows.h>
#include <stdio.h>

// ============================================================================
// Build Mode Detection
// ============================================================================

#ifdef _DEBUG
    #define DEBUG_BUILD 1
    #define RELEASE_BUILD 0
#else
    #define DEBUG_BUILD 0
    #define RELEASE_BUILD 1
#endif

// ============================================================================
// Logging Macros - Compile out completely in release
// ============================================================================

#if DEBUG_BUILD
    static inline DWORD _log_tick() {
        return GetTickCount();
    }
    static DWORD _log_start_tick = 0;
    static bool _log_timer_inited = false;
    static inline DWORD _log_elapsed() {
        if (!_log_timer_inited) { _log_start_tick = _log_tick(); _log_timer_inited = true; }
        return _log_tick() - _log_start_tick;
    }

    #define LOG_INIT_TIMER() do { _log_start_tick = _log_tick(); _log_timer_inited = true; } while(0)
    #define LOG(fmt, ...) printf("[*] [%6ums] " fmt "\n", _log_elapsed(), ##__VA_ARGS__)
    #define LOG_ERROR(fmt, ...) printf("[-] [%6ums] " fmt "\n", _log_elapsed(), ##__VA_ARGS__)
    #define LOG_SUCCESS(fmt, ...) printf("[+] [%6ums] " fmt "\n", _log_elapsed(), ##__VA_ARGS__)
    #define LOG_INFO(fmt, ...) printf("[i] [%6ums] " fmt "\n", _log_elapsed(), ##__VA_ARGS__)
    #define LOG_HEX(label, addr, size) DebugHexDump(label, addr, size)
    
    inline void DebugHexDump(const char* label, const void* addr, size_t size) {
        printf("[HEX] [%6ums] %s (%p, %zu bytes):\n", _log_elapsed(), label, addr, size);
        const unsigned char* p = (const unsigned char*)addr;
        for (size_t i = 0; i < size && i < 64; i++) {
            printf("%02X ", p[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        if (size > 64) printf("... (truncated)\n");
        else if (size % 16 != 0) printf("\n");
    }
#else
    #define LOG_INIT_TIMER() ((void)0)
    #define LOG(fmt, ...) ((void)0)
    #define LOG_ERROR(fmt, ...) ((void)0)
    #define LOG_SUCCESS(fmt, ...) ((void)0)
    #define LOG_INFO(fmt, ...) ((void)0)
    #define LOG_HEX(label, addr, size) ((void)0)
#endif

// ============================================================================
// Compile-Time Wide String Obfuscation
// ============================================================================
// Usage: OBFW(L"ntdll.dll") - returns obfuscated wide string
// In release builds, this provides basic string hiding
// In debug builds, returns string as-is for readability

#if RELEASE_BUILD
    // Simple XOR obfuscation at compile time (C++14 constexpr)
    // Include polymorphic config if available
    #if __has_include("polymorphic_config.h")
    #include "polymorphic_config.h"
    #endif

    #ifndef POLY_XOR_KEY_BASE
    #define POLY_XOR_KEY_BASE 0x5A
    #endif

    template<size_t N>
    struct ObfuscatedWideString {
        wchar_t data[N];
        
        constexpr ObfuscatedWideString(const wchar_t(&str)[N]) : data{} {
            for (size_t i = 0; i < N; i++) {
                data[i] = str[i] ^ (POLY_XOR_KEY_BASE + i);
            }
        }
        
        const wchar_t* decode() const {
            static wchar_t decoded[N];
            for (size_t i = 0; i < N; i++) {
                decoded[i] = data[i] ^ (POLY_XOR_KEY_BASE + i);
            }
            return decoded;
        }
    };
    
    #define OBFW(str) (ObfuscatedWideString<sizeof(str)/sizeof(wchar_t)>(str).decode())
#else
    #define OBFW(str) (str)
#endif

// ============================================================================
// Feature Toggles (source protection & hardening)
// ============================================================================

// Enable/disable source protection and hardening features
#define ENABLE_SLEEP_OBFUSCATION    1   // Encrypt payload in memory during sleep (reduces inspection window)
#define ENABLE_STACK_SPOOFING       1   // Call-context hardening (module: call_context)
#define ENABLE_ANTI_ANALYSIS        1   // (legacy name, prefer ENABLE_ENV_VERIFY)
#define ENABLE_ENV_VERIFY          ENABLE_ANTI_ANALYSIS   // Environment verification (tamper/non-production checks; protects payload)
#define ENABLE_SECTION_EXECUTION    1   // Section-backed execution (file protection / hardening)

// Sleep duration in milliseconds (used by sleep obfuscation)
#ifndef SLEEP_DURATION_MS
    #define SLEEP_DURATION_MS 3000
#endif

// ============================================================================
// Architecture Validation
// ============================================================================

#ifndef _WIN64
    #error "v5 engine requires x64 architecture"
#endif

// ============================================================================
// NT Status Helpers
// ============================================================================

#ifndef NT_SUCCESS
    #define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
    #define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
