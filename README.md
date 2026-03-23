<p align="center">
  <h1 align="center">Typhon</h1>
  <p align="center">Evasive process injection toolkit for Windows — indirect syscalls, call-stack spoofing, section-backed memory, zero-patch AMSI/ETW bypass, and all 8 PoolParty thread pool variants in a single binary.</p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/arch-x64-blue" />
  <img src="https://img.shields.io/badge/OS-Windows%2010%2F11-blue" />
  <img src="https://img.shields.io/badge/variants-8%2F8-green" />
  <img src="https://img.shields.io/badge/syscalls-indirect-orange" />
  <img src="https://img.shields.io/badge/AMSI-zero--patch-red" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
</p>

<p align="center">
  <a href="https://t.me/CrypterCC"><img src="https://img.shields.io/badge/Telegram-Channel-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white" /></a>
  &nbsp;
  <a href="http://t.me/+cqqW4Z9PcP9kODE0"><img src="https://img.shields.io/badge/Telegram-Chat-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white" /></a>
  &nbsp;
  <a href="https://t.me/CCVouchesReviews"><img src="https://img.shields.io/badge/Reviews_%26_Vouches-⭐-gold?style=for-the-badge&logo=telegram&logoColor=white" /></a>
</p>

---

Typhon is not just another PoolParty implementation. It's a complete evasive injection framework that combines six independent bypass layers into a single tool — indirect syscalls via Tartarus Gate, per-call trampoline rotation, full call-stack spoofing with CET awareness, section-backed cross-process memory, PEB-only API resolution with zero imports, and a zero-patch AMSI/ETW bypass that doesn't touch a single code byte. The PoolParty thread pool variants are the delivery mechanism. Everything else is what keeps it alive in a monitored environment.

Built on the research by [SafeBreach Labs](https://github.com/SafeBreach-Labs/PoolParty) — Alon Leviev, Black Hat EU 2023.

---

<p align="center">
  <strong>🔐 Brought to you by <a href="https://crypter.cloud">Crypter.cloud</a> & <a href="https://crypter.shop">Crypter.shop</a></strong><br>
  <em>Advanced cryptography and security solutions</em>
</p>

---

## Why This Exists

Every PoolParty implementation on GitHub does the same thing: calls `NtSetIoCompletion` through a direct syscall (or worse, through ntdll imports) after allocating memory with `VirtualAllocEx`. That's not evasion — that's just another injection tool with a fancy name.

The entire point of PoolParty is that it eliminates the execution primitive. No `CreateRemoteThread`. No APC. No context hijacking. The thread pool's own worker threads pick up your callback as part of their normal scheduling loop. But if your syscalls are direct, your call stack is raw, and your memory is `MEM_PRIVATE` from `VirtualAllocEx` — you've already lost. EDRs will flag you before the callback even fires.

Typhon does it right. Every layer matters, and they compound.

## The Six Evasion Layers

These are not alternatives — they're cumulative. Every layer runs on every injection.

### 1. Indirect Syscalls via Tartarus Gate
Every NT call goes through a `syscall; ret` gadget harvested from ntdll's `.text` section — not through ntdll's export table, not through a direct `syscall` instruction in your binary. The SSN (Syscall Service Number) is extracted at runtime from ntdll's in-memory stubs, and if a stub is hooked (EDR inline hook), Tartarus walks to neighboring stubs and derives the correct SSN from a clean neighbor. Your binary contains zero NT API references.

### 2. Trampoline Rotation
The `syscall; ret` gadget address changes on every invocation. The engine scans ntdll for all valid gadgets, quality-scores them (proximity to known syscall stubs, distance from hooks, position in `.text`), and randomly selects a high-quality one per call. ETW telemetry and stack-based heuristics that fingerprint a fixed trampoline address see a different origin every time.

### 3. Call-Stack Spoofing + CET Awareness
The indirect syscall frame has a spoofed RBP chain built from real return addresses harvested from system DLLs (ntdll, kernel32, kernelbase, user32). A full thread `CONTEXT` is stolen from a sibling thread so non-volatile registers match a real suspended frame. If Intel CET (shadow stack) is active, synthetic `.pdata` entries are registered via `RtlAddFunctionTable` so the Windows unwinder treats the frames as legitimate. EDR stack walkers see a plausible call chain originating from system modules.

### 4. Section-Backed Memory (No VirtualAllocEx)
Shellcode lands in the target via `NtCreateSection` + `NtMapViewOfSection` — mapped RW in our process for writing, mapped RWX in the target for execution (donut shellcode decrypts itself in-place). The target sees `MEM_MAPPED` memory (looks like a DLL or shared section), not `MEM_PRIVATE` from `VirtualAllocEx`. After writing, our local view is unmapped — zero trace in our process. No `WriteProcessMemory` for bulk writes.

### 5. Zero IAT / Full PEB Resolution
Every API — `CreateFileW`, `GetTempPathW`, `CreateToolhelp32Snapshot`, everything — is resolved by walking the PEB's `InMemoryOrderModuleList` and matching compile-time hashed names. The import table contains nothing interesting. Static analysis of the binary reveals no suspicious API usage.

### 6. Zero-Patch AMSI/ETW Bypass
Most tools rely on donut's AMSI bypass, which patches `AmsiScanBuffer` directly — that's been signatured by every EDR since 2020. Typhon uses a completely different approach:

- **AMSI**: Three-layer zero-patch context corruption. No code patching at all — just data writes to amsi.dll's heap memory. Corrupts the magic signature, decapitates the provider list, and overflows the session counter. Indistinguishable from normal heap writes.
- **ETW**: Patches `EtwEventWrite`, `EtwEventWriteEx`, and `NtTraceEvent` stubs to return 0. The memory protection change goes through indirect syscalls with spoofed stacks, so EDR hooks on `VirtualProtect`/`NtProtectVirtualMemory` never see it. Plus per-thread TEB instrumentation suppression as a safety net.

When building standalone executables, donut's bypass is explicitly disabled (`-b 1`) because ours is better.

### The Result

```
Typical repos:  PoolParty technique + direct ntdll call + VirtualAllocEx + raw stack + IAT imports + donut AMSI bypass
Typhon:          PoolParty technique + indirect syscall + trampoline rotation + spoofed stack + section memory + PEB resolution + zero-patch AMSI/ETW
```

That's the difference between "novel injection primitive" and "novel injection primitive that actually survives in a monitored environment."

## Quick Start

### Interactive mode (just run it)

```bash
typhon.exe
```

No arguments, no embedded shellcode — Typhon launches an interactive menu:

```
  Typhon -- Evasive Process Injection Toolkit
  ============================================
  Indirect Syscalls | Call-Stack Spoofing | Section-Backed Memory
  AMSI/ETW Bypass | 8 PoolParty Variants | Auto-Target Selection

  [1] Build standalone exe (embed shellcode into portable exe)
  [2] Inject from file    (load shellcode and inject now)
  [3] Show help           (CLI usage and options)
```

### Build a standalone exe (recommended workflow)

The most common use case: embed your shellcode (or exe/dll) into a standalone .exe that auto-injects on launch. No arguments needed at runtime, no runtime dependencies, runs on a clean Windows 10/11 install.

```bash
# Compile typhon
build.bat

# Build from raw shellcode
typhon.exe -build payload.bin -o injector.exe

# Build from a native PE (auto-converts via donut)
typhon.exe -build implant.exe -o loader.exe

# Build from a .NET exe (auto-detects CLR, donut handles bootstrap)
typhon.exe -build agent.exe -o loader.exe

# The output is self-contained — just run it:
injector.exe
# → auto-finds target, injects, done
```

The builder auto-detects whether the input is raw shellcode (.bin) or a PE (.exe/.dll). If it's a PE, it automatically converts it to shellcode using [donut](https://github.com/TheWover/donut) — including .NET assemblies (CLR bootstrapping handled automatically). Just point it at your file and it figures out the rest.

The output exe is statically linked (`/MT`), needs zero VC runtime, and works on any x64 Windows 10/11 machine out of the box. Apply your own static protection (packing, obfuscation, signing) and deploy.

```bash
# Builder options
typhon.exe -build <file> [-o output.exe] [-variant X] [-delay ms] [-debug] [-donut path]

# Specific variant (V1 recommended for modern Windows with XFG)
typhon.exe -build payload.bin -o out.exe -variant 1          # V1 Worker Factory (recommended)
typhon.exe -build payload.bin -o out.exe -variant direct      # V7 TP_DIRECT
typhon.exe -build payload.bin -o out.exe -variant timer -delay 60000  # V8 with delay

# Debug mode — keeps console output in the built exe (for testing)
typhon.exe -build payload.bin -o out.exe -debug

# Custom donut path (auto-detected if in same dir or PATH)
typhon.exe -build implant.exe -o out.exe -donut C:\tools\donut.exe
```

### CLI mode (testing / development)

```bash
# Inject from shellcode file (auto-selects target)
typhon.exe payload.bin

# Inject into specific PID
typhon.exe payload.bin 1234

# Force V1 (Worker Factory) — bypasses CFG/XFG
typhon.exe payload.bin 1234 1
```

Shellcode format: raw bytes. Works with [donut](https://github.com/TheWover/donut), msfvenom, Cobalt Strike, or any raw shellcode generator.

When no PID is specified, Typhon automatically finds a suitable target — long-running, same-session process with an active thread pool (RuntimeBroker, sihost, taskhostw, explorer, etc.).

## All 8 Variants

| # | Name | Trigger | Notes |
|---|---|---|---|
| **V1** | **Worker Factory** | **Overwrite `TppWorkerThread`, force new worker** | **Recommended — bypasses CFG/XFG on modern Windows** |
| V2 | TP_WORK | Insert into task queue doubly-linked list | Worker thread dequeues and executes |
| V3 | TP_IO | Associate file with I/O completion port, write to file | File completion fires callback |
| V4 | TP_WAIT | Create wait completion packet, signal event | Event signal fires callback |
| V5 | TP_ALPC | Create ALPC port on I/O completion port, connect | ALPC message fires callback |
| V6 | TP_JOB | Create job object on I/O completion port, assign process | Job notification fires callback |
| V7 | TP_DIRECT | Queue TP_DIRECT to I/O completion port | One structure, one syscall. **Blocked by XFG.** |
| V8 | TP_TIMER | Insert into timer queue red-black tree | **Delayed execution** — attacker can exit |

> **Note on CFG/XFG:** Variants 3-8 use I/O completion callbacks dispatched through `TppDirectExecuteCallback`, which is an XFG-protected indirect call on modern Windows 10/11. These variants crash the target with `STATUS_STACK_BUFFER_OVERRUN` (0xC0000409). V1 bypasses this entirely by overwriting `TppWorkerThread` itself — the worker thread jumps directly to our trampoline via a `call` instruction, never going through the XFG-checked dispatch path. **V1 is the recommended variant for modern targets.**

### Variant Selection

```bash
typhon.exe payload.bin <pid> all       # All 8 (including destructive V1)
typhon.exe payload.bin <pid> safe      # V2-V8 (non-destructive)
typhon.exe payload.bin <pid> rec       # V1 (recommended)
typhon.exe payload.bin <pid> direct    # V7 only
typhon.exe payload.bin <pid> timer     # V8 only
typhon.exe payload.bin <pid> io        # V3-V7 (I/O completion variants)
typhon.exe payload.bin <pid> 1         # Specific variant by number
```

## V1 Worker Factory — How It Works

V1 is the recommended variant because it bypasses CFG/XFG entirely. Here's the execution flow:

1. **Handle hijacking**: Enumerate system handles, duplicate the target's `WorkerFactory` handle
2. **Query worker factory**: Get `TppWorkerThread` address (the start routine for all worker threads)
3. **Inject shellcode**: Map shellcode into target via `NtCreateSection` + `NtMapViewOfSection` (RWX for donut self-decryption)
4. **Build trampoline**: Allocate private RW page in target, write a `CreateThread` trampoline with an idempotent guard (`lock cmpxchg`), register as valid CFG target via `SetProcessValidCallTargets`
5. **Overwrite start routine**: Write a `mov rax, <trampoline>; jmp rax` stub over `TppWorkerThread` in ntdll
6. **Force worker creation**: Bump `WorkerFactoryThreadMinimum` via `NtSetInformationWorkerFactory` + queue dummy I/O completion packet
7. **New worker thread starts**: Calls the overwritten `TppWorkerThread`, hits our JMP stub, lands in the trampoline
8. **Trampoline executes**: `lock cmpxchg` guard ensures only the first worker calls `CreateThread(shellcode)`. Subsequent workers return 0 harmlessly.
9. **Shellcode runs in new thread**: Donut bootstraps the CLR, loads the .NET assembly, executes. The worker thread returns cleanly.

The key insight: worker threads call `TppWorkerThread` through a direct `call` instruction, not through an indirect call that CFG/XFG validates. By overwriting the function itself, we bypass the entire control flow integrity check.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Typhon                               │
│         Interactive Menu / CLI / Embedded Exe Mode           │
├─────────────────────────────────────────────────────────────┤
│                   AMSI/ETW Bypass                           │
│    Zero-patch AMSI corruption | ETW stub patch via syscall  │
│    TEB instrumentation suppression | No VirtualProtect      │
├─────────────────────────────────────────────────────────────┤
│                     PRNG Dispatcher                         │
│          Randomly selects variant from allowed set           │
├──────┬──────┬──────┬──────┬──────┬──────┬──────┬────────────┤
│  V1  │  V2  │  V3  │  V4  │  V5  │  V6  │  V7  │    V8     │
│Worker│TP_   │TP_IO │TP_   │TP_   │TP_   │TP_   │TP_TIMER   │
│Factor│WORK  │      │WAIT  │ALPC  │JOB   │DIRECT│           │
├──────┴──────┴──────┴──────┴──────┴──────┴──────┴────────────┤
│                    Memory Writer                            │
│         NtCreateSection → NtMapViewOfSection                │
│         RW local view → RWX remote view → detach local      │
├─────────────────────────────────────────────────────────────┤
│                   Handle Hijacker                           │
│      NtQuerySystemInformation(SystemHandleInformationEx)    │
│      → NtDuplicateObject → NtQueryObject (type check)      │
│      Discovers: WorkerFactory, IoCompletion, IRTimer        │
│      TP_POOL scan for correct IoCompletion handle           │
├─────────────────────────────────────────────────────────────┤
│                    Syscall Engine                            │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │  Tartarus   │  │  Trampoline  │  │   Call-Context      │ │
│  │  Gate       │  │  Manager     │  │   Hardening         │ │
│  │             │  │              │  │                     │ │
│  │  SSN from   │  │  syscall;ret │  │  Return addr        │ │
│  │  ntdll stub │  │  gadgets     │  │  harvesting +       │ │
│  │  + hook     │  │  quality     │  │  context theft +    │ │
│  │  recovery   │  │  scored +    │  │  CET .pdata +       │ │
│  │             │  │  rotated     │  │  VEH spoofing       │ │
│  └────────────┘  └──────────────┘  └─────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    PEB Resolver                             │
│       Module + export lookup by compile-time hash           │
│       Zero GetModuleHandle / GetProcAddress / IAT           │
└─────────────────────────────────────────────────────────────┘
```

## How Thread Pool Injection Bypasses EDRs

Traditional injection needs an explicit execution primitive — `CreateRemoteThread`, `NtQueueApcThread`, `SetThreadContext`, callback registration. EDRs have kernel callbacks and usermode hooks on all of these.

PoolParty eliminates the execution primitive entirely. You write data structures into the target's memory, and the thread pool's existing worker threads pick them up as part of their normal scheduling loop. The trigger is a completely legitimate operation — a file write completing, a timer expiring, an ALPC message arriving, an event being signaled.

From the EDR's perspective:
- No new thread was created
- No APC was queued
- No thread context was modified
- No callback was registered through any monitored API
- A worker thread that was already running just executed a callback that was already in its queue

The fundamental detection challenge: the thread pool is designed to execute arbitrary callbacks. That's its entire purpose. Distinguishing a legitimate callback from an attacker-inserted one requires understanding the full set of valid callbacks for every process — which is not practical at scale.

## Comparison

| | SafeBreach POC | Typical GitHub Repos | Typhon |
|---|---|---|---|
| Variants | 8 (separate binaries) | 1-2 (usually just V7) | 8 (single binary, PRNG-selected) |
| Syscalls | ntdll imports | Direct syscall / SysWhispers | Indirect via Tartarus Gate |
| Trampoline | N/A | Fixed address (if any) | Rotated per-call, quality-scored |
| Call stack | Raw | Raw | Spoofed RBP chain + stolen CONTEXT |
| CET/Shadow Stack | Not handled | Not handled | Detected + `.pdata` synthesis |
| Memory | `VirtualAllocEx` (RWX) | `VirtualAllocEx` (RWX) | `NtCreateSection` + `NtMapViewOfSection` (RW→RWX) |
| API resolution | `GetProcAddress` | `GetProcAddress` / static | PEB walking, compile-time hashes |
| AMSI bypass | None | Donut's (patched, signatured) | Zero-patch context corruption (3-layer) |
| ETW bypass | None | None or donut's | Stub patch via indirect syscall + TEB suppression |
| Handle discovery | `DuplicateHandle` (k32) | `DuplicateHandle` (k32) | `NtDuplicateObject` via indirect syscall |
| IoCompletion | From `WORKER_FACTORY_BASIC_INFORMATION` | From `WORKER_FACTORY_BASIC_INFORMATION` | TP_POOL scan (WF field is always 0 on modern Windows) |
| CFG/XFG | Not handled | Not handled | V1 bypasses entirely; CFG target registration for trampoline |
| Target selection | Manual PID | Manual PID | Auto-discovery of suitable targets |
| Input format | Hardcoded array | Hardcoded / file | .bin, .exe, .dll (native + .NET, auto-donut) |
| Builder | None | None | Standalone exe builder with embedded shellcode |
| Interactive mode | None | None | Menu-driven build/inject/help |

## The Syscall Engine (Reusable)

The syscall engine is independent of the injection variants and can be used for any project that needs indirect syscalls with call-stack spoofing. It consists of three components:

### Tartarus Gate
Extracts SSNs from ntdll's in-memory syscall stubs. If a stub is hooked (JMP/CALL at entry from an EDR inline hook), it walks to neighboring stubs and derives the SSN from a clean neighbor (adjacent stubs have sequential SSNs). Works against all known usermode hooking frameworks.

### Trampoline Manager
Scans ntdll's `.text` section for `syscall; ret` (0F 05 C3) gadgets. Each gadget is quality-scored:
- **+50** preceded by `mov eax, imm32` (confirmed syscall stub)
- **+30** near function padding (CC/90 bytes)
- **+20** deep inside `.text`
- **-50** near a JMP (possible hook trampoline)
- **-30** near INT3 clusters (debugger artifacts)

A random high-quality gadget is selected per invocation — the trampoline address varies every call.

### Call-Context Hardening
Makes indirect syscall frames look legitimate to EDR stack walkers:
1. Harvests real return addresses from `.text` sections of system DLLs
2. Steals a full `CONTEXT` from a sibling thread for register coherence
3. Detects Intel CET and synthesizes `.pdata` entries via `RtlAddFunctionTable`
4. Registers a VEH handler for full frame coherence on exception

The `DoSyscallSpoofed` ASM stub builds a synthetic RBP chain using harvested return addresses, so stack walkers see a plausible call chain from system modules.

## Building

### Requirements
- Visual Studio 2019+ with C++ desktop workload (MSVC v142+)
- Windows SDK 10.0.19041.0+
- x64 only
- [donut](https://github.com/TheWover/donut) (for PE-to-shellcode conversion in builder mode)

### Compile
```batch
build.bat
```

For debug builds with console output:
```batch
build.bat debug
```

Or manually:
```batch
cl /nologo /c /EHsc /W3 /std:c++17 /O2 /GL /MT /I"include" /Fo"build\" src\*.cpp
ml64 /nologo /c /Fo"build\syscall_stub.obj" src\syscall_stub.asm
link /nologo build\*.obj kernel32.lib user32.lib advapi32.lib /OUT:build\typhon.exe /SUBSYSTEM:CONSOLE /LTCG /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA
```

## Project Structure

```
├── include/
│   ├── poolparty_types.h      # Undocumented NT thread pool structures
│   ├── handle_hijack.h        # Thread pool handle discovery
│   ├── memory_writer.h        # Section-backed cross-process memory
│   ├── variants.h             # All 8 variant interfaces + dispatcher
│   ├── amsi_etw.h             # AMSI/ETW bypass interface
│   ├── tartarus.h             # Tartarus Gate SSN extraction
│   ├── syscall_manager.h      # Trampoline harvesting + rotation
│   ├── call_context.h         # Call-stack spoofing + CET
│   ├── peb_lookup.h           # PEB module/export resolution
│   ├── hashing.h              # Compile-time API name hashing
│   ├── crypto.h               # RC4 + SecureZero
│   ├── prng.h                 # xorshift64 PRNG
│   ├── nt_types.h             # NT structure definitions
│   └── config.h               # Build configuration
├── src/
│   ├── main.cpp               # Entry point, interactive menu, CLI, builder
│   ├── variants.cpp           # All 8 variant implementations
│   ├── handle_hijack.cpp      # Handle enumeration + TP_POOL IoCompletion scan
│   ├── memory_writer.cpp      # Section-backed memory injection
│   ├── amsi_etw.cpp           # AMSI/ETW bypass implementation
│   ├── tartarus.cpp           # SSN extraction engine
│   ├── syscall_manager.cpp    # Trampoline harvesting
│   ├── call_context.cpp       # Call-stack spoofing
│   ├── peb_lookup.cpp         # PEB walking
│   ├── prng.cpp               # PRNG implementation
│   └── syscall_stub.asm       # Indirect syscall ASM stubs (DoSyscallSpoofed)
├── build.bat                  # Build script
├── .gitignore
├── LICENSE
└── README.md
```

## What This Avoids (Detection Surface)

Zero usage of:
- `CreateRemoteThread` / `NtCreateThreadEx` (for injection — V1 trampoline uses `CreateThread` inside the target)
- `NtQueueApcThread` / `NtQueueApcThreadEx`
- `SetThreadContext` / `NtSetContextThread`
- `WriteProcessMemory` for bulk shellcode writes
- Any callback registration API
- Direct ntdll imports
- `GetProcAddress` / `GetModuleHandle`
- Donut's AMSI bypass (`AmsiScanBuffer` patch)

What could potentially detect it:
- Cross-process `NtMapViewOfSection` with execute permissions
- `NtDuplicateObject` cross-process handle duplication patterns
- `NtSetInformationWorkerFactory` with `WorkerFactoryThreadMinimum` changes
- Memory page protection changes on ntdll `.text` section (V1 start routine overwrite)
- I/O completion callback pointer validation against known-good code regions
- Heap integrity checks on amsi.dll's internal structures

## Known Limitations

- **V7 (TP_DIRECT) and V3-V8 blocked by XFG**: On modern Windows 10/11 with eXtended Flow Guard enabled, I/O completion-based variants crash the target with `STATUS_STACK_BUFFER_OVERRUN` (0xC0000409). Use V1 instead.
- **V1 is destructive**: Overwrites `TppWorkerThread`, permanently breaking the target's thread pool. Best for one-shot execution where target stability doesn't matter.
- **IoCompletion handle discovery**: The `WORKER_FACTORY_BASIC_INFORMATION.CompletionPort` field is always 0 on modern Windows. Typhon works around this by scanning the TP_POOL structure for matching handle values (consistently found at `TP_POOL+0x040`).
- **WorkerFactoryThreadMinimum**: The correct info class value is `4`, not `1` as documented in many sources. Value `1` is actually `WorkerFactoryRetryTimeout`.

## References

- [SafeBreach Labs — PoolParty](https://github.com/SafeBreach-Labs/PoolParty) (original research)
- [The Pool Party You Will Never Forget](https://www.blackhat.com/eu-23/briefings/schedule/#the-pool-party-you-will-never-forget-new-process-injection-techniques-using-windows-thread-pools-35446) — Black Hat EU 2023, Alon Leviev
- [Tartarus' Gate](https://github.com/trickster0/TartarusGate) — trickster0
- [SysWhispers](https://github.com/jthuraisamy/SysWhispers) — indirect syscall concept
- [donut](https://github.com/TheWover/donut) — PE to shellcode conversion

## ⚠️ Legal Disclaimer

**IMPORTANT: READ BEFORE USE**

This software is provided for **educational and authorized security research purposes only**. By downloading, compiling, or using this software, you acknowledge and agree to the following:

### Authorized Use Only
- This tool is intended **exclusively** for authorized penetration testing, red team exercises, security research, and educational purposes
- You must have **explicit written permission** from the system owner before using this software
- Use on systems you do not own or lack authorization for is **strictly prohibited**
- This software should only be used in controlled, isolated environments (labs, sandboxes, authorized test networks)

### Legal Compliance
- Users are **solely responsible** for ensuring compliance with all applicable local, state, federal, and international laws
- The authors provide this software "as-is" without any warranties or guarantees
- The authors **disclaim all liability** for any damages, legal consequences, or misuse of this software
- Unauthorized use may violate computer fraud and abuse laws, including but not limited to:
  - Computer Fraud and Abuse Act (CFAA) in the United States
  - Computer Misuse Act in the United Kingdom
  - Similar cybercrime legislation in other jurisdictions

### Ethical Guidelines
- This tool should be used to **improve security**, not to cause harm
- Responsible disclosure practices should be followed when vulnerabilities are discovered
- Do not use this software for malicious purposes, including but not limited to:
  - Unauthorized access to computer systems
  - Data theft or destruction
  - Disruption of services
  - Installation of malware or backdoors

### No Support for Malicious Use
- The authors do not condone, support, or provide assistance for any illegal or unethical use
- Issues, pull requests, or discussions related to malicious use will be immediately closed and reported
- This project may be discontinued if evidence of widespread misuse is discovered

### Academic and Research Use
- Researchers and educators are encouraged to use this tool for legitimate security research
- Please cite this work appropriately in academic publications
- Consider contributing improvements back to the community through responsible disclosure

**By using this software, you acknowledge that you have read, understood, and agree to be bound by these terms. If you do not agree with these terms, do not download, compile, or use this software.**

---

<p align="center">
  <strong>🔐 <a href="https://crypter.cloud">Crypter.cloud</a> & <a href="https://crypter.shop">Crypter.shop</a></strong>
</p>

## License

MIT License - See [LICENSE](LICENSE) file for details.

**Note**: The MIT license applies to the code itself. The legal disclaimer above governs the use of this software and supersedes any conflicting terms in the license regarding liability and authorized use.
