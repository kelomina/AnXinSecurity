; AnXinHypervisor - Intel VMX Assembly Entry/Exit
; Module: native/hypervisor/src/intel/entry_intel.asm
;
; VM-exit entry point: saves all guest GPRs, calls C handler,
; restores GPRs, then executes VMRESUME.
;
; Build: MASM (ml64.exe)

.code

; External C handler (defined in exit_handler.c)
; void AnxHandleVmExit(ULONG CpuNumber, PVOID GuestRegs);
EXTERN AnxHandleVmExit:PROC

; Guest register save area layout (on host stack)
; Offset from RSP after all pushes:
GUEST_RAX     EQU 000h
GUEST_RCX     EQU 008h
GUEST_RDX     EQU 010h
GUEST_RBX     EQU 018h
GUEST_RSP     EQU 020h  ; original RSP (placeholder)
GUEST_RBP     EQU 028h
GUEST_RSI     EQU 030h
GUEST_RDI     EQU 038h
GUEST_R8      EQU 040h
GUEST_R9      EQU 048h
GUEST_R10     EQU 050h
GUEST_R11     EQU 058h
GUEST_R12     EQU 060h
GUEST_R13     EQU 068h
GUEST_R14     EQU 070h
GUEST_R15     EQU 078h
REGS_SIZE     EQU 080h

; ─────────────────────────────────────────────────────────────────────
; AnxVmxExitEntry
;
; VM-exit lands here (set as VMCS Host RIP = 0x6C16).
; At this point:
;   - Guest state is saved in VMCS (RIP, RSP, RFLAGS, segments, etc.)
;   - RAX-R15 contain guest values (NOT saved by hardware to memory)
;   - RSP = Host RSP (from VMCS 0x6C14)
;   - CS/SS/DS/ES = host flat segments
;   - We are in VMX root operation, ring 0, 64-bit mode
;
; Strategy:
;   1. Push all GPRs to create a guest register context on host stack
;   2. Call C handler with pointer to saved registers
;   3. Pop all GPRs (handler may have modified RAX for return values)
;   4. VMRESUME to re-enter guest
; ─────────────────────────────────────────────────────────────────────

AnxVmxExitEntry PROC
    ; Save all guest general-purpose registers
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15

    ; RCX (param1) = CpuNumber (read from per-CPU or use KeGetCurrentProcessorNumber)
    ; For simplicity, pass RSP as guest regs pointer; C handler reads CPU# internally
    ; Param1 (RCX) = pointer to saved guest registers
    mov     rcx, rsp

    ; Align stack to 16 bytes before call (15 pushes = 120 bytes, +8 return = 128, aligned)
    ; Actually 15 * 8 = 120, RSP was 16-aligned at entry, so RSP is now misaligned by 8
    ; Subtract 8 to align
    sub     rsp, 28h            ; Shadow space (32) + alignment (8)

    ; Call C handler: AnxHandleVmExit(PVOID GuestRegs)
    call    AnxHandleVmExit

    add     rsp, 28h

    ; Restore guest GPRs (handler may have modified values via the struct)
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax

    ; Re-enter guest
    vmresume

    ; If VMRESUME fails, we fall through here (should not happen in normal operation)
    int 3
    jmp     $

AnxVmxExitEntry ENDP

; ─────────────────────────────────────────────────────────────────────
; AnxVmxLaunchGuest
;
; Called from C after VMCS is fully configured.
; Sets Guest RIP = return address, Guest RSP = RSP+8, then VMLAUNCH.
; On success: guest "returns" to caller (RAX=0 in guest mode).
; On failure: returns to caller with RAX=1 (still in root mode).
;
; ULONG64 AnxVmxLaunchGuest(void);
; ─────────────────────────────────────────────────────────────────────

AnxVmxLaunchGuest PROC
    ; Write Guest RIP (0x681E) = return address
    mov     rax, [rsp]
    mov     rcx, 0681Eh
    vmwrite rcx, rax

    ; Write Guest RSP (0x681C) = RSP + 8 (guest sees stack after "ret")
    lea     rax, [rsp + 8]
    mov     rcx, 0681Ch
    vmwrite rcx, rax

    ; RAX=0 so guest sees success return value
    xor     eax, eax

    vmlaunch

    ; VMLAUNCH failed — still in root mode, return 1
    mov     rax, 1
    ret
AnxVmxLaunchGuest ENDP

; ─────────────────────────────────────────────────────────────────────
; AnxVmxResumeGuest
;
; Executes VMRESUME. On success, does not return (guest runs).
; On failure, returns to caller with RAX=1.
;
; ULONG64 AnxVmxResumeGuest(void);
; ─────────────────────────────────────────────────────────────────────

AnxVmxResumeGuest PROC
    vmresume
    ; VMRESUME failed
    mov     rax, 1
    ret
AnxVmxResumeGuest ENDP

; ─────────────────────────────────────────────────────────────────────
; AnxVmxVmxonWrapper
;
; Executes VMXON with the given physical address.
; Returns: RAX = 0 on success, 1 on failure.
;
; UCHAR AnxVmxVmxonWrapper(PHYSICAL_ADDRESS* VmxonPa);
; ─────────────────────────────────────────────────────────────────────

AnxVmxVmxonWrapper PROC
    vmxon   QWORD PTR [rcx]
    setna   al          ; CF=1 or ZF=1 means failure
    ret
AnxVmxVmxonWrapper ENDP

; ─────────────────────────────────────────────────────────────────────
; AnxVmxVmxoffWrapper
;
; Executes VMXOFF. Must be in VMX root (outside guest).
;
; void AnxVmxVmxoffWrapper(void);
; ─────────────────────────────────────────────────────────────────────

AnxVmxVmxoffWrapper PROC
    vmxoff
    ret
AnxVmxVmxoffWrapper ENDP

; ─────────────────────────────────────────────────────────────────────
; AnxVmxVmclearWrapper
;
; void AnxVmxVmclearWrapper(PHYSICAL_ADDRESS* VmcsPa);
; ─────────────────────────────────────────────────────────────────────

AnxVmxVmclearWrapper PROC
    vmclear QWORD PTR [rcx]
    ret
AnxVmxVmclearWrapper ENDP

; ─────────────────────────────────────────────────────────────────────
; AnxVmxVmptrldWrapper
;
; void AnxVmxVmptrldWrapper(PHYSICAL_ADDRESS* VmcsPa);
; ─────────────────────────────────────────────────────────────────────

AnxVmxVmptrldWrapper PROC
    vmptrld QWORD PTR [rcx]
    ret
AnxVmxVmptrldWrapper ENDP

; ─────────────────────────────────────────────────────────────────────
; AnxVmxReadStr
;
; Reads the Task Register segment selector.
; USHORT AnxVmxReadStr(void);
; ─────────────────────────────────────────────────────────────────────

AnxVmxReadStr PROC
    str     ax
    ret
AnxVmxReadStr ENDP

; ─────────────────────────────────────────────────────────────────────
; Segment register read wrappers
; USHORT __readcs(void); etc.
; ─────────────────────────────────────────────────────────────────────

__readcs PROC
    mov     ax, cs
    ret
__readcs ENDP

__readss PROC
    mov     ax, ss
    ret
__readss ENDP

__readds PROC
    mov     ax, ds
    ret
__readds ENDP

__reades PROC
    mov     ax, es
    ret
__reades ENDP

__readfs PROC
    mov     ax, fs
    ret
__readfs ENDP

__readgs PROC
    mov     ax, gs
    ret
__readgs ENDP

__readtr PROC
    str     ax
    ret
__readtr ENDP

; ─────────────────────────────────────────────────────────────────────
; INVEPT wrapper
; void __invept(ULONG Type, INVEPT_DESCRIPTOR* Desc);
; RCX = type, RDX = pointer to descriptor
; ─────────────────────────────────────────────────────────────────────

__invept PROC
    invept  rcx, OWORD PTR [rdx]
    ret
__invept ENDP

END
