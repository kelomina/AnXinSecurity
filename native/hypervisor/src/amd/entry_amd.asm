; AnXinHypervisor - AMD SVM Assembly Entry/Exit
; Module: native/hypervisor/src/amd/entry_amd.asm
;
; VMEXIT entry: saves RBX-R15 (NOT auto-saved by hardware),
; calls C handler, restores GPRs, re-enters guest via VMRUN.
;
; Key AMD difference: VMCB only saves RAX, RIP, RSP, RFLAGS, segments.
; RBX-R15 remain in physical registers after VMEXIT and must be
; manually preserved before any C call.
;
; Build: MASM (ml64.exe)

.code

; External C handler
; void AnxSvmHandleExit(ULONG64 VmcbPa);
EXTERN AnxSvmHandleExit:PROC

; ─────────────────────────────────────────────────────────────────────
; AnxSvmExitEntry
;
; After VMRUN returns (VMEXIT occurred):
;   - RAX = VMCB physical address (hardware behavior)
;   - RBX-R15 = guest values (hardware does NOT save them)
;   - RSP = host RSP (restored from host save area)
;   - RIP = instruction after VMRUN (host RIP from save area)
;   - Guest state (RAX, RIP, RSP, RFLAGS, segments) written to VMCB
;
; We must immediately save RBX-R15 before calling any C code.
; ─────────────────────────────────────────────────────────────────────

AnxSvmExitEntry PROC
    ; Save VMCB PA (RAX will be clobbered by C calls)
    push    rax                 ; [rsp+0] = VMCB PA

    ; Save guest GPRs (VMCB does not contain RBX-R15)
    push    rbx
    push    rcx
    push    rdx
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

    ; Pass VMCB PA to C handler
    ; After 15 pushes, VMCB PA is at [rsp + 15*8] = [rsp + 120]
    mov     rcx, [rsp + 15*8]  ; param1 = VMCB physical address

    ; Align stack and provide shadow space
    sub     rsp, 28h
    call    AnxSvmHandleExit
    add     rsp, 28h

    ; Restore guest GPRs
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
    pop     rdx
    pop     rcx
    pop     rbx

    ; Restore VMCB PA to RAX (VMRUN requires RAX = VMCB physical address)
    pop     rax

    ; Re-enter guest
    vmrun   rax

    ; VMEXIT lands here (host RIP = next instruction after VMRUN).
    ; Loop back to handle the next exit.
    jmp     AnxSvmExitEntry

AnxSvmExitEntry ENDP

; ─────────────────────────────────────────────────────────────────────
; AnxSvmRunGuest
;
; Initial VMRUN entry from C code (transparent hypervisor).
; Sets Guest RIP = return address, Guest RSP = caller's RSP,
; so the guest (host OS) continues as if VMRUN was a NOP.
; After VMEXIT, jumps to AnxSvmExitEntry loop.
;
; void AnxSvmRunGuest(PVOID VmcbVa, PVOID VmcbPa);
;   RCX = VMCB virtual address (for memory writes)
;   RDX = VMCB physical address (for VMRUN instruction)
; ─────────────────────────────────────────────────────────────────────

AnxSvmRunGuest PROC
    ; Update CR3 in VMCB (may differ from Stage 1 capture)
    mov     rax, cr3
    mov     [rcx + 550h], rax   ; VMCB StateSave.CR3

    ; Set Guest RIP = return address (VMCB StateSave.Rip at offset 0x578)
    mov     rax, [rsp]          ; return address = where guest continues
    mov     [rcx + 578h], rax   ; write via virtual address

    ; Set Guest RSP = RSP + 8 (skip return address) (StateSave.Rsp at 0x5D8)
    lea     rax, [rsp + 8]
    mov     [rcx + 5D8h], rax   ; write via virtual address

    ; RAX must = VMCB physical address for VMRUN
    mov     rax, rdx

    ; Execute VMRUN - enters guest
    vmrun   rax

    ; === VMEXIT lands here ===
    ; RAX = VMCB PA (hardware), RBX-R15 = guest values, RSP = host RSP
    jmp     AnxSvmExitEntry

AnxSvmRunGuest ENDP

; ─────────────────────────────────────────────────────────────────────
; AnxSvmVmload
;
; Executes VMLOAD: loads FS/GS/TR/LDTR/KernelGsBase from VMCB.
; Must be called before VMRUN to set up host segment state.
;
; void AnxSvmVmload(PVOID VmcbPa);
; ─────────────────────────────────────────────────────────────────────

AnxSvmVmload PROC
    mov     rax, rcx
    vmload  rax
    ret
AnxSvmVmload ENDP

; ─────────────────────────────────────────────────────────────────────
; AnxSvmVmsave
;
; Executes VMSAVE: saves FS/GS/TR/LDTR/KernelGsBase to VMCB.
;
; void AnxSvmVmsave(PVOID VmcbPa);
; ─────────────────────────────────────────────────────────────────────

AnxSvmVmsave PROC
    mov     rax, rcx
    vmsave  rax
    ret
AnxSvmVmsave ENDP

; ─────────────────────────────────────────────────────────────────────
; AnxSvmInvlpga
;
; Executes INVLPGA: invalidates TLB entries for a given ASID.
;
; void AnxSvmInvlpga(PVOID Gva, ULONG Asid);
;   RCX = GVA (or 0 for full ASID flush)
;   RDX = ASID
; ─────────────────────────────────────────────────────────────────────

AnxSvmInvlpga PROC
    mov     rax, rcx        ; RAX = GVA
    mov     ecx, edx        ; ECX = ASID
    invlpga rax, ecx
    ret
AnxSvmInvlpga ENDP

; MSVC intrinsic name wrapper
__invlpga PROC
    mov     rax, rcx        ; RAX = GVA
    mov     ecx, edx        ; ECX = ASID
    invlpga rax, ecx
    ret
__invlpga ENDP

; ─────────────────────────────────────────────────────────────────────
; AnxSvmReadTr / AnxSvmReadLdtr
;
; Return the current TR / LDTR selector value.
; USHORT AnxSvmReadTr(VOID);
; USHORT AnxSvmReadLdtr(VOID);
; ─────────────────────────────────────────────────────────────────────

AnxSvmReadTr PROC
    xor     eax, eax
    str     ax
    ret
AnxSvmReadTr ENDP

AnxSvmReadLdtr PROC
    xor     eax, eax
    sldt    ax
    ret
AnxSvmReadLdtr ENDP

END
