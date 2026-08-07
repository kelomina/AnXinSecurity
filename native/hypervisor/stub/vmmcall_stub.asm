; AnXinHypervisor - AMD VMMCALL Stub
; Module: native/hypervisor/stub/vmmcall_stub.asm
;
; Linked by AnXinProcProtect.sys to communicate with the hypervisor.
; Identical calling convention to vmcall_stub.asm, but uses VMMCALL
; instruction (opcode: 0F 01 D9) instead of VMCALL (0F 01 C1).
;
; Build: MASM (ml64.exe)

.code

ANX_VMCALL_MAGIC EQU 0414E5848563031h  ; "ANXHV01"

; ─────────────────────────────────────────────────────────────────────
; AnxHvVmmCall
;
; ULONG64 AnxHvVmmCall(ULONG64 Function, ULONG64 Param1,
;                       ULONG64 Param2, ULONG64 Param3);
; ─────────────────────────────────────────────────────────────────────

AnxHvVmmCall PROC
    ; Rearrange registers for VMMCALL convention (same as VMCALL)
    mov     r10, rcx        ; Save function
    mov     r11, rdx        ; Save param1

    mov     rax, ANX_VMCALL_MAGIC
    mov     rbx, r10        ; RBX = function
    mov     rcx, r11        ; RCX = param1
    mov     rdx, r8         ; RDX = param2
    mov     r8, r9          ; R8  = param3

    ; Execute VMMCALL (opcode: 0F 01 D9)
    vmmcall

    ; Return: RAX = status
    ret

AnxHvVmmCall ENDP

END
