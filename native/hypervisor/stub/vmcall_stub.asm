; AnXinHypervisor - Intel VMCALL Stub
; Module: native/hypervisor/stub/vmcall_stub.asm
;
; Linked by AnXinProcProtect.sys to communicate with the hypervisor.
; Calling convention:
;   RCX = function code
;   RDX = param1
;   R8  = param2
;   R9  = param3
;   Returns: RAX = status (0 = success)
;
; Build: MASM (ml64.exe)

.code

ANX_VMCALL_MAGIC EQU 0414E5848563031h  ; "ANXHV01"

; ─────────────────────────────────────────────────────────────────────
; AnxHvVmxCall
;
; ULONG64 AnxHvVmxCall(ULONG64 Function, ULONG64 Param1,
;                       ULONG64 Param2, ULONG64 Param3);
;
; Registers on entry (Windows x64 calling convention):
;   RCX = Function
;   RDX = Param1
;   R8  = Param2
;   R9  = Param3
;
; VMCALL convention:
;   RAX = magic
;   RBX = function
;   RCX = param1
;   RDX = param2
;   R8  = param3
;
; Returns: RAX = status, RBX = output size
; ─────────────────────────────────────────────────────────────────────

AnxHvVmxCall PROC
    ; Rearrange registers for VMCALL convention
    mov     r10, rcx        ; Save function (RCX will be overwritten)
    mov     r11, rdx        ; Save param1

    mov     rax, ANX_VMCALL_MAGIC
    mov     rbx, r10        ; RBX = function
    mov     rcx, r11        ; RCX = param1
    mov     rdx, r8         ; RDX = param2
    mov     r8, r9          ; R8  = param3

    ; Execute VMCALL (opcode: 0F 01 C1)
    vmcall

    ; Return: RAX = status (already in RAX)
    ret

AnxHvVmxCall ENDP

END
