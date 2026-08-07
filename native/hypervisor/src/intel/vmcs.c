/*
 * AnXinHypervisor - Intel VMCS Field Access
 * Module: native/hypervisor/src/intel/vmcs.c
 *
 * Thin wrappers around VMREAD/VMWRITE with error checking.
 * VMCS field encodings per Intel SDM Vol.3C Appendix B.
 */

#include "../../include/platform.h"
#include "../../include/per_cpu.h"

extern VOID AnxDebugPrint(const char* Fmt, ...);

/* ─── VMCS Field Encodings ────────────────────────────────────────── */

/* 16-bit control fields */
#define VMCS_CTRL_VPID                  0x0000

/* 16-bit guest-state fields */
#define VMCS_GUEST_ES_SEL               0x0800
#define VMCS_GUEST_CS_SEL               0x0802
#define VMCS_GUEST_SS_SEL               0x0804
#define VMCS_GUEST_DS_SEL               0x0806
#define VMCS_GUEST_FS_SEL               0x0808
#define VMCS_GUEST_GS_SEL               0x080A
#define VMCS_GUEST_LDTR_SEL             0x080C
#define VMCS_GUEST_TR_SEL               0x080E

/* 16-bit host-state fields */
#define VMCS_HOST_ES_SEL                0x0C00
#define VMCS_HOST_CS_SEL                0x0C02
#define VMCS_HOST_SS_SEL                0x0C04
#define VMCS_HOST_DS_SEL                0x0C06
#define VMCS_HOST_FS_SEL                0x0C08
#define VMCS_HOST_GS_SEL                0x0C0A
#define VMCS_HOST_TR_SEL                0x0C0C

/* 64-bit control fields */
#define VMCS_CTRL_IO_BITMAP_A           0x2000
#define VMCS_CTRL_IO_BITMAP_B           0x2002
#define VMCS_CTRL_MSR_BITMAP            0x2004
#define VMCS_CTRL_TSC_OFFSET            0x2010
#define VMCS_CTRL_EPTP                  0x201A

/* 64-bit guest-state fields */
#define VMCS_CTRL_VMCS_LINK_POINTER     0x2800
#define VMCS_GUEST_IA32_DEBUGCTL        0x2802
#define VMCS_GUEST_IA32_PAT             0x2804
#define VMCS_GUEST_IA32_EFER            0x2806

/* 64-bit host-state fields */
#define VMCS_HOST_IA32_PAT              0x2C00
#define VMCS_HOST_IA32_EFER             0x2C02

/* 32-bit control fields */
#define VMCS_CTRL_PIN_BASED             0x4000
#define VMCS_CTRL_PROC_BASED            0x4002
#define VMCS_CTRL_EXCEPTION_BITMAP      0x4004
#define VMCS_CTRL_PAGEFAULT_ERROR_MASK  0x4006
#define VMCS_CTRL_PAGEFAULT_ERROR_MATCH 0x4008
#define VMCS_CTRL_CR3_TARGET_COUNT      0x400A
#define VMCS_CTRL_VMEXIT_CONTROLS       0x400C
#define VMCS_CTRL_VMEXIT_MSR_STORE_CNT  0x400E
#define VMCS_CTRL_VMEXIT_MSR_LOAD_CNT   0x4010
#define VMCS_CTRL_VMENTRY_CONTROLS      0x4012
#define VMCS_CTRL_VMENTRY_MSR_LOAD_CNT  0x4014
#define VMCS_CTRL_VMENTRY_INTR_INFO     0x4016
#define VMCS_CTRL_VMENTRY_EXCEPTION_ERR 0x4018
#define VMCS_CTRL_VMENTRY_INSTR_LEN     0x401A
#define VMCS_CTRL_SECONDARY_PROC_BASED  0x401E

/* 32-bit read-only fields */
#define VMCS_RO_VMEXIT_REASON           0x4402
#define VMCS_RO_VMEXIT_INTR_INFO        0x4404
#define VMCS_RO_VMEXIT_INTR_ERROR       0x4406
#define VMCS_RO_IDT_VECTORING_INFO      0x4408
#define VMCS_RO_IDT_VECTORING_ERROR     0x440A
#define VMCS_RO_VMEXIT_INSTR_LEN        0x440C
#define VMCS_RO_VMEXIT_INSTR_INFO       0x440E

/* Natural-width control fields */
#define VMCS_CTRL_CR0_GUEST_HOST_MASK   0x6000
#define VMCS_CTRL_CR4_GUEST_HOST_MASK   0x6002
#define VMCS_CTRL_CR0_READ_SHADOW       0x6004
#define VMCS_CTRL_CR4_READ_SHADOW       0x6006
#define VMCS_CTRL_CR3_TARGET_VALUE0     0x6008

/* Natural-width read-only fields */
#define VMCS_RO_EXIT_QUALIFICATION      0x6400
#define VMCS_RO_GUEST_PHYSICAL_ADDR     0x2400

/* 32-bit guest-state fields */
#define VMCS_GUEST_ES_LIMIT             0x4800
#define VMCS_GUEST_CS_LIMIT             0x4802
#define VMCS_GUEST_SS_LIMIT             0x4804
#define VMCS_GUEST_DS_LIMIT             0x4806
#define VMCS_GUEST_FS_LIMIT             0x4808
#define VMCS_GUEST_GS_LIMIT             0x480A
#define VMCS_GUEST_LDTR_LIMIT           0x480C
#define VMCS_GUEST_TR_LIMIT             0x480E
#define VMCS_GUEST_GDTR_LIMIT           0x4810
#define VMCS_GUEST_IDTR_LIMIT           0x4812
#define VMCS_GUEST_ES_ACCESS            0x4814
#define VMCS_GUEST_CS_ACCESS            0x4816
#define VMCS_GUEST_SS_ACCESS            0x4818
#define VMCS_GUEST_DS_ACCESS            0x481A
#define VMCS_GUEST_FS_ACCESS            0x481C
#define VMCS_GUEST_GS_ACCESS            0x481E
#define VMCS_GUEST_LDTR_ACCESS          0x4820
#define VMCS_GUEST_TR_ACCESS            0x4822
#define VMCS_GUEST_INTERRUPTIBILITY     0x4824
#define VMCS_GUEST_ACTIVITY_STATE       0x4826

/* Natural-width guest-state fields */
#define VMCS_GUEST_CR0                  0x6800
#define VMCS_GUEST_CR3                  0x6802
#define VMCS_GUEST_CR4                  0x6804
#define VMCS_GUEST_ES_BASE              0x6806
#define VMCS_GUEST_CS_BASE              0x6808
#define VMCS_GUEST_SS_BASE              0x680A
#define VMCS_GUEST_DS_BASE              0x680C
#define VMCS_GUEST_FS_BASE              0x680E
#define VMCS_GUEST_GS_BASE              0x6810
#define VMCS_GUEST_LDTR_BASE            0x6812
#define VMCS_GUEST_TR_BASE              0x6814
#define VMCS_GUEST_GDTR_BASE            0x6816
#define VMCS_GUEST_IDTR_BASE            0x6818
#define VMCS_GUEST_DR7                  0x681A
#define VMCS_GUEST_RSP                  0x681C
#define VMCS_GUEST_RIP                  0x681E
#define VMCS_GUEST_RFLAGS               0x6820

/* Natural-width host-state fields */
#define VMCS_HOST_CR0                   0x6C00
#define VMCS_HOST_CR3                   0x6C02
#define VMCS_HOST_CR4                   0x6C04
#define VMCS_HOST_FS_BASE               0x6C06
#define VMCS_HOST_GS_BASE               0x6C08
#define VMCS_HOST_TR_BASE               0x6C0A
#define VMCS_HOST_GDTR_BASE             0x6C0C
#define VMCS_HOST_IDTR_BASE             0x6C0E
#define VMCS_HOST_SYSENTER_CS           0x4C00
#define VMCS_HOST_SYSENTER_ESP          0x6C10
#define VMCS_HOST_SYSENTER_EIP          0x6C12
#define VMCS_HOST_RSP                   0x6C14
#define VMCS_HOST_RIP                   0x6C16

/* ─── Access Functions ────────────────────────────────────────────── */

ULONG64
VmcsRead(
    ULONG32 FieldEncoding
)
{
    size_t value = 0;
    __vmx_vmread((size_t)FieldEncoding, &value);
    return (ULONG64)value;
}

VOID
VmcsWrite(
    ULONG32 FieldEncoding,
    ULONG64 Value
)
{
    __vmx_vmwrite((size_t)FieldEncoding, (size_t)Value);
}

VOID
VmcsWrite64(
    ULONG32 FieldEncoding,
    ULONG64 Value
)
{
    /* 64-bit fields: write low and high halves */
    __vmx_vmwrite((size_t)FieldEncoding, (size_t)(Value & 0xFFFFFFFF));
    __vmx_vmwrite((size_t)(FieldEncoding + 1), (size_t)(Value >> 32));
}

ULONG64
VmcsRead64(
    ULONG32 FieldEncoding
)
{
    size_t lo = 0, hi = 0;
    __vmx_vmread((size_t)FieldEncoding, &lo);
    __vmx_vmread((size_t)(FieldEncoding + 1), &hi);
    return ((ULONG64)hi << 32) | (ULONG64)(ULONG32)lo;
}

/* ─── VMCS Setup ──────────────────────────────────────────────────── */

/* Declared in entry_intel.asm */
extern VOID AnxVmxExitEntry(VOID);

/*
 * Fill all VMCS fields for initial VM-entry.
 * Captures current CPU state as "guest state" (the OS becomes the guest).
 */
NTSTATUS
AnxVmxSetupVmcs(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    ULONG64 cr0, cr3, cr4, rflags, rsp;
    ULONG64 efer;
    USHORT cs, ss, ds, es, fs, gs, tr;
    ULONG64 vmxPinBased, vmxProcBased, vmxExitCtrl, vmxEntryCtrl;
    ULONG32 pinBased, procBased, secProcBased, exitCtrl, entryCtrl;

    /* Read current CPU state (this becomes guest state) */
    cr0 = __readcr0();
    cr3 = __readcr3();
    cr4 = __readcr4();
    rflags = __readeflags();
    rsp = (ULONG64)_AddressOfReturnAddress() + 8; /* Approximate guest RSP */
    efer = __readmsr(ANX_MSR_IA32_EFER);

    cs = __readcs();
    ss = __readss();
    ds = __readds();
    es = __reades();
    fs = __readfs();
    gs = __readgs();

    /* Read TR (task register selector) */
    tr = __readtr();

    /* ─── Guest State ─── */
    VmcsWrite64(VMCS_CTRL_VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFFULL);
    VmcsWrite(VMCS_GUEST_CR0, cr0);
    VmcsWrite(VMCS_GUEST_CR3, cr3);
    VmcsWrite(VMCS_GUEST_CR4, cr4);
    VmcsWrite(VMCS_GUEST_DR7, __readdr(7));
    VmcsWrite64(VMCS_GUEST_IA32_DEBUGCTL, __readmsr(0x1D9));
    VmcsWrite64(VMCS_GUEST_IA32_EFER, efer);
    VmcsWrite(VMCS_GUEST_RSP, rsp);
    VmcsWrite(VMCS_GUEST_RFLAGS, rflags);
    /* Guest RIP and RSP are finalized in AnxVmxLaunchGuest (asm) right before VMLAUNCH */

    /* Guest segments */
    VmcsWrite(VMCS_GUEST_CS_SEL, cs);
    VmcsWrite(VMCS_GUEST_SS_SEL, ss);
    VmcsWrite(VMCS_GUEST_DS_SEL, ds);
    VmcsWrite(VMCS_GUEST_ES_SEL, es);
    VmcsWrite(VMCS_GUEST_FS_SEL, fs);
    VmcsWrite(VMCS_GUEST_GS_SEL, gs);
    VmcsWrite(VMCS_GUEST_TR_SEL, tr);

    /* Guest segment bases (flat model for CS/SS/DS/ES) */
    VmcsWrite(VMCS_GUEST_CS_BASE, 0);
    VmcsWrite(VMCS_GUEST_SS_BASE, 0);
    VmcsWrite(VMCS_GUEST_DS_BASE, 0);
    VmcsWrite(VMCS_GUEST_ES_BASE, 0);
    VmcsWrite(VMCS_GUEST_FS_BASE, __readmsr(0xC0000100)); /* IA32_FS_BASE */
    VmcsWrite(VMCS_GUEST_GS_BASE, __readmsr(0xC0000101)); /* IA32_GS_BASE */

    /* Guest segment limits */
    VmcsWrite(VMCS_GUEST_ES_LIMIT, 0xFFFFFFFF);
    VmcsWrite(VMCS_GUEST_CS_LIMIT, 0xFFFFFFFF);
    VmcsWrite(VMCS_GUEST_SS_LIMIT, 0xFFFFFFFF);
    VmcsWrite(VMCS_GUEST_DS_LIMIT, 0xFFFFFFFF);
    VmcsWrite(VMCS_GUEST_FS_LIMIT, 0xFFFFFFFF);
    VmcsWrite(VMCS_GUEST_GS_LIMIT, 0xFFFFFFFF);

    /* Guest segment access rights */
    VmcsWrite(VMCS_GUEST_CS_ACCESS, 0xA09B);  /* type=B, S=1, DPL=0, P=1, L=1 */
    VmcsWrite(VMCS_GUEST_SS_ACCESS, 0xC093);  /* type=3, S=1, DPL=0, P=1, DB=1 */
    VmcsWrite(VMCS_GUEST_DS_ACCESS, 0xC093);
    VmcsWrite(VMCS_GUEST_ES_ACCESS, 0xC093);
    VmcsWrite(VMCS_GUEST_FS_ACCESS, 0xC093);
    VmcsWrite(VMCS_GUEST_GS_ACCESS, 0xC093);

    /* Guest GDTR/IDTR base and limit */
    {
        UCHAR gdtr[10], idtr[10];
        _sgdt(gdtr);
        __sidt(idtr);
        VmcsWrite(VMCS_GUEST_GDTR_BASE, *(PULONG64)(gdtr + 2));
        VmcsWrite(VMCS_GUEST_IDTR_BASE, *(PULONG64)(idtr + 2));
        VmcsWrite(VMCS_GUEST_GDTR_LIMIT, (ULONG64)(*(PUSHORT)gdtr));
        VmcsWrite(VMCS_GUEST_IDTR_LIMIT, (ULONG64)(*(PUSHORT)idtr));
    }

    VmcsWrite(VMCS_GUEST_INTERRUPTIBILITY, 0);
    VmcsWrite(VMCS_GUEST_ACTIVITY_STATE, 0);

    /* ─── Host State ─── */
    VmcsWrite(VMCS_HOST_CR0, cr0);  /* Must have PE+PG+NE */
    VmcsWrite(VMCS_HOST_CR3, cr3);  /* Use same page tables (hypervisor shares) */
    VmcsWrite(VMCS_HOST_CR4, cr4);  /* Must have VMXE */
    VmcsWrite(VMCS_HOST_RSP, (ULONG64)perCpu->HostStackTop);
    VmcsWrite(VMCS_HOST_RIP, (ULONG64)AnxVmxExitEntry);
    VmcsWrite64(VMCS_HOST_IA32_EFER, efer);

    /* Host segments: use current selectors (must be valid ring-0 GDT entries) */
    VmcsWrite(VMCS_HOST_CS_SEL, cs);
    VmcsWrite(VMCS_HOST_SS_SEL, ss);
    VmcsWrite(VMCS_HOST_DS_SEL, ds);
    VmcsWrite(VMCS_HOST_ES_SEL, es);
    VmcsWrite(VMCS_HOST_FS_SEL, fs);
    VmcsWrite(VMCS_HOST_GS_SEL, gs);
    VmcsWrite(VMCS_HOST_TR_SEL, tr);

    /* Host segment bases */
    VmcsWrite(VMCS_HOST_FS_BASE, __readmsr(0xC0000100));
    VmcsWrite(VMCS_HOST_GS_BASE, __readmsr(0xC0000101));
    {
        UCHAR gdtr[10], idtr[10];
        _sgdt(gdtr);
        __sidt(idtr);
        VmcsWrite(VMCS_HOST_GDTR_BASE, *(PULONG64)(gdtr + 2));
        VmcsWrite(VMCS_HOST_IDTR_BASE, *(PULONG64)(idtr + 2));
    }
    /* TR base: parse 64-bit TSS descriptor from GDT */
    {
        UCHAR gdtr[10];
        PUCHAR desc;
        ULONG64 trBase;
        _sgdt(gdtr);
        desc = (PUCHAR)(*(PULONG64)(gdtr + 2)) + (tr & 0xFFF8);
        trBase = ((ULONG64)desc[2]) | ((ULONG64)desc[3] << 8) |
                 ((ULONG64)desc[4] << 16) | ((ULONG64)desc[7] << 24) |
                 ((ULONG64)(*(PULONG32)(desc + 8)) << 32);
        VmcsWrite(VMCS_HOST_TR_BASE, trBase);
    }

    /* Host SYSENTER (required by VMX spec) */
    VmcsWrite(VMCS_HOST_SYSENTER_CS, __readmsr(0x174));
    VmcsWrite(VMCS_HOST_SYSENTER_ESP, __readmsr(0x175));
    VmcsWrite(VMCS_HOST_SYSENTER_EIP, __readmsr(0x176));

    /* ─── Execution Controls ─── */

    /* Read capability MSRs to determine allowed 0/1 settings */
    vmxPinBased = __readmsr(0x481);  /* IA32_VMX_PINBASED_CTLS */
    vmxProcBased = __readmsr(0x482); /* IA32_VMX_PROCBASED_CTLS */
    vmxExitCtrl = __readmsr(0x483);  /* IA32_VMX_EXIT_CTLS */
    vmxEntryCtrl = __readmsr(0x484); /* IA32_VMX_ENTRY_CTLS */

    /* Pin-based: external-interrupt exiting (bit 0) */
    pinBased = (ULONG32)(vmxPinBased >> 32);  /* Allowed 0-settings */
    pinBased |= 0x1;  /* Set bit 0 */

    /* Primary processor-based: activate secondary controls (bit 31) */
    procBased = (ULONG32)(vmxProcBased >> 32);
    procBased |= (1UL << 31);  /* Activate secondary controls */
    procBased |= (1UL << 7);   /* HLT exiting (reduce exits) */

    /* Secondary processor-based: EPT (bit 1) + VPID (bit 5) */
    secProcBased = (1UL << 1) | (1UL << 5);

    /* Exit controls: Host address space size = 64-bit (bit 9) */
    exitCtrl = (ULONG32)(vmxExitCtrl >> 32);
    exitCtrl |= (1UL << 9);   /* IA-32e mode host */
    exitCtrl |= (1UL << 12);  /* Acknowledge interrupt on exit */

    /* Entry controls: IA-32e mode guest (bit 9) + load IA32_EFER (bit 15) */
    entryCtrl = (ULONG32)(vmxEntryCtrl >> 32);
    entryCtrl |= (1UL << 9);   /* IA-32e mode guest */
    entryCtrl |= (1UL << 15);  /* Load IA32_EFER */

    VmcsWrite(VMCS_CTRL_PIN_BASED, pinBased);
    VmcsWrite(VMCS_CTRL_PROC_BASED, procBased);
    VmcsWrite(VMCS_CTRL_SECONDARY_PROC_BASED, secProcBased);
    VmcsWrite(VMCS_CTRL_VMEXIT_CONTROLS, exitCtrl);
    VmcsWrite(VMCS_CTRL_VMENTRY_CONTROLS, entryCtrl);

    /* Exception bitmap: #MC (bit 18) always intercepted */
    VmcsWrite(VMCS_CTRL_EXCEPTION_BITMAP, (1UL << 18));

    /* CR4 guest/host mask: intercept VMXE (bit 13) modifications */
    VmcsWrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, ANX_CR4_VMXE);
    VmcsWrite(VMCS_CTRL_CR4_READ_SHADOW, cr4);  /* Guest sees VMXE as set */

    /* VPID */
    VmcsWrite(VMCS_CTRL_VPID, (ULONG64)(CpuNumber + 1));

    /* EPTP: write the pre-computed EPT pointer from page table init */
    if (perCpu->PageTablePointer != 0) {
        VmcsWrite64(VMCS_CTRL_EPTP, perCpu->PageTablePointer);
    } else {
        /* EPT not available: disable EPT bit in secondary controls */
        secProcBased &= ~(1UL << 1);
        VmcsWrite(VMCS_CTRL_SECONDARY_PROC_BASED, secProcBased);
        AnxDebugPrint("[HV:WRN] CPU %d: EPT not available, running without EPT\n",
                      (ULONG64)CpuNumber);
    }

    AnxDebugPrint("[HV:DBG] CPU %d: VMCS configured (pin=0x%x proc=0x%x sec=0x%x)\n",
                  (ULONG64)CpuNumber, (ULONG64)pinBased, (ULONG64)procBased,
                  (ULONG64)secProcBased);
    return STATUS_SUCCESS;
}
