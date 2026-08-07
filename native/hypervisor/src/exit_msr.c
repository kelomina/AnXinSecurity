/*
 * AnXinHypervisor - MSR Exit Handler
 * Module: native/hypervisor/src/exit_msr.c
 *
 * Handles RDMSR/WRMSR VM-exits for intercepted MSRs.
 *
 * Intercepted MSRs (write-protected):
 *   - IA32_LSTAR (0x176): syscall entry point (prevent SSDT hook)
 *   - IA32_CSTAR (0x178): 32-bit syscall entry
 *   - IA32_FEATURE_CONTROL (0x3A): return locked+enabled to hide VMX
 *   - IA32_VMX_BASIC (0x480) - IA32_VMX_VMFUNC (0x491): virtualize VMX MSRs
 *   - IA32_EFER (0xC0000080): prevent clearing NXE/SVME
 *
 * For reads: return virtualized values.
 * For writes: validate and either allow or silently drop.
 */

#include "../include/platform.h"
#include "../include/hal.h"
#include "../include/per_cpu.h"
#include "../include/exit_reasons.h"

extern VOID AnxDebugPrint(const char* Fmt, ...);
extern ANX_CPU_VENDOR g_CpuVendor;

/* MSR indices */
#define MSR_IA32_FEATURE_CONTROL    0x0000003A
#define MSR_IA32_VMX_BASIC          0x00000480
#define MSR_IA32_VMX_PINBASED       0x00000481
#define MSR_IA32_VMX_PROCBASED      0x00000482
#define MSR_IA32_VMX_EXIT_CTLS      0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS     0x00000484
#define MSR_IA32_VMX_MISC           0x00000485
#define MSR_IA32_VMX_CR0_FIXED0     0x00000486
#define MSR_IA32_VMX_CR0_FIXED1     0x00000487
#define MSR_IA32_VMX_CR4_FIXED0     0x00000488
#define MSR_IA32_VMX_CR4_FIXED1     0x00000489
#define MSR_IA32_VMX_VMCS_ENUM      0x0000048A
#define MSR_IA32_VMX_PROCBASED2     0x0000048B
#define MSR_IA32_VMX_EPT_VPID_CAP  0x0000048C
#define MSR_IA32_VMX_TRUE_PINBASED  0x0000048D
#define MSR_IA32_VMX_TRUE_PROCBASED 0x0000048E
#define MSR_IA32_VMX_TRUE_EXIT      0x0000048F
#define MSR_IA32_VMX_TRUE_ENTRY     0x00000490
#define MSR_IA32_VMX_VMFUNC         0x00000491
#define MSR_IA32_LSTAR              0x00000176
#define MSR_IA32_CSTAR              0x00000178
#define MSR_IA32_EFER               0xC0000080

/* IA32_FEATURE_CONTROL bits */
#define FEATURE_CONTROL_LOCK        (1ULL << 0)
#define FEATURE_CONTROL_VMXON_SMX   (1ULL << 1)
#define FEATURE_CONTROL_VMXON_NO_SMX (1ULL << 2)

/*
 * Handle an MSR read/write exit.
 *
 * Intel: MSR index in guest RCX, value in RAX(low)+RDX(high).
 * AMD: MSR index in guest RCX (VMCB or stack), EXITINFO1 bit 0 = write.
 */
VOID
AnxHandleMsrExit(
    _In_ ULONG CpuNumber,
    _In_ BOOLEAN IsWrite
)
{
    ULONG64 msrIndex;
    ULONG64 readValueLow = 0, readValueHigh = 0;
    ULONG64 writeValueLow, writeValueHigh;
    BOOLEAN handled = FALSE;

    /* Get MSR index from guest RCX */
    msrIndex = g_HvOps.GetGuestReg(CpuNumber, ANX_REG_RCX);

    /* For writes, get the value from RAX (low) + RDX (high) */
    writeValueLow = g_HvOps.GetGuestReg(CpuNumber, ANX_REG_RAX);
    writeValueHigh = g_HvOps.GetGuestReg(CpuNumber, ANX_REG_RDX);

    switch (msrIndex) {

    /* ─── IA32_FEATURE_CONTROL: hide VMX enablement ─── */
    case MSR_IA32_FEATURE_CONTROL:
        if (!IsWrite) {
            /* Return: locked + VMX enabled (appears normal) */
            readValueLow = FEATURE_CONTROL_LOCK | FEATURE_CONTROL_VMXON_NO_SMX;
            readValueHigh = 0;
            handled = TRUE;
        } else {
            /* Silently drop writes (MSR is locked) */
            handled = TRUE;
        }
        break;

    /* ─── VMX capability MSRs: virtualize to hide hypervisor ─── */
    case MSR_IA32_VMX_BASIC:
    case MSR_IA32_VMX_PINBASED:
    case MSR_IA32_VMX_PROCBASED:
    case MSR_IA32_VMX_EXIT_CTLS:
    case MSR_IA32_VMX_ENTRY_CTLS:
    case MSR_IA32_VMX_MISC:
    case MSR_IA32_VMX_CR0_FIXED0:
    case MSR_IA32_VMX_CR0_FIXED1:
    case MSR_IA32_VMX_CR4_FIXED0:
    case MSR_IA32_VMX_CR4_FIXED1:
    case MSR_IA32_VMX_VMCS_ENUM:
    case MSR_IA32_VMX_PROCBASED2:
    case MSR_IA32_VMX_EPT_VPID_CAP:
    case MSR_IA32_VMX_TRUE_PINBASED:
    case MSR_IA32_VMX_TRUE_PROCBASED:
    case MSR_IA32_VMX_TRUE_EXIT:
    case MSR_IA32_VMX_TRUE_ENTRY:
    case MSR_IA32_VMX_VMFUNC:
        if (!IsWrite) {
            /* Passthrough: read physical MSR value */
            ULONG64 val = __readmsr((ULONG)msrIndex);
            readValueLow = val & 0xFFFFFFFF;
            readValueHigh = val >> 32;
            handled = TRUE;
        } else {
            /* VMX MSRs are read-only: drop writes */
            handled = TRUE;
        }
        break;

    /* ─── IA32_LSTAR / IA32_CSTAR: syscall entry protection ─── */
    case MSR_IA32_LSTAR:
    case MSR_IA32_CSTAR:
        if (IsWrite) {
            /* Log the modification attempt (potential SSDT hook) */
            ULONG64 currentVal = __readmsr((ULONG)msrIndex);
            ULONG64 newVal = writeValueLow | (writeValueHigh << 32);

            if (newVal != currentVal) {
                AnxDebugPrint("[HV:WRN] CPU %d: IA32_LSTAR/CSTAR modification 0x%p → 0x%p\n",
                              (ULONG64)CpuNumber, currentVal, newVal);
            }
            /* Allow the write (Windows legitimately updates this on patch) */
            __writemsr((ULONG)msrIndex, newVal);
            handled = TRUE;
        } else {
            ULONG64 val = __readmsr((ULONG)msrIndex);
            readValueLow = val & 0xFFFFFFFF;
            readValueHigh = val >> 32;
            handled = TRUE;
        }
        break;

    /* ─── IA32_EFER: prevent clearing NXE or SVME ─── */
    case MSR_IA32_EFER:
        if (IsWrite) {
            ULONG64 newVal = writeValueLow | (writeValueHigh << 32);
            ULONG64 currentVal = __readmsr(MSR_IA32_EFER);

            /* Ensure NXE stays set */
            newVal |= (currentVal & ANX_EFER_NXE);

            /* AMD: ensure SVME stays set */
            if (g_CpuVendor == ANX_CPU_AMD) {
                newVal |= ANX_EFER_SVME;
            }

            __writemsr(MSR_IA32_EFER, newVal);
            handled = TRUE;
        } else {
            ULONG64 val = __readmsr(MSR_IA32_EFER);
            /* Hide SVME bit from guest on AMD */
            if (g_CpuVendor == ANX_CPU_AMD) {
                val &= ~ANX_EFER_SVME;
            }
            readValueLow = val & 0xFFFFFFFF;
            readValueHigh = val >> 32;
            handled = TRUE;
        }
        break;

    default:
        /* Unhandled MSR: passthrough to physical hardware */
        if (!IsWrite) {
            ULONG64 val = __readmsr((ULONG)msrIndex);
            readValueLow = val & 0xFFFFFFFF;
            readValueHigh = val >> 32;
        } else {
            __writemsr((ULONG)msrIndex, writeValueLow | (writeValueHigh << 32));
        }
        handled = TRUE;
        break;
    }

    /* For reads: write result back to guest RAX + RDX */
    if (!IsWrite && handled) {
        g_HvOps.SetGuestReg(CpuNumber, ANX_REG_RAX, readValueLow);
        g_HvOps.SetGuestReg(CpuNumber, ANX_REG_RDX, readValueHigh);
    }

    /* Advance guest RIP past RDMSR/WRMSR (2 bytes: 0F 32 or 0F 30) */
    {
        ULONG64 rip = g_HvOps.GetGuestRip(CpuNumber);
        g_HvOps.SetGuestRip(CpuNumber, rip + 2);
    }
}
