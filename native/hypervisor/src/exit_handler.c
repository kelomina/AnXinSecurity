/*
 * AnXinHypervisor - Unified Exit Handler
 * Module: native/hypervisor/src/exit_handler.c
 *
 * Platform-independent VM-exit / VMEXIT dispatcher.
 * Called from assembly entry points (entry_intel.asm / entry_amd.asm)
 * after GPRs are saved. Routes to specific handlers based on
 * unified exit reason codes from HAL GetExitReason().
 */

#include "../include/platform.h"
#include "../include/hal.h"
#include "../include/per_cpu.h"
#include "../include/exit_reasons.h"
#include "../include/anx_hv.h"

extern VOID AnxDebugPrint(const char* Fmt, ...);

/* From exit_cpuid.c */
extern VOID AnxHandleCpuidExit(ULONG CpuNumber);

/* From page_table.c */
extern VOID AnxHandlePageFaultExit(ULONG CpuNumber);

/* From protect.c */
extern BOOLEAN AnxProtectCheckViolation(ULONG CpuNumber, ULONG64 Gpa, ULONG64 Rip,
                                        ULONG64 Cr3, BOOLEAN IsWrite);
extern VOID AnxProtectSingleStepComplete(ULONG CpuNumber, ULONG64 Gpa);

/* From exit_cr.c (Phase 5) */
extern VOID AnxHandleCrAccessExit(ULONG CpuNumber);

/* From exit_msr.c (Phase 5) */
extern VOID AnxHandleMsrExit(ULONG CpuNumber, BOOLEAN IsWrite);

/* From hypercall.c (Phase 4) */
extern VOID AnxHandleHypercall(ULONG CpuNumber);

/* ─── Intel VM-exit Handler ───────────────────────────────────────── */

/*
 * Called from entry_intel.asm AnxVmxExitEntry.
 * GuestRegs points to the saved GPR frame on the host stack.
 */
VOID
AnxHandleVmExit(
    _In_ PVOID GuestRegs
)
{
    ULONG cpu = KeGetCurrentProcessorNumber();
    PANX_HV_PER_CPU perCpu;
    ULONG exitReason;

    UNREFERENCED_PARAMETER(GuestRegs);

    if (cpu >= g_CpuCount) return;
    perCpu = g_PerCpuArray[cpu];
    if (!perCpu) return;

    perCpu->VmExitCount++;
    perCpu->InRoot = TRUE;

    exitReason = g_HvOps.GetExitReason(cpu);

    switch (exitReason) {
    case ANX_EXIT_CPUID:
        perCpu->CpuidExitCount++;
        AnxHandleCpuidExit(cpu);
        break;

    case ANX_EXIT_HYPERCALL:
        perCpu->HypercallCount++;
        AnxHandleHypercall(cpu);
        break;

    case ANX_EXIT_CR_ACCESS:
        AnxHandleCrAccessExit(cpu);
        break;

    case ANX_EXIT_MSR_READ:
        AnxHandleMsrExit(cpu, FALSE);
        break;

    case ANX_EXIT_MSR_WRITE:
        AnxHandleMsrExit(cpu, TRUE);
        break;

    case ANX_EXIT_PAGE_FAULT:
        perCpu->PageFaultCount++;
        AnxHandlePageFaultExit(cpu);
        break;

    case ANX_EXIT_SINGLE_STEP:
        /* MTF exit: single-step bypass complete, re-protect the page */
        g_HvOps.DisableSingleStep(cpu);
        if (perCpu->SingleStepGpa != 0) {
            AnxProtectSingleStepComplete(cpu, perCpu->SingleStepGpa);
            perCpu->SingleStepGpa = 0;
        }
        break;

    case ANX_EXIT_EXTERNAL_INT:
        /* Re-inject to guest or handle via host IDT */
        /* Phase 1: acknowledge and re-enable interrupts */
        break;

    case ANX_EXIT_HLT:
        /* Guest executed HLT: advance RIP and resume */
        {
            ULONG64 rip = g_HvOps.GetGuestRip(cpu);
            g_HvOps.SetGuestRip(cpu, rip + 1);
        }
        break;

    case ANX_EXIT_TRIPLE_FAULT:
        AnxDebugPrint("[HV:ERR] CPU %d: TRIPLE FAULT - attempting recovery\n",
                      (ULONG64)cpu);
        /* Attempt to reset guest state; if fails, shutdown virtualization */
        break;

    default:
        AnxDebugPrint("[HV:WRN] CPU %d: unhandled exit reason 0x%x\n",
                      (ULONG64)cpu, (ULONG64)exitReason);
        break;
    }

    perCpu->InRoot = FALSE;
}

/* ─── AMD VMEXIT Handler ──────────────────────────────────────────── */

/*
 * Called from entry_amd.asm AnxSvmExitEntry.
 * VmcbPa is the physical address of the current VMCB.
 */
VOID
AnxSvmHandleExit(
    _In_ ULONG64 VmcbPa
)
{
    ULONG cpu = KeGetCurrentProcessorNumber();
    PANX_HV_PER_CPU perCpu;
    ULONG exitReason;

    UNREFERENCED_PARAMETER(VmcbPa);

    if (cpu >= g_CpuCount) return;
    perCpu = g_PerCpuArray[cpu];
    if (!perCpu) return;

    perCpu->VmExitCount++;
    perCpu->InRoot = TRUE;

    exitReason = g_HvOps.GetExitReason(cpu);

    switch (exitReason) {
    case ANX_EXIT_CPUID:
        perCpu->CpuidExitCount++;
        AnxHandleCpuidExit(cpu);
        break;

    case ANX_EXIT_HYPERCALL:
        perCpu->HypercallCount++;
        AnxHandleHypercall(cpu);
        break;

    case ANX_EXIT_CR_ACCESS:
        AnxHandleCrAccessExit(cpu);
        break;

    case ANX_EXIT_MSR_READ:
        AnxHandleMsrExit(cpu, FALSE);
        break;

    case ANX_EXIT_MSR_WRITE:
        AnxHandleMsrExit(cpu, TRUE);
        break;

    case ANX_EXIT_PAGE_FAULT:
        perCpu->PageFaultCount++;
        AnxHandlePageFaultExit(cpu);
        break;

    case ANX_EXIT_SINGLE_STEP:
        /* #DB intercept: single-step bypass complete, re-protect */
        g_HvOps.DisableSingleStep(cpu);
        if (perCpu->SingleStepGpa != 0) {
            AnxProtectSingleStepComplete(cpu, perCpu->SingleStepGpa);
            perCpu->SingleStepGpa = 0;
        }
        break;

    case ANX_EXIT_EXTERNAL_INT:
        break;

    case ANX_EXIT_HLT:
        {
            ULONG64 rip = g_HvOps.GetGuestRip(cpu);
            g_HvOps.SetGuestRip(cpu, rip + 1);
        }
        break;

    case ANX_EXIT_TRIPLE_FAULT:
        AnxDebugPrint("[HV:ERR] CPU %d: SHUTDOWN (triple fault) - recovering\n",
                      (ULONG64)cpu);
        break;

    default:
        AnxDebugPrint("[HV:WRN] CPU %d: unhandled SVM exit 0x%x\n",
                      (ULONG64)cpu, (ULONG64)exitReason);
        break;
    }

    perCpu->InRoot = FALSE;
}
