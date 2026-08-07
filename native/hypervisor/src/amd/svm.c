/*
 * AnXinHypervisor - AMD SVM Operations
 * Module: native/hypervisor/src/amd/svm.c
 *
 * EFER.SVME enable/disable, VM_HSAVE_PA setup, VMRUN/VMLOAD/VMSAVE wrappers.
 */

#include "../../include/platform.h"
#include "../../include/hal.h"
#include "../../include/per_cpu.h"

extern VOID AnxDebugPrint(const char* Fmt, ...);
extern NTSTATUS AnxVmcbSetup(ULONG CpuNumber);

/* From entry_amd.asm */
extern VOID AnxSvmRunGuest(PVOID VmcbVa, PVOID VmcbPa);
extern VOID AnxSvmVmload(PVOID VmcbPa);
extern VOID AnxSvmVmsave(PVOID VmcbPa);

/*
 * Enable SVM on the current processor.
 * Sets EFER.SVME and configures VM_HSAVE_PA MSR.
 */
NTSTATUS
AnxSvmEnable(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    ULONG64 efer;
    PHYSICAL_ADDRESS hostSavePa;

    /* Set EFER.SVME (bit 12) */
    efer = __readmsr(ANX_MSR_IA32_EFER);
    if (!(efer & ANX_EFER_SVME)) {
        efer |= ANX_EFER_SVME;
        __writemsr(ANX_MSR_IA32_EFER, efer);
    }

    /* Set VM_HSAVE_PA to host save area physical address */
    hostSavePa = MmGetPhysicalAddress(perCpu->Amd.HostSaveArea);
    __writemsr(ANX_MSR_VM_HSAVE_PA, hostSavePa.QuadPart);

    AnxDebugPrint("[HV:DBG] CPU %d: SVM enabled (EFER=0x%p, HSAVE_PA=0x%p)\n",
                  (ULONG64)CpuNumber, efer, (ULONG64)hostSavePa.QuadPart);
    return STATUS_SUCCESS;
}

/*
 * Disable SVM on the current processor.
 */
VOID
AnxSvmDisable(VOID)
{
    ULONG64 efer = __readmsr(ANX_MSR_IA32_EFER);
    efer &= ~ANX_EFER_SVME;
    __writemsr(ANX_MSR_IA32_EFER, efer);
}

/*
 * Initialize SVM for a CPU: enable + setup VMCB.
 */
NTSTATUS
AnxSvmInitCpu(
    _In_ ULONG CpuNumber
)
{
    NTSTATUS status;

    status = AnxSvmEnable(CpuNumber);
    if (!NT_SUCCESS(status)) return status;

    status = AnxVmcbSetup(CpuNumber);
    if (!NT_SUCCESS(status)) return status;

    return STATUS_SUCCESS;
}

/*
 * Enter guest via VMRUN.
 * On success, does not return until VMEXIT.
 * The asm wrapper handles the VMRUN loop.
 */
NTSTATUS
AnxSvmEnterGuest(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    PHYSICAL_ADDRESS vmcbPa;

    vmcbPa = MmGetPhysicalAddress(perCpu->Amd.VmcbRegion);

    /* VMRUN: enter guest.
       Pass virtual address (RCX) for VMCB writes, physical address (RDX) for VMRUN.
       On success: guest continues at the return address below (transparent).
       On failure: asm jumps to AnxSvmExitEntry (host mode, never returns here). */
    AnxSvmRunGuest(perCpu->Amd.VmcbRegion, (PVOID)vmcbPa.QuadPart);

    /* Guest is now running — this IS the success continuation. */
    return STATUS_SUCCESS;
}
