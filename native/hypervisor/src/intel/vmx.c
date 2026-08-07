/*
 * AnXinHypervisor - Intel VMX Operations
 * Module: native/hypervisor/src/intel/vmx.c
 *
 * VMXON/VMXOFF/VMCLEAR/VMPTRLD/VMLAUNCH/VMRESUME wrappers.
 * All functions execute at DISPATCH_LEVEL or higher (during IPI callback).
 */

#include "../../include/platform.h"
#include "../../include/hal.h"
#include "../../include/per_cpu.h"

extern VOID AnxDebugPrint(const char* Fmt, ...);
extern UCHAR AnxVmxVmxonWrapper(PHYSICAL_ADDRESS* VmxonPa);
extern VOID AnxVmxVmxoffWrapper(VOID);
extern VOID AnxVmxVmclearWrapper(PHYSICAL_ADDRESS* VmcsPa);
extern VOID AnxVmxVmptrldWrapper(PHYSICAL_ADDRESS* VmcsPa);

/* VMX instruction error codes (read from VMCS 0x4400) */
#define VMX_ERROR_VMLAUNCH_NON_CLEAR    4
#define VMX_ERROR_VMRESUME_NON_LAUNCHED 5

/*
 * Execute VMXON on the current processor.
 * Requires: CR4.VMXE set, IA32_FEATURE_CONTROL locked+enabled.
 */
NTSTATUS
AnxVmxVmxon(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    PHYSICAL_ADDRESS vmxonPa;
    ULONG64 vmxBasic;
    ULONG32 revisionId;

    /* Read VMCS revision identifier from IA32_VMX_BASIC */
    vmxBasic = __readmsr(ANX_MSR_IA32_VMX_BASIC);
    revisionId = (ULONG32)(vmxBasic & 0x7FFFFFFF);

    /* Write revision ID to VMXON region (first 4 bytes) */
    *(PULONG32)perCpu->Intel.VmxonRegion = revisionId;

    /* Set CR4.VMXE */
    __writecr4(__readcr4() | ANX_CR4_VMXE);

    /* Execute VMXON via asm wrapper (MSVC intrinsic unreliable in manual builds) */
    vmxonPa = MmGetPhysicalAddress(perCpu->Intel.VmxonRegion);
    {
        UCHAR vmxonResult = AnxVmxVmxonWrapper(&vmxonPa);
        if (vmxonResult != 0) {
            AnxDebugPrint("[HV:ERR] CPU %d: VMXON failed (result=%d)\n",
                          (ULONG64)CpuNumber, (ULONG64)vmxonResult);
            return STATUS_UNSUCCESSFUL;
        }
    }

    AnxDebugPrint("[HV:DBG] CPU %d: VMXON executed (revision 0x%x)\n",
                  (ULONG64)CpuNumber, (ULONG64)revisionId);
    return STATUS_SUCCESS;
}

/*
 * Execute VMXOFF on the current processor.
 * Must be in VMX root operation (outside guest).
 */
VOID
AnxVmxVmxoff(VOID)
{
    AnxVmxVmxoffWrapper();
}

/*
 * VMCLEAR + VMPTRLD: load a VMCS for the current processor.
 */
NTSTATUS
AnxVmxLoadVmcs(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    PHYSICAL_ADDRESS vmcsPa;
    ULONG64 vmxBasic;
    ULONG32 revisionId;

    /* Write revision ID to VMCS region */
    vmxBasic = __readmsr(ANX_MSR_IA32_VMX_BASIC);
    revisionId = (ULONG32)(vmxBasic & 0x7FFFFFFF);
    *(PULONG32)perCpu->Intel.VmcsRegion = revisionId;

    /* VMCLEAR: set VMCS to "clear" state */
    vmcsPa = MmGetPhysicalAddress(perCpu->Intel.VmcsRegion);
    AnxVmxVmclearWrapper(&vmcsPa);

    /* VMPTRLD: make this VMCS the current VMCS */
    AnxVmxVmptrldWrapper(&vmcsPa);

    perCpu->Intel.VmcsLaunched = FALSE;
    return STATUS_SUCCESS;
}

/*
 * Execute VMLAUNCH (first entry) or VMRESUME (subsequent entries).
 * Returns STATUS_SUCCESS only if VM-entry fails (we stay in root).
 * On successful entry, execution continues in guest and this function
 * does not return until the next VM-exit.
 */
NTSTATUS
AnxVmxEnterGuest(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    size_t vmError;

    if (!perCpu->Intel.VmcsLaunched) {
        /* First entry: VMLAUNCH */
        __vmx_vmlaunch();

        /* If we reach here, VMLAUNCH failed */
        __vmx_vmread(0x4400, &vmError);
        AnxDebugPrint("[HV:ERR] CPU %d: VMLAUNCH failed, error %d\n",
                      (ULONG64)CpuNumber, (ULONG64)vmError);
        return STATUS_UNSUCCESSFUL;
    } else {
        /* Subsequent entries: VMRESUME */
        __vmx_vmresume();

        /* If we reach here, VMRESUME failed */
        __vmx_vmread(0x4400, &vmError);
        AnxDebugPrint("[HV:ERR] CPU %d: VMRESUME failed, error %d\n",
                      (ULONG64)CpuNumber, (ULONG64)vmError);
        return STATUS_UNSUCCESSFUL;
    }
}
