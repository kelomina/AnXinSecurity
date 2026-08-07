/*
 * AnXinHypervisor - HAL vtable Binding
 * Module: native/hypervisor/src/hal.c
 *
 * Selects the platform backend (Intel VT-x or AMD SVM) based on CPU vendor
 * detected in DriverEntry, and populates the global g_HvOps vtable.
 */

#include "../include/hal.h"
#include "../include/exit_reasons.h"

/* Global HAL instance */
ANX_HV_OPS g_HvOps = { 0 };

/* Global per-CPU array */
PANX_HV_PER_CPU* g_PerCpuArray = NULL;
ULONG g_CpuCount = 0;

/* Platform name strings (static storage, no runtime alloc) */
static const char g_IntelName[] = "Intel VT-x";
static const char g_AmdName[]   = "AMD SVM";

/*
 * Bind the HAL vtable to the appropriate backend.
 * Called once in DriverEntry after CPU vendor detection.
 */
NTSTATUS
AnxHalBind(
    _In_ ANX_CPU_VENDOR Vendor
)
{
    RtlZeroMemory(&g_HvOps, sizeof(g_HvOps));

    switch (Vendor) {
    case ANX_CPU_INTEL:
        AnxIntelInitOps(&g_HvOps);
        g_HvOps.PlatformName = g_IntelName;
        break;

    case ANX_CPU_AMD:
        AnxAmdInitOps(&g_HvOps);
        g_HvOps.PlatformName = g_AmdName;
        break;

    default:
        return STATUS_NOT_SUPPORTED;
    }

    /* Validate all required function pointers are filled */
    if (!g_HvOps.Init || !g_HvOps.EnterGuest || !g_HvOps.Shutdown ||
        !g_HvOps.HandleExit || !g_HvOps.GetExitReason ||
        !g_HvOps.GetGuestReg || !g_HvOps.SetGuestReg ||
        !g_HvOps.GetGuestRip || !g_HvOps.SetGuestRip ||
        !g_HvOps.BuildPageTables || !g_HvOps.ProtectPage ||
        !g_HvOps.FlushTlb || !g_HvOps.InjectUD) {
        return STATUS_DRIVER_INTERNAL_ERROR;
    }

    return STATUS_SUCCESS;
}
