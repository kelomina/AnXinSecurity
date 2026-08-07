/*
 * AnXinHypervisor - Driver Entry & Lifecycle
 * Module: native/hypervisor/src/driver.c
 *
 * Boot-start driver (Start=0). Detects CPU vendor, checks virtualization
 * capabilities, allocates per-CPU structures, and enters virtualization
 * on all cores via IPI broadcast.
 */

#include "../include/platform.h"
#include "../include/hal.h"
#include "../include/per_cpu.h"
#include "../include/anx_hv.h"
#include "../include/protect.h"
#include "../include/ept.h"
#include <ntstrsafe.h>

/* Declared in debug.c */
extern VOID AnxDebugInit(VOID);
extern VOID AnxDebugPrint(const char* Fmt, ...);

/* File-based crash diagnostics: appends to C:\hv_debug.log */
VOID AnxLogToFile(const char* Msg)
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    NTSTATUS st;
    char buf[256];
    size_t len = 0;
    ULONG writeLen;

    RtlInitUnicodeString(&path, L"\\??\\C:\\hv_debug.log");
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&hFile, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
                      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(st)) return;

    RtlStringCbCopyA(buf, sizeof(buf) - 2, Msg);
    RtlStringCbLengthA(buf, sizeof(buf), &len);
    buf[len] = '\r'; buf[len+1] = '\n';
    writeLen = (ULONG)(len + 2);
    ZwWriteFile(hFile, NULL, NULL, NULL, &iosb, buf, writeLen, NULL, NULL);
    ZwFlushBuffersFile(hFile, &iosb);
    ZwClose(hFile);
}

/* Declared in hal.c */
extern NTSTATUS AnxHalBind(ANX_CPU_VENDOR Vendor);

/* Declared in protect.c */
extern ULONG AnxProtectDrainViolations(PANX_HV_VIOLATION_EVENT Buffer, ULONG MaxEvents);
extern VOID AnxProtectGetStats(PANX_HV_STATS Stats);

/* Global state */
ANX_CPU_VENDOR g_CpuVendor = ANX_CPU_UNKNOWN;
static BOOLEAN g_HypervisorActive = FALSE;
static BOOLEAN g_HvSuspending = FALSE;
static ULONG64 g_ReferenceTsc = 0;  /* CPU 0 TSC at IPI broadcast time */
ANX_PROTECT_ENGINE g_ProtectEngine = { 0 };

/* Degradation state (Phase 6) */
static ANX_HV_MODE g_OperatingMode = ANX_HV_MODE_FULL;
static char g_DegradReason[128] = { 0 };
static BOOLEAN g_PageTablesActive = FALSE;

/* Device object for user-mode IOCTL queries */
static PDEVICE_OBJECT g_DeviceObject = NULL;

/* Forward declarations */
static NTSTATUS AnxCheckIntelCapabilities(VOID);
static NTSTATUS AnxCheckAmdCapabilities(VOID);
static NTSTATUS AnxAllocatePerCpuStructures(VOID);
static NTSTATUS AnxAllocateAndBuildPageTables(VOID);
static VOID AnxFreePerCpuStructures(VOID);
static VOID AnxRegisterProcessorCallback(VOID);
static ULONG_PTR AnxStageInitCallback(ULONG_PTR Argument);
static ULONG_PTR AnxInitializeCpuCallback(ULONG_PTR Argument);
static VOID AnxShutdownCpuCallback(ULONG_PTR Argument);
static NTSTATUS AnxCreateDeviceObject(PDRIVER_OBJECT DriverObject);
static VOID AnxDestroyDeviceObject(VOID);
static NTSTATUS AnxIrpDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static VOID AnxSetDegradedMode(ANX_HV_MODE Mode, const char* Reason);
VOID AnxDriverUnload(PDRIVER_OBJECT DriverObject);

/* ─── DriverEntry ─────────────────────────────────────────────────── */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    ULONG cpuCount;

    UNREFERENCED_PARAMETER(RegistryPath);

    /* Initialize serial debug output first */
    AnxDebugInit();
    AnxDebugPrint("[HV:INF] AnXinHypervisor %s loading\n", ANX_HV_VERSION_STRING);
    AnxLogToFile("[HV] DriverEntry: loaded");

    /* Create device object early so user-mode can query status in any mode */
    status = AnxCreateDeviceObject(DriverObject);
    if (!NT_SUCCESS(status)) {
        AnxDebugPrint("[HV:ERR] Device creation failed: 0x%x\n", (ULONG64)status);
        return status;
    }
    DriverObject->DriverUnload = AnxDriverUnload;

    /* Step 1: Detect existing hypervisor (Hyper-V, VMware, etc.) */
    if (AnxDetectExistingHypervisor()) {
        ANX_CPUID_RESULT r;
        char sig[13] = { 0 };
        BOOLEAN nestedVirtAvailable = FALSE;

        AnxCpuid(&r, 0x40000000);
        RtlCopyMemory(sig, &r.Ebx, 12);

        /* Check if nested virtualization exposes VMX or SVM */
        AnxCpuid(&r, 1);
        if (r.Ecx & ANX_CPUID1_ECX_VMX) {
            nestedVirtAvailable = TRUE;
        } else {
            ANX_CPUID_RESULT rAmd;
            AnxCpuid(&rAmd, 0x80000001);
            if (rAmd.Ecx & ANX_CPUID_80000001_ECX_SVM) {
                nestedVirtAvailable = TRUE;
            }
        }

        if (!nestedVirtAvailable) {
            AnxSetDegradedMode(ANX_HV_MODE_DEGRADED_HYPERV, sig);
            AnxDebugPrint("[HV:INF] Existing hypervisor detected: %s - degrading\n", sig);
            return STATUS_SUCCESS;
        }

        AnxDebugPrint("[HV:INF] Hypervisor present (%s) but nested virt exposes VMX/SVM - attempting full mode\n", sig);
    }

    /* Step 2: CPU vendor detection */
    g_CpuVendor = AnxDetectCpuVendor();
    switch (g_CpuVendor) {
    case ANX_CPU_INTEL:
        AnxDebugPrint("[HV:INF] CPU vendor: GenuineIntel\n");
        break;
    case ANX_CPU_AMD:
        AnxDebugPrint("[HV:INF] CPU vendor: AuthenticAMD\n");
        break;
    default:
        AnxSetDegradedMode(ANX_HV_MODE_DEGRADED_CPU, "Unknown CPU vendor");
        AnxDebugPrint("[HV:WRN] Unknown CPU vendor - degrading\n");
        return STATUS_SUCCESS;
    }

    /* Step 3: Platform capability detection */
    if (g_CpuVendor == ANX_CPU_INTEL) {
        status = AnxCheckIntelCapabilities();
    } else {
        status = AnxCheckAmdCapabilities();
    }
    if (!NT_SUCCESS(status)) {
        ANX_HV_MODE mode;
        const char* reason;
        if (g_CpuVendor == ANX_CPU_INTEL) {
            mode = ANX_HV_MODE_DEGRADED_VTX_OFF;
            reason = "Intel VT-x disabled or unavailable (BIOS)";
        } else {
            mode = ANX_HV_MODE_DEGRADED_SVM_OFF;
            reason = "AMD SVM disabled or unavailable (BIOS)";
        }
        AnxSetDegradedMode(mode, reason);
        AnxDebugPrint("[HV:WRN] Virtualization not available (0x%x) - degrading\n",
                      (ULONG64)status);
        return STATUS_SUCCESS;
    }

    /* Step 4: Bind HAL vtable */
    status = AnxHalBind(g_CpuVendor);
    if (!NT_SUCCESS(status)) {
        AnxSetDegradedMode(ANX_HV_MODE_DEGRADED_INIT_FAIL, "HAL bind failed");
        AnxDebugPrint("[HV:ERR] HAL bind failed: 0x%x\n", (ULONG64)status);
        return STATUS_SUCCESS;
    }
    AnxDebugPrint("[HV:INF] HAL bound: %s\n", (ULONG64)g_HvOps.PlatformName);

    /* Step 5: Allocate per-CPU structures */
    cpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    g_CpuCount = cpuCount;
    status = AnxAllocatePerCpuStructures();
    if (!NT_SUCCESS(status)) {
        AnxSetDegradedMode(ANX_HV_MODE_DEGRADED_INIT_FAIL, "Per-CPU allocation failed");
        AnxDebugPrint("[HV:ERR] Per-CPU alloc failed: 0x%x\n", (ULONG64)status);
        return STATUS_SUCCESS;
    }

    /* Step 5b: Allocate and build secondary page tables (EPT/NPT) */
    /* TEMP: EPT disabled to isolate triple fault source */
    g_PageTablesActive = FALSE;
    AnxDebugPrint("[HV:WRN] EPT disabled for debugging\n");

    /* Step 6: Initialize protection engine */
    RtlZeroMemory(&g_ProtectEngine, sizeof(g_ProtectEngine));

    /* Step 7: Enter virtualization on all CPUs via staged IPI broadcasts */
    AnxDebugPrint("[HV:INF] Entering virtualization on %d CPUs...\n", (ULONG64)cpuCount);
    g_ReferenceTsc = __rdtsc();

    /* Stage 1: Platform-specific init (VMXON+VMCS for Intel, EFER+VMCB for AMD) */
    /* Pre-allocate IOPM/MSRPM at PASSIVE_LEVEL (cannot alloc at IPI_LEVEL) */
    if (g_CpuVendor == ANX_CPU_AMD) {
        extern NTSTATUS AnxSvmAllocatePermissionMaps(VOID);
        status = AnxSvmAllocatePermissionMaps();
        if (!NT_SUCCESS(status)) {
            AnxSetDegradedMode(ANX_HV_MODE_DEGRADED_INIT_FAIL, "IOPM/MSRPM alloc failed");
            return STATUS_SUCCESS;
        }
    }
    AnxLogToFile("[HV] Stage 1: Init (HAL)");
    KeIpiGenericCall(AnxStageInitCallback, 0);
    AnxLogToFile("[HV] Stage 1: Init done");

    /* Diagnostic: validate VMCB state for CPU 0 before VMRUN */
    if (g_CpuVendor == ANX_CPU_AMD && g_PerCpuArray[0]) {
        PUCHAR vmcb = (PUCHAR)g_PerCpuArray[0]->Amd.VmcbRegion;
        PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(vmcb);
        ULONG64 cr0 = *(PULONG64)(vmcb + 0x558);
        ULONG64 cr3 = *(PULONG64)(vmcb + 0x550);
        ULONG64 cr4 = *(PULONG64)(vmcb + 0x548);
        ULONG64 efer = *(PULONG64)(vmcb + 0x4D0);
        USHORT csAttrib = *(PUSHORT)(vmcb + 0x412);
        ULONG asid = *(PULONG32)(vmcb + 0x058);
        ULONG64 iopm = *(PULONG64)(vmcb + 0x040);
        ULONG64 msrpm = *(PULONG64)(vmcb + 0x048);
        ULONG64 hsavePa = __readmsr(0xC0010117);

        AnxDebugPrint("[HV:DIAG] VMCB PA=0x%p align=0x%x\n",
                      (ULONG64)pa.QuadPart, (ULONG)(pa.QuadPart & 0xFFF));
        AnxDebugPrint("[HV:DIAG] CR0=0x%p CR3=0x%p CR4=0x%p EFER=0x%p\n",
                      cr0, cr3, cr4, efer);
        AnxDebugPrint("[HV:DIAG] CS.Attrib=0x%x ASID=%d IOPM=0x%p MSRPM=0x%p\n",
                      (ULONG64)csAttrib, (ULONG64)asid, iopm, msrpm);
        AnxDebugPrint("[HV:DIAG] HSAVE_PA=0x%p\n", hsavePa);

        /* Simple pass/fail checks logged to file */
        if (pa.QuadPart & 0xFFF)
            AnxLogToFile("[HV:DIAG] FAIL: VMCB not 4K aligned");
        else
            AnxLogToFile("[HV:DIAG] OK: VMCB 4K aligned");

        if (hsavePa & 0xFFF)
            AnxLogToFile("[HV:DIAG] FAIL: HSAVE not 4K aligned");
        else
            AnxLogToFile("[HV:DIAG] OK: HSAVE 4K aligned");

        if (!(cr0 & 1))
            AnxLogToFile("[HV:DIAG] FAIL: CR0.PE=0");
        if (!(cr0 & (1ULL << 31)))
            AnxLogToFile("[HV:DIAG] FAIL: CR0.PG=0");
        if (!(efer & (1ULL << 10)))
            AnxLogToFile("[HV:DIAG] FAIL: EFER.LMA=0");
        if (!(efer & (1ULL << 12)))
            AnxLogToFile("[HV:DIAG] FAIL: EFER.SVME=0");
        if (csAttrib != 0x029B)
            AnxLogToFile("[HV:DIAG] FAIL: CS.Attrib wrong");
        else
            AnxLogToFile("[HV:DIAG] OK: CS.Attrib=0x029B");
        if (asid == 0)
            AnxLogToFile("[HV:DIAG] FAIL: ASID=0");
        if (iopm == 0)
            AnxLogToFile("[HV:DIAG] FAIL: IOPM=0");
        if (msrpm == 0)
            AnxLogToFile("[HV:DIAG] FAIL: MSRPM=0");
        if (cr3 == 0)
            AnxLogToFile("[HV:DIAG] FAIL: CR3=0");

        AnxLogToFile("[HV:DIAG] Validation done");
    }

    /* Stage 2: Enter guest (VMLAUNCH/VMRUN) */
    AnxLogToFile("[HV] Stage 2: EnterGuest");
    KeIpiGenericCall(AnxInitializeCpuCallback, 0);
    AnxLogToFile("[HV] Stage 2: EnterGuest done");

    /* Verify all CPUs succeeded */
    for (ULONG i = 0; i < cpuCount; i++) {
        if (!g_PerCpuArray[i]->VirtEnabled) {
            AnxDebugPrint("[HV:ERR] CPU %d failed to virtualize - rolling back\n",
                          (ULONG64)i);
            KeIpiGenericCall(AnxShutdownCpuCallback, 0);
            AnxFreePerCpuStructures();
            AnxSetDegradedMode(ANX_HV_MODE_DEGRADED_INIT_FAIL,
                               "CPU virtualization failed during IPI broadcast");
            return STATUS_SUCCESS;
        }
    }

    g_HypervisorActive = TRUE;
    if (!g_PageTablesActive) {
        g_OperatingMode = ANX_HV_MODE_DEGRADED_NO_EPT;
        RtlStringCbCopyA(g_DegradReason, sizeof(g_DegradReason),
                         "Virtualization active but EPT/NPT unavailable");
    }
    AnxDebugPrint("[HV:INF] Virtualization active on all %d CPUs (mode=%d)\n",
                  (ULONG64)cpuCount, (ULONG64)g_OperatingMode);

    /* Register CPU hotplug callback */
    AnxRegisterProcessorCallback();

    return STATUS_SUCCESS;
}

/* ─── CPU Hotplug Callback ────────────────────────────────────────── */

static PVOID g_ProcessorCallbackHandle = NULL;

/*
 * Called when a processor is added or removed from the system.
 * For new CPUs: allocate per-CPU structures and virtualize.
 * For removed CPUs: shutdown virtualization and mark offline.
 */
static
VOID
AnxProcessorChangeCallback(
    _In_ PVOID CallbackContext,
    _In_ PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT ChangeContext,
    _Inout_ PNTSTATUS OperationStatus
)
{
    ULONG cpu;
    PANX_HV_PER_CPU perCpu;

    UNREFERENCED_PARAMETER(CallbackContext);

    cpu = ChangeContext->NtNumber;
    *OperationStatus = STATUS_SUCCESS;

    if (ChangeContext->State == KeProcessorAddCompleteNotify) {
        /* New CPU online: virtualize it */
        AnxDebugPrint("[HV:INF] CPU %d added, virtualizing...\n", (ULONG64)cpu);

        if (cpu >= g_CpuCount) {
            /* Beyond our array: ignore (would need dynamic resize) */
            AnxDebugPrint("[HV:WRN] CPU %d beyond max (%d), skipping\n",
                          (ULONG64)cpu, (ULONG64)g_CpuCount);
            return;
        }

        perCpu = g_PerCpuArray[cpu];
        if (!perCpu) {
            /* Allocate per-CPU structure on the fly */
            perCpu = (PANX_HV_PER_CPU)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(ANX_HV_PER_CPU), 'xHnA');
            if (!perCpu) {
                *OperationStatus = STATUS_INSUFFICIENT_RESOURCES;
                return;
            }
            RtlZeroMemory(perCpu, sizeof(ANX_HV_PER_CPU));
            perCpu->CpuNumber = cpu;
            perCpu->HostStack = AnxAllocateContiguous(ANX_HOST_STACK_SIZE);
            if (!perCpu->HostStack) {
                ExFreePoolWithTag(perCpu, 'xHnA');
                *OperationStatus = STATUS_INSUFFICIENT_RESOURCES;
                return;
            }
            perCpu->HostStackTop = (PUCHAR)perCpu->HostStack + ANX_HOST_STACK_SIZE - 8;

            if (g_CpuVendor == ANX_CPU_INTEL) {
                perCpu->Intel.VmxonRegion = AnxAllocateContiguous(ANX_PAGE_SIZE);
                perCpu->Intel.VmcsRegion = AnxAllocateContiguous(ANX_PAGE_SIZE);
                perCpu->Intel.VmcsLaunched = FALSE;
            } else {
                perCpu->Amd.VmcbRegion = AnxAllocateContiguous(ANX_PAGE_SIZE);
                perCpu->Amd.HostSaveArea = AnxAllocateContiguous(ANX_PAGE_SIZE);
                perCpu->Amd.Asid = 1;
            }

            /* Share page table context */
            perCpu->PageTableCtx = g_PerCpuArray[0]->PageTableCtx;
            perCpu->PageTablePointer = g_PerCpuArray[0]->PageTablePointer;

            g_PerCpuArray[cpu] = perCpu;
        }

        /* Run initialization on this CPU */
        g_ReferenceTsc = __rdtsc();
        AnxInitializeCpuCallback(0);

        if (!perCpu->VirtEnabled) {
            *OperationStatus = STATUS_UNSUCCESSFUL;
        }

    } else if (ChangeContext->State == 1 /* KeProcessorRemoveCompleteNotify */) {
        /* CPU removed: mark as offline */
        AnxDebugPrint("[HV:INF] CPU %d removed\n", (ULONG64)cpu);

        if (cpu < g_CpuCount && g_PerCpuArray[cpu]) {
            g_PerCpuArray[cpu]->VirtEnabled = FALSE;
        }
    }
}

static
VOID
AnxRegisterProcessorCallback(VOID)
{
    g_ProcessorCallbackHandle = KeRegisterProcessorChangeCallback(
        AnxProcessorChangeCallback, NULL, 0);

    if (g_ProcessorCallbackHandle) {
        AnxDebugPrint("[HV:INF] Processor change callback registered\n");
    } else {
        AnxDebugPrint("[HV:WRN] Processor callback registration failed\n");
    }
}

/* ─── S3/S4 Power Management ──────────────────────────────────────── */

/*
 * After S3/S4 resume, all CPU virtualization state is lost.
 * Re-initialize all CPUs: VMCLEAR→VMPTRLD→VMLAUNCH (Intel)
 * or re-VMRUN (AMD).
 *
 * Registered via IoRegisterPlugPlayNotification for PNP power events,
 * or called manually from a power IRP handler.
 */
VOID
AnxHandleResumeFromSleep(VOID)
{
    ULONG i;

    if (!g_HypervisorActive) return;

    AnxDebugPrint("[HV:INF] Resuming from S3/S4, re-virtualizing %d CPUs...\n",
                  (ULONG64)g_CpuCount);

    /* Reset VmcsLaunched for all CPUs (Intel needs VMLAUNCH again) */
    if (g_CpuVendor == ANX_CPU_INTEL) {
        for (i = 0; i < g_CpuCount; i++) {
            if (g_PerCpuArray[i]) {
                g_PerCpuArray[i]->Intel.VmcsLaunched = FALSE;
            }
        }
    }

    /* Re-run initialization on all CPUs */
    g_ReferenceTsc = __rdtsc();
    KeIpiGenericCall(AnxInitializeCpuCallback, 0);

    /* Verify */
    for (i = 0; i < g_CpuCount; i++) {
        if (g_PerCpuArray[i] && !g_PerCpuArray[i]->VirtEnabled) {
            AnxDebugPrint("[HV:ERR] CPU %d failed to re-virtualize after resume\n",
                          (ULONG64)i);
        }
    }

    AnxDebugPrint("[HV:INF] Resume complete\n");
}

/* ─── Intel Capability Detection ──────────────────────────────────── */

static
NTSTATUS
AnxCheckIntelCapabilities(VOID)
{
    ANX_CPUID_RESULT r;
    ULONG64 featureControl;
    ULONG64 cr0Fixed0, cr0Fixed1, cr4Fixed0, cr4Fixed1;

    /* CPUID.1:ECX[5] = VMX */
    AnxCpuid(&r, 1);
    if (!(r.Ecx & ANX_CPUID1_ECX_VMX)) {
        AnxDebugPrint("[HV:WRN] VMX not supported (CPUID.1:ECX[5]=0)\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* CPUID.80000001:EDX[20] = NX (required) */
    AnxCpuid(&r, 0x80000001);
    if (!(r.Edx & ANX_CPUID_80000001_EDX_NX)) {
        AnxDebugPrint("[HV:WRN] NX not supported\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* IA32_FEATURE_CONTROL: must be locked with VMXON-outside-SMX enabled */
    featureControl = __readmsr(ANX_MSR_IA32_FEATURE_CONTROL);
    if (!(featureControl & ANX_FEATURE_CONTROL_LOCK)) {
        /* Not locked - we can set it ourselves */
        featureControl |= ANX_FEATURE_CONTROL_LOCK | ANX_FEATURE_CONTROL_VMXON_OUT;
        __writemsr(ANX_MSR_IA32_FEATURE_CONTROL, featureControl);
        AnxDebugPrint("[HV:INF] IA32_FEATURE_CONTROL locked and VMX enabled\n");
    } else if (!(featureControl & ANX_FEATURE_CONTROL_VMXON_OUT)) {
        AnxDebugPrint("[HV:WRN] VMX disabled by BIOS (FEATURE_CONTROL locked)\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* CR0/CR4 fixed bits (informational, applied during VMCS setup) */
    cr0Fixed0 = __readmsr(ANX_MSR_IA32_VMX_CR0_FIXED0);
    cr0Fixed1 = __readmsr(ANX_MSR_IA32_VMX_CR0_FIXED1);
    cr4Fixed0 = __readmsr(ANX_MSR_IA32_VMX_CR4_FIXED0);
    cr4Fixed1 = __readmsr(ANX_MSR_IA32_VMX_CR4_FIXED1);
    AnxDebugPrint("[HV:DBG] CR0 fixed0=%p fixed1=%p\n", cr0Fixed0, cr0Fixed1);
    AnxDebugPrint("[HV:DBG] CR4 fixed0=%p fixed1=%p\n", cr4Fixed0, cr4Fixed1);

    return STATUS_SUCCESS;
}

/* ─── AMD Capability Detection ────────────────────────────────────── */

static
NTSTATUS
AnxCheckAmdCapabilities(VOID)
{
    ANX_CPUID_RESULT r;
    ULONG64 vmCr;
    ULONG nasid;

    /* CPUID.80000001:ECX[2] = SVM */
    AnxCpuid(&r, 0x80000001);
    if (!(r.Ecx & ANX_CPUID_80000001_ECX_SVM)) {
        AnxDebugPrint("[HV:WRN] SVM not supported (CPUID.80000001:ECX[2]=0)\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* CPUID.80000001:EDX[20] = NX (required) */
    if (!(r.Edx & ANX_CPUID_80000001_EDX_NX)) {
        AnxDebugPrint("[HV:WRN] NX not supported\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* CPUID.8000000A:EDX[0] = Nested Paging (NPT) */
    AnxCpuid(&r, 0x8000000A);
    if (!(r.Edx & ANX_CPUID_8000000A_EDX_NP)) {
        AnxDebugPrint("[HV:WRN] Nested Paging (NPT) not supported\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* NASID: number of available ASIDs (must be >= 1) */
    nasid = r.Ebx;
    if (nasid < 1) {
        AnxDebugPrint("[HV:WRN] No ASIDs available (NASID=%d)\n", (ULONG64)nasid);
        return STATUS_NOT_SUPPORTED;
    }
    AnxDebugPrint("[HV:INF] AMD SVM: NASID=%d, NPT=yes\n", (ULONG64)nasid);

    /* VM_CR MSR: SVMDIS bit must be 0 */
    vmCr = __readmsr(ANX_MSR_VM_CR);
    if (vmCr & ANX_VM_CR_SVMDIS) {
        AnxDebugPrint("[HV:WRN] SVM disabled by BIOS (VM_CR.SVMDIS=1)\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* Optional features (informational) */
    if (r.Edx & ANX_CPUID_8000000A_EDX_SVML)
        AnxDebugPrint("[HV:DBG] SVML (SVM Lock) available\n");
    if (r.Edx & ANX_CPUID_8000000A_EDX_AVIC)
        AnxDebugPrint("[HV:DBG] AVIC available\n");

    return STATUS_SUCCESS;
}

/* ─── Per-CPU Allocation ──────────────────────────────────────────── */

static
NTSTATUS
AnxAllocatePerCpuStructures(VOID)
{
    ULONG i;
    SIZE_T arraySize = g_CpuCount * sizeof(PANX_HV_PER_CPU);

    /* Allocate pointer array */
    g_PerCpuArray = (PANX_HV_PER_CPU*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, arraySize, 'xHnA');
    if (!g_PerCpuArray) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_PerCpuArray, arraySize);

    for (i = 0; i < g_CpuCount; i++) {
        PANX_HV_PER_CPU perCpu = (PANX_HV_PER_CPU)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(ANX_HV_PER_CPU), 'xHnA');
        if (!perCpu) {
            AnxFreePerCpuStructures();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(perCpu, sizeof(ANX_HV_PER_CPU));
        perCpu->CpuNumber = i;

        /* Allocate host stack (16KB) */
        perCpu->HostStack = AnxAllocateContiguous(ANX_HOST_STACK_SIZE);
        if (!perCpu->HostStack) {
            ExFreePoolWithTag(perCpu, 'xHnA');
            AnxFreePerCpuStructures();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        perCpu->HostStackTop = (PUCHAR)perCpu->HostStack + ANX_HOST_STACK_SIZE - 8;

        /* Platform-specific allocations */
        if (g_CpuVendor == ANX_CPU_INTEL) {
            /* VMXON region: 4KB aligned */
            perCpu->Intel.VmxonRegion = AnxAllocateContiguous(ANX_PAGE_SIZE);
            perCpu->Intel.VmcsRegion = AnxAllocateContiguous(ANX_PAGE_SIZE);
            if (!perCpu->Intel.VmxonRegion || !perCpu->Intel.VmcsRegion) {
                AnxFreePerCpuStructures();
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            perCpu->Intel.VmcsLaunched = FALSE;
        } else {
            /* VMCB region: 4KB aligned */
            perCpu->Amd.VmcbRegion = AnxAllocateContiguous(ANX_PAGE_SIZE);
            perCpu->Amd.HostSaveArea = AnxAllocateContiguous(ANX_PAGE_SIZE);
            if (!perCpu->Amd.VmcbRegion || !perCpu->Amd.HostSaveArea) {
                AnxFreePerCpuStructures();
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            perCpu->Amd.Asid = 1;  /* Single guest: all CPUs share ASID 1 */
        }

        g_PerCpuArray[i] = perCpu;
    }

    AnxDebugPrint("[HV:INF] Allocated per-CPU structures for %d CPUs\n",
                  (ULONG64)g_CpuCount);
    return STATUS_SUCCESS;
}

static
VOID
AnxFreePerCpuStructures(VOID)
{
    if (!g_PerCpuArray) return;

    for (ULONG i = 0; i < g_CpuCount; i++) {
        PANX_HV_PER_CPU perCpu = g_PerCpuArray[i];
        if (!perCpu) continue;

        if (perCpu->HostStack) AnxFreeContiguous(perCpu->HostStack);

        if (g_CpuVendor == ANX_CPU_INTEL) {
            if (perCpu->Intel.VmxonRegion) AnxFreeContiguous(perCpu->Intel.VmxonRegion);
            if (perCpu->Intel.VmcsRegion) AnxFreeContiguous(perCpu->Intel.VmcsRegion);
        } else {
            if (perCpu->Amd.VmcbRegion) AnxFreeContiguous(perCpu->Amd.VmcbRegion);
            if (perCpu->Amd.HostSaveArea) AnxFreeContiguous(perCpu->Amd.HostSaveArea);
        }

        ExFreePoolWithTag(perCpu, 'xHnA');
        g_PerCpuArray[i] = NULL;
    }

    ExFreePoolWithTag(g_PerCpuArray, 'xHnA');
    g_PerCpuArray = NULL;
}

/* ─── Page Table Allocation & Build ───────────────────────────────── */

/*
 * Allocate memory for secondary page tables (EPT/NPT) and build
 * the 1:1 identity map. Called once from DriverEntry before IPI broadcast.
 *
 * Memory layout (contiguous allocation):
 *   [0]:          ANX_PAGE_TABLE_CTX structure
 *   [ctx+1]:      PML4 (4KB) + PDPTs + PDs (variable, depends on RAM size)
 *   [after PDs]:  Split page pool (for Phase 4 page splitting)
 *
 * For 16GB RAM: ~18 pages for tables + 64 pages split pool = ~328KB total.
 */
static
NTSTATUS
AnxAllocateAndBuildPageTables(VOID)
{
    PANX_PAGE_TABLE_CTX ctx;
    ULONG64 maxPhys;
    ULONG64 pdptCount;
    ULONG64 tablePages;
    ULONG64 tableSize;
    ULONG64 splitPoolPages = 64;
    ULONG64 splitPoolSize = splitPoolPages * ANX_PAGE_SIZE;
    ULONG64 totalSize;
    PVOID allocation;
    NTSTATUS status;

    if (g_CpuCount == 0 || !g_PerCpuArray[0]) {
        return STATUS_UNSUCCESSFUL;
    }

    /* Query physical memory size */
    maxPhys = AnxGetMaxPhysicalAddress();
    if (maxPhys == 0) {
        maxPhys = 16ULL * 1024 * 1024 * 1024;  /* Default: assume 16GB */
    }

    /* Calculate table memory requirements:
     * PML4: 1 page
     * PDPT: ceil(maxPhys / 512GB) pages
     * PD: ceil(maxPhys / 1GB) pages (one PD per 1GB region)
     */
    pdptCount = (maxPhys + EPT_PAGE_SIZE_1GB * 512 - 1) / (EPT_PAGE_SIZE_1GB * 512);
    if (pdptCount == 0) pdptCount = 1;
    tablePages = 1 + pdptCount + (maxPhys + EPT_PAGE_SIZE_1GB - 1) / EPT_PAGE_SIZE_1GB;
    tableSize = tablePages * ANX_PAGE_SIZE;

    totalSize = sizeof(ANX_PAGE_TABLE_CTX) + tableSize + splitPoolSize;

    /* Allocate contiguous memory (physically contiguous, non-paged) */
    allocation = AnxAllocateContiguous(totalSize);
    if (!allocation) {
        AnxDebugPrint("[HV:ERR] Page table alloc failed: need %d KB\n",
                      (ULONG64)(totalSize / 1024));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(allocation, totalSize);

    /* Layout the allocation */
    ctx = (PANX_PAGE_TABLE_CTX)allocation;
    ctx->RootTablePa = (ULONG64)AnxVirtToPhys((PUCHAR)allocation + sizeof(ANX_PAGE_TABLE_CTX));
    ctx->MaxPhysicalAddress = maxPhys;
    ctx->SplitPagePool = (PUCHAR)allocation + sizeof(ANX_PAGE_TABLE_CTX) + tableSize;
    ctx->SplitPoolSize = splitPoolSize;
    ctx->SplitPoolUsed = 0;

    /* Store context in CPU 0's per-CPU struct (shared by all CPUs) */
    g_PerCpuArray[0]->PageTableCtx = ctx;
    g_PerCpuArray[0]->PageTablePml4 = (PVOID)ctx->RootTablePa;

    /* Build the identity map via HAL */
    status = g_HvOps.BuildPageTables();
    if (!NT_SUCCESS(status)) {
        AnxDebugPrint("[HV:ERR] BuildPageTables failed: 0x%x\n", (ULONG64)status);
        AnxFreeContiguous(allocation);
        g_PerCpuArray[0]->PageTableCtx = NULL;
        g_PerCpuArray[0]->PageTablePml4 = NULL;
        return status;
    }

    /* Propagate PageTablePointer to all CPUs */
    for (ULONG i = 0; i < g_CpuCount; i++) {
        g_PerCpuArray[i]->PageTableCtx = ctx;
        g_PerCpuArray[i]->PageTablePointer = ctx->TablePointer;
        g_PerCpuArray[i]->PageTablePml4 = (PVOID)ctx->RootTablePa;
    }

    AnxDebugPrint("[HV:INF] Page tables built: %d KB tables, %d KB split pool, ptr=0x%p\n",
                  (ULONG64)(tableSize / 1024), (ULONG64)(splitPoolSize / 1024),
                  ctx->TablePointer);

    return STATUS_SUCCESS;
}

/* ─── Staged Per-CPU Callbacks (each does one VMX step) ─────────── */

static
ULONG_PTR
AnxStageInitCallback(
    _In_ ULONG_PTR Argument
)
{
    NTSTATUS status;
    ULONG cpu = KeGetCurrentProcessorNumber();
    UNREFERENCED_PARAMETER(Argument);
    if (cpu >= g_CpuCount || !g_PerCpuArray[cpu]) return 1;

    /* Get APIC ID */
    {
        ANX_CPUID_RESULT r;
        AnxCpuid(&r, 1);
        g_PerCpuArray[cpu]->ApicId = (r.Ebx >> 24) & 0xFF;
    }

    status = g_HvOps.Init(cpu);
    return NT_SUCCESS(status) ? 0 : 1;
}

/* ─── Stage 4: VMLAUNCH/VMRUN (runs on each CPU via IPI) ────────── */

static
ULONG_PTR
AnxInitializeCpuCallback(
    _In_ ULONG_PTR Argument
)
{
    NTSTATUS status;
    ULONG cpu = KeGetCurrentProcessorNumber();
    PANX_HV_PER_CPU perCpu;

    UNREFERENCED_PARAMETER(Argument);

    if (cpu >= g_CpuCount) return 1;
    perCpu = g_PerCpuArray[cpu];
    if (!perCpu) return 1;

    /* TSC synchronization: compensate for per-core TSC drift */
    {
        ULONG64 currentTsc = __rdtsc();
        LONG64 tscOffset = (LONG64)(g_ReferenceTsc - currentTsc);
        if (tscOffset != 0) {
            g_HvOps.SetTscOffset(cpu, tscOffset);
        }
    }

    /* Enter guest (VMLAUNCH/VMRUN) - after this, we're in root mode */
    status = g_HvOps.EnterGuest(cpu);
    if (!NT_SUCCESS(status)) {
        AnxDebugPrint("[HV:ERR] CPU %d EnterGuest failed: 0x%x\n",
                      (ULONG64)cpu, (ULONG64)status);
        return 1;
    }

    perCpu->VirtEnabled = TRUE;
    AnxDebugPrint("[HV:INF] CPU %d virtualized (APIC ID %d)\n",
                  (ULONG64)cpu, (ULONG64)perCpu->ApicId);
    return 0;
}

/* ─── Per-CPU Shutdown Callback ───────────────────────────────────── */

static
VOID
AnxShutdownCpuCallback(
    _In_ ULONG_PTR Argument
)
{
    ULONG cpu = KeGetCurrentProcessorNumber();
    PANX_HV_PER_CPU perCpu;

    UNREFERENCED_PARAMETER(Argument);

    if (cpu >= g_CpuCount) return;
    perCpu = g_PerCpuArray[cpu];
    if (!perCpu || !perCpu->VirtEnabled) return;

    g_HvOps.Shutdown(cpu);
    perCpu->VirtEnabled = FALSE;
    AnxDebugPrint("[HV:INF] CPU %d virtualization stopped\n", (ULONG64)cpu);
}

/* ─── Degradation State Management ────────────────────────────────── */

static
VOID
AnxSetDegradedMode(
    _In_ ANX_HV_MODE Mode,
    _In_ const char* Reason
)
{
    g_OperatingMode = Mode;
    g_HypervisorActive = FALSE;
    if (Reason) {
        RtlStringCbCopyA(g_DegradReason, sizeof(g_DegradReason), Reason);
    }
}

/* ─── Device Object & IOCTL ───────────────────────────────────────── */

static
NTSTATUS
AnxCreateDeviceObject(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    NTSTATUS status;
    UNICODE_STRING devName;
    UNICODE_STRING symLink;

    RtlInitUnicodeString(&devName, ANX_HV_DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &devName,
                            FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&symLink, ANX_HV_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = AnxIrpDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = AnxIrpDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AnxIrpDispatch;

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    AnxDebugPrint("[HV:INF] Device object created: %s\n", (ULONG64)ANX_HV_DEVICE_NAME);
    return STATUS_SUCCESS;
}

static
VOID
AnxDestroyDeviceObject(VOID)
{
    UNICODE_STRING symLink;

    if (!g_DeviceObject) return;

    RtlInitUnicodeString(&symLink, ANX_HV_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(g_DeviceObject);
    g_DeviceObject = NULL;
}

static
NTSTATUS
AnxIrpDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG info = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);

    switch (irpSp->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        break;

    case IRP_MJ_DEVICE_CONTROL:
        switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
        case ANX_HV_IOCTL_GET_STATUS: {
            ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
            PANX_HV_STATUS_INFO out;

            if (outLen < sizeof(ANX_HV_STATUS_INFO)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            out = (PANX_HV_STATUS_INFO)Irp->AssociatedIrp.SystemBuffer;
            RtlZeroMemory(out, sizeof(ANX_HV_STATUS_INFO));
            out->VersionMajor = ANX_HV_VERSION_MAJOR;
            out->VersionMinor = ANX_HV_VERSION_MINOR;
            out->VersionPatch = ANX_HV_VERSION_PATCH;
            out->OperatingMode = (ULONG)g_OperatingMode;
            out->CpuVendor = (ULONG)g_CpuVendor;
            out->CpuCount = g_HypervisorActive ? g_CpuCount : 0;
            out->PageTablesActive = g_PageTablesActive ? 1 : 0;

            if (g_HypervisorActive && g_HvOps.PlatformName) {
                RtlStringCbCopyA(out->PlatformName, sizeof(out->PlatformName),
                                 g_HvOps.PlatformName);
            }
            if (g_OperatingMode != ANX_HV_MODE_FULL) {
                RtlStringCbCopyA(out->DegradReason, sizeof(out->DegradReason),
                                 g_DegradReason);
            }

            info = sizeof(ANX_HV_STATUS_INFO);
            break;
        }

        case ANX_HV_IOCTL_GET_STATS: {
            ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
            PANX_HV_STATS out;

            if (outLen < sizeof(ANX_HV_STATS)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            if (!g_HypervisorActive) {
                status = STATUS_NOT_SUPPORTED;
                break;
            }

            out = (PANX_HV_STATS)Irp->AssociatedIrp.SystemBuffer;
            AnxProtectGetStats(out);
            info = sizeof(ANX_HV_STATS);
            break;
        }

        case ANX_HV_IOCTL_GET_VIOLATIONS: {
            ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
            ULONG eventSize = sizeof(ANX_HV_VIOLATION_EVENT);
            ULONG maxEvents;

            if (!g_HypervisorActive) {
                status = STATUS_NOT_SUPPORTED;
                break;
            }
            if (outLen < eventSize) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            maxEvents = outLen / eventSize;
            info = AnxProtectDrainViolations(
                (PANX_HV_VIOLATION_EVENT)Irp->AssociatedIrp.SystemBuffer, maxEvents);
            info *= eventSize;
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ─── Driver Unload ───────────────────────────────────────────────── */

VOID
AnxDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    AnxDebugPrint("[HV:INF] Driver unloading...\n");

    if (g_HypervisorActive) {
        KeIpiGenericCall(AnxShutdownCpuCallback, 0);
        g_HypervisorActive = FALSE;
    }

    if (g_ProcessorCallbackHandle) {
        KeDeregisterProcessorChangeCallback(g_ProcessorCallbackHandle);
        g_ProcessorCallbackHandle = NULL;
    }

    AnxFreePerCpuStructures();
    AnxDestroyDeviceObject();

    AnxDebugPrint("[HV:INF] Driver unloaded\n");
}
