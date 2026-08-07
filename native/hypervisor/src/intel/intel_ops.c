/*
 * AnXinHypervisor - Intel VT-x HAL Operations
 * Module: native/hypervisor/src/intel/intel_ops.c
 *
 * Fills the ANX_HV_OPS vtable with Intel VT-x implementations.
 */

#include "../../include/platform.h"
#include "../../include/hal.h"
#include "../../include/per_cpu.h"
#include "../../include/exit_reasons.h"
#include "../../include/ept.h"
#include "../../include/protect.h"

extern VOID AnxDebugPrint(const char* Fmt, ...);

/* From vmx.c */
extern NTSTATUS AnxVmxVmxon(ULONG CpuNumber);
extern VOID AnxVmxVmxoff(VOID);
extern NTSTATUS AnxVmxLoadVmcs(ULONG CpuNumber);
extern NTSTATUS AnxVmxEnterGuest(ULONG CpuNumber);

/* From vmcs.c */
extern NTSTATUS AnxVmxSetupVmcs(ULONG CpuNumber);
extern ULONG64 VmcsRead(ULONG32 FieldEncoding);
extern VOID VmcsWrite(ULONG32 FieldEncoding, ULONG64 Value);

/* From entry_intel.asm */
extern VOID AnxVmxExitEntry(VOID);
extern ULONG64 AnxVmxLaunchGuest(VOID);
extern ULONG64 AnxVmxResumeGuest(VOID);

/* VMCS field encodings (subset needed here) */
#define VMCS_RO_VMEXIT_REASON       0x4402
#define VMCS_RO_EXIT_QUALIFICATION  0x6400
#define VMCS_RO_GUEST_PHYS_ADDR     0x2400
#define VMCS_GUEST_RIP              0x681E
#define VMCS_GUEST_RSP              0x681C
#define VMCS_GUEST_CR3              0x6802
#define VMCS_CTRL_VMENTRY_INTR_INFO 0x4016
#define VMCS_CTRL_VMENTRY_EXC_ERR   0x4018
#define VMCS_CTRL_PROC_BASED        0x4002
#define VMCS_RO_VMEXIT_INSTR_LEN    0x440C

/* ─── Lifecycle ───────────────────────────────────────────────────── */

extern VOID AnxLogToFile(const char* Msg);

static
NTSTATUS
IntelInit(
    _In_ ULONG CpuNumber
)
{
    NTSTATUS status;

    /* VMXON */
    AnxLogToFile("[HV] IntelInit: before VMXON");
    status = AnxVmxVmxon(CpuNumber);
    if (!NT_SUCCESS(status)) {
        AnxLogToFile("[HV] IntelInit: VMXON FAILED");
        return status;
    }
    AnxLogToFile("[HV] IntelInit: VMXON OK");

    /* Load VMCS (VMCLEAR + VMPTRLD) */
    AnxLogToFile("[HV] IntelInit: before LoadVmcs");
    status = AnxVmxLoadVmcs(CpuNumber);
    if (!NT_SUCCESS(status)) {
        AnxLogToFile("[HV] IntelInit: LoadVmcs FAILED");
        return status;
    }
    AnxLogToFile("[HV] IntelInit: LoadVmcs OK");

    /* Fill VMCS fields */
    AnxLogToFile("[HV] IntelInit: before SetupVmcs");
    status = AnxVmxSetupVmcs(CpuNumber);
    if (!NT_SUCCESS(status)) {
        AnxLogToFile("[HV] IntelInit: SetupVmcs FAILED");
        return status;
    }
    AnxLogToFile("[HV] IntelInit: SetupVmcs OK");

    return STATUS_SUCCESS;
}

static
NTSTATUS
IntelEnterGuest(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    ULONG64 result;

    if (!perCpu->Intel.VmcsLaunched) {
        result = AnxVmxLaunchGuest();
        if (result != 0) {
            return STATUS_UNSUCCESSFUL;
        }
        perCpu->Intel.VmcsLaunched = TRUE;
        return STATUS_SUCCESS;
    } else {
        result = AnxVmxResumeGuest();
        if (result != 0) {
            return STATUS_UNSUCCESSFUL;
        }
        return STATUS_SUCCESS;
    }
}

static
VOID
IntelShutdown(
    _In_ ULONG CpuNumber
)
{
    UNREFERENCED_PARAMETER(CpuNumber);
    AnxVmxVmxoff();
}

/* ─── Exit Handling ───────────────────────────────────────────────── */

static
VOID
IntelHandleExit(
    _In_ ULONG CpuNumber
)
{
    /* Dispatched by unified exit_handler.c via GetExitReason */
    UNREFERENCED_PARAMETER(CpuNumber);
}

static
ULONG
IntelGetExitReason(
    _In_ ULONG CpuNumber
)
{
    ULONG64 reason = VmcsRead(VMCS_RO_VMEXIT_REASON);
    ULONG basicReason = (ULONG)(reason & 0xFFFF);

    UNREFERENCED_PARAMETER(CpuNumber);

    switch (basicReason) {
    case VMX_EXIT_CPUID:            return ANX_EXIT_CPUID;
    case VMX_EXIT_CR_ACCESS:        return ANX_EXIT_CR_ACCESS;
    case VMX_EXIT_MSR_READ:         return ANX_EXIT_MSR_READ;
    case VMX_EXIT_MSR_WRITE:        return ANX_EXIT_MSR_WRITE;
    case VMX_EXIT_EPT_VIOLATION:    return ANX_EXIT_PAGE_FAULT;
    case VMX_EXIT_VMCALL:           return ANX_EXIT_HYPERCALL;
    case VMX_EXIT_IO:               return ANX_EXIT_IO;
    case VMX_EXIT_EXCEPTION_NMI:    return ANX_EXIT_EXCEPTION;
    case VMX_EXIT_TRIPLE_FAULT:     return ANX_EXIT_TRIPLE_FAULT;
    case VMX_EXIT_MTF:              return ANX_EXIT_SINGLE_STEP;
    case VMX_EXIT_EXTERNAL_INT:     return ANX_EXIT_EXTERNAL_INT;
    case VMX_EXIT_HLT:              return ANX_EXIT_HLT;
    case VMX_EXIT_VMX_PREEMPT:      return ANX_EXIT_VMX_PREEMPT;
    default:                        return ANX_EXIT_UNKNOWN;
    }
}

static
ULONG64
IntelGetExitQualification(
    _In_ ULONG CpuNumber
)
{
    UNREFERENCED_PARAMETER(CpuNumber);
    return VmcsRead(VMCS_RO_EXIT_QUALIFICATION);
}

/* ─── Guest State Access ──────────────────────────────────────────── */

/*
 * Guest GPR access via the saved register context on host stack.
 * In Phase 1, we access via VMCS for RIP/RSP/CR3 and via the
 * register save area (passed from asm) for GPRs.
 * For simplicity, GPR read/write here uses VMCS where possible.
 */
static
ULONG64
IntelGetGuestReg(
    _In_ ULONG CpuNumber,
    _In_ ULONG RegIndex
)
{
    UNREFERENCED_PARAMETER(CpuNumber);
    UNREFERENCED_PARAMETER(RegIndex);
    /* GPRs are accessed via the stack frame in the exit handler.
     * This function is a placeholder for HAL completeness. */
    return 0;
}

static
VOID
IntelSetGuestReg(
    _In_ ULONG CpuNumber,
    _In_ ULONG RegIndex,
    _In_ ULONG64 Value
)
{
    UNREFERENCED_PARAMETER(CpuNumber);
    UNREFERENCED_PARAMETER(RegIndex);
    UNREFERENCED_PARAMETER(Value);
}

static
ULONG64
IntelGetGuestRip(
    _In_ ULONG CpuNumber
)
{
    UNREFERENCED_PARAMETER(CpuNumber);
    return VmcsRead(VMCS_GUEST_RIP);
}

static
VOID
IntelSetGuestRip(
    _In_ ULONG CpuNumber,
    _In_ ULONG64 Rip
)
{
    UNREFERENCED_PARAMETER(CpuNumber);
    VmcsWrite(VMCS_GUEST_RIP, Rip);
}

static
ULONG64
IntelGetGuestCr3(
    _In_ ULONG CpuNumber
)
{
    UNREFERENCED_PARAMETER(CpuNumber);
    return VmcsRead(VMCS_GUEST_CR3);
}

/* ─── Secondary Page Table (EPT) ──────────────────────────────────── */

/* From ept.c */
extern NTSTATUS AnxEptBuildIdentityMap(PANX_PAGE_TABLE_CTX Ctx);
extern VOID AnxEptInvept(ULONG Type, ULONG64 Eptp);
extern VOID AnxEptFlushAll(PANX_PAGE_TABLE_CTX Ctx);
extern NTSTATUS AnxEptSetPermission(PANX_PAGE_TABLE_CTX Ctx, ULONG64 Gpa, ULONG64 PermMask);

static
NTSTATUS
IntelBuildPageTables(VOID)
{
    PANX_HV_PER_CPU perCpu;
    PANX_PAGE_TABLE_CTX ctx;

    if (g_CpuCount == 0 || !g_PerCpuArray[0]) {
        return STATUS_UNSUCCESSFUL;
    }

    perCpu = g_PerCpuArray[0];
    ctx = (PANX_PAGE_TABLE_CTX)perCpu->PageTableCtx;
    if (!ctx) return STATUS_UNSUCCESSFUL;

    return AnxEptBuildIdentityMap(ctx);
}

static
NTSTATUS
IntelProtectPage(
    _In_ ULONG64 Gpa,
    _In_ ULONG Flags
)
{
    PANX_PAGE_TABLE_CTX ctx;
    ULONG64 perm = EPT_PERM_READ | EPT_PERM_EXECUTE;

    if (g_CpuCount == 0 || !g_PerCpuArray[0]) return STATUS_UNSUCCESSFUL;
    ctx = (PANX_PAGE_TABLE_CTX)g_PerCpuArray[0]->PageTableCtx;
    if (!ctx) return STATUS_UNSUCCESSFUL;

    if (Flags & ANX_PROT_WRITE) perm |= EPT_PERM_WRITE;

    return AnxEptSetPermission(ctx, Gpa, perm);
}

static
NTSTATUS
IntelUnprotectPage(
    _In_ ULONG64 Gpa
)
{
    PANX_PAGE_TABLE_CTX ctx;
    ULONG64 perm = EPT_PERM_READ | EPT_PERM_WRITE | EPT_PERM_EXECUTE;

    if (g_CpuCount == 0 || !g_PerCpuArray[0]) return STATUS_UNSUCCESSFUL;
    ctx = (PANX_PAGE_TABLE_CTX)g_PerCpuArray[0]->PageTableCtx;
    if (!ctx) return STATUS_UNSUCCESSFUL;

    return AnxEptSetPermission(ctx, Gpa, perm);
}

static
VOID
IntelFlushTlb(VOID)
{
    PANX_PAGE_TABLE_CTX ctx;

    if (g_CpuCount == 0 || !g_PerCpuArray[0]) return;
    ctx = (PANX_PAGE_TABLE_CTX)g_PerCpuArray[0]->PageTableCtx;

    AnxEptFlushAll(ctx);
}

/* ─── Single Step (Monitor Trap Flag) ─────────────────────────────── */

static
NTSTATUS
IntelEnableSingleStep(
    _In_ ULONG CpuNumber
)
{
    ULONG64 procBased;
    UNREFERENCED_PARAMETER(CpuNumber);

    /* Set MTF bit (bit 27) in Primary Processor-Based Controls */
    procBased = VmcsRead(VMCS_CTRL_PROC_BASED);
    procBased |= (1ULL << 27);
    VmcsWrite(VMCS_CTRL_PROC_BASED, procBased);
    return STATUS_SUCCESS;
}

static
VOID
IntelDisableSingleStep(
    _In_ ULONG CpuNumber
)
{
    ULONG64 procBased;
    UNREFERENCED_PARAMETER(CpuNumber);

    procBased = VmcsRead(VMCS_CTRL_PROC_BASED);
    procBased &= ~(1ULL << 27);
    VmcsWrite(VMCS_CTRL_PROC_BASED, procBased);
}

/* ─── Exception Injection ─────────────────────────────────────────── */

static
VOID
IntelInjectPF(
    _In_ ULONG CpuNumber,
    _In_ ULONG64 FaultAddr,
    _In_ ULONG ErrorCode
)
{
    /*
     * VM-Entry Interruption-Information (VMCS 0x4016):
     *   Vector = 14 (#PF), Type = 3 (HW exception),
     *   Deliver error code = 1, Valid = 1
     */
    ULONG64 intrInfo = (1ULL << 31) | (1ULL << 11) | (3ULL << 8) | 14;

    UNREFERENCED_PARAMETER(CpuNumber);

    VmcsWrite(VMCS_CTRL_VMENTRY_INTR_INFO, intrInfo);
    VmcsWrite(VMCS_CTRL_VMENTRY_EXC_ERR, (ULONG64)ErrorCode);

    /* Intel VMX has no Guest CR2 VMCS field.
     * CR2 is shared between root/non-root; load it directly. */
    __writecr2(FaultAddr);
}

static
VOID
IntelInjectUD(
    _In_ ULONG CpuNumber
)
{
    /* Vector = 6 (#UD), Type = 3, no error code, Valid = 1 */
    ULONG64 intrInfo = (1ULL << 31) | (3ULL << 8) | 6;

    UNREFERENCED_PARAMETER(CpuNumber);
    VmcsWrite(VMCS_CTRL_VMENTRY_INTR_INFO, intrInfo);
}

/* ─── TSC Offset ──────────────────────────────────────────────────── */

static
VOID
IntelSetTscOffset(
    _In_ ULONG CpuNumber,
    _In_ LONG64 Offset
)
{
    UNREFERENCED_PARAMETER(CpuNumber);
    /* VMCS 0x2010: TSC Offset (64-bit control field) */
    VmcsWrite(0x2010, (ULONG64)Offset);
}

/* ─── Vtable Initialization ───────────────────────────────────────── */

VOID
AnxIntelInitOps(
    _Out_ PANX_HV_OPS Ops
)
{
    Ops->PlatformName       = "Intel VT-x";
    Ops->Init               = IntelInit;
    Ops->EnterGuest         = IntelEnterGuest;
    Ops->Shutdown           = IntelShutdown;
    Ops->HandleExit         = IntelHandleExit;
    Ops->GetExitReason      = IntelGetExitReason;
    Ops->GetExitQualification = IntelGetExitQualification;
    Ops->GetGuestReg        = IntelGetGuestReg;
    Ops->SetGuestReg        = IntelSetGuestReg;
    Ops->GetGuestRip        = IntelGetGuestRip;
    Ops->SetGuestRip        = IntelSetGuestRip;
    Ops->GetGuestCr3        = IntelGetGuestCr3;
    Ops->BuildPageTables    = IntelBuildPageTables;
    Ops->ProtectPage        = IntelProtectPage;
    Ops->UnprotectPage      = IntelUnprotectPage;
    Ops->FlushTlb           = IntelFlushTlb;
    Ops->EnableSingleStep   = IntelEnableSingleStep;
    Ops->DisableSingleStep  = IntelDisableSingleStep;
    Ops->InjectPF           = IntelInjectPF;
    Ops->InjectUD           = IntelInjectUD;
    Ops->SetTscOffset       = IntelSetTscOffset;
}
