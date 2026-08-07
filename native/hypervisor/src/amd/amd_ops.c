/*
 * AnXinHypervisor - AMD SVM HAL Operations
 * Module: native/hypervisor/src/amd/amd_ops.c
 *
 * Fills the ANX_HV_OPS vtable with AMD SVM implementations.
 */

#include "../../include/platform.h"
#include "../../include/hal.h"
#include "../../include/per_cpu.h"
#include "../../include/exit_reasons.h"
#include "../../include/ept.h"
#include "../../include/protect.h"

extern VOID AnxDebugPrint(const char* Fmt, ...);

/* From svm.c */
extern NTSTATUS AnxSvmInitCpu(ULONG CpuNumber);
extern NTSTATUS AnxSvmEnterGuest(ULONG CpuNumber);
extern VOID AnxSvmDisable(VOID);

/* From entry_amd.asm */
extern VOID AnxSvmInvlpga(PVOID Gva, ULONG Asid);

/* VMCB access helpers (from vmcb.c) */
typedef struct _VMCB_CONTROL_AREA VMCB_CONTROL_AREA;
typedef struct _VMCB_STATE_SAVE_AREA VMCB_STATE_SAVE_AREA;

#define VMCB_CTRL_OFFSET(ctrl, field) \
    (*(PULONG64)((PUCHAR)(ctrl) + FIELD_OFFSET(VMCB_CONTROL_AREA, field)))

/* VMCB field offsets (hardcoded for speed in root context) */
#define VMCB_OFF_EXIT_CODE      0x070
#define VMCB_OFF_EXIT_INFO1     0x078
#define VMCB_OFF_EXIT_INFO2     0x080
#define VMCB_OFF_EVENT_INJ      0x0A8
#define VMCB_OFF_NRIP           0x0B8
#define VMCB_OFF_TSC_OFFSET     0x050

/* State save offsets (relative to VMCB base) */
#define VMCB_SS_OFF_EFER        0x4D0
#define VMCB_SS_OFF_CR4         0x548
#define VMCB_SS_OFF_CR3         0x550
#define VMCB_SS_OFF_CR0         0x558
#define VMCB_SS_OFF_RFLAGS      0x570
#define VMCB_SS_OFF_RIP         0x578
#define VMCB_SS_OFF_RSP         0x5D8
#define VMCB_SS_OFF_RAX         0x5F8

/* ─── VMCB Memory Access Helpers ──────────────────────────────────── */

__forceinline
ULONG64
VmcbReadCtrl(
    _In_ PVOID Vmcb,
    _In_ ULONG Offset
)
{
    return *(PULONG64)((PUCHAR)Vmcb + Offset);
}

__forceinline
VOID
VmcbWriteCtrl(
    _In_ PVOID Vmcb,
    _In_ ULONG Offset,
    _In_ ULONG64 Value
)
{
    *(PULONG64)((PUCHAR)Vmcb + Offset) = Value;
}

__forceinline
ULONG64
VmcbReadState(
    _In_ PVOID Vmcb,
    _In_ ULONG Offset
)
{
    return *(PULONG64)((PUCHAR)Vmcb + Offset);
}

__forceinline
VOID
VmcbWriteState(
    _In_ PVOID Vmcb,
    _In_ ULONG Offset,
    _In_ ULONG64 Value
)
{
    *(PULONG64)((PUCHAR)Vmcb + Offset) = Value;
}

/* ─── Lifecycle ───────────────────────────────────────────────────── */

static
NTSTATUS
AmdInit(
    _In_ ULONG CpuNumber
)
{
    return AnxSvmInitCpu(CpuNumber);
}

static
NTSTATUS
AmdEnterGuest(
    _In_ ULONG CpuNumber
)
{
    return AnxSvmEnterGuest(CpuNumber);
}

static
VOID
AmdShutdown(
    _In_ ULONG CpuNumber
)
{
    UNREFERENCED_PARAMETER(CpuNumber);
    AnxSvmDisable();
}

/* ─── Exit Handling ───────────────────────────────────────────────── */

static
VOID
AmdHandleExit(
    _In_ ULONG CpuNumber
)
{
    UNREFERENCED_PARAMETER(CpuNumber);
    /* Dispatched by unified exit_handler.c */
}

static
ULONG
AmdGetExitReason(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    ULONG64 exitCode = VmcbReadCtrl(perCpu->Amd.VmcbRegion, VMCB_OFF_EXIT_CODE);

    switch ((ULONG)exitCode) {
    case SVM_EXIT_CPUID:        return ANX_EXIT_CPUID;
    case SVM_EXIT_MSR_READ:     return ANX_EXIT_MSR_READ;
    case SVM_EXIT_MSR_WRITE:    return ANX_EXIT_MSR_WRITE;
    case SVM_EXIT_NPF:          return ANX_EXIT_PAGE_FAULT;
    case SVM_EXIT_VMMCALL:      return ANX_EXIT_HYPERCALL;
    case SVM_EXIT_IOIO:         return ANX_EXIT_IO;
    case SVM_EXIT_SHUTDOWN:     return ANX_EXIT_TRIPLE_FAULT;
    case SVM_EXIT_INTR:         return ANX_EXIT_EXTERNAL_INT;
    case SVM_EXIT_NMI:          return ANX_EXIT_NMI;
    case SVM_EXIT_HLT:          return ANX_EXIT_HLT;
    default:
        /* Check exception range (0x40-0x5F) */
        if (exitCode >= SVM_EXIT_EXCEPTION_BASE &&
            exitCode < SVM_EXIT_EXCEPTION_BASE + 32) {
            if (exitCode == SVM_EXIT_EXCEPTION_DB)
                return ANX_EXIT_SINGLE_STEP;
            return ANX_EXIT_EXCEPTION;
        }
        /* Check CR write range (0x10-0x1F) */
        if (exitCode >= SVM_EXIT_CR_WRITE_BASE &&
            exitCode < SVM_EXIT_CR_WRITE_BASE + 16) {
            return ANX_EXIT_CR_ACCESS;
        }
        return ANX_EXIT_UNKNOWN;
    }
}

static
ULONG64
AmdGetExitQualification(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    return VmcbReadCtrl(perCpu->Amd.VmcbRegion, VMCB_OFF_EXIT_INFO1);
}

/* ─── Guest State Access ──────────────────────────────────────────── */

static
ULONG64
AmdGetGuestReg(
    _In_ ULONG CpuNumber,
    _In_ ULONG RegIndex
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];

    /* Only RAX is in VMCB state save; others via stack frame */
    if (RegIndex == ANX_REG_RAX) {
        return VmcbReadState(perCpu->Amd.VmcbRegion, VMCB_SS_OFF_RAX);
    }
    /* Other GPRs accessed via exit handler stack frame */
    return 0;
}

static
VOID
AmdSetGuestReg(
    _In_ ULONG CpuNumber,
    _In_ ULONG RegIndex,
    _In_ ULONG64 Value
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];

    if (RegIndex == ANX_REG_RAX) {
        VmcbWriteState(perCpu->Amd.VmcbRegion, VMCB_SS_OFF_RAX, Value);
    }
}

static
ULONG64
AmdGetGuestRip(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    return VmcbReadState(perCpu->Amd.VmcbRegion, VMCB_SS_OFF_RIP);
}

static
VOID
AmdSetGuestRip(
    _In_ ULONG CpuNumber,
    _In_ ULONG64 Rip
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    VmcbWriteState(perCpu->Amd.VmcbRegion, VMCB_SS_OFF_RIP, Rip);
}

static
ULONG64
AmdGetGuestCr3(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    return VmcbReadState(perCpu->Amd.VmcbRegion, VMCB_SS_OFF_CR3);
}

/* ─── Secondary Page Table (NPT) ──────────────────────────────────── */

/* From npt.c */
extern NTSTATUS AnxNptBuildIdentityMap(PANX_PAGE_TABLE_CTX Ctx);
extern VOID AnxNptFlushAll(PANX_PAGE_TABLE_CTX Ctx);
extern NTSTATUS AnxNptSetPermission(PANX_PAGE_TABLE_CTX Ctx, ULONG64 Gpa, ULONG64 PermMask);

static
NTSTATUS
AmdBuildPageTables(VOID)
{
    PANX_HV_PER_CPU perCpu;
    PANX_PAGE_TABLE_CTX ctx;

    if (g_CpuCount == 0 || !g_PerCpuArray[0]) {
        return STATUS_UNSUCCESSFUL;
    }

    perCpu = g_PerCpuArray[0];
    ctx = (PANX_PAGE_TABLE_CTX)perCpu->PageTableCtx;
    if (!ctx) return STATUS_UNSUCCESSFUL;

    return AnxNptBuildIdentityMap(ctx);
}

static
NTSTATUS
AmdProtectPage(
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

    return AnxNptSetPermission(ctx, Gpa, perm);
}

static
NTSTATUS
AmdUnprotectPage(
    _In_ ULONG64 Gpa
)
{
    PANX_PAGE_TABLE_CTX ctx;
    ULONG64 perm = EPT_PERM_READ | EPT_PERM_WRITE | EPT_PERM_EXECUTE;

    if (g_CpuCount == 0 || !g_PerCpuArray[0]) return STATUS_UNSUCCESSFUL;
    ctx = (PANX_PAGE_TABLE_CTX)g_PerCpuArray[0]->PageTableCtx;
    if (!ctx) return STATUS_UNSUCCESSFUL;

    return AnxNptSetPermission(ctx, Gpa, perm);
}

static
VOID
AmdFlushTlb(VOID)
{
    /* INVLPGA with RAX=0 flushes all TLB entries for the ASID */
    AnxSvmInvlpga(NULL, 1);
}

/* ─── Single Step (RFLAGS.TF + #DB intercept) ─────────────────────── */

static
NTSTATUS
AmdEnableSingleStep(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    PVOID vmcb = perCpu->Amd.VmcbRegion;
    ULONG64 rflags;

    /* Set RFLAGS.TF (bit 8) in VMCB state save */
    rflags = VmcbReadState(vmcb, VMCB_SS_OFF_RFLAGS);
    rflags |= (1ULL << 8);  /* Trap Flag */
    VmcbWriteState(vmcb, VMCB_SS_OFF_RFLAGS, rflags);

    /* Enable #DB exception intercept (bit 1 in InterceptException) */
    {
        PULONG32 interceptExc = (PULONG32)((PUCHAR)vmcb + 0x010);
        *interceptExc |= (1UL << 1);
    }

    return STATUS_SUCCESS;
}

static
VOID
AmdDisableSingleStep(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    PVOID vmcb = perCpu->Amd.VmcbRegion;
    ULONG64 rflags;

    /* Clear RFLAGS.TF */
    rflags = VmcbReadState(vmcb, VMCB_SS_OFF_RFLAGS);
    rflags &= ~(1ULL << 8);
    VmcbWriteState(vmcb, VMCB_SS_OFF_RFLAGS, rflags);

    /* Disable #DB intercept */
    {
        PULONG32 interceptExc = (PULONG32)((PUCHAR)vmcb + 0x010);
        *interceptExc &= ~(1UL << 1);
    }
}

/* ─── Exception Injection ─────────────────────────────────────────── */

static
VOID
AmdInjectPF(
    _In_ ULONG CpuNumber,
    _In_ ULONG64 FaultAddr,
    _In_ ULONG ErrorCode
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    PVOID vmcb = perCpu->Amd.VmcbRegion;

    /*
     * EVENTINJ (VMCB +0x0A8):
     *   bit 63 = Valid
     *   bit 62 = Ev (error code valid)
     *   bits [10:8] = Type (3 = Exception)
     *   bits [7:0] = Vector (14 = #PF)
     *   bits [63:32] = Error code
     */
    ULONG64 eventInj = (1ULL << 63) | (1ULL << 62) | (3ULL << 8) | 14;
    eventInj |= ((ULONG64)ErrorCode << 32);

    VmcbWriteCtrl(vmcb, VMCB_OFF_EVENT_INJ, eventInj);

    /*
     * AMD: CR2 management is complex (no dedicated VMCB field).
     * Preferred approach: use NRip to skip the faulting instruction
     * instead of injecting #PF. Only inject when guest #PF handler
     * execution is required.
     */
    UNREFERENCED_PARAMETER(FaultAddr);
}

static
VOID
AmdInjectUD(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    PVOID vmcb = perCpu->Amd.VmcbRegion;

    /* Vector=6 (#UD), Type=3, no error code, Valid=1 */
    ULONG64 eventInj = (1ULL << 63) | (3ULL << 8) | 6;
    VmcbWriteCtrl(vmcb, VMCB_OFF_EVENT_INJ, eventInj);
}

/* ─── TSC Offset ──────────────────────────────────────────────────── */

static
VOID
AmdSetTscOffset(
    _In_ ULONG CpuNumber,
    _In_ LONG64 Offset
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    VmcbWriteCtrl(perCpu->Amd.VmcbRegion, VMCB_OFF_TSC_OFFSET, (ULONG64)Offset);
}

/* ─── Vtable Initialization ───────────────────────────────────────── */

VOID
AnxAmdInitOps(
    _Out_ PANX_HV_OPS Ops
)
{
    Ops->PlatformName       = "AMD SVM";
    Ops->Init               = AmdInit;
    Ops->EnterGuest         = AmdEnterGuest;
    Ops->Shutdown           = AmdShutdown;
    Ops->HandleExit         = AmdHandleExit;
    Ops->GetExitReason      = AmdGetExitReason;
    Ops->GetExitQualification = AmdGetExitQualification;
    Ops->GetGuestReg        = AmdGetGuestReg;
    Ops->SetGuestReg        = AmdSetGuestReg;
    Ops->GetGuestRip        = AmdGetGuestRip;
    Ops->SetGuestRip        = AmdSetGuestRip;
    Ops->GetGuestCr3        = AmdGetGuestCr3;
    Ops->BuildPageTables    = AmdBuildPageTables;
    Ops->ProtectPage        = AmdProtectPage;
    Ops->UnprotectPage      = AmdUnprotectPage;
    Ops->FlushTlb           = AmdFlushTlb;
    Ops->EnableSingleStep   = AmdEnableSingleStep;
    Ops->DisableSingleStep  = AmdDisableSingleStep;
    Ops->InjectPF           = AmdInjectPF;
    Ops->InjectUD           = AmdInjectUD;
    Ops->SetTscOffset       = AmdSetTscOffset;
}
