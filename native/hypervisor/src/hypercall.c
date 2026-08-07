/*
 * AnXinHypervisor - Hypercall Dispatcher
 * Module: native/hypervisor/src/hypercall.c
 *
 * Handles VMCALL (Intel) / VMMCALL (AMD) exits.
 * Validates magic number, dispatches to function handlers.
 *
 * Calling convention (guest Ring 0):
 *   RAX = ANX_VMCALL_MAGIC (0x414E5848563031)
 *   RBX = function code
 *   RCX = param1
 *   RDX = param2
 *   R8  = param3
 *   Return: RAX = status, RBX = output size
 *
 * All handlers run in VMX root / SVM host context.
 */

#include "../include/platform.h"
#include "../include/hal.h"
#include "../include/per_cpu.h"
#include "../include/anx_hv.h"
#include "../include/protect.h"

extern VOID AnxDebugPrint(const char* Fmt, ...);

/* From protect.c */
extern ULONG AnxProtectRegisterRegion(ULONG64 Gpa, ULONG64 Size, ULONG Flags,
                                      ULONG OwnerPid, PULONG64 Token);
extern NTSTATUS AnxProtectUnregisterRegion(ULONG Slot, ULONG64 Token);
extern VOID AnxProtectGetStats(PANX_HV_STATS Stats);
extern PANX_VIOLATION_RING AnxProtectGetViolationRing(VOID);

/* ─── Hypercall Handlers ──────────────────────────────────────────── */

static
ULONG64
AnxHcGetVersion(
    _In_ ULONG CpuNumber,
    _Out_ PULONG64 OutputSize
)
{
    UNREFERENCED_PARAMETER(CpuNumber);
    *OutputSize = 0;

    /* Return version packed in RBX: major.minor.patch */
    return (ULONG64)(ANX_HV_VERSION_MAJOR << 16) |
           (ULONG64)(ANX_HV_VERSION_MINOR << 8) |
           (ULONG64)ANX_HV_VERSION_PATCH;
}

static
ULONG64
AnxHcPing(
    _In_ ULONG CpuNumber,
    _In_ ULONG64 Param1,
    _Out_ PULONG64 OutputSize
)
{
    UNREFERENCED_PARAMETER(CpuNumber);
    *OutputSize = 0;

    /* Echo back param1 as proof of life */
    return Param1;
}

static
ULONG64
AnxHcProtectRegion(
    _In_ ULONG CpuNumber,
    _In_ ULONG64 Param1,
    _In_ ULONG64 Param2,
    _In_ ULONG64 Param3,
    _Out_ PULONG64 OutputSize
)
{
    /*
     * Param1 = GPA of ANX_HV_PROTECT_PARAMS structure (guest physical)
     * Param2 = sizeof(ANX_HV_PROTECT_PARAMS)
     * Param3 = unused
     *
     * For Phase 4, we read the params structure from guest memory.
     * Since we have 1:1 EPT mapping, GPA == HPA for now.
     */
    PANX_HV_PROTECT_PARAMS params;
    ULONG64 token;
    ULONG slot;

    UNREFERENCED_PARAMETER(CpuNumber);
    UNREFERENCED_PARAMETER(Param3);
    *OutputSize = 0;

    if (!Param1 || Param2 < sizeof(ANX_HV_PROTECT_PARAMS)) {
        return ANX_HV_ERR_INVALID_PARAM;
    }

    /* With 1:1 EPT, GPA is directly accessible */
    params = (PANX_HV_PROTECT_PARAMS)AnxPhysToVirt(Param1);
    if (!params) {
        return ANX_HV_ERR_INVALID_PARAM;
    }

    slot = AnxProtectRegisterRegion(
        params->GuestPhysAddr,
        params->Size,
        params->ProtectFlags,
        params->OwnerPid,
        &token);

    if (slot == MAXULONG) {
        return ANX_HV_ERR_POOL_FULL;
    }

    /* Write token back to guest buffer */
    params->RegistrationToken = token;

    /* Return slot index in output */
    *OutputSize = sizeof(ULONG64);
    return ANX_HV_SUCCESS | (ULONG64)slot;
}

static
ULONG64
AnxHcUnprotectRegion(
    _In_ ULONG CpuNumber,
    _In_ ULONG64 Param1,
    _In_ ULONG64 Param2,
    _Out_ PULONG64 OutputSize
)
{
    /*
     * Param1 = slot index
     * Param2 = registration token
     */
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CpuNumber);
    *OutputSize = 0;

    status = AnxProtectUnregisterRegion((ULONG)Param1, Param2);

    if (status == STATUS_NOT_FOUND) return ANX_HV_ERR_REGION_NOT_FOUND;
    if (status == STATUS_ACCESS_DENIED) return ANX_HV_ERR_NOT_AUTHORIZED;
    if (!NT_SUCCESS(status)) return ANX_HV_ERR_INVALID_PARAM;

    return ANX_HV_SUCCESS;
}

static
ULONG64
AnxHcGetStats(
    _In_ ULONG CpuNumber,
    _In_ ULONG64 Param1,
    _In_ ULONG64 Param2,
    _Out_ PULONG64 OutputSize
)
{
    /*
     * Param1 = GPA of output buffer (ANX_HV_STATS)
     * Param2 = sizeof(ANX_HV_STATS)
     */
    PANX_HV_STATS stats;

    UNREFERENCED_PARAMETER(CpuNumber);
    *OutputSize = 0;

    if (!Param1 || Param2 < sizeof(ANX_HV_STATS)) {
        return ANX_HV_ERR_INVALID_PARAM;
    }

    stats = (PANX_HV_STATS)AnxPhysToVirt(Param1);
    if (!stats) return ANX_HV_ERR_INVALID_PARAM;

    AnxProtectGetStats(stats);
    *OutputSize = sizeof(ANX_HV_STATS);

    return ANX_HV_SUCCESS;
}

static
ULONG64
AnxHcQueryViolation(
    _In_ ULONG CpuNumber,
    _In_ ULONG64 Param1,
    _In_ ULONG64 Param2,
    _Out_ PULONG64 OutputSize
)
{
    /*
     * Param1 = GPA of output buffer for violation events
     * Param2 = max events to copy
     *
     * Copies pending events from ring buffer to guest output buffer.
     */
    PANX_VIOLATION_RING ring;
    PANX_HV_VIOLATION_EVENT outBuf;
    ULONG tail, head;
    ULONG count = 0;
    ULONG maxEvents;

    UNREFERENCED_PARAMETER(CpuNumber);
    *OutputSize = 0;

    if (!Param1 || Param2 == 0) {
        return ANX_HV_ERR_INVALID_PARAM;
    }

    outBuf = (PANX_HV_VIOLATION_EVENT)AnxPhysToVirt(Param1);
    if (!outBuf) return ANX_HV_ERR_INVALID_PARAM;

    maxEvents = (ULONG)Param2;
    ring = AnxProtectGetViolationRing();

    tail = ring->Tail;
    head = ring->Head;

    while (tail != head && count < maxEvents) {
        outBuf[count] = ring->Events[tail];
        tail = (tail + 1) % ANX_VIOLATION_RING_SIZE;
        count++;
    }

    ring->Tail = tail;
    *OutputSize = count * sizeof(ANX_HV_VIOLATION_EVENT);

    return ANX_HV_SUCCESS;
}

/* ─── Main Dispatcher ─────────────────────────────────────────────── */

VOID
AnxHandleHypercall(
    _In_ ULONG CpuNumber
)
{
    ULONG64 magic, func, param1, param2, param3;
    ULONG64 result = ANX_HV_SUCCESS;
    ULONG64 outputSize = 0;
    ULONG64 rip;

    /* Read hypercall parameters from guest registers */
    magic = g_HvOps.GetGuestReg(CpuNumber, ANX_REG_RAX);
    func = g_HvOps.GetGuestReg(CpuNumber, ANX_REG_RBX);
    param1 = g_HvOps.GetGuestReg(CpuNumber, ANX_REG_RCX);
    param2 = g_HvOps.GetGuestReg(CpuNumber, ANX_REG_RDX);
    param3 = g_HvOps.GetGuestReg(CpuNumber, ANX_REG_R8);

    /* Validate magic */
    if (magic != ANX_VMCALL_MAGIC) {
        /* Not our hypercall: could be Hyper-V or other HV.
         * Inject #UD to guest (invalid opcode). */
        AnxDebugPrint("[HV:WRN] CPU %d: VMCALL with bad magic 0x%p\n",
                      (ULONG64)CpuNumber, magic);
        g_HvOps.InjectUD(CpuNumber);
        return;
    }

    /* Dispatch by function code */
    switch (func) {
    case ANX_VMCALL_PING:
        result = AnxHcPing(CpuNumber, param1, &outputSize);
        break;

    case ANX_VMCALL_GET_VERSION:
        result = AnxHcGetVersion(CpuNumber, &outputSize);
        break;

    case ANX_VMCALL_PROTECT_REGION:
        result = AnxHcProtectRegion(CpuNumber, param1, param2, param3, &outputSize);
        break;

    case ANX_VMCALL_UNPROTECT_REGION:
        result = AnxHcUnprotectRegion(CpuNumber, param1, param2, &outputSize);
        break;

    case ANX_VMCALL_GET_STATS:
        result = AnxHcGetStats(CpuNumber, param1, param2, &outputSize);
        break;

    case ANX_VMCALL_QUERY_VIOLATION:
        result = AnxHcQueryViolation(CpuNumber, param1, param2, &outputSize);
        break;

    default:
        AnxDebugPrint("[HV:WRN] CPU %d: unknown hypercall func 0x%x\n",
                      (ULONG64)CpuNumber, func);
        result = ANX_HV_ERR_INVALID_FUNC;
        break;
    }

    /* Write return values to guest registers */
    g_HvOps.SetGuestReg(CpuNumber, ANX_REG_RAX, result);
    g_HvOps.SetGuestReg(CpuNumber, ANX_REG_RBX, outputSize);

    /* Advance guest RIP past VMCALL/VMMCALL (3 bytes: 0F 01 C1 or 0F 01 D9) */
    rip = g_HvOps.GetGuestRip(CpuNumber);
    g_HvOps.SetGuestRip(CpuNumber, rip + 3);
}
