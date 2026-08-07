/*
 * AnXinHypervisor - CR Access Exit Handler
 * Module: native/hypervisor/src/exit_cr.c
 *
 * Handles MOV to/from CRx, CLTS, LMSW exits.
 *
 * Key protections:
 *   - CR4.VMXE (Intel): prevent guest from clearing VMXE (would disable VMX)
 *   - CR3 tracking: detect process switches (update per-process protection)
 *   - CR0.PG/PE: prevent disabling paging/protection mode
 *
 * Intel Exit Qualification (VMCS 0x6400):
 *   [3:0]   = CR number
 *   [5:4]   = access type (0=MOV to CR, 1=MOV from CR, 2=CLTS, 3=LMSW)
 *   [8]     = LMSW operand type
 *   [11:8]  = GPR register index
 *   [31:16] = LMSW source data
 *
 * AMD SVM exit codes:
 *   0x00 = CR0 selective write, 0x01 = CR0 write
 *   0x02 = CR1 write, 0x03 = CR3 write, 0x04 = CR3 read
 *   0x05 = CR4 write, 0x06 = CR4 read
 */

#include "../include/platform.h"
#include "../include/hal.h"
#include "../include/per_cpu.h"
#include "../include/exit_reasons.h"

extern VOID AnxDebugPrint(const char* Fmt, ...);
extern ANX_CPU_VENDOR g_CpuVendor;

/* From vmcs.c (Intel) */
extern ULONG64 VmcsRead(ULONG32 FieldEncoding);
extern VOID VmcsWrite(ULONG32 FieldEncoding, ULONG64 Value);

#define VMCS_RO_EXIT_QUALIFICATION  0x6400
#define VMCS_GUEST_CR0              0x6800
#define VMCS_GUEST_CR3              0x6802
#define VMCS_GUEST_CR4              0x6804
#define VMCS_CTRL_CR0_READ_SHADOW   0x6004
#define VMCS_CTRL_CR4_READ_SHADOW   0x6006

/* ─── Intel CR Access Handler ─────────────────────────────────────── */

static
VOID
AnxHandleCrAccessIntel(
    _In_ ULONG CpuNumber
)
{
    ULONG64 qual = VmcsRead(VMCS_RO_EXIT_QUALIFICATION);
    ULONG crNumber = (ULONG)(qual & 0xF);
    ULONG accessType = (ULONG)((qual >> 4) & 0x3);
    ULONG gprIndex = (ULONG)((qual >> 8) & 0xF);
    ULONG64 rip;

    switch (accessType) {
    case 0: /* MOV to CR */
    {
        ULONG64 value = g_HvOps.GetGuestReg(CpuNumber, gprIndex);

        switch (crNumber) {
        case 0: /* CR0 */
            /* Ensure PE and PG stay set (cannot disable protected mode / paging) */
            value |= (ANX_CR0_PE | ANX_CR0_PG | ANX_CR0_NE);
            VmcsWrite(VMCS_GUEST_CR0, value);
            VmcsWrite(VMCS_CTRL_CR0_READ_SHADOW, value);
            break;

        case 3: /* CR3 (process switch) */
            VmcsWrite(VMCS_GUEST_CR3, value);
            /* Track process switch for per-process protection (Phase 4+) */
            g_PerCpuArray[CpuNumber]->GuestCr3 = value;
            break;

        case 4: /* CR4 */
            /* PROTECT VMXE: never allow guest to clear it */
            value |= ANX_CR4_VMXE;
            VmcsWrite(VMCS_GUEST_CR4, value);
            VmcsWrite(VMCS_CTRL_CR4_READ_SHADOW, value);
            break;

        default:
            AnxDebugPrint("[HV:WRN] CPU %d: MOV to CR%d (unhandled)\n",
                          (ULONG64)CpuNumber, (ULONG64)crNumber);
            break;
        }
        break;
    }

    case 1: /* MOV from CR */
    {
        ULONG64 value = 0;

        switch (crNumber) {
        case 0:
            value = VmcsRead(VMCS_CTRL_CR0_READ_SHADOW);
            break;
        case 3:
            value = VmcsRead(VMCS_GUEST_CR3);
            break;
        case 4:
            value = VmcsRead(VMCS_CTRL_CR4_READ_SHADOW);
            break;
        default:
            break;
        }

        g_HvOps.SetGuestReg(CpuNumber, gprIndex, value);
        break;
    }

    case 2: /* CLTS */
    {
        ULONG64 cr0 = VmcsRead(VMCS_GUEST_CR0);
        cr0 &= ~ANX_CR0_TS;
        VmcsWrite(VMCS_GUEST_CR0, cr0);
        break;
    }

    case 3: /* LMSW */
    {
        ULONG64 msw = (qual >> 16) & 0xFFFF;
        ULONG64 cr0 = VmcsRead(VMCS_GUEST_CR0);
        /* LMSW can only set PE, MP, EM, TS (low 4 bits); cannot clear PE */
        cr0 = (cr0 & ~0xEULL) | (msw & 0xEULL);
        cr0 |= ANX_CR0_PE;  /* PE cannot be cleared by LMSW */
        VmcsWrite(VMCS_GUEST_CR0, cr0);
        break;
    }
    }

    /* Advance RIP past the instruction */
    rip = g_HvOps.GetGuestRip(CpuNumber);
    {
        /* MOV to/from CR is 3 bytes (REX + 0F 20/22 modrm) typically.
         * Use VM-exit instruction length for accuracy. */
        ULONG64 instrLen = VmcsRead(0x440C);  /* VM-exit instruction length */
        if (instrLen > 0 && instrLen <= 15) {
            g_HvOps.SetGuestRip(CpuNumber, rip + instrLen);
        } else {
            g_HvOps.SetGuestRip(CpuNumber, rip + 3);
        }
    }
}

/* ─── AMD CR Access Handler ───────────────────────────────────────── */

static
VOID
AnxHandleCrAccessAmd(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    PUCHAR vmcb = (PUCHAR)perCpu->Amd.VmcbRegion;
    ULONG64 exitCode = *(PULONG64)(vmcb + 0x070);  /* EXITCODE */
    ULONG64 rip;

    /*
     * AMD SVM CR exit codes:
     *   0x00 = CR0 selective write
     *   0x01 = CR0 write (all bits)
     *   0x03 = CR3 write
     *   0x04 = CR3 read
     *   0x05 = CR4 write
     *   0x06 = CR4 read
     */
    switch (exitCode) {
    case 0x00:
    case 0x01:
    {
        /* CR0 write: value in VMCB StateSave.CR0 (offset 0x558 from VMCB base) */
        ULONG64 cr0 = *(PULONG64)(vmcb + 0x558);
        cr0 |= (ANX_CR0_PE | ANX_CR0_PG | ANX_CR0_NE);
        *(PULONG64)(vmcb + 0x558) = cr0;
        break;
    }

    case 0x03:
    {
        /* CR3 write: process switch */
        ULONG64 cr3 = *(PULONG64)(vmcb + 0x550);
        perCpu->GuestCr3 = cr3;
        break;
    }

    case 0x05:
    {
        /* CR4 write: protect VMXE equivalent (not applicable on AMD,
         * but protect against unexpected modifications) */
        break;
    }

    default:
        AnxDebugPrint("[HV:WRN] CPU %d: AMD CR exit code 0x%x\n",
                      (ULONG64)CpuNumber, exitCode);
        break;
    }

    /* AMD: use NRip for RIP advancement */
    rip = *(PULONG64)(vmcb + 0x0B8);  /* NRip */
    if (rip != 0) {
        *(PULONG64)(vmcb + 0x578) = rip;  /* StateSave.Rip */
    }
}

/* ─── Unified Entry Point ─────────────────────────────────────────── */

VOID
AnxHandleCrAccessExit(
    _In_ ULONG CpuNumber
)
{
    if (g_CpuVendor == ANX_CPU_INTEL) {
        AnxHandleCrAccessIntel(CpuNumber);
    } else {
        AnxHandleCrAccessAmd(CpuNumber);
    }
}
