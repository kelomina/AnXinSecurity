/*
 * AnXinHypervisor - Platform-Independent Page Table Interface
 * Module: native/hypervisor/src/page_table.c
 *
 * Provides unified page table operations that dispatch to the
 * appropriate platform backend (Intel EPT or AMD NPT) via HAL.
 *
 * Also implements the EPT violation / #NPF handler logic:
 *   - Determine violation type (read/write/execute)
 *   - Look up protection region table
 *   - Record violation event
 *   - Decide: inject #PF to guest, single-step bypass, or report
 */

#include "../include/platform.h"
#include "../include/ept.h"
#include "../include/hal.h"
#include "../include/per_cpu.h"
#include "../include/protect.h"
#include "../include/anx_hv.h"

extern VOID AnxDebugPrint(const char* Fmt, ...);
extern ANX_CPU_VENDOR g_CpuVendor;

/* From vmcs.c (Intel only) */
extern ULONG64 VmcsRead(ULONG32 FieldEncoding);

/* ─── Page Table Initialization ───────────────────────────────────── */

/*
 * Called per-CPU after VMXON/VMRUN setup.
 * Builds the identity-mapped page tables and activates them.
 * For Phase 2, all CPUs share the same page table (single guest).
 */
NTSTATUS
AnxPageTableInit(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    PANX_PAGE_TABLE_CTX ctx;
    NTSTATUS status;

    if (!perCpu) return STATUS_INVALID_PARAMETER;

    ctx = (PANX_PAGE_TABLE_CTX)perCpu->PageTableCtx;
    if (!ctx) {
        /* First CPU builds the tables; others share */
        if (CpuNumber == 0) {
            return STATUS_UNSUCCESSFUL;
        }
        /* Share CPU 0's page table context */
        ctx = (PANX_PAGE_TABLE_CTX)g_PerCpuArray[0]->PageTableCtx;
        perCpu->PageTableCtx = ctx;
        perCpu->PageTablePointer = ctx->TablePointer;
        return STATUS_SUCCESS;
    }

    /* Build identity map via platform-specific backend */
    if (g_CpuVendor == ANX_CPU_INTEL) {
        status = AnxEptBuildIdentityMap(ctx);
    } else {
        status = AnxNptBuildIdentityMap(ctx);
    }

    if (NT_SUCCESS(status)) {
        perCpu->PageTablePointer = ctx->TablePointer;
    }

    return status;
}

/* ─── Protection Interface ────────────────────────────────────────── */

/*
 * Remove write permission from a page (make it read-only).
 * Used by the protection engine (Phase 4) to guard critical memory.
 */
NTSTATUS
AnxPageTableProtect(
    _In_ ULONG64 Gpa,
    _In_ ULONG Flags
)
{
    PANX_PAGE_TABLE_CTX ctx;
    ULONG64 perm;

    if (g_CpuCount == 0 || !g_PerCpuArray[0]) {
        return STATUS_UNSUCCESSFUL;
    }

    ctx = (PANX_PAGE_TABLE_CTX)g_PerCpuArray[0]->PageTableCtx;
    if (!ctx) return STATUS_UNSUCCESSFUL;

    /* Build permission mask based on flags */
    perm = EPT_PERM_READ | EPT_PERM_EXECUTE;
    if (Flags & ANX_PROT_WRITE) {
        perm |= EPT_PERM_WRITE;
    }

    if (g_CpuVendor == ANX_CPU_INTEL) {
        return AnxEptSetPermission(ctx, Gpa, perm);
    } else {
        return AnxNptSetPermission(ctx, Gpa, perm);
    }
}

/*
 * Restore full RWX permission to a page.
 */
NTSTATUS
AnxPageTableUnprotect(
    _In_ ULONG64 Gpa
)
{
    PANX_PAGE_TABLE_CTX ctx;
    ULONG64 perm = EPT_PERM_READ | EPT_PERM_WRITE | EPT_PERM_EXECUTE;

    if (g_CpuCount == 0 || !g_PerCpuArray[0]) {
        return STATUS_UNSUCCESSFUL;
    }

    ctx = (PANX_PAGE_TABLE_CTX)g_PerCpuArray[0]->PageTableCtx;
    if (!ctx) return STATUS_UNSUCCESSFUL;

    if (g_CpuVendor == ANX_CPU_INTEL) {
        return AnxEptSetPermission(ctx, Gpa, perm);
    } else {
        return AnxNptSetPermission(ctx, Gpa, perm);
    }
}

/*
 * Flush TLB for the current CPU's page tables.
 */
VOID
AnxPageTableFlush(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu;
    PANX_PAGE_TABLE_CTX ctx;

    if (CpuNumber >= g_CpuCount) return;
    perCpu = g_PerCpuArray[CpuNumber];
    if (!perCpu) return;

    ctx = (PANX_PAGE_TABLE_CTX)perCpu->PageTableCtx;

    if (g_CpuVendor == ANX_CPU_INTEL) {
        AnxEptFlushAll(ctx);
    } else {
        AnxNptFlushAll(ctx);
    }
}

/*
 * Check if a GPA falls within a known MMIO region.
 */
BOOLEAN
AnxPageTableIsMmio(
    _In_ ULONG64 Gpa
)
{
    PANX_PAGE_TABLE_CTX ctx;
    ULONG i;

    if (g_CpuCount == 0 || !g_PerCpuArray[0]) return FALSE;

    ctx = (PANX_PAGE_TABLE_CTX)g_PerCpuArray[0]->PageTableCtx;
    if (!ctx) return FALSE;

    for (i = 0; i < ctx->MmioRegionCount; i++) {
        if (ctx->MmioRegions[i].InUse &&
            Gpa >= ctx->MmioRegions[i].BaseAddress &&
            Gpa < ctx->MmioRegions[i].BaseAddress + ctx->MmioRegions[i].Size) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ─── EPT Violation / #NPF Handler ────────────────────────────────── */

/*
 * Intel EPT Violation Exit Qualification (VMCS 0x6400):
 *   Bit 0: Data read caused the violation
 *   Bit 1: Data write caused the violation
 *   Bit 2: Instruction fetch caused the violation
 *   Bit 3: EPT PTE Read bit was 1
 *   Bit 4: EPT PTE Write bit was 1
 *   Bit 5: EPT PTE Execute bit was 1
 *   Bit 6: EPT PTE Execute (user) bit was 1
 *   Bit 7: Valid guest linear address (bit 8 valid)
 *   Bit 8: Guest linear address field valid
 *   Bit 9: NMI unblocking due to IRET
 *   Bit 10: Shadow-stack access
 *   Bit 11: NMI unblocking due to IRET (supervisor shadow-stack)
 *
 * AMD #NPF EXITINFO1 (VMCB +0x088):
 *   Bit 0: Present bit in nested page table
 *   Bit 1: Write access (0=read, 1=write)
 *   Bit 2: User/Supervisor (0=user, 1=supervisor)
 *   Bit 4: Instruction fetch (NX violation)
 *   Bit 32: Final (1 = fault in guest page table walk)
 *   Bit 33: PT (1 = fault during guest PT walk, GPA is PT address)
 */

/*
 * Handle an EPT violation (Intel) or #NPF (AMD).
 * Called from exit_handler.c when exitReason == ANX_EXIT_PAGE_FAULT.
 *
 * Phase 2 behavior: log and advance (no protection engine yet).
 * Phase 4 will add protection region lookup and single-step bypass.
 */
VOID
AnxHandlePageFaultExit(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu;
    ULONG64 qualification;
    ULONG64 gpa;
    BOOLEAN isWrite;
    BOOLEAN isExecute;
    BOOLEAN isRead;

    if (CpuNumber >= g_CpuCount) return;
    perCpu = g_PerCpuArray[CpuNumber];
    if (!perCpu) return;

    /* Get exit qualification / EXITINFO1 */
    qualification = g_HvOps.GetExitQualification(CpuNumber);

    /* Get faulting guest physical address */
    if (g_CpuVendor == ANX_CPU_INTEL) {
        /* Guest Physical Address: VMCS natural-width read-only 0x2400 */
        gpa = g_HvOps.GetExitQualification(CpuNumber);
        /* Actually, GPA is in a separate VMCS field (0x2400).
         * For Intel, GetExitQualification returns 0x6400 (exit qual).
         * We need a separate read for GPA. Use HAL or direct VMCS read. */
        gpa = VmcsRead(0x2400);
    } else {
        /* AMD: EXITINFO2 (VMCB +0x090) contains the faulting GPA */
        PUCHAR vmcb = (PUCHAR)perCpu->Amd.VmcbRegion;
        gpa = *(PULONG64)(vmcb + 0x090);
    }

    /* Decode violation type */
    if (g_CpuVendor == ANX_CPU_INTEL) {
        isRead = (qualification & 1) != 0;
        isWrite = (qualification & 2) != 0;
        isExecute = (qualification & 4) != 0;
    } else {
        isRead = (qualification & 1) == 0 && (qualification & 2) == 0;
        isWrite = (qualification & 2) != 0;
        isExecute = (qualification & 0x10) != 0;
    }

    /* Check if this is a known MMIO access (expected, not a violation) */
    if (AnxPageTableIsMmio(gpa)) {
        /* MMIO access through unmapped/UC region: expected behavior.
         * If the page is simply not present, map it as UC and resume. */
        AnxDebugPrint("[HV:DBG] CPU %d: MMIO access GPA=0x%p %s%s%s\n",
                      (ULONG64)CpuNumber, gpa,
                      isRead ? "R" : "", isWrite ? "W" : "", isExecute ? "X" : "");
        return;
    }

    /*
     * Phase 2: No protection engine yet.
     * Any EPT violation on non-MMIO memory is unexpected.
     * Log it and attempt to continue by making the page RWX.
     */
    AnxDebugPrint("[HV:WRN] CPU %d: EPT/NPF violation GPA=0x%p %s%s%s qual=0x%p\n",
                  (ULONG64)CpuNumber, gpa,
                  isRead ? "R" : "", isWrite ? "W" : "", isExecute ? "X" : "",
                  qualification);

    /* Attempt to unprotect the page (make RWX) to prevent infinite loop */
    AnxPageTableUnprotect(gpa & ~(EPT_PAGE_SIZE_4KB - 1));
}
