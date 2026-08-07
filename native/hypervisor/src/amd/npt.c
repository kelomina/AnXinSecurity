/*
 * AnXinHypervisor - AMD NPT (Nested Page Tables)
 * Module: native/hypervisor/src/amd/npt.c
 *
 * Builds a 1:1 identity-mapped NPT (also called "nested paging" or
 * "Rapid Virtualization Indexing" / RVI) covering all physical memory.
 *
 * NPT uses standard x86-64 page table format (same bit layout as
 * regular PTEs), unlike Intel EPT which has its own format.
 *
 * Memory typing: controlled via PWT/PCD/PAT bits in leaf entries.
 *   RAM:  PWT=0, PCD=0 (WB via host PAT)
 *   MMIO: PWT=0, PCD=1 (UC)
 *
 * The NCR3 (Nested CR3) is written to VMCB control area offset 0x0B8.
 * TLB flush: INVLPGA instruction with ASID.
 *
 * Reference: AMD APM Vol.2 Section 15.25 (Nested Paging)
 */

#include "../../include/platform.h"
#include "../../include/ept.h"
#include "../../include/per_cpu.h"

extern VOID AnxDebugPrint(const char* Fmt, ...);

/* ─── Internal Helpers ────────────────────────────────────────────── */

static
BOOLEAN
AnxNptIsMmioAddress(
    _In_ PANX_PAGE_TABLE_CTX Ctx,
    _In_ ULONG64 PhysAddr
)
{
    ULONG i;
    for (i = 0; i < Ctx->MmioRegionCount; i++) {
        if (Ctx->MmioRegions[i].InUse &&
            PhysAddr >= Ctx->MmioRegions[i].BaseAddress &&
            PhysAddr < Ctx->MmioRegions[i].BaseAddress + Ctx->MmioRegions[i].Size) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * For NPT, memory type is encoded via PCD bit:
 *   PCD=0 → WB (normal RAM)
 *   PCD=1 → UC (MMIO / device memory)
 */
static
BOOLEAN
AnxNptShouldUncacheable(
    _In_ PANX_PAGE_TABLE_CTX Ctx,
    _In_ ULONG64 PhysAddr
)
{
    return AnxNptIsMmioAddress(Ctx, PhysAddr);
}

/* ─── NPT Construction ────────────────────────────────────────────── */

/*
 * Build a 1:1 identity-mapped NPT for all physical memory.
 *
 * Strategy (same as Intel EPT but with x86-64 PTE format):
 *   - PML4 covers 48-bit address space
 *   - PDPT entries point to PDs (no 1GB large pages for simplicity)
 *   - PD entries are 2MB large pages (1:1 mapping)
 *   - MMIO regions marked with PCD=1 (UC)
 *
 * NCR3 = physical address of PML4 table.
 */
NTSTATUS
AnxNptBuildIdentityMap(
    _Inout_ PANX_PAGE_TABLE_CTX Ctx
)
{
    PNPT_PML4E pml4;
    ULONG64 maxPhys;
    ULONG64 pdptCount;
    ULONG64 i, j;
    ULONG64 poolOffset;

    if (!Ctx || !Ctx->RootTablePa) {
        return STATUS_INVALID_PARAMETER;
    }

    pml4 = (PNPT_PML4E)AnxPhysToVirt(Ctx->RootTablePa);
    if (!pml4) {
        return STATUS_UNSUCCESSFUL;
    }

    maxPhys = Ctx->MaxPhysicalAddress;
    if (maxPhys == 0) {
        maxPhys = AnxGetMaxPhysicalAddress();
        Ctx->MaxPhysicalAddress = maxPhys;
    }

    /* Detect MMIO regions (reuse same known regions) */
    if (Ctx->MmioRegionCount == 0) {
        /* IOAPIC */
        Ctx->MmioRegions[0].BaseAddress = 0xFEC00000;
        Ctx->MmioRegions[0].Size = 0x1000;
        Ctx->MmioRegions[0].InUse = TRUE;
        /* Local APIC */
        Ctx->MmioRegions[1].BaseAddress = 0xFEE00000;
        Ctx->MmioRegions[1].Size = 0x100000;
        Ctx->MmioRegions[1].InUse = TRUE;
        /* HPET */
        Ctx->MmioRegions[2].BaseAddress = 0xFED00000;
        Ctx->MmioRegions[2].Size = 0x1000;
        Ctx->MmioRegions[2].InUse = TRUE;
        Ctx->MmioRegionCount = 3;
    }

    pdptCount = (maxPhys + EPT_PAGE_SIZE_1GB * 512 - 1) / (EPT_PAGE_SIZE_1GB * 512);
    if (pdptCount == 0) pdptCount = 1;

    poolOffset = 0;

    for (i = 0; i < pdptCount; i++) {
        PNPT_PDPTE pdpt;
        ULONG64 pdptPa;
        ULONG64 baseForPdpt = i * 512 * EPT_PAGE_SIZE_1GB;

        pdptPa = Ctx->RootTablePa + EPT_PAGE_SIZE_4KB + poolOffset;
        poolOffset += EPT_PAGE_SIZE_4KB;
        pdpt = (PNPT_PDPTE)AnxPhysToVirt(pdptPa);
        if (!pdpt) return STATUS_INSUFFICIENT_RESOURCES;

        /* Link PML4[i] → PDPT */
        pml4[i].Value = 0;
        pml4[i].Present = 1;
        pml4[i].Write = 1;
        pml4[i].User = 1;
        pml4[i].PhysAddr = pdptPa >> 12;

        for (j = 0; j < EPT_ENTRIES_PER_TABLE; j++) {
            ULONG64 gbBase = baseForPdpt + j * EPT_PAGE_SIZE_1GB;
            PNPT_PDE pd;
            ULONG64 pdPa;
            ULONG64 k;

            if (gbBase >= maxPhys + EPT_PAGE_SIZE_1GB) {
                pdpt[j].Value = 0;
                continue;
            }

            pdPa = Ctx->RootTablePa + EPT_PAGE_SIZE_4KB + poolOffset;
            poolOffset += EPT_PAGE_SIZE_4KB;
            pd = (PNPT_PDE)AnxPhysToVirt(pdPa);
            if (!pd) return STATUS_INSUFFICIENT_RESOURCES;

            /* Link PDPT[j] → PD */
            pdpt[j].Value = 0;
            pdpt[j].Present = 1;
            pdpt[j].Write = 1;
            pdpt[j].User = 1;
            pdpt[j].LargePage = 0;
            pdpt[j].PhysAddr = pdPa >> 12;

            /* Fill PD with 2MB large pages */
            for (k = 0; k < EPT_ENTRIES_PER_TABLE; k++) {
                ULONG64 physAddr = gbBase + k * EPT_PAGE_SIZE_2MB;

                if (physAddr >= maxPhys && !AnxNptIsMmioAddress(Ctx, physAddr)) {
                    pd[k].Value = 0;
                    continue;
                }

                pd[k].Value = 0;
                pd[k].Present = 1;
                pd[k].Write = 1;
                pd[k].User = 1;
                pd[k].LargePage = 1;
                pd[k].PhysAddr = physAddr >> 12;

                /* MMIO: set PCD=1 for uncacheable */
                if (AnxNptShouldUncacheable(Ctx, physAddr)) {
                    pd[k].Pcd = 1;
                }

                Ctx->LargePageCount++;
            }
        }
    }

    /* NCR3 = physical address of PML4 */
    Ctx->TablePointer = Ctx->RootTablePa;

    AnxDebugPrint("[HV:INF] NPT built: maxPhys=0x%p largePages=%d ncr3=0x%p\n",
                  maxPhys, Ctx->LargePageCount, Ctx->TablePointer);

    return STATUS_SUCCESS;
}

/* ─── INVLPGA ─────────────────────────────────────────────────────── */

/*
 * Execute INVLPGA instruction to flush nested TLB entries.
 * Address: virtual address to invalidate (0 for all).
 * Asid: ASID of the guest (we use 1 for single-guest).
 */
VOID
AnxNptInvlpga(
    _In_ ULONG64 Address,
    _In_ ULONG Asid
)
{
    /* INVLPGA: RAX = address, ECX = ASID */
    /* Use inline assembly or compiler intrinsic */
    __invlpga((PVOID)Address, Asid);
}

VOID
AnxNptFlushAll(
    _In_ PANX_PAGE_TABLE_CTX Ctx
)
{
    UNREFERENCED_PARAMETER(Ctx);
    /* Flush all nested TLB entries for ASID 1 */
    AnxNptInvlpga(0, 1);
}

/* ─── Page Splitting (2MB → 512×4KB) ─────────────────────────────── */

NTSTATUS
AnxNptSplitPage(
    _Inout_ PANX_PAGE_TABLE_CTX Ctx,
    _In_ ULONG64 Gpa
)
{
    PNPT_PDE pde;
    PNPT_PTE pt;
    ULONG64 ptPa;
    ULONG64 baseAddr;
    BOOLEAN uncacheable;
    ULONG64 i;

    pde = AnxNptGetPde(Ctx, Gpa);
    if (!pde) return STATUS_NOT_FOUND;

    if (!pde->LargePage) {
        return STATUS_SUCCESS;
    }

    if (Ctx->SplitPoolUsed + EPT_PAGE_SIZE_4KB > Ctx->SplitPoolSize) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ptPa = (ULONG64)AnxVirtToPhys((PUCHAR)Ctx->SplitPagePool + Ctx->SplitPoolUsed);
    pt = (PNPT_PTE)((PUCHAR)Ctx->SplitPagePool + Ctx->SplitPoolUsed);
    Ctx->SplitPoolUsed += EPT_PAGE_SIZE_4KB;

    __stosq((PULONG64)pt, 0, EPT_ENTRIES_PER_TABLE);

    baseAddr = (Gpa & ~(EPT_PAGE_SIZE_2MB - 1));
    uncacheable = AnxNptShouldUncacheable(Ctx, baseAddr);

    for (i = 0; i < EPT_ENTRIES_PER_TABLE; i++) {
        pt[i].Value = 0;
        pt[i].Present = 1;
        pt[i].Write = 1;
        pt[i].User = 1;
        pt[i].PhysAddr = (baseAddr + i * EPT_PAGE_SIZE_4KB) >> 12;

        if (uncacheable) {
            pt[i].Pcd = 1;
        }
    }

    /* Convert PD entry from large page to PT pointer */
    pde->Value = 0;
    pde->Present = 1;
    pde->Write = 1;
    pde->User = 1;
    pde->LargePage = 0;
    pde->PhysAddr = ptPa >> 12;

    Ctx->LargePageCount--;
    Ctx->SmallPageCount += EPT_ENTRIES_PER_TABLE;

    AnxNptInvlpga(0, 1);

    return STATUS_SUCCESS;
}

/* ─── Permission Modification ─────────────────────────────────────── */

/*
 * Set NPT permissions for a single 4KB page.
 * For NPT, "removing write" means clearing the Write bit.
 * "Removing execute" means setting the NX bit.
 */
NTSTATUS
AnxNptSetPermission(
    _Inout_ PANX_PAGE_TABLE_CTX Ctx,
    _In_ ULONG64 Gpa,
    _In_ ULONG64 PermMask
)
{
    PNPT_PTE pte;
    NTSTATUS status;

    status = AnxNptSplitPage(Ctx, Gpa);
    if (!NT_SUCCESS(status)) return status;

    pte = AnxNptGetPte(Ctx, Gpa);
    if (!pte) return STATUS_NOT_FOUND;

    /* PermMask uses EPT_PERM_* constants for unified interface */
    pte->Write = (PermMask & EPT_PERM_WRITE) ? 1 : 0;
    pte->Nx = (PermMask & EPT_PERM_EXECUTE) ? 0 : 1;
    /* Present and Read are always 1 for mapped pages */

    AnxNptInvlpga(0, 1);

    return STATUS_SUCCESS;
}

/* ─── Page Table Walk ─────────────────────────────────────────────── */

PNPT_PDE
AnxNptGetPde(
    _In_ PANX_PAGE_TABLE_CTX Ctx,
    _In_ ULONG64 Gpa
)
{
    PNPT_PML4E pml4;
    PNPT_PDPTE pdpt;
    PNPT_PDE pd;
    ULONG64 pml4Idx, pdptIdx, pdIdx;

    pml4Idx = (Gpa >> 39) & 0x1FF;
    pdptIdx = (Gpa >> 30) & 0x1FF;
    pdIdx = (Gpa >> 21) & 0x1FF;

    pml4 = (PNPT_PML4E)AnxPhysToVirt(Ctx->RootTablePa);
    if (!pml4 || !pml4[pml4Idx].Present) return NULL;

    pdpt = (PNPT_PDPTE)AnxPhysToVirt((ULONG64)pml4[pml4Idx].PhysAddr << 12);
    if (!pdpt || !pdpt[pdptIdx].Present) return NULL;

    if (pdpt[pdptIdx].LargePage) return NULL;

    pd = (PNPT_PDE)AnxPhysToVirt((ULONG64)pdpt[pdptIdx].PhysAddr << 12);
    if (!pd) return NULL;

    return &pd[pdIdx];
}

PNPT_PTE
AnxNptGetPte(
    _In_ PANX_PAGE_TABLE_CTX Ctx,
    _In_ ULONG64 Gpa
)
{
    PNPT_PDE pde;
    PNPT_PTE pt;
    ULONG64 ptIdx;

    ptIdx = (Gpa >> 12) & 0x1FF;

    pde = AnxNptGetPde(Ctx, Gpa);
    if (!pde) return NULL;

    if (pde->LargePage) return NULL;

    pt = (PNPT_PTE)AnxPhysToVirt((ULONG64)pde->PhysAddr << 12);
    if (!pt) return NULL;

    return &pt[ptIdx];
}
