/*
 * AnXinHypervisor - Intel EPT (Extended Page Tables)
 * Module: native/hypervisor/src/intel/ept.c
 *
 * Builds a 1:1 identity-mapped EPT covering all physical memory.
 * Initial mapping uses 2MB large pages for efficiency.
 * Individual pages can be split to 4KB for fine-grained protection (Phase 4).
 *
 * Memory layout (pre-allocated in DriverEntry, zero-filled):
 *   PML4: 1 page (4KB)
 *   PDPT: N pages (1 per 512GB of physical address space)
 *   PD:   N*512 pages (1 per 1GB region)
 *   PT:   allocated on-demand when splitting a 2MB page to 4KB
 *
 * Reference: Intel SDM Vol.3C Chapter 29 (EPT Translation)
 */

#include "../../include/platform.h"
#include "../../include/ept.h"
#include "../../include/per_cpu.h"

extern VOID AnxDebugPrint(const char* Fmt, ...);

/* ─── Internal Helpers ────────────────────────────────────────────── */

/*
 * Detect MMIO regions by scanning physical address space.
 * In a real implementation, this would parse ACPI/PCI BARs.
 * For Phase 2, we use a heuristic: regions above installed RAM
 * that are not backed by physical memory are MMIO.
 *
 * Key known MMIO regions on x86-64:
 *   0xFEC00000 - 0xFEC00FFF: IOAPIC
 *   0xFEE00000 - 0xFEEFFFFF: Local APIC
 *   0xFED00000 - 0xFED003FF: HPET
 *   0x80000000 - 0x8FFFFFFF: PCI MMCONFIG (typical)
 */
static
VOID
AnxEptDetectMmioRegions(
    _Inout_ PANX_PAGE_TABLE_CTX Ctx
)
{
    ULONG64 maxPhys = Ctx->MaxPhysicalAddress;

    /* IOAPIC */
    if (Ctx->MmioRegionCount < ANX_MAX_MMIO_REGIONS) {
        Ctx->MmioRegions[Ctx->MmioRegionCount].BaseAddress = 0xFEC00000;
        Ctx->MmioRegions[Ctx->MmioRegionCount].Size = 0x1000;
        Ctx->MmioRegions[Ctx->MmioRegionCount].InUse = TRUE;
        Ctx->MmioRegionCount++;
    }

    /* Local APIC */
    if (Ctx->MmioRegionCount < ANX_MAX_MMIO_REGIONS) {
        Ctx->MmioRegions[Ctx->MmioRegionCount].BaseAddress = 0xFEE00000;
        Ctx->MmioRegions[Ctx->MmioRegionCount].Size = 0x100000;
        Ctx->MmioRegions[Ctx->MmioRegionCount].InUse = TRUE;
        Ctx->MmioRegionCount++;
    }

    /* HPET */
    if (Ctx->MmioRegionCount < ANX_MAX_MMIO_REGIONS) {
        Ctx->MmioRegions[Ctx->MmioRegionCount].BaseAddress = 0xFED00000;
        Ctx->MmioRegions[Ctx->MmioRegionCount].Size = 0x1000;
        Ctx->MmioRegions[Ctx->MmioRegionCount].InUse = TRUE;
        Ctx->MmioRegionCount++;
    }

    /* PCI MMCONFIG (typical base, 256MB window) */
    if (maxPhys >= 0x80000000 && Ctx->MmioRegionCount < ANX_MAX_MMIO_REGIONS) {
        Ctx->MmioRegions[Ctx->MmioRegionCount].BaseAddress = 0x80000000;
        Ctx->MmioRegions[Ctx->MmioRegionCount].Size = 0x10000000;
        Ctx->MmioRegions[Ctx->MmioRegionCount].InUse = TRUE;
        Ctx->MmioRegionCount++;
    }
}

static
BOOLEAN
AnxEptIsMmioAddress(
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
 * Determine EPT memory type for a given physical address.
 * RAM → WB (Write-Back), MMIO → UC (Uncacheable).
 */
static
ULONG
AnxEptGetMemoryType(
    _In_ PANX_PAGE_TABLE_CTX Ctx,
    _In_ ULONG64 PhysAddr
)
{
    if (AnxEptIsMmioAddress(Ctx, PhysAddr)) {
        return EPT_MEMORY_TYPE_UC;
    }
    return EPT_MEMORY_TYPE_WB;
}

/* ─── EPT Construction ────────────────────────────────────────────── */

/*
 * Build a 1:1 identity-mapped EPT for all physical memory.
 *
 * Strategy:
 *   - PML4 covers the full 48-bit physical address space (512 entries × 512GB)
 *   - For each 1GB region within MaxPhysicalAddress:
 *     - Allocate a PD (512 × 2MB entries)
 *     - Map each 2MB page as a large page (1:1, RWX)
 *   - MMIO regions get UC memory type; RAM gets WB
 *
 * All memory must be pre-allocated before calling this function.
 * Ctx->RootTablePa must point to a zero-filled 4KB page for PML4.
 * Ctx->SplitPagePool must point to pre-allocated pool for PD tables.
 */
NTSTATUS
AnxEptBuildIdentityMap(
    _Inout_ PANX_PAGE_TABLE_CTX Ctx
)
{
    PEPT_PML4E pml4;
    ULONG64 maxPhys;
    ULONG64 pdptCount;
    ULONG64 i, j;
    ULONG64 poolOffset;

    if (!Ctx || !Ctx->RootTablePa) {
        return STATUS_INVALID_PARAMETER;
    }

    pml4 = (PEPT_PML4E)AnxPhysToVirt(Ctx->RootTablePa);
    if (!pml4) {
        return STATUS_UNSUCCESSFUL;
    }

    maxPhys = Ctx->MaxPhysicalAddress;
    if (maxPhys == 0) {
        /* Query physical memory size */
        maxPhys = AnxGetMaxPhysicalAddress();
        Ctx->MaxPhysicalAddress = maxPhys;
    }

    /* Detect MMIO regions before building tables */
    AnxEptDetectMmioRegions(Ctx);

    /*
     * Calculate how many PDPT pages we need.
     * Each PML4 entry covers 512GB. Each PDPT entry covers 1GB.
     * We need ceil(maxPhys / 512GB) PDPT tables.
     */
    pdptCount = (maxPhys + EPT_PAGE_SIZE_1GB * 512 - 1) / (EPT_PAGE_SIZE_1GB * 512);
    if (pdptCount == 0) pdptCount = 1;

    poolOffset = 0;

    for (i = 0; i < pdptCount; i++) {
        PEPT_PDPTE pdpt;
        ULONG64 pdptPa;
        ULONG64 baseForPdpt = i * 512 * EPT_PAGE_SIZE_1GB;

        /* Allocate PDPT from pool */
        pdptPa = Ctx->RootTablePa + EPT_PAGE_SIZE_4KB + poolOffset;
        poolOffset += EPT_PAGE_SIZE_4KB;
        pdpt = (PEPT_PDPTE)AnxPhysToVirt(pdptPa);
        if (!pdpt) return STATUS_INSUFFICIENT_RESOURCES;

        /* Link PML4[i] → PDPT */
        pml4[i].Value = 0;
        pml4[i].Read = 1;
        pml4[i].Write = 1;
        pml4[i].Execute = 1;
        pml4[i].PhysAddr = pdptPa >> 12;

        /* Fill PDPT entries (each covers 1GB) */
        for (j = 0; j < EPT_ENTRIES_PER_TABLE; j++) {
            ULONG64 gbBase = baseForPdpt + j * EPT_PAGE_SIZE_1GB;
            PEPT_PDE pd;
            ULONG64 pdPa;
            ULONG64 k;

            if (gbBase >= maxPhys + EPT_PAGE_SIZE_1GB) {
                /* Beyond physical memory: leave unmapped */
                pdpt[j].Value = 0;
                continue;
            }

            /* Allocate PD from pool */
            pdPa = Ctx->RootTablePa + EPT_PAGE_SIZE_4KB + poolOffset;
            poolOffset += EPT_PAGE_SIZE_4KB;
            pd = (PEPT_PDE)AnxPhysToVirt(pdPa);
            if (!pd) return STATUS_INSUFFICIENT_RESOURCES;

            /* Link PDPT[j] → PD (not a large page at PDPT level) */
            pdpt[j].Value = 0;
            pdpt[j].Read = 1;
            pdpt[j].Write = 1;
            pdpt[j].Execute = 1;
            pdpt[j].LargePage = 0;
            pdpt[j].PhysAddr = pdPa >> 12;

            /* Fill PD entries (each covers 2MB, mapped as large pages) */
            for (k = 0; k < EPT_ENTRIES_PER_TABLE; k++) {
                ULONG64 physAddr = gbBase + k * EPT_PAGE_SIZE_2MB;
                ULONG memType;

                if (physAddr >= maxPhys && !AnxEptIsMmioAddress(Ctx, physAddr)) {
                    pd[k].Value = 0;
                    continue;
                }

                memType = AnxEptGetMemoryType(Ctx, physAddr);

                pd[k].Value = 0;
                pd[k].Read = 1;
                pd[k].Write = 1;
                pd[k].Execute = 1;
                pd[k].LargePage = 1;
                pd[k].MemoryType = memType;
                pd[k].IgnorePat = 0;
                pd[k].PhysAddr = physAddr >> 12;

                Ctx->LargePageCount++;
            }
        }
    }

    /* Compute EPTP value */
    {
        EPTP eptp;
        eptp.Value = 0;
        eptp.MemoryType = EPT_MEMORY_TYPE_WB;
        eptp.PageWalkLength = 3;  /* 4-level (value = levels - 1) */
        eptp.DirtyAccess = 1;     /* Enable A/D bits */
        eptp.Pml4PhysAddr = Ctx->RootTablePa >> 12;
        Ctx->TablePointer = eptp.Value;
    }

    AnxDebugPrint("[HV:INF] EPT built: maxPhys=0x%p largePages=%d mmio=%d eptp=0x%p\n",
                  maxPhys, Ctx->LargePageCount, Ctx->MmioRegionCount, Ctx->TablePointer);

    return STATUS_SUCCESS;
}

/* ─── INVEPT ──────────────────────────────────────────────────────── */

/*
 * Execute INVEPT instruction.
 * Type: INVEPT_SINGLE_CONTEXT (1) or INVEPT_ALL_CONTEXT (2).
 * For single-context, Eptp must match the EPTP used in VMCS.
 * For all-context, Eptp is ignored (can be 0).
 */
VOID
AnxEptInvept(
    _In_ ULONG Type,
    _In_ ULONG64 Eptp
)
{
    INVEPT_DESCRIPTOR desc;
    desc.Eptp = Eptp;
    desc.Reserved = 0;

    __invept(Type, &desc);
}

VOID
AnxEptFlushAll(
    _In_ PANX_PAGE_TABLE_CTX Ctx
)
{
    if (Ctx) {
        AnxEptInvept(INVEPT_SINGLE_CONTEXT, Ctx->TablePointer);
    } else {
        AnxEptInvept(INVEPT_ALL_CONTEXT, 0);
    }
}

/* ─── Page Splitting (2MB → 512×4KB) ─────────────────────────────── */

/*
 * Split a 2MB large page into 512 individual 4KB pages.
 * Required before applying per-page protection (Phase 4).
 *
 * Allocates one PT page from the pre-allocated split pool.
 * After splitting, the PD entry points to the PT instead of
 * being a large page.
 */
NTSTATUS
AnxEptSplitPage(
    _Inout_ PANX_PAGE_TABLE_CTX Ctx,
    _In_ ULONG64 Gpa
)
{
    PEPT_PDE pde;
    PEPT_PTE pt;
    ULONG64 ptPa;
    ULONG64 baseAddr;
    ULONG memType;
    ULONG64 i;

    pde = AnxEptGetPde(Ctx, Gpa);
    if (!pde) return STATUS_NOT_FOUND;

    /* Already split? */
    if (!pde->LargePage) {
        return STATUS_SUCCESS;
    }

    /* Allocate a PT page from the split pool */
    if (Ctx->SplitPoolUsed + EPT_PAGE_SIZE_4KB > Ctx->SplitPoolSize) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ptPa = (ULONG64)AnxVirtToPhys((PUCHAR)Ctx->SplitPagePool + Ctx->SplitPoolUsed);
    pt = (PEPT_PTE)((PUCHAR)Ctx->SplitPagePool + Ctx->SplitPoolUsed);
    Ctx->SplitPoolUsed += EPT_PAGE_SIZE_4KB;

    /* Zero the PT page */
    __stosq((PULONG64)pt, 0, EPT_ENTRIES_PER_TABLE);

    /* Fill 512 × 4KB entries */
    baseAddr = (Gpa & ~(EPT_PAGE_SIZE_2MB - 1));
    memType = AnxEptGetMemoryType(Ctx, baseAddr);

    for (i = 0; i < EPT_ENTRIES_PER_TABLE; i++) {
        pt[i].Value = 0;
        pt[i].Read = 1;
        pt[i].Write = 1;
        pt[i].Execute = 1;
        pt[i].MemoryType = memType;
        pt[i].PhysAddr = (baseAddr + i * EPT_PAGE_SIZE_4KB) >> 12;
    }

    /* Convert PD entry from large page to PT pointer */
    pde->Value = 0;
    pde->Read = 1;
    pde->Write = 1;
    pde->Execute = 1;
    pde->LargePage = 0;
    pde->PhysAddr = ptPa >> 12;

    Ctx->LargePageCount--;
    Ctx->SmallPageCount += EPT_ENTRIES_PER_TABLE;

    /* Flush EPT to ensure new mapping takes effect */
    AnxEptInvept(INVEPT_SINGLE_CONTEXT, Ctx->TablePointer);

    return STATUS_SUCCESS;
}

/* ─── Permission Modification ─────────────────────────────────────── */

/*
 * Set EPT permissions for a single 4KB page.
 * Automatically splits the containing 2MB page if needed.
 *
 * PermMask: combination of EPT_PERM_READ/WRITE/EXECUTE.
 * The page must already be split (or will be split by this function).
 */
NTSTATUS
AnxEptSetPermission(
    _Inout_ PANX_PAGE_TABLE_CTX Ctx,
    _In_ ULONG64 Gpa,
    _In_ ULONG64 PermMask
)
{
    PEPT_PTE pte;
    NTSTATUS status;

    /* Ensure the page is split to 4KB granularity */
    status = AnxEptSplitPage(Ctx, Gpa);
    if (!NT_SUCCESS(status)) return status;

    pte = AnxEptGetPte(Ctx, Gpa);
    if (!pte) return STATUS_NOT_FOUND;

    /* Apply permission mask (preserve memory type and physical address) */
    pte->Read = (PermMask & EPT_PERM_READ) ? 1 : 0;
    pte->Write = (PermMask & EPT_PERM_WRITE) ? 1 : 0;
    pte->Execute = (PermMask & EPT_PERM_EXECUTE) ? 1 : 0;

    /* Flush TLB for this mapping */
    AnxEptInvept(INVEPT_SINGLE_CONTEXT, Ctx->TablePointer);

    return STATUS_SUCCESS;
}

/* ─── Page Table Walk ─────────────────────────────────────────────── */

/*
 * Walk EPT to get the PDE (2MB level) for a given GPA.
 * Returns NULL if the GPA is not mapped.
 */
PEPT_PDE
AnxEptGetPde(
    _In_ PANX_PAGE_TABLE_CTX Ctx,
    _In_ ULONG64 Gpa
)
{
    PEPT_PML4E pml4;
    PEPT_PDPTE pdpt;
    PEPT_PDE pd;
    ULONG64 pml4Idx, pdptIdx, pdIdx;

    pml4Idx = (Gpa >> 39) & 0x1FF;
    pdptIdx = (Gpa >> 30) & 0x1FF;
    pdIdx = (Gpa >> 21) & 0x1FF;

    pml4 = (PEPT_PML4E)AnxPhysToVirt(Ctx->RootTablePa);
    if (!pml4 || !pml4[pml4Idx].Read) return NULL;

    pdpt = (PEPT_PDPTE)AnxPhysToVirt((ULONG64)pml4[pml4Idx].PhysAddr << 12);
    if (!pdpt || !pdpt[pdptIdx].Read) return NULL;

    /* If PDPT entry is a 1GB large page, there's no PD level */
    if (pdpt[pdptIdx].LargePage) return NULL;

    pd = (PEPT_PDE)AnxPhysToVirt((ULONG64)pdpt[pdptIdx].PhysAddr << 12);
    if (!pd) return NULL;

    return &pd[pdIdx];
}

/*
 * Walk EPT to get the PTE (4KB level) for a given GPA.
 * Returns NULL if the page is still mapped as a 2MB large page
 * (call AnxEptSplitPage first).
 */
PEPT_PTE
AnxEptGetPte(
    _In_ PANX_PAGE_TABLE_CTX Ctx,
    _In_ ULONG64 Gpa
)
{
    PEPT_PDE pde;
    PEPT_PTE pt;
    ULONG64 ptIdx;

    ptIdx = (Gpa >> 12) & 0x1FF;

    pde = AnxEptGetPde(Ctx, Gpa);
    if (!pde) return NULL;

    /* Must not be a large page (must be split already) */
    if (pde->LargePage) return NULL;

    pt = (PEPT_PTE)AnxPhysToVirt((ULONG64)pde->PhysAddr << 12);
    if (!pt) return NULL;

    return &pt[ptIdx];
}
