/*
 * AnXinHypervisor - EPT / NPT Data Structures
 * Module: native/hypervisor/include/ept.h
 *
 * Intel EPT (Extended Page Tables) per Intel SDM Vol.3C Chapter 29.
 * AMD NPT (Nested Page Tables) per AMD APM Vol.2 Section 15.25.
 *
 * Both use 4-level paging with 2MB large pages for initial 1:1 mapping.
 * EPT uses a simplified permission model (R/W/X bits).
 * NPT uses standard x86-64 page table format with PWT/PCD/PAT for memory typing.
 */

#pragma once

#include "platform.h"

/* ─── Constants ───────────────────────────────────────────────────── */

#define EPT_ENTRIES_PER_TABLE       512
#define EPT_PAGE_SIZE_4KB           0x1000ULL
#define EPT_PAGE_SIZE_2MB           0x200000ULL
#define EPT_PAGE_SIZE_1GB           0x40000000ULL

/* EPT Memory Types (EPTP[2:0] and leaf entries[5:3]) */
#define EPT_MEMORY_TYPE_UC          0   /* Uncacheable */
#define EPT_MEMORY_TYPE_WC          1   /* Write-Combining */
#define EPT_MEMORY_TYPE_WT          4   /* Write-Through */
#define EPT_MEMORY_TYPE_WP          5   /* Write-Protected */
#define EPT_MEMORY_TYPE_WB          6   /* Write-Back */

/* EPT permission bits */
#define EPT_PERM_READ               (1ULL << 0)
#define EPT_PERM_WRITE              (1ULL << 1)
#define EPT_PERM_EXECUTE            (1ULL << 2)
#define EPT_PERM_EXECUTE_USER       (1ULL << 10)

/* EPT entry flags */
#define EPT_FLAG_ACCESSED           (1ULL << 8)
#define EPT_FLAG_DIRTY              (1ULL << 9)
#define EPT_FLAG_LARGE_PAGE         (1ULL << 7)

/* NPT (AMD) uses standard x86-64 PTE bits */
#define NPT_PERM_PRESENT            (1ULL << 0)
#define NPT_PERM_WRITE              (1ULL << 1)
#define NPT_PERM_USER               (1ULL << 2)
#define NPT_PERM_PWT                (1ULL << 3)   /* Page Write-Through */
#define NPT_PERM_PCD                (1ULL << 4)   /* Page Cache Disable */
#define NPT_PERM_ACCESSED           (1ULL << 5)
#define NPT_PERM_DIRTY              (1ULL << 6)
#define NPT_PERM_LARGE_PAGE         (1ULL << 7)
#define NPT_PERM_NX                 (1ULL << 63)  /* No-Execute */

/* ─── Intel EPT Structures ────────────────────────────────────────── */

/* EPT PML4 Entry (512 entries, each covers 512GB) */
typedef union _EPT_PML4E {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;           /* [0] */
        ULONG64 Write : 1;          /* [1] */
        ULONG64 Execute : 1;        /* [2] */
        ULONG64 Reserved1 : 5;      /* [7:3] must be 0 */
        ULONG64 Accessed : 1;       /* [8] */
        ULONG64 Ignored1 : 1;       /* [9] */
        ULONG64 ExecuteUser : 1;    /* [10] mode-based execute (optional) */
        ULONG64 Reserved2 : 1;      /* [11] must be 0 */
        ULONG64 PhysAddr : 40;      /* [51:12] next-level table PA >> 12 */
        ULONG64 Reserved3 : 12;     /* [63:52] must be 0 */
    };
} EPT_PML4E, *PEPT_PML4E;

/* EPT PDPT Entry (512 entries, each covers 1GB) */
typedef union _EPT_PDPTE {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;           /* [0] */
        ULONG64 Write : 1;          /* [1] */
        ULONG64 Execute : 1;        /* [2] */
        ULONG64 MemoryType : 3;     /* [5:3] only valid if LargePage=1 */
        ULONG64 IgnorePat : 1;      /* [6] only valid if LargePage=1 */
        ULONG64 LargePage : 1;      /* [7] 1 = 1GB page */
        ULONG64 Accessed : 1;       /* [8] */
        ULONG64 Dirty : 1;          /* [9] only valid if LargePage=1 */
        ULONG64 ExecuteUser : 1;    /* [10] */
        ULONG64 Reserved : 1;       /* [11] must be 0 */
        ULONG64 PhysAddr : 40;      /* [51:12] */
        ULONG64 Reserved2 : 12;     /* [63:52] */
    };
} EPT_PDPTE, *PEPT_PDPTE;

/* EPT PD Entry (512 entries, each covers 2MB) */
typedef union _EPT_PDE {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;           /* [0] */
        ULONG64 Write : 1;          /* [1] */
        ULONG64 Execute : 1;        /* [2] */
        ULONG64 MemoryType : 3;     /* [5:3] only valid if LargePage=1 */
        ULONG64 IgnorePat : 1;      /* [6] only valid if LargePage=1 */
        ULONG64 LargePage : 1;      /* [7] 1 = 2MB page, 0 = points to PT */
        ULONG64 Accessed : 1;       /* [8] */
        ULONG64 Dirty : 1;          /* [9] only valid if LargePage=1 */
        ULONG64 ExecuteUser : 1;    /* [10] */
        ULONG64 Reserved : 1;       /* [11] must be 0 */
        ULONG64 PhysAddr : 40;      /* [51:12] */
        ULONG64 Reserved2 : 12;     /* [63:52] */
    };
} EPT_PDE, *PEPT_PDE;

/* EPT PT Entry (512 entries, each covers 4KB) */
typedef union _EPT_PTE {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;           /* [0] */
        ULONG64 Write : 1;          /* [1] */
        ULONG64 Execute : 1;        /* [2] */
        ULONG64 MemoryType : 3;     /* [5:3] */
        ULONG64 IgnorePat : 1;      /* [6] */
        ULONG64 Ignored1 : 1;       /* [7] must be 0 (not large page) */
        ULONG64 Accessed : 1;       /* [8] */
        ULONG64 Dirty : 1;          /* [9] */
        ULONG64 ExecuteUser : 1;    /* [10] */
        ULONG64 Reserved : 1;       /* [11] must be 0 */
        ULONG64 PhysAddr : 40;      /* [51:12] */
        ULONG64 Reserved2 : 12;     /* [63:52] */
    };
} EPT_PTE, *PEPT_PTE;

/* EPTP (written to VMCS EPT Pointer field, encoding 0x201A) */
typedef union _EPTP {
    ULONG64 Value;
    struct {
        ULONG64 MemoryType : 3;     /* [2:0] = 6 (Write-Back) */
        ULONG64 PageWalkLength : 3; /* [5:3] = 3 (4-level walk) */
        ULONG64 DirtyAccess : 1;    /* [6] = 1 (enable A/D bits) */
        ULONG64 Reserved : 5;       /* [11:7] must be 0 */
        ULONG64 Pml4PhysAddr : 40;  /* [51:12] PML4 table PA >> 12 */
        ULONG64 Reserved2 : 12;     /* [63:52] must be 0 */
    };
} EPTP, *PEPTP;

/* INVEPT descriptor (passed to INVEPT instruction) */
typedef struct _INVEPT_DESCRIPTOR {
    ULONG64 Eptp;                   /* EPTP value (for single-context) */
    ULONG64 Reserved;               /* must be 0 */
} INVEPT_DESCRIPTOR, *PINVEPT_DESCRIPTOR;

/* INVEPT types */
#define INVEPT_SINGLE_CONTEXT       1
#define INVEPT_ALL_CONTEXT          2

/* ─── AMD NPT Structures (standard x86-64 format) ─────────────────── */

/* NPT uses standard x86-64 page table entries */
typedef union _NPT_PML4E {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;        /* [0] */
        ULONG64 Write : 1;          /* [1] */
        ULONG64 User : 1;           /* [2] */
        ULONG64 Pwt : 1;            /* [3] Page Write-Through */
        ULONG64 Pcd : 1;            /* [4] Page Cache Disable */
        ULONG64 Accessed : 1;       /* [5] */
        ULONG64 Ignored1 : 1;       /* [6] */
        ULONG64 Reserved : 1;       /* [7] must be 0 */
        ULONG64 Ignored2 : 4;       /* [11:8] */
        ULONG64 PhysAddr : 40;      /* [51:12] */
        ULONG64 Ignored3 : 11;      /* [62:52] */
        ULONG64 Nx : 1;             /* [63] No-Execute */
    };
} NPT_PML4E, *PNPT_PML4E;

typedef union _NPT_PDPTE {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;        /* [0] */
        ULONG64 Write : 1;          /* [1] */
        ULONG64 User : 1;           /* [2] */
        ULONG64 Pwt : 1;            /* [3] */
        ULONG64 Pcd : 1;            /* [4] */
        ULONG64 Accessed : 1;       /* [5] */
        ULONG64 Dirty : 1;          /* [6] only if LargePage=1 */
        ULONG64 LargePage : 1;      /* [7] 1 = 1GB page */
        ULONG64 Ignored1 : 4;       /* [11:8] */
        ULONG64 PhysAddr : 40;      /* [51:12] (30-bit aligned if large) */
        ULONG64 Ignored2 : 11;      /* [62:52] */
        ULONG64 Nx : 1;             /* [63] */
    };
} NPT_PDPTE, *PNPT_PDPTE;

typedef union _NPT_PDE {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;        /* [0] */
        ULONG64 Write : 1;          /* [1] */
        ULONG64 User : 1;           /* [2] */
        ULONG64 Pwt : 1;            /* [3] */
        ULONG64 Pcd : 1;            /* [4] */
        ULONG64 Accessed : 1;       /* [5] */
        ULONG64 Dirty : 1;          /* [6] only if LargePage=1 */
        ULONG64 LargePage : 1;      /* [7] 1 = 2MB page */
        ULONG64 Ignored1 : 4;       /* [11:8] */
        ULONG64 PhysAddr : 40;      /* [51:12] (21-bit aligned if large) */
        ULONG64 Ignored2 : 11;      /* [62:52] */
        ULONG64 Nx : 1;             /* [63] */
    };
} NPT_PDE, *PNPT_PDE;

typedef union _NPT_PTE {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;        /* [0] */
        ULONG64 Write : 1;          /* [1] */
        ULONG64 User : 1;           /* [2] */
        ULONG64 Pwt : 1;            /* [3] */
        ULONG64 Pcd : 1;            /* [4] */
        ULONG64 Accessed : 1;       /* [5] */
        ULONG64 Dirty : 1;          /* [6] */
        ULONG64 Pat : 1;            /* [7] PAT bit (4KB pages) */
        ULONG64 Ignored1 : 4;       /* [11:8] */
        ULONG64 PhysAddr : 40;      /* [51:12] */
        ULONG64 Ignored2 : 11;      /* [62:52] */
        ULONG64 Nx : 1;             /* [63] */
    };
} NPT_PTE, *PNPT_PTE;

/* ─── MMIO Region Tracking ────────────────────────────────────────── */

#define ANX_MAX_MMIO_REGIONS    64

typedef struct _ANX_MMIO_REGION {
    ULONG64 BaseAddress;            /* Physical base (page-aligned) */
    ULONG64 Size;                   /* Region size */
    BOOLEAN InUse;
    UCHAR   Reserved[7];
} ANX_MMIO_REGION, *PANX_MMIO_REGION;

/* ─── Page Table Context ──────────────────────────────────────────── */

/*
 * Per-platform page table state.
 * Stored in ANX_HV_PER_CPU.PageTablePointer.
 * Allocated once during DriverEntry (before VMXON/VMRUN).
 */
typedef struct _ANX_PAGE_TABLE_CTX {
    /* Root table physical address */
    ULONG64 RootTablePa;

    /* Intel: computed EPTP value (ready to write to VMCS) */
    /* AMD: NCR3 value (ready to write to VMCB) */
    ULONG64 TablePointer;

    /* Total physical memory mapped */
    ULONG64 MaxPhysicalAddress;

    /* Number of 2MB large pages used */
    ULONG64 LargePageCount;

    /* Number of 4KB pages (split from large pages for protection) */
    ULONG64 SmallPageCount;

    /* MMIO regions detected */
    ANX_MMIO_REGION MmioRegions[ANX_MAX_MMIO_REGIONS];
    ULONG MmioRegionCount;

    /* Pre-allocated page pool for 4KB splits (Phase 4 protection engine) */
    PVOID   SplitPagePool;
    ULONG64 SplitPoolSize;
    ULONG64 SplitPoolUsed;
} ANX_PAGE_TABLE_CTX, *PANX_PAGE_TABLE_CTX;

/* ─── Function Declarations ───────────────────────────────────────── */

/* Intel EPT (ept.c) */
NTSTATUS AnxEptBuildIdentityMap(_Inout_ PANX_PAGE_TABLE_CTX Ctx);
VOID AnxEptInvept(_In_ ULONG Type, _In_ ULONG64 Eptp);
VOID AnxEptFlushAll(_In_ PANX_PAGE_TABLE_CTX Ctx);
NTSTATUS AnxEptSplitPage(_Inout_ PANX_PAGE_TABLE_CTX Ctx, _In_ ULONG64 Gpa);
NTSTATUS AnxEptSetPermission(_Inout_ PANX_PAGE_TABLE_CTX Ctx, _In_ ULONG64 Gpa, _In_ ULONG64 PermMask);
PEPT_PTE AnxEptGetPte(_In_ PANX_PAGE_TABLE_CTX Ctx, _In_ ULONG64 Gpa);
PEPT_PDE AnxEptGetPde(_In_ PANX_PAGE_TABLE_CTX Ctx, _In_ ULONG64 Gpa);

/* AMD NPT (npt.c) */
NTSTATUS AnxNptBuildIdentityMap(_Inout_ PANX_PAGE_TABLE_CTX Ctx);
VOID AnxNptInvlpga(_In_ ULONG64 Address, _In_ ULONG Asid);
VOID AnxNptFlushAll(_In_ PANX_PAGE_TABLE_CTX Ctx);
NTSTATUS AnxNptSplitPage(_Inout_ PANX_PAGE_TABLE_CTX Ctx, _In_ ULONG64 Gpa);
NTSTATUS AnxNptSetPermission(_Inout_ PANX_PAGE_TABLE_CTX Ctx, _In_ ULONG64 Gpa, _In_ ULONG64 PermMask);
PNPT_PTE AnxNptGetPte(_In_ PANX_PAGE_TABLE_CTX Ctx, _In_ ULONG64 Gpa);
PNPT_PDE AnxNptGetPde(_In_ PANX_PAGE_TABLE_CTX Ctx, _In_ ULONG64 Gpa);

/* Platform-independent (page_table.c) */
NTSTATUS AnxPageTableInit(_In_ ULONG CpuNumber);
NTSTATUS AnxPageTableProtect(_In_ ULONG64 Gpa, _In_ ULONG Flags);
NTSTATUS AnxPageTableUnprotect(_In_ ULONG64 Gpa);
VOID AnxPageTableFlush(_In_ ULONG CpuNumber);
BOOLEAN AnxPageTableIsMmio(_In_ ULONG64 Gpa);
