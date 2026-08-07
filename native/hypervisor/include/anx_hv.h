/*
 * AnXinHypervisor - Public Header
 * Module: native/hypervisor/include/anx_hv.h
 *
 * Hypercall numbers, error codes, shared structures between
 * hypervisor (Ring -1) and guest drivers (Ring 0).
 */

#pragma once

/* ─── Hypercall Interface ─────────────────────────────────────────── */

/* Magic value: "ANXHV01" in little-endian ASCII */
#define ANX_VMCALL_MAGIC            0x414E5848563031ULL

/* Hypercall function codes (RBX) */
#define ANX_VMCALL_GET_VERSION      0x0001
#define ANX_VMCALL_PROTECT_REGION   0x0010
#define ANX_VMCALL_UNPROTECT_REGION 0x0011
#define ANX_VMCALL_QUERY_VIOLATION  0x0020
#define ANX_VMCALL_SET_POLICY       0x0030
#define ANX_VMCALL_GET_STATS        0x0040
#define ANX_VMCALL_PING             0x00FF
#define ANX_VMCALL_DEBUG_DUMP       0x00FE  /* Debug builds only */

/*
 * Calling convention (from Ring 0 guest):
 *   RAX = ANX_VMCALL_MAGIC
 *   RBX = function code
 *   RCX = param1 (GPA of input buffer)
 *   RDX = param2 (input buffer size)
 *   R8  = param3 (GPA of output buffer)
 *   Intel: VMCALL (0F 01 C1)
 *   AMD:   VMMCALL (0F 01 D9)
 *   Return: RAX = status (0 = success), RBX = output size
 */

/* ─── Error Codes ─────────────────────────────────────────────────── */

#define ANX_HV_SUCCESS              0x00000000ULL
#define ANX_HV_ERR_INVALID_MAGIC    0x80000001ULL
#define ANX_HV_ERR_INVALID_FUNC     0x80000002ULL
#define ANX_HV_ERR_INVALID_PARAM    0x80000003ULL
#define ANX_HV_ERR_NOT_AUTHORIZED   0x80000004ULL
#define ANX_HV_ERR_POOL_FULL        0x80000005ULL
#define ANX_HV_ERR_REGION_NOT_FOUND 0x80000006ULL
#define ANX_HV_ERR_REPLAY           0x80000007ULL
#define ANX_HV_ERR_NOT_READY        0x80000008ULL
#define ANX_HV_ERR_EPT_FAIL         0x80000009ULL
#define ANX_HV_ERR_SUSPENDED        0x8000000AULL

/* ─── Version ─────────────────────────────────────────────────────── */

#define ANX_HV_VERSION_MAJOR    0
#define ANX_HV_VERSION_MINOR    1
#define ANX_HV_VERSION_PATCH    0
#define ANX_HV_VERSION_STRING   "0.1.0-phase6"

/* ─── Degradation State ───────────────────────────────────────────── */

typedef enum _ANX_HV_MODE {
    ANX_HV_MODE_FULL = 0,           /* Virtualization active (EPT/NPT + MSR + CR) */
    ANX_HV_MODE_DEGRADED_HYPERV,    /* Existing hypervisor detected (Hyper-V/VMware) */
    ANX_HV_MODE_DEGRADED_CPU,       /* CPU vendor unknown or unsupported */
    ANX_HV_MODE_DEGRADED_VTX_OFF,   /* Intel VT-x disabled by BIOS */
    ANX_HV_MODE_DEGRADED_SVM_OFF,   /* AMD SVM disabled by BIOS */
    ANX_HV_MODE_DEGRADED_NO_NX,     /* NX not supported */
    ANX_HV_MODE_DEGRADED_NO_NPT,    /* AMD Nested Paging not available */
    ANX_HV_MODE_DEGRADED_INIT_FAIL, /* Virtualization init failed at runtime */
    ANX_HV_MODE_DEGRADED_NO_EPT     /* Running without EPT/NPT (no memory protection) */
} ANX_HV_MODE;

/* ─── User-Mode Query Interface (IOCTL) ───────────────────────────── */

#define ANX_HV_DEVICE_NAME      L"\\Device\\AnXinHypervisor"
#define ANX_HV_SYMLINK_NAME     L"\\DosDevices\\AnXinHypervisor"

#define ANX_HV_IOCTL_BASE       0x8000
#define ANX_HV_IOCTL_GET_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ANX_HV_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ANX_HV_IOCTL_GET_STATS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ANX_HV_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ANX_HV_IOCTL_GET_VIOLATIONS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, ANX_HV_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _ANX_HV_STATUS_INFO {
    ULONG       VersionMajor;
    ULONG       VersionMinor;
    ULONG       VersionPatch;
    ULONG       OperatingMode;      /* ANX_HV_MODE enum value */
    ULONG       CpuVendor;          /* 0=Unknown, 1=Intel, 2=AMD */
    ULONG       CpuCount;           /* Number of virtualized CPUs */
    ULONG       PageTablesActive;   /* 1 if EPT/NPT built successfully */
    ULONG       Reserved[2];
    char        PlatformName[64];   /* HAL platform string */
    char        DegradReason[128];  /* Human-readable degradation reason */
} ANX_HV_STATUS_INFO, *PANX_HV_STATUS_INFO;

/* ─── Violation Event Reporting ───────────────────────────────────── */

typedef struct _ANX_HV_VIOLATION_EVENT {
    ULONG64     Timestamp;          /* TSC value (guest converts to FILETIME) */
    ULONG64     GuestRip;           /* RIP that triggered the violation */
    ULONG64     GuestCr3;           /* Process page table base at violation */
    ULONG64     TargetGpa;          /* Guest physical address accessed */
    ULONG       AccessType;         /* 0=Read, 1=Write, 2=Execute */
    ULONG       RegionIndex;        /* Protected region slot index */
    ULONG       OwnerPid;           /* PID owning the protected region */
    ULONG       CpuNumber;          /* CPU that triggered the event */
    ULONG64     ModuleBase;         /* Estimated module base of guest RIP */
    ULONG       SequenceId;         /* Monotonic event sequence (loss detection) */
} ANX_HV_VIOLATION_EVENT, *PANX_HV_VIOLATION_EVENT;

#define ANX_VIOLATION_RING_SIZE     64

typedef struct _ANX_VIOLATION_RING {
    volatile ULONG  Head;           /* Written by hypervisor */
    volatile ULONG  Tail;           /* Read by guest (ProcProtect) */
    ULONG           Reserved;
    ULONG           OverflowCount;  /* Dropped events when ring full */
    ANX_HV_VIOLATION_EVENT Events[ANX_VIOLATION_RING_SIZE];
} ANX_VIOLATION_RING, *PANX_VIOLATION_RING;

/* ─── Hypercall Stats Output ──────────────────────────────────────── */

typedef struct _ANX_HV_STATS {
    ULONG64     TotalVmExits;
    ULONG64     PageFaultExits;
    ULONG64     CpuidExits;
    ULONG64     HypercallCount;
    ULONG64     MsrExits;
    ULONG64     CrAccessExits;
    ULONG64     ViolationsBlocked;
    ULONG64     ViolationsAllowed;  /* Whitelisted writes via single-step */
} ANX_HV_STATS, *PANX_HV_STATS;

/* ─── Protect Region Hypercall Parameters ─────────────────────────── */

typedef struct _ANX_HV_PROTECT_PARAMS {
    ULONG64     GuestPhysAddr;      /* Page-aligned GPA to protect */
    ULONG64     Size;               /* Region size (page-aligned) */
    ULONG       ProtectFlags;       /* ANX_PROT_* combination */
    ULONG       OwnerPid;           /* Owning process (0 = global/self) */
    ULONG64     RegistrationToken;  /* Returned on success, needed for unprotect */
} ANX_HV_PROTECT_PARAMS, *PANX_HV_PROTECT_PARAMS;

/* Protection flags (shared with protect.h) */
#define ANX_PROT_READ       0x0001
#define ANX_PROT_WRITE      0x0002
#define ANX_PROT_EXECUTE    0x0004
#define ANX_PROT_DENY_ALL   0x0000
#define ANX_PROT_RO         0x0005  /* Read + Execute */
#define ANX_PROT_NOTIFY     0x0100  /* Report event without blocking */
#define ANX_PROT_MTF_BYPASS 0x0200  /* Enable single-step for whitelisted writes */
