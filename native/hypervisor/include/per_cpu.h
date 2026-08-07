/*
 * AnXinHypervisor - Per-CPU Data Structures
 * Module: native/hypervisor/include/per_cpu.h
 */

#pragma once

#include "platform.h"

#pragma warning(push)
#pragma warning(disable: 4201)

/*
 * Per-CPU hypervisor state.
 * One instance per logical processor, allocated in DriverEntry
 * before entering virtualization.
 */
typedef struct _ANX_HV_PER_CPU {
    /* Platform-specific region (union, use one per CPU vendor) */
    union {
        struct {    /* Intel VT-x */
            PVOID   VmxonRegion;        /* 4KB aligned, physically contiguous */
            PVOID   VmcsRegion;         /* 4KB aligned, physically contiguous */
            BOOLEAN VmcsLaunched;       /* VMLAUNCH done; subsequent entries use VMRESUME */
            UCHAR   IntelReserved[7];
        } Intel;
        struct {    /* AMD SVM */
            PVOID   VmcbRegion;         /* 4KB aligned (VMCB control block) */
            PVOID   HostSaveArea;       /* 4KB aligned (VM_HSAVE_PA target) */
            ULONG   Asid;               /* Address space ID (>= 1) */
            UCHAR   Reserved[4];
        } Amd;
    };

    /* Shared fields */
    PVOID           HostStack;          /* 16KB kernel stack */
    PVOID           HostStackTop;       /* Initial RSP value */

    /* Secondary page table (EPT or NPT, same format, slightly different semantics) */
    PVOID           PageTablePml4;      /* Top-level page table (physical address) */
    ULONG64         PageTablePointer;   /* Intel: EPTP value / AMD: NCR3 value */
    PVOID           PageTableCtx;       /* PANX_PAGE_TABLE_CTX - shared page table state */

    /* Guest state backup (auto-saved on exit, quick-access copy here) */
    ULONG64         GuestCr3;
    ULONG64         GuestRip;
    ULONG64         GuestRsp;
    ULONG64         SingleStepGpa;  /* GPA temporarily unprotected for MTF/TF bypass */

    /* Statistics */
    ULONG64         VmExitCount;
    ULONG64         PageFaultCount;     /* EPT violation / #NPF */
    ULONG64         CpuidExitCount;
    ULONG64         HypercallCount;

    /* State flags */
    BOOLEAN         VirtEnabled;        /* VMX/SVM enabled on this CPU */
    BOOLEAN         InRoot;             /* Currently in root mode */
    BOOLEAN         InitialExit;        /* TRUE until first VM-exit returns to IPI caller */
    UCHAR           Padding[5];

    /* Initial VM-entry return context (Intel: first VM-exit returns to IPI callback) */
    ULONG64         SavedIpiRsp;        /* RSP of IPI callback before VMLAUNCH */
    ULONG64         GuestRipInitial;    /* Return address of IPI callback = Guest RIP */
    ULONG64         HostRbx, HostRbp, HostRsi, HostRdi;
    ULONG64         HostR12, HostR13, HostR14, HostR15;

    /* Processor identification */
    ULONG           CpuNumber;
    ULONG           ApicId;             /* For IPI targeting */
} ANX_HV_PER_CPU, *PANX_HV_PER_CPU;

/* Host stack size per CPU */
#define ANX_HOST_STACK_SIZE     (16 * 1024)

/* Global per-CPU array (indexed by KeGetCurrentProcessorNumber()) */
extern PANX_HV_PER_CPU* g_PerCpuArray;
extern ULONG g_CpuCount;

/* Get current CPU's hypervisor state */
__forceinline
PANX_HV_PER_CPU
AnxGetCurrentPerCpu(VOID)
{
    ULONG cpu = KeGetCurrentProcessorNumber();
    return g_PerCpuArray[cpu];
}

#pragma warning(pop)
