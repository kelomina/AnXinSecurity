/*
 * AnXinHypervisor - Hardware Abstraction Layer (HAL) Interface
 * Module: native/hypervisor/include/hal.h
 *
 * The HAL vtable (ANX_HV_OPS) abstracts Intel VT-x and AMD SVM differences.
 * Each platform backend implements one instance; DriverEntry selects based
 * on CPU vendor. All functions (except Init/Shutdown) execute in
 * VMX root / SVM host context.
 */

#pragma once

#include "platform.h"
#include "per_cpu.h"

/* Register indices for GetGuestReg/SetGuestReg */
#define ANX_REG_RAX     0
#define ANX_REG_RCX     1
#define ANX_REG_RDX     2
#define ANX_REG_RBX     3
#define ANX_REG_RSP     4
#define ANX_REG_RBP     5
#define ANX_REG_RSI     6
#define ANX_REG_RDI     7
#define ANX_REG_R8      8
#define ANX_REG_R9      9
#define ANX_REG_R10     10
#define ANX_REG_R11     11
#define ANX_REG_R12     12
#define ANX_REG_R13     13
#define ANX_REG_R14     14
#define ANX_REG_R15     15

/* Page protection flags for ProtectPage */
#define ANX_PAGE_PROT_READ      0x01
#define ANX_PAGE_PROT_WRITE     0x02
#define ANX_PAGE_PROT_EXECUTE   0x04
#define ANX_PAGE_PROT_RWX       (ANX_PAGE_PROT_READ | ANX_PAGE_PROT_WRITE | ANX_PAGE_PROT_EXECUTE)
#define ANX_PAGE_PROT_RO_X      (ANX_PAGE_PROT_READ | ANX_PAGE_PROT_EXECUTE)
#define ANX_PAGE_PROT_NONE      0x00

/*
 * Hardware abstraction layer operations interface.
 * Each platform backend fills one instance; DriverEntry binds g_HvOps.
 */
typedef struct _ANX_HV_OPS {
    /* Platform identification */
    const char*     PlatformName;       /* "Intel VT-x" or "AMD SVM" */

    /* Lifecycle */
    NTSTATUS      (*Init)(ULONG CpuNumber);
    NTSTATUS      (*EnterGuest)(ULONG CpuNumber);
    void          (*Shutdown)(ULONG CpuNumber);

    /* VM-exit / VMEXIT handling */
    void          (*HandleExit)(ULONG CpuNumber);
    ULONG         (*GetExitReason)(ULONG CpuNumber);
    ULONG64       (*GetExitQualification)(ULONG CpuNumber);

    /* Guest state access */
    ULONG64       (*GetGuestReg)(ULONG CpuNumber, ULONG RegIndex);
    void          (*SetGuestReg)(ULONG CpuNumber, ULONG RegIndex, ULONG64 Value);
    ULONG64       (*GetGuestRip)(ULONG CpuNumber);
    void          (*SetGuestRip)(ULONG CpuNumber, ULONG64 Rip);
    ULONG64       (*GetGuestCr3)(ULONG CpuNumber);

    /* Secondary page table (EPT / NPT) */
    NTSTATUS      (*BuildPageTables)(VOID);
    NTSTATUS      (*ProtectPage)(ULONG64 Gpa, ULONG Flags);
    NTSTATUS      (*UnprotectPage)(ULONG64 Gpa);
    void          (*FlushTlb)(VOID);

    /* Single-step (for legitimate write bypass) */
    NTSTATUS      (*EnableSingleStep)(ULONG CpuNumber);
    void          (*DisableSingleStep)(ULONG CpuNumber);

    /* Exception injection */
    void          (*InjectPF)(ULONG CpuNumber, ULONG64 FaultAddr, ULONG ErrorCode);
    void          (*InjectUD)(ULONG CpuNumber);

    /* TSC offset */
    void          (*SetTscOffset)(ULONG CpuNumber, LONG64 Offset);
} ANX_HV_OPS, *PANX_HV_OPS;

/* Global HAL instance (assigned in DriverEntry based on CPU vendor) */
extern ANX_HV_OPS g_HvOps;

/* Backend initialization functions (called by hal.c) */
VOID AnxIntelInitOps(_Out_ PANX_HV_OPS Ops);
VOID AnxAmdInitOps(_Out_ PANX_HV_OPS Ops);
