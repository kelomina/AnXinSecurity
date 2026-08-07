/*
 * AnXinHypervisor - Protection Engine Structures
 * Module: native/hypervisor/include/protect.h
 *
 * All memory is pre-allocated in DriverEntry (before VMXON/VMRUN).
 * Runtime operations only do pool-internal bitmap slot alloc/free.
 * No ExAllocatePool / MmAllocate* calls in VMX root / SVM host.
 */

#pragma once

#include "platform.h"

#define ANX_MAX_PROTECTED_REGIONS   256
#define ANX_MAX_WHITELIST_RANGES    32

/* Protection flags (used in ANX_PROTECTED_REGION.ProtectFlags and HAL calls) */
#define ANX_PROT_READ               0x0001  /* Allow read (always set) */
#define ANX_PROT_WRITE              0x0002  /* Allow write */
#define ANX_PROT_EXECUTE            0x0004  /* Allow execute */
#define ANX_PROT_READ_ONLY          (ANX_PROT_READ | ANX_PROT_EXECUTE)
#define ANX_PROT_FULL               (ANX_PROT_READ | ANX_PROT_WRITE | ANX_PROT_EXECUTE)

/* Protected memory region descriptor (fixed pool slot) */
typedef struct _ANX_PROTECTED_REGION {
    ULONG64     GuestPhysAddr;      /* Protected GPA (page-aligned) */
    ULONG64     Size;               /* Region size in bytes (page-aligned) */
    ULONG       ProtectFlags;       /* ANX_PROT_* combination */
    ULONG       OwnerPid;           /* Owning process PID (0 = global/self) */
    ULONG64     ViolationCount;     /* Violation access counter */
    ULONG64     RegistrationToken;  /* Random token for unprotect auth */
    BOOLEAN     InUse;              /* Slot occupied */
    UCHAR       Reserved[7];
} ANX_PROTECTED_REGION, *PANX_PROTECTED_REGION;

/* RIP whitelist range (legitimate writer code segments) */
typedef struct _ANX_RIP_WHITELIST {
    ULONG64     RangeStart;         /* Code segment start GPA */
    ULONG64     RangeEnd;           /* Code segment end GPA */
    BOOLEAN     InUse;
    UCHAR       Reserved[7];
} ANX_RIP_WHITELIST, *PANX_RIP_WHITELIST;

/* Global protection engine state (allocated once in DriverEntry) */
typedef struct _ANX_PROTECT_ENGINE {
    ANX_PROTECTED_REGION    Regions[ANX_MAX_PROTECTED_REGIONS];
    ANX_RIP_WHITELIST       Whitelist[ANX_MAX_WHITELIST_RANGES];
    ULONG64                 RegionBitmap[(ANX_MAX_PROTECTED_REGIONS + 63) / 64];
    ULONG                   ActiveCount;
    volatile LONG64         Lock;   /* Spinlock: _disable()/_enable() + InterlockedCompareExchange64 */
} ANX_PROTECT_ENGINE, *PANX_PROTECT_ENGINE;

/* Global instance */
extern ANX_PROTECT_ENGINE g_ProtectEngine;

/*
 * Lock protocol in VMX root / SVM host:
 *   KeAcquireSpinLock is NOT available (it's a Windows API).
 *   Use: _disable() + InterlockedCompareExchange64(&Lock, 1, 0)
 *   Release: InterlockedExchange64(&Lock, 0) + _enable()
 */
__forceinline
VOID
AnxProtectLock(VOID)
{
    _disable();
    while (InterlockedCompareExchange64(&g_ProtectEngine.Lock, 1, 0) != 0) {
        _mm_pause();
    }
}

__forceinline
VOID
AnxProtectUnlock(VOID)
{
    InterlockedExchange64(&g_ProtectEngine.Lock, 0);
    _enable();
}
