/*
 * AnXinHypervisor - Protection Engine
 * Module: native/hypervisor/src/protect.c
 *
 * Manages protected memory regions and RIP whitelists.
 * All operations run in VMX root / SVM host context:
 *   - No Windows API calls (no ExAllocatePool, KeAcquireSpinLock, etc.)
 *   - Uses custom spinlock (_disable + InterlockedCompareExchange64)
 *   - Fixed-size pool with bitmap allocation (zero runtime allocation)
 *
 * Flow:
 *   1. Guest driver (ProcProtect) issues PROTECT_REGION hypercall
 *   2. protect.c registers the region, calls HAL to remove write permission
 *   3. Any write to the region triggers EPT violation / #NPF
 *   4. page_table.c calls AnxProtectCheckViolation()
 *   5. If RIP is whitelisted → single-step bypass (Phase 4 MTF/TF)
 *   6. If RIP is NOT whitelisted → block write, record violation event
 */

#include "../include/platform.h"
#include "../include/protect.h"
#include "../include/hal.h"
#include "../include/per_cpu.h"
#include "../include/ept.h"
#include "../include/anx_hv.h"

extern VOID AnxDebugPrint(const char* Fmt, ...);

/* Forward declaration (defined below, called from AnxProtectCheckViolation) */
VOID AnxProtectRecordViolation(ULONG CpuNumber, ULONG64 Gpa, ULONG64 Rip,
    ULONG64 Cr3, ULONG AccessType, ULONG RegionIndex, ULONG OwnerPid);

/* Violation ring buffer (shared with guest via hypercall) */
static ANX_VIOLATION_RING g_ViolationRing = { 0 };
static volatile ULONG g_SequenceCounter = 0;

/* ─── Bitmap Helpers ──────────────────────────────────────────────── */

static
ULONG
AnxBitmapAlloc(
    _Inout_ PULONG64 Bitmap,
    _In_ ULONG MaxBits
)
{
    ULONG i, bit;
    for (i = 0; i < (MaxBits + 63) / 64; i++) {
        if (Bitmap[i] != ~0ULL) {
            for (bit = 0; bit < 64; bit++) {
                ULONG idx = i * 64 + bit;
                if (idx >= MaxBits) return MAXULONG;
                if (!(Bitmap[i] & (1ULL << bit))) {
                    Bitmap[i] |= (1ULL << bit);
                    return idx;
                }
            }
        }
    }
    return MAXULONG;
}

static
VOID
AnxBitmapFree(
    _Inout_ PULONG64 Bitmap,
    _In_ ULONG Index
)
{
    Bitmap[Index / 64] &= ~(1ULL << (Index % 64));
}

/* ─── Region Registration ─────────────────────────────────────────── */

/*
 * Register a memory region for protection.
 * Called from hypercall context (VMX root / SVM host).
 *
 * Returns: slot index on success, MAXULONG on failure.
 */
ULONG
AnxProtectRegisterRegion(
    _In_ ULONG64 GuestPhysAddr,
    _In_ ULONG64 Size,
    _In_ ULONG ProtectFlags,
    _In_ ULONG OwnerPid,
    _Out_ PULONG64 RegistrationToken
)
{
    ULONG slot;
    PANX_PROTECTED_REGION region;
    ULONG64 pageAddr;
    ULONG64 pageCount;
    ULONG64 i;
    NTSTATUS status;

    /* Validate alignment */
    if (GuestPhysAddr & (ANX_PAGE_SIZE - 1)) return MAXULONG;
    if (Size == 0 || (Size & (ANX_PAGE_SIZE - 1))) return MAXULONG;

    AnxProtectLock();

    slot = AnxBitmapAlloc(g_ProtectEngine.RegionBitmap, ANX_MAX_PROTECTED_REGIONS);
    if (slot == MAXULONG) {
        AnxProtectUnlock();
        return MAXULONG;
    }

    region = &g_ProtectEngine.Regions[slot];
    region->GuestPhysAddr = GuestPhysAddr;
    region->Size = Size;
    region->ProtectFlags = ProtectFlags;
    region->OwnerPid = OwnerPid;
    region->ViolationCount = 0;
    region->RegistrationToken = __rdtsc() ^ (ULONG64)(slot + 1) * 0x9E3779B97F4A7C15ULL;
    region->InUse = TRUE;

    g_ProtectEngine.ActiveCount++;

    AnxProtectUnlock();

    *RegistrationToken = region->RegistrationToken;

    /* Apply EPT/NPT protection: remove write permission from all pages */
    pageAddr = GuestPhysAddr;
    pageCount = Size / ANX_PAGE_SIZE;

    for (i = 0; i < pageCount; i++) {
        status = g_HvOps.ProtectPage(pageAddr + i * ANX_PAGE_SIZE, ProtectFlags);
        if (!NT_SUCCESS(status)) {
            AnxDebugPrint("[HV:ERR] ProtectPage failed at GPA 0x%p: 0x%x\n",
                          pageAddr + i * ANX_PAGE_SIZE, (ULONG64)status);
        }
    }

    AnxDebugPrint("[HV:INF] Region registered: slot=%d GPA=0x%p size=0x%p flags=0x%x\n",
                  (ULONG64)slot, GuestPhysAddr, Size, (ULONG64)ProtectFlags);

    return slot;
}

/*
 * Unregister a protected region (restore RWX permissions).
 * Requires the registration token for authorization.
 */
NTSTATUS
AnxProtectUnregisterRegion(
    _In_ ULONG Slot,
    _In_ ULONG64 RegistrationToken
)
{
    PANX_PROTECTED_REGION region;
    ULONG64 pageAddr;
    ULONG64 pageCount;
    ULONG64 i;

    if (Slot >= ANX_MAX_PROTECTED_REGIONS) {
        return STATUS_INVALID_PARAMETER;
    }

    AnxProtectLock();

    region = &g_ProtectEngine.Regions[Slot];
    if (!region->InUse) {
        AnxProtectUnlock();
        return STATUS_NOT_FOUND;
    }

    if (region->RegistrationToken != RegistrationToken) {
        AnxProtectUnlock();
        return STATUS_ACCESS_DENIED;
    }

    pageAddr = region->GuestPhysAddr;
    pageCount = region->Size / ANX_PAGE_SIZE;

    region->InUse = FALSE;
    g_ProtectEngine.ActiveCount--;
    AnxBitmapFree(g_ProtectEngine.RegionBitmap, Slot);

    AnxProtectUnlock();

    /* Restore full permissions */
    for (i = 0; i < pageCount; i++) {
        g_HvOps.UnprotectPage(pageAddr + i * ANX_PAGE_SIZE);
    }

    AnxDebugPrint("[HV:INF] Region unregistered: slot=%d GPA=0x%p\n",
                  (ULONG64)Slot, pageAddr);

    return STATUS_SUCCESS;
}

/* ─── Whitelist Management ────────────────────────────────────────── */

NTSTATUS
AnxProtectAddWhitelist(
    _In_ ULONG64 RangeStart,
    _In_ ULONG64 RangeEnd
)
{
    ULONG i;

    if (RangeStart >= RangeEnd) return STATUS_INVALID_PARAMETER;

    AnxProtectLock();

    for (i = 0; i < ANX_MAX_WHITELIST_RANGES; i++) {
        if (!g_ProtectEngine.Whitelist[i].InUse) {
            g_ProtectEngine.Whitelist[i].RangeStart = RangeStart;
            g_ProtectEngine.Whitelist[i].RangeEnd = RangeEnd;
            g_ProtectEngine.Whitelist[i].InUse = TRUE;
            AnxProtectUnlock();
            AnxDebugPrint("[HV:INF] Whitelist added: [0x%p - 0x%p]\n",
                          RangeStart, RangeEnd);
            return STATUS_SUCCESS;
        }
    }

    AnxProtectUnlock();
    return STATUS_INSUFFICIENT_RESOURCES;
}

/* ─── Violation Check ─────────────────────────────────────────────── */

/*
 * Check if a GPA falls within any protected region.
 * Returns the region slot index, or MAXULONG if not protected.
 */
ULONG
AnxProtectFindRegion(
    _In_ ULONG64 Gpa
)
{
    ULONG i;

    for (i = 0; i < ANX_MAX_PROTECTED_REGIONS; i++) {
        PANX_PROTECTED_REGION r = &g_ProtectEngine.Regions[i];
        if (r->InUse &&
            Gpa >= r->GuestPhysAddr &&
            Gpa < r->GuestPhysAddr + r->Size) {
            return i;
        }
    }
    return MAXULONG;
}

/*
 * Check if a RIP is in the whitelist (legitimate writer).
 */
BOOLEAN
AnxProtectIsRipWhitelisted(
    _In_ ULONG64 Rip
)
{
    ULONG i;

    for (i = 0; i < ANX_MAX_WHITELIST_RANGES; i++) {
        PANX_RIP_WHITELIST w = &g_ProtectEngine.Whitelist[i];
        if (w->InUse && Rip >= w->RangeStart && Rip < w->RangeEnd) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Main violation check: called from EPT violation / #NPF handler.
 *
 * Returns:
 *   TRUE  = violation handled (either blocked or single-step bypass initiated)
 *   FALSE = not a protected region violation (caller should handle normally)
 */
BOOLEAN
AnxProtectCheckViolation(
    _In_ ULONG CpuNumber,
    _In_ ULONG64 Gpa,
    _In_ ULONG64 Rip,
    _In_ ULONG64 Cr3,
    _In_ BOOLEAN IsWrite
)
{
    ULONG regionIdx;
    PANX_PROTECTED_REGION region;
    BOOLEAN whitelisted;

    /* Only write violations are interesting for protection */
    if (!IsWrite) return FALSE;

    regionIdx = AnxProtectFindRegion(Gpa);
    if (regionIdx == MAXULONG) return FALSE;

    region = &g_ProtectEngine.Regions[regionIdx];
    region->ViolationCount++;

    whitelisted = AnxProtectIsRipWhitelisted(Rip);

    if (whitelisted) {
        /* Legitimate writer: initiate single-step bypass */
        /* Temporarily restore write permission, enable MTF/TF */
        PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
        ULONG64 pageGpa = Gpa & ~(ANX_PAGE_SIZE - 1);

        g_HvOps.UnprotectPage(pageGpa);
        g_HvOps.EnableSingleStep(CpuNumber);

        /* Store GPA for re-protection on MTF exit */
        if (perCpu) perCpu->SingleStepGpa = pageGpa;

        AnxDebugPrint("[HV:DBG] CPU %d: whitelisted write GPA=0x%p RIP=0x%p → single-step\n",
                      (ULONG64)CpuNumber, Gpa, Rip);
        return TRUE;
    }

    /* Unauthorized write: BLOCK it and record violation */
    AnxDebugPrint("[HV:WRN] CPU %d: BLOCKED write GPA=0x%p RIP=0x%p CR3=0x%p region=%d\n",
                  (ULONG64)CpuNumber, Gpa, Rip, Cr3, (ULONG64)regionIdx);

    /* Record violation event to ring buffer */
    AnxProtectRecordViolation(CpuNumber, Gpa, Rip, Cr3, 1, regionIdx, region->OwnerPid);

    return TRUE;
}

/* ─── Single-Step Completion ──────────────────────────────────────── */

/*
 * Called from MTF / #DB exit handler after a single-step bypass completes.
 * Re-applies write protection to the page that was temporarily unprotected.
 */
VOID
AnxProtectSingleStepComplete(
    _In_ ULONG CpuNumber,
    _In_ ULONG64 Gpa
)
{
    UNREFERENCED_PARAMETER(CpuNumber);

    /* Re-protect the page (remove write permission) */
    g_HvOps.ProtectPage(Gpa & ~(ANX_PAGE_SIZE - 1), ANX_PROT_READ_ONLY);

    /* Flush TLB to ensure protection takes effect immediately */
    g_HvOps.FlushTlb();
}

/* ─── Violation Event Recording ───────────────────────────────────── */

VOID
AnxProtectRecordViolation(
    _In_ ULONG CpuNumber,
    _In_ ULONG64 Gpa,
    _In_ ULONG64 Rip,
    _In_ ULONG64 Cr3,
    _In_ ULONG AccessType,
    _In_ ULONG RegionIndex,
    _In_ ULONG OwnerPid
)
{
    ULONG head;
    PANX_HV_VIOLATION_EVENT evt;

    head = g_ViolationRing.Head;

    /* Check if ring is full */
    if (((head + 1) % ANX_VIOLATION_RING_SIZE) == g_ViolationRing.Tail) {
        g_ViolationRing.OverflowCount++;
        return;
    }

    evt = &g_ViolationRing.Events[head];
    evt->Timestamp = __rdtsc();
    evt->GuestRip = Rip;
    evt->GuestCr3 = Cr3;
    evt->TargetGpa = Gpa;
    evt->AccessType = AccessType;
    evt->RegionIndex = RegionIndex;
    evt->OwnerPid = OwnerPid;
    evt->CpuNumber = CpuNumber;
    evt->ModuleBase = 0;  /* Estimated by guest-side consumer */
    evt->SequenceId = InterlockedIncrement((volatile LONG*)&g_SequenceCounter);

    /* Advance head (memory barrier ensures event is visible before head update) */
    _mm_mfence();
    g_ViolationRing.Head = (head + 1) % ANX_VIOLATION_RING_SIZE;
}

/* ─── Stats Collection ────────────────────────────────────────────── */

VOID
AnxProtectGetStats(
    _Out_ PANX_HV_STATS Stats
)
{
    ULONG i;
    ULONG64 totalExits = 0, pfExits = 0, cpuidExits = 0, hypercalls = 0;

    for (i = 0; i < g_CpuCount; i++) {
        PANX_HV_PER_CPU perCpu = g_PerCpuArray[i];
        if (!perCpu) continue;
        totalExits += perCpu->VmExitCount;
        pfExits += perCpu->PageFaultCount;
        cpuidExits += perCpu->CpuidExitCount;
        hypercalls += perCpu->HypercallCount;
    }

    Stats->TotalVmExits = totalExits;
    Stats->PageFaultExits = pfExits;
    Stats->CpuidExits = cpuidExits;
    Stats->HypercallCount = hypercalls;
    Stats->MsrExits = 0;
    Stats->CrAccessExits = 0;
    Stats->ViolationsBlocked = g_SequenceCounter;
    Stats->ViolationsAllowed = 0;
}

/* ─── Ring Buffer Access (for hypercall QUERY_VIOLATIONS) ─────────── */

PANX_VIOLATION_RING
AnxProtectGetViolationRing(VOID)
{
    return &g_ViolationRing;
}

ULONG
AnxProtectDrainViolations(
    _Out_ PANX_HV_VIOLATION_EVENT Buffer,
    _In_ ULONG MaxEvents
)
{
    ULONG count = 0;
    ULONG head = g_ViolationRing.Head;
    ULONG tail = g_ViolationRing.Tail;

    while (tail != head && count < MaxEvents) {
        Buffer[count] = g_ViolationRing.Events[tail % ANX_VIOLATION_RING_SIZE];
        tail = (tail + 1) % ANX_VIOLATION_RING_SIZE;
        count++;
    }

    g_ViolationRing.Tail = tail;
    return count;
}
