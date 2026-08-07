/*
 * AnXinHypervisor - AMD SVM VMCB Structures
 * Module: native/hypervisor/src/amd/vmcb.c
 *
 * VMCB (Virtual Machine Control Block) is plain memory (unlike Intel VMCS).
 * Control Area: offset 0x000-0x0FF
 * State Save Area: offset 0x400-0x5FF
 * Reference: AMD APM Vol.2 Table 15-17 / 15-18
 */

#include "../../include/platform.h"
#include "../../include/per_cpu.h"

#pragma warning(push)
#pragma warning(disable: 4201)

/* VMCB segment descriptor (16 bytes each) */
typedef struct _VMCB_SEGMENT {
    USHORT      Selector;
    USHORT      Attrib;
    ULONG32     Limit;
    ULONG64     Base;
} VMCB_SEGMENT;

/*
 * VMCB Control Area (offset 0x000 - 0x0FF)
 * Reference: AMD APM Vol.2 Table 15-17
 */
typedef struct _VMCB_CONTROL_AREA {
    ULONG32     InterceptCrRead;        /* +0x000 */
    ULONG32     InterceptCrWrite;       /* +0x004 */
    ULONG32     InterceptDrRead;        /* +0x008 */
    ULONG32     InterceptDrWrite;       /* +0x00C */
    ULONG32     InterceptException;     /* +0x010 */
    ULONG32     InterceptMisc1;         /* +0x014: INTR/NMI/SMI/INIT/VINTR/etc */
    ULONG32     InterceptMisc2;         /* +0x018: VMRUN/VMMCALL/VMLOAD/VMSAVE/etc */
    UCHAR       Reserved1[0x040 - 0x01C];

    ULONG64     IopmBasePa;            /* +0x040: I/O Permission Map PA (12KB) */
    ULONG64     MsrpmBasePa;           /* +0x048: MSR Permission Map PA (8KB) */

    ULONG64     TscOffset;             /* +0x050 */

    ULONG32     GuestAsid;             /* +0x058: must be >= 1 */
    ULONG32     TlbControl;            /* +0x05C: 0x00=no flush, 0x01=flush ASID */

    ULONG64     VIntr;                 /* +0x060: virtual interrupt control */
    ULONG64     InterruptShadow;       /* +0x068 */

    ULONG64     ExitCode;              /* +0x070: VMEXIT reason (hardware writes) */
    ULONG64     ExitInfo1;             /* +0x078 */
    ULONG64     ExitInfo2;             /* +0x080: #NPF fault GPA */
    ULONG64     ExitIntInfo;           /* +0x088 */

    ULONG64     NpEnable;              /* +0x090: bit 0 = 1 enables NPT */
    ULONG64     AvicApicBar;           /* +0x098 */
    ULONG64     NCr3;                  /* +0x0A0: NPT PML4 physical address */

    ULONG64     EventInj;              /* +0x0A8: event injection */
    ULONG64     VmcbClean;             /* +0x0B0: clean bits for VMRUN optimization */

    ULONG64     NRip;                  /* +0x0B8: next RIP (hardware writes on exit) */

    ULONG64     NumInstrBytes;         /* +0x0C0 */
    UCHAR       InstrBytes[15];        /* +0x0C8 */
    UCHAR       Reserved2[0x0E0 - 0x0D7];
} VMCB_CONTROL_AREA;

/*
 * VMCB State Save Area (offset 0x400 - 0x5FF)
 * Reference: AMD APM Vol.2 Table 15-18
 *
 * IMPORTANT: Large reserved gaps exist. CR4/CR3/CR0 do NOT follow EFER directly.
 */
typedef struct _VMCB_STATE_SAVE_AREA {
    VMCB_SEGMENT  Es;                  /* +0x400 */
    VMCB_SEGMENT  Cs;                  /* +0x410 */
    VMCB_SEGMENT  Ss;                  /* +0x420 */
    VMCB_SEGMENT  Ds;                  /* +0x430 */
    VMCB_SEGMENT  Fs;                  /* +0x440 (VMRUN does not load; use VMLOAD) */
    VMCB_SEGMENT  Gs;                  /* +0x450 (VMRUN does not load; use VMLOAD) */
    VMCB_SEGMENT  Gdtr;               /* +0x460 */
    VMCB_SEGMENT  Ldtr;               /* +0x470 */
    VMCB_SEGMENT  Idtr;               /* +0x480 */
    VMCB_SEGMENT  Tr;                  /* +0x490 */

    UCHAR       Reserved1[0x4CB - 0x4A0];

    UCHAR       Cpl;                   /* +0x4CB */
    UCHAR       Reserved2[4];          /* +0x4CC */

    ULONG64     Efer;                  /* +0x4D0 */

    UCHAR       Reserved3[0x548 - 0x4D8];  /* 112 bytes gap */

    ULONG64     Cr4;                   /* +0x548 */
    ULONG64     Cr3;                   /* +0x550 */
    ULONG64     Cr0;                   /* +0x558 */
    ULONG64     Dr7;                   /* +0x560 */
    ULONG64     Dr6;                   /* +0x568 */
    ULONG64     Rflags;                /* +0x570 */
    ULONG64     Rip;                   /* +0x578 */

    UCHAR       Reserved4[0x5D8 - 0x580];

    ULONG64     Rsp;                   /* +0x5D8 */

    UCHAR       Reserved5[0x5F8 - 0x5E0];

    ULONG64     Rax;                   /* +0x5F8 */

    /* RBX-R15 are NOT in VMCB. Must be saved/restored manually in asm. */
} VMCB_STATE_SAVE_AREA;

/* Complete VMCB (4KB aligned allocation) */
typedef struct _VMCB {
    VMCB_CONTROL_AREA   Control;       /* offset 0x000 */
    UCHAR               Pad[0x400 - sizeof(VMCB_CONTROL_AREA)];
    VMCB_STATE_SAVE_AREA StateSave;    /* offset 0x400 */
} VMCB;

typedef VMCB_CONTROL_AREA* PVMCB_CONTROL_AREA;
typedef VMCB_STATE_SAVE_AREA* PVMCB_STATE_SAVE_AREA;
typedef VMCB* PVMCB;

#pragma warning(pop)

/* Static assertions (verified at compile time) */
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, IopmBasePa) == 0x040);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, MsrpmBasePa) == 0x048);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, TscOffset) == 0x050);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, GuestAsid) == 0x058);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, ExitCode) == 0x070);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, ExitInfo1) == 0x078);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, ExitInfo2) == 0x080);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, NpEnable) == 0x090);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, NCr3) == 0x0A0);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, EventInj) == 0x0A8);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, VmcbClean) == 0x0B0);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, NRip) == 0x0B8);

C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Efer) == 0x0D0);   /* relative to StateSave start */
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Cr4) == 0x148);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Cr3) == 0x150);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Cr0) == 0x158);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Rflags) == 0x170);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Rip) == 0x178);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Rsp) == 0x1D8);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Rax) == 0x1F8);

C_ASSERT(sizeof(VMCB) <= 4096);

/* ─── Shared IOPM / MSRPM (allocated once, shared by all CPUs) ───── */

static PVOID    g_IopmBase = NULL;      /* 12KB, all zeros = allow all I/O */
static PVOID    g_MsrpmBase = NULL;     /* 8KB, all zeros = allow all MSR */
static ULONG64  g_IopmBasePa = 0;
static ULONG64  g_MsrpmBasePa = 0;

NTSTATUS
AnxSvmAllocatePermissionMaps(VOID)
{
    PHYSICAL_ADDRESS maxPhys;
    maxPhys.QuadPart = ANX_MAX_PHYS_ADDR;

    if (g_IopmBase) return STATUS_SUCCESS;

    g_IopmBase = MmAllocateContiguousMemory(12 * 1024, maxPhys);
    if (!g_IopmBase) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_IopmBase, 12 * 1024);
    g_IopmBasePa = (ULONG64)MmGetPhysicalAddress(g_IopmBase).QuadPart;

    g_MsrpmBase = MmAllocateContiguousMemory(8 * 1024, maxPhys);
    if (!g_MsrpmBase) {
        MmFreeContiguousMemory(g_IopmBase);
        g_IopmBase = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_MsrpmBase, 8 * 1024);
    g_MsrpmBasePa = (ULONG64)MmGetPhysicalAddress(g_MsrpmBase).QuadPart;

    return STATUS_SUCCESS;
}

/* ─── VMCB Access Helpers ─────────────────────────────────────────── */

__forceinline
PVMCB_CONTROL_AREA
AnxVmcbGetControl(
    _In_ PVOID VmcbRegion
)
{
    return (PVMCB_CONTROL_AREA)VmcbRegion;
}

__forceinline
PVMCB_STATE_SAVE_AREA
AnxVmcbGetStateSave(
    _In_ PVOID VmcbRegion
)
{
    return (PVMCB_STATE_SAVE_AREA)((PUCHAR)VmcbRegion + 0x400);
}

/*
 * Initialize VMCB for first VMRUN.
 * Captures current CPU state as guest state.
 */
NTSTATUS
AnxVmcbSetup(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    PVMCB_CONTROL_AREA ctrl;
    PVMCB_STATE_SAVE_AREA state;
    ULONG64 efer;

    ctrl = AnxVmcbGetControl(perCpu->Amd.VmcbRegion);
    state = AnxVmcbGetStateSave(perCpu->Amd.VmcbRegion);

    /* Zero the entire VMCB first */
    RtlZeroMemory(perCpu->Amd.VmcbRegion, ANX_PAGE_SIZE);

    /* ─── Control Area ─── */

    /* IOPM/MSRPM must be pre-allocated at PASSIVE_LEVEL by DriverEntry */
    if (!g_IopmBasePa || !g_MsrpmBasePa) return STATUS_UNSUCCESSFUL;

    /* InterceptMisc1: CPUID (bit 18) + HLT (bit 24) + SHUTDOWN (bit 31) */
    ctrl->InterceptMisc1 = (1UL << 18) | (1UL << 24) | (1UL << 31);

    /* InterceptMisc2: VMMCALL (bit 1) for hypercall communication */
    ctrl->InterceptMisc2 = (1UL << 1);

    /* ASID (must be >= 1) */
    ctrl->GuestAsid = perCpu->Amd.Asid;
    ctrl->TlbControl = 0;  /* No TLB flush on VMRUN */

    /* NPT: enable nested paging if page tables are built */
    if (perCpu->PageTablePointer != 0) {
        ctrl->NpEnable = 1;  /* bit 0 = NP enable */
        ctrl->NCr3 = perCpu->PageTablePointer;  /* NPT PML4 physical address */
    } else {
        ctrl->NpEnable = 0;
        ctrl->NCr3 = 0;
    }

    /* IOPM/MSRPM: valid physical addresses (all zeros = allow all) */
    ctrl->IopmBasePa = g_IopmBasePa;
    ctrl->MsrpmBasePa = g_MsrpmBasePa;

    /* TSC offset: 0 (no compensation yet) */
    ctrl->TscOffset = 0;

    /* Event injection: clear */
    ctrl->EventInj = 0;

    /* Clean bits: mark all as clean initially */
    ctrl->VmcbClean = 0;

    /* ─── State Save Area ─── */

    /* Capture current CPU state as guest */
    state->Cr0 = __readcr0();
    state->Cr3 = __readcr3();
    state->Cr4 = __readcr4();
    efer = __readmsr(ANX_MSR_IA32_EFER);
    state->Efer = efer;
    state->Rflags = __readeflags();
    /* CPL = 0 (kernel mode) */
    state->Cpl = 0;

    /* Guest RIP/RSP are set by AnxSvmRunGuest asm wrapper at VMRUN time
       (transparent hypervisor: guest continues at caller's return address). */

    /* Segment registers — AMD VMCB attribute format:
       Bits 7:0 = Type[3:0], S, DPL[1:0], P
       Bits 11:8 = AVL(bit8), L(bit9), DB(bit10), G(bit11)
       Bits 15:12 = Reserved (must be 0) */
    state->Cs.Selector = __readcs();
    state->Cs.Attrib = 0x029B;  /* 64-bit code: type=B, S=1, DPL=0, P=1, L=1 */
    state->Cs.Limit = 0xFFFFFFFF;
    state->Cs.Base = 0;

    state->Ss.Selector = __readss();
    state->Ss.Attrib = 0x0C93;  /* Data: type=3, S=1, DPL=0, P=1, DB=1, G=1 */
    state->Ss.Limit = 0xFFFFFFFF;
    state->Ss.Base = 0;

    state->Ds.Selector = __readds();
    state->Ds.Attrib = 0x0C93;
    state->Ds.Limit = 0xFFFFFFFF;
    state->Ds.Base = 0;

    state->Es.Selector = __reades();
    state->Es.Attrib = 0x0C93;
    state->Es.Limit = 0xFFFFFFFF;
    state->Es.Base = 0;

    state->Fs.Selector = __readfs();
    state->Fs.Attrib = 0x0C93;
    state->Fs.Limit = 0xFFFFFFFF;
    state->Fs.Base = __readmsr(0xC0000100);

    state->Gs.Selector = __readgs();
    state->Gs.Attrib = 0x0C93;
    state->Gs.Limit = 0xFFFFFFFF;
    state->Gs.Base = __readmsr(0xC0000101);

    /* GDTR / IDTR */
    {
        UCHAR gdtr[10], idtr[10];
        _sgdt(gdtr);
        __sidt(idtr);
        state->Gdtr.Limit = *(PUSHORT)gdtr;
        state->Gdtr.Base = *(PULONG64)(gdtr + 2);
        state->Idtr.Limit = *(PUSHORT)idtr;
        state->Idtr.Base = *(PULONG64)(idtr + 2);
    }

    /* TR / LDTR — parse GDT entries for base/limit/attrib */
    {
        extern USHORT AnxSvmReadTr(VOID);
        extern USHORT AnxSvmReadLdtr(VOID);

        UCHAR gdtr[10];
        ULONG64 gdtBase;
        USHORT trSel, ldtSel;

        _sgdt(gdtr);
        gdtBase = *(PULONG64)(gdtr + 2);

        trSel = AnxSvmReadTr();
        if (trSel != 0) {
            PUCHAR desc = (PUCHAR)(gdtBase + (trSel & 0xFFF8));
            ULONG64 base = *(PUSHORT)(desc + 2)
                         | ((ULONG64)desc[4] << 16)
                         | ((ULONG64)desc[7] << 24)
                         | ((ULONG64)*(PULONG32)(desc + 8) << 32);
            ULONG32 limit = *(PUSHORT)desc | ((ULONG32)(desc[6] & 0x0F) << 16);
            USHORT attrib = (USHORT)(desc[5] | ((desc[6] & 0xF0) << 4));

            state->Tr.Selector = trSel;
            state->Tr.Attrib = attrib;
            state->Tr.Limit = limit;
            state->Tr.Base = base;
        }

        ldtSel = AnxSvmReadLdtr();
        if (ldtSel != 0) {
            PUCHAR desc = (PUCHAR)(gdtBase + (ldtSel & 0xFFF8));
            ULONG64 base = *(PUSHORT)(desc + 2)
                         | ((ULONG64)desc[4] << 16)
                         | ((ULONG64)desc[7] << 24)
                         | ((ULONG64)*(PULONG32)(desc + 8) << 32);
            ULONG32 limit = *(PUSHORT)desc | ((ULONG32)(desc[6] & 0x0F) << 16);
            USHORT attrib = (USHORT)(desc[5] | ((desc[6] & 0xF0) << 4));

            state->Ldtr.Selector = ldtSel;
            state->Ldtr.Attrib = attrib;
            state->Ldtr.Limit = limit;
            state->Ldtr.Base = base;
        }
    }

    /* DR7 */
    state->Dr7 = __readdr(7);
    state->Dr6 = 0;

    AnxDebugPrint("[HV:DBG] CPU %d: VMCB configured (ASID=%d, EFER=0x%p)\n",
                  (ULONG64)CpuNumber, (ULONG64)perCpu->Amd.Asid, efer);
    return STATUS_SUCCESS;
}
