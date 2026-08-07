/*
 * AnXinHypervisor - Platform Detection & CPUID Wrappers
 * Module: native/hypervisor/include/platform.h
 */

#pragma once

#include <ntddk.h>
#include <intrin.h>

/* WDK 28000 sal.h defines SAL annotations with syntax that breaks in manual
   cl.exe /kernel builds (no WDK MSBuild toolset). Override them all as empty
   AFTER the WDK headers have been included. */
#undef _In_
#undef _Out_
#undef _Inout_
#undef _In_opt_
#undef _Out_opt_
#undef _Inout_opt_
#undef _Outptr_
#undef _Outptr_opt_
#undef _In_reads_
#undef _Out_writes_
#undef _In_reads_bytes_
#undef _Out_writes_bytes_
#undef _In_reads_opt_
#undef _Out_writes_opt_
#undef _Out_writes_to_
#undef _Out_writes_bytes_to_
#undef _When_
#undef _At_
#undef _Success_
#undef _Must_inspect_result_
#undef _Check_return_
#undef _IRQL_requires_
#undef _IRQL_requires_max_
#undef _IRQL_requires_min_
#undef _IRQL_saves_
#undef _IRQL_restores_
#undef _IRQL_raises_
#undef _IRQL_lowers_
#undef _Acquires_lock_
#undef _Releases_lock_
#undef _Requires_lock_held_
#undef _Requires_lock_not_held_
#undef _Use_decl_annotations_
#undef _Function_class_
#undef _Kernel_float_saved_
#undef _Kernel_float_restored_
#undef _Kernel_float_cleared_
#undef _Reserved_
#undef _Const_
#undef _Notnull_
#undef _Maybenull_
#undef _Null_
#undef _Pre_notnull_
#undef _Post_valid_
#undef _Post_invalid_
#undef _Post_ptr_invalid_
#undef _Deref_pre_notnull_
#undef _Deref_post_notnull_
#undef _Deref_out_
#undef _Deref_out_opt_
#undef _Deref_inout_
#undef _Deref_inout_opt_
#undef _Deref_out_bound_
#undef _In_bound_
#undef _Out_bound_
#undef _Inout_bound_
#undef _Field_size_
#undef _Field_size_opt_
#undef _Field_size_bytes_
#undef _Struct_size_bytes_
#undef _Printf_format_string_
#undef _Scanf_format_string_
#undef _Null_terminated_
#undef _NullNull_terminated_
#undef _Valid_
#undef _Notvalid_
#undef _Pre_valid_
#undef _Pre_invalid_
#undef _Pre_readable_
#undef _Pre_writable_
#undef _Post_readable_
#undef _Post_writable_
#undef _Writable_
#undef _Readable_
#undef _Ret_maybenull_
#undef _Ret_notnull_
#undef _Pre_defensive_
#undef _Post_defensive_
#undef _Assume_
#undef _Analysis_assume_
#undef _Analysis_mode_
#undef _Analysis_noreturn_
#undef _Raises_SEH_exception_
#undef _Maybe_raises_SEH_exception_
#undef _Interlocked_
#undef _Interlocked_operand_
#undef _Pre_satisfies_
#undef _Post_satisfies_
#undef _Satisfies_
#undef _Return_type_success_
#undef _On_failure_
#undef _Always_
#undef _Group_
#undef _Pre_
#undef _Post_
#undef _Deref_
#undef _Notref_
#define _In_
#define _Out_
#define _Inout_
#define _In_opt_
#define _Out_opt_
#define _Inout_opt_
#define _Outptr_
#define _Outptr_opt_
#define _In_reads_(x)
#define _Out_writes_(x)
#define _In_reads_bytes_(x)
#define _Out_writes_bytes_(x)
#define _In_reads_opt_(x)
#define _Out_writes_opt_(x)
#define _Out_writes_to_(x,y)
#define _Out_writes_bytes_to_(x,y)
#define _When_(x,y)
#define _At_(x,y)
#define _Success_(x)
#define _Must_inspect_result_
#define _Check_return_
#define _IRQL_requires_(x)
#define _IRQL_requires_max_(x)
#define _IRQL_requires_min_(x)
#define _IRQL_saves_
#define _IRQL_restores_
#define _IRQL_raises_(x)
#define _IRQL_lowers_(x)
#define _Acquires_lock_(x)
#define _Releases_lock_(x)
#define _Requires_lock_held_(x)
#define _Requires_lock_not_held_(x)
#define _Use_decl_annotations_
#define _Function_class_(x)
#define _Kernel_float_saved_
#define _Kernel_float_restored_
#define _Kernel_float_cleared_
#define _Reserved_
#define _Const_
#define _Notnull_
#define _Maybenull_
#define _Null_
#define _Pre_notnull_
#define _Post_valid_
#define _Post_invalid_
#define _Post_ptr_invalid_
#define _Deref_pre_notnull_
#define _Deref_post_notnull_
#define _Deref_out_
#define _Deref_out_opt_
#define _Deref_inout_
#define _Deref_inout_opt_
#define _Deref_out_bound_
#define _In_bound_
#define _Out_bound_
#define _Inout_bound_
#define _Field_size_(x)
#define _Field_size_opt_(x)
#define _Field_size_bytes_(x)
#define _Struct_size_bytes_(x)
#define _Printf_format_string_
#define _Scanf_format_string_
#define _Null_terminated_
#define _NullNull_terminated_
#define _Valid_
#define _Notvalid_
#define _Pre_valid_
#define _Pre_invalid_
#define _Pre_readable_(x)
#define _Pre_writable_(x)
#define _Post_readable_(x)
#define _Post_writable_(x)
#define _Writable_(x)
#define _Readable_(x)
#define _Ret_maybenull_
#define _Ret_notnull_
#define _Pre_defensive_
#define _Post_defensive_
#define _Assume_(x)
#define _Analysis_assume_(x)
#define _Analysis_mode_(x)
#define _Analysis_noreturn_
#define _Raises_SEH_exception_
#define _Maybe_raises_SEH_exception_
#define _Interlocked_
#define _Interlocked_operand_
#define _Pre_satisfies_(x)
#define _Post_satisfies_(x)
#define _Satisfies_(x)
#define _Return_type_success_(x)
#define _On_failure_(x)
#define _Always_(x)
#define _Group_(x)
#define _Pre_
#define _Post_
#define _Deref_
#define _Notref_

/* CPU vendor identifiers */
typedef enum _ANX_CPU_VENDOR {
    ANX_CPU_UNKNOWN = 0,
    ANX_CPU_INTEL,
    ANX_CPU_AMD
} ANX_CPU_VENDOR;

/* CPUID leaf 0 vendor strings */
#define ANX_INTEL_EBX   0x756E6547  /* "Genu" */
#define ANX_INTEL_EDX   0x49656E69  /* "ineI" */
#define ANX_INTEL_ECX   0x6C65746E  /* "ntel" */

#define ANX_AMD_EBX     0x68747541  /* "Auth" */
#define ANX_AMD_EDX     0x69746E65  /* "enti" */
#define ANX_AMD_ECX     0x444D4163  /* "cAMD" */

/* CPUID feature bits */
#define ANX_CPUID1_ECX_VMX          (1UL << 5)
#define ANX_CPUID1_ECX_HYPERVISOR   (1UL << 31)
#define ANX_CPUID1_ECX_X2APIC       (1UL << 21)

#define ANX_CPUID_80000001_ECX_SVM  (1UL << 2)
#define ANX_CPUID_80000001_EDX_NX   (1UL << 20)
#define ANX_CPUID_80000001_EDX_1GB  (1UL << 26)

#define ANX_CPUID_8000000A_EDX_NP   (1UL << 0)
#define ANX_CPUID_8000000A_EDX_SVML (1UL << 2)
#define ANX_CPUID_8000000A_EDX_AVIC (1UL << 13)

#define ANX_CPUID7_EDX_FLUSH_CMD    (1UL << 26)

/* MSR indices */
#define ANX_MSR_IA32_FEATURE_CONTROL    0x0000003A
#define ANX_MSR_IA32_VMX_CR0_FIXED0    0x00000606
#define ANX_MSR_IA32_VMX_CR0_FIXED1    0x00000607
#define ANX_MSR_IA32_VMX_CR4_FIXED0    0x00000608
#define ANX_MSR_IA32_VMX_CR4_FIXED1    0x00000609
#define ANX_MSR_IA32_VMX_BASIC         0x00000480
#define ANX_MSR_IA32_VMX_MISC          0x00000485
#define ANX_MSR_IA32_APIC_BASE         0x0000001B
#define ANX_MSR_IA32_EFER              0xC0000080
#define ANX_MSR_IA32_LSTAR             0xC0000082
#define ANX_MSR_IA32_CSTAR             0xC0000083
#define ANX_MSR_VM_CR                  0xC0010114
#define ANX_MSR_VM_HSAVE_PA            0xC0010117

/* IA32_FEATURE_CONTROL bits */
#define ANX_FEATURE_CONTROL_LOCK        (1ULL << 0)
#define ANX_FEATURE_CONTROL_VMXON_OUT   (1ULL << 2)

/* EFER bits */
#define ANX_EFER_NXE    (1ULL << 11)
#define ANX_EFER_LMA    (1ULL << 10)
#define ANX_EFER_LME    (1ULL << 8)
#define ANX_EFER_SVME   (1ULL << 12)

/* VM_CR bits (AMD) */
#define ANX_VM_CR_SVMDIS    (1ULL << 4)

/* CR0 / CR4 bits */
#define ANX_CR0_PE      (1ULL << 0)
#define ANX_CR0_TS      (1ULL << 3)
#define ANX_CR0_NE      (1ULL << 5)
#define ANX_CR0_PG      (1ULL << 31)
#define ANX_CR4_VMXE    (1ULL << 13)

/* Page constants */
#define ANX_PAGE_SIZE           4096
#define ANX_PAGE_ALIGN          0xFFFFFFFFFFFFF000ULL
#define ANX_2MB_PAGE_SIZE       (2 * 1024 * 1024)
#define ANX_1GB_PAGE_SIZE       (1024 * 1024 * 1024)

/* Physical address helpers */
#define ANX_MAX_PHYS_ADDR       0x000000FFFFFFFFFFULL  /* 40-bit */

#pragma warning(push)
#pragma warning(disable: 4201)  /* nameless struct/union */

/* CPUID result */
typedef struct _ANX_CPUID_RESULT {
    ULONG Eax;
    ULONG Ebx;
    ULONG Ecx;
    ULONG Edx;
} ANX_CPUID_RESULT;

typedef ANX_CPUID_RESULT* PANX_CPUID_RESULT;

#pragma warning(pop)

/* Inline CPUID wrapper */
__forceinline
VOID
AnxCpuid(
    PANX_CPUID_RESULT Result,
    ULONG Leaf
)
{
    int regs[4];
    __cpuid(regs, (int)Leaf);
    Result->Eax = (ULONG)regs[0];
    Result->Ebx = (ULONG)regs[1];
    Result->Ecx = (ULONG)regs[2];
    Result->Edx = (ULONG)regs[3];
}

__forceinline
VOID
AnxCpuidEx(
    PANX_CPUID_RESULT Result,
    ULONG Leaf,
    ULONG SubLeaf
)
{
    int regs[4];
    __cpuidex(regs, (int)Leaf, (int)SubLeaf);
    Result->Eax = (ULONG)regs[0];
    Result->Ebx = (ULONG)regs[1];
    Result->Ecx = (ULONG)regs[2];
    Result->Edx = (ULONG)regs[3];
}

/* Detect CPU vendor via CPUID leaf 0 */
__forceinline
ANX_CPU_VENDOR
AnxDetectCpuVendor(VOID)
{
    ANX_CPUID_RESULT r;
    AnxCpuid(&r, 0);

    if (r.Ebx == ANX_INTEL_EBX && r.Edx == ANX_INTEL_EDX && r.Ecx == ANX_INTEL_ECX)
        return ANX_CPU_INTEL;
    if (r.Ebx == ANX_AMD_EBX && r.Edx == ANX_AMD_EDX && r.Ecx == ANX_AMD_ECX)
        return ANX_CPU_AMD;

    return ANX_CPU_UNKNOWN;
}

/* Check if a hypervisor is already present (Hyper-V, VMware, etc.) */
__forceinline
BOOLEAN
AnxDetectExistingHypervisor(VOID)
{
    ANX_CPUID_RESULT r;
    AnxCpuid(&r, 1);
    return (r.Ecx & ANX_CPUID1_ECX_HYPERVISOR) ? TRUE : FALSE;
}

/* Physical address extraction from virtual (kernel VA) */
__forceinline
PHYSICAL_ADDRESS
AnxGetPhysicalAddress(
    _In_ PVOID VirtualAddress
)
{
    return MmGetPhysicalAddress(VirtualAddress);
}

/* Allocate physically contiguous, 4KB-aligned memory */
__forceinline
PVOID
AnxAllocateContiguous(
    _In_ SIZE_T Size
)
{
    PHYSICAL_ADDRESS maxPhys;
    maxPhys.QuadPart = ANX_MAX_PHYS_ADDR;
    PVOID p = MmAllocateContiguousMemory(Size, maxPhys);
    if (p) RtlZeroMemory(p, Size);
    return p;
}

__forceinline
VOID
AnxFreeContiguous(
    _In_ PVOID Address
)
{
    if (Address) MmFreeContiguousMemory(Address);
}

/* Convert physical address to kernel virtual address */
__forceinline
PVOID
AnxPhysToVirt(
    _In_ ULONG64 PhysicalAddress
)
{
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)PhysicalAddress;
    return MmGetVirtualForPhysical(pa);
}

/* Convert kernel virtual address to physical address (as ULONG64) */
__forceinline
ULONG64
AnxVirtToPhys(
    _In_ PVOID VirtualAddress
)
{
    PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(VirtualAddress);
    return (ULONG64)pa.QuadPart;
}

/* Get maximum physical address on the system (top of RAM) */
__forceinline
ULONG64
AnxGetMaxPhysicalAddress(VOID)
{
    /* Use MmGetPhysicalMemoryRanges to find the highest address.
     * For simplicity, return the highest range's end address. */
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    ULONG64 maxAddr = 0;
    if (ranges) {
        for (ULONG i = 0; ranges[i].NumberOfBytes.QuadPart != 0; i++) {
            ULONG64 end = (ULONG64)ranges[i].BaseAddress.QuadPart +
                          (ULONG64)ranges[i].NumberOfBytes.QuadPart;
            if (end > maxAddr) maxAddr = end;
        }
        ExFreePoolWithTag(ranges, 'hPmM');
    }
    return maxAddr;
}
