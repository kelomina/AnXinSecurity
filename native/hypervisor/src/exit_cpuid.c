/*
 * AnXinHypervisor - CPUID Exit Handler
 * Module: native/hypervisor/src/exit_handler.c (exit_cpuid.c)
 *
 * Handles CPUID VM-exit / VMEXIT:
 *   - Leaf 1: ECX[31] (Hypervisor Present) → cleared to hide ourselves
 *   - Leaves 0x40000000-0x400000FF → return all zeros (no HV signature)
 *   - All other leaves → transparent passthrough of physical CPUID
 *
 * Platform-independent: reads/writes guest RAX-RDX via HAL or
 * directly via VMCS/VMCB depending on platform.
 */

#include "../include/platform.h"
#include "../include/hal.h"
#include "../include/per_cpu.h"
#include "../include/exit_reasons.h"

extern VOID AnxDebugPrint(const char* Fmt, ...);
extern ANX_CPU_VENDOR g_CpuVendor;

/*
 * Guest register frame layout (must match entry_intel.asm / entry_amd.asm).
 * The assembly entry pushes GPRs in this order onto the host stack.
 */
typedef struct _ANX_GUEST_REGS {
    ULONG64 R15;
    ULONG64 R14;
    ULONG64 R13;
    ULONG64 R12;
    ULONG64 R11;
    ULONG64 R10;
    ULONG64 R9;
    ULONG64 R8;
    ULONG64 Rdi;
    ULONG64 Rsi;
    ULONG64 Rbp;
    ULONG64 Rbx;
    ULONG64 Rdx;
    ULONG64 Rcx;
    ULONG64 Rax;
} ANX_GUEST_REGS, *PANX_GUEST_REGS;

/*
 * Handle a CPUID exit.
 *
 * For Intel: guest RAX/RBX/RCX/RDX are on the stack frame (pushed by asm).
 *   We modify them in-place; the asm epilogue pops them back → guest sees modified values.
 *   After handling, advance guest RIP past the CPUID instruction (2 bytes: 0F A2).
 *
 * For AMD: guest RAX is in VMCB StateSave.Rax; RBX/RCX/RDX are on the stack frame.
 *   After handling, set guest RIP = VMCB NRip (hardware-provided next RIP).
 */
VOID
AnxHandleCpuidExit(
    _In_ ULONG CpuNumber
)
{
    PANX_HV_PER_CPU perCpu = g_PerCpuArray[CpuNumber];
    ULONG64 rip;
    ULONG leaf;
    ANX_CPUID_RESULT result;

    /*
     * Read guest RAX (CPUID leaf) from the appropriate source.
     * For Phase 1, we use a simplified approach:
     * - Intel: RAX is in the stack frame (handled by asm passing regs pointer)
     * - AMD: RAX is in VMCB StateSave
     *
     * Since the C handler is called differently on each platform,
     * we use the HAL to get/set RIP and handle RAX via platform-specific code.
     * For CPUID, we execute the physical CPUID and modify results.
     */

    /* Get the leaf from guest RAX via HAL */
    /* Note: In the actual implementation, the asm passes the register frame.
     * For Phase 1, we read RAX from VMCB (AMD) or assume it's passed. */
    leaf = (ULONG)g_HvOps.GetGuestReg(CpuNumber, ANX_REG_RAX);

    /* Execute physical CPUID */
    AnxCpuid(&result, leaf);

    /* Apply virtualization modifications */
    if (leaf == 1) {
        /* Clear Hypervisor Present bit (ECX[31]) to hide our existence */
        result.Ecx &= ~ANX_CPUID1_ECX_HYPERVISOR;
    }
    else if (leaf >= 0x40000000 && leaf <= 0x400000FF) {
        /* Hypervisor signature leaves: return all zeros */
        result.Eax = 0;
        result.Ebx = 0;
        result.Ecx = 0;
        result.Edx = 0;
    }
    /* All other leaves: passthrough (result already contains physical values) */

    /* Write results back to guest registers */
    g_HvOps.SetGuestReg(CpuNumber, ANX_REG_RAX, result.Eax);
    g_HvOps.SetGuestReg(CpuNumber, ANX_REG_RBX, result.Ebx);
    g_HvOps.SetGuestReg(CpuNumber, ANX_REG_RCX, result.Ecx);
    g_HvOps.SetGuestReg(CpuNumber, ANX_REG_RDX, result.Edx);

    /* Advance guest RIP past the CPUID instruction */
    rip = g_HvOps.GetGuestRip(CpuNumber);

    if (g_CpuVendor == ANX_CPU_INTEL) {
        /* CPUID is 2 bytes: 0F A2 */
        g_HvOps.SetGuestRip(CpuNumber, rip + 2);
    } else {
        /* AMD: use NRip from VMCB (hardware provides next RIP) */
        /* NRip is at VMCB +0x0B8 */
        ULONG64 nrip = *(PULONG64)((PUCHAR)perCpu->Amd.VmcbRegion + 0x0B8);
        if (nrip != 0) {
            g_HvOps.SetGuestRip(CpuNumber, nrip);
        } else {
            /* Fallback: CPUID is 2 bytes */
            g_HvOps.SetGuestRip(CpuNumber, rip + 2);
        }
    }
}
