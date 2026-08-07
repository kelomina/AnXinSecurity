/*
 * AnXinHypervisor - Unified Exit Reason Codes
 * Module: native/hypervisor/include/exit_reasons.h
 *
 * Platform-independent exit reason encoding.
 * Each backend (Intel/AMD) translates hardware-specific exit codes
 * to these unified values via HAL GetExitReason().
 */

#pragma once

#define ANX_EXIT_CPUID          0x01
#define ANX_EXIT_CR_ACCESS      0x02
#define ANX_EXIT_MSR_READ       0x03
#define ANX_EXIT_MSR_WRITE      0x04
#define ANX_EXIT_PAGE_FAULT     0x05    /* EPT violation / #NPF */
#define ANX_EXIT_HYPERCALL      0x06    /* VMCALL / VMMCALL */
#define ANX_EXIT_IO             0x07
#define ANX_EXIT_EXCEPTION      0x08
#define ANX_EXIT_TRIPLE_FAULT   0x09
#define ANX_EXIT_SINGLE_STEP    0x0A    /* MTF exit / #DB intercept */
#define ANX_EXIT_EXTERNAL_INT   0x0B
#define ANX_EXIT_NMI            0x0C
#define ANX_EXIT_HLT            0x0D
#define ANX_EXIT_VMX_PREEMPT    0x0E    /* Intel VMX preemption timer */
#define ANX_EXIT_UNKNOWN        0xFF

/* Intel VMX exit reasons (VMCS 0x6400 low 16 bits) */
#define VMX_EXIT_EXCEPTION_NMI      0
#define VMX_EXIT_EXTERNAL_INT       1
#define VMX_EXIT_TRIPLE_FAULT       2
#define VMX_EXIT_CPUID              10
#define VMX_EXIT_HLT                12
#define VMX_EXIT_VMCALL             18
#define VMX_EXIT_CR_ACCESS          28
#define VMX_EXIT_IO                 30
#define VMX_EXIT_MSR_READ           31
#define VMX_EXIT_MSR_WRITE          32
#define VMX_EXIT_MTF                27
#define VMX_EXIT_EPT_VIOLATION      48
#define VMX_EXIT_VMX_PREEMPT        52

/* AMD SVM exit codes (VMCB +0x070 ExitCode) */
#define SVM_EXIT_CR0_SEL_WRITE      0x00
#define SVM_EXIT_CR_READ_BASE       0x00    /* 0x00-0x0F: CR reads */
#define SVM_EXIT_CR_WRITE_BASE      0x10    /* 0x10-0x1F: CR writes */
#define SVM_EXIT_EXCEPTION_BASE     0x40    /* 0x40-0x5F: exceptions */
#define SVM_EXIT_INTR               0x60
#define SVM_EXIT_NMI                0x61
#define SVM_EXIT_SMI                0x62
#define SVM_EXIT_VINTR              0x64
#define SVM_EXIT_CPUID              0x72
#define SVM_EXIT_HLT                0x78
#define SVM_EXIT_IOIO               0x7B
#define SVM_EXIT_MSR_READ           0x7C
#define SVM_EXIT_MSR_WRITE          0x7D
#define SVM_EXIT_SHUTDOWN           0x7F
#define SVM_EXIT_VMRUN              0x80
#define SVM_EXIT_VMMCALL            0x81
#define SVM_EXIT_VMLOAD             0x82
#define SVM_EXIT_VMSAVE             0x83
#define SVM_EXIT_NPF                0x400   /* Nested Page Fault */
#define SVM_EXIT_AVIC_INCOMPLETE    0x401

/* AMD exception vector offsets within SVM_EXIT_EXCEPTION_BASE */
#define SVM_EXIT_EXCEPTION_DB       (SVM_EXIT_EXCEPTION_BASE + 1)   /* #DB */
#define SVM_EXIT_EXCEPTION_MC       (SVM_EXIT_EXCEPTION_BASE + 18)  /* #MC */
#define SVM_EXIT_EXCEPTION_PF       (SVM_EXIT_EXCEPTION_BASE + 14)  /* #PF */
