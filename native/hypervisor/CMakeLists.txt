# AnXinHypervisor - WDK Kernel Driver Build Configuration
# Requires: WDK 10.0.26100+, Visual Studio 2022, MASM (ml64.exe)
#
# This CMakeLists.txt is for IDE integration and reference.
# Actual WDK kernel driver compilation uses MSBuild with WDK targets.
# Use build_hypervisor.bat for one-click builds.

cmake_minimum_required(VERSION 3.20)
project(AnXinHypervisor C ASM_MASM)

set(CMAKE_C_STANDARD 11)

# WDK kernel-mode compile flags (reference; actual build via MSBuild/WDK)
set(KERNEL_C_FLAGS
    /kernel
    /GS-
    /Oi
    /W4
    /WX
    /Zp8
    /GF
    /Gy
    /Zi
)

# Include paths
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Source files
set(HV_SOURCES
    src/driver.c
    src/hal.c
    src/exit_handler.c
    src/exit_cpuid.c
    src/exit_cr.c
    src/exit_msr.c
    src/exit_pagefault.c
    src/hypercall.c
    src/page_table.c
    src/protect.c
    src/hide.c
    src/smp.c
    src/power.c
    src/debug.c
    src/intel/vmx.c
    src/intel/vmcs.c
    src/intel/ept.c
    src/intel/intel_ops.c
    src/amd/svm.c
    src/amd/vmcb.c
    src/amd/npt.c
    src/amd/amd_ops.c
)

set(HV_ASM_SOURCES
    src/intel/entry_intel.asm
    src/amd/entry_amd.asm
)

# Stub libraries (linked by ProcProtect, not by hypervisor itself)
set(STUB_SOURCES
    stub/vmcall_stub.asm
    stub/vmmcall_stub.asm
)

# Note: WDK drivers cannot be built with standard CMake toolchain.
# This file serves as project structure reference.
# Actual build: build_hypervisor.bat (MSBuild + WDK .vcxproj)
message(STATUS "AnXinHypervisor: Use build_hypervisor.bat for WDK kernel build")
