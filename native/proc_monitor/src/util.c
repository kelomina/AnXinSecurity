/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    util.c

Abstract:
    AnXinProcMon.sys 纯工具函数：时间、防呆 PID、路径拷贝、前缀匹配。
    Pure helpers: time, fail-safe PID, path copy, prefix match.

    设计依据：docs/proc_monitor_design.md（契约 v6）
    Design source: docs/proc_monitor_design.md (contract v6)

Environment:
    Kernel mode only.

--*/

#include "anx_proc_internal.h"

/*
 * 函数名称：AnxProcGetTimeMs
 * 函数作用：系统单调时钟毫秒（活性心跳与超时用，不随系统时间跳变）。
 * Purpose: Monotonic system time in ms (heartbeat & timeouts).
 * IRQL：任何 / any
 */
UINT64 AnxProcGetTimeMs(void)
{
    LARGE_INTEGER now;
    KeQuerySystemTimePrecise(&now);   /* 100ns FILETIME */
    return (UINT64)(now.QuadPart / 10000);
}

/*
 * 函数名称：AnxProcGetFileTime
 * 函数作用：100ns FILETIME 系统时间（事件时间戳）。
 * Purpose: 100ns FILETIME system time (event timestamps).
 * IRQL：任何 / any
 */
UINT64 AnxProcGetFileTime(void)
{
    LARGE_INTEGER now;
    KeQuerySystemTimePrecise(&now);
    return (UINT64)now.QuadPart;
}

/*
 * 函数名称：AnxProcIsSystemPid
 * 函数作用：内置防呆 —— PID 0（Idle）/ 4（System）/ 8（Registry）必丢，
 * 不可被用户过滤表覆盖（§3.4）。
 * Purpose: Built-in fail-safe — PIDs 0/4/8 are always dropped; the user table
 * cannot override this (contract §3.4).
 * IRQL：任何 / any
 */
BOOLEAN AnxProcIsSystemPid(_In_ ULONG Pid)
{
    return (Pid == ANX_PROC_SYSTEM_PID) ||
           (Pid == ANX_PROC_SYSTEM_IDLE_PID) ||
           (Pid == ANX_PROC_SYSTEM_REG_PID);
}

/*
 * 函数名称：AnxProcCopyWide
 * 函数作用：带边界的安全宽字符拷贝（目标含 NUL 截断）。
 * Purpose: Bounded wide-char copy with NUL truncation.
 * IRQL：任何 / any
 */
void AnxProcCopyWide(_Out_writes_(DestChars) PWCHAR Dest, _In_ SIZE_T DestChars,
                     _In_reads_opt_(SrcChars) PCWCHAR Src, _In_ SIZE_T SrcChars)
{
    SIZE_T copy = SrcChars;

    if (Dest == NULL || DestChars == 0) {
        return;
    }
    if (Src == NULL) {
        Dest[0] = L'\0';
        return;
    }
    if (copy >= DestChars) {
        copy = DestChars - 1;
    }
    if (copy > 0) {
        RtlCopyMemory(Dest, Src, copy * sizeof(WCHAR));
    }
    Dest[copy] = L'\0';
}

/*
 * 函数名称：AnxProcMatchPrefix
 * 函数作用：规则名称与目标路径的前缀匹配（可选忽略大小写）。
 * 仅用于采集过滤，不用于授权（无权限语义）。
 * Purpose: Prefix match between a rule name and a path (optional case-folding).
 * Filtering only — never an authorization primitive.
 * IRQL：任何 / any
 */
BOOLEAN AnxProcMatchPrefix(_In_reads_opt_(RuleChars) PCWCHAR Rule,
                           _In_ SIZE_T RuleChars,
                           _In_reads_opt_(PathChars) PCWCHAR Path,
                           _In_ SIZE_T PathChars,
                           _In_ BOOLEAN CaseInsensitive)
{
    SIZE_T i;

    if (Rule == NULL || RuleChars == 0 || Path == NULL) {
        return FALSE;
    }
    if (RuleChars > PathChars) {
        return FALSE;
    }

    for (i = 0; i < RuleChars; i++) {
        WCHAR r = Rule[i];
        WCHAR p = Path[i];

        if (CaseInsensitive) {
            if (r >= L'A' && r <= L'Z') {
                r = (WCHAR)(r - L'A' + L'a');
            }
            if (p >= L'A' && p <= L'Z') {
                p = (WCHAR)(p - L'A' + L'a');
            }
        }
        if (r != p) {
            return FALSE;
        }
    }
    return TRUE;
}