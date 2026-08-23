/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    anx_proc_internal.h

Abstract:
    AnXinProcMon.sys 驱动内部共享定义（仅内核使用，不构成用户态契约）。
    Driver-internal shared definitions (kernel only; not part of the user-mode
    contract — see anx_proc_ioctl.h for that).

    设计依据：docs/proc_monitor_design.md（契约 v6）
    Design source: docs/proc_monitor_design.md (contract v6)

Environment:
    Kernel mode only.

--*/

#ifndef ANX_PROC_INTERNAL_H
#define ANX_PROC_INTERNAL_H

/*
 * 强制将 NTDDI_VERSION 锁定到 NTDDI_WIN10_CO (0x0A00000B, Windows 10 21H2)。
 * 原因与 net_filter 相同：WDK 默认 NTDDI_VERSION 会让
 * ExAllocateFromLookasideListEx 在 Win10 21H2 内核上加载失败（错误 127）。
 * 必须在 #include <ntifs.h> 之前 #undef，因为 WDK 会通过 /D 在命令行末尾追加
 * NTDDI_VERSION=0xA000012，源码中的 #undef 才能覆盖命令行定义。
 */
#undef  NTDDI_VERSION
#define NTDDI_VERSION 0x0A00000B
#undef  _NT_TARGET_VERSION
#define _NT_TARGET_VERSION 0x0A00000B

#include <ntifs.h>
#include <wdm.h>
#include <ntstrsafe.h>

/*
 * fwpsk.h 要求先包含 fwpmk.h 之前定义 NDIS 版本（network.c 使用 WFP）。
 * fwpsk.h requires the NDIS version to be declared before inclusion.
 */
#ifndef NDIS_SUPPORT_NDIS6
#define NDIS_SUPPORT_NDIS6 1
#endif

#include <fwpsk.h>
#include <fwpmk.h>
#include <fltKernel.h>
#include <wdmsec.h>

#include "anx_proc_ioctl.h"

/* ==========================================================================
 * 池标记与日志 / Pool tags and logging
 * ========================================================================== */

#define ANX_PROC_TAG_NODE      'oNcP'   /* PcNo — 事件节点壳 */
#define ANX_PROC_TAG_PAYLOAD   'lPcP'   /* PcPl — 事件负载 */
#define ANX_PROC_TAG_RULES     'RrcP'   /* PcRr — 过滤表 */

#if DBG
#define AnxProcTrace(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[AnXinProc] " fmt, __VA_ARGS__)
#define AnxProcWarn(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, "[AnXinProc] " fmt, __VA_ARGS__)
#else
#define AnxProcTrace(fmt, ...)
#define AnxProcWarn(fmt, ...)
#endif

/* 错误级日志在 Release 下保留，便于现场排障 / kept in Release for field triage */
#define AnxProcError(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AnXinProc] " fmt, __VA_ARGS__)

/* ==========================================================================
 * 防呆常量 / Fail-safe constants
 * ========================================================================== */

#define ANX_PROC_SYSTEM_PID       4u
#define ANX_PROC_SYSTEM_IDLE_PID  0u
#define ANX_PROC_SYSTEM_REG_PID   8u

/* 过滤表最大分配字节（防溢出） */
#define ANX_PROC_FILTER_TABLE_MAX_BYTES  (16u * 1024u * 1024u)

/* ==========================================================================
 * 内部数据结构 / Internal data structures
 * ========================================================================== */

/*
 * 事件节点：LOOKASIDE 复用节点壳，负载按需池分配。
 * 节点壳固定大小，负载平均 200-600B，队列满载内存可控：
 * 2048+8192 节点壳 + 负载 ≈ 数十 MB 量级上限内的有界分配。
 * Event node: the shell is reused via LOOKASIDE; the payload is a separate
 * non-paged allocation. Bounded memory under full queues.
 */
typedef struct _ANX_PROC_EVENT_NODE {
    LIST_ENTRY       Link;
    ANX_PROC_EVENT_HDR Hdr;
    PUINT8           Payload;      /* 可为 NULL / may be NULL */
    ULONG            PayloadSize;
} ANX_PROC_EVENT_NODE, *PANX_PROC_EVENT_NODE;

/* 单个事件队列（生命周期 / 行为各一） / One event queue (lifecycle/behavior) */
typedef struct _ANX_PROC_QUEUE {
    LIST_ENTRY       EventList;
    KSPIN_LOCK       EventLock;
    volatile LONG    EventCount;
    volatile LONG64  EventsQueued;
    volatile LONG64  EventsDropped;
    volatile LONG    DroppedSinceLast;
    volatile LONG64  Sequence;       /* InterlockedIncrement64 单调递增 */
    LONG             MaxDepth;       /* ANX_PROC_MAX_*_QUEUE */
    BOOLEAN          DropNewest;     /* TRUE=满时丢新保旧（生命周期主干）；
                                        FALSE=满时丢旧保新（行为事件，§3.5） */
    IO_CSQ           Csq;
    LIST_ENTRY       IrpQueue;
    KSPIN_LOCK       IrpQueueLock;
    volatile LONG64  PendingEvents;  /* 构造中未入队（调试） */
} ANX_PROC_QUEUE, *PANX_PROC_QUEUE;

/* 过滤表（整表原子替换） / Filter table (whole-table atomic swap) */
typedef struct _ANX_PROC_FILTER_TABLE {
    UINT32               Version;
    UINT32               Count;
    ANX_PROC_FILTER_RULE Rules[ANYSIZE_ARRAY];
} ANX_PROC_FILTER_TABLE, *PANX_PROC_FILTER_TABLE;

/* 全局状态 / Global state */
typedef struct _ANX_PROC_GLOBALS {
    PDEVICE_OBJECT   DeviceObject;
    PDRIVER_OBJECT   DriverObject;
    UNICODE_STRING   SymlinkName;
    BOOLEAN          SymlinkCreated;

    /* --- 接管状态（版本握手即接管） --- */
    volatile LONG    UserModeAttached;
    volatile PVOID   AttachedProcessId;

    /* --- 功能开关（用户态 SET_FILTER 附带/或默认全开，采集按过滤表执行） --- */
    volatile LONG    Enabled;

    /* --- 过滤表 --- */
    PANX_PROC_FILTER_TABLE FilterTable;
    EX_SPIN_LOCK     TableLock;

    /* --- 事件双队列 --- */
    ANX_PROC_QUEUE   LifecycleQueue;
    ANX_PROC_QUEUE   BehaviorQueue;

    /* --- 回调活性（§13.7） --- */
    volatile LONG64  LastCallbackTickMs;

    /* --- 诊断 --- */
    volatile LONG    DiagFlags;

    /* --- 生命周期回调整体开关（按功能类别，SET_FILTER 时由用户态决定） --- */
    volatile LONG    CollectLifecycle;   /* 1=进程/线程/映像回调生效 */

    /* --- 卸载协调 --- */
    volatile LONG    ShuttingDown;
} ANX_PROC_GLOBALS, *PANX_PROC_GLOBALS;

extern ANX_PROC_GLOBALS g_AnxProc;

/* ==========================================================================
 * 跨模块函数声明 / Cross-module function declarations
 * ========================================================================== */

/* --- util.c ------------------------------------------------------------ */
UINT64  AnxProcGetTimeMs(void);                    /* 系统单调毫秒 */
UINT64  AnxProcGetFileTime(void);                  /* 100ns FILETIME */
BOOLEAN AnxProcIsSystemPid(_In_ ULONG Pid);        /* 0/4/8 防呆 */
BOOLEAN AnxProcIsShuttingDown(void);
BOOLEAN AnxProcIsAttached(void);
void    AnxProcCopyWide(_Out_writes_(DestChars) PWCHAR Dest, _In_ SIZE_T DestChars,
                        _In_reads_opt_(SrcChars) PCWCHAR Src, _In_ SIZE_T SrcChars);
BOOLEAN AnxProcMatchPrefix(_In_reads_opt_(RuleChars) PCWCHAR Rule,
                           _In_ SIZE_T RuleChars,
                           _In_reads_opt_(PathChars) PCWCHAR Path,
                           _In_ SIZE_T PathChars,
                           _In_ BOOLEAN CaseInsensitive);

/* --- events.c ---------------------------------------------------------- */
NTSTATUS AnxProcEventsInitialize(void);
void     AnxProcEventsShutdown(void);
/* 构造并投递一条事件（负载由调用方分配，投递失败时释放） */
void     AnxProcPostEvent(_In_ PANX_PROC_QUEUE Queue, _In_ UINT16 EventType,
                          _In_ UINT16 Flags, _In_ ULONG Pid, _In_ ULONG ParentPid,
                          _In_ ULONG CreatorPid, _In_ ULONG SessionId,
                          _In_ ULONG ExitStatus, _In_ UINT64 CreateTime,
                          _In_reads_opt_(PayloadSize) const void* Payload,
                          _In_ ULONG PayloadSize);
/* 队列满时丢最旧并注入 DROP_MARKER（§3.5） */
void     AnxProcDrainToIrps(_In_ PANX_PROC_QUEUE Queue);
void     AnxProcCsqFlushAll(_In_ PANX_PROC_QUEUE Queue, _In_ NTSTATUS Status);
ANX_PROC_QUEUE* AnxProcQueueByKind(_In_ UINT16 EventType);

/* --- rules.c ----------------------------------------------------------- */
NTSTATUS AnxProcRulesInitialize(void);
void     AnxProcRulesShutdown(void);
NTSTATUS AnxProcRulesSetTable(_In_reads_bytes_(Length) const void* Buffer,
                              _In_ ULONG Length);
/* 过滤决策：TRUE = 采集（入队），FALSE = 丢弃 */
BOOLEAN  AnxProcFilterDecide(_In_ UINT32 RuleType, _In_opt_ PCWSTR Name,
                             _In_ SIZE_T NameChars);
/* 默认跳过：内置防呆路径（映像加载的 System32 核心 DLL 精确白名单） */
BOOLEAN  AnxProcImageBuiltinSkip(_In_opt_ PCWSTR Path, _In_ SIZE_T PathChars);

/* --- lifecycle.c ------------------------------------------------------- */
NTSTATUS AnxProcLifecycleInitialize(void);
void     AnxProcLifecycleShutdown(void);
void     AnxProcLifecycleRegisterCallbacks(void);
void     AnxProcLifecycleUnregisterCallbacks(void);
ULONG    AnxProcLifecycleCallbackStatus(void);   /* GET_HEALTH 诊断位 */

/* --- file.c ------------------------------------------------------------ */
NTSTATUS AnxProcFileInitialize(_In_ PDRIVER_OBJECT DriverObject);
void     AnxProcFileShutdown(void);

/* --- registry.c -------------------------------------------------------- */
NTSTATUS AnxProcRegistryInitialize(void);
void     AnxProcRegistryShutdown(void);

/* --- network.c --------------------------------------------------------- */
NTSTATUS AnxProcNetworkInitialize(_In_ PDEVICE_OBJECT DeviceObject);
void     AnxProcNetworkShutdown(void);

/* ==========================================================================
 * 内联小工具 / Small inline helpers
 * ========================================================================== */

FORCEINLINE BOOLEAN AnxProcIsAttached(void)
{
    return InterlockedCompareExchange(&g_AnxProc.UserModeAttached, 0, 0) != 0;
}

FORCEINLINE BOOLEAN AnxProcIsShuttingDown(void)
{
    return InterlockedCompareExchange(&g_AnxProc.ShuttingDown, 0, 0) != 0;
}

FORCEINLINE BOOLEAN AnxProcIsCollectEnabled(void)
{
    return InterlockedCompareExchange(&g_AnxProc.CollectLifecycle, 0, 0) != 0;
}

/* 记录回调活性（§13.7）：每次事件入队时更新 */
FORCEINLINE void AnxProcTouchHealth(void)
{
    InterlockedExchange64(&g_AnxProc.LastCallbackTickMs, (LONG64)AnxProcGetTimeMs());
}

#endif /* ANX_PROC_INTERNAL_H */