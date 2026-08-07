/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    anx_net_internal.h

Abstract:
    AnXinNetFilter.sys 驱动内部共享定义（仅内核使用，不构成用户态契约）。
    Driver-internal shared definitions (kernel only; not part of the user-mode
    contract — see anx_net_ioctl.h for that).

Environment:
    Kernel mode only.

--*/

#ifndef ANX_NET_INTERNAL_H
#define ANX_NET_INTERNAL_H

/*
 * 强制将 NTDDI_VERSION 锁定到 NTDDI_WIN10_CO (0x0A00000B, Windows 10 21H2)。
 * WDK 10.0.28000 默认把 NTDDI_VERSION 设为 0x0A000012（Win11 24H2+），这会让
 * wdm.h 把 ExAllocateFromLookasideListEx / ExFreeToLookasideListEx 当作
 * 「导出函数」而非 FORCEINLINE——但这两个函数只在 Win11 22H2+ 的 ntoskrnl.exe
 * 中导出，Win10 21H2 内核不导出，导致驱动加载时报错 127「找不到指定的程序」。
 * Force NTDDI_VERSION to NTDDI_WIN10_CO so wdm.h picks the FORCEINLINE
 * variant of ExAllocateFromLookasideListEx / ExFreeToLookasideListEx;
 * the exported variant only exists on Win11 22H2+ kernels and makes the
 * driver fail to load with error 127 on Win10.
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
 * fwpsk.h 要求先包含 fwpmk.h 之前定义 NDIS 版本。
 * fwpsk.h requires the NDIS version to be declared before inclusion.
 */
#ifndef NDIS_SUPPORT_NDIS6
#define NDIS_SUPPORT_NDIS6 1
#endif

#include <fwpsk.h>
#include <fwpmk.h>
#include <netioddk.h>

#include "anx_net_ioctl.h"

/* ==========================================================================
 * 池标记与日志 / Pool tags and logging
 * ========================================================================== */

#define ANX_TAG_RULES     'RteN'   /* NetR — 规则表 */
#define ANX_TAG_DOMAIN    'DteN'   /* NetD — 域名表 */
#define ANX_TAG_LIMIT     'LteN'   /* NetL — 限速表 */
#define ANX_TAG_EVENT     'EteN'   /* NetE — 事件节点 */
#define ANX_TAG_PENDING   'PteN'   /* NetP — 挂起决策 */
#define ANX_TAG_CACHE     'CteN'   /* NetC — 裁决缓存 */
#define ANX_TAG_FLOW      'FteN'   /* NetF — 流上下文 */
#define ANX_TAG_STAT      'SteN'   /* NetS — 进程统计 */
#define ANX_TAG_GENERIC   'GteN'   /* NetG — 通用临时缓冲 */

#if DBG
#define AnxTrace(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "[AnXinNet] " fmt, __VA_ARGS__)
#define AnxWarn(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, "[AnXinNet] " fmt, __VA_ARGS__)
#else
#define AnxTrace(fmt, ...)
#define AnxWarn(fmt, ...)
#endif

/* 错误级日志在 Release 下保留，便于现场排障 / kept in Release for field triage */
#define AnxError(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "[AnXinNet] " fmt, __VA_ARGS__)

/* ==========================================================================
 * 容量与调优常量 / Capacity and tuning constants
 * ========================================================================== */

#define ANX_CACHE_BUCKETS         256u
#define ANX_STAT_BUCKETS          128u
#define ANX_PENDING_TIMER_MS      500u    /* 挂起超时扫描周期 / sweep period */
#define ANX_DEFAULT_PROMPT_MS     20000u
#define ANX_MAX_INSPECT_BYTES     2048u   /* 每流最多检查的首部字节数 */
#define ANX_SUBLAYER_WEIGHT       0x8000
#define ANX_FILTER_WEIGHT_CATCH   0x0000  /* 兜底过滤器权重最低 */

/* ==========================================================================
 * 内部数据结构 / Internal data structures
 * ========================================================================== */

/* 规则表（整表替换，指针原子换出） / Rule table (whole-table atomic swap) */
typedef struct _ANX_RULE_TABLE {
    UINT32       Version;
    UINT32       Count;
    ANX_NET_RULE Rules[ANYSIZE_ARRAY];
} ANX_RULE_TABLE, *PANX_RULE_TABLE;

typedef struct _ANX_DOMAIN_TABLE {
    UINT32              Version;
    UINT32              Count;
    ANX_NET_DOMAIN_RULE Rules[ANYSIZE_ARRAY];
} ANX_DOMAIN_TABLE, *PANX_DOMAIN_TABLE;

typedef struct _ANX_LIMIT_TABLE {
    UINT32        Version;
    UINT32        Count;
    ANX_NET_LIMIT Limits[ANYSIZE_ARRAY];
} ANX_LIMIT_TABLE, *PANX_LIMIT_TABLE;

/* 裁决缓存条目 / Verdict cache entry */
typedef struct _ANX_CACHE_ENTRY {
    LIST_ENTRY   Link;
    UINT64       AppIdHash;
    ANX_NET_ADDR RemoteAddr;
    UINT64       ExpiryMs;      /* 0 = 永不过期 / never expires */
    UINT32       ProcessId;
    UINT32       Action;
    UINT16       RemotePort;
    UINT8        Protocol;
    UINT8        Direction;
    BOOLEAN      AnyRemote;     /* TRUE = 对该进程的全部目标生效 */
} ANX_CACHE_ENTRY, *PANX_CACHE_ENTRY;

/* 待用户裁决的挂起连接 / Connection pended awaiting a user verdict */
typedef struct _ANX_PENDING_ENTRY {
    LIST_ENTRY    Link;
    UINT64        DecisionId;
    UINT64        ClassifyHandle;   /* FwpsAcquireClassifyHandle0 返回值 */
    UINT64        ExpiryMs;
    UINT16        LayerId;
    BOOLEAN       Completed;        /* 已完成，等待清理 / done, awaiting reap */
    UINT64        AppIdHash;
    UINT32        ProcessId;
    ANX_NET_ADDR  RemoteAddr;
    UINT16        RemotePort;
    UINT8         Protocol;
    UINT8         Direction;
} ANX_PENDING_ENTRY, *PANX_PENDING_ENTRY;

/* 内核 → 用户的事件节点 / Kernel-to-user event node */
typedef struct _ANX_EVENT_NODE {
    LIST_ENTRY    Link;
    ANX_NET_EVENT Event;
} ANX_EVENT_NODE, *PANX_EVENT_NODE;

/* 流上下文（统计与限速） / Flow context (stats and rate limiting) */
typedef struct _ANX_FLOW_CTX {
    UINT64          FlowId;
    UINT64          AppIdHash;
    UINT32          ProcessId;
    UINT32          Direction;
    UINT32          Protocol;
    UINT16          LocalPort;
    UINT16          RemotePort;
    ANX_NET_ADDR    RemoteAddr;
    volatile LONG64 BytesIn;
    volatile LONG64 BytesOut;
    volatile LONG   InspectDone;    /* SNI/Host 已提取，避免重复解析 */
    UINT32          InspectedBytes;
} ANX_FLOW_CTX, *PANX_FLOW_CTX;

/* 进程级统计与令牌桶 / Per-process stats and token bucket */
typedef struct _ANX_STAT_NODE {
    LIST_ENTRY        Link;
    ANX_NET_PROC_STAT Stat;
    volatile LONG64   TokensIn;
    volatile LONG64   TokensOut;
    UINT64            LastRefillMs;
    UINT64            LimitIn;      /* 字节/秒，0 = 不限 */
    UINT64            LimitOut;
    UINT64            BurstBytes;
} ANX_STAT_NODE, *PANX_STAT_NODE;

/* ==========================================================================
 * 全局状态 / Global state
 * ========================================================================== */

typedef struct _ANX_GLOBALS {
    PDEVICE_OBJECT   DeviceObject;
    PDRIVER_OBJECT   DriverObject;
    UNICODE_STRING   SymlinkName;
    BOOLEAN          SymlinkCreated;

    /* --- WFP --- */
    HANDLE           EngineHandle;
    UINT64           SubLayerKeySet;      /* 非 0 表示子层已添加 */
    UINT32           Capabilities;        /* ANX_NET_CAP_* */

    /* --- 运行配置（由用户态下发） --- */
    ANX_NET_CONFIG   Config;
    EX_SPIN_LOCK     ConfigLock;

    /*
     * 用户态是否已完成握手并接管。为 FALSE 时驱动一律放行（fail-open），
     * 这是最重要的安全兜底：服务进程崩溃不得导致机器断网。
     * Whether user mode has completed the handshake and taken over. While
     * FALSE the driver permits everything (fail-open) — the single most
     * important safety property: a crashed service must never cut networking.
     */
    volatile LONG    UserModeAttached;
    HANDLE           AttachedProcessId;

    /* --- 规则 / 域名 / 限速表 --- */
    PANX_RULE_TABLE   RuleTable;
    PANX_DOMAIN_TABLE DomainTable;
    PANX_LIMIT_TABLE  LimitTable;
    EX_SPIN_LOCK      TableLock;

    /* --- 裁决缓存 --- */
    LIST_ENTRY       CacheBuckets[ANX_CACHE_BUCKETS];
    EX_SPIN_LOCK     CacheLock;
    volatile LONG64  CacheHits;
    volatile LONG64  CacheMisses;

    /* --- 进程统计 --- */
    LIST_ENTRY       StatBuckets[ANX_STAT_BUCKETS];
    EX_SPIN_LOCK     StatLock;

    /* --- 挂起决策 --- */
    LIST_ENTRY       PendingList;
    KSPIN_LOCK       PendingLock;
    volatile LONG64  NextDecisionId;
    volatile LONG    PendingCount;
    volatile LONG64  PendingTimedOut;
    KTIMER           PendingTimer;
    KDPC             PendingDpc;
    BOOLEAN          PendingTimerStarted;

    /* --- 事件队列（内核 → 用户） --- */
    LIST_ENTRY       EventList;
    KSPIN_LOCK       EventLock;
    volatile LONG    EventCount;
    volatile LONG64  EventsQueued;
    volatile LONG64  EventsDropped;
    volatile LONG    DroppedSinceLast;

    /* --- 取消安全 IRP 队列（倒置调用） --- */
    IO_CSQ           Csq;
    LIST_ENTRY       IrpQueue;
    KSPIN_LOCK       IrpQueueLock;

    /* --- 卸载协调 --- */
    volatile LONG    ShuttingDown;
} ANX_GLOBALS, *PANX_GLOBALS;

extern ANX_GLOBALS g_Anx;

/* ==========================================================================
 * 分类判定的中间结果 / Intermediate classification result
 * ========================================================================== */

typedef struct _ANX_CONN_INFO {
    UINT32       ProcessId;
    UINT64       AppIdHash;
    UINT32       Direction;
    UINT32       Protocol;
    UINT16       LocalPort;
    UINT16       RemotePort;
    ANX_NET_ADDR LocalAddr;
    ANX_NET_ADDR RemoteAddr;
    BOOLEAN      IsLoopback;
    BOOLEAN      IsReauthorize;
    /* 映像 NT 路径，可能为空串 / image NT path, may be empty */
    WCHAR        ImagePath[ANX_NET_MAX_PATH];
} ANX_CONN_INFO, *PANX_CONN_INFO;

/* ==========================================================================
 * 跨模块函数声明 / Cross-module function declarations
 * ========================================================================== */

/* --- util.c ------------------------------------------------------------ */
UINT64  AnxGetSystemTimeMs(void);
UINT64  AnxHashAppIdBytes(_In_reads_bytes_(ByteLength) const void* Bytes, _In_ SIZE_T ByteLength);
UINT64  AnxHashImagePath(_In_ PCWSTR Path, _In_ SIZE_T CharCount);
BOOLEAN AnxAddrIsLoopback(_In_ const ANX_NET_ADDR* Addr);
BOOLEAN AnxAddrMatchesCidr(_In_ const ANX_NET_ADDR* Addr,
                           _In_ const ANX_NET_ADDR* Network,
                           _In_ UINT8 PrefixLen);
void    AnxCopyPathToBuffer(_Out_writes_(DestChars) PWCHAR Dest,
                            _In_ SIZE_T DestChars,
                            _In_opt_ PCWSTR Source,
                            _In_ SIZE_T SourceChars);
void    AnxDomainToLower(_Inout_updates_(CharCount) PWCHAR Domain, _In_ SIZE_T CharCount);

/* --- rules.c ----------------------------------------------------------- */
NTSTATUS AnxRulesInitialize(void);
void     AnxRulesShutdown(void);
NTSTATUS AnxRulesSetTable(_In_reads_bytes_(Length) const void* Buffer, _In_ ULONG Length);
NTSTATUS AnxDomainsSetTable(_In_reads_bytes_(Length) const void* Buffer, _In_ ULONG Length);
NTSTATUS AnxLimitsSetTable(_In_reads_bytes_(Length) const void* Buffer, _In_ ULONG Length);

/* 返回 ANX_NET_ACTION_*；MatchedRuleId 为命中的规则 ID（未命中时为 0） */
UINT32   AnxRulesEvaluate(_In_ const ANX_CONN_INFO* Conn, _Out_ UINT32* MatchedRuleId);
UINT32   AnxDomainsEvaluate(_In_ PCWSTR Domain, _Out_ UINT32* MatchedRuleId);

BOOLEAN  AnxCacheLookup(_In_ const ANX_CONN_INFO* Conn, _Out_ UINT32* Action);
void     AnxCacheInsert(_In_ const ANX_CONN_INFO* Conn, _In_ UINT32 Action,
                        _In_ BOOLEAN AnyRemote, _In_ UINT32 TtlMs);
void     AnxCacheFlush(_In_ UINT32 Scope, _In_ UINT32 ProcessId, _In_ UINT64 AppIdHash);

PANX_STAT_NODE AnxStatAcquire(_In_ UINT32 ProcessId, _In_ UINT64 AppIdHash);
void     AnxStatAddBytes(_In_ UINT32 ProcessId, _In_ UINT64 AppIdHash,
                         _In_ UINT64 BytesIn, _In_ UINT64 BytesOut);
void     AnxStatCountConnection(_In_ UINT32 ProcessId, _In_ UINT64 AppIdHash, _In_ BOOLEAN Allowed);
NTSTATUS AnxStatSnapshot(_Out_writes_bytes_(OutLength) void* Buffer, _In_ ULONG OutLength,
                         _Out_ ULONG* BytesWritten);
/* 令牌桶：返回 TRUE 表示应放行，FALSE 表示超出配额需丢弃/延迟 */
BOOLEAN  AnxRateConsume(_In_ UINT32 ProcessId, _In_ UINT64 AppIdHash,
                        _In_ UINT64 Bytes, _In_ BOOLEAN Inbound);

/* --- events.c ---------------------------------------------------------- */
NTSTATUS AnxEventsInitialize(void);
void     AnxEventsShutdown(void);
void     AnxEventPost(_In_ const ANX_NET_EVENT* Event);
void     AnxEventBuildFromConn(_Out_ ANX_NET_EVENT* Event, _In_ const ANX_CONN_INFO* Conn,
                               _In_ UINT32 Kind, _In_ UINT32 Action, _In_ UINT32 RuleId);
/* CSQ 与 IRP 派发 / CSQ and IRP dispatch */
void     AnxCsqInitialize(void);
void     AnxCsqFlushAll(_In_ NTSTATUS Status);
void     AnxEventDrainToIrps(void);

/* --- pending.c --------------------------------------------------------- */
NTSTATUS AnxPendingInitialize(void);
void     AnxPendingShutdown(void);
/* 返回新分配的 DecisionId；失败返回 0 */
UINT64   AnxPendingAdd(_In_ UINT64 ClassifyHandle, _In_ UINT16 LayerId,
                       _In_ const ANX_CONN_INFO* Conn, _In_ UINT32 TimeoutMs);
NTSTATUS AnxPendingResolve(_In_ UINT64 DecisionId, _In_ UINT32 Action, _In_ UINT32 Flags,
                           _In_ UINT32 CacheTtlMs);
/* VUL-093：撤销已登记但未成功挂起的决策（不调用 FwpsCompleteClassify0） */
void     AnxPendingCancel(_In_ UINT64 DecisionId);
void     AnxPendingAbortAll(_In_ UINT32 Action);

/* --- wfp.c ------------------------------------------------------------- */
NTSTATUS AnxWfpInitialize(_In_ PDEVICE_OBJECT DeviceObject);
void     AnxWfpShutdown(void);

/* --- callouts.c -------------------------------------------------------- */
NTSTATUS AnxCalloutsRegister(_In_ PDEVICE_OBJECT DeviceObject);
void     AnxCalloutsUnregister(void);
NTSTATUS AnxCalloutsAddFilters(void);

/* --- inspect.c --------------------------------------------------------- */
/* 从 DNS 查询报文中提取首个 QNAME；成功返回 TRUE */
BOOLEAN AnxParseDnsQuery(_In_reads_bytes_(Length) const UINT8* Data, _In_ SIZE_T Length,
                         _Out_writes_(DomainChars) PWCHAR Domain, _In_ SIZE_T DomainChars);
/* 从 TLS ClientHello 中提取 SNI */
BOOLEAN AnxParseTlsSni(_In_reads_bytes_(Length) const UINT8* Data, _In_ SIZE_T Length,
                       _Out_writes_(DomainChars) PWCHAR Domain, _In_ SIZE_T DomainChars);
/* 从明文 HTTP 请求头中提取 Host */
BOOLEAN AnxParseHttpHost(_In_reads_bytes_(Length) const UINT8* Data, _In_ SIZE_T Length,
                         _Out_writes_(DomainChars) PWCHAR Domain, _In_ SIZE_T DomainChars);

/* ==========================================================================
 * 内联小工具 / Small inline helpers
 * ========================================================================== */

/*
 * 读取当前配置的快照。配置结构很小，直接在共享自旋锁下整体拷贝，
 * 避免分类路径上出现字段撕裂。
 * Snapshot the current config. The struct is small, so it is copied wholesale
 * under a shared spin lock to avoid field tearing on the classify path.
 */
FORCEINLINE void AnxConfigGet(_Out_ ANX_NET_CONFIG* Out)
{
    KIRQL oldIrql;
    oldIrql = ExAcquireSpinLockShared(&g_Anx.ConfigLock);
    RtlCopyMemory(Out, &g_Anx.Config, sizeof(ANX_NET_CONFIG));
    ExReleaseSpinLockShared(&g_Anx.ConfigLock, oldIrql);
}

FORCEINLINE BOOLEAN AnxIsAttached(void)
{
    return InterlockedCompareExchange(&g_Anx.UserModeAttached, 0, 0) != 0;
}

FORCEINLINE BOOLEAN AnxIsShuttingDown(void)
{
    return InterlockedCompareExchange(&g_Anx.ShuttingDown, 0, 0) != 0;
}

#endif /* ANX_NET_INTERNAL_H */
