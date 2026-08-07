/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    anx_net_ioctl.h

Abstract:
    AnXinNetFilter.sys 与用户态之间的二进制契约（IOCTL 码与数据结构）。
    Binary contract (IOCTL codes and data structures) between AnXinNetFilter.sys
    and user mode.

    本文件同时被内核驱动（C）与 Rust 用户态客户端镜像引用：
    This file is consumed by the kernel driver (C) and mirrored by the Rust
    user-mode client:
    - 内核侧 / kernel side : native/net_filter/src/*.c
    - 用户侧 / user side   : src-tauri/src/utils/net_driver_client.rs

    ！！修改本文件必须同步更新 Rust 侧镜像常量与结构体，并同步递增
    ANX_NET_PROTOCOL_VERSION，否则驱动会拒绝旧版用户态连接。
    !! Any change here MUST be mirrored in the Rust side and MUST bump
    ANX_NET_PROTOCOL_VERSION, otherwise the driver rejects the stale client.

    所有结构体均为固定长度、自然对齐、无指针，可直接用于 METHOD_BUFFERED。
    All structures are fixed-size, naturally aligned, pointer-free, and safe for
    METHOD_BUFFERED transfer.

Environment:
    Kernel mode and user mode.

--*/

#ifndef ANX_NET_IOCTL_H
#define ANX_NET_IOCTL_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#pragma pack(push, 8)

/* ==========================================================================
 * 设备名与协议版本 / Device names and protocol version
 * ========================================================================== */

#define ANX_NET_DRIVER_NAME       L"AnXinNetFilter"
#define ANX_NET_DEVICE_NAME       L"\\Device\\AnXinNetFilter"
#define ANX_NET_SYMLINK_NAME      L"\\DosDevices\\AnXinNetFilter"

/* 用户态 CreateFileW 打开路径 / User-mode CreateFileW path */
#define ANX_NET_WIN32_DEVICE_PATH L"\\\\.\\AnXinNetFilter"

/*
 * 协议版本。用户态连接后必须先发 IOCTL_ANX_NET_GET_VERSION 校验；
 * 版本不匹配时用户态必须放弃接管，驱动保持全放行（fail-open）。
 * Protocol version. User mode must issue IOCTL_ANX_NET_GET_VERSION first;
 * on mismatch it must not take over and the driver stays fully permissive.
 */
#define ANX_NET_PROTOCOL_VERSION  1

/* 设备 DACL：仅 SYSTEM 与 Administrators 可打开
 * Device DACL: only SYSTEM and Administrators may open the device.
 * 注意：进程保护驱动使用的 IoCreateDevice 无显式 DACL，本驱动改用
 * IoCreateDeviceSecure 收紧，避免任意进程下发规则/裁决。
 * Note: the process-protection driver uses IoCreateDevice without an explicit
 * DACL; this driver uses IoCreateDeviceSecure so arbitrary processes cannot
 * push rules or verdicts. */
#define ANX_NET_DEVICE_SDDL       L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

/* ==========================================================================
 * 容量上限 / Capacity limits
 * ========================================================================== */

#define ANX_NET_MAX_PATH          520   /* WCHAR，含结尾 NUL / WCHARs incl. NUL */
#define ANX_NET_MAX_DOMAIN        256   /* WCHAR，含结尾 NUL / WCHARs incl. NUL */
#define ANX_NET_MAX_RULES         512
#define ANX_NET_MAX_DOMAIN_RULES  1024
#define ANX_NET_MAX_LIMITS        64
#define ANX_NET_MAX_PENDING       256   /* 同时挂起等待用户决策的连接数上限 */
#define ANX_NET_MAX_EVENT_QUEUE   512   /* 内核事件环形队列深度 */
#define ANX_NET_MAX_STATS         512   /* 单次 GET_STATS 返回的进程数上限 */

/* ==========================================================================
 * IOCTL 码 / IOCTL codes
 *
 * CTL_CODE(DeviceType, Function, Method, Access)
 *   = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
 * FILE_DEVICE_UNKNOWN = 0x22, METHOD_BUFFERED = 0,
 * FILE_READ_DATA = 1, FILE_WRITE_DATA = 2
 *
 * 右侧注释给出展开后的十六进制值，Rust 侧常量必须与之逐一对应，
 * 并由 net_driver_client.rs 的单元测试用同一公式重新计算校验。
 * The expanded hex value is given in the comment; the Rust constants must match
 * and are re-derived from the same formula by a unit test.
 * ========================================================================== */

#define IOCTL_ANX_NET_GET_VERSION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_DATA)   /* 0x00226400 */
#define IOCTL_ANX_NET_SET_CONFIG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_WRITE_DATA)  /* 0x0022A404 */
#define IOCTL_ANX_NET_SET_RULES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_WRITE_DATA)  /* 0x0022A408 */
#define IOCTL_ANX_NET_GET_EVENT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_READ_DATA)   /* 0x0022640C */
#define IOCTL_ANX_NET_SET_VERDICT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_WRITE_DATA)  /* 0x0022A410 */
#define IOCTL_ANX_NET_GET_STATS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_READ_DATA)   /* 0x00226414 */
#define IOCTL_ANX_NET_SET_DOMAINS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_WRITE_DATA)  /* 0x0022A418 */
#define IOCTL_ANX_NET_SET_LIMITS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x907, METHOD_BUFFERED, FILE_WRITE_DATA)  /* 0x0022A41C */
#define IOCTL_ANX_NET_FLUSH_CACHE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x908, METHOD_BUFFERED, FILE_WRITE_DATA)  /* 0x0022A420 */

/* ==========================================================================
 * 枚举 / Enumerations
 * ========================================================================== */

/* 裁决动作 / Verdict action */
#define ANX_NET_ACTION_ALLOW      0u
#define ANX_NET_ACTION_BLOCK      1u
#define ANX_NET_ACTION_PROMPT     2u   /* 仅规则可用；挂起并询问用户 / rule-only */
#define ANX_NET_ACTION_CONTINUE   3u   /* 仅规则可用；不裁决，交给下一条 / rule-only */

/* 方向 / Direction */
#define ANX_NET_DIR_OUTBOUND      0u
#define ANX_NET_DIR_INBOUND       1u
#define ANX_NET_DIR_ANY           2u

/* 协议 / Protocol（与 IPPROTO_* 一致；0 表示任意 / 0 means any） */
#define ANX_NET_PROTO_ANY         0u
#define ANX_NET_PROTO_TCP         6u
#define ANX_NET_PROTO_UDP         17u

/* 地址族 / Address family */
#define ANX_NET_AF_INET           4u
#define ANX_NET_AF_INET6          6u

/* 运行模式 / Operating mode */
#define ANX_NET_MODE_SILENT       0u   /* 只按规则执行，不弹窗 / rules only */
#define ANX_NET_MODE_PROMPT       1u   /* 未知连接挂起并询问 / pend and ask */
#define ANX_NET_MODE_LEARN        2u   /* 一律放行并上报，用于生成规则 / observe */

/* 事件类型 / Event kind */
#define ANX_NET_EVT_CONNECT_REQUEST 1u /* 需要用户裁决，携带 DecisionId */
#define ANX_NET_EVT_CONNECT_LOG     2u /* 已由规则裁决，仅上报 */
#define ANX_NET_EVT_DNS_QUERY       3u /* DNS 查询（含放行/拦截结果） */
#define ANX_NET_EVT_DOMAIN_BLOCKED  4u /* 域名/SNI/Host 命中黑名单被拦截 */
#define ANX_NET_EVT_FLOW_CLOSED     5u /* 流结束，携带字节统计 */
#define ANX_NET_EVT_RATE_LIMITED    6u /* 触发限速 */

/* 事件标志 / Event flags */
#define ANX_NET_EVTF_LOOPBACK       0x00000001u
#define ANX_NET_EVTF_REAUTHORIZE    0x00000002u
#define ANX_NET_EVTF_TIMED_OUT      0x00000004u /* 决策超时，按默认动作处理 */
#define ANX_NET_EVTF_CACHE_HIT      0x00000008u
#define ANX_NET_EVTF_SELF_EXEMPT    0x00000010u /* 本产品自身流量豁免 */

/* 裁决标志 / Verdict flags */
#define ANX_NET_VF_REMEMBER         0x00000001u /* 写入内核裁决缓存 / cache it */
#define ANX_NET_VF_REMEMBER_PROCESS 0x00000002u /* 对该进程的全部目标生效 */

/* 规则标志 / Rule flags */
#define ANX_NET_RF_ENABLED          0x00000001u
#define ANX_NET_RF_LOG              0x00000002u
#define ANX_NET_RF_MATCH_LOOPBACK   0x00000004u /* 允许命中回环地址 */

/* 域名匹配方式 / Domain match type */
#define ANX_NET_DM_EXACT            0u
#define ANX_NET_DM_SUFFIX           1u  /* 匹配 domain 及其任意子域 */
#define ANX_NET_DM_CONTAINS         2u

/* 域名来源 / Domain source */
#define ANX_NET_DSRC_DNS            0u
#define ANX_NET_DSRC_TLS_SNI        1u
#define ANX_NET_DSRC_HTTP_HOST      2u

/* ==========================================================================
 * 通用数据结构 / Common data structures
 * ========================================================================== */

/*
 * IP 地址。Bytes 采用网络字节序；IPv4 只使用前 4 字节。
 * IP address. Bytes are in network byte order; IPv4 uses the first 4 bytes only.
 */
typedef struct _ANX_NET_ADDR {
    UINT8  Family;        /* ANX_NET_AF_* */
    UINT8  Reserved[3];
    UINT8  Bytes[16];
} ANX_NET_ADDR;

/* ==========================================================================
 * IOCTL_ANX_NET_GET_VERSION
 * ========================================================================== */

typedef struct _ANX_NET_VERSION {
    UINT32 ProtocolVersion;   /* = ANX_NET_PROTOCOL_VERSION */
    UINT32 DriverMajor;
    UINT32 DriverMinor;
    UINT32 DriverPatch;
    UINT32 Capabilities;      /* 见下方 ANX_NET_CAP_* / see ANX_NET_CAP_* below */
    UINT32 MaxRules;
    UINT32 MaxDomainRules;
    UINT32 MaxPending;
} ANX_NET_VERSION;

/* 驱动实际注册成功的能力位 / Capabilities actually registered by the driver */
#define ANX_NET_CAP_ALE_V4        0x00000001u
#define ANX_NET_CAP_ALE_V6        0x00000002u
#define ANX_NET_CAP_FLOW_STATS    0x00000004u
#define ANX_NET_CAP_STREAM        0x00000008u
#define ANX_NET_CAP_DATAGRAM      0x00000010u
#define ANX_NET_CAP_RATE_LIMIT    0x00000020u
#define ANX_NET_CAP_PEND          0x00000040u

/* ==========================================================================
 * IOCTL_ANX_NET_SET_CONFIG
 * ========================================================================== */

typedef struct _ANX_NET_CONFIG {
    UINT32 Enabled;              /* 0 = 全放行旁路 / global bypass */
    UINT32 Mode;                 /* ANX_NET_MODE_* */
    UINT32 DefaultOutbound;      /* ANX_NET_ACTION_ALLOW/BLOCK/PROMPT */
    UINT32 DefaultInbound;       /* ANX_NET_ACTION_ALLOW/BLOCK/PROMPT */
    UINT32 PromptTimeoutMs;      /* 挂起等待用户裁决的超时 / pend timeout */
    UINT32 TimeoutAction;        /* 超时后的动作 / action on timeout */
    UINT32 EnableDns;            /* DNS 解析与域名管控 */
    UINT32 EnableStreamInspect;  /* TLS SNI / HTTP Host 提取 */
    UINT32 EnableRateLimit;      /* 令牌桶限速 */
    UINT32 EnableStats;          /* 流量统计 */
    UINT32 AllowLoopback;        /* 回环地址直接放行，强烈建议为 1 */
    UINT32 SelfPid;              /* 本产品服务进程 PID，自身流量豁免 */
    UINT32 CacheTtlMs;           /* 裁决缓存生存期，0 表示不过期 */
    UINT32 Reserved[3];
} ANX_NET_CONFIG;

/* ==========================================================================
 * IOCTL_ANX_NET_SET_RULES
 *
 * 规则整表原子替换：用户态一次性下发完整规则集，驱动在自旋锁下整体换表，
 * 不存在部分生效的中间态。
 * Whole-table atomic replace: user mode pushes the complete rule set and the
 * driver swaps it under a lock, so there is never a partially-applied state.
 *
 * 匹配顺序 = 数组顺序（用户态负责按优先级排好序），首个命中即终止。
 * Match order == array order (user mode sorts by priority); first hit wins.
 * ========================================================================== */

typedef struct _ANX_NET_RULE {
    UINT32       RuleId;
    UINT32       Action;          /* ANX_NET_ACTION_* */
    UINT32       Direction;       /* ANX_NET_DIR_* */
    UINT32       Protocol;        /* ANX_NET_PROTO_* */
    UINT32       Flags;           /* ANX_NET_RF_* */
    UINT32       RemotePortLow;   /* 0 且 High=0 表示任意端口 / 0,0 = any */
    UINT32       RemotePortHigh;
    UINT32       LocalPortLow;
    UINT32       LocalPortHigh;
    ANX_NET_ADDR RemoteAddr;      /* Family=0 表示任意地址 / 0 = any */
    UINT8        RemotePrefixLen; /* CIDR 前缀长度 / CIDR prefix length */
    UINT8        Reserved[7];
    /*
     * 进程映像 NT 路径的 FNV-1a 64 位哈希（大写规范化后计算）。
     * 0 表示匹配任意进程。
     * FNV-1a 64 hash of the process image NT path (upper-cased first).
     * 0 matches any process.
     */
    UINT64       AppIdHash;
} ANX_NET_RULE;

typedef struct _ANX_NET_RULE_SET {
    UINT32       Version;         /* 用户态自增，仅用于日志 / for logging only */
    UINT32       Count;
    ANX_NET_RULE Rules[1];        /* 变长 / variable length */
} ANX_NET_RULE_SET;

/* ==========================================================================
 * IOCTL_ANX_NET_SET_DOMAINS
 * ========================================================================== */

typedef struct _ANX_NET_DOMAIN_RULE {
    UINT32 RuleId;
    UINT32 Action;                /* ALLOW / BLOCK */
    UINT32 MatchType;             /* ANX_NET_DM_* */
    UINT32 Flags;
    WCHAR  Domain[ANX_NET_MAX_DOMAIN];  /* 小写、NUL 结尾 / lower-case, NUL-term */
} ANX_NET_DOMAIN_RULE;

typedef struct _ANX_NET_DOMAIN_SET {
    UINT32              Version;
    UINT32              Count;
    ANX_NET_DOMAIN_RULE Rules[1];
} ANX_NET_DOMAIN_SET;

/* ==========================================================================
 * IOCTL_ANX_NET_SET_LIMITS
 * ========================================================================== */

typedef struct _ANX_NET_LIMIT {
    UINT64 AppIdHash;        /* 0 表示全局限速 / 0 = global */
    UINT64 BytesPerSecIn;    /* 0 表示不限 / 0 = unlimited */
    UINT64 BytesPerSecOut;
    UINT64 BurstBytes;       /* 令牌桶容量，0 表示取 1 秒配额 */
} ANX_NET_LIMIT;

typedef struct _ANX_NET_LIMIT_SET {
    UINT32        Version;
    UINT32        Count;
    ANX_NET_LIMIT Limits[1];
} ANX_NET_LIMIT_SET;

/* ==========================================================================
 * IOCTL_ANX_NET_GET_EVENT （倒置调用 / inverted call）
 *
 * 用户态预先投递若干个重叠 IOCTL，驱动把它们放进取消安全队列（CSQ）；
 * 有事件时完成其中一个并回填 ANX_NET_EVENT。
 * User mode posts several overlapped IOCTLs which the driver parks in a
 * cancel-safe queue (CSQ); when an event arrives one IRP is completed with an
 * ANX_NET_EVENT payload.
 * ========================================================================== */

typedef struct _ANX_NET_EVENT {
    UINT32       Size;           /* = sizeof(ANX_NET_EVENT) */
    UINT32       Kind;           /* ANX_NET_EVT_* */
    UINT64       DecisionId;     /* 非 0 时必须回 IOCTL_ANX_NET_SET_VERDICT */
    UINT64       TimestampMs;    /* Unix 毫秒 / Unix milliseconds */
    UINT32       ProcessId;
    UINT32       Direction;      /* ANX_NET_DIR_* */
    UINT32       Protocol;       /* ANX_NET_PROTO_* */
    UINT32       LocalPort;
    UINT32       RemotePort;
    UINT32       RuleId;         /* 命中的规则 ID，0 表示未命中 */
    UINT32       Action;         /* 最终动作 / resulting action */
    UINT32       Flags;          /* ANX_NET_EVTF_* */
    UINT32       DomainSource;   /* ANX_NET_DSRC_*，Domain 非空时有效 */
    UINT32       DroppedSinceLast; /* 队列溢出丢弃计数 / drop counter */
    UINT64       BytesIn;        /* FLOW_CLOSED / RATE_LIMITED 有效 */
    UINT64       BytesOut;
    UINT64       AppIdHash;
    ANX_NET_ADDR LocalAddress;
    ANX_NET_ADDR RemoteAddress;
    WCHAR        ImagePath[ANX_NET_MAX_PATH];  /* NT 路径 / NT path */
    WCHAR        Domain[ANX_NET_MAX_DOMAIN];   /* DNS QNAME / SNI / Host */
} ANX_NET_EVENT;

/* ==========================================================================
 * IOCTL_ANX_NET_SET_VERDICT
 * ========================================================================== */

typedef struct _ANX_NET_VERDICT {
    UINT64 DecisionId;
    UINT32 Action;        /* ANX_NET_ACTION_ALLOW / ANX_NET_ACTION_BLOCK */
    UINT32 Flags;         /* ANX_NET_VF_* */
    UINT32 CacheTtlMs;    /* 0 表示沿用全局 CacheTtlMs */
    UINT32 Reserved[3];
} ANX_NET_VERDICT;

/* ==========================================================================
 * IOCTL_ANX_NET_GET_STATS
 * ========================================================================== */

typedef struct _ANX_NET_PROC_STAT {
    UINT32 ProcessId;
    UINT32 ActiveFlows;
    UINT64 AppIdHash;
    UINT64 BytesIn;
    UINT64 BytesOut;
    UINT64 ConnAllowed;
    UINT64 ConnBlocked;
    UINT64 LastActivityMs;
} ANX_NET_PROC_STAT;

typedef struct _ANX_NET_STATS {
    UINT32            Count;             /* 本次返回的条目数 */
    UINT32            TotalProcesses;    /* 驱动内实际持有的条目数 */
    UINT64            EventsQueued;
    UINT64            EventsDropped;
    UINT64            PendingCount;
    UINT64            PendingTimedOut;
    UINT64            CacheHits;
    UINT64            CacheMisses;
    ANX_NET_PROC_STAT Entries[1];        /* 变长 / variable length */
} ANX_NET_STATS;

/* ==========================================================================
 * IOCTL_ANX_NET_FLUSH_CACHE
 * ========================================================================== */

#define ANX_NET_FLUSH_ALL        0u
#define ANX_NET_FLUSH_BY_PID     1u
#define ANX_NET_FLUSH_BY_APPID   2u

typedef struct _ANX_NET_FLUSH {
    UINT32 Scope;        /* ANX_NET_FLUSH_* */
    UINT32 ProcessId;
    UINT64 AppIdHash;
} ANX_NET_FLUSH;

#pragma pack(pop)

/* ==========================================================================
 * 编译期断言 —— 结构体大小必须与 Rust 侧镜像一致
 * Compile-time assertions — sizes must match the Rust mirror
 * ========================================================================== */

/*
 * 逐字段偏移（x64，pack(8)）已手工核算，Rust 侧 net_driver_client.rs 的
 * layout 测试会用相同数值复核。
 * Field offsets (x64, pack(8)) were hand-derived; the Rust layout tests in
 * net_driver_client.rs re-check the same numbers.
 *
 * ANX_NET_RULE : 0 RuleId .. 32 LocalPortHigh, 36 RemoteAddr(20),
 *                56 RemotePrefixLen, 57 Reserved[7], 64 AppIdHash  => 72
 * ANX_NET_EVENT: 0 Size, 8 DecisionId, 16 TimestampMs, 24..60 UINT32 x10,
 *                64 BytesIn, 72 BytesOut, 80 AppIdHash,
 *                88 LocalAddress(20), 108 RemoteAddress(20),
 *                128 ImagePath(1040), 1168 Domain(512)            => 1680
 */
C_ASSERT(sizeof(ANX_NET_ADDR)        == 20);
C_ASSERT(sizeof(ANX_NET_VERSION)     == 32);
C_ASSERT(sizeof(ANX_NET_CONFIG)      == 64);
C_ASSERT(sizeof(ANX_NET_RULE)        == 72);
C_ASSERT(sizeof(ANX_NET_DOMAIN_RULE) == 528);
C_ASSERT(sizeof(ANX_NET_LIMIT)       == 32);
C_ASSERT(sizeof(ANX_NET_VERDICT)     == 32);
C_ASSERT(sizeof(ANX_NET_PROC_STAT)   == 56);
C_ASSERT(sizeof(ANX_NET_EVENT)       == 1680);
C_ASSERT(FIELD_OFFSET(ANX_NET_EVENT, ImagePath) == 128);
C_ASSERT(FIELD_OFFSET(ANX_NET_EVENT, Domain)    == 1168);
C_ASSERT(FIELD_OFFSET(ANX_NET_RULE,  AppIdHash) == 64);

#endif /* ANX_NET_IOCTL_H */
