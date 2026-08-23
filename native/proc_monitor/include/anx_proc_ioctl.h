/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    anx_proc_ioctl.h

Abstract:
    AnXinProcMon.sys 与用户态之间的二进制契约（IOCTL 码与数据结构）。
    Binary contract (IOCTL codes and data structures) between AnXinProcMon.sys
    and user mode.

    本文件同时被内核驱动（C）与 Rust 用户态客户端镜像引用：
    This file is consumed by the kernel driver (C) and mirrored by the Rust
    user-mode client:
    - 内核侧 / kernel side : native/proc_monitor/src/*.c
    - 用户侧 / user side   : src-tauri/src/utils/proc_driver_client.rs

    ！！修改本文件必须同步更新 Rust 侧镜像常量与结构体，并同步递增
    ANX_PROC_PROTOCOL_VERSION，否则驱动会拒绝旧版用户态连接。
    !! Any change here MUST be mirrored in the Rust side and MUST bump
    ANX_PROC_PROTOCOL_VERSION, otherwise the driver rejects the stale client.

    所有结构体均为固定长度、自然对齐、无指针，可直接用于 METHOD_BUFFERED。
    All structures are fixed-size, naturally aligned, pointer-free, and safe for
    METHOD_BUFFERED transfer.

    设计依据：docs/proc_monitor_design.md（契约 v6）
    Design source: docs/proc_monitor_design.md (contract v6)

Environment:
    Kernel mode and user mode.

--*/

#ifndef ANX_PROC_IOCTL_H
#define ANX_PROC_IOCTL_H

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

#define ANX_PROC_DRIVER_NAME       L"AnXinProcMon"
#define ANX_PROC_DEVICE_NAME       L"\\Device\\AnXinProcMon"
#define ANX_PROC_SYMLINK_NAME      L"\\DosDevices\\AnXinProcMon"

/* 用户态 CreateFileW 打开路径 / User-mode CreateFileW path */
#define ANX_PROC_WIN32_DEVICE_PATH L"\\\\.\\AnXinProcMon"

/* 协议版本。用户态连接后必须先发 IOCTL_ANX_PROC_GET_VERSION 校验；
 * 版本不匹配时用户态必须放弃接管，驱动保持 fail-open（不采集）。
 * Protocol version. User mode must issue IOCTL_ANX_PROC_GET_VERSION first;
 * on mismatch it must not take over and the driver stays permissive. */
#define ANX_PROC_PROTOCOL_VERSION  1

/* 设备 DACL：仅 SYSTEM 与 Administrators 可打开
 * Device DACL: only SYSTEM and Administrators may open the device. */
#define ANX_PROC_DEVICE_SDDL       L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

/*
 * CmRegisterCallbackEx altitude：注册表行为采集。数值高于
 * AnXinProcProtect 自保回调、低于文件保护驱动自保 altitude（防御侧在上层）。
 * Altitude for CmRegisterCallbackEx: registry behavior collection, layered
 * below the self-protection callbacks of the other drivers.
 */
#define ANX_PROC_REG_ALTITUDE      L"320060"

/* ==========================================================================
 * 容量上限 / Capacity limits
 * ========================================================================== */

#define ANX_PROC_MAX_PATH          520   /* WCHAR，含结尾 NUL / WCHARs incl. NUL */
#define ANX_PROC_MAX_PAYLOAD       4096  /* 单事件负载上限（字节） / max payload bytes */
#define ANX_PROC_MAX_CMD_CHARS     2047  /* 命令行最大字符数（UTF-16，含 NUL） */
#define ANX_PROC_MAX_FILTER_RULES  512   /* 过滤规则数上限 */
#define ANX_PROC_MAX_FILTER_NAME   520   /* 单条规则名称最大 WCHAR（含 NUL） */
#define ANX_PROC_MAX_LIFECYCLE_QUEUE 2048 /* 生命周期队列深度（不丢逻辑见 GET_HEALTH） */
#define ANX_PROC_MAX_BEHAVIOR_QUEUE  8192 /* 行为队列深度 */

/* ==========================================================================
 * IOCTL 码 / IOCTL codes
 *
 * CTL_CODE(DeviceType, Function, Method, Access)
 * FILE_DEVICE_UNKNOWN = 0x22, METHOD_BUFFERED = 0,
 * FILE_READ_DATA = 1, FILE_WRITE_DATA = 2
 *
 * 右侧注释给出展开后的十六进制值，Rust 侧常量必须与之逐一对应，
 * 并由 proc_driver_client.rs 的单元测试用同一公式重新计算校验。
 * ========================================================================== */

#define IOCTL_ANX_PROC_GET_VERSION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA00, METHOD_BUFFERED, FILE_READ_DATA)   /* 0x00226800 */
#define IOCTL_ANX_PROC_GET_LIFECYCLE_EVENTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA01, METHOD_BUFFERED, FILE_READ_DATA)   /* 0x00226804 */
#define IOCTL_ANX_PROC_GET_BEHAVIOR_EVENTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA02, METHOD_BUFFERED, FILE_READ_DATA)   /* 0x00226808 */
#define IOCTL_ANX_PROC_SET_FILTER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA03, METHOD_BUFFERED, FILE_WRITE_DATA)  /* 0x0022A80C */
#define IOCTL_ANX_PROC_GET_HEALTH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA04, METHOD_BUFFERED, FILE_READ_DATA)   /* 0x00226810 */
#define IOCTL_ANX_PROC_CLEAR_STATS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA05, METHOD_BUFFERED, FILE_WRITE_DATA)  /* 0x0022A814 */
#define IOCTL_ANX_PROC_SET_DIAG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA06, METHOD_BUFFERED, FILE_WRITE_DATA)  /* 0x0022A818 */

/* ==========================================================================
 * 枚举 / Enumerations
 * ========================================================================== */

/* 事件类型 / Event type */
#define ANX_PROC_EVT_PROC_CREATE     1u  /* 负载：命令行 UTF-16（可为空） */
#define ANX_PROC_EVT_PROC_EXIT       2u  /* 无负载（退出码在 header） */
#define ANX_PROC_EVT_IMAGE_LOAD      3u  /* 负载：DLL 路径 UTF-16 */
#define ANX_PROC_EVT_REMOTE_THREAD   4u  /* 负载：目标线程 ID（UINT32） */
#define ANX_PROC_EVT_FILE_CREATE     5u  /* 负载：文件路径 UTF-16 */
#define ANX_PROC_EVT_FILE_WRITE      6u  /* 负载：文件路径 UTF-16 */
#define ANX_PROC_EVT_FILE_DELETE     7u  /* 负载：文件路径 UTF-16 */
#define ANX_PROC_EVT_FILE_RENAME     8u  /* 负载：文件路径 UTF-16 */
#define ANX_PROC_EVT_REG_SETVALUE    9u  /* 负载：注册表键路径 UTF-16 */
#define ANX_PROC_EVT_REG_CREATEKEY   10u /* 负载：注册表键路径 UTF-16 */
#define ANX_PROC_EVT_REG_DELETE      11u /* 负载：注册表键路径 UTF-16 */
#define ANX_PROC_EVT_REG_RENAME      12u /* 负载：注册表键路径 UTF-16 */
#define ANX_PROC_EVT_NET_CONNECT     13u /* 负载：ANX_PROC_NET_TUPLE */
#define ANX_PROC_EVT_IPC_CONNECT     14u /* 负载：管道名 UTF-16 */
#define ANX_PROC_EVT_DROP_MARKER     15u /* 负载：UINT32 丢弃计数 */

/* 事件标志 / Event flags */
#define ANX_PROC_FLAG_PPID_SPOOFED        0x0001u /* parent_pid != creator_pid（§13.1） */
#define ANX_PROC_FLAG_TOKEN_ELEVATED      0x0002u /* 创建时 Token 已提升（§13.2） */
#define ANX_PROC_FLAG_TOKEN_HIGH_INTEGRITY 0x0004u /* Token 完整性级别高/系统（§13.2） */
#define ANX_PROC_FLAG_PICO                0x0008u /* Pico 进程（WSL1，§14.4，可用时置位） */

/* 队列标识 / Queue identifiers（GET_HEALTH / 事件头无关，供内部与诊断） */
#define ANX_PROC_QUEUE_LIFECYCLE   0u
#define ANX_PROC_QUEUE_BEHAVIOR    1u

/* 过滤规则类型 / Filter rule types */
#define ANX_PROC_RULE_FILE_PATH_PREFIX   1u
#define ANX_PROC_RULE_REG_KEY_PREFIX     2u
#define ANX_PROC_RULE_PROC_PATH_PREFIX   3u
#define ANX_PROC_RULE_IPC_NAME_PREFIX    4u
#define ANX_PROC_RULE_IMAGE_PATH_EXACT   5u  /* 精确完整路径（防 Phantom DLL） */
#define ANX_PROC_RULE_IMAGE_PATH_PREFIX  6u

/* 过滤动作 / Filter actions */
#define ANX_PROC_FILTER_COLLECT   1u   /* 命中：采集 */
#define ANX_PROC_FILTER_DROP      2u   /* 命中：丢弃 */

/* 过滤规则标志 / Filter rule flags */
#define ANX_PROC_FILTER_F_CASE_INSENSITIVE 0x00000001u

/* 驱动能力位 / Driver capabilities */
#define ANX_PROC_CAP_LIFECYCLE     0x00000001u
#define ANX_PROC_CAP_IMAGE         0x00000002u
#define ANX_PROC_CAP_REMOTE_THREAD 0x00000004u
#define ANX_PROC_CAP_FILE          0x00000008u
#define ANX_PROC_CAP_REGISTRY      0x00000010u
#define ANX_PROC_CAP_NETWORK       0x00000020u
#define ANX_PROC_CAP_IPC           0x00000040u
#define ANX_PROC_CAP_PICO          0x00000080u

/* ==========================================================================
 * 通用数据结构 / Common data structures
 * ========================================================================== */

/*
 * 事件头（定长 48 字节）。负载在头之后按 payload_len 字节原样追加，
 * 由用户态按 event_type 解析。结构体先整体清零再填充，杜绝内核内存泄漏。
 * Event header (fixed 48 bytes). The payload follows verbatim for payload_len
 * bytes and is interpreted by user mode per event_type. The struct is zeroed
 * before fill to prevent kernel memory disclosure.
 */
typedef struct _ANX_PROC_EVENT_HDR {
    UINT64 event_time;      /* 100ns FILETIME */
    UINT64 create_time;     /* 创建事件：进程创建时间（PID 复用防伪联合标识） */
    UINT32 pid;
    UINT32 parent_pid;      /* 创建：声称的父进程；退出：0；远程线程：创建者 */
    UINT32 creator_pid;     /* 创建：真实发起者（CreateInfo->CreatingThreadId.UniqueProcess） */
    UINT32 session_id;
    UINT32 exit_status;     /* 退出事件：进程退出码 */
    UINT32 sequence;        /* 每队列单调递增（InterlockedIncrement64） */
    UINT16 event_type;      /* ANX_PROC_EVT_* */
    UINT16 flags;           /* ANX_PROC_FLAG_* */
    UINT16 payload_len;     /* 负载字节数（0 = 无负载） */
} ANX_PROC_EVENT_HDR;

/* 网络连接元组 / Network connection tuple */
typedef struct _ANX_PROC_NET_TUPLE {
    UINT16 Protocol;        /* IPPROTO_TCP/UDP */
    UINT16 AddressFamily;   /* ANX_NET_AF_INET = 4 / ANX_NET_AF_INET6 = 6 */
    UINT16 LocalPort;
    UINT16 RemotePort;
    UINT8  LocalAddress[16];   /* 网络字节序 / network byte order */
    UINT8  RemoteAddress[16];
} ANX_PROC_NET_TUPLE;

/* ==========================================================================
 * IOCTL_ANX_PROC_GET_VERSION
 * ========================================================================== */

typedef struct _ANX_PROC_VERSION {
    UINT32 ProtocolVersion;   /* = ANX_PROC_PROTOCOL_VERSION */
    UINT32 DriverMajor;
    UINT32 DriverMinor;
    UINT32 DriverPatch;
    UINT32 Capabilities;      /* ANX_PROC_CAP_* */
    UINT32 MaxFilterRules;
    UINT32 MaxCommandLineChars;
} ANX_PROC_VERSION;

/* ==========================================================================
 * IOCTL_ANX_PROC_SET_FILTER
 *
 * 过滤表整表原子替换（复用 net_filter rules.c 模式）：
 * 新表建好 → 锁下换指针 → 释放旧表，无中间态。
 * Whole-table atomic replace (net_filter rules.c pattern): build the new table,
 * swap the pointer under a lock, then free the old table. Never a partial state.
 *
 * 匹配语义 / Match semantics:
 * - 快路径先查 DROP 规则（排除表，命中即丢弃返回），再查 COLLECT 规则。
 * - 同类型多条规则按数组顺序匹配，首个命中生效。
 * - 驱动内置防呆：PID 0/4/8 及系统会话内核进程必丢，不可被用户表覆盖。
 * ========================================================================== */

typedef struct _ANX_PROC_FILTER_RULE {
    UINT32 RuleType;       /* ANX_PROC_RULE_* */
    UINT32 Action;         /* ANX_PROC_FILTER_COLLECT / DROP */
    UINT32 Flags;          /* ANX_PROC_FILTER_F_* */
    UINT32 NameLen;        /* name 的 WCHAR 数（不含 NUL），0 = 任意 */
    WCHAR  Name[1];        /* 变长 / variable length */
} ANX_PROC_FILTER_RULE;

typedef struct _ANX_PROC_FILTER_SET {
    UINT32               Version;  /* 用户态自增，仅用于日志 */
    UINT32               Count;
    ANX_PROC_FILTER_RULE Rules[1]; /* 变长 / variable length */
} ANX_PROC_FILTER_SET;

/* ==========================================================================
 * IOCTL_ANX_PROC_GET_HEALTH （回调活性心跳，§13.7）
 * ========================================================================== */

typedef struct _ANX_PROC_HEALTH {
    UINT64 LastCallbackTickMs;    /* 最近一次回调入队时刻（系统单调毫秒） */
    UINT64 EventsLifecycleQueued;
    UINT64 EventsLifecycleDropped;
    UINT64 EventsBehaviorQueued;
    UINT64 EventsBehaviorDropped;
    UINT32 LifecycleDepth;        /* 当前队列深度 */
    UINT32 BehaviorDepth;
    UINT32 Attached;              /* 0/1：是否已接管 */
    UINT32 DiagFlags;             /* 当前诊断开关 */
} ANX_PROC_HEALTH;

/* ==========================================================================
 * IOCTL_ANX_PROC_SET_DIAG
 * ========================================================================== */

#define ANX_PROC_DIAG_NONE          0u
#define ANX_PROC_DIAG_TRACE        0x1u  /* 回调路径详细日志（DBG 构建） */

typedef struct _ANX_PROC_DIAG {
    UINT32 Flags;         /* ANX_PROC_DIAG_* */
} ANX_PROC_DIAG;

#pragma pack(pop)

/* ==========================================================================
 * 编译期断言 —— 结构体大小必须与 Rust 侧镜像一致
 * Compile-time assertions — sizes must match the Rust mirror
 * ========================================================================== */

/*
 * 逐字段偏移（x64，pack(8)）已手工核算，Rust 侧 proc_driver_client.rs 的
 * layout 测试会用相同数值复核。
 *
 * ANX_PROC_EVENT_HDR: 0 event_time, 8 create_time, 16 pid, 20 parent_pid,
 *                     24 creator_pid, 28 session_id, 32 exit_status,
 *                     36 sequence, 40 event_type, 42 flags, 44 payload_len
 *                     => 对齐到 8 = 48
 * ANX_PROC_NET_TUPLE: 0 Protocol, 2 AddressFamily, 4 LocalPort, 6 RemotePort,
 *                     8 LocalAddress(16), 24 RemoteAddress(16)           => 40
 * ANX_PROC_VERSION:   0..28 UINT32 x7                                        => 28
 * ANX_PROC_HEALTH:    0 LastCallbackTickMs, 8..40 UINT64 x5, 40..56 UINT32 x4 => 56
 */
C_ASSERT(sizeof(ANX_PROC_EVENT_HDR) == 48);
C_ASSERT(sizeof(ANX_PROC_NET_TUPLE) == 40);
C_ASSERT(sizeof(ANX_PROC_VERSION)   == 28);
C_ASSERT(sizeof(ANX_PROC_HEALTH)    == 56);
C_ASSERT(FIELD_OFFSET(ANX_PROC_EVENT_HDR, event_type)  == 40);
C_ASSERT(FIELD_OFFSET(ANX_PROC_EVENT_HDR, payload_len) == 44);
C_ASSERT(FIELD_OFFSET(ANX_PROC_NET_TUPLE, LocalAddress) == 8);
C_ASSERT(FIELD_OFFSET(ANX_PROC_NET_TUPLE, RemoteAddress) == 24);

#endif /* ANX_PROC_IOCTL_H */
