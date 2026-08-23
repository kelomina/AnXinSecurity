//! 网络过滤驱动客户端 — AnXinNetFilter.sys 的 IOCTL 互操作层。
//!  Network filter driver client — the IOCTL interop layer for AnXinNetFilter.sys.
//!
//! 本模块是 `native/net_filter/include/anx_net_ioctl.h` 的 Rust 镜像。
//! 两侧的结构体布局、IOCTL 码与哈希算法必须逐字节一致，否则内核会按错误的
//! 偏移解释用户态下发的数据。本文件末尾的单元测试用与 C 侧相同的公式重新
//! 推导 IOCTL 码，并断言每个结构体的大小与字段偏移。
//!  This module mirrors `native/net_filter/include/anx_net_ioctl.h`. Structure
//!  layouts, IOCTL codes and the hash algorithm must agree byte for byte, or the
//!  kernel will interpret user-mode data at the wrong offsets. The unit tests at
//!  the bottom re-derive the IOCTL codes with the same formula as the C side and
//!  assert every structure size and field offset.
//!
//! 中文关键词：驱动客户端，IOCTL，倒置调用，结构体布局
//! English keywords: driver client, IOCTL, inverted call, struct layout

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::sync::Mutex;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
    OPEN_EXISTING,
};
use windows::Win32::System::IO::{CancelIoEx, DeviceIoControl};

// ============================================================================
// 设备路径与协议版本 / Device path and protocol version
// ============================================================================

/// 驱动设备的 Win32 打开路径 / Win32 path used to open the driver device
pub const NET_DEVICE_PATH: &str = r"\\.\AnXinNetFilter";

/// 协议版本，必须与 anx_net_ioctl.h 的 ANX_NET_PROTOCOL_VERSION 一致
///  Protocol version; must match ANX_NET_PROTOCOL_VERSION in anx_net_ioctl.h
pub const NET_PROTOCOL_VERSION: u32 = 1;

// ============================================================================
// IOCTL 码 / IOCTL codes
// ============================================================================

const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
const METHOD_BUFFERED: u32 = 0;
const FILE_READ_DATA: u32 = 1;
const FILE_WRITE_DATA: u32 = 2;

/// CTL_CODE 宏的 Rust 实现，与 Windows `winioctl.h` 完全一致。
///  Rust implementation of the CTL_CODE macro, identical to `winioctl.h`.
///
/// 现有的 `driver_client.rs` 把这些常量写成了手工推算的字面量并且推错了
/// （例如 ADD_PID 写成 0x80000024，实际应为 0x0022A000），这里改为编译期计算，
/// 从根子上排除同类错误。
///  The existing `driver_client.rs` hand-wrote these constants and got them
///  wrong (ADD_PID is written as 0x80000024 but the macro yields 0x0022A000).
///  Computing them at compile time removes that whole class of mistake.
const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub const IOCTL_ANX_NET_GET_VERSION: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_DATA);
pub const IOCTL_ANX_NET_SET_CONFIG: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_WRITE_DATA);
pub const IOCTL_ANX_NET_SET_RULES: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_WRITE_DATA);
pub const IOCTL_ANX_NET_GET_EVENT: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_READ_DATA);
pub const IOCTL_ANX_NET_SET_VERDICT: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_WRITE_DATA);
pub const IOCTL_ANX_NET_GET_STATS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_READ_DATA);
pub const IOCTL_ANX_NET_SET_DOMAINS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x906, METHOD_BUFFERED, FILE_WRITE_DATA);
pub const IOCTL_ANX_NET_SET_LIMITS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x907, METHOD_BUFFERED, FILE_WRITE_DATA);
pub const IOCTL_ANX_NET_FLUSH_CACHE: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x908, METHOD_BUFFERED, FILE_WRITE_DATA);

// ============================================================================
// 容量上限 / Capacity limits（与 C 侧一致 / must match the C side）
// ============================================================================

pub const NET_MAX_PATH: usize = 520;
pub const NET_MAX_DOMAIN: usize = 256;
pub const NET_MAX_RULES: usize = 512;
pub const NET_MAX_DOMAIN_RULES: usize = 1024;
pub const NET_MAX_LIMITS: usize = 64;
pub const NET_MAX_STATS: usize = 512;

// ============================================================================
// 枚举常量 / Enumeration constants
// ============================================================================

pub const ACTION_ALLOW: u32 = 0;
pub const ACTION_BLOCK: u32 = 1;
pub const ACTION_PROMPT: u32 = 2;
pub const ACTION_CONTINUE: u32 = 3;

pub const DIR_OUTBOUND: u32 = 0;
pub const DIR_INBOUND: u32 = 1;
pub const DIR_ANY: u32 = 2;

pub const PROTO_ANY: u32 = 0;
pub const PROTO_TCP: u32 = 6;
pub const PROTO_UDP: u32 = 17;

pub const AF_INET: u8 = 4;
pub const AF_INET6: u8 = 6;

pub const MODE_SILENT: u32 = 0;
pub const MODE_PROMPT: u32 = 1;
pub const MODE_LEARN: u32 = 2;

pub const EVT_CONNECT_REQUEST: u32 = 1;
pub const EVT_CONNECT_LOG: u32 = 2;
pub const EVT_DNS_QUERY: u32 = 3;
pub const EVT_DOMAIN_BLOCKED: u32 = 4;
pub const EVT_FLOW_CLOSED: u32 = 5;
pub const EVT_RATE_LIMITED: u32 = 6;

// 线上契约常量：AnXinNetFilter.sys 在事件上报/能力位/刷新作用域中会生成或消费
// 这些取值（见 anx_net_ioctl.h 与 native/net_filter/src/*.c），当前用户态防火墙
// 客户端尚未消费它们。为保持本文件「Rust 镜像与 C 头逐字节一致」的不变式而保留，
// 禁止删除（删除会使镜像失真，且后续接入 prompt/learn/DNS 过滤时需重新添加）。
//  Live wire-contract constants: AnXinNetFilter.sys produces or consumes these
//  values (see anx_net_ioctl.h and native/net_filter/src/*.c); the user-mode
//  firewall client does not consume them yet. Kept to preserve this file's
//  byte-for-byte mirror invariant with the C header — do not remove.
#[allow(dead_code)]
pub const EVTF_LOOPBACK: u32 = 0x0000_0001;
#[allow(dead_code)]
pub const EVTF_REAUTHORIZE: u32 = 0x0000_0002;
pub const EVTF_TIMED_OUT: u32 = 0x0000_0004;
#[allow(dead_code)]
pub const EVTF_CACHE_HIT: u32 = 0x0000_0008;
#[allow(dead_code)]
pub const EVTF_SELF_EXEMPT: u32 = 0x0000_0010;

pub const VF_REMEMBER: u32 = 0x0000_0001;
pub const VF_REMEMBER_PROCESS: u32 = 0x0000_0002;

pub const RF_ENABLED: u32 = 0x0000_0001;
pub const RF_LOG: u32 = 0x0000_0002;
pub const RF_MATCH_LOOPBACK: u32 = 0x0000_0004;

pub const DM_EXACT: u32 = 0;
pub const DM_SUFFIX: u32 = 1;
pub const DM_CONTAINS: u32 = 2;

// 域名来源/刷新作用域/能力位：驱动侧生成或消费（见上「线上契约常量」说明）。
//  Domain source / flush scope / capability bits: produced or consumed by the
//  driver side (see the "wire-contract constants" note above).
#[allow(dead_code)]
pub const DSRC_DNS: u32 = 0;
#[allow(dead_code)]
pub const DSRC_TLS_SNI: u32 = 1;
#[allow(dead_code)]
pub const DSRC_HTTP_HOST: u32 = 2;

pub const FLUSH_ALL: u32 = 0;
#[allow(dead_code)]
pub const FLUSH_BY_PID: u32 = 1;
#[allow(dead_code)]
pub const FLUSH_BY_APPID: u32 = 2;

#[allow(dead_code)]
pub const CAP_ALE_V4: u32 = 0x0000_0001;
#[allow(dead_code)]
pub const CAP_ALE_V6: u32 = 0x0000_0002;
#[allow(dead_code)]
pub const CAP_FLOW_STATS: u32 = 0x0000_0004;
#[allow(dead_code)]
pub const CAP_STREAM: u32 = 0x0000_0008;
#[allow(dead_code)]
pub const CAP_DATAGRAM: u32 = 0x0000_0010;
#[allow(dead_code)]
pub const CAP_RATE_LIMIT: u32 = 0x0000_0020;
#[allow(dead_code)]
pub const CAP_PEND: u32 = 0x0000_0040;

// ============================================================================
// 结构体镜像 / Structure mirrors
// ============================================================================

/// IP 地址，`bytes` 为网络字节序，IPv4 只用前 4 字节。
///  IP address; `bytes` is network byte order and IPv4 uses the first 4 only.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetAddr {
    pub family: u8,
    pub reserved: [u8; 3],
    pub bytes: [u8; 16],
}

impl NetAddr {
    /// 从点分十进制 IPv4 构造 / Builds from a dotted-quad IPv4 literal
    pub fn from_ipv4(octets: [u8; 4]) -> Self {
        let mut addr = Self {
            family: AF_INET,
            ..Default::default()
        };
        addr.bytes[..4].copy_from_slice(&octets);
        addr
    }

    /// 从 16 字节 IPv6 构造 / Builds from a 16-byte IPv6 address
    pub fn from_ipv6(octets: [u8; 16]) -> Self {
        Self {
            family: AF_INET6,
            reserved: [0; 3],
            bytes: octets,
        }
    }

    /// 渲染为可读文本，供 UI 与日志使用。
    ///  Renders a human-readable form for the UI and logs.
    pub fn to_display_string(&self) -> String {
        match self.family {
            AF_INET => format!(
                "{}.{}.{}.{}",
                self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]
            ),
            AF_INET6 => {
                let groups: Vec<String> = (0..8)
                    .map(|i| {
                        format!(
                            "{:x}",
                            u16::from_be_bytes([self.bytes[i * 2], self.bytes[i * 2 + 1]])
                        )
                    })
                    .collect();
                groups.join(":")
            }
            _ => String::new(),
        }
    }
}

/// 驱动版本与能力 / Driver version and capabilities
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NetVersion {
    pub protocol_version: u32,
    pub driver_major: u32,
    pub driver_minor: u32,
    pub driver_patch: u32,
    pub capabilities: u32,
    pub max_rules: u32,
    pub max_domain_rules: u32,
    pub max_pending: u32,
}

/// 驱动运行配置 / Driver runtime configuration
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NetConfig {
    pub enabled: u32,
    pub mode: u32,
    pub default_outbound: u32,
    pub default_inbound: u32,
    pub prompt_timeout_ms: u32,
    pub timeout_action: u32,
    pub enable_dns: u32,
    pub enable_stream_inspect: u32,
    pub enable_rate_limit: u32,
    pub enable_stats: u32,
    pub allow_loopback: u32,
    pub self_pid: u32,
    pub cache_ttl_ms: u32,
    pub reserved: [u32; 3],
}

impl Default for NetConfig {
    /// 默认是最保守的一档：不启用、全放行、放行回环。
    ///  The most conservative baseline: disabled, permit all, permit loopback.
    fn default() -> Self {
        Self {
            enabled: 0,
            mode: MODE_SILENT,
            default_outbound: ACTION_ALLOW,
            default_inbound: ACTION_ALLOW,
            prompt_timeout_ms: 20_000,
            timeout_action: ACTION_ALLOW,
            enable_dns: 0,
            enable_stream_inspect: 0,
            enable_rate_limit: 0,
            enable_stats: 1,
            allow_loopback: 1,
            self_pid: 0,
            cache_ttl_ms: 0,
            reserved: [0; 3],
        }
    }
}

/// 连接级规则（已编译为定长二进制形式）
///  A connection rule, compiled to its fixed-size binary form
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NetRule {
    pub rule_id: u32,
    pub action: u32,
    pub direction: u32,
    pub protocol: u32,
    pub flags: u32,
    pub remote_port_low: u32,
    pub remote_port_high: u32,
    pub local_port_low: u32,
    pub local_port_high: u32,
    pub remote_addr: NetAddr,
    pub remote_prefix_len: u8,
    pub reserved: [u8; 7],
    pub app_id_hash: u64,
}

/// 域名规则 / Domain rule
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetDomainRule {
    pub rule_id: u32,
    pub action: u32,
    pub match_type: u32,
    pub flags: u32,
    pub domain: [u16; NET_MAX_DOMAIN],
}

impl Default for NetDomainRule {
    fn default() -> Self {
        Self {
            rule_id: 0,
            action: ACTION_BLOCK,
            match_type: DM_SUFFIX,
            flags: 0,
            domain: [0; NET_MAX_DOMAIN],
        }
    }
}

impl NetDomainRule {
    /// 写入域名，自动小写并截断到上限。
    ///  Stores a domain, lower-cased and truncated to the limit.
    pub fn set_domain(&mut self, domain: &str) {
        self.domain = [0; NET_MAX_DOMAIN];
        for (i, unit) in domain
            .to_ascii_lowercase()
            .encode_utf16()
            .take(NET_MAX_DOMAIN - 1)
            .enumerate()
        {
            self.domain[i] = unit;
        }
    }
}

impl std::fmt::Debug for NetDomainRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetDomainRule")
            .field("rule_id", &self.rule_id)
            .field("action", &self.action)
            .field("match_type", &self.match_type)
            .field("domain", &wide_to_string(&self.domain))
            .finish()
    }
}

/// 限速条目 / Rate-limit entry
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NetLimit {
    pub app_id_hash: u64,
    pub bytes_per_sec_in: u64,
    pub bytes_per_sec_out: u64,
    pub burst_bytes: u64,
}

/// 用户裁决 / User verdict
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NetVerdict {
    pub decision_id: u64,
    pub action: u32,
    pub flags: u32,
    pub cache_ttl_ms: u32,
    pub reserved: [u32; 3],
}

/// 内核事件（倒置调用返回的负载）
///  A kernel event — the payload returned by the inverted call
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetEvent {
    pub size: u32,
    pub kind: u32,
    pub decision_id: u64,
    pub timestamp_ms: u64,
    pub process_id: u32,
    pub direction: u32,
    pub protocol: u32,
    pub local_port: u32,
    pub remote_port: u32,
    pub rule_id: u32,
    pub action: u32,
    pub flags: u32,
    pub domain_source: u32,
    pub dropped_since_last: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub app_id_hash: u64,
    pub local_address: NetAddr,
    pub remote_address: NetAddr,
    pub image_path: [u16; NET_MAX_PATH],
    pub domain: [u16; NET_MAX_DOMAIN],
}

impl Default for NetEvent {
    fn default() -> Self {
        // SAFETY: NetEvent 是纯 POD（全部字段都是整数或整数数组），全零是合法值。
        //  NetEvent is plain POD (integers and integer arrays only); all-zero is valid.
        unsafe { std::mem::zeroed() }
    }
}

impl NetEvent {
    /// 映像路径的字符串形式 / The image path as a string
    pub fn image_path_string(&self) -> String {
        wide_to_string(&self.image_path)
    }

    /// 域名的字符串形式 / The domain as a string
    pub fn domain_string(&self) -> String {
        wide_to_string(&self.domain)
    }

    /// 是否需要用户裁决 / Whether a user verdict is required
    pub fn requires_verdict(&self) -> bool {
        self.kind == EVT_CONNECT_REQUEST && self.decision_id != 0
    }
}

impl std::fmt::Debug for NetEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetEvent")
            .field("kind", &self.kind)
            .field("decision_id", &self.decision_id)
            .field("pid", &self.process_id)
            .field("remote", &self.remote_address.to_display_string())
            .field("remote_port", &self.remote_port)
            .field("action", &self.action)
            .field("domain", &self.domain_string())
            .field("image", &self.image_path_string())
            .finish()
    }
}

/// 进程级统计 / Per-process statistics
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NetProcStat {
    pub process_id: u32,
    pub active_flows: u32,
    pub app_id_hash: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub conn_allowed: u64,
    pub conn_blocked: u64,
    pub last_activity_ms: u64,
}

/// GET_STATS 返回缓冲的头部 / Header of the GET_STATS output buffer
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NetStatsHeader {
    count: u32,
    total_processes: u32,
    events_queued: u64,
    events_dropped: u64,
    pending_count: u64,
    pending_timed_out: u64,
    cache_hits: u64,
    cache_misses: u64,
}

/// 统计快照 / A statistics snapshot
#[derive(Clone, Debug, Default)]
pub struct NetStatsSnapshot {
    pub total_processes: u32,
    pub events_queued: u64,
    pub events_dropped: u64,
    pub pending_count: u64,
    pub pending_timed_out: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub processes: Vec<NetProcStat>,
}

/// 缓存清理参数 / Cache flush parameters
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NetFlush {
    scope: u32,
    process_id: u32,
    app_id_hash: u64,
}

// ============================================================================
// AppId 哈希 / AppId hashing
// ============================================================================

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// 函数名称：app_id_hash_from_utf16
/// 函数作用：对 UTF-16 码元序列做与内核 `AnxHashImagePath` 完全一致的 FNV-1a 哈希。
/// Purpose: FNV-1a hash over UTF-16 code units, byte-identical to the kernel's
///          `AnxHashImagePath`.
///
/// 折叠规则只处理 ASCII 'a'-'z'，每个码元按小端两字节喂入。这两点必须与
/// util.c 里的实现保持一致，任何一侧改动都会让全部按进程匹配的规则静默失效。
/// Case folding covers ASCII 'a'-'z' only and each code unit is fed as two
/// little-endian bytes. Both details must match util.c exactly; changing either
/// side silently breaks every per-process rule.
///
/// 中文关键词：FNV-1a，大小写折叠，跨语言一致性
/// English keywords: FNV-1a, case folding, cross-language parity
pub fn app_id_hash_from_utf16(units: &[u16]) -> u64 {
    // 剥掉全部结尾 NUL，与内核侧 AnxHashAppIdBytes 的处理一致
    //  Strip every trailing NUL, matching the kernel's AnxHashAppIdBytes
    let mut end = units.len();
    while end > 0 && units[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return 0;
    }

    let mut hash = FNV_OFFSET_BASIS;
    for &unit in &units[..end] {
        let c = if (0x61..=0x7A).contains(&unit) {
            unit - 0x20 // 'a'..'z' -> 'A'..'Z'
        } else {
            unit
        };
        hash ^= u64::from(c & 0x00FF);
        hash = hash.wrapping_mul(FNV_PRIME);
        hash ^= u64::from((c >> 8) & 0x00FF);
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    if hash == 0 {
        1
    } else {
        hash
    }
}

/// 函数名称：app_id_hash_for_path
/// 函数作用：把 DOS 路径转成 WFP 的 app id（NT 路径）再哈希。
/// Purpose: Converts a DOS path to the WFP app id (an NT path) and hashes it.
///
/// 优先调用 `FwpmGetAppIdFromFileName0`，因为这正是 WFP 在 ALE 层交给驱动的
/// 那份字节序列，用它可以保证两侧哈希严格一致。该函数不可用时退化为手工
/// 拼接 `\device\harddiskvolumeN\...`，这条退路精度较低，仅作兜底。
/// `FwpmGetAppIdFromFileName0` is preferred because it returns exactly the byte
/// sequence WFP hands the driver at the ALE layer, guaranteeing hash parity. If
/// it fails we fall back to composing `\device\harddiskvolumeN\...` by hand,
/// which is less precise and exists only as a last resort.
///
/// 调用方：规则编译
/// Called by: rule compilation
/// 中文关键词：应用标识，NT 路径，哈希一致性
/// English keywords: app id, NT path, hash parity
pub fn app_id_hash_for_path(dos_path: &str) -> u64 {
    if dos_path.is_empty() {
        return 0;
    }

    if let Some(units) = app_id_utf16_from_file_name(dos_path) {
        return app_id_hash_from_utf16(&units);
    }

    // 退路：直接对原始路径做哈希。只有当 WFP 恰好也用同样的表示时才会匹配，
    // 因此调用方应把 FwpmGetAppIdFromFileName0 失败视为规则可能失效的信号。
    //  Fallback: hash the raw path. It only matches if WFP happens to use the
    //  same representation, so callers should treat a failure above as a signal
    //  that the rule may not match.
    let units: Vec<u16> = dos_path.encode_utf16().collect();
    app_id_hash_from_utf16(&units)
}

/// 通过 fwpuclnt.dll 取得 WFP 认可的 app id 字节块。
///  Obtains the WFP-canonical app id blob via fwpuclnt.dll.
fn app_id_utf16_from_file_name(dos_path: &str) -> Option<Vec<u16>> {
    let wide: Vec<u16> = OsStr::new(dos_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut blob: *mut FwpByteBlob = std::ptr::null_mut();

    // SAFETY: `wide` 是以 NUL 结尾的合法 UTF-16 缓冲；成功时 blob 指向由 WFP
    // 分配的内存，必须用 FwpmFreeMemory0 释放。
    //  `wide` is a valid NUL-terminated UTF-16 buffer. On success blob points to
    //  WFP-allocated memory that must be released with FwpmFreeMemory0.
    let status = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut blob) };

    if status != 0 || blob.is_null() {
        return None;
    }

    // SAFETY: blob 非空且由 WFP 填充，size/data 成对有效。
    //  blob is non-null and WFP-populated; size and data are valid together.
    let units = unsafe {
        let size = (*blob).size as usize;
        let data = (*blob).data;
        if data.is_null() || size < 2 {
            None
        } else {
            let count = size / 2;
            let slice = std::slice::from_raw_parts(data as *const u16, count);
            Some(slice.to_vec())
        }
    };

    // SAFETY: 释放 WFP 分配的内存，指针置空由 FwpmFreeMemory0 负责。
    //  Frees the WFP allocation; FwpmFreeMemory0 nulls the pointer itself.
    unsafe {
        let mut p = blob as *mut std::ffi::c_void;
        FwpmFreeMemory0(&mut p);
    }

    units
}

#[repr(C)]
struct FwpByteBlob {
    size: u32,
    data: *mut u8,
}

#[link(name = "fwpuclnt")]
extern "system" {
    fn FwpmGetAppIdFromFileName0(file_name: PCWSTR, app_id: *mut *mut FwpByteBlob) -> u32;
    fn FwpmFreeMemory0(p: *mut *mut std::ffi::c_void);
}

// ============================================================================
// 工具 / Helpers
// ============================================================================

/// 把定长 UTF-16 缓冲按首个 NUL 截断转成 String。
///  Converts a fixed-size UTF-16 buffer to a String, truncating at the first NUL.
fn wide_to_string(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

/// 把定长数组序列化为字节切片，用于 IOCTL 输入缓冲。
///  Serializes a typed slice into bytes for an IOCTL input buffer.
fn build_table_buffer<T: Copy>(version: u32, items: &[T]) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(8 + std::mem::size_of_val(items));
    buffer.extend_from_slice(&version.to_ne_bytes());
    buffer.extend_from_slice(&(items.len() as u32).to_ne_bytes());

    // SAFETY: T 是 Copy 的 #[repr(C)] POD，按其内存表示原样写出，
    // 与内核侧同名结构体逐字节对应。
    //  T is a Copy #[repr(C)] POD written out by its memory representation,
    //  matching the identically-named kernel structure byte for byte.
    let bytes = unsafe {
        std::slice::from_raw_parts(items.as_ptr() as *const u8, std::mem::size_of_val(items))
    };
    buffer.extend_from_slice(bytes);
    buffer
}

// ============================================================================
// 驱动客户端 / Driver client
// ============================================================================

/// AnXinNetFilter.sys 的线程安全客户端。
///  A thread-safe client for AnXinNetFilter.sys.
///
/// 句柄可以被多个线程并发使用：事件泵线程阻塞在 `wait_event` 上的同时，
/// 其他线程仍可下发裁决与规则。因此 `wait_event` 取出句柄后立刻释放锁。
///  The handle may be used concurrently: the pump thread blocks in `wait_event`
///  while other threads still push verdicts and rules, so `wait_event` copies the
///  handle out and releases the lock immediately.
pub struct NetDriverClient {
    handle: Mutex<Option<HANDLE>>,
}

impl NetDriverClient {
    /// 创建一个尚未连接的客户端 / Creates an unconnected client
    pub const fn new() -> Self {
        Self {
            handle: Mutex::new(None),
        }
    }

    /// 函数名称：connect
    /// 函数作用：打开驱动设备并完成版本握手，握手成功即表示驱动开始接管流量。
    /// Purpose: Opens the device and performs the version handshake; a successful
    ///          handshake is what makes the driver start enforcing.
    ///
    /// 协议版本不一致时立即断开：让版本不匹配的用户态去驱动内核结构体，
    /// 后果是按错误偏移解析内存。
    /// A protocol mismatch disconnects immediately — letting a mismatched client
    /// drive kernel structures means parsing memory at the wrong offsets.
    ///
    /// 调用方：FirewallService::start
    /// Called by: FirewallService::start
    /// 中文关键词：设备打开，版本握手，接管
    /// English keywords: device open, version handshake, attach
    pub fn connect(&self) -> io::Result<NetVersion> {
        let path: Vec<u16> = OsStr::new(NET_DEVICE_PATH)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: 使用固定的内核设备路径，路径缓冲以 NUL 结尾。
        //  A fixed kernel device path in a NUL-terminated buffer.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;

        {
            let mut guard = self.handle.lock().unwrap();
            *guard = Some(handle);
        }

        match self.get_version() {
            Ok(version) if version.protocol_version == NET_PROTOCOL_VERSION => Ok(version),
            Ok(version) => {
                self.disconnect();
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "driver protocol version {} does not match expected {}",
                        version.protocol_version, NET_PROTOCOL_VERSION
                    ),
                ))
            }
            Err(e) => {
                self.disconnect();
                Err(e)
            }
        }
    }

    /// 关闭设备句柄，驱动侧会在 IRP_MJ_CLEANUP 中解除接管并恢复全放行。
    ///  Closes the handle; the driver detaches in IRP_MJ_CLEANUP and reverts to
    ///  fully permissive.
    pub fn disconnect(&self) {
        let mut guard = self.handle.lock().unwrap();
        if let Some(handle) = guard.take() {
            // 先取消阻塞中的 GET_EVENT，避免事件泵线程卡在已关闭的句柄上
            //  Cancel the blocked GET_EVENT first so the pump thread is not left
            //  waiting on a closed handle
            // SAFETY: handle 仍然有效，CancelIoEx 对无挂起 I/O 的句柄也是安全的。
            unsafe {
                let _ = CancelIoEx(handle, None);
                let _ = CloseHandle(handle);
            }
        }
    }

    /// 查询驱动版本与已注册的能力位。
    ///  Queries the driver version and the registered capability bits.
    pub fn get_version(&self) -> io::Result<NetVersion> {
        let mut version = NetVersion::default();
        let mut returned = 0u32;
        let handle = self.get_handle()?;

        // SAFETY: 输出缓冲大小与内核侧 ANX_NET_VERSION 一致。
        unsafe {
            DeviceIoControl(
                handle,
                IOCTL_ANX_NET_GET_VERSION,
                None,
                0,
                Some(&mut version as *mut _ as *mut _),
                std::mem::size_of::<NetVersion>() as u32,
                Some(&mut returned),
                None,
            )
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        }

        Ok(version)
    }

    /// 下发运行配置 / Pushes the runtime configuration
    pub fn set_config(&self, config: &NetConfig) -> io::Result<()> {
        // SAFETY: NetConfig 是 #[repr(C)] POD，按内存表示写出。
        let bytes = unsafe {
            std::slice::from_raw_parts(
                config as *const NetConfig as *const u8,
                std::mem::size_of::<NetConfig>(),
            )
        };
        self.ioctl_write(IOCTL_ANX_NET_SET_CONFIG, bytes)
    }

    /// 整表替换连接级规则 / Replaces the whole connection rule table
    pub fn set_rules(&self, version: u32, rules: &[NetRule]) -> io::Result<()> {
        if rules.len() > NET_MAX_RULES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "rule count {} exceeds driver limit {}",
                    rules.len(),
                    NET_MAX_RULES
                ),
            ));
        }
        self.ioctl_write(IOCTL_ANX_NET_SET_RULES, &build_table_buffer(version, rules))
    }

    /// 整表替换域名规则 / Replaces the whole domain rule table
    pub fn set_domains(&self, version: u32, rules: &[NetDomainRule]) -> io::Result<()> {
        if rules.len() > NET_MAX_DOMAIN_RULES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "domain rule count {} exceeds driver limit {}",
                    rules.len(),
                    NET_MAX_DOMAIN_RULES
                ),
            ));
        }
        self.ioctl_write(
            IOCTL_ANX_NET_SET_DOMAINS,
            &build_table_buffer(version, rules),
        )
    }

    /// 整表替换限速表 / Replaces the whole rate-limit table
    pub fn set_limits(&self, version: u32, limits: &[NetLimit]) -> io::Result<()> {
        if limits.len() > NET_MAX_LIMITS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "limit count {} exceeds driver limit {}",
                    limits.len(),
                    NET_MAX_LIMITS
                ),
            ));
        }
        self.ioctl_write(
            IOCTL_ANX_NET_SET_LIMITS,
            &build_table_buffer(version, limits),
        )
    }

    /// 函数名称：set_verdict
    /// 函数作用：把用户的允许/阻止决策回送给驱动，完成那次被挂起的连接分类。
    /// Purpose: Sends the user's allow/block decision back to complete the pended
    ///          classification.
    ///
    /// 驱动返回 `STATUS_NOT_FOUND` 说明该决策已被超时扫描抢先完成，这不是错误，
    /// 调用方应当把它当成「用户点晚了」正常处理。
    /// `STATUS_NOT_FOUND` from the driver means the timeout sweep already
    /// completed it. That is not an error; callers should treat it as "the user
    /// clicked too late".
    ///
    /// 中文关键词：用户裁决，挂起完成，超时竞态
    /// English keywords: user verdict, pend completion, timeout race
    pub fn set_verdict(&self, verdict: &NetVerdict) -> io::Result<()> {
        // SAFETY: NetVerdict 是 #[repr(C)] POD。
        let bytes = unsafe {
            std::slice::from_raw_parts(
                verdict as *const NetVerdict as *const u8,
                std::mem::size_of::<NetVerdict>(),
            )
        };
        self.ioctl_write(IOCTL_ANX_NET_SET_VERDICT, bytes)
    }

    /// 清理内核裁决缓存 / Flushes the kernel verdict cache
    pub fn flush_cache(&self, scope: u32, process_id: u32, app_id_hash: u64) -> io::Result<()> {
        let flush = NetFlush {
            scope,
            process_id,
            app_id_hash,
        };
        // SAFETY: NetFlush 是 #[repr(C)] POD。
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &flush as *const NetFlush as *const u8,
                std::mem::size_of::<NetFlush>(),
            )
        };
        self.ioctl_write(IOCTL_ANX_NET_FLUSH_CACHE, bytes)
    }

    /// 读取进程级流量统计快照 / Reads a per-process traffic snapshot
    pub fn get_stats(&self) -> io::Result<NetStatsSnapshot> {
        let header_size = std::mem::size_of::<NetStatsHeader>();
        let entry_size = std::mem::size_of::<NetProcStat>();
        let mut buffer = vec![0u8; header_size + NET_MAX_STATS * entry_size];
        let mut returned = 0u32;

        let handle = self.get_handle()?;

        // SAFETY: 缓冲按驱动上限分配，足以容纳头部与最多 NET_MAX_STATS 条记录。
        unsafe {
            DeviceIoControl(
                handle,
                IOCTL_ANX_NET_GET_STATS,
                None,
                0,
                Some(buffer.as_mut_ptr() as *mut _),
                buffer.len() as u32,
                Some(&mut returned),
                None,
            )
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        }

        if (returned as usize) < header_size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "driver returned a truncated stats header",
            ));
        }

        // SAFETY: 已确认返回长度覆盖头部，且缓冲对齐满足 NetStatsHeader 的要求
        // （Vec<u8> 的分配至少 8 字节对齐，头部最大成员是 u64）。
        let header = unsafe { *(buffer.as_ptr() as *const NetStatsHeader) };

        let available = (returned as usize - header_size) / entry_size;
        let count = std::cmp::min(header.count as usize, available);

        let mut processes = Vec::with_capacity(count);
        for i in 0..count {
            let offset = header_size + i * entry_size;
            // SAFETY: offset + entry_size 已由 count 的上界保证不越界。
            let stat = unsafe { *(buffer.as_ptr().add(offset) as *const NetProcStat) };
            processes.push(stat);
        }

        Ok(NetStatsSnapshot {
            total_processes: header.total_processes,
            events_queued: header.events_queued,
            events_dropped: header.events_dropped,
            pending_count: header.pending_count,
            pending_timed_out: header.pending_timed_out,
            cache_hits: header.cache_hits,
            cache_misses: header.cache_misses,
            processes,
        })
    }

    /// 函数名称：wait_event
    /// 函数作用：阻塞等待驱动推送的下一条网络事件（倒置调用）。
    /// Purpose: Blocks until the driver pushes the next network event (inverted call).
    ///
    /// 这是一个同步阻塞调用，必须跑在专用线程上。要唤醒它只需调用
    /// `disconnect()`：句柄关闭会让内核以 STATUS_CANCELLED 完成挂起的 IRP。
    /// This is a synchronous blocking call and must run on a dedicated thread.
    /// To wake it, call `disconnect()`: closing the handle makes the kernel
    /// complete the pended IRP with STATUS_CANCELLED.
    ///
    /// 调用方：FirewallService 的事件泵线程
    /// Called by: the FirewallService event-pump thread
    /// 中文关键词：倒置调用，阻塞等待，事件泵
    /// English keywords: inverted call, blocking wait, event pump
    pub fn wait_event(&self) -> io::Result<NetEvent> {
        let mut event = NetEvent::default();
        let mut returned = 0u32;

        // 立刻释放锁，否则事件泵会把其他调用者全部堵死
        //  Release the lock immediately or the pump would starve every other caller
        let handle = self.get_handle()?;

        // SAFETY: 输出缓冲大小与内核侧 ANX_NET_EVENT 一致；该调用会阻塞直到
        // 驱动完成 IRP 或句柄被关闭。
        unsafe {
            DeviceIoControl(
                handle,
                IOCTL_ANX_NET_GET_EVENT,
                None,
                0,
                Some(&mut event as *mut _ as *mut _),
                std::mem::size_of::<NetEvent>() as u32,
                Some(&mut returned),
                None,
            )
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        }

        if (returned as usize) < std::mem::size_of::<NetEvent>() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "driver returned a truncated event",
            ));
        }

        Ok(event)
    }

    // ------------------------------------------------------------------
    // 内部辅助 / Internal helpers
    // ------------------------------------------------------------------

    fn get_handle(&self) -> io::Result<HANDLE> {
        self.handle
            .lock()
            .unwrap()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "net driver not connected"))
    }

    fn ioctl_write(&self, code: u32, input: &[u8]) -> io::Result<()> {
        let handle = self.get_handle()?;
        let mut returned = 0u32;

        // SAFETY: input 是可读的字节切片，长度与指针成对传入；无输出缓冲。
        unsafe {
            DeviceIoControl(
                handle,
                code,
                Some(input.as_ptr() as *const _),
                input.len() as u32,
                None,
                0,
                Some(&mut returned),
                None,
            )
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        }

        Ok(())
    }
}

impl Default for NetDriverClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NetDriverClient {
    fn drop(&mut self) {
        self.disconnect();
    }
}

// SAFETY: 内部状态只有一个受 Mutex 保护的 Win32 HANDLE；HANDLE 本身可以跨线程使用。
//  The only state is a Mutex-guarded Win32 HANDLE, which is safe to use across threads.
unsafe impl Send for NetDriverClient {}
unsafe impl Sync for NetDriverClient {}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// IOCTL 码必须与 anx_net_ioctl.h 中注释给出的展开值一致。
    ///  The IOCTL codes must equal the expanded values documented in anx_net_ioctl.h.
    #[test]
    fn ioctl_codes_match_c_header() {
        assert_eq!(IOCTL_ANX_NET_GET_VERSION, 0x0022_6400);
        assert_eq!(IOCTL_ANX_NET_SET_CONFIG, 0x0022_A404);
        assert_eq!(IOCTL_ANX_NET_SET_RULES, 0x0022_A408);
        assert_eq!(IOCTL_ANX_NET_GET_EVENT, 0x0022_640C);
        assert_eq!(IOCTL_ANX_NET_SET_VERDICT, 0x0022_A410);
        assert_eq!(IOCTL_ANX_NET_GET_STATS, 0x0022_6414);
        assert_eq!(IOCTL_ANX_NET_SET_DOMAINS, 0x0022_A418);
        assert_eq!(IOCTL_ANX_NET_SET_LIMITS, 0x0022_A41C);
        assert_eq!(IOCTL_ANX_NET_FLUSH_CACHE, 0x0022_A420);
    }

    /// 结构体大小必须与 anx_net_ioctl.h 里的 C_ASSERT 逐条对应。
    ///  Structure sizes must match the C_ASSERTs in anx_net_ioctl.h one for one.
    #[test]
    fn struct_sizes_match_c_header() {
        assert_eq!(std::mem::size_of::<NetAddr>(), 20);
        assert_eq!(std::mem::size_of::<NetVersion>(), 32);
        assert_eq!(std::mem::size_of::<NetConfig>(), 64);
        assert_eq!(std::mem::size_of::<NetRule>(), 72);
        assert_eq!(std::mem::size_of::<NetDomainRule>(), 528);
        assert_eq!(std::mem::size_of::<NetLimit>(), 32);
        assert_eq!(std::mem::size_of::<NetVerdict>(), 32);
        assert_eq!(std::mem::size_of::<NetProcStat>(), 56);
        assert_eq!(std::mem::size_of::<NetEvent>(), 1680);
        assert_eq!(std::mem::size_of::<NetFlush>(), 16);
        assert_eq!(std::mem::size_of::<NetStatsHeader>(), 56);
    }

    /// 关键字段偏移必须与 C 侧一致，否则内核会读到错位的数据。
    ///  Key field offsets must match the C side or the kernel reads shifted data.
    #[test]
    fn struct_offsets_match_c_header() {
        let event = NetEvent::default();
        let base = &event as *const NetEvent as usize;
        assert_eq!(&event.image_path as *const _ as usize - base, 128);
        assert_eq!(&event.domain as *const _ as usize - base, 1168);
        assert_eq!(&event.bytes_in as *const _ as usize - base, 64);

        let rule = NetRule::default();
        let rule_base = &rule as *const NetRule as usize;
        assert_eq!(&rule.remote_addr as *const _ as usize - rule_base, 36);
        assert_eq!(&rule.app_id_hash as *const _ as usize - rule_base, 64);
    }

    /// FNV-1a 的实现必须逐步骤复现内核算法，这里用手工展开的期望值锁定。
    ///  The FNV-1a implementation must reproduce the kernel algorithm step by
    ///  step; a hand-expanded expected value pins it down.
    #[test]
    fn app_id_hash_matches_reference_expansion() {
        // 输入 "A"（单个码元 0x0041），按小端两字节喂入：先 0x41 再 0x00
        //  Input "A" (one code unit 0x0041) fed as little-endian bytes: 0x41, 0x00
        let mut expected = FNV_OFFSET_BASIS;
        expected ^= 0x41;
        expected = expected.wrapping_mul(FNV_PRIME);
        expected ^= 0x00;
        expected = expected.wrapping_mul(FNV_PRIME);

        assert_eq!(app_id_hash_from_utf16(&[0x0041]), expected);
    }

    /// 大小写折叠只处理 ASCII，且必须让大小写不同的同一路径得到同一个哈希。
    ///  Case folding is ASCII-only and must map differently-cased paths to the
    ///  same hash.
    #[test]
    fn app_id_hash_is_case_insensitive_for_ascii() {
        let lower: Vec<u16> = "c:\\windows\\system32\\svchost.exe"
            .encode_utf16()
            .collect();
        let upper: Vec<u16> = "C:\\WINDOWS\\SYSTEM32\\SVCHOST.EXE"
            .encode_utf16()
            .collect();
        assert_eq!(
            app_id_hash_from_utf16(&lower),
            app_id_hash_from_utf16(&upper)
        );
    }

    /// 结尾 NUL 必须被剥掉，否则和内核侧算出的哈希会不同。
    ///  Trailing NULs must be stripped or the kernel hash would differ.
    #[test]
    fn app_id_hash_strips_trailing_nuls() {
        let plain: Vec<u16> = "abc".encode_utf16().collect();
        let mut padded = plain.clone();
        padded.extend_from_slice(&[0, 0, 0]);
        assert_eq!(
            app_id_hash_from_utf16(&plain),
            app_id_hash_from_utf16(&padded)
        );
    }

    /// 空输入返回 0，0 在规则里表示「匹配任意进程」。
    ///  Empty input yields 0, which means "match any process" in a rule.
    #[test]
    fn app_id_hash_empty_is_zero() {
        assert_eq!(app_id_hash_from_utf16(&[]), 0);
        assert_eq!(app_id_hash_from_utf16(&[0, 0]), 0);
    }

    /// 表缓冲的头部是 version + count，随后紧跟定长条目数组。
    ///  The table buffer header is version + count followed by the fixed-size items.
    #[test]
    fn table_buffer_layout_has_header_then_items() {
        let rules = vec![NetRule::default(); 3];
        let buffer = build_table_buffer(7, &rules);

        assert_eq!(buffer.len(), 8 + 3 * std::mem::size_of::<NetRule>());
        assert_eq!(u32::from_ne_bytes(buffer[0..4].try_into().unwrap()), 7);
        assert_eq!(u32::from_ne_bytes(buffer[4..8].try_into().unwrap()), 3);
    }

    #[test]
    fn addr_display_renders_ipv4_and_ipv6() {
        assert_eq!(
            NetAddr::from_ipv4([192, 168, 1, 1]).to_display_string(),
            "192.168.1.1"
        );

        let mut v6 = [0u8; 16];
        v6[15] = 1;
        assert_eq!(
            NetAddr::from_ipv6(v6).to_display_string(),
            "0:0:0:0:0:0:0:1"
        );
    }

    #[test]
    fn domain_rule_stores_lowercase_and_truncates() {
        let mut rule = NetDomainRule::default();
        rule.set_domain("EXAMPLE.COM");
        assert_eq!(wide_to_string(&rule.domain), "example.com");

        let long = "a".repeat(NET_MAX_DOMAIN + 50);
        rule.set_domain(&long);
        assert_eq!(wide_to_string(&rule.domain).len(), NET_MAX_DOMAIN - 1);
    }

    /// 驱动的出厂配置必须是「全放行」：未启用、出入站默认放行、超时放行、回环放行。
    /// 这是整个模块最重要的不变量——驱动自己永远不发起拦截，任何一次拦截都必须
    /// 由主程序显式下发规则或回送裁决才会发生。改动这里等于改变产品的失败姿态。
    ///  The driver's out-of-the-box configuration must permit everything: disabled,
    ///  allow inbound and outbound, allow on timeout, allow loopback. This is the
    ///  module's most important invariant — the driver never originates a block on
    ///  its own; every block requires the main program to have pushed a rule or
    ///  returned a verdict. Changing this changes the product's failure posture.
    #[test]
    fn default_driver_config_permits_everything() {
        let config = NetConfig::default();

        assert_eq!(config.enabled, 0, "the driver must ship disabled");
        assert_eq!(config.mode, MODE_SILENT);
        assert_eq!(
            config.default_outbound, ACTION_ALLOW,
            "outbound must default to allow, never block"
        );
        assert_eq!(
            config.default_inbound, ACTION_ALLOW,
            "inbound must default to allow, never block"
        );
        assert_eq!(
            config.timeout_action, ACTION_ALLOW,
            "an unanswered prompt must resolve to allow, never block"
        );
        assert_eq!(
            config.allow_loopback, 1,
            "loopback carries local IPC and must be permitted by default"
        );
    }

    /// 三张规则表为空时，驱动没有任何拦截依据。空表 + 默认配置 = 全放行。
    ///  With all three tables empty the driver has nothing to block on. Empty
    ///  tables plus the default config equals permit-everything.
    #[test]
    fn empty_tables_serialize_to_zero_count() {
        let rules: Vec<NetRule> = Vec::new();
        let buffer = build_table_buffer(1, &rules);

        assert_eq!(buffer.len(), 8, "an empty table is header-only");
        assert_eq!(u32::from_ne_bytes(buffer[4..8].try_into().unwrap()), 0);
    }

    /// 未连接的客户端对任何 IOCTL 操作都必须返回 NotConnected，而不能静默挂起或返回
    /// 假数据。连接状态由上层 `FirewallService::is_driver_connected()` 以 AtomicBool
    /// 维护（start/stop 与 handle 生命周期同步），客户端不再单独暴露原始句柄查询。
    ///  An unconnected client must return NotConnected for every IOCTL operation
    ///  instead of hanging silently or returning fabricated data. Connection state
    ///  is tracked at the service layer via `FirewallService::is_driver_connected()`
    ///  (kept in lockstep with the handle through start/stop), so the client does
    ///  not expose a raw-handle query anymore.
    #[test]
    fn unconnected_client_reports_not_connected() {
        let client = NetDriverClient::new();

        let err = client.get_version().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);

        let err = client.set_config(&NetConfig::default()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }

    /// 超过驱动容量的规则集必须在用户态就被拒绝，不能等内核返回错误。
    ///  Oversized tables must be rejected in user mode rather than by the kernel.
    #[test]
    fn oversized_tables_are_rejected_locally() {
        let client = NetDriverClient::new();

        let rules = vec![NetRule::default(); NET_MAX_RULES + 1];
        let err = client.set_rules(1, &rules).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let limits = vec![NetLimit::default(); NET_MAX_LIMITS + 1];
        let err = client.set_limits(1, &limits).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn event_requires_verdict_only_for_connect_requests() {
        let mut event = NetEvent::default();
        assert!(!event.requires_verdict());

        event.kind = EVT_CONNECT_REQUEST;
        event.decision_id = 0;
        assert!(!event.requires_verdict());

        event.decision_id = 42;
        assert!(event.requires_verdict());
    }
}
