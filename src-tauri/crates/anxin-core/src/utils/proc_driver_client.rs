// AnXinProcMon.sys 的用户态 IOCTL 客户端
//  User-mode IOCTL client for AnXinProcMon.sys
//
// 本文件是 native/proc_monitor/include/anx_proc_ioctl.h 的 Rust 镜像：
//  This file mirrors native/proc_monitor/include/anx_proc_ioctl.h:
// - IOCTL 码、枚举、容量常量逐一对应（单元测试用 CTL_CODE 公式重新计算校验）
// - 结构体与 C 侧 #pragma pack(8) 布局一致（单元测试断言大小与字段偏移）
// - 修改驱动契约必须同步本文件并递增 ANX_PROC_PROTOCOL_VERSION
//
// 事件读取语义：GET_LIFECYCLE_EVENTS / GET_BEHAVIOR_EVENTS 是 CSQ 预投 IRP，
// 每个挂起的 IOCTL 配对**一个**事件（48 字节头 + 负载），驱动把负载截断到
// 输出缓冲容量。用户态必须「挂起 → 收到一个事件 → 再挂起」循环消费。
// Event-read semantics: GET_*_EVENTS pends an IRP on the driver CSQ; each pended
// IOCTL is paired with exactly ONE event (48-byte header + payload, truncated to
// the output buffer). User mode must loop "pend -> one event -> pend again".
//
// 设计依据：docs/proc_monitor_design.md（契约 v6）
// Design source: docs/proc_monitor_design.md (contract v6)
//
// 中文关键词：内核驱动，IOCTL 客户端，事件泵，协议版本，BYOVD 探针
// English keywords: kernel driver, IOCTL client, event pump, protocol version, BYOVD probe
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::Mutex;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
    OPEN_EXISTING,
};
use windows::Win32::System::IO::{CancelIoEx, DeviceIoControl};

// ============================================================================
// 设备与协议 / Device and protocol
// ============================================================================

/// 用户态 CreateFileW 打开路径 / User-mode CreateFileW path
pub const PROC_DEVICE_PATH: &str = r"\\.\AnXinProcMon";
/// 协议版本，必须与 ANX_PROC_PROTOCOL_VERSION 一致 / Must match ANX_PROC_PROTOCOL_VERSION
pub const PROC_PROTOCOL_VERSION: u32 = 1;

/// 生命周期队列深度（驱动侧，与 ioctl.h 一致）
///  Lifecycle queue depth (driver side, matches ioctl.h)
pub const PROC_MAX_LIFECYCLE_QUEUE: u32 = 2048;
/// 行为队列深度 / Behavior queue depth
pub const PROC_MAX_BEHAVIOR_QUEUE: u32 = 8192;
/// 单事件负载上限（字节） / Max payload bytes per event
pub const PROC_MAX_PAYLOAD: usize = 4096;
/// 命令行最大字符数（UTF-16，含 NUL） / Max command line chars (UTF-16 incl. NUL)
pub const PROC_MAX_CMD_CHARS: u32 = 2047;
/// 过滤规则数上限 / Max filter rules
pub const PROC_MAX_FILTER_RULES: u32 = 512;

// ============================================================================
// IOCTL 码 / IOCTL codes
//
// CTL_CODE(DeviceType=0x22, Function, Method=0 BUFFERED, Access)
//  Access: FILE_READ_DATA=1 / FILE_WRITE_DATA=2
// ============================================================================

const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
const METHOD_BUFFERED: u32 = 0;
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;

/// CTL_CODE 宏的 Rust 实现，与 Windows `winioctl.h` 完全一致。
///  Rust implementation of the CTL_CODE macro, identical to `winioctl.h`.
const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub const IOCTL_PROC_GET_VERSION: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0xA00, METHOD_BUFFERED, FILE_READ_DATA);
pub const IOCTL_PROC_GET_LIFECYCLE_EVENTS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0xA01, METHOD_BUFFERED, FILE_READ_DATA);
pub const IOCTL_PROC_GET_BEHAVIOR_EVENTS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0xA02, METHOD_BUFFERED, FILE_READ_DATA);
pub const IOCTL_PROC_SET_FILTER: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0xA03, METHOD_BUFFERED, FILE_WRITE_DATA);
pub const IOCTL_PROC_GET_HEALTH: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0xA04, METHOD_BUFFERED, FILE_READ_DATA);
pub const IOCTL_PROC_CLEAR_STATS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0xA05, METHOD_BUFFERED, FILE_WRITE_DATA);
pub const IOCTL_PROC_SET_DIAG: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0xA06, METHOD_BUFFERED, FILE_WRITE_DATA);

// ============================================================================
// 枚举 / Enumerations
// ============================================================================

/// 事件类型 / Event type
pub mod evt {
    pub const PROC_CREATE: u16 = 1;
    pub const PROC_EXIT: u16 = 2;
    pub const IMAGE_LOAD: u16 = 3;
    pub const REMOTE_THREAD: u16 = 4;
    pub const FILE_CREATE: u16 = 5;
    pub const FILE_WRITE: u16 = 6;
    pub const FILE_DELETE: u16 = 7;
    pub const FILE_RENAME: u16 = 8;
    pub const REG_SETVALUE: u16 = 9;
    pub const REG_CREATEKEY: u16 = 10;
    pub const REG_DELETE: u16 = 11;
    pub const REG_RENAME: u16 = 12;
    pub const NET_CONNECT: u16 = 13;
    pub const IPC_CONNECT: u16 = 14;
    pub const DROP_MARKER: u16 = 15;
}

/// 事件标志 / Event flags
pub const PROC_FLAG_PPID_SPOOFED: u16 = 0x0001;
pub const PROC_FLAG_TOKEN_ELEVATED: u16 = 0x0002;
pub const PROC_FLAG_TOKEN_HIGH_INTEGRITY: u16 = 0x0004;
pub const PROC_FLAG_PICO: u16 = 0x0008;

/// 队列标识 / Queue identifiers
pub const PROC_QUEUE_LIFECYCLE: u32 = 0;
pub const PROC_QUEUE_BEHAVIOR: u32 = 1;

/// 过滤规则类型 / Filter rule types
pub const PROC_RULE_FILE_PATH_PREFIX: u32 = 1;
pub const PROC_RULE_REG_KEY_PREFIX: u32 = 2;
pub const PROC_RULE_PROC_PATH_PREFIX: u32 = 3;
pub const PROC_RULE_IPC_NAME_PREFIX: u32 = 4;
pub const PROC_RULE_IMAGE_PATH_EXACT: u32 = 5;
pub const PROC_RULE_IMAGE_PATH_PREFIX: u32 = 6;

/// 过滤动作 / Filter actions
pub const PROC_FILTER_COLLECT: u32 = 1;
pub const PROC_FILTER_DROP: u32 = 2;

/// 驱动能力位 / Driver capabilities
pub const PROC_CAP_LIFECYCLE: u32 = 0x00000001;
pub const PROC_CAP_IMAGE: u32 = 0x00000002;
pub const PROC_CAP_REMOTE_THREAD: u32 = 0x00000004;
pub const PROC_CAP_FILE: u32 = 0x00000008;
pub const PROC_CAP_REGISTRY: u32 = 0x00000010;
pub const PROC_CAP_NETWORK: u32 = 0x00000020;
pub const PROC_CAP_IPC: u32 = 0x00000040;
pub const PROC_CAP_PICO: u32 = 0x00000080;

/// 诊断开关 / Diagnostics
pub const PROC_DIAG_NONE: u32 = 0;
pub const PROC_DIAG_TRACE: u32 = 0x1;

// ============================================================================
// 数据结构 / Data structures
// ============================================================================

/// 事件头（定长 48 字节，与 ANX_PROC_EVENT_HDR 逐字段对应）
///  Event header (fixed 48 bytes; field-for-field mirror of ANX_PROC_EVENT_HDR)
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct ProcEventHeader {
    /// 100ns FILETIME
    pub event_time: u64,
    /// 创建事件：进程创建时间（PID 复用防伪联合标识） / creation time (PID-reuse guard)
    pub create_time: u64,
    pub pid: u32,
    /// 创建：声称的父进程；退出：0；远程线程：创建者
    pub parent_pid: u32,
    /// 创建：真实发起者（CreatingThreadId.UniqueProcess）
    pub creator_pid: u32,
    pub session_id: u32,
    /// 退出事件：进程退出码
    pub exit_status: u32,
    /// 每队列单调递增序号
    pub sequence: u32,
    pub event_type: u16,
    pub flags: u16,
    pub payload_len: u16,
}

/// 网络连接元组 / Network connection tuple
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProcNetTuple {
    pub protocol: u16,
    pub address_family: u16,
    pub local_port: u16,
    pub remote_port: u16,
    pub local_address: [u8; 16],
    pub remote_address: [u8; 16],
}

/// 版本信息（IOCTL_PROC_GET_VERSION 输出，28 字节） / Version info
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProcVersion {
    pub protocol_version: u32,
    pub driver_major: u32,
    pub driver_minor: u32,
    pub driver_patch: u32,
    pub capabilities: u32,
    pub max_filter_rules: u32,
    pub max_command_line_chars: u32,
}

/// 回调活性心跳（IOCTL_PROC_GET_HEALTH 输出，56 字节，§13.7）
///  Callback-activity heartbeat (56 bytes; contract §13.7)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProcHealth {
    /// 最近一次回调入队时刻（系统单调毫秒）
    pub last_callback_tick_ms: u64,
    pub events_lifecycle_queued: u64,
    pub events_lifecycle_dropped: u64,
    pub events_behavior_queued: u64,
    pub events_behavior_dropped: u64,
    pub lifecycle_depth: u32,
    pub behavior_depth: u32,
    /// 0/1：是否已接管
    pub attached: u32,
    pub diag_flags: u32,
}

/// 过滤规则（变长，整表原子替换）
///  Filter rule (variable-length; whole-table atomic replace)
#[repr(C)]
#[derive(Clone)]
pub struct ProcFilterRule {
    pub rule_type: u32,
    pub action: u32,
    pub flags: u32,
    pub name_len: u32,
    pub name: Vec<u16>,
}

/// 一条已解析的驱动事件（头 + 负载） / One parsed driver event (header + payload)
#[derive(Debug, Clone)]
pub struct ProcEvent {
    pub header: ProcEventHeader,
    /// 负载字节（按 event_type 解析；DROP_MARKER 时是 UINT32 丢弃计数）
    pub payload: Vec<u8>,
}

// ============================================================================
// 客户端 / Client
// ============================================================================

/// AnXinProcMon 驱动客户端（句柄 + 版本握手）
///  AnXinProcMon driver client (handle + version handshake)
///
/// 线程模型与 net_driver_client 一致：句柄受 Mutex 保护；wait_event 是同步
/// 阻塞调用，必须跑在专用线程上，用 disconnect()（CancelIoEx + 关句柄）唤醒。
/// Threading mirrors net_driver_client: a Mutex-guarded handle; wait_event is a
/// blocking sync call that must run on a dedicated thread and is woken by
/// disconnect() (CancelIoEx + close).
pub struct ProcDriverClient {
    handle: Mutex<Option<HANDLE>>,
}

impl Default for ProcDriverClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ProcDriverClient {
    fn drop(&mut self) {
        self.disconnect();
    }
}

// SAFETY: 内部状态只有一个受 Mutex 保护的 Win32 HANDLE；HANDLE 本身可以跨线程使用。
//  The only state is a Mutex-guarded Win32 HANDLE, which is safe to use across threads.
unsafe impl Send for ProcDriverClient {}
unsafe impl Sync for ProcDriverClient {}

impl ProcDriverClient {
    /// 创建一个尚未连接的客户端 / Creates an unconnected client
    pub const fn new() -> Self {
        Self {
            handle: Mutex::new(None),
        }
    }

    /// 打开设备并完成版本握手。握手成功即表示驱动开始向本客户端入队事件
    /// （fail-open：连接前驱动不采集）。
    ///  Opens the device and performs the version handshake; a successful handshake is what
    ///  makes the driver start queueing events (fail-open: no collection before connect).
    ///
    /// 协议版本不一致时立即断开：版本错配的用户态去读内核结构体会按错误偏移解析。
    ///  A protocol mismatch disconnects immediately — parsing kernel structures at
    ///  wrong offsets is how mismatched clients break.
    pub fn connect(&self) -> std::io::Result<ProcVersion> {
        let path: Vec<u16> = OsStr::new(PROC_DEVICE_PATH)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: 固定内核设备路径，缓冲以 NUL 结尾。
        let handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR(path.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

        {
            let mut guard = self.handle.lock().unwrap();
            *guard = Some(handle);
        }

        match self.get_version() {
            Ok(version) if version.protocol_version == PROC_PROTOCOL_VERSION => Ok(version),
            Ok(version) => {
                self.disconnect();
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "driver protocol version {} does not match expected {}",
                        version.protocol_version, PROC_PROTOCOL_VERSION
                    ),
                ))
            }
            Err(e) => {
                self.disconnect();
                Err(e)
            }
        }
    }

    /// 关闭句柄；驱动在 IRP_MJ_CLEANUP 中解除接管并停止入队。
    ///  Closes the handle; the driver detaches in IRP_MJ_CLEANUP and stops queueing.
    pub fn disconnect(&self) {
        let mut guard = self.handle.lock().unwrap();
        if let Some(handle) = guard.take() {
            // 先取消阻塞中的 GET_EVENTS，避免事件泵线程卡在已关闭的句柄上
            //  Cancel the blocked GET_EVENTS first so pump threads are not left waiting on a closed handle
            // SAFETY: handle 仍有效，CancelIoEx 对无挂起 I/O 的句柄也是安全的。
            unsafe {
                let _ = CancelIoEx(handle, None);
                let _ = CloseHandle(handle);
            }
        }
    }

    /// 查询驱动版本与能力位 / Queries the driver version and capability bits
    pub fn get_version(&self) -> std::io::Result<ProcVersion> {
        let mut version = ProcVersion::default();
        let mut returned = 0u32;
        let handle = self.get_handle()?;

        // SAFETY: 输出缓冲与内核侧 ANX_PROC_VERSION 一致（28 字节）。
        unsafe {
            DeviceIoControl(
                handle,
                IOCTL_PROC_GET_VERSION,
                None,
                0,
                Some(&mut version as *mut _ as *mut _),
                std::mem::size_of::<ProcVersion>() as u32,
                Some(&mut returned),
                None,
            )
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
        }
        if (returned as usize) < std::mem::size_of::<ProcVersion>() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "driver returned a truncated version",
            ));
        }
        Ok(version)
    }

    /// 阻塞等待下一条生命周期事件（PROC_QUEUE_LIFECYCLE）。
    ///  Blocks until the next lifecycle event arrives.
    ///
    /// 同步阻塞，必须跑在专用线程；disconnect() 使挂起 IRP 以取消完成并返回错误。
    ///  Blocking sync call for a dedicated thread; disconnect() completes the
    ///  pended IRP cancelled and returns an error.
    pub fn wait_lifecycle_event(&self) -> std::io::Result<ProcEvent> {
        self.wait_event(IOCTL_PROC_GET_LIFECYCLE_EVENTS)
    }

    /// 阻塞等待下一条行为事件（PROC_QUEUE_BEHAVIOR）。
    ///  Blocks until the next behavior event arrives.
    pub fn wait_behavior_event(&self) -> std::io::Result<ProcEvent> {
        self.wait_event(IOCTL_PROC_GET_BEHAVIOR_EVENTS)
    }

    /// 读取回调活性心跳（§13.7 探针的被动侧数据源） / Reads the callback-activity heartbeat
    pub fn get_health(&self) -> std::io::Result<ProcHealth> {
        let mut health = ProcHealth::default();
        let mut returned = 0u32;
        let handle = self.get_handle()?;

        // SAFETY: 输出缓冲与内核侧 ANX_PROC_HEALTH 一致（56 字节）。
        unsafe {
            DeviceIoControl(
                handle,
                IOCTL_PROC_GET_HEALTH,
                None,
                0,
                Some(&mut health as *mut _ as *mut _),
                std::mem::size_of::<ProcHealth>() as u32,
                Some(&mut returned),
                None,
            )
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
        }
        if (returned as usize) < std::mem::size_of::<ProcHealth>() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "driver returned a truncated health",
            ));
        }
        Ok(health)
    }

    /// 整表替换过滤规则（原子；规则名按 UTF-16 原样打包） / Whole-table filter replace
    pub fn set_filter(&self, version: u32, rules: &[ProcFilterRule]) -> std::io::Result<()> {
        if rules.len() > PROC_MAX_FILTER_RULES as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "rule count {} exceeds driver limit {}",
                    rules.len(),
                    PROC_MAX_FILTER_RULES
                ),
            ));
        }

        // 布局：UINT32 Version + UINT32 Count + 逐条规则（UINT32 x4 + UTF-16 name，无对齐填充）
        //  Layout: UINT32 Version + UINT32 Count + rules (UINT32 x4 + UTF-16 name, no padding)
        let mut bytes: Vec<u8> = Vec::with_capacity(8 + rules.len() * 16);
        bytes.extend_from_slice(&version.to_ne_bytes());
        bytes.extend_from_slice(&(rules.len() as u32).to_ne_bytes());
        for rule in rules {
            if rule.name.len() > u32::MAX as usize {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "rule name too long",
                ));
            }
            bytes.extend_from_slice(&rule.rule_type.to_ne_bytes());
            bytes.extend_from_slice(&rule.action.to_ne_bytes());
            bytes.extend_from_slice(&rule.flags.to_ne_bytes());
            bytes.extend_from_slice(&(rule.name.len() as u32).to_ne_bytes());
            for unit in &rule.name {
                bytes.extend_from_slice(&unit.to_ne_bytes());
            }
        }
        self.ioctl_write(IOCTL_PROC_SET_FILTER, &bytes)
    }

    /// 清零驱动统计（测试与诊断） / Zeroes driver counters (tests & diagnostics)
    pub fn clear_stats(&self) -> std::io::Result<()> {
        self.ioctl_write(IOCTL_PROC_CLEAR_STATS, &[])
    }

    /// 设置诊断开关 / Sets the diagnostics flags
    pub fn set_diag(&self, flags: u32) -> std::io::Result<()> {
        let bytes = flags.to_ne_bytes();
        self.ioctl_write(IOCTL_PROC_SET_DIAG, &bytes)
    }

    // ------------------------------------------------------------------
    // 内部辅助 / Internal helpers
    // ------------------------------------------------------------------

    /// 阻塞等待队列中的下一条事件。缓冲按 48 头 + 最大负载分配，
    /// 驱动对超长负载截断（头完整）。 / Blocks for the next queued event.
    fn wait_event(&self, code: u32) -> std::io::Result<ProcEvent> {
        let mut buffer = vec![0u8; std::mem::size_of::<ProcEventHeader>() + PROC_MAX_PAYLOAD];
        let mut returned = 0u32;
        let handle = self.get_handle()?;

        // SAFETY: 缓冲大小 = 头 + 最大负载，足以容纳驱动拷贝的头与（截断后的）负载。
        unsafe {
            DeviceIoControl(
                handle,
                code,
                None,
                0,
                Some(buffer.as_mut_ptr() as *mut _),
                buffer.len() as u32,
                Some(&mut returned),
                None,
            )
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
        }

        // SAFETY: 驱动保证至少返回 48 字节完整头（缓冲不足时以 STATUS_BUFFER_TOO_SMALL 拒绝）。
        let header_size = std::mem::size_of::<ProcEventHeader>();
        if (returned as usize) < header_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "driver returned a truncated event header",
            ));
        }
        let header_bytes: [u8; 48] = buffer[..header_size]
            .try_into()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "bad header"))?;
        let header: ProcEventHeader = unsafe { std::mem::transmute(header_bytes) };

        let payload_len = (returned as usize).saturating_sub(header_size);
        buffer.truncate(header_size + payload_len);
        let payload = buffer[header_size..].to_vec();

        Ok(ProcEvent { header, payload })
    }

    fn get_handle(&self) -> std::io::Result<HANDLE> {
        self.handle
            .lock()
            .unwrap()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotConnected, "proc driver not connected"))
    }

    fn ioctl_write(&self, code: u32, input: &[u8]) -> std::io::Result<()> {
        let handle = self.get_handle()?;
        let mut returned = 0u32;

        // SAFETY: input 是可读字节切片；无输出缓冲。
        unsafe {
            DeviceIoControl(
                handle,
                code,
                if input.is_empty() {
                    None
                } else {
                    Some(input.as_ptr() as *const _)
                },
                input.len() as u32,
                None,
                0,
                Some(&mut returned),
                None,
            )
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
        }
        Ok(())
    }
}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::offset_of;

    #[test]
    fn ioctl_codes_match_annotated_values() {
        // 与 anx_proc_ioctl.h 的 CTL_CODE 宏展开值逐一对应
        //（注意：ioctl.h 的注释值已修正为宏展开值，勿照抄旧注释）
        assert_eq!(IOCTL_PROC_GET_VERSION, 0x0022_6800);
        assert_eq!(IOCTL_PROC_GET_LIFECYCLE_EVENTS, 0x0022_6804);
        assert_eq!(IOCTL_PROC_GET_BEHAVIOR_EVENTS, 0x0022_6808);
        assert_eq!(IOCTL_PROC_SET_FILTER, 0x0022_A80C);
        assert_eq!(IOCTL_PROC_GET_HEALTH, 0x0022_6810);
        assert_eq!(IOCTL_PROC_CLEAR_STATS, 0x0022_A814);
        assert_eq!(IOCTL_PROC_SET_DIAG, 0x0022_A818);
    }

    #[test]
    fn event_header_layout_matches_c_assert() {
        // C_ASSERT(sizeof(ANX_PROC_EVENT_HDR) == 48) 且 pack(8)
        assert_eq!(std::mem::size_of::<ProcEventHeader>(), 48);
        let base = 0usize;
        assert_eq!(offset_of!(ProcEventHeader, event_time) - base, 0);
        assert_eq!(offset_of!(ProcEventHeader, create_time) - base, 8);
        assert_eq!(offset_of!(ProcEventHeader, pid) - base, 16);
        assert_eq!(offset_of!(ProcEventHeader, parent_pid) - base, 20);
        assert_eq!(offset_of!(ProcEventHeader, creator_pid) - base, 24);
        assert_eq!(offset_of!(ProcEventHeader, session_id) - base, 28);
        assert_eq!(offset_of!(ProcEventHeader, exit_status) - base, 32);
        assert_eq!(offset_of!(ProcEventHeader, sequence) - base, 36);
        assert_eq!(offset_of!(ProcEventHeader, event_type) - base, 40);
        assert_eq!(offset_of!(ProcEventHeader, flags) - base, 42);
        assert_eq!(offset_of!(ProcEventHeader, payload_len) - base, 44);
    }

    #[test]
    fn net_tuple_layout_matches_c_assert() {
        // C_ASSERT(sizeof(ANX_PROC_NET_TUPLE) == 40)；LocalAddress@8、RemoteAddress@24
        assert_eq!(std::mem::size_of::<ProcNetTuple>(), 40);
        assert_eq!(offset_of!(ProcNetTuple, local_address) - 0usize, 8);
        assert_eq!(offset_of!(ProcNetTuple, remote_address) - 0usize, 24);
    }

    #[test]
    fn version_and_health_sizes_match_c_assert() {
        // C_ASSERT: VERSION == 28（7 x UINT32）、HEALTH == 56（5 x UINT64 + 4 x UINT32）
        assert_eq!(std::mem::size_of::<ProcVersion>(), 28);
        assert_eq!(std::mem::size_of::<ProcHealth>(), 56);
    }

    #[test]
    fn set_filter_buffer_layout_matches_c_contract() {
        let rules = vec![ProcFilterRule {
            rule_type: PROC_RULE_PROC_PATH_PREFIX,
            action: PROC_FILTER_DROP,
            flags: PROC_FILTER_F_CASE_INSENSITIVE,
            name_len: 3,
            name: vec![b'c' as u16, b'm' as u16, b'd' as u16],
        }];
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&42u32.to_ne_bytes()); // Version
        bytes.extend_from_slice(&1u32.to_ne_bytes()); // Count
        bytes.extend_from_slice(&PROC_RULE_PROC_PATH_PREFIX.to_ne_bytes());
        bytes.extend_from_slice(&PROC_FILTER_DROP.to_ne_bytes());
        bytes.extend_from_slice(&PROC_FILTER_F_CASE_INSENSITIVE.to_ne_bytes());
        bytes.extend_from_slice(&3u32.to_ne_bytes());
        bytes.extend_from_slice(&0x0063u16.to_ne_bytes());
        bytes.extend_from_slice(&0x006Du16.to_ne_bytes());
        bytes.extend_from_slice(&0x0064u16.to_ne_bytes());
        assert_eq!(bytes.len(), 8 + 16 + 6);

        let version = 42u32;
        let packed = pack_filter_buffer(version, &rules);
        assert_eq!(packed, bytes);
    }
}

/// 把规则表打包成驱动侧 ANX_PROC_FILTER_SET 的内存布局（供测试与 set_filter 复用）。
///  Packs rules into the driver-side ANX_PROC_FILTER_SET memory layout.
fn pack_filter_buffer(version: u32, rules: &[ProcFilterRule]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity(8 + rules.len() * 16);
    bytes.extend_from_slice(&version.to_ne_bytes());
    bytes.extend_from_slice(&(rules.len() as u32).to_ne_bytes());
    for rule in rules {
        bytes.extend_from_slice(&rule.rule_type.to_ne_bytes());
        bytes.extend_from_slice(&rule.action.to_ne_bytes());
        bytes.extend_from_slice(&rule.flags.to_ne_bytes());
        bytes.extend_from_slice(&(rule.name.len() as u32).to_ne_bytes());
        for unit in &rule.name {
            bytes.extend_from_slice(&unit.to_ne_bytes());
        }
    }
    bytes
}

// 与 ioctl.h 的 ANX_PROC_FILTER_F_CASE_INSENSITIVE 一致 / matches ioctl.h
const PROC_FILTER_F_CASE_INSENSITIVE: u32 = 0x00000001;
