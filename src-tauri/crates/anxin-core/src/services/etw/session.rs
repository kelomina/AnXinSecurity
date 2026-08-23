use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{
    atomic::{AtomicBool, AtomicPtr, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;

use super::parser::{self, ParsedEvent, FILE_GUID, NETWORK_GUID, PROCESS_GUID, REGISTRY_GUID};
use super::rules::{EtwRuleEngine, MatchedEvent, ProviderKind};
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_RECORD, EVENT_TRACE_LOGFILEW, EVENT_TRACE_LOGFILEW_0, EVENT_TRACE_LOGFILEW_1,
};

const EVENT_TRACE_CONTROL_STOP: u32 = 1;
const EVENT_TRACE_REAL_TIME_MODE: u32 = 0x00000100;
const EVENT_TRACE_SYSTEM_LOGGER_MODE: u32 = 0x02000000;
const PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x00000100;
const PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x10000000;
const WNODE_FLAG_TRACED_GUID: u32 = 0x00020000;
const ERROR_SUCCESS: u32 = 0;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_WMI_INSTANCE_NOT_FOUND: u32 = 4201;
const INVALID_PROCESSTRACE_HANDLE: u64 = u64::MAX;
// 内核 ETW 会话标志 — 必须在 EventTraceProperties.enable_flags 中设置，内核提供者才会产生事件

// Kernel ETW session flags — must be set in EventTraceProperties.enable_flags for kernel providers to emit events
const EVENT_TRACE_FLAG_PROCESS: u32 = 0x00000001;
const EVENT_TRACE_FLAG_THREAD: u32 = 0x00000002;
const EVENT_TRACE_FLAG_DISK_FILE_IO: u32 = 0x00000200;
const EVENT_TRACE_FLAG_REGISTRY: u32 = 0x00080000;
const EVENT_TRACE_FLAG_NETWORK_TCPIP: u32 = 0x00010000;

/// 全量 ETW 采集标志（无驱动接管时的默认模式）。
///  Full ETW collection flags (default mode when no collector driver is attached).
pub const ETW_FLAGS_FULL: u32 = EVENT_TRACE_FLAG_PROCESS
    | EVENT_TRACE_FLAG_THREAD
    | EVENT_TRACE_FLAG_DISK_FILE_IO
    | EVENT_TRACE_FLAG_REGISTRY
    | EVENT_TRACE_FLAG_NETWORK_TCPIP;

/// 降噪 ETW 标志（§4.5：AnXinProcMon 驱动接管后关闭重复类别，事件由驱动采集；
/// 保留会话本身以便失联时快速恢复全量）。
///  Reduced ETW flags (§4.5: after AnXinProcMon takes over, shut down the duplicated
///  kernel classes; the session stays so it can be restored quickly on driver loss).
pub const ETW_FLAGS_REDUCED: u32 = 0;

// Microsoft-Windows-Kernel-* provider keyword values verified with:
// logman query providers "Microsoft-Windows-Kernel-Process/File/Registry/Network"
pub(crate) const KERNEL_PROCESS_KEYWORD_PROCESS: u64 = 0x0000000000000010;
pub(crate) const KERNEL_PROCESS_KEYWORD_THREAD: u64 = 0x0000000000000020;
pub(crate) const KERNEL_PROCESS_KEYWORD_IMAGE: u64 = 0x0000000000000040;
pub(crate) const KERNEL_FILE_KEYWORD_FILENAME: u64 = 0x0000000000000010;
pub(crate) const KERNEL_FILE_KEYWORD_CREATE: u64 = 0x0000000000000080;
pub(crate) const KERNEL_FILE_KEYWORD_DELETE_PATH: u64 = 0x0000000000000400;
pub(crate) const KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH: u64 = 0x0000000000000800;
pub(crate) const KERNEL_FILE_KEYWORD_CREATE_NEW_FILE: u64 = 0x0000000000001000;
pub(crate) const KERNEL_REGISTRY_KEYWORD_SET_VALUE: u64 = 0x0000000000000100;
pub(crate) const KERNEL_REGISTRY_KEYWORD_DELETE_VALUE: u64 = 0x0000000000000200;
pub(crate) const KERNEL_REGISTRY_KEYWORD_CREATE_KEY: u64 = 0x0000000000001000;
pub(crate) const KERNEL_REGISTRY_KEYWORD_DELETE_KEY: u64 = 0x0000000000004000;
pub(crate) const KERNEL_NETWORK_KEYWORD_IPV4: u64 = 0x0000000000000010;
pub(crate) const KERNEL_NETWORK_KEYWORD_IPV6: u64 = 0x0000000000000020;

pub(crate) const DEFAULT_PROCESS_ANY_KEYWORD: u64 =
    KERNEL_PROCESS_KEYWORD_PROCESS | KERNEL_PROCESS_KEYWORD_THREAD | KERNEL_PROCESS_KEYWORD_IMAGE;
pub(crate) const DEFAULT_FILE_ANY_KEYWORD: u64 = KERNEL_FILE_KEYWORD_FILENAME
    | KERNEL_FILE_KEYWORD_CREATE
    | KERNEL_FILE_KEYWORD_DELETE_PATH
    | KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH
    | KERNEL_FILE_KEYWORD_CREATE_NEW_FILE;
pub(crate) const DEFAULT_REGISTRY_ANY_KEYWORD: u64 = KERNEL_REGISTRY_KEYWORD_SET_VALUE
    | KERNEL_REGISTRY_KEYWORD_DELETE_VALUE
    | KERNEL_REGISTRY_KEYWORD_CREATE_KEY
    | KERNEL_REGISTRY_KEYWORD_DELETE_KEY;
pub(crate) const DEFAULT_NETWORK_ANY_KEYWORD: u64 =
    KERNEL_NETWORK_KEYWORD_IPV4 | KERNEL_NETWORK_KEYWORD_IPV6;

// AnXin 自己的 ETW 会话 GUID，避免误用 Windows 系统 logger 的控制 GUID。
// AnXin-owned ETW session GUID; avoids reusing the Windows system logger control GUID.
const ANXIN_ETW_SESSION_GUID: [u8; 16] = [
    0xBC, 0xB6, 0x67, 0x1A, 0x6E, 0x43, 0x30, 0x43, 0xBE, 0x4D, 0xC7, 0x47, 0xEF, 0xAE, 0x83, 0xE7,
];

type StartTraceFn =
    unsafe extern "system" fn(*mut u64, *const u16, *mut EventTraceProperties) -> u32;
type ControlTraceFn =
    unsafe extern "system" fn(u64, *const u16, *mut EventTraceProperties, u32) -> u32;

// Global static for the callback context (set before ProcessTrace, cleared after)
static CALLBACK_CTX: AtomicPtr<EtwCallbackContext> = AtomicPtr::new(std::ptr::null_mut());

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
struct WnodeHeader {
    buffer_size: u32,
    provider_id: u32,
    historical_context: u64,
    time_stamp: [u32; 2],
    guid: Guid,
    client_context: u32,
    flags: u32,
}

#[repr(C)]
struct EventTraceProperties {
    wnode: WnodeHeader,
    buffer_size: u32,
    minimum_buffers: u32,
    maximum_buffers: u32,
    maximum_file_size: u32,
    log_file_mode: u32,
    flush_timer: u32,
    enable_flags: u32,
    age_limit: i32,
    number_of_buffers: u32,
    free_buffers: u32,
    events_lost: u32,
    buffers_written: u32,
    log_buffers_lost: u32,
    real_time_buffers_lost: u32,
    logger_thread_id: isize,
    log_file_name_offset: u32,
    logger_name_offset: u32,
}

#[repr(C)]
struct EventRecord {
    event_header: EventHeader,
    // Windows EVENT_RECORD.BufferContext is ETW_BUFFER_CONTEXT: a 4-byte
    // structure ({ u16 processor/alignment/index } + u16 logger id).  This
    // local FFI mirror must stay layout-compatible with the Windows binding;
    // using a larger placeholder shifts UserDataLength/UserData and makes every
    // payload look empty in live ETW callbacks.
    buffer_context: EtwBufferContext,
    extended_data_count: u16,
    user_data_length: u16,
    extended_data: *const u8,
    user_data: *const u8,
    user_context: *const u8,
}

#[repr(C)]
struct EtwBufferContext {
    processor_or_index: u16,
    logger_id: u16,
}

#[repr(C)]
struct EventHeader {
    size: u16,
    header_type: u16,
    flags: u16,
    event_property: u16,
    thread_id: u32,
    process_id: u32,
    time_stamp: i64,
    provider_id: Guid,
    event_descriptor: EventDescriptor,
    _union: [u32; 2],
    activity_id: Guid,
}

#[repr(C)]
struct EventDescriptor {
    id: u16,
    version: u8,
    channel: u8,
    level: u8,
    opcode: u8,
    task: u16,
    keyword: u64,
}

struct EtwCallbackContext {
    event_queue: Arc<Mutex<VecDeque<String>>>,
    rule_engine: Arc<Mutex<EtwRuleEngine>>,
}

/// 函数名称：build_private_trace_properties_buffer
/// 函数作用：构造 StartTraceW / ControlTraceW 共用的 ETW 会话属性缓冲区。
/// Purpose: Builds the ETW session properties buffer shared by StartTraceW / ControlTraceW.
///
/// 关键点：这里创建的是 AnXin 私有系统实时会话，因此使用项目自己的 GUID 和会话名，
/// 同时设置 EVENT_TRACE_SYSTEM_LOGGER_MODE，让 Windows 把系统级 provider 事件送入本会话。
/// 可以把它理解成“开自己的系统收音频道”，后续再通过 EnableTraceEx2 订阅进程、文件、注册表和网络事件。
/// Key point: This creates an AnXin-owned private real-time session with the
/// project session GUID/name and system logger mode instead of taking over the Windows NT Kernel Logger.
/// enable_flags 参数化：全量模式（进程/线程/文件/注册表/网络）与驱动接管后的降噪模式
/// （§4.5：驱动在线时关闭重复类别，避免双通道重复采集）共用同一构建函数。
/// Parameterized enable_flags: full mode (process/thread/file/registry/network) and the
/// reduced mode after the collector driver takes over (§4.5) share this builder.
fn build_private_trace_properties_buffer(wide_name: &[u16], enable_flags: u32) -> Vec<u8> {
    let props_size = std::mem::size_of::<EventTraceProperties>();
    let name_bytes = wide_name.len() * std::mem::size_of::<u16>();
    let buf_size = props_size + name_bytes + 1024;
    let mut buf: Vec<u8> = vec![0u8; buf_size];

    unsafe {
        let props = &mut *(buf.as_mut_ptr() as *mut EventTraceProperties);
        props.wnode.buffer_size = buf_size as u32;
        props.wnode.client_context = 1;
        props.wnode.flags = WNODE_FLAG_TRACED_GUID;
        props.wnode.guid = raw_guid(&ANXIN_ETW_SESSION_GUID);
        props.log_file_mode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        // 必须设置内核追踪标志，否则内核提供者不会产生事件
        // Must set kernel trace flags, otherwise kernel providers will not emit events
        props.enable_flags = enable_flags;
        props.logger_name_offset = props_size as u32;

        let name_dst = buf.as_mut_ptr().add(props.logger_name_offset as usize) as *mut u16;
        std::ptr::copy_nonoverlapping(wide_name.as_ptr(), name_dst, wide_name.len());
    }

    buf
}

/// 函数名称：start_private_trace_session
/// 函数作用：用统一属性启动一次 AnXin 私有 ETW 会话，并把 Windows 返回码原样交给调用方判断。
/// Purpose: Starts one AnXin private ETW session with shared properties and returns the raw Windows status code.
unsafe fn start_private_trace_session(
    start_trace: StartTraceFn,
    wide_name: &[u16],
    handle: &mut u64,
    enable_flags: u32,
) -> u32 {
    let mut buf = build_private_trace_properties_buffer(wide_name, enable_flags);
    let props = buf.as_mut_ptr() as *mut EventTraceProperties;
    start_trace(handle, wide_name.as_ptr(), props)
}

/// 函数名称：stop_existing_trace_session
/// 函数作用：按会话名停止同名 ETW 会话，用于清理异常退出留下的 AnXin 残留会话。
/// Purpose: Stops a same-name ETW session to clean up stale AnXin sessions left by abnormal exits.
unsafe fn stop_existing_trace_session(control_trace: ControlTraceFn, wide_name: &[u16]) -> u32 {
    let mut buf = build_private_trace_properties_buffer(wide_name, 0);
    let props = buf.as_mut_ptr() as *mut EventTraceProperties;
    control_trace(0, wide_name.as_ptr(), props, EVENT_TRACE_CONTROL_STOP)
}

/// 函数名称：current_ts_ms
/// 函数作用：获取当前 Unix 时间戳（毫秒）。
/// Purpose: Gets current Unix timestamp in milliseconds.
fn current_ts_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub struct EtwSession {
    pub session_handle: u64,
    trace_handle: u64,
    session_name: String,
    trace_thread: Option<thread::JoinHandle<()>>,
    stop_flag: Arc<AtomicBool>,
    event_queue: Arc<Mutex<VecDeque<String>>>,
    rule_engine: Arc<Mutex<EtwRuleEngine>>,
    _ctx_box: Option<Box<EtwCallbackContext>>,
}

impl EtwSession {
    /// 函数名称：new
    /// 函数作用：创建 ETW 会话，并初始化从 config/etw_match_rules.json 加载的规则引擎。
    /// Purpose: Creates an ETW session and initializes the rule engine loaded from config/etw_match_rules.json.
    /// 调用方：EtwService::start。
    /// Called by: EtwService::start.
    /// 被调用方：enable_se_system_profile_privilege、StartTraceW、ControlTraceW、EtwRuleEngine::new。
    /// Calls: enable_se_system_profile_privilege, StartTraceW, ControlTraceW, EtwRuleEngine::new.
    /// 参数说明：session_name 为 ETW 会话名；enable_flags 为内核追踪标志
    /// （全量模式由 EtwService 传全部类别位；降噪模式传 0——驱动接管后
    /// 关闭重复类别，§4.5）。
    /// Parameters: session_name is the ETW session name; enable_flags are the
    /// kernel trace flags (full mode from EtwService; reduced mode passes 0
    /// after the collector driver takes over, §4.5).
    /// 返回值说明：成功返回可启动的 ETW 会话；DLL 加载或 StartTraceW 非权限错误失败时返回 String。
    /// Returns: ETW session on success; String when DLL loading or non-permission StartTraceW failures occur.
    /// 错误处理：无管理员权限时保留 session_handle=0 并让上层跳过 provider 启用；同名残留会话会停止后只重试一次；规则配置失败由 EtwRuleEngine::new 明确回退。
    /// Error handling: Keeps session_handle=0 without admin rights so the caller skips provider enabling; stale same-name sessions are stopped and retried once; rule config failures are explicitly handled by EtwRuleEngine::new fallback.
    /// 中文关键词：ETW会话，规则配置加载，私有实时会话，权限回退
    /// English keywords: ETW session, rule config loading, private real-time session, permission fallback
    pub fn new(session_name: &str, enable_flags: u32) -> Result<Self, String> {
        let wide_name: Vec<u16> = session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let sechost = libloading::Library::new("sechost.dll")
                .map_err(|e| format!("Failed to load sechost.dll: {}", e))?;

            let start_trace: StartTraceFn = *sechost
                .get(b"StartTraceW")
                .map_err(|e| format!("Failed to load StartTraceW: {}", e))?;
            let control_trace: ControlTraceFn = *sechost
                .get(b"ControlTraceW")
                .map_err(|e| format!("Failed to load ControlTraceW: {}", e))?;

            // 尝试启用 SE_SYSTEM_PROFILE_NAME 特权。部分内核 provider 需要管理员令牌里启用该特权。
            // Try to enable SE_SYSTEM_PROFILE_NAME privilege. Some kernel providers require it in the administrator token.
            let _ = enable_se_system_profile_privilege();

            // 创建 AnXin 私有实时 ETW Session。不要使用 Windows 系统 logger 的控制 GUID，
            // 否则容易和系统级 session 或上次异常退出残留的 session 冲突。
            // Create an AnXin-owned private real-time ETW session. Do not use the
            // Windows system logger control GUID here, because it can collide with
            // system-level sessions or stale sessions from a previous crash.
            let mut handle: u64 = 0;
            let mut status =
                start_private_trace_session(start_trace, &wide_name, &mut handle, enable_flags);

            if status == ERROR_ALREADY_EXISTS {
                eprintln!(
                    "[EtwSession] Existing ETW session '{}' found; stopping it before retry",
                    session_name
                );
                let stop_status = stop_existing_trace_session(control_trace, &wide_name);
                if stop_status != ERROR_SUCCESS && stop_status != ERROR_WMI_INSTANCE_NOT_FOUND {
                    return Err(format!(
                        "ControlTraceW stop existing session failed: {}",
                        stop_status
                    ));
                }

                thread::sleep(Duration::from_millis(150));
                handle = 0;
                status =
                    start_private_trace_session(start_trace, &wide_name, &mut handle, enable_flags);
            }

            if status == ERROR_ACCESS_DENIED {
                eprintln!("[EtwSession] Access denied (code 5) on StartTraceW. ETW unavailable.");
            }
            if status != ERROR_SUCCESS && status != ERROR_ACCESS_DENIED {
                return Err(format!("StartTraceW failed: {}", status));
            }
            if status == ERROR_SUCCESS && handle == 0 {
                return Err("StartTraceW returned success but session handle was 0".to_string());
            }

            Ok(Self {
                session_handle: handle,
                trace_handle: 0,
                session_name: session_name.to_string(),
                trace_thread: None,
                stop_flag: Arc::new(AtomicBool::new(false)),
                event_queue: Arc::new(Mutex::new(VecDeque::new())),
                rule_engine: Arc::new(Mutex::new(EtwRuleEngine::new())),
                _ctx_box: None,
            })
        }
    }

    pub fn start(
        &mut self,
        process_all: u64,
        process_any: u64,
        file_all: u64,
        file_any: u64,
        registry_all: u64,
        registry_any: u64,
        network_all: u64,
        network_any: u64,
        _network_enabled: i32,
        _filter_private_ips: i32,
        _skip_loopback: i32,
        _user_data_max_bytes: u32,
    ) -> Result<(), String> {
        unsafe {
            let sechost = libloading::Library::new("sechost.dll")
                .map_err(|e| format!("Failed to load sechost.dll: {}", e))?;

            type EnableTraceFn = unsafe extern "system" fn(
                u64,         // TraceHandle
                *const Guid, // ProviderId
                u32,         // ControlCode (0=Disable, 1=Enable)
                u8,          // Level
                u64,         // AnyKeyword
                u64,         // AllKeyword
                u32,         // Timeout
                *const u8,   // EnableParameters
            ) -> u32;
            let enable_trace: EnableTraceFn = *sechost
                .get(b"EnableTraceEx2")
                .map_err(|e| format!("Failed to load EnableTraceEx2: {}", e))?;

            let providers: [(&[u8; 16], u64, u64); 4] = [
                (&PROCESS_GUID, process_any, process_all),
                (&FILE_GUID, file_any, file_all),
                (&REGISTRY_GUID, registry_any, registry_all),
                (&NETWORK_GUID, network_any, network_all),
            ];

            for (guid_bytes, any_kw, _all_kw) in &providers {
                let guid = raw_guid(guid_bytes);
                let status = enable_trace(
                    self.session_handle,
                    &guid,
                    1,                // ControlCode = ENABLE
                    0xFF,             // Level = 0xFF (全部级别)
                    *any_kw,          // AnyKeyword
                    0,                // AllKeyword
                    0,                // Timeout = no wait
                    std::ptr::null(), // EnableParameters = none
                );
                eprintln!(
                    "[EtwSession] EnableTraceEx2: guid={:02X}{:02X}{:02X}{:02X}-..., any_kw=0x{:X}, status={}",
                    guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3],
                    any_kw, status
                );
                if status != 0 {
                    // 内核 ETW 会话通过 enable_flags 已经启用了事件采集，
                    // EnableTraceEx2 对内核提供者 GUID 可能返回错误，不应致命。
                    // For kernel ETW sessions, enable_flags already enables event collection.
                    // EnableTraceEx2 may fail for kernel provider GUIDs; treat as non-fatal.
                    eprintln!(
                        "[EtwSession] EnableTraceEx2 warning: status={}, any_kw=0x{:X} (non-fatal, events still collected via enable_flags)",
                        status, any_kw
                    );
                }
            }

            // Build callback context
            let ctx = Box::new(EtwCallbackContext {
                event_queue: self.event_queue.clone(),
                rule_engine: self.rule_engine.clone(),
            });
            CALLBACK_CTX.store(Box::into_raw(ctx), Ordering::SeqCst);
            eprintln!("[EtwSession] Callback context stored, about to call OpenTraceW");

            // Open the trace with callback
            let mut wide_name: Vec<u16> = self
                .session_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
            logfile.LoggerName = windows::core::PWSTR(wide_name.as_mut_ptr());
            logfile.Anonymous1 = EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
            };
            logfile.Anonymous2 = EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(etw_event_record_callback),
            };

            type OpenTraceFn = unsafe extern "system" fn(*mut EVENT_TRACE_LOGFILEW) -> u64;
            let open_trace: OpenTraceFn = *sechost
                .get(b"OpenTraceW")
                .map_err(|e| format!("Failed to load OpenTraceW: {}", e))?;

            let trace_handle = open_trace(&mut logfile);
            if trace_handle == 0 || trace_handle == INVALID_PROCESSTRACE_HANDLE {
                let ptr = CALLBACK_CTX.swap(std::ptr::null_mut(), Ordering::SeqCst);
                if !ptr.is_null() {
                    drop(Box::from_raw(ptr));
                }
                return Err(format!(
                    "OpenTraceW failed: invalid handle {}",
                    trace_handle
                ));
            }
            self.trace_handle = trace_handle;

            self.stop_flag.store(false, Ordering::Relaxed);

            let trace_handle = trace_handle;

            // ProcessTrace in background thread (blocking call)
            let trace_thread = thread::spawn(move || {
                let sechost = match libloading::Library::new("sechost.dll") {
                    Ok(l) => l,
                    Err(_) => return,
                };
                type ProcessTraceFn =
                    unsafe extern "system" fn(*const u64, u32, *const i64, *const i64) -> u32;
                let process_trace: ProcessTraceFn = match sechost.get(b"ProcessTrace") {
                    Ok(f) => *f,
                    Err(_) => return,
                };

                // ProcessTrace blocks until ControlTraceW stops the trace
                let handles = [trace_handle];
                let start_time: i64 = 0;
                let end_time: i64 = 0;
                let _ = process_trace(handles.as_ptr(), 1, &start_time, &end_time);
            });

            self.trace_thread = Some(trace_thread);
        }

        Ok(())
    }

    /// 函数名称：stop
    /// 函数作用：停止 ETW 会话，并在限定时间内等待 ProcessTrace 后台线程退出。
    /// Purpose: Stops the ETW session and waits for the ProcessTrace background thread to exit within a bounded timeout.
    /// 调用方：EtwService::pause。
    /// Called by: EtwService::pause.
    /// 被调用方：ControlTraceW、wait_for_trace_thread_stop。
    /// Calls: ControlTraceW, wait_for_trace_thread_stop.
    /// 参数说明：timeout_ms 为等待后台线程退出的最长毫秒数。
    /// Parameters: timeout_ms is the maximum milliseconds to wait for the background thread to exit.
    /// 返回值说明：成功停止返回 Ok；ControlTraceW 失败或线程超时未退出返回 String。
    /// Returns: Ok on successful stop; String when ControlTraceW fails or the thread does not exit before timeout.
    /// 错误处理：不再无限 join；停止失败时保留线程句柄，方便后续重试或诊断。
    /// Error handling: Does not join indefinitely; keeps the thread handle on failure for retry or diagnosis.
    /// 中文关键词：停止ETW，ProcessTrace，有限等待，阻塞防护
    /// English keywords: stop ETW, ProcessTrace, bounded wait, blocking guard
    pub fn stop(&mut self, timeout_ms: u32) -> Result<(), String> {
        self.stop_flag.store(true, Ordering::Relaxed);

        if self.session_handle != 0 || self.trace_handle != 0 {
            let stop_status = unsafe {
                let sechost = libloading::Library::new("sechost.dll")
                    .map_err(|e| format!("Failed to load sechost.dll: {}", e))?;

                type ControlTraceFn = unsafe extern "system" fn(
                    u64,
                    *const u16,
                    *mut EventTraceProperties,
                    u32,
                ) -> u32;
                let control_trace: ControlTraceFn = *sechost
                    .get(b"ControlTraceW")
                    .map_err(|e| format!("Failed to load ControlTraceW: {}", e))?;

                let mut buf: Vec<u8> =
                    vec![0u8; std::mem::size_of::<EventTraceProperties>() + 2048];
                let props = &mut *(buf.as_mut_ptr() as *mut EventTraceProperties);
                props.wnode.buffer_size =
                    (std::mem::size_of::<EventTraceProperties>() + 2048) as u32;

                let wide_name: Vec<u16> = self
                    .session_name
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                control_trace(
                    self.session_handle,
                    wide_name.as_ptr(),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                )
            };

            if stop_status != 0 && stop_status != ERROR_WMI_INSTANCE_NOT_FOUND {
                return Err(format!("ControlTraceW stop failed: {}", stop_status));
            }
        }

        if let Some(handle) = self.trace_thread.take() {
            match wait_for_trace_thread_stop(handle, timeout_ms)? {
                Some(handle) => {
                    self.trace_thread = Some(handle);
                    return Err(format!(
                        "ETW trace thread did not stop within {} ms",
                        timeout_ms.max(1)
                    ));
                }
                None => {
                    self.trace_handle = 0;
                }
            }
        }

        // Clean up callback context
        let ptr = CALLBACK_CTX.swap(std::ptr::null_mut(), Ordering::SeqCst);
        if !ptr.is_null() {
            unsafe {
                drop(Box::from_raw(ptr));
            }
        }

        Ok(())
    }

    pub fn poll_events(&self) -> Vec<String> {
        let mut queue = self.event_queue.lock().unwrap_or_else(|e| e.into_inner());
        queue.drain(..).collect()
    }
}

/// 函数名称：wait_for_trace_thread_stop
/// 函数作用：在限定时间内等待 ETW ProcessTrace 线程自然结束，避免 stop 路径无限阻塞。
/// Purpose: Waits for the ETW ProcessTrace thread to finish within a bounded timeout so the stop path cannot block forever.
/// 调用方：EtwSession::stop。
/// Called by: EtwSession::stop.
/// 参数说明：handle 为后台线程句柄；timeout_ms 为最大等待毫秒数。
/// Parameters: handle is the background thread handle; timeout_ms is the maximum wait in milliseconds.
/// 返回值说明：线程结束返回 None；超时返回 Some(handle) 交还调用方保存。
/// Returns: None when the thread finished; Some(handle) on timeout so the caller can keep it.
/// 错误处理：线程 panic 转换为 String；超时不 panic、不无限等待。
/// Error handling: Converts thread panic to String; timeout does not panic or wait indefinitely.
/// 中文关键词：ETW停止，线程等待，超时保护，阻塞防护
/// English keywords: ETW stop, thread wait, timeout guard, blocking guard
fn wait_for_trace_thread_stop(
    handle: thread::JoinHandle<()>,
    timeout_ms: u32,
) -> Result<Option<thread::JoinHandle<()>>, String> {
    let timeout = Duration::from_millis(timeout_ms.max(1) as u64);
    let started_at = Instant::now();

    while started_at.elapsed() < timeout {
        if handle.is_finished() {
            handle
                .join()
                .map_err(|_| "ETW trace thread panicked during stop".to_string())?;
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(25));
    }

    Ok(Some(handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_thread_wait_joins_finished_thread_without_timeout() {
        let handle = thread::spawn(|| {});

        let remaining_handle = wait_for_trace_thread_stop(handle, 250)
            .expect("finished trace thread should join cleanly");

        assert!(
            remaining_handle.is_none(),
            "finished trace thread should not be kept for retry"
        );
    }

    #[test]
    fn etw_callback_panic_guard_catches_panic() {
        let caught = run_etw_callback_with_panic_guard(|| {
            panic!("simulated ETW callback parser panic");
        });

        assert!(
            caught,
            "ETW callback panic guard must catch panics before they cross the FFI boundary"
        );
    }

    #[test]
    fn etw_callback_panic_guard_reports_normal_completion() {
        let caught = run_etw_callback_with_panic_guard(|| {});

        assert!(
            !caught,
            "ETW callback panic guard should return false when the callback body completes"
        );
    }

    #[test]
    fn etw_callback_pid_guard_filters_system_and_invalid_pid() {
        assert!(is_system_or_invalid_pid(0));
        assert!(is_system_or_invalid_pid(4));
        assert!(is_system_or_invalid_pid(u32::MAX));
        assert!(!is_system_or_invalid_pid(47216));
    }

    #[test]
    fn private_trace_properties_use_anxin_guid_and_realtime_mode() {
        let wide_name: Vec<u16> = "AnXinETWSession"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let buf = build_private_trace_properties_buffer(&wide_name, ETW_FLAGS_FULL);

        unsafe {
            let props = &*(buf.as_ptr() as *const EventTraceProperties);
            assert_ne!(
                props.log_file_mode & EVENT_TRACE_REAL_TIME_MODE,
                0,
                "ETW session must be real-time so events can be streamed to the app"
            );
            assert_ne!(
                props.log_file_mode & EVENT_TRACE_SYSTEM_LOGGER_MODE,
                0,
                "SystemTraceProvider sessions must set EVENT_TRACE_SYSTEM_LOGGER_MODE"
            );
            assert_eq!(props.wnode.client_context, 1);
            assert_eq!(props.wnode.flags, WNODE_FLAG_TRACED_GUID);
            assert_eq!(guid_bytes(&props.wnode.guid), ANXIN_ETW_SESSION_GUID);
            // 验证内核追踪标志已设置
            // Verify kernel trace flags are set
            assert_ne!(
                props.enable_flags & EVENT_TRACE_FLAG_PROCESS,
                0,
                "EVENT_TRACE_FLAG_PROCESS must be set"
            );
            assert_ne!(
                props.enable_flags & EVENT_TRACE_FLAG_DISK_FILE_IO,
                0,
                "EVENT_TRACE_FLAG_DISK_FILE_IO must be set"
            );
            assert_ne!(
                props.enable_flags & EVENT_TRACE_FLAG_REGISTRY,
                0,
                "EVENT_TRACE_FLAG_REGISTRY must be set"
            );

            let name_ptr = buf.as_ptr().add(props.logger_name_offset as usize) as *const u16;
            let stored_name = std::slice::from_raw_parts(name_ptr, wide_name.len());
            assert_eq!(stored_name, wide_name.as_slice());
        }
    }

    #[test]
    fn reduced_flags_disable_kernel_classes_for_driver_takeover() {
        // §4.5：驱动接管后降噪模式必须关闭进程/线程/文件/注册表/网络五类内核 flag
        let wide_name: Vec<u16> = "AnXinETWSession"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let buf = build_private_trace_properties_buffer(&wide_name, ETW_FLAGS_REDUCED);
        unsafe {
            let props = &*(buf.as_ptr() as *const EventTraceProperties);
            assert_eq!(props.enable_flags, 0, "reduced mode must clear all kernel flags");
        }
        // 全量 flags 必须覆盖五类
        assert_ne!(ETW_FLAGS_FULL & EVENT_TRACE_FLAG_PROCESS, 0);
        assert_ne!(ETW_FLAGS_FULL & EVENT_TRACE_FLAG_THREAD, 0);
        assert_ne!(ETW_FLAGS_FULL & EVENT_TRACE_FLAG_DISK_FILE_IO, 0);
        assert_ne!(ETW_FLAGS_FULL & EVENT_TRACE_FLAG_REGISTRY, 0);
        assert_ne!(ETW_FLAGS_FULL & EVENT_TRACE_FLAG_NETWORK_TCPIP, 0);
    }

    #[test]
    fn local_event_record_layout_matches_windows_binding() {
        use std::mem::{align_of, size_of};
        use windows::Win32::System::Diagnostics::Etw::{
            ETW_BUFFER_CONTEXT, EVENT_HEADER, EVENT_RECORD,
        };

        assert_eq!(
            size_of::<EtwBufferContext>(),
            size_of::<ETW_BUFFER_CONTEXT>(),
            "ETW_BUFFER_CONTEXT is 4 bytes; a larger local mirror shifts UserDataLength"
        );
        assert_eq!(
            align_of::<EtwBufferContext>(),
            align_of::<ETW_BUFFER_CONTEXT>()
        );
        assert_eq!(size_of::<EventHeader>(), size_of::<EVENT_HEADER>());
        assert_eq!(align_of::<EventHeader>(), align_of::<EVENT_HEADER>());
        assert_eq!(size_of::<EventRecord>(), size_of::<EVENT_RECORD>());
        assert_eq!(align_of::<EventRecord>(), align_of::<EVENT_RECORD>());
    }

    #[test]
    fn default_provider_keywords_match_kernel_provider_categories() {
        for required in [
            KERNEL_PROCESS_KEYWORD_PROCESS,
            KERNEL_PROCESS_KEYWORD_THREAD,
            KERNEL_PROCESS_KEYWORD_IMAGE,
        ] {
            assert_ne!(
                DEFAULT_PROCESS_ANY_KEYWORD & required,
                0,
                "process provider default keywords must include 0x{required:X}"
            );
        }

        for required in [
            KERNEL_FILE_KEYWORD_FILENAME,
            KERNEL_FILE_KEYWORD_CREATE,
            KERNEL_FILE_KEYWORD_DELETE_PATH,
            KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH,
            KERNEL_FILE_KEYWORD_CREATE_NEW_FILE,
        ] {
            assert_ne!(
                DEFAULT_FILE_ANY_KEYWORD & required,
                0,
                "file provider default keywords must include 0x{required:X}"
            );
        }

        for required in [
            KERNEL_REGISTRY_KEYWORD_SET_VALUE,
            KERNEL_REGISTRY_KEYWORD_DELETE_VALUE,
            KERNEL_REGISTRY_KEYWORD_CREATE_KEY,
            KERNEL_REGISTRY_KEYWORD_DELETE_KEY,
        ] {
            assert_ne!(
                DEFAULT_REGISTRY_ANY_KEYWORD & required,
                0,
                "registry provider default keywords must include 0x{required:X}"
            );
        }

        assert_ne!(
            DEFAULT_NETWORK_ANY_KEYWORD & KERNEL_NETWORK_KEYWORD_IPV4,
            0,
            "network provider must subscribe to IPv4 events"
        );
        assert_ne!(
            DEFAULT_NETWORK_ANY_KEYWORD & KERNEL_NETWORK_KEYWORD_IPV6,
            0,
            "network provider must subscribe to IPv6 events"
        );
    }

    #[test]
    fn unknown_provider_json_preserves_pid_for_downstream_filtering() {
        let ev = ParsedEvent {
            ts_ms: 123456,
            pid: 47216,
            tid: 77,
            ppid: 0,
            provider: ProviderKind::Unknown,
            opcode: 9,
            id: 42,
            op: "unknown".to_string(),
            target: String::new(),
            target2: String::new(),
            image_base: None,
            image_size: None,
            start_address: None,
            raw_user_data_len: 0,
            raw_user_data_preview: String::new(),
        };

        let json_line = parsed_event_to_json(&ev, 123456);
        let value: serde_json::Value =
            serde_json::from_str(&json_line).expect("unknown provider JSON should parse");

        assert_eq!(value["event"]["pid"], 47216);
        assert_eq!(value["event"]["tid"], 77);
        assert_eq!(value["event"]["provider"], "Unknown");
    }
}

/// ETW 事件记录回调 — 由 ProcessTrace 线程调用，解析事件并推入队列并运行规则引擎。
/// ETW event record callback — called by ProcessTrace thread, parses events, pushes to queue, runs rule engine.
/// 中文关键词：ETW回调，事件记录，ProcessTrace，规则匹配
/// English keywords: ETW callback, event record, ProcessTrace, rule matching
unsafe extern "system" fn etw_event_record_callback(rec: *mut EVENT_RECORD) {
    if run_etw_callback_with_panic_guard(|| {
        etw_event_record_callback_inner(rec);
    }) {
        eprintln!("[EtwSession] ETW callback panic was caught; dropped one event");
    }
}

/// 函数名称：run_etw_callback_with_panic_guard
/// 函数作用：执行 ETW 回调主体并捕获 panic，避免 Rust panic 穿过 Windows FFI 回调边界。
/// Purpose: Runs the ETW callback body and catches panics so Rust panics cannot cross the Windows FFI callback boundary.
/// 调用方：etw_event_record_callback，ETW session 单元测试。
/// Called by: etw_event_record_callback and ETW session unit tests.
/// 返回值说明：返回 true 表示捕获到 panic 并丢弃该事件；false 表示正常完成。
/// Returns: true when a panic was caught and the event was dropped; false on normal completion.
/// 中文关键词：ETW回调，panic隔离，FFI边界
/// English keywords: ETW callback, panic isolation, FFI boundary
fn run_etw_callback_with_panic_guard(callback_body: impl FnOnce()) -> bool {
    catch_unwind(AssertUnwindSafe(callback_body)).is_err()
}

/// 函数名称：is_system_or_invalid_pid
/// 函数作用：识别不应进入 ETW 队列的系统或无效 PID。
/// Purpose: Identifies system or invalid PIDs that should not enter the ETW queue.
/// 中文关键词：ETW过滤，PID过滤，无效PID，性能保护
/// English keywords: ETW filter, PID filter, invalid PID, performance guard
fn is_system_or_invalid_pid(pid: u32) -> bool {
    matches!(pid, 0 | 4) || pid == u32::MAX
}

/// 函数名称：etw_event_record_callback_inner
/// 函数作用：处理单条 ETW EVENT_RECORD；只能由外层 catch_unwind 包裹的 FFI 回调调用。
/// Purpose: Handles one ETW EVENT_RECORD; called only by the outer FFI callback wrapped with catch_unwind.
/// 调用方：etw_event_record_callback。
/// Called by: etw_event_record_callback.
/// 错误处理：内部尽量跳过异常字段；外层回调兜底捕获 panic，避免 panic 穿过 Windows 回调边界导致进程 abort。
/// Error handling: Skips invalid fields where possible; the outer callback catches panics so they cannot cross the Windows callback boundary and abort the process.
/// 中文关键词：ETW回调，panic隔离，FFI安全，事件丢弃
/// English keywords: ETW callback, panic isolation, FFI safety, event drop
unsafe fn etw_event_record_callback_inner(rec: *mut EVENT_RECORD) {
    if rec.is_null() {
        return;
    }

    let ctx_ptr = CALLBACK_CTX.load(Ordering::Relaxed);
    if ctx_ptr.is_null() {
        return;
    }

    let rec = &*(rec as *const EventRecord);
    let header = &rec.event_header;
    let provider_bytes = guid_bytes(&header.provider_id);
    let opcode = header.event_descriptor.opcode as u16;
    let id = header.event_descriptor.id;
    let pid = header.process_id;
    let tid = header.thread_id;

    // 过滤系统/无效事件：PID 0 是 System Idle Process，PID 4 是 System Process，
    // 0xFFFFFFFF 表示没有有效进程归属，不能进入实时日志和风险链路。
    // Filter system/invalid events before queueing to avoid downstream noise and extra work.
    if is_system_or_invalid_pid(pid) {
        return;
    }

    // ETW timestamp is 100ns intervals since Jan 1, 1601
    let ts_ms = if header.time_stamp > 0 {
        (header.time_stamp as u64) / 10000 - 11644473600000u64
    } else {
        current_ts_ms()
    };

    let user_data_slice = if rec.user_data_length > 0 && !rec.user_data.is_null() {
        std::slice::from_raw_parts(rec.user_data, rec.user_data_length as usize)
    } else {
        &[]
    };

    let ev = parser::parse_event_record(
        &provider_bytes,
        opcode,
        id,
        pid,
        tid,
        ts_ms,
        user_data_slice,
    );

    let ctx = &*ctx_ptr;

    // Run rule engine (if locked, skip)
    let matched = ctx
        .rule_engine
        .lock()
        .ok()
        .and_then(|mut engine| engine.on_event(&ev));

    // Build JSON and push to queue
    let now = current_ts_ms();
    let json_event = parsed_event_to_json(&ev, now);

    if let Ok(mut queue) = ctx.event_queue.lock() {
        if queue.len() < 5000 {
            if let Some(m) = matched {
                let match_json = match_event_to_json(&m);
                if !match_json.is_empty() {
                    queue.push_back(match_json);
                }
            }
            queue.push_back(json_event);
        }
    }
}

/// 将内部 GUID 结构体字节转为 [u8; 16]
/// Converts internal GUID struct to raw byte array
fn guid_bytes(g: &Guid) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&g.data1.to_le_bytes());
    bytes[4..6].copy_from_slice(&g.data2.to_le_bytes());
    bytes[6..8].copy_from_slice(&g.data3.to_le_bytes());
    bytes[8..16].copy_from_slice(&g.data4);
    bytes
}

/// 将 [u8; 16] 字节转为内部 GUID 结构体
/// Converts raw byte array to internal GUID struct
fn raw_guid(bytes: &[u8; 16]) -> Guid {
    Guid {
        data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        data2: u16::from_le_bytes([bytes[4], bytes[5]]),
        data3: u16::from_le_bytes([bytes[6], bytes[7]]),
        data4: [
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ],
    }
}

/// 将解析后的事件序列化为 JSON 字符串（兼容 C++ etw_bridge 输出格式）
/// Serializes parsed event to JSON string (compatible with C++ etw_bridge output format)
/// 中文关键词：JSON序列化，ETW事件，日志格式，事件输出
/// English keywords: JSON serialization, ETW event, log format, event output
fn parsed_event_to_json(ev: &ParsedEvent, _ts_ms: u64) -> String {
    let provider_name = match ev.provider {
        ProviderKind::Process => "Process",
        ProviderKind::Thread => "Thread",
        ProviderKind::Image => "Image",
        ProviderKind::File => "File",
        ProviderKind::Registry => "Registry",
        ProviderKind::Network => "Network",
        ProviderKind::Unknown => "Unknown",
    };
    match ev.provider {
        ProviderKind::Process => serde_json::to_string(&json!({
            "type": "log",
            "event": {
                "timestamp": ev.ts_ms, "pid": ev.pid, "tid": ev.tid,
                "provider": provider_name, "opcode": ev.opcode, "id": ev.id,
                "rawUserDataLength": ev.raw_user_data_len,
                "rawUserDataPreview": ev.raw_user_data_preview,
                "data": {
                    "processName": ev.target, "parentPid": ev.ppid, "type": ev.op
                }
            }
        })).unwrap_or_default(),
        ProviderKind::Thread => serde_json::to_string(&json!({
            "type": "log",
            "event": {
                "timestamp": ev.ts_ms, "pid": ev.pid, "tid": ev.tid,
                "provider": provider_name, "opcode": ev.opcode, "id": ev.id,
                "rawUserDataLength": ev.raw_user_data_len,
                "rawUserDataPreview": ev.raw_user_data_preview,
                "data": {
                    "threadId": ev.target, "type": ev.op,
                    "startAddress": ev.start_address.map(|addr| format!("0x{:x}", addr))
                }
            }
        })).unwrap_or_default(),
        ProviderKind::Image => serde_json::to_string(&json!({
            "type": "log",
            "event": {
                "timestamp": ev.ts_ms, "pid": ev.pid, "tid": ev.tid,
                "provider": provider_name, "opcode": ev.opcode, "id": ev.id,
                "rawUserDataLength": ev.raw_user_data_len,
                "rawUserDataPreview": ev.raw_user_data_preview,
                "data": {
                    "imageName": ev.target, "type": ev.op,
                    "imageBase": ev.image_base.map(|addr| format!("0x{:x}", addr)),
                    "imageSize": ev.image_size
                }
            }
        })).unwrap_or_default(),
        ProviderKind::File => serde_json::to_string(&json!({
            "type": "log",
            "event": {
                "timestamp": ev.ts_ms, "pid": ev.pid, "tid": ev.tid,
                "provider": provider_name, "opcode": ev.opcode, "id": ev.id,
                "rawUserDataLength": ev.raw_user_data_len,
                "rawUserDataPreview": ev.raw_user_data_preview,
                "data": {
                    "fileName": ev.target, "type": ev.op
                }
            }
        })).unwrap_or_default(),
        ProviderKind::Registry => serde_json::to_string(&json!({
            "type": "log",
            "event": {
                "timestamp": ev.ts_ms, "pid": ev.pid, "tid": ev.tid,
                "provider": provider_name, "opcode": ev.opcode, "id": ev.id,
                "rawUserDataLength": ev.raw_user_data_len,
                "rawUserDataPreview": ev.raw_user_data_preview,
                "data": {
                    "keyName": if ev.target2.is_empty() { ev.target.clone() } else { ev.target2.clone() },
                    "operation": ev.op
                }
            }
        })).unwrap_or_default(),
        ProviderKind::Network => {
            let parts: Vec<&str> = ev.target.split(':').collect();
            serde_json::to_string(&json!({
                "type": "log",
                "event": {
                    "timestamp": ev.ts_ms, "pid": ev.pid, "tid": ev.tid,
                    "provider": provider_name, "opcode": ev.opcode, "id": ev.id,
                    "rawUserDataLength": ev.raw_user_data_len,
                    "rawUserDataPreview": ev.raw_user_data_preview,
                    "data": {
                        "remoteAddress": parts.first().unwrap_or(&""),
                        "remotePort": parts.get(1).and_then(|p| p.parse::<u16>().ok()).unwrap_or(0),
                        "protocol": "TCP"
                    }
                }
            })).unwrap_or_default()
        }
        _ => serde_json::to_string(&json!({
            "type": "log",
            "event": {
                "timestamp": ev.ts_ms, "pid": ev.pid, "tid": ev.tid,
                "provider": provider_name, "opcode": ev.opcode, "id": ev.id,
                "rawUserDataLength": ev.raw_user_data_len,
                "rawUserDataPreview": ev.raw_user_data_preview,
                "data": {
                    "type": ev.op
                }
            }
        }))
        .unwrap_or_default(),
    }
}

/// 将规则匹配结果序列化为 JSON 字符串（兼容 C++ etw_bridge 输出格式）
/// Serializes rule match result to JSON string (compatible with C++ etw_bridge output format)
/// 中文关键词：匹配序列化，威胁告警，规则匹配，JSON输出
/// English keywords: match serialization, threat alert, rule match, JSON output
fn match_event_to_json(m: &MatchedEvent) -> String {
    serde_json::to_string(&json!({
        "type": "match",
        "matched": true,
        "ruleId": m.rule_id,
        "threatType": m.threat_type,
        "severity": m.severity,
        "recommendAction": m.recommend_action,
        "description": m.description,
        "provider": m.provider,
        "op": m.op,
        "operation": m.op,
        "pid": m.pid,
        "path": m.path,
        "tsMs": m.ts_ms,
        "evidence": m.evidence,
        "context": m.context.iter().map(|c| json!({
            "tsMs": c.ts_ms, "provider": c.provider, "op": c.op, "target": c.target
        })).collect::<Vec<_>>()
    }))
    .unwrap_or_default()
}

/// 函数名称：enable_se_system_profile_privilege
/// 函数作用：启用当前进程的 SE_SYSTEM_PROFILE_NAME 特权。某些内核级 ETW provider
///   在管理员会话里仍需要这个特权处于启用状态；即使以管理员身份运行，默认也可能未启用。
///   这里通过 AdjustTokenPrivileges 只做“打开现有钥匙”，不创建新的权限。
/// Purpose: Enables the SE_SYSTEM_PROFILE_NAME privilege for the current process.
///   Some kernel-level ETW providers still require this privilege to be enabled
///   in the administrator token. Even when running as Administrator, it may not
///   be enabled by default. This function enables it via AdjustTokenPrivileges.
/// 调用方：EtwSession::new() — 在 StartTraceW 之前调用
/// Called by: EtwSession::new() — called before StartTraceW
/// 中文关键词：特权启用，SE_SYSTEM_PROFILE_NAME，内核ETW，管理员权限
/// English keywords: privilege enable, SE_SYSTEM_PROFILE_NAME, kernel ETW, admin privilege
fn enable_se_system_profile_privilege() -> Result<(), String> {
    unsafe {
        let advapi32 = libloading::Library::new("advapi32.dll")
            .map_err(|e| format!("Failed to load advapi32.dll: {}", e))?;

        type OpenProcessTokenFn = unsafe extern "system" fn(isize, u32, *mut isize) -> u32;
        type LookupPrivilegeValueWFn =
            unsafe extern "system" fn(*const u16, *const u16, *mut i64) -> u32;
        type AdjustTokenPrivilegesFn =
            unsafe extern "system" fn(isize, u32, *const u8, u32, *mut u8, *mut u32) -> u32;

        let open_process_token: OpenProcessTokenFn = *advapi32
            .get(b"OpenProcessToken")
            .map_err(|e| format!("Failed to find OpenProcessToken: {}", e))?;
        let lookup_privilege_value: LookupPrivilegeValueWFn = *advapi32
            .get(b"LookupPrivilegeValueW")
            .map_err(|e| format!("Failed to find LookupPrivilegeValueW: {}", e))?;
        let adjust_token_privileges: AdjustTokenPrivilegesFn = *advapi32
            .get(b"AdjustTokenPrivileges")
            .map_err(|e| format!("Failed to find AdjustTokenPrivileges: {}", e))?;

        // TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES
        const TOKEN_QUERY: u32 = 0x0008;
        const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
        const SE_PRIVILEGE_ENABLED: u32 = 0x00000002;

        #[repr(C)]
        struct Luid {
            low_part: u32,
            high_part: i32,
        }

        #[repr(C)]
        struct LuidAndAttributes {
            luid: Luid,
            attributes: u32,
        }

        #[repr(C)]
        struct TokenPrivileges {
            privilege_count: u32,
            privileges: [LuidAndAttributes; 1],
        }

        // 第 1 步：打开进程令牌 / Step 1: Open process token
        let mut token: isize = 0;
        let status = open_process_token(
            -1isize, // GetCurrentProcess() 伪句柄
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut token,
        );
        if status == 0 {
            return Err(format!("OpenProcessToken failed: {}", status));
        }

        // 第 2 步：查找 SE_SYSTEM_PROFILE_NAME 的 LUID
        // Step 2: Look up LUID for SE_SYSTEM_PROFILE_NAME
        let priv_name: Vec<u16> = "SeSystemProfilePrivilege\0".encode_utf16().collect();
        let mut luid: i64 = 0;
        let status = lookup_privilege_value(std::ptr::null(), priv_name.as_ptr(), &mut luid);
        if status == 0 {
            // 关闭令牌 / Close token
            let _ = std::mem::drop(advapi32);
            return Err(format!("LookupPrivilegeValueW failed: {}", status));
        }

        // 第 3 步：调整特权 — 启用 SE_SYSTEM_PROFILE_NAME
        // Step 3: Adjust token privileges — enable SE_SYSTEM_PROFILE_NAME
        let new_luid = Luid {
            low_part: luid as u32,
            high_part: (luid >> 32) as i32,
        };

        let tp = TokenPrivileges {
            privilege_count: 1,
            privileges: [LuidAndAttributes {
                luid: new_luid,
                attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let status = adjust_token_privileges(
            token,
            0, // FALSE = 不全部禁用
            &tp as *const TokenPrivileges as *const u8,
            0, // 不获取前一个特权集
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        if status == 0 {
            eprintln!("[EtwSession] AdjustTokenPrivileges failed (code 0)");
            // 非致命：即使特权启用失败，有时 StartTraceW 仍可工作
        } else {
            eprintln!("[EtwSession] SE_SYSTEM_PROFILE_NAME privilege enabled");
        }

        // 关闭令牌句柄（OpenProcessToken 返回的是真实句柄，需要关闭）
        // Close the token handle (OpenProcessToken returns a real handle)
        if token != 0 && token != -1 {
            let kernel32 = match libloading::Library::new("kernel32.dll") {
                Ok(l) => l,
                Err(_) => return Ok(()), // 非致命：无法加载 kernel32 时忽略
            };
            type CloseHandleFn = unsafe extern "system" fn(isize) -> u32;
            if let Ok(close_handle_ptr) = kernel32.get::<CloseHandleFn>(b"CloseHandle") {
                let _ = (*close_handle_ptr)(token);
            }
        }

        Ok(())
    }
}
