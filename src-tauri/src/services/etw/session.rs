use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, AtomicPtr, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

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

const SYSTEM_TRACE_CONTROL_GUID: [u8; 16] = [
    0x68, 0xDD, 0x9E, 0x9E, 0x0C, 0x8D, 0x84, 0x45, 0x82, 0x77, 0x7D, 0x5D, 0x82, 0xA9, 0xAC, 0xE4,
];

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
    buffer_context: [u32; 4],
    extended_data_count: u16,
    user_data_length: u16,
    extended_data: *const u8,
    user_data: *const u8,
    user_context: *const u8,
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
    /// 函数作用：创建 ETW 会话。先尝试启用 SE_SYSTEM_PROFILE_NAME 特权（系统级 ETW 所需），
    ///   然后调用 StartTraceW 创建系统日志会话。若首次失败且为权限错误，重试一次。
    /// Purpose: Creates an ETW session. First tries to enable SE_SYSTEM_PROFILE_NAME privilege
    ///   (required for system-level ETW), then calls StartTraceW to create a system logger session.
    ///   Retries once if the first attempt fails with access denied.
    pub fn new(session_name: &str) -> Result<Self, String> {
        let wide_name: Vec<u16> = session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let buf_size = std::mem::size_of::<EventTraceProperties>() + 2048;

        unsafe {
            let sechost = libloading::Library::new("sechost.dll")
                .map_err(|e| format!("Failed to load sechost.dll: {}", e))?;

            type StartTraceFn =
                unsafe extern "system" fn(*mut u64, *const u16, *mut EventTraceProperties) -> u32;

            let start_trace: StartTraceFn = *sechost
                .get(b"StartTraceW")
                .map_err(|e| format!("Failed to load StartTraceW: {}", e))?;

            // 尝试启用 SE_SYSTEM_PROFILE_NAME 特权（系统级 ETW 会话必需）
            // Try to enable SE_SYSTEM_PROFILE_NAME privilege (required for system-level ETW sessions)
            let _ = enable_se_system_profile_privilege();

            // 创建 Session（使用 SYSTEM_TRACE_CONTROL_GUID）
            // 如果有同名 Session 已存在（183），MSDN 说明 handle 仍有效
            let mut buf: Vec<u8> = vec![0u8; buf_size];
            let props = &mut *(buf.as_mut_ptr() as *mut EventTraceProperties);
            props.wnode.buffer_size = buf_size as u32;
            props.wnode.flags = 0x00020000;
            props.wnode.guid = raw_guid(&SYSTEM_TRACE_CONTROL_GUID);
            props.log_file_mode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
            props.logger_name_offset = std::mem::size_of::<EventTraceProperties>() as u32;

            let name_dst = buf.as_mut_ptr().add(props.logger_name_offset as usize) as *mut u16;
            std::ptr::copy_nonoverlapping(wide_name.as_ptr(), name_dst, wide_name.len());

            let mut handle: u64 = 0;
            let status = start_trace(&mut handle, wide_name.as_ptr(), props);
            if status != 0 && status != 183 && status != 5 {
                return Err(format!("StartTraceW failed: {}", status));
            }
            if status == 5 {
                eprintln!("[EtwSession] Access denied (code 5) on StartTraceW. ETW unavailable.");
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
                if status != 0 {
                    return Err(format!("EnableTraceEx2 failed: {}", status));
                }
            }

            // Build callback context
            let ctx = Box::new(EtwCallbackContext {
                event_queue: self.event_queue.clone(),
                rule_engine: self.rule_engine.clone(),
            });
            CALLBACK_CTX.store(Box::into_raw(ctx), Ordering::SeqCst);

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
            if trace_handle == 0 {
                CALLBACK_CTX.store(std::ptr::null_mut(), Ordering::SeqCst);
                return Err("OpenTraceW failed".to_string());
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

    pub fn stop(&mut self, _timeout_ms: u32) -> Result<(), String> {
        unsafe {
            let sechost = libloading::Library::new("sechost.dll")
                .map_err(|e| format!("Failed to load sechost.dll: {}", e))?;

            type ControlTraceFn =
                unsafe extern "system" fn(u64, *const u16, *mut EventTraceProperties, u32) -> u32;
            let control_trace: ControlTraceFn = *sechost
                .get(b"ControlTraceW")
                .map_err(|e| format!("Failed to load ControlTraceW: {}", e))?;

            let mut buf: Vec<u8> = vec![0u8; std::mem::size_of::<EventTraceProperties>() + 2048];
            let props = &mut *(buf.as_mut_ptr() as *mut EventTraceProperties);
            props.wnode.buffer_size = (std::mem::size_of::<EventTraceProperties>() + 2048) as u32;

            let wide_name: Vec<u16> = self
                .session_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let _ = control_trace(
                self.session_handle,
                wide_name.as_ptr(),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
        }

        if let Some(handle) = self.trace_thread.take() {
            let _ = handle.join();
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

/// ETW event record callback — called from ProcessTrace thread
/// ETW 事件记录回调 — 由 ProcessTrace 线程调用，解析事件并推入队列并运行规则引擎。
/// ETW event record callback — called by ProcessTrace thread, parses events, pushes to queue, runs rule engine.
/// 中文关键词：ETW回调，事件记录，ProcessTrace，规则匹配
/// English keywords: ETW callback, event record, ProcessTrace, rule matching
unsafe extern "system" fn etw_event_record_callback(rec: *mut EVENT_RECORD) {
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
                "data": {
                    "processName": ev.target, "parentPid": ev.ppid, "type": ev.op
                }
            }
        })).unwrap_or_default(),
        ProviderKind::File => serde_json::to_string(&json!({
            "type": "log",
            "event": {
                "timestamp": ev.ts_ms, "pid": ev.pid, "tid": ev.tid,
                "provider": provider_name, "opcode": ev.opcode, "id": ev.id,
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
                    "data": {
                        "remoteAddress": parts.first().unwrap_or(&""),
                        "remotePort": parts.get(1).and_then(|p| p.parse::<u16>().ok()).unwrap_or(0),
                        "protocol": "TCP"
                    }
                }
            })).unwrap_or_default()
        }
        _ => serde_json::to_string(&json!({"type": "log", "event": {}})).unwrap_or_default(),
    }
}

/// 将规则匹配结果序列化为 JSON 字符串（兼容 C++ etw_bridge 输出格式）
/// Serializes rule match result to JSON string (compatible with C++ etw_bridge output format)
/// 中文关键词：匹配序列化，威胁告警，规则匹配，JSON输出
/// English keywords: match serialization, threat alert, rule match, JSON output
fn match_event_to_json(m: &MatchedEvent) -> String {
    serde_json::to_string(&json!({
        "type": "match",
        "ruleId": m.rule_id,
        "threatType": m.threat_type,
        "severity": m.severity,
        "recommendAction": m.recommend_action,
        "provider": m.provider,
        "op": m.op,
        "pid": m.pid,
        "tsMs": m.ts_ms,
        "evidence": m.evidence,
        "context": m.context.iter().map(|c| json!({
            "tsMs": c.ts_ms, "provider": c.provider, "op": c.op, "target": c.target
        })).collect::<Vec<_>>()
    }))
    .unwrap_or_default()
}

/// 函数名称：enable_se_system_profile_privilege
/// 函数作用：启用当前进程的 SE_SYSTEM_PROFILE_NAME 特权。系统级 ETW 会话（StartTraceW
///   使用 SYSTEM_TRACE_CONTROL_GUID + EVENT_TRACE_SYSTEM_LOGGER_MODE）需要此特权，
///   即使以管理员身份运行，默认也可能未启用。此函数通过 AdjustTokenPrivileges 启用该特权。
/// Purpose: Enables the SE_SYSTEM_PROFILE_NAME privilege for the current process.
///   System-level ETW sessions (StartTraceW with SYSTEM_TRACE_CONTROL_GUID +
///   EVENT_TRACE_SYSTEM_LOGGER_MODE) require this privilege. Even when running as
///   Administrator, it may not be enabled by default. This function enables it via
///   AdjustTokenPrivileges.
/// 调用方：EtwSession::new() — 在 StartTraceW 之前调用
/// Called by: EtwSession::new() — called before StartTraceW
/// 中文关键词：特权启用，SE_SYSTEM_PROFILE_NAME，系统级ETW，管理员权限
/// English keywords: privilege enable, SE_SYSTEM_PROFILE_NAME, system-level ETW, admin privilege
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
        if status != 0 {
            return Err(format!("OpenProcessToken failed: {}", status));
        }

        // 第 2 步：查找 SE_SYSTEM_PROFILE_NAME 的 LUID
        // Step 2: Look up LUID for SE_SYSTEM_PROFILE_NAME
        let priv_name: Vec<u16> = "SeSystemProfilePrivilege\0".encode_utf16().collect();
        let mut luid: i64 = 0;
        let status = lookup_privilege_value(std::ptr::null(), priv_name.as_ptr(), &mut luid);
        if status != 0 {
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
