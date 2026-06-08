// 文件钩子服务 — 管理命名管道服务端，接收注入进程的实时文件操作事件
// File hook service — manages named pipe server, receives real-time file operation events from injected processes
use crate::commands::logs;
use crate::services::behavior_service::BehaviorService;
use crate::services::risk_service::{RiskEvent, RiskService};
use crate::services::trust_service::TrustService;
use libloading::{Library, Symbol};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::mpsc;

const HOOK_SERVICE_STOP_JOIN_TIMEOUT_MS: u64 = 2_500;
const HOOK_SERVICE_STOP_JOIN_POLL_MS: u64 = 25;

/// 文件钩子事件 / File hook event
/// Received from injected file_hook_detours.dll via named pipe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHookEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<String>,
    pub path: String,
    #[serde(rename = "targetPath", skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    pub pid: u32,
    #[serde(default)]
    pub tid: u32,
    #[serde(rename = "processName", skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(default, alias = "ts")]
    pub timestamp: u64,
}

/// Hook 管道消息 / Hook pipe message
pub enum HookPipeMessage {
    /// 心跳消息，需要服务端应答 / Heartbeat message that requires server acknowledgement
    Heartbeat,
    /// 文件操作事件，需要进入产品事件链路 / File operation event that must enter the product event pipeline
    Event(FileHookEvent),
}

/// 文件钩子服务 — 命名管道服务端
/// File hook service — named pipe server
///
/// 使用 libloading 动态调用 kernel32.dll 的命名管道 API，避免 windows-core 版本冲突。
/// Uses libloading to dynamically call kernel32.dll named pipe APIs, avoiding windows-core version conflicts.
pub struct HookService {
    tx: Arc<Mutex<Option<mpsc::UnboundedSender<FileHookEvent>>>>,
    running: Arc<AtomicBool>,
    server_thread: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
}

impl HookService {
    pub fn new() -> Self {
        Self {
            tx: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            server_thread: Arc::new(Mutex::new(None)),
        }
    }

    /// 函数名称：start
    /// 函数作用：启动可停止的命名管道服务端，接收文件操作事件并分发到前端、日志、行为数据库和风险分析。
    /// Purpose: Starts a stoppable named pipe server, receives file operation events, and dispatches them to frontend, logs, behavior DB, and risk analysis.
    /// 调用方：commands::hook::start_hook_service。
    /// Called by: commands::hook::start_hook_service.
    /// 被调用方：serve_pipe_connection、dispatch_hook_event。
    /// Calls: serve_pipe_connection, dispatch_hook_event.
    /// 参数说明：pipe_name 为管道名称后缀；app_handle 用于访问 Tauri 状态和事件系统。
    /// Parameters: pipe_name is the pipe name suffix; app_handle accesses Tauri state and events.
    /// 返回值说明：成功返回 Hook 事件接收器；失败返回 String。
    /// Returns: Hook event receiver on success; String error on failure.
    /// 错误处理：重复启动返回错误；单条事件分发失败记录错误后继续服务；管道等待采用短轮询，避免 stop 无法打断阻塞等待。
    /// Error handling: Duplicate start returns an error; per-event dispatch errors are logged and the service continues; pipe waits use short polling so stop can interrupt waits.
    /// 中文关键词：启动管道，接收事件，文件钩子启动，事件分发，风险链路，可停止线程
    /// English keywords: start pipe, receive events, file hook start, event dispatch, risk pipeline, stoppable thread
    pub fn start(
        &self,
        pipe_name: &str,
        app_handle: AppHandle,
    ) -> Result<mpsc::UnboundedReceiver<FileHookEvent>, String> {
        if self.running.load(Ordering::SeqCst) {
            return Err("Hook service is already running".to_string());
        }

        let mut tx_guard = self.tx.lock().map_err(|e| e.to_string())?;
        let mut server_thread_guard = self.server_thread.lock().map_err(|e| e.to_string())?;
        if server_thread_guard.is_some() {
            return Err("Hook service is still stopping".to_string());
        }

        let (tx, rx) = mpsc::unbounded_channel::<FileHookEvent>();
        *tx_guard = Some(tx);

        let running = self.running.clone();
        let full_pipe_name = format!(r"\\.\pipe\{}", pipe_name);
        self.running.store(true, Ordering::SeqCst);

        let handle = thread::spawn(move || {
            eprintln!(
                "[HookService] Starting named pipe server: {}",
                full_pipe_name
            );
            while running.load(Ordering::SeqCst) {
                match serve_pipe_connection(&full_pipe_name, &running) {
                    Ok(events) => {
                        for event in events {
                            if let Err(err) = dispatch_hook_event(&app_handle, event) {
                                eprintln!("[HookService] Event dispatch error: {}", err);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[HookService] Pipe connection error: {}", e);
                    }
                }
                thread::sleep(Duration::from_millis(100));
            }
            eprintln!("[HookService] Named pipe server stopped");
        });
        *server_thread_guard = Some(handle);

        Ok(rx)
    }

    /// 函数名称：stop
    /// 函数作用：停止文件 Hook 管道服务，并用有限等待避免停止命令无限阻塞。
    /// Purpose: Stops the file hook pipe service with bounded waits so the stop command cannot block indefinitely.
    /// 调用方：commands::hook::stop_hook_service。
    /// Called by: commands::hook::stop_hook_service.
    /// 被调用方：wait_for_hook_thread_stop。
    /// Calls: wait_for_hook_thread_stop.
    /// 返回值说明：成功停止返回 Ok；锁中毒、线程 panic 或超时未退出返回 String 错误。
    /// Returns: Ok on successful stop; String error on poisoned locks, thread panic, or timed-out thread exit.
    /// 错误处理：先清空发送器并关闭运行标志；超时未退出时保存线程句柄，避免误报已完全停止。
    /// Error handling: Clears sender and running flag first; retains the thread handle on timeout instead of reporting a confirmed stop.
    /// 中文关键词：停止钩子，关闭管道，线程退出，有限等待，阻塞防护
    /// English keywords: stop hook, close pipe, thread exit, bounded wait, blocking guard
    pub fn stop(&self) -> Result<(), String> {
        self.running.store(false, Ordering::SeqCst);
        *self.tx.lock().map_err(|e| e.to_string())? = None;

        let handle = {
            let mut server_thread_guard = self.server_thread.lock().map_err(|e| e.to_string())?;
            server_thread_guard.take()
        };

        if let Some(handle) = handle {
            match wait_for_hook_thread_stop(
                handle,
                Duration::from_millis(HOOK_SERVICE_STOP_JOIN_TIMEOUT_MS),
            )? {
                Some(handle) => {
                    *self.server_thread.lock().map_err(|e| e.to_string())? = Some(handle);
                    return Err(format!(
                        "Hook service thread did not stop within {} ms",
                        HOOK_SERVICE_STOP_JOIN_TIMEOUT_MS
                    ));
                }
                None => {}
            }
        }
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// 函数名称：wait_for_hook_thread_stop
/// 函数作用：在限定时间内等待 Hook 管道线程退出，避免 stop 路径无限 join。
/// Purpose: Waits for the hook pipe thread to finish within a bounded timeout, avoiding indefinite joins on stop.
/// 调用方：HookService::stop，Hook 服务单元测试。
/// Called by: HookService::stop, Hook service unit tests.
/// 参数说明：handle 为后台线程句柄；timeout 为最大等待时间。
/// Parameters: handle is the background thread handle; timeout is the maximum wait.
/// 返回值说明：线程结束返回 None；超时返回 Some(handle) 交还调用方保存。
/// Returns: None when the thread finished; Some(handle) on timeout so the caller can keep it.
/// 错误处理：线程 panic 转换为 String；超时不 panic、不无限等待。
/// Error handling: Converts thread panic to String; timeout does not panic or wait indefinitely.
/// 中文关键词：Hook停止，线程等待，超时保护，阻塞防护
/// English keywords: hook stop, thread wait, timeout guard, blocking guard
fn wait_for_hook_thread_stop(
    handle: thread::JoinHandle<()>,
    timeout: Duration,
) -> Result<Option<thread::JoinHandle<()>>, String> {
    let started_at = Instant::now();

    while started_at.elapsed() < timeout {
        if handle.is_finished() {
            handle
                .join()
                .map_err(|_| "Hook service thread panicked during stop".to_string())?;
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(HOOK_SERVICE_STOP_JOIN_POLL_MS));
    }

    Ok(Some(handle))
}

/// 函数名称：hook_event_to_app_event
/// 函数作用：把原生 file_hook DLL 上报的事件转换为应用统一事件 JSON。
/// Purpose: Converts native file_hook DLL events into the application's unified event JSON.
/// 调用方：dispatch_hook_event，Hook 服务单元测试。
/// Called by: dispatch_hook_event, Hook service unit tests.
/// 被调用方：chrono::Utc::now。
/// Calls: chrono::Utc::now.
/// 参数说明：event 为已解析的 Hook 事件。
/// Parameters: event is a parsed Hook event.
/// 返回值说明：返回可直接写入行为库和前端事件流的 JSON。
/// Returns: JSON suitable for behavior DB ingestion and frontend event stream.
/// 错误处理：缺失时间戳时使用当前时间；不抛异常。
/// Error handling: Uses current time when timestamp is missing; does not throw.
/// 中文关键词：Hook事件，事件转换，行为数据库，前端事件
/// English keywords: hook event, event conversion, behavior database, frontend event
pub fn hook_event_to_app_event(event: &FileHookEvent) -> serde_json::Value {
    let timestamp_ms = if event.timestamp == 0 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    } else {
        event.timestamp
    };
    let process_name = event
        .process_name
        .clone()
        .unwrap_or_else(|| format!("PID {}", event.pid));
    let operation = event.api.clone().unwrap_or_else(|| event.event_type.clone());
    serde_json::json!({
        "type": "file_hook",
        "source": event.source.clone().unwrap_or_else(|| "file_hook".to_string()),
        "pid": event.pid,
        "tid": event.tid,
        "processName": process_name,
        "provider": "FileHook",
        "operation": operation,
        "path": event.path.clone(),
        "targetPath": event.target_path.clone(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "timestampMs": timestamp_ms,
        "details": {
            "eventType": event.event_type.clone(),
            "api": event.api.clone(),
            "source": event.source.clone(),
            "targetPath": event.target_path.clone(),
        }
    })
}

/// 函数名称：hook_event_to_risk_event
/// 函数作用：将 Hook 文件操作事件映射为风险分析事件。
/// Purpose: Maps a Hook file operation event into a risk analysis event.
/// 调用方：dispatch_hook_event，Hook 服务单元测试。
/// Called by: dispatch_hook_event, Hook service unit tests.
/// 参数说明：event 为 Hook 事件；app_event 为统一事件 JSON。
/// Parameters: event is the Hook event; app_event is the unified event JSON.
/// 返回值说明：返回 RiskEvent，供 RiskService 继续写库和推送拦截。
/// Returns: RiskEvent for RiskService to continue DB write and interception.
/// 中文关键词：Hook风险，文件行为，风险事件，拦截链路
/// English keywords: hook risk, file behavior, risk event, interception pipeline
pub fn hook_event_to_risk_event(event: &FileHookEvent, app_event: &serde_json::Value) -> RiskEvent {
    let operation = event.api.as_deref().unwrap_or(event.event_type.as_str());
    let normalized_operation = operation.to_ascii_lowercase();
    let severity = if normalized_operation.contains("createfile") {
        45
    } else {
        35
    };
    RiskEvent {
        pid: event.pid,
        process_name: app_event
            .get("processName")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string(),
        file_path: Some(event.path.clone()),
        threat_type: "file_hook_activity".to_string(),
        threat_name: Some(operation.to_string()),
        severity,
        rule_id: "FILE_HOOK_ACTIVITY".to_string(),
        description: format!("File hook captured {} on {}", operation, event.path),
        timestamp: app_event
            .get("timestampMs")
            .and_then(|v| v.as_u64())
            .unwrap_or(event.timestamp),
    }
}

fn dispatch_hook_event(app_handle: &AppHandle, event: FileHookEvent) -> Result<(), String> {
    let app_event = hook_event_to_app_event(&event);
    let json_line = serde_json::to_string(&app_event).map_err(|e| e.to_string())?;

    logs::append_log(json_line);
    let _ = app_handle.emit("etw-event", app_event.clone());
    let _ = app_handle.emit("file-hook-event", app_event.clone());

    if let Some(behavior_state) =
        app_handle.try_state::<Arc<std::sync::Mutex<BehaviorService>>>()
    {
        let behavior = {
            let guard = behavior_state.lock().map_err(|e| e.to_string())?;
            guard.clone()
        };
        let behavior_event = app_event.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(err) = behavior.ingest_event(behavior_event).await {
                eprintln!("[HookService] Behavior ingest error: {}", err);
            }
        });
    }

    let risk_event = hook_event_to_risk_event(&event, &app_event);
    let app_handle_risk = app_handle.clone();
    tauri::async_runtime::spawn(async move {
        if let Some(risk_state) = app_handle_risk.try_state::<RiskService>() {
            let behavior_service = app_handle_risk
                .try_state::<Arc<std::sync::Mutex<BehaviorService>>>()
                .and_then(|state| state.lock().ok().map(|guard| guard.clone()));
            let trust_state = app_handle_risk.try_state::<TrustService>();
            let trust_service = trust_state.as_ref().map(|state| state.inner());

            let _ = risk_state
                .analyze_event(
                    risk_event,
                    trust_service,
                    behavior_service.as_ref(),
                    &app_handle_risk,
                )
                .await;
        }
    });

    Ok(())
}

/// 函数名称：parse_hook_pipe_line
/// 函数作用：解析 file_hook DLL 通过命名管道发送的一行 JSON 消息。
/// Purpose: Parses one JSON message line sent by the file_hook DLL through the named pipe.
/// 调用方：serve_pipe_connection，Hook 服务单元测试。
/// Called by: serve_pipe_connection, Hook service unit tests.
/// 被调用方：serde_json::from_str，serde_json::from_value。
/// Calls: serde_json::from_str, serde_json::from_value.
/// 参数说明：line 为单行 JSON 文本，可包含首尾空白。
/// Parameters: line is one JSON text line and may contain surrounding whitespace.
/// 返回值说明：空行返回 None；heartbeat 返回 Heartbeat；文件 Hook 事件返回 Event。
/// Returns: None for blank lines; Heartbeat for heartbeat messages; Event for file hook events.
/// 错误处理：非法 JSON 或字段缺失返回可定位错误。
/// Error handling: Invalid JSON or missing fields return locatable errors.
/// 中文关键词：Hook消息解析，命名管道，心跳，应答，文件事件
/// English keywords: hook message parsing, named pipe, heartbeat, acknowledgement, file event
pub fn parse_hook_pipe_line(line: &str) -> Result<Option<HookPipeMessage>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let value: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|e| format!("Invalid hook JSON: {}", e))?;
    if value.get("type").and_then(|v| v.as_str()) == Some("heartbeat") {
        return Ok(Some(HookPipeMessage::Heartbeat));
    }

    let event = serde_json::from_value::<FileHookEvent>(value)
        .map_err(|e| format!("Invalid hook event payload: {}", e))?;
    Ok(Some(HookPipeMessage::Event(event)))
}

/// 函数名称：should_retry_hook_pipe_wait
/// 函数作用：判断命名管道在非阻塞等待中遇到的 Windows 错误码是否可以短暂等待后重试。
/// Purpose: Determines whether a Windows named-pipe nonblocking wait error can be retried after a short pause.
/// 调用方：serve_pipe_connection，Hook 服务单元测试。
/// Called by: serve_pipe_connection, Hook service unit tests.
/// 参数说明：error_code 为 GetLastError 返回的 Windows 错误码。
/// Parameters: error_code is the Windows error code returned by GetLastError.
/// 返回值说明：可重试返回 true；连接断开或未知错误返回 false。
/// Returns: true for retryable wait states; false for disconnected or unknown errors.
/// 中文关键词：命名管道，非阻塞等待，重试错误码，阻塞防护
/// English keywords: named pipe, nonblocking wait, retryable error code, blocking guard
pub fn should_retry_hook_pipe_wait(error_code: u32) -> bool {
    const ERROR_NO_DATA: u32 = 232;
    const ERROR_PIPE_LISTENING: u32 = 536;

    error_code == ERROR_NO_DATA || error_code == ERROR_PIPE_LISTENING
}

/// 函数名称：serve_pipe_connection
/// 函数作用：通过 libloading 动态调用 kernel32.dll 的命名管道 API 处理单个连接，并在 stop 标志关闭时及时退出。
/// Purpose: Handles a single named pipe connection through dynamically loaded kernel32.dll APIs and exits promptly when the stop flag is cleared.
/// 调用方：HookService::start 后台线程。
/// Called by: HookService::start background thread.
/// 被调用方：CreateNamedPipeA、ConnectNamedPipe、ReadFile、WriteFile、CloseHandle、parse_hook_pipe_line。
/// Calls: CreateNamedPipeA, ConnectNamedPipe, ReadFile, WriteFile, CloseHandle, parse_hook_pipe_line.
/// 参数说明：pipe_name 为完整管道名；running 为服务运行标志。
/// Parameters: pipe_name is the full pipe name; running is the service running flag.
/// 返回值说明：返回本次连接读取到的文件 Hook 事件；停止或无事件时返回空列表。
/// Returns: file hook events read from the connection; empty list when stopped or no events are available.
/// 错误处理：Windows API 加载或管道创建失败返回 String；等待连接和读取时遇到可重试状态会短暂停顿后继续检查 stop。
/// Error handling: Windows API loading or pipe creation failures return String; retryable connect/read states sleep briefly and continue checking stop.
/// 中文关键词：命名管道，文件钩子，非阻塞等待，停止服务，线程退出
/// English keywords: named pipe, file hook, nonblocking wait, stop service, thread exit
fn serve_pipe_connection(
    pipe_name: &str,
    running: &Arc<AtomicBool>,
) -> Result<Vec<FileHookEvent>, String> {
    // 动态加载 kernel32.dll / Dynamically load kernel32.dll
    let kernel32 = unsafe {
        Library::new("kernel32.dll").map_err(|e| format!("Failed to load kernel32.dll: {}", e))?
    };

    // CreateNamedPipeA
    type CreateNamedPipeFn = unsafe extern "system" fn(
        name: *const u8,
        open_mode: u32,
        pipe_mode: u32,
        max_instances: u32,
        out_buf_size: u32,
        in_buf_size: u32,
        default_timeout: u32,
        security_attrs: *const u8,
    ) -> isize;
    let create_pipe: Symbol<CreateNamedPipeFn> = unsafe { kernel32.get(b"CreateNamedPipeA") }
        .map_err(|e| format!("Failed to get CreateNamedPipeA: {}", e))?;

    // ConnectNamedPipe
    type ConnectNamedPipeFn = unsafe extern "system" fn(pipe: isize, overlapped: *const u8) -> i32;
    let connect_pipe: Symbol<ConnectNamedPipeFn> = unsafe { kernel32.get(b"ConnectNamedPipe") }
        .map_err(|e| format!("Failed to get ConnectNamedPipe: {}", e))?;

    // GetLastError
    type GetLastErrorFn = unsafe extern "system" fn() -> u32;
    let get_last_error: Symbol<GetLastErrorFn> = unsafe { kernel32.get(b"GetLastError") }
        .map_err(|e| format!("Failed to get GetLastError: {}", e))?;

    // ReadFile
    type ReadFileFn = unsafe extern "system" fn(
        file: isize,
        buffer: *mut u8,
        bytes_to_read: u32,
        bytes_read: *mut u32,
        overlapped: *const u8,
    ) -> i32;
    let read_file: Symbol<ReadFileFn> = unsafe { kernel32.get(b"ReadFile") }
        .map_err(|e| format!("Failed to get ReadFile: {}", e))?;

    // WriteFile
    type WriteFileFn = unsafe extern "system" fn(
        file: isize,
        buffer: *const u8,
        bytes_to_write: u32,
        bytes_written: *mut u32,
        overlapped: *const u8,
    ) -> i32;
    let write_file: Symbol<WriteFileFn> = unsafe { kernel32.get(b"WriteFile") }
        .map_err(|e| format!("Failed to get WriteFile: {}", e))?;

    // CloseHandle
    type CloseHandleFn = unsafe extern "system" fn(handle: isize) -> i32;
    let close_handle: Symbol<CloseHandleFn> = unsafe { kernel32.get(b"CloseHandle") }
        .map_err(|e| format!("Failed to get CloseHandle: {}", e))?;

    // 管道模式常量 / Pipe mode constants
    const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
    const PIPE_TYPE_MESSAGE: u32 = 0x00000004;
    const PIPE_READMODE_MESSAGE: u32 = 0x00000002;
    const PIPE_NOWAIT: u32 = 0x00000001;
    const ERROR_BROKEN_PIPE: u32 = 109;
    const ERROR_PIPE_CONNECTED: u32 = 535;
    const ERROR_PIPE_NOT_CONNECTED: u32 = 233;
    const INVALID_HANDLE_VALUE: isize = -1;

    use std::ffi::CString;
    let pipe_name_c = CString::new(pipe_name).map_err(|_| "Invalid pipe name".to_string())?;

    let pipe_handle = unsafe {
        create_pipe(
            pipe_name_c.as_ptr() as *const u8,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
            1,                // max instances
            65536,            // out buffer
            65536,            // in buffer
            0,                // default timeout
            std::ptr::null(), // default security
        )
    };

    if pipe_handle == INVALID_HANDLE_VALUE {
        return Err("Failed to create named pipe".to_string());
    }

    // 等待客户端连接，但不能无限期卡住，否则 stop() 无法让后台线程退出。
    // Wait for a client connection without blocking forever; otherwise stop() cannot finish.
    let mut is_connected = false;
    while running.load(Ordering::SeqCst) {
        let connected = unsafe { connect_pipe(pipe_handle, std::ptr::null()) };
        if connected != 0 {
            is_connected = true;
            break;
        }

        let error_code = unsafe { get_last_error() };
        if error_code == ERROR_PIPE_CONNECTED {
            is_connected = true;
            break;
        }
        if should_retry_hook_pipe_wait(error_code) {
            thread::sleep(Duration::from_millis(50));
            continue;
        }

        unsafe {
            close_handle(pipe_handle);
        }
        return Err(format!("ConnectNamedPipe failed: {}", error_code));
    }

    if !is_connected {
        unsafe {
            close_handle(pipe_handle);
        }
        return Ok(Vec::new());
    }

    let mut events: Vec<FileHookEvent> = Vec::new();
    let mut buffer = vec![0u8; 65536];

    // 读取消息 / Read messages
    while running.load(Ordering::SeqCst) {
        let mut bytes_read: u32 = 0;
        let result = unsafe {
            read_file(
                pipe_handle,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut bytes_read,
                std::ptr::null(),
            )
        };

        if result == 0 || bytes_read == 0 {
            let error_code = unsafe { get_last_error() };
            if should_retry_hook_pipe_wait(error_code) {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            if error_code == ERROR_BROKEN_PIPE || error_code == ERROR_PIPE_NOT_CONNECTED {
                break;
            }
            break;
        }

        let msg = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
        for line in msg.lines() {
            match parse_hook_pipe_line(line) {
                Ok(Some(HookPipeMessage::Heartbeat)) => {
                    let ack = b"{\"type\":\"heartbeat_ack\"}\n";
                    let mut written: u32 = 0;
                    let _ = unsafe {
                        write_file(
                            pipe_handle,
                            ack.as_ptr(),
                            ack.len() as u32,
                            &mut written,
                            std::ptr::null(),
                        )
                    };
                }
                Ok(Some(HookPipeMessage::Event(event))) => events.push(event),
                Ok(None) => {}
                Err(err) => {
                    eprintln!("[HookService] Failed to parse hook pipe line: {}", err);
                }
            }
        }
    }

    unsafe {
        close_handle(pipe_handle);
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_thread_wait_joins_finished_thread_without_timeout() {
        let handle = thread::spawn(|| {});

        let remaining_handle = wait_for_hook_thread_stop(handle, Duration::from_millis(250))
            .expect("finished hook thread should join cleanly");

        assert!(
            remaining_handle.is_none(),
            "finished hook thread should not be retained"
        );
    }
}
