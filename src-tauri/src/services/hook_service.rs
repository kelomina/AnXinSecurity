// 文件钩子服务 — 管理命名管道服务端，接收注入进程的实时文件操作事件
// File hook service — manages named pipe server, receives real-time file operation events from injected processes
use crate::commands::logs;
use crate::services::app_lifecycle_service::app_is_exiting;
use crate::services::behavior_service::BehaviorService;
use crate::services::interception_diagnostics_service::append_interception_diagnostic;
use crate::services::risk_service::{RiskEvent, RiskService};
use crate::services::trust_service::TrustService;
use libloading::{Library, Symbol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::mpsc;

use crate::services::interception_service::{InterceptionEntry, InterceptionService};
use crate::services::process_control_service::{
    is_current_process_or_ancestor, query_process_identity, resume_process_by_pid,
};
use crate::services::process_scanner_service::{file_name_from_path, ProcessScannerService};

const HOOK_SERVICE_STOP_JOIN_TIMEOUT_MS: u64 = 2_500;
const HOOK_SERVICE_STOP_JOIN_POLL_MS: u64 = 25;
const INJECTION_CHAIN_WINDOW_MS: u64 = 5_000;
const INJECTION_CHAIN_MAX_TRACKED: usize = 1024;
const HOOK_PIPE_WORKER_COUNT: usize = 8;
const HOOK_PIPE_POLL_MS: u64 = 5;
const HOOK_PIPE_MAX_EMPTY_READ_POLLS: u32 = 40;
const HOOK_PIPE_RAW_PREVIEW_CHARS: usize = 768;

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
    #[serde(default)]
    pub path: String,
    #[serde(rename = "targetPath", skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    pub pid: u32,
    #[serde(default)]
    pub tid: u32,
    #[serde(rename = "processName", skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(rename = "processPath", skip_serializing_if = "Option::is_none")]
    pub process_path: Option<String>,
    #[serde(rename = "targetPid", skip_serializing_if = "Option::is_none")]
    pub target_pid: Option<u32>,
    #[serde(rename = "desiredAccess", skip_serializing_if = "Option::is_none")]
    pub desired_access: Option<u64>,
    #[serde(rename = "baseAddress", skip_serializing_if = "Option::is_none")]
    pub base_address: Option<String>,
    #[serde(rename = "startAddress", skip_serializing_if = "Option::is_none")]
    pub start_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<bool>,
    #[serde(rename = "targetSuspended", skip_serializing_if = "Option::is_none")]
    pub target_suspended: Option<bool>,
    #[serde(rename = "lastError", skip_serializing_if = "Option::is_none")]
    pub last_error: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    #[serde(default, alias = "ts")]
    pub timestamp: u64,
}

#[derive(Debug, Clone, Default)]
struct InjectionChainState {
    started_at: u64,
    last_seen: u64,
    apis: Vec<String>,
    saw_open_process: bool,
    saw_virtual_alloc_ex: bool,
    saw_write_process_memory: bool,
    saw_create_remote_thread: bool,
    blocked_by_hook: bool,
    target_suspended_by_hook: bool,
    desired_access: Option<u64>,
    base_address: Option<String>,
    size: Option<u64>,
    start_address: Option<String>,
}

/// APIHook 注入链告警 / APIHook injection-chain alert.
///
/// 这不是单个 API 的孤立判断，而是同一源 PID 对同一目标 PID 在短时间内形成的
/// `OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread` 行为链。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionChainAlert {
    pub source_pid: u32,
    pub target_pid: u32,
    pub apis: Vec<String>,
    pub started_at: u64,
    pub last_seen: u64,
    pub blocked_by_hook: bool,
    pub target_suspended_by_hook: bool,
    pub desired_access: Option<u64>,
    pub base_address: Option<String>,
    pub size: Option<u64>,
    pub start_address: Option<String>,
}

impl InjectionChainAlert {
    pub fn from_blocked_hook_event(event: &FileHookEvent) -> Option<Self> {
        let api = event.api.as_deref()?;
        let api_lower = api.to_ascii_lowercase();
        if api_lower != "createremotethread" && api_lower != "createremotethreadex" {
            return None;
        }
        if !event.blocked.unwrap_or(false) {
            return None;
        }
        let target_pid = event.target_pid?;
        if event.pid == 0
            || event.pid == 4
            || event.pid == u32::MAX
            || target_pid == 0
            || target_pid == 4
            || target_pid == u32::MAX
            || event.pid == target_pid
        {
            return None;
        }
        let now = hook_event_timestamp_ms(event);
        let mut apis = Vec::new();
        if let Some(chain) = event.chain.as_deref() {
            for api_name in chain
                .split(|ch| matches!(ch, '>' | ',' | '|' | ';' | ' '))
                .map(str::trim)
                .filter(|item| !item.is_empty())
            {
                let api_name = api_name.to_string();
                if apis.last() != Some(&api_name) {
                    apis.push(api_name);
                }
            }
        }
        if apis.is_empty() || apis.last().map(|item| item.as_str()) != Some(api) {
            apis.push(api.to_string());
        }
        Some(Self {
            source_pid: event.pid,
            target_pid,
            apis,
            started_at: now,
            last_seen: now,
            blocked_by_hook: true,
            target_suspended_by_hook: event.target_suspended.unwrap_or(false),
            desired_access: event.desired_access,
            base_address: event.base_address.clone(),
            size: event.size,
            start_address: event.start_address.clone(),
        })
    }
}

/// 注入链聚合器 / Injection chain aggregator.
///
/// 按 `(source_pid, target_pid)` 聚合 APIHook 事件；只有形成完整远程线程注入链时才告警，
/// 避免“看见 cmd/calc/regedit 就拦截”的误伤。
#[derive(Debug)]
pub struct InjectionChainTracker {
    chains: HashMap<(u32, u32), InjectionChainState>,
    window_ms: u64,
    max_tracked: usize,
}

impl Default for InjectionChainTracker {
    fn default() -> Self {
        Self::new(INJECTION_CHAIN_WINDOW_MS)
    }
}

impl InjectionChainTracker {
    pub fn new(window_ms: u64) -> Self {
        Self {
            chains: HashMap::new(),
            window_ms,
            max_tracked: INJECTION_CHAIN_MAX_TRACKED,
        }
    }

    /// 记录一条 APIHook 事件；当同一源/目标 PID 形成注入链时返回告警。
    pub fn record(&mut self, event: &FileHookEvent) -> Option<InjectionChainAlert> {
        if !is_process_injection_api(event.api.as_deref()) {
            return None;
        }

        let target_pid = event.target_pid?;
        if event.pid == 0
            || event.pid == 4
            || event.pid == u32::MAX
            || target_pid == 0
            || target_pid == 4
            || target_pid == u32::MAX
            || event.pid == target_pid
        {
            return None;
        }

        let now = hook_event_timestamp_ms(event);
        self.prune(now);

        let key = (event.pid, target_pid);
        let state = self
            .chains
            .entry(key)
            .or_insert_with(|| InjectionChainState {
                started_at: now,
                last_seen: now,
                ..InjectionChainState::default()
            });

        if now.saturating_sub(state.started_at) > self.window_ms {
            *state = InjectionChainState {
                started_at: now,
                last_seen: now,
                ..InjectionChainState::default()
            };
        }

        let api = event
            .api
            .clone()
            .unwrap_or_else(|| event.event_type.clone());
        let api_lower = api.to_ascii_lowercase();
        state.last_seen = now;
        state.desired_access = event.desired_access.or(state.desired_access);
        state.base_address = event
            .base_address
            .clone()
            .or_else(|| state.base_address.clone());
        state.size = event.size.or(state.size);
        state.start_address = event
            .start_address
            .clone()
            .or_else(|| state.start_address.clone());
        state.blocked_by_hook |= event.blocked.unwrap_or(false);
        state.target_suspended_by_hook |= event.target_suspended.unwrap_or(false);

        if state.apis.last() != Some(&api) {
            state.apis.push(api.clone());
            if state.apis.len() > 12 {
                state.apis.remove(0);
            }
        }

        if api_lower == "openprocess" {
            state.saw_open_process = true;
        } else if api_lower == "virtualallocex" {
            state.saw_virtual_alloc_ex = true;
        } else if api_lower == "writeprocessmemory" {
            state.saw_write_process_memory = true;
        } else if api_lower == "createremotethread" || api_lower == "createremotethreadex" {
            state.saw_create_remote_thread = true;
        }

        let has_full_chain = state.saw_create_remote_thread
            && state.saw_write_process_memory
            && (state.saw_virtual_alloc_ex || state.saw_open_process);
        let native_hook_already_blocked = state.saw_create_remote_thread && state.blocked_by_hook;

        if has_full_chain || native_hook_already_blocked {
            let alert = InjectionChainAlert {
                source_pid: event.pid,
                target_pid,
                apis: state.apis.clone(),
                started_at: state.started_at,
                last_seen: state.last_seen,
                blocked_by_hook: state.blocked_by_hook,
                target_suspended_by_hook: state.target_suspended_by_hook,
                desired_access: state.desired_access,
                base_address: state.base_address.clone(),
                size: state.size,
                start_address: state.start_address.clone(),
            };
            self.chains.remove(&key);
            return Some(alert);
        }

        if self.chains.len() > self.max_tracked {
            self.drop_oldest();
        }
        None
    }

    fn prune(&mut self, now: u64) {
        let window_ms = self.window_ms;
        self.chains
            .retain(|_, state| now.saturating_sub(state.last_seen) <= window_ms);
    }

    fn drop_oldest(&mut self) {
        if let Some(oldest_key) = self
            .chains
            .iter()
            .min_by_key(|(_, state)| state.last_seen)
            .map(|(key, _)| *key)
        {
            self.chains.remove(&oldest_key);
        }
    }
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
    server_threads: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    injection_tracker: Arc<Mutex<InjectionChainTracker>>,
}

impl HookService {
    pub fn new() -> Self {
        Self {
            tx: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            server_threads: Arc::new(Mutex::new(Vec::new())),
            injection_tracker: Arc::new(Mutex::new(InjectionChainTracker::default())),
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
    /// 返回值说明：成功返回 Hook 事件接收器；已经启动时返回一个空接收器以保持启动命令幂等；失败返回 String。
    /// Returns: Hook event receiver on success; when already running returns an empty receiver so start commands are idempotent; String error on failure.
    /// 错误处理：重复启动幂等成功；单条事件分发失败记录错误后继续服务；管道等待采用短轮询，避免 stop 无法打断阻塞等待。
    /// Error handling: Duplicate start succeeds idempotently; per-event dispatch errors are logged and the service continues; pipe waits use short polling so stop can interrupt waits.
    /// 中文关键词：启动管道，接收事件，文件钩子启动，事件分发，风险链路，可停止线程
    /// English keywords: start pipe, receive events, file hook start, event dispatch, risk pipeline, stoppable thread
    pub fn start(
        &self,
        pipe_name: &str,
        app_handle: AppHandle,
    ) -> Result<mpsc::UnboundedReceiver<FileHookEvent>, String> {
        if self.running.load(Ordering::SeqCst) {
            let (_tx, rx) = mpsc::unbounded_channel::<FileHookEvent>();
            return Ok(rx);
        }

        let mut tx_guard = self.tx.lock().map_err(|e| e.to_string())?;
        let mut server_thread_guard = self.server_threads.lock().map_err(|e| e.to_string())?;
        if !server_thread_guard.is_empty() {
            return Err("Hook service is still stopping".to_string());
        }

        let (tx, rx) = mpsc::unbounded_channel::<FileHookEvent>();
        *tx_guard = Some(tx);

        let full_pipe_name = format!(r"\\.\pipe\{}", pipe_name);
        self.running.store(true, Ordering::SeqCst);

        eprintln!(
            "[HookService] Starting named pipe server: {} (workers={})",
            full_pipe_name, HOOK_PIPE_WORKER_COUNT
        );
        for worker_index in 0..HOOK_PIPE_WORKER_COUNT {
            let running = self.running.clone();
            let injection_tracker = self.injection_tracker.clone();
            let worker_pipe_name = full_pipe_name.clone();
            let worker_app_handle = app_handle.clone();
            let handle = thread::spawn(move || {
                append_interception_diagnostic(
                    "hook_pipe_worker_started",
                    serde_json::json!({
                        "workerIndex": worker_index,
                        "pipeName": worker_pipe_name.clone(),
                    }),
                );
                while running.load(Ordering::SeqCst) {
                    match serve_pipe_connection(&worker_pipe_name, &running, worker_index) {
                        Ok(events) => {
                            for event in events {
                                if let Err(err) = dispatch_hook_event(
                                    &worker_app_handle,
                                    event,
                                    &injection_tracker,
                                ) {
                                    eprintln!("[HookService] Event dispatch error: {}", err);
                                }
                            }
                        }
                        Err(e) => {
                            append_interception_diagnostic(
                                "hook_pipe_worker_error",
                                serde_json::json!({
                                    "workerIndex": worker_index,
                                    "error": e.clone(),
                                }),
                            );
                            eprintln!(
                                "[HookService] Pipe worker {} connection error: {}",
                                worker_index, e
                            );
                            thread::sleep(Duration::from_millis(100));
                        }
                    }
                }
                eprintln!("[HookService] Named pipe worker {} stopped", worker_index);
            });
            server_thread_guard.push(handle);
        }

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

        let handles = {
            let mut server_thread_guard = self.server_threads.lock().map_err(|e| e.to_string())?;
            std::mem::take(&mut *server_thread_guard)
        };

        let mut remaining_handles = Vec::new();
        for handle in handles {
            match wait_for_hook_thread_stop(
                handle,
                Duration::from_millis(HOOK_SERVICE_STOP_JOIN_TIMEOUT_MS),
            )? {
                Some(handle) => {
                    remaining_handles.push(handle);
                }
                None => {}
            }
        }
        if !remaining_handles.is_empty() {
            let remaining_count = remaining_handles.len();
            *self.server_threads.lock().map_err(|e| e.to_string())? = remaining_handles;
            return Err(format!(
                "{} Hook service worker(s) did not stop within {} ms",
                remaining_count, HOOK_SERVICE_STOP_JOIN_TIMEOUT_MS
            ));
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
        .or_else(|| event.process_path.as_deref().and_then(file_name_from_path))
        .unwrap_or_else(|| format!("PID {}", event.pid));
    let operation = event
        .api
        .clone()
        .unwrap_or_else(|| event.event_type.clone());
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
        "processPath": event.process_path.clone(),
        "targetPid": event.target_pid,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "timestampMs": timestamp_ms,
        "details": {
            "eventType": event.event_type.clone(),
            "api": event.api.clone(),
            "source": event.source.clone(),
            "targetPath": event.target_path.clone(),
            "processPath": event.process_path.clone(),
            "targetPid": event.target_pid,
            "desiredAccess": event.desired_access,
            "baseAddress": event.base_address.clone(),
            "startAddress": event.start_address.clone(),
            "size": event.size,
            "blocked": event.blocked,
            "targetSuspended": event.target_suspended,
            "lastError": event.last_error,
            "chain": event.chain.clone(),
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
    let is_injection_api = is_process_injection_api(Some(operation));
    let severity = if normalized_operation.contains("createfile") {
        45
    } else if is_injection_api {
        // 单个注入相关 API 只入库/上报，不直接交给 RiskService 自动挂起；
        // 真正拦截由 InjectionChainTracker 在完整链路命中后执行。
        20
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
        file_path: if is_injection_api {
            None
        } else if event.path.is_empty() {
            event.process_path.clone()
        } else {
            Some(event.path.clone())
        },
        threat_type: if is_injection_api {
            "api_hook_process_activity".to_string()
        } else {
            "file_hook_activity".to_string()
        },
        threat_name: Some(operation.to_string()),
        severity,
        rule_id: if is_injection_api {
            "API_HOOK_PROCESS_ACTIVITY".to_string()
        } else {
            "FILE_HOOK_ACTIVITY".to_string()
        },
        description: if is_injection_api {
            format!(
                "APIHook captured {} from PID {} to target PID {:?}",
                operation, event.pid, event.target_pid
            )
        } else {
            format!("File hook captured {} on {}", operation, event.path)
        },
        timestamp: app_event
            .get("timestampMs")
            .and_then(|v| v.as_u64())
            .unwrap_or(event.timestamp),
    }
}

fn dispatch_hook_event(
    app_handle: &AppHandle,
    event: FileHookEvent,
    injection_tracker: &Arc<Mutex<InjectionChainTracker>>,
) -> Result<(), String> {
    if is_process_injection_api(event.api.as_deref())
        || event.source.as_deref() == Some("detours_process_injection")
    {
        append_interception_diagnostic(
            "hook_event_received",
            serde_json::json!({
                "sourcePid": event.pid,
                "targetPid": event.target_pid,
                "api": event.api.clone(),
                "source": event.source.clone(),
                "blocked": event.blocked,
                "targetSuspended": event.target_suspended,
                "lastError": event.last_error,
                "chain": event.chain.clone(),
                "processName": event.process_name.clone(),
                "processPath": event.process_path.clone(),
            }),
        );
        eprintln!(
            "[HookService] Received process-injection hook event: source_pid={}, target_pid={:?}, api={:?}, blocked={:?}, target_suspended={:?}",
            event.pid, event.target_pid, event.api, event.blocked, event.target_suspended
        );
    }

    if should_drop_system_hook_event(&event) {
        append_interception_diagnostic(
            "hook_event_dropped",
            serde_json::json!({
                "reason": "system_or_invalid_source_pid",
                "sourcePid": event.pid,
                "targetPid": event.target_pid,
                "api": event.api.clone(),
            }),
        );
        return Ok(());
    }

    let injection_alert = {
        let mut tracker = injection_tracker.lock().map_err(|e| e.to_string())?;
        tracker.record(&event)
    };
    let direct_blocked_alert = if injection_alert.is_none() {
        InjectionChainAlert::from_blocked_hook_event(&event)
    } else {
        None
    };
    if let Some(alert) = injection_alert.or(direct_blocked_alert) {
        append_interception_diagnostic(
            "injection_chain_alert",
            serde_json::json!({
                "sourcePid": alert.source_pid,
                "targetPid": alert.target_pid,
                "apis": alert.apis.clone(),
                "blockedByHook": alert.blocked_by_hook,
                "targetSuspendedByHook": alert.target_suspended_by_hook,
                "desiredAccess": alert.desired_access,
                "baseAddress": alert.base_address.clone(),
                "size": alert.size,
                "startAddress": alert.start_address.clone(),
            }),
        );
        enqueue_injection_target_interception(app_handle, &event, alert);
    }

    let app_event = hook_event_to_app_event(&event);

    let _ = logs::append_event_log_and_emit(app_handle, &app_event);
    if !app_is_exiting(app_handle) {
        let _ = app_handle.emit("etw-event", app_event.clone());
        let _ = app_handle.emit("file-hook-event", app_event.clone());
    }

    if let Some(behavior_state) = app_handle.try_state::<Arc<std::sync::Mutex<BehaviorService>>>() {
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
            let trust_state = app_handle_risk.try_state::<Arc<TrustService>>();
            let trust_service = trust_state.as_ref().map(|state| state.inner().as_ref());

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

fn enqueue_injection_target_interception(
    app_handle: &AppHandle,
    event: &FileHookEvent,
    alert: InjectionChainAlert,
) {
    append_interception_diagnostic(
        "injection_target_interception_requested",
        serde_json::json!({
            "sourcePid": alert.source_pid,
            "targetPid": alert.target_pid,
            "api": event.api.clone(),
            "blockedByHook": alert.blocked_by_hook,
            "targetSuspendedByHook": alert.target_suspended_by_hook,
        }),
    );
    eprintln!(
        "[HookService] Injection target interception requested: source_pid={}, target_pid={}, api={:?}, blocked={}, target_suspended={}",
        alert.source_pid,
        alert.target_pid,
        event.api,
        alert.blocked_by_hook,
        alert.target_suspended_by_hook
    );

    if app_is_exiting(app_handle) {
        append_interception_diagnostic(
            "injection_target_interception_skipped",
            serde_json::json!({
                "reason": "app_exiting",
                "sourcePid": alert.source_pid,
                "targetPid": alert.target_pid,
                "preSuspended": alert.target_suspended_by_hook,
            }),
        );
        if alert.target_suspended_by_hook {
            rollback_pre_suspended_injection_target(alert.target_pid, "app exiting");
        }
        return;
    }

    let source_process_path = event.process_path.clone().or_else(|| {
        query_process_identity(alert.source_pid)
            .ok()
            .map(|identity| identity.image_path)
    });
    let source_process_name = event
        .process_name
        .clone()
        .or_else(|| source_process_path.as_deref().and_then(file_name_from_path))
        .unwrap_or_else(|| format!("PID {}", alert.source_pid));

    let target_identity = query_process_identity(alert.target_pid).ok();
    let target_process_path = target_identity
        .as_ref()
        .map(|identity| identity.image_path.clone());
    let target_process_name = target_process_path
        .as_deref()
        .and_then(file_name_from_path)
        .unwrap_or_else(|| format!("PID {}", alert.target_pid));

    let reason = if alert.target_suspended_by_hook {
        "检测到远程线程注入行为链，APIHook 已在远程线程创建前挂起被注入目标进程，等待用户处理。"
    } else if alert.blocked_by_hook {
        "检测到远程线程注入行为链，APIHook 已阻断远程线程创建，并尝试挂起被注入目标进程。"
    } else {
        "检测到注入源头行为链：OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread，疑似远程线程注入。"
    };

    let payload = serde_json::json!({
        "source": "api_hook_process_injection_chain",
        "sourcePid": alert.source_pid,
        "targetPid": alert.target_pid,
        "apis": alert.apis,
        "windowMs": alert.last_seen.saturating_sub(alert.started_at),
        "blockedByHook": alert.blocked_by_hook,
        "targetSuspendedByHook": alert.target_suspended_by_hook,
        "desiredAccess": alert.desired_access,
        "baseAddress": alert.base_address,
        "size": alert.size,
        "startAddress": alert.start_address,
        "sourceProcessName": source_process_name,
        "sourceProcessPath": source_process_path.clone(),
        "targetProcessPath": target_process_path.clone(),
    });

    if let Some(interception) = app_handle.try_state::<Arc<InterceptionService>>() {
        let entry = InterceptionEntry {
            pid: alert.target_pid,
            process_name: target_process_name,
            file_path: target_process_path.unwrap_or_default(),
            risk_level: "high".to_string(),
            threat_type: Some("remote_thread_injection_target".to_string()),
            reason: reason.to_string(),
            payload: Some(payload.to_string()),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        if alert.target_suspended_by_hook && is_current_process_or_ancestor(alert.target_pid) {
            append_interception_diagnostic(
                "interception_enqueue_result",
                serde_json::json!({
                    "result": "RejectedBeforeEnqueue",
                    "reason": "protected_control_chain",
                    "sourcePid": alert.source_pid,
                    "targetPid": alert.target_pid,
                    "preSuspended": true,
                }),
            );
            eprintln!(
                "[HookService] APIHook suspended protected AnXin control-chain target PID {}, rolling back",
                alert.target_pid
            );
            rollback_pre_suspended_injection_target(alert.target_pid, "protected control chain");
        } else {
            let enqueue_result = if alert.target_suspended_by_hook {
                interception.enqueue_pre_suspended(entry)
            } else {
                interception.enqueue(entry)
            };

            if alert.target_suspended_by_hook
                && !enqueue_result.is_enqueued()
                && !enqueue_result.rollback_performed()
            {
                rollback_pre_suspended_injection_target(alert.target_pid, "enqueue rejection");
            }

            append_interception_diagnostic(
                "interception_enqueue_result",
                serde_json::json!({
                    "result": format!("{:?}", enqueue_result),
                    "sourcePid": alert.source_pid,
                    "targetPid": alert.target_pid,
                    "preSuspended": alert.target_suspended_by_hook,
                }),
            );

            if enqueue_result.is_enqueued() {
                eprintln!(
                    "[HookService] Injection target queued for interception window: target_pid={}, source_pid={}, pre_suspended={}",
                    alert.target_pid, alert.source_pid, alert.target_suspended_by_hook
                );
                interception.try_show_next(app_handle);
            } else {
                eprintln!(
                    "[HookService] Injection target was not queued: target_pid={}, source_pid={}, result={:?}",
                    alert.target_pid, alert.source_pid, enqueue_result
                );
            }
        }
    } else if alert.target_suspended_by_hook {
        append_interception_diagnostic(
            "interception_enqueue_result",
            serde_json::json!({
                "result": "RejectedBeforeEnqueue",
                "reason": "missing_interception_service",
                "sourcePid": alert.source_pid,
                "targetPid": alert.target_pid,
                "preSuspended": true,
            }),
        );
        rollback_pre_suspended_injection_target(alert.target_pid, "missing interception service");
    }

    if let Some(scanner) = app_handle.try_state::<ProcessScannerService>() {
        scanner.mark_hot_pid(alert.source_pid, "api_hook_injection_source");
        scanner.mark_hot_pid(alert.target_pid, "api_hook_injection_target");
    }
}

fn rollback_pre_suspended_injection_target(pid: u32, reason: &str) {
    if let Err(err) = resume_process_by_pid(pid) {
        eprintln!(
            "[HookService] Failed to roll back pre-suspended injection target PID {} after {}: {}",
            pid, reason, err
        );
    }
}

/// 函数名称：should_drop_system_hook_event
/// 函数作用：判断文件 Hook 事件是否来自系统或无效 PID，避免系统进程噪音进入日志和风险链路。
/// Purpose: Returns whether a file hook event belongs to system/invalid PIDs and should be dropped.
/// 中文关键词：Hook过滤，PID过滤，系统噪音
/// English keywords: hook filter, PID filter, system noise
fn should_drop_system_hook_event(event: &FileHookEvent) -> bool {
    matches!(event.pid, 0 | 4) || event.pid == u32::MAX
}

fn hook_event_timestamp_ms(event: &FileHookEvent) -> u64 {
    if event.timestamp == 0 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    } else {
        event.timestamp
    }
}

fn is_process_injection_api(api: Option<&str>) -> bool {
    matches!(
        api.map(|value| value.to_ascii_lowercase()),
        Some(value)
            if matches!(
                value.as_str(),
                "openprocess"
                    | "virtualallocex"
                    | "writeprocessmemory"
                    | "createremotethread"
                    | "createremotethreadex"
            )
    )
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

fn diagnostic_preview(input: &str, max_chars: usize) -> String {
    let mut preview: String = input.chars().take(max_chars).collect();
    if input.chars().count() > max_chars {
        preview.push_str("...");
    }
    preview
}

fn should_diagnose_hook_pipe_raw(message: &str) -> bool {
    message.contains(r#""source":"detours_process_injection""#)
        || message.contains(r#""api":"OpenProcess""#)
        || message.contains(r#""api":"VirtualAllocEx""#)
        || message.contains(r#""api":"WriteProcessMemory""#)
        || message.contains(r#""api":"CreateRemoteThread""#)
        || message.contains(r#""api":"CreateRemoteThreadEx""#)
        || message.contains(r#""blocked":true"#)
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
    worker_index: usize,
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
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
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
            PIPE_UNLIMITED_INSTANCES,
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
            thread::sleep(Duration::from_millis(HOOK_PIPE_POLL_MS));
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
    let mut empty_read_polls: u32 = 0;
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
                empty_read_polls = empty_read_polls.saturating_add(1);
                if empty_read_polls >= HOOK_PIPE_MAX_EMPTY_READ_POLLS {
                    append_interception_diagnostic(
                        "hook_pipe_read_timeout",
                        serde_json::json!({
                            "workerIndex": worker_index,
                            "errorCode": error_code,
                            "emptyPolls": empty_read_polls,
                        }),
                    );
                    break;
                }
                thread::sleep(Duration::from_millis(HOOK_PIPE_POLL_MS));
                continue;
            }
            if error_code == ERROR_BROKEN_PIPE || error_code == ERROR_PIPE_NOT_CONNECTED {
                break;
            }
            append_interception_diagnostic(
                "hook_pipe_read_error",
                serde_json::json!({
                    "workerIndex": worker_index,
                    "errorCode": error_code,
                    "bytesRead": bytes_read,
                }),
            );
            break;
        }

        let msg = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
        let should_diagnose_raw = should_diagnose_hook_pipe_raw(&msg);
        if should_diagnose_raw {
            append_interception_diagnostic(
                "hook_pipe_raw_message_received",
                serde_json::json!({
                    "workerIndex": worker_index,
                    "bytesRead": bytes_read,
                    "lineCount": msg.lines().count(),
                    "rawPreview": diagnostic_preview(&msg, HOOK_PIPE_RAW_PREVIEW_CHARS),
                }),
            );
        }
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
                Ok(Some(HookPipeMessage::Event(event))) => {
                    if is_process_injection_api(event.api.as_deref())
                        || event.source.as_deref() == Some("detours_process_injection")
                    {
                        append_interception_diagnostic(
                            "hook_pipe_line_parsed",
                            serde_json::json!({
                                "workerIndex": worker_index,
                                "messageType": "event",
                                "sourcePid": event.pid,
                                "targetPid": event.target_pid,
                                "api": event.api.clone(),
                                "source": event.source.clone(),
                                "blocked": event.blocked,
                                "targetSuspended": event.target_suspended,
                            }),
                        );
                    }
                    events.push(event)
                }
                Ok(None) => {}
                Err(err) => {
                    append_interception_diagnostic(
                        "hook_pipe_line_parse_error",
                        serde_json::json!({
                            "workerIndex": worker_index,
                            "error": err.clone(),
                            "linePreview": diagnostic_preview(line, HOOK_PIPE_RAW_PREVIEW_CHARS),
                        }),
                    );
                    eprintln!("[HookService] Failed to parse hook pipe line: {}", err);
                }
            }
        }
        // file_hook_detours.dll 的上报模型是“一条消息一个短连接”：
        // CreateFile/OpenProcess/VirtualAllocEx/WriteProcessMemory/CreateRemoteThread 会快速连续
        // 打开管道、写一行 JSON、关闭管道。服务端读到当前批次后应立即释放本 pipe 实例，
        // 让外层循环马上创建下一根管道；否则继续在同一实例上空等，会让后续连接在
        // WaitNamedPipeW 处撞到 ERROR_SEM_TIMEOUT(121)。
        //
        // The native hook uses one short pipe connection per message. After reading the current
        // batch, close this pipe instance promptly so the outer loop can create the next instance.
        break;
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

    #[test]
    fn hook_pipe_raw_diagnostic_filter_focuses_process_injection_messages() {
        assert!(should_diagnose_hook_pipe_raw(
            r#"{"type":"hook_notice","source":"detours_process_injection","api":"OpenProcess","pid":5100,"targetPid":6200}"#
        ));
        assert!(should_diagnose_hook_pipe_raw(
            r#"{"type":"hook_notice","api":"CreateRemoteThread","pid":5100,"targetPid":6200,"blocked":true}"#
        ));
        assert!(!should_diagnose_hook_pipe_raw(
            r#"{"type":"heartbeat","pid":4242,"ts":10}"#
        ));
        assert!(!should_diagnose_hook_pipe_raw(
            r#"{"type":"hook_notice","api":"CreateFileW","pid":4242,"path":"C:\\temp\\sample.txt"}"#
        ));
    }

    #[test]
    fn system_pid_hook_events_are_dropped_before_dispatch() {
        let mut event = FileHookEvent {
            event_type: "hook_notice".to_string(),
            source: Some("detours_createfile".to_string()),
            api: Some("CreateFileW".to_string()),
            path: "C:\\Windows\\System32\\kernel.dat".to_string(),
            target_path: None,
            pid: 0,
            tid: 1,
            process_name: None,
            process_path: None,
            target_pid: None,
            desired_access: None,
            base_address: None,
            start_address: None,
            size: None,
            blocked: None,
            target_suspended: None,
            last_error: None,
            chain: None,
            timestamp: 123456,
        };

        assert!(should_drop_system_hook_event(&event));

        event.pid = 4;
        assert!(should_drop_system_hook_event(&event));

        event.pid = u32::MAX;
        assert!(should_drop_system_hook_event(&event));

        event.pid = 47216;
        assert!(!should_drop_system_hook_event(&event));
    }
}
