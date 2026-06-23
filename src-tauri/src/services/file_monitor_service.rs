// 文件监控服务 — 从 ETW 事件流中捕获文件创建/修改事件，调用 Axon 引擎扫描
// File monitoring service — captures file create/modify events from ETW event stream, calls Axon engine to scan
//
// 通过订阅 ETW 广播频道，过滤文件操作事件，提取文件路径后调用扫描引擎检测。
// Subscribes to ETW broadcast channel, filters file operation events, extracts file path, and calls scan engine.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::time;

use crate::services::app_lifecycle_service::app_is_exiting;
use crate::services::engine_service::EngineService;
use crate::services::interception_service::{InterceptionEntry, InterceptionService};
use crate::services::path_policy_service::should_skip_security_scan;
use crate::services::process_scanner_service::{
    file_name_from_path, query_process_image_path, scan_confidence, scan_result_is_malware,
    scan_threat_type, ProcessScannerService,
};
use crate::services::scan_result_cache_service::{CachedScanResult, ScanResultCacheService};
use tauri::{AppHandle, Manager, Runtime};

const FILE_MONITOR_STOP_POLL_MS: u64 = 250;
const FILE_MONITOR_LAG_LOG_INTERVAL_SECS: u64 = 10;

// `tokio::spawn` 在 setup 阶段不可用，改用 Tauri 的 async_runtime
// tokio::spawn is unavailable during setup, use tauri's async_runtime instead
fn spawn_task<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tauri::async_runtime::spawn(fut);
}

/// 文件监控服务
/// File monitoring service
pub struct FileMonitorService {
    running: Arc<AtomicBool>,
}

impl FileMonitorService {
    /// 函数名称：new
    /// 函数作用：创建文件监控服务实例。
    /// Purpose: Creates a new FileMonitorService instance.
    /// 中文关键词：文件监控，创建服务，初始化
    /// English keywords: file monitoring, create service, initialization
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 函数名称：start
    /// 函数作用：启动文件监控后台任务；文件事件扫描前实时读取排除项和允许列表，命中时跳过扫描。
    /// Function name: start
    /// Purpose: Starts the file monitoring background task; reads exclusions and allowlist before file-event scans and skips matching paths.
    ///
    /// 订阅 ETW 广播频道，过滤文件创建/写入/重命名事件，
    /// 对事件中的文件路径调用 Axon 引擎进行恶意代码检测。
    /// Subscribes to the ETW broadcast channel, filters file create/write/rename events,
    /// and calls the Axon engine to perform malware detection on the event file paths.
    ///
    /// 调用方：main.rs（应用启动时初始化）
    /// Called by: main.rs (initialized on app startup)
    ///
    /// 参数：
    ///   engine: 引擎服务引用（用于执行扫描）
    ///   etw_rx: ETW 事件广播接收器
    ///
    /// 副作用：
    ///   启动后台 Tokio 任务，持续监听 ETW 事件并调用引擎扫描文件
    ///   接收事件时使用短超时轮询，确保 stop() 修改运行标志后后台任务能及时醒来退出
    ///
    /// 中文关键词：启动监控，文件事件，ETW事件，引擎扫描，文件检测，排除项生效，允许列表生效，跳过扫描，运行时列表，实时保护
    /// English keywords: start monitoring, file events, ETW events, engine scan, file detection, exclusion effective, allowlist effective, skip scan, runtime list, realtime protection, stoppable receive
    pub fn start<R: Runtime>(
        &self,
        engine: Arc<EngineService>,
        cache: Arc<ScanResultCacheService>,
        interception: Arc<InterceptionService>,
        app_handle: AppHandle<R>,
        etw_rx: broadcast::Receiver<String>,
    ) {
        if self.running.load(Ordering::SeqCst) {
            eprintln!("[FileMonitor] Already running");
            return;
        }
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();

        spawn_task(async move {
            eprintln!("[FileMonitor] Started, listening for ETW file events");
            let mut rx = etw_rx;
            let mut lagged_since_last_log = 0u64;
            let mut last_lag_log = Instant::now()
                .checked_sub(Duration::from_secs(FILE_MONITOR_LAG_LOG_INTERVAL_SECS))
                .unwrap_or_else(Instant::now);

            while running.load(Ordering::SeqCst) {
                match time::timeout(file_monitor_stop_poll_interval(), rx.recv()).await {
                    Err(_) => {
                        continue;
                    }
                    Ok(Ok(json_str)) => {
                        if !running.load(Ordering::SeqCst) {
                            break;
                        }
                        // 解析事件 JSON，判断是否为文件操作事件
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                            if let Some(file_path) = extract_file_path_from_etw_event(&val) {
                                match should_skip_security_scan(&file_path) {
                                    Ok(true) => {
                                        continue;
                                    }
                                    Ok(false) => {}
                                    Err(e) => {
                                        eprintln!(
                                            "[FileMonitor] Failed to load path policy for {}: {}",
                                            file_path, e
                                        );
                                    }
                                }

                                match cache.scan_or_get_cached(&engine, &file_path).await {
                                    Ok(scan_result) => {
                                        if scan_result_is_malware(&scan_result.raw_result) {
                                            let confidence =
                                                scan_confidence(&scan_result.raw_result);
                                            eprintln!(
                                                "[FileMonitor] MALWARE DETECTED in file: {}, confidence={}, cacheHit={}",
                                                file_path, confidence, scan_result.cache_hit
                                            );
                                            direct_intercept_malicious_file_writer(
                                                &interception,
                                                &app_handle,
                                                &val,
                                                &file_path,
                                                &scan_result,
                                            );
                                            mark_hot_pid_for_file_event(
                                                &app_handle,
                                                &val,
                                                "file_monitor_malicious_write",
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "[FileMonitor] Scan failed for {}: {}",
                                            file_path, e
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                        lagged_since_last_log = lagged_since_last_log.saturating_add(n);
                        if last_lag_log.elapsed()
                            >= Duration::from_secs(FILE_MONITOR_LAG_LOG_INTERVAL_SECS)
                        {
                            eprintln!(
                                "[FileMonitor] Lagged by {} file-monitor events in the last {}s",
                                lagged_since_last_log, FILE_MONITOR_LAG_LOG_INTERVAL_SECS
                            );
                            lagged_since_last_log = 0;
                            last_lag_log = Instant::now();
                        }
                    }
                    Ok(Err(broadcast::error::RecvError::Closed)) => {
                        eprintln!("[FileMonitor] ETW channel closed, stopping");
                        break;
                    }
                }
            }

            eprintln!("[FileMonitor] Stopped");
        });
    }

    /// 函数名称：stop
    /// 函数作用：停止文件监控后台任务；后台接收循环最多等待一个短轮询周期后退出。
    /// Purpose: Stops the file monitoring background task; the receive loop exits after at most one short polling interval.
    /// 中文关键词：停止监控，停止文件监控，可停止接收
    /// English keywords: stop monitoring, stop file monitoring, stoppable receive
    #[allow(dead_code)]
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        eprintln!("[FileMonitor] Stop requested");
    }

    /// 函数名称：is_running
    /// 函数作用：检查文件监控服务是否正在运行。
    /// Purpose: Checks if the file monitoring service is running.
    /// 中文关键词：运行状态，检查运行
    /// English keywords: running status, check running
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// 函数名称：direct_intercept_malicious_file_writer
/// 函数作用：文件实时扫描命中恶意后，直接拦截触发文件写入/创建事件的来源 PID。
/// Function name: direct_intercept_malicious_file_writer
/// Purpose: Directly intercepts the source PID that wrote/created a malicious file in realtime.
fn direct_intercept_malicious_file_writer<R: Runtime>(
    interception: &Arc<InterceptionService>,
    app_handle: &AppHandle<R>,
    event: &serde_json::Value,
    file_path: &str,
    scan_result: &CachedScanResult,
) {
    if app_is_exiting(app_handle) {
        return;
    }

    let Some(pid) = file_event_pid(event) else {
        return;
    };
    if pid == 0 || pid == 4 || pid == u32::MAX || pid == std::process::id() {
        return;
    }

    let process_path = query_process_image_path(pid).unwrap_or_default();
    let process_name = file_name_from_path(&process_path)
        .or_else(|| process_name_from_file_event(event))
        .unwrap_or_else(|| format!("PID {}", pid));
    let confidence = scan_confidence(&scan_result.raw_result);
    let payload = serde_json::json!({
        "source": "file_monitor_realtime_preblock",
        "targetType": "file_write_source_process",
        "maliciousFilePath": file_path,
        "processPath": process_path,
        "sha256": scan_result.hash_hex,
        "cacheHit": scan_result.cache_hit,
        "rawResult": scan_result.raw_result,
    });
    let entry = InterceptionEntry {
        pid,
        process_name,
        file_path: if process_path.is_empty() {
            file_path.to_string()
        } else {
            process_path
        },
        risk_level: "high".to_string(),
        threat_type: scan_threat_type(&scan_result.raw_result)
            .or_else(|| Some("malicious_file_write".to_string())),
        reason: format!(
            "实时文件监控发现该进程写入恶意文件：{}，confidence={}",
            file_path, confidence
        ),
        payload: Some(payload.to_string()),
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
    };

    interception.enqueue(entry);
    interception.try_show_next(app_handle);
}

fn mark_hot_pid_for_file_event<R: Runtime>(
    app_handle: &AppHandle<R>,
    event: &serde_json::Value,
    source: &str,
) {
    let Some(pid) = file_event_pid(event) else {
        return;
    };
    if let Some(scanner) = app_handle.try_state::<ProcessScannerService>() {
        scanner.mark_hot_pid(pid, source);
    }
}

/// 函数名称：file_monitor_stop_poll_interval
/// 函数作用：返回文件监控后台任务检查 stop 标志的最大等待间隔。
/// Purpose: Returns the maximum wait interval before the file monitor background task checks the stop flag.
/// 调用方：FileMonitorService::start，文件监控单元测试。
/// Called by: FileMonitorService::start, file monitor unit tests.
/// 返回值说明：返回短轮询 Duration，避免 recv().await 无限等待。
/// Returns: Short polling Duration that prevents recv().await from waiting forever.
/// 中文关键词：文件监控，停止轮询，阻塞防护
/// English keywords: file monitor, stop polling, blocking guard
fn file_monitor_stop_poll_interval() -> Duration {
    Duration::from_millis(FILE_MONITOR_STOP_POLL_MS)
}

/// 函数名称：extract_file_path_from_etw_event
/// 函数作用：从 ETW 事件 JSON 中提取文件路径，兼容 Rust ETW 嵌套事件和旧版顶层 provider/operation/path 事件。
/// Purpose: Extracts file path from ETW event JSON, supporting both nested Rust ETW events and legacy top-level provider/operation/path events.
///
/// 检查事件的 provider 是否为 "File"，operation 是否为 create/write/rename/setinfo/create_new，
/// 如果是则从 path/filePath/fileName 或 event.data.fileName 中返回路径。
/// Checks if the provider is "File" and operation is create/write/rename/setinfo/create_new,
/// then returns path from path/filePath/fileName or event.data.fileName.
///
/// 调用方：FileMonitorService::start，etw_file_monitor_tests。
/// Called by: FileMonitorService::start, etw_file_monitor_tests.
/// 参数说明：val 为已解析的 ETW JSON 值。
/// Parameters: val is the parsed ETW JSON value.
/// 返回值说明：文件事件且路径非空时返回 Some(path)，否则返回 None。
/// Returns: Some(path) when the JSON is a file event with a non-empty path; otherwise None.
/// 错误处理：缺失字段或未知结构直接返回 None，不 panic。
/// Error handling: Missing fields or unknown shapes return None without panicking.
/// 中文关键词：文件路径提取，ETW事件解析，文件操作过滤，嵌套事件兼容
/// English keywords: file path extraction, ETW event parsing, file operation filter, nested event compatibility
pub fn extract_file_path_from_etw_event(val: &serde_json::Value) -> Option<String> {
    let provider = string_at_any(val, &[&["provider"], &["event", "provider"]]).unwrap_or("");
    if !provider.eq_ignore_ascii_case("File") {
        return None;
    }

    let operation = extract_file_operation(val)?;

    if !is_file_scan_operation(operation) {
        return None;
    }

    string_at_any(
        val,
        &[
            &["path"],
            &["filePath"],
            &["fileName"],
            &["event", "path"],
            &["event", "filePath"],
            &["event", "fileName"],
            &["event", "data", "path"],
            &["event", "data", "filePath"],
            &["event", "data", "fileName"],
        ],
    )
    .filter(|p| !p.is_empty())
    .map(|s| s.to_string())
}

fn file_event_pid(val: &serde_json::Value) -> Option<u32> {
    val.get("pid")
        .or_else(|| val.get("event").and_then(|event| event.get("pid")))
        .and_then(|value| value.as_u64())
        .filter(|pid| *pid <= u32::MAX as u64)
        .map(|pid| pid as u32)
}

fn process_name_from_file_event(val: &serde_json::Value) -> Option<String> {
    string_at_any(
        val,
        &[
            &["processName"],
            &["event", "processName"],
            &["event", "data", "processName"],
        ],
    )
    .filter(|value| !value.eq_ignore_ascii_case("Unknown"))
    .map(|value| value.to_string())
}

/// 函数名称：extract_file_operation
/// 函数作用：按优先级从旧版顶层字段和 Rust ETW 嵌套 data 字段中提取文件操作名。
/// Purpose: Extracts file operation from legacy top-level fields and nested Rust ETW data fields by priority.
/// 中文关键词：操作提取，ETW嵌套字段，兼容旧格式
/// English keywords: operation extraction, ETW nested fields, legacy compatibility
fn extract_file_operation(val: &serde_json::Value) -> Option<&str> {
    string_at_any(
        val,
        &[
            &["operation"],
            &["op"],
            &["event", "operation"],
            &["event", "op"],
            &["event", "data", "operation"],
            &["event", "data", "op"],
            &["event", "data", "type"],
        ],
    )
    .or_else(|| {
        let event_type = string_at_path(val, &["type"])?;
        if event_type.eq_ignore_ascii_case("log") || event_type.eq_ignore_ascii_case("match") {
            None
        } else {
            Some(event_type)
        }
    })
}

/// 函数名称：is_file_scan_operation
/// 函数作用：判断文件操作是否需要触发实时扫描。
/// Purpose: Determines whether a file operation should trigger real-time scanning.
/// 中文关键词：文件操作过滤，实时扫描，创建写入重命名
/// English keywords: file operation filter, real-time scan, create write rename
fn is_file_scan_operation(operation: &str) -> bool {
    let normalized = operation
        .chars()
        .filter(|ch| !matches!(ch, '_' | '-' | ' '))
        .flat_map(|ch| ch.to_lowercase())
        .collect::<String>();

    matches!(
        normalized.as_str(),
        "create" | "createnew" | "write" | "setinfo" | "rename"
    ) || normalized.contains("create")
        || normalized.contains("write")
}

/// 函数名称：string_at_any
/// 函数作用：按候选路径读取 JSON 字符串字段，返回第一个非空字符串。
/// Purpose: Reads JSON string fields by candidate paths and returns the first non-empty string.
/// 中文关键词：JSON字段读取，候选路径，事件兼容
/// English keywords: JSON field read, candidate paths, event compatibility
fn string_at_any<'a>(val: &'a serde_json::Value, paths: &[&[&str]]) -> Option<&'a str> {
    paths
        .iter()
        .filter_map(|path| string_at_path(val, path))
        .find(|value| !value.is_empty())
}

/// 函数名称：string_at_path
/// 函数作用：从 JSON 对象中按字段路径读取字符串。
/// Purpose: Reads a string from a JSON object by field path.
/// 中文关键词：JSON路径，字符串字段
/// English keywords: JSON path, string field
fn string_at_path<'a>(val: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
    let mut current = val;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn file_monitor_stop_poll_interval_stays_short() {
        assert!(
            file_monitor_stop_poll_interval() <= Duration::from_millis(250),
            "file monitor stop should not wait on ETW events indefinitely"
        );
    }

    #[test]
    fn nested_rust_file_event_extracts_file_name() {
        let event = json!({
            "type": "log",
            "event": {
                "pid": 24680,
                "provider": "File",
                "data": {
                    "type": "create",
                    "processName": "dropper.exe",
                    "fileName": r"C:\Users\Alice\AppData\Local\Temp\dropper.exe"
                }
            }
        });

        assert_eq!(
            extract_file_path_from_etw_event(&event).as_deref(),
            Some(r"C:\Users\Alice\AppData\Local\Temp\dropper.exe")
        );
        assert_eq!(file_event_pid(&event), Some(24680));
        assert_eq!(
            process_name_from_file_event(&event).as_deref(),
            Some("dropper.exe")
        );
    }

    #[test]
    fn legacy_top_level_file_event_still_extracts_path() {
        let event = json!({
            "provider": "File",
            "operation": "Write",
            "path": r"C:\Temp\legacy.bin"
        });

        assert_eq!(
            extract_file_path_from_etw_event(&event).as_deref(),
            Some(r"C:\Temp\legacy.bin")
        );
    }

    #[test]
    fn nested_non_scan_file_operation_is_ignored() {
        let event = json!({
            "type": "log",
            "event": {
                "provider": "File",
                "data": {
                    "type": "open",
                    "fileName": r"C:\Temp\readme.txt"
                }
            }
        });

        assert!(extract_file_path_from_etw_event(&event).is_none());
    }
}
