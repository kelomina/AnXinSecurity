// 文件监控服务 — 从 ETW 事件流中捕获文件创建/修改事件，调用 Axon 引擎扫描
// File monitoring service — captures file create/modify events from ETW event stream, calls Axon engine to scan
//
// 通过订阅 ETW 广播频道，过滤文件操作事件，提取文件路径后调用扫描引擎检测。
// Subscribes to ETW broadcast channel, filters file operation events, extracts file path, and calls scan engine.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::services::engine_service::EngineService;
use crate::services::path_policy_service::should_skip_security_scan;

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
    ///
    /// 中文关键词：启动监控，文件事件，ETW事件，引擎扫描，文件检测，排除项生效，允许列表生效，跳过扫描，运行时列表，实时保护
    /// English keywords: start monitoring, file events, ETW events, engine scan, file detection, exclusion effective, allowlist effective, skip scan, runtime list, realtime protection
    pub fn start(&self, engine: Arc<EngineService>, etw_rx: broadcast::Receiver<String>) {
        if self.running.load(Ordering::SeqCst) {
            eprintln!("[FileMonitor] Already running");
            return;
        }
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();

        spawn_task(async move {
            eprintln!("[FileMonitor] Started, listening for ETW file events");
            let mut rx = etw_rx;

            while running.load(Ordering::SeqCst) {
                match rx.recv().await {
                    Ok(json_str) => {
                        if !running.load(Ordering::SeqCst) {
                            break;
                        }
                        // 解析事件 JSON，判断是否为文件操作事件
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                            if let Some(file_path) = extract_file_path(&val) {
                                eprintln!("[FileMonitor] File event: {}", file_path);

                                match should_skip_security_scan(&file_path) {
                                    Ok(true) => {
                                        eprintln!(
                                            "[FileMonitor] Skipped by exclusions or allowlist: {}",
                                            file_path
                                        );
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

                                match engine.is_malware(&file_path).await {
                                    Ok((is_malware, confidence)) => {
                                        if is_malware {
                                            eprintln!(
                                                "[FileMonitor] MALWARE DETECTED in file: {}, confidence={}",
                                                file_path, confidence
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
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("[FileMonitor] Lagged by {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        eprintln!("[FileMonitor] ETW channel closed, stopping");
                        break;
                    }
                }
            }

            eprintln!("[FileMonitor] Stopped");
        });
    }

    /// 函数名称：stop
    /// 函数作用：停止文件监控后台任务。
    /// Purpose: Stops the file monitoring background task.
    /// 中文关键词：停止监控，停止文件监控
    /// English keywords: stop monitoring, stop file monitoring
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

/// 函数名称：extract_file_path
/// 函数作用：从 ETW 事件 JSON 中提取文件路径（仅限文件创建/写入/重命名事件）。
/// Purpose: Extracts file path from ETW event JSON (only for file create/write/rename events).
///
/// 检查事件的 provider 是否为 "File"，operation 是否为 Create/Write/Rename，
/// 如果是则返回 path 字段。
/// Checks if the event provider is "File" and operation is Create/Write/Rename,
/// then returns the path field.
///
/// 中文关键词：文件路径提取，ETW事件解析，文件操作过滤
/// English keywords: file path extraction, ETW event parsing, file operation filter
fn extract_file_path(val: &serde_json::Value) -> Option<String> {
    let provider = val.get("provider").and_then(|v| v.as_str()).unwrap_or("");
    if !provider.eq_ignore_ascii_case("File") {
        return None;
    }

    let operation = val
        .get("operation")
        .or_else(|| val.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let is_file_op = operation.eq_ignore_ascii_case("Create")
        || operation.eq_ignore_ascii_case("Write")
        || operation.eq_ignore_ascii_case("SetInfo")
        || operation.eq_ignore_ascii_case("Rename")
        || operation.contains("Create")
        || operation.contains("Write");

    if !is_file_op {
        return None;
    }

    val.get("path")
        .or_else(|| val.get("filePath"))
        .or_else(|| val.get("fileName"))
        .and_then(|v| v.as_str())
        .filter(|p| !p.is_empty())
        .map(|s| s.to_string())
}
