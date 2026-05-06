// 进程扫描服务 — 轮询系统进程，对新创建的进程调用 Axon 引擎检测
// Process scanner service — polls system processes, calls Axon engine to scan newly created processes
//
// 与被监控进程无关，专注于对新进程的可执行文件进行恶意代码检测。
// Unrelated to process monitoring; focuses on malware detection of new process executables.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tauri::AppHandle;
use tokio::sync::Mutex as TokioMutex;
use tokio::time;

use crate::services::engine_service::EngineService;
use crate::services::interception_service::{InterceptionEntry, InterceptionService};
use crate::services::path_policy_service::should_skip_security_scan;
use crate::services::scan_result_cache_service::{CachedScanResult, ScanResultCacheService};

// `tokio::spawn` 在 setup 阶段不可用，改用 Tauri 的 async_runtime
// tokio::spawn is unavailable during setup, use tauri's async_runtime instead
fn spawn_task<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tauri::async_runtime::spawn(fut);
}

/// 进程扫描服务
/// Process scanner service
pub struct ProcessScannerService {
    running: Arc<AtomicBool>,
    known_pids: Arc<TokioMutex<HashSet<u32>>>,
}

impl ProcessScannerService {
    /// 函数名称：new
    /// 函数作用：创建进程扫描服务实例。
    /// Purpose: Creates a new ProcessScannerService instance.
    /// 中文关键词：进程扫描，创建服务，初始化
    /// English keywords: process scan, create service, initialization
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            known_pids: Arc::new(TokioMutex::new(HashSet::new())),
        }
    }

    /// 函数名称：start
    /// 函数作用：启动进程扫描后台任务；扫描前实时读取排除项和允许列表，命中时跳过引擎检测。
    /// Function name: start
    /// Purpose: Starts the process scanning background task; reads exclusions and allowlist before scanning and skips matching paths.
    ///
    /// 每隔 interval_ms 轮询一次系统进程列表，对比已记录的 PID 发现新进程，
    /// 对新进程的可执行文件路径调用 Axon 引擎扫描。
    /// Polls the system process list every interval_ms, compares with recorded PIDs to find new processes,
    /// and calls the Axon engine to scan the executable path of each new process.
    ///
    /// 调用方：main.rs（应用启动时初始化）
    /// Called by: main.rs (initialized on app startup)
    ///
    /// 参数：
    ///   engine: 引擎服务引用（用于执行扫描）
    ///   interval_ms: 轮询间隔毫秒数
    ///
    /// 副作用：
    ///   启动后台 Tokio 任务，持续轮询系统进程并调用引擎扫描
    ///
    /// 中文关键词：启动扫描，进程轮询，新进程检测，引擎扫描，排除项生效，允许列表生效，跳过扫描，运行时列表，路径策略，实时监控
    /// English keywords: start scanning, process polling, new process detection, engine scan, exclusion effective, allowlist effective, skip scan, runtime list, path policy, realtime monitor
    pub fn start(
        &self,
        engine: Arc<EngineService>,
        cache: Arc<ScanResultCacheService>,
        interception: Arc<InterceptionService>,
        app_handle: AppHandle,
        interval_ms: u64,
    ) {
        if self.running.load(Ordering::SeqCst) {
            eprintln!("[ProcessScanner] Already running");
            return;
        }
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        let known_pids = self.known_pids.clone();
        let interval = std::cmp::max(interval_ms, 1000);

        spawn_task(async move {
            eprintln!("[ProcessScanner] Started, interval={}ms", interval);

            // 初始填充已知 PID 列表
            let initial = collect_current_pids();
            let mut known = known_pids.lock().await;
            for pid in &initial {
                if *pid > 4 {
                    known.insert(*pid);
                }
            }

            let mut tick = time::interval(Duration::from_millis(interval));
            tick.tick().await; // 跳过第一次立即执行

            while running.load(Ordering::SeqCst) {
                tick.tick().await;

                if !running.load(Ordering::SeqCst) {
                    break;
                }

                let current = collect_current_pids();
                let self_pid = std::process::id();
                let mut new_pids = Vec::new();

                {
                    let mut known = known_pids.lock().await;
                    for pid in &current {
                        if *pid <= 4 || *pid == self_pid {
                            continue;
                        }
                        if known.insert(*pid) {
                            new_pids.push(*pid);
                        }
                    }
                    // 清理已退出的 PID
                    known.retain(|p| current.contains(p));
                }

                // 对每个新进程扫描
                for pid in new_pids {
                    let image_path = query_process_image_path(pid);
                    let path = match image_path {
                        Some(p) if !p.is_empty() => p,
                        _ => continue,
                    };

                    let modules = enumerate_process_modules(pid);
                    match &modules {
                        Ok(items) => {
                            eprintln!(
                                "[ProcessScanner] New process PID={}, path={}, loadedModules={}",
                                pid,
                                path,
                                items.len()
                            );
                            for module_path in items {
                                eprintln!(
                                    "[ProcessScanner]   module PID={}, path={}",
                                    pid, module_path
                                );
                            }
                        }
                        Err(err) => {
                            eprintln!(
                                "[ProcessScanner] New process PID={}, path={}, module enumeration failed: {}",
                                pid,
                                path,
                                err
                            );
                        }
                    }

                    scan_target_and_intercept(
                        &engine,
                        &cache,
                        &interception,
                        &app_handle,
                        pid,
                        "process",
                        &path,
                        None,
                    )
                    .await;

                    if let Ok(module_paths) = modules {
                        for module_path in module_paths {
                            scan_target_and_intercept(
                                &engine,
                                &cache,
                                &interception,
                                &app_handle,
                                pid,
                                "module",
                                &module_path,
                                Some(&path),
                            )
                            .await;
                        }
                    }
                }
            }

            eprintln!("[ProcessScanner] Stopped");
        });
    }

    /// 函数名称：stop
    /// 函数作用：停止进程扫描后台任务。
    /// Purpose: Stops the process scanning background task.
    /// 中文关键词：停止扫描，停止进程监控
    /// English keywords: stop scanning, stop process monitoring
    #[allow(dead_code)]
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        eprintln!("[ProcessScanner] Stop requested");
    }

    /// 函数名称：is_running
    /// 函数作用：检查进程扫描服务是否正在运行。
    /// Purpose: Checks if the process scanner service is running.
    /// 中文关键词：运行状态，检查运行
    /// English keywords: running status, check running
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// 函数名称：collect_current_pids
/// 函数作用：通过 CreateToolhelp32Snapshot 收集系统当前所有进程 PID。
/// Purpose: Collects all current process PIDs via CreateToolhelp32Snapshot.
/// 函数名称：scan_target_and_intercept
/// 函数作用：扫描进程本体或加载模块，优先使用持久化缓存，并在恶意结果时推入拦截队列。
/// Function name: scan_target_and_intercept
/// Purpose: Scans a process image or loaded module, prefers persistent cache, and enqueues interception on malware.
/// 调用方：ProcessScannerService::start 后台任务。
/// Called by: ProcessScannerService::start background task.
/// 被调用方：should_skip_security_scan、ScanResultCacheService::scan_or_get_cached、InterceptionService::enqueue、InterceptionService::try_show_next。
/// Calls: should_skip_security_scan, ScanResultCacheService::scan_or_get_cached, InterceptionService::enqueue, InterceptionService::try_show_next.
/// 副作用：可能调用扫描引擎、写入扫描缓存、推送 process-intercepted 前端事件。
/// Side effects: May call scan engine, write scan cache, and emit process-intercepted frontend events.
async fn scan_target_and_intercept(
    engine: &Arc<EngineService>,
    cache: &Arc<ScanResultCacheService>,
    interception: &Arc<InterceptionService>,
    app_handle: &AppHandle,
    pid: u32,
    target_type: &str,
    target_path: &str,
    process_path: Option<&str>,
) {
    match should_skip_security_scan(target_path) {
        Ok(true) => {
            eprintln!(
                "[ProcessScanner] Skipped {} by exclusions or allowlist: {}",
                target_type, target_path
            );
            return;
        }
        Ok(false) => {}
        Err(err) => {
            eprintln!(
                "[ProcessScanner] Failed to load path policy for {} {}: {}",
                target_type, target_path, err
            );
        }
    }

    match cache.scan_or_get_cached(engine, target_path).await {
        Ok(scan_result) => {
            log_cached_scan_result(
                "ProcessScanner",
                pid,
                target_type,
                target_path,
                &scan_result,
            );
            if scan_result_is_malware(&scan_result.raw_result) {
                let confidence = scan_confidence(&scan_result.raw_result);
                eprintln!(
                    "[ProcessScanner] MALWARE DETECTED targetType={}, PID={}, path={}, confidence={}, cacheHit={}",
                    target_type,
                    pid,
                    target_path,
                    confidence,
                    scan_result.cache_hit
                );
                enqueue_scan_interception(
                    interception,
                    app_handle,
                    pid,
                    target_type,
                    target_path,
                    process_path,
                    &scan_result,
                );
            }
        }
        Err(err) => {
            eprintln!(
                "[ProcessScanner] Scan failed for targetType={}, PID={}, path={}: {}",
                target_type, pid, target_path, err
            );
        }
    }
}

pub(crate) fn log_cached_scan_result(
    source: &str,
    pid: u32,
    target_type: &str,
    target_path: &str,
    scan_result: &CachedScanResult,
) {
    eprintln!(
        "[{}] Scan result targetType={}, PID={}, path={}, sha256={}, cacheHit={}, raw={}",
        source,
        target_type,
        pid,
        target_path,
        scan_result.hash_hex,
        scan_result.cache_hit,
        scan_result.raw_result
    );
}

pub(crate) fn scan_result_is_malware(raw: &serde_json::Value) -> bool {
    raw.get("is_malware")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

pub(crate) fn scan_confidence(raw: &serde_json::Value) -> f64 {
    raw.get("confidence")
        .and_then(|value| value.as_f64())
        .unwrap_or(0.0)
}

pub(crate) fn scan_threat_type(raw: &serde_json::Value) -> Option<String> {
    raw.get("malware_family")
        .and_then(|value| value.get("family_name"))
        .and_then(|value| value.as_str())
        .or_else(|| raw.get("family_name").and_then(|value| value.as_str()))
        .or_else(|| raw.get("threat_type").and_then(|value| value.as_str()))
        .or_else(|| raw.get("threatType").and_then(|value| value.as_str()))
        .or_else(|| raw.get("label").and_then(|value| value.as_str()))
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn enqueue_scan_interception(
    interception: &Arc<InterceptionService>,
    app_handle: &AppHandle,
    pid: u32,
    target_type: &str,
    target_path: &str,
    process_path: Option<&str>,
    scan_result: &CachedScanResult,
) {
    let process_name = process_path
        .or(Some(target_path))
        .and_then(file_name_from_path)
        .unwrap_or_else(|| format!("PID {}", pid));
    let threat_type = scan_threat_type(&scan_result.raw_result)
        .or_else(|| Some(format!("malware_{}", target_type)));
    let payload = serde_json::json!({
        "source": "process_scanner",
        "targetType": target_type,
        "targetPath": target_path,
        "processPath": process_path,
        "sha256": scan_result.hash_hex,
        "cacheHit": scan_result.cache_hit,
        "rawResult": scan_result.raw_result,
    });

    let entry = InterceptionEntry {
        pid,
        process_name,
        file_path: target_path.to_string(),
        risk_level: "high".to_string(),
        threat_type,
        reason: format!(
            "引擎扫描发现{}存在恶意特征：{}",
            if target_type == "module" {
                "进程加载模块"
            } else {
                "进程文件"
            },
            target_path
        ),
        payload: Some(payload.to_string()),
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
    };
    interception.enqueue(entry);
    interception.try_show_next(app_handle);
}

pub(crate) fn file_name_from_path(path: &str) -> Option<String> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
        .map(|name| name.to_string())
}

/// 函数名称：enumerate_process_modules
/// 函数作用：通过 ToolHelp 模块快照枚举指定 PID 已加载模块路径。
/// Function name: enumerate_process_modules
/// Purpose: Enumerates loaded module paths for a PID through a ToolHelp module snapshot.
/// 调用方：ProcessScannerService::start、SnapshotService 启动扫描。
/// Called by: ProcessScannerService::start, SnapshotService startup scan.
/// 错误处理：无法创建模块快照或读取模块时返回错误，由调用方记录调试输出并继续扫描。
/// Error handling: Snapshot or enumeration failures return errors; callers log and continue scanning.
pub(crate) fn enumerate_process_modules(pid: u32) -> Result<Vec<String>, String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };

    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) }
            .map_err(|err| format!("创建模块快照失败: {}", err))?;

    let mut modules = Vec::new();
    let mut entry = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe {
        if Module32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let path = String::from_utf16_lossy(
                    &entry.szExePath[..entry
                        .szExePath
                        .iter()
                        .position(|ch| *ch == 0)
                        .unwrap_or(entry.szExePath.len())],
                );
                if !path.is_empty() {
                    modules.push(path);
                }
                if !Module32NextW(snapshot, &mut entry).is_ok() {
                    break;
                }
            }
        }
        CloseHandle(snapshot).ok();
    }

    Ok(modules)
}

fn collect_current_pids() -> HashSet<u32> {
    use windows::Win32::Foundation::*;
    use windows::Win32::System::Diagnostics::ToolHelp::*;

    let mut pids = HashSet::new();
    unsafe {
        if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    pids.insert(entry.th32ProcessID);
                    if !Process32NextW(snapshot, &mut entry).is_ok() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
    }
    pids
}

/// 函数名称：query_process_image_path
/// 函数作用：通过 OpenProcess + QueryFullProcessImageNameW 获取指定 PID 的可执行文件路径。
/// Purpose: Gets executable path for a PID via OpenProcess + QueryFullProcessImageNameW.
fn query_process_image_path(pid: u32) -> Option<String> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::*;
    use windows::Win32::System::Threading::*;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf: Vec<u16> = vec![0u16; 4096];
        let mut size: u32 = 4096;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        );
        CloseHandle(handle).ok();
        if ok.is_ok() && size > 0 {
            Some(String::from_utf16_lossy(&buf[..size as usize]))
        } else {
            None
        }
    }
}
