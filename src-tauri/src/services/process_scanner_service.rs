// 进程扫描服务 — 轮询系统进程，对新创建的进程调用 Axon 引擎检测
// Process scanner service — polls system processes, calls Axon engine to scan newly created processes
//
// 与被监控进程无关，专注于对新进程的可执行文件进行恶意代码检测。
// Unrelated to process monitoring; focuses on malware detection of new process executables.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex as TokioMutex;
use tokio::time;

use crate::services::engine_service::EngineService;

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
    /// 函数作用：启动进程扫描后台任务。
    /// Purpose: Starts the process scanning background task.
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
    /// 中文关键词：启动扫描，进程轮询，新进程检测，引擎扫描
    /// English keywords: start scanning, process polling, new process detection, engine scan
    pub fn start(&self, engine: Arc<EngineService>, interval_ms: u64) {
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

                    eprintln!("[ProcessScanner] New process PID={}, path={}", pid, path);

                    match engine.is_malware(&path).await {
                        Ok((is_malware, confidence)) => {
                            if is_malware {
                                eprintln!(
                                    "[ProcessScanner] MALWARE DETECTED PID={}, path={}, confidence={}",
                                    pid, path, confidence
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "[ProcessScanner] Scan failed for PID={}, path={}: {}",
                                pid, path, e
                            );
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
fn collect_current_pids() -> HashSet<u32> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::Foundation::*;

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
    use windows::Win32::System::Threading::*;
    use windows::Win32::Foundation::*;
    use windows::core::PWSTR;

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
