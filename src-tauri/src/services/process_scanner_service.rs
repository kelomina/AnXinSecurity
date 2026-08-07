// 进程扫描服务 — 轮询系统进程，对新创建的进程调用 Axon 引擎检测
// Process scanner service — polls system processes, calls Axon engine to scan newly created processes
//
// 与被监控进程无关，专注于对新进程的可执行文件进行恶意代码检测。
// Unrelated to process monitoring; focuses on malware detection of new process executables.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tauri::{AppHandle, Runtime};
use tokio::sync::{Mutex as TokioMutex, Notify};
use tokio::time;

use crate::services::app_lifecycle_service::app_is_exiting;
use crate::services::engine_service::EngineService;
use crate::services::interception_service::{
    InterceptionEnqueueResult, InterceptionEntry, InterceptionService,
};
use crate::services::path_policy_service::should_skip_security_scan;
use crate::services::scan_result_cache_service::{CachedScanResult, ScanResultCacheService};
use crate::services::service_context::AppContext;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // MZ
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // PE\0\0
const IMAGE_NT_OPTIONAL_HDR32_MAGIC_VALUE: u16 = 0x10B;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC_VALUE: u16 = 0x20B;
const MAX_PE_HEADER_READ_SIZE: usize = 4096;
const MAX_PRIVATE_EXECUTABLE_REGIONS_TO_REPORT: usize = 8;
const MAX_UNLINKED_IMAGE_REGIONS_TO_REPORT: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessModuleInfo {
    pub path: String,
    pub base_address: usize,
    pub image_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessImageIntegrityStatus {
    Clean,
    Suspicious,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessImageIntegrityResult {
    pub status: ProcessImageIntegrityStatus,
    pub reason: String,
    pub main_module_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessMemoryAnomalyStatus {
    Clean,
    Suspicious,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SuspiciousMemoryRegion {
    pub base_address: usize,
    pub region_size: usize,
    pub protect: u32,
    pub memory_type: u32,
    pub has_mz: bool,
    pub has_pe: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SuspiciousImageRegion {
    pub base_address: usize,
    pub region_size: usize,
    pub protect: u32,
    pub mapped_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessMemoryAnomalyResult {
    pub status: ProcessMemoryAnomalyStatus,
    pub reason: String,
    pub regions: Vec<SuspiciousMemoryRegion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeImageHeaderSummary {
    entry_point_rva: u32,
    size_of_image: u32,
    is_64_bit: bool,
}

#[derive(Default)]
struct HotPidQueue {
    ordered: VecDeque<u32>,
    seen: HashSet<u32>,
}

impl HotPidQueue {
    fn push(&mut self, pid: u32) -> bool {
        if !self.seen.insert(pid) {
            return false;
        }
        self.ordered.push_back(pid);
        true
    }

    fn drain(&mut self) -> Vec<u32> {
        let drained = self.ordered.drain(..).collect::<Vec<_>>();
        self.seen.clear();
        drained
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.ordered.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessScannerWake {
    Interval,
    HotPid,
    Stopped,
}

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
    hot_pids: Arc<StdMutex<HotPidQueue>>,
    hot_notify: Arc<Notify>,
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
            hot_pids: Arc::new(StdMutex::new(HotPidQueue::default())),
            hot_notify: Arc::new(Notify::new()),
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
    ///   轮询间隔内部使用短步进等待，确保 stop() 修改运行标志后后台任务能及时退出
    ///
    /// 中文关键词：启动扫描，进程轮询，新进程检测，引擎扫描，排除项生效，允许列表生效，跳过扫描，运行时列表，路径策略，实时监控，可停止等待
    /// English keywords: start scanning, process polling, new process detection, engine scan, exclusion effective, allowlist effective, skip scan, runtime list, path policy, realtime monitor, stoppable wait
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
        let hot_pids = self.hot_pids.clone();
        let hot_notify = self.hot_notify.clone();
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

            while running.load(Ordering::SeqCst) {
                let hot_batch = drain_hot_pid_queue(&hot_pids);
                for pid in hot_batch {
                    scan_runtime_pid(
                        &engine,
                        &cache,
                        &interception,
                        &app_handle,
                        pid,
                        "process_scanner_hot_pid",
                    )
                    .await;
                }

                match wait_for_process_scan_interval_or_hot(&running, &hot_notify, interval).await {
                    ProcessScannerWake::Stopped => break,
                    ProcessScannerWake::HotPid => continue,
                    ProcessScannerWake::Interval => {}
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
                    scan_runtime_pid(
                        &engine,
                        &cache,
                        &interception,
                        &app_handle,
                        pid,
                        "process_scanner",
                    )
                    .await;
                }
            }

            eprintln!("[ProcessScanner] Stopped");
        });
    }

    /// 函数名称：mark_hot_pid
    /// 函数作用：把 ETW / 文件监控已经命中的 PID 放入高优先级复扫队列，并唤醒后台扫描任务。
    /// Function name: mark_hot_pid
    /// Purpose: Adds a PID already matched by ETW/file monitoring into the high-priority rescan queue and wakes the background scanner.
    ///
    /// 这个入口不是第一拦截点；第一拦截点应由 ETW / 文件监控直接入拦截队列完成。
    /// This entry is not the first interception point; ETW/file monitoring should enqueue interception first.
    /// 它只负责事后补证：快速复扫进程映像、模块链和内存异常，补充证据并覆盖漏掉的新模块。
    /// It only provides post-event evidence collection: quick rescans for image, module-chain, and memory anomalies.
    pub fn mark_hot_pid(&self, pid: u32, source: &str) -> bool {
        if !self.running.load(Ordering::SeqCst)
            || pid == 0
            || pid == 4
            || pid == u32::MAX
            || pid == std::process::id()
        {
            return false;
        }

        let inserted = {
            let mut hot = self.hot_pids.lock().unwrap_or_else(|err| err.into_inner());
            hot.push(pid)
        };
        if inserted {
            if source != "remote_thread_start_outside_image" {
                eprintln!(
                    "[ProcessScanner] Hot PID queued from {}: PID={}",
                    source, pid
                );
            }
            self.hot_notify.notify_one();
        }
        inserted
    }

    /// 函数名称：stop
    /// 函数作用：停止进程扫描后台任务；后台轮询等待最多一个短步进周期后退出。
    /// Purpose: Stops the process scanning background task; the polling wait exits after at most one short step.
    /// 中文关键词：停止扫描，停止进程监控，可停止等待
    /// English keywords: stop scanning, stop process monitoring, stoppable wait
    #[allow(dead_code)]
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.hot_notify.notify_waiters();
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

/// 函数名称：wait_for_process_scan_interval_or_hot
/// 函数作用：等待扫描轮询间隔，或在 ETW / 文件监控标记热 PID 时立刻唤醒。
/// Function name: wait_for_process_scan_interval_or_hot
/// Purpose: Waits for the polling interval or wakes immediately when ETW/file monitoring marks a hot PID.
async fn wait_for_process_scan_interval_or_hot(
    running: &Arc<AtomicBool>,
    hot_notify: &Arc<Notify>,
    interval_ms: u64,
) -> ProcessScannerWake {
    if !running.load(Ordering::SeqCst) {
        return ProcessScannerWake::Stopped;
    }

    let sleep = time::sleep(Duration::from_millis(interval_ms));
    tokio::pin!(sleep);
    tokio::select! {
        _ = &mut sleep => {
            if running.load(Ordering::SeqCst) {
                ProcessScannerWake::Interval
            } else {
                ProcessScannerWake::Stopped
            }
        }
        _ = hot_notify.notified() => {
            if running.load(Ordering::SeqCst) {
                ProcessScannerWake::HotPid
            } else {
                ProcessScannerWake::Stopped
            }
        }
    }
}

/// 函数名称：drain_hot_pid_queue
/// 函数作用：原子性地取出当前热 PID 队列，供后台优先复扫。
/// Function name: drain_hot_pid_queue
/// Purpose: Atomically drains the current hot PID queue for priority rescans.
fn drain_hot_pid_queue(hot_pids: &Arc<StdMutex<HotPidQueue>>) -> Vec<u32> {
    let mut hot = hot_pids.lock().unwrap_or_else(|err| err.into_inner());
    hot.drain()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::interception_service::InterceptionService;
    use std::time::Instant;

    #[tokio::test]
    async fn process_scan_wait_returns_immediately_when_stop_requested() {
        let running = Arc::new(AtomicBool::new(false));
        let hot_notify = Arc::new(Notify::new());
        let started_at = Instant::now();

        let wake = wait_for_process_scan_interval_or_hot(&running, &hot_notify, 2_000).await;

        assert_eq!(wake, ProcessScannerWake::Stopped);
        assert!(
            started_at.elapsed() < Duration::from_millis(250),
            "process scanner wait should not sleep full interval after stop"
        );
    }

    #[tokio::test]
    async fn hot_pid_queue_deduplicates_and_drains_in_fifo_order() {
        let mut queue = HotPidQueue::default();

        assert!(queue.push(100));
        assert!(!queue.push(100));
        assert!(queue.push(200));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.drain(), vec![100, 200]);
        assert_eq!(queue.len(), 0);
    }

    #[tokio::test]
    async fn hot_wait_returns_hot_pid_when_notified() {
        let running = Arc::new(AtomicBool::new(true));
        let hot_notify = Arc::new(Notify::new());
        hot_notify.notify_one();

        let wake = wait_for_process_scan_interval_or_hot(&running, &hot_notify, 1_000).await;

        assert_eq!(wake, ProcessScannerWake::HotPid);
    }

    #[test]
    fn image_integrity_is_unknown_without_module_snapshot() {
        let result = detect_process_image_integrity(123, r"C:\Windows\System32\notepad.exe", None);

        assert_eq!(result.status, ProcessImageIntegrityStatus::Unknown);
        assert!(result.reason.contains("main module unavailable"));
    }

    #[test]
    fn image_integrity_detects_main_module_path_mismatch() {
        let modules = vec![r"C:\Temp\notepad.exe".to_string()];
        let result =
            detect_process_image_integrity(123, r"C:\Windows\System32\notepad.exe", Some(&modules));

        assert_eq!(result.status, ProcessImageIntegrityStatus::Suspicious);
        assert!(result.reason.contains("does not match"));
        assert_eq!(
            result.main_module_path.as_deref(),
            Some(r"C:\Temp\notepad.exe")
        );
    }

    #[test]
    fn image_integrity_from_module_info_detects_main_module_path_mismatch() {
        let modules = vec![ProcessModuleInfo {
            path: r"C:\Temp\notepad.exe".to_string(),
            base_address: 0x1000,
            image_size: 0x2000,
        }];
        let result = detect_process_image_integrity_from_modules(
            123,
            r"C:\Windows\System32\notepad.exe",
            Some(&modules),
        );

        assert_eq!(result.status, ProcessImageIntegrityStatus::Suspicious);
        assert!(result.reason.contains("does not match"));
        assert_eq!(
            result.main_module_path.as_deref(),
            Some(r"C:\Temp\notepad.exe")
        );
    }

    #[test]
    fn image_integrity_from_module_info_is_unknown_without_module_snapshot() {
        let result = detect_process_image_integrity_from_modules(
            123,
            r"C:\Windows\System32\notepad.exe",
            None,
        );

        assert_eq!(result.status, ProcessImageIntegrityStatus::Unknown);
        assert!(result.reason.contains("main module unavailable"));
    }

    #[test]
    fn image_integrity_treats_non_absolute_process_path_as_unknown() {
        let modules = vec![r"C:\Windows\System32\svchost.exe".to_string()];
        let result = detect_process_image_integrity(123, "svchost.exe", Some(&modules));

        assert_eq!(result.status, ProcessImageIntegrityStatus::Unknown);
        assert!(result.reason.contains("not an absolute file path"));
    }

    #[test]
    fn module_path_match_requires_same_normalized_full_path() {
        assert!(module_path_matches_process_path(
            r"\\?\C:/Windows/System32/notepad.exe",
            r"C:\Windows\System32\NOTEPAD.EXE"
        ));
        assert!(!module_path_matches_process_path(
            r"C:\Windows\System32\svchost.exe",
            r"C:\Temp\svchost.exe"
        ));
    }

    #[test]
    fn module_paths_from_info_preserves_existing_path_list_behavior() {
        let modules = vec![
            ProcessModuleInfo {
                path: r"C:\Windows\System32\kernel32.dll".to_string(),
                base_address: 0x1000,
                image_size: 0x2000,
            },
            ProcessModuleInfo {
                path: r"C:\Windows\System32\user32.dll".to_string(),
                base_address: 0x3000,
                image_size: 0x4000,
            },
        ];

        assert_eq!(
            module_paths_from_info(&modules),
            vec![
                r"C:\Windows\System32\kernel32.dll".to_string(),
                r"C:\Windows\System32\user32.dll".to_string()
            ]
        );
    }

    #[test]
    fn module_chain_detection_is_unknown_without_module_snapshot() {
        let result = detect_module_chain_anomalies(123, None);

        assert_eq!(result.status, ProcessImageIntegrityStatus::Unknown);
        assert!(result.reason.contains("module snapshot unavailable"));
    }

    #[test]
    fn module_chain_detection_is_clean_when_all_sampled_bases_are_known() {
        let modules = vec![
            ProcessModuleInfo {
                path: r"C:\Windows\System32\notepad.exe".to_string(),
                base_address: 0x1000,
                image_size: 0x2000,
            },
            ProcessModuleInfo {
                path: r"C:\Windows\System32\kernel32.dll".to_string(),
                base_address: 0x3000,
                image_size: 0x4000,
            },
        ];

        let result = module_list_contains_base_address(&modules, 0x3000);

        assert!(result);
        assert!(module_list_contains_base_address(&modules, 0x1000));
        assert!(!module_list_contains_base_address(&modules, 0x5000));
    }

    #[test]
    fn module_chain_detection_clean_or_unknown_without_runtime_scan() {
        let modules = vec![ProcessModuleInfo {
            path: r"C:\Windows\System32\notepad.exe".to_string(),
            base_address: 0x1000,
            image_size: 0x2000,
        }];
        let regions = vec![];
        let result = module_chain_integrity_from_regions(&modules, &regions);

        assert_eq!(result.status, ProcessImageIntegrityStatus::Clean);
        assert!(result.reason.contains("represented in module snapshot"));
    }

    #[test]
    fn module_chain_detection_marks_missing_allocation_base_as_suspicious() {
        let modules = vec![ProcessModuleInfo {
            path: r"C:\Windows\System32\notepad.exe".to_string(),
            base_address: 0x1000,
            image_size: 0x2000,
        }];
        let regions = vec![SuspiciousImageRegion {
            base_address: 0x9000,
            region_size: 0x2000,
            protect: 0x20,
            mapped_path: Some(r"\Device\HarddiskVolume3\Temp\unlinked.dll".to_string()),
        }];
        let result = module_chain_integrity_from_regions(&modules, &regions);

        assert_eq!(result.status, ProcessImageIntegrityStatus::Suspicious);
        assert!(result.reason.contains("module chain mismatch"));
        assert_eq!(
            result.main_module_path.as_deref(),
            Some(r"\Device\HarddiskVolume3\Temp\unlinked.dll")
        );
    }

    #[test]
    fn private_executable_region_probe_detects_headers() {
        let mut bytes = vec![0u8; 512];
        bytes[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
        bytes[0x3c..0x40].copy_from_slice(&(0x80i32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());

        let probe = inspect_pe_like_header(&bytes);

        assert!(probe.has_mz);
        assert!(probe.has_pe);
    }

    #[test]
    fn memory_region_predicates_require_committed_private_exec_pages() {
        let executable = memory_region_is_private_executable(
            0x1000,
            0x20000,
            0x20,
            0x1000,
            0x20000,
            [0x10, 0x20, 0x40, 0x80],
            0x100,
        );
        let rejected = memory_region_is_private_executable(
            0x1000,
            0x40000,
            0x20,
            0x1000,
            0x20000,
            [0x10, 0x20, 0x40, 0x80],
            0x100,
        );

        assert!(executable);
        assert!(!rejected);
    }

    #[test]
    fn module_chain_interception_payload_uses_dedicated_threat_type() {
        let interception = Arc::new(InterceptionService::new_for_tests());
        let dummy_app = tauri::test::mock_app();

        enqueue_module_chain_anomaly_interception(
            &interception,
            &dummy_app.handle(),
            4321,
            "process_scanner",
            r"C:\Windows\System32\notepad.exe",
            Some(r"\\Device\\HarddiskVolume3\\Temp\\unlinked.dll"),
            "module chain mismatch test",
        );

        let entry = interception
            .entry_for_pid(4321)
            .expect("entry should exist");
        let payload: serde_json::Value =
            serde_json::from_str(entry.payload.as_deref().expect("payload should exist"))
                .expect("payload should parse");

        assert_eq!(
            entry.threat_type.as_deref(),
            Some("module_chain_unlinked_image")
        );
        assert_eq!(payload["targetType"], "process_module_chain");
        assert_eq!(payload["source"], "process_scanner");
        assert_eq!(
            payload["sampleMappedPath"],
            r"\\Device\\HarddiskVolume3\\Temp\\unlinked.dll"
        );
    }

    #[test]
    fn parse_pe_header_summary_extracts_entry_point_and_size() {
        let pe = fake_pe_header(0x1234, 0x5000, true);
        let summary = parse_pe_header_summary(&pe).expect("valid fake PE header");

        assert_eq!(summary.entry_point_rva, 0x1234);
        assert_eq!(summary.size_of_image, 0x5000);
        assert!(summary.is_64_bit);
    }

    #[test]
    fn pe_header_integrity_detects_entry_point_mismatch() {
        let main_module = ProcessModuleInfo {
            path: r"C:\Windows\System32\notepad.exe".to_string(),
            base_address: 0x10000000,
            image_size: 0x6000,
        };

        let (status, reason) = assess_pe_header_integrity(
            &main_module,
            Ok(PeImageHeaderSummary {
                entry_point_rva: 0x1200,
                size_of_image: 0x5000,
                is_64_bit: true,
            }),
            Ok(PeImageHeaderSummary {
                entry_point_rva: 0x2400,
                size_of_image: 0x5000,
                is_64_bit: true,
            }),
        );

        assert_eq!(status, ProcessImageIntegrityStatus::Suspicious);
        assert!(reason.contains("entry point RVA differs"));
    }

    #[test]
    fn pe_header_integrity_detects_entry_point_outside_module() {
        let main_module = ProcessModuleInfo {
            path: r"C:\Windows\System32\notepad.exe".to_string(),
            base_address: 0x10000000,
            image_size: 0x1000,
        };

        let (status, reason) = assess_pe_header_integrity(
            &main_module,
            Ok(PeImageHeaderSummary {
                entry_point_rva: 0x2000,
                size_of_image: 0x5000,
                is_64_bit: true,
            }),
            Ok(PeImageHeaderSummary {
                entry_point_rva: 0x2000,
                size_of_image: 0x5000,
                is_64_bit: true,
            }),
        );

        assert_eq!(status, ProcessImageIntegrityStatus::Suspicious);
        assert!(reason.contains("outside main module range"));
    }

    fn fake_pe_header(entry_point_rva: u32, size_of_image: u32, is_64_bit: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; 512];
        bytes[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
        bytes[0x3c..0x40].copy_from_slice(&(0x80i32).to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());
        let optional_header_offset = 0x80 + 24;
        let magic = if is_64_bit {
            IMAGE_NT_OPTIONAL_HDR64_MAGIC_VALUE
        } else {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC_VALUE
        };
        bytes[optional_header_offset..optional_header_offset + 2]
            .copy_from_slice(&magic.to_le_bytes());
        bytes[optional_header_offset + 16..optional_header_offset + 20]
            .copy_from_slice(&entry_point_rva.to_le_bytes());
        bytes[optional_header_offset + 56..optional_header_offset + 60]
            .copy_from_slice(&size_of_image.to_le_bytes());
        bytes
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
    if app_is_exiting(app_handle) {
        return;
    }

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

/// 函数名称：enqueue_process_image_integrity_interception
/// 函数作用：把疑似进程镂空或主映像替换结果推入拦截队列。
/// Function name: enqueue_process_image_integrity_interception
/// Purpose: Enqueues suspected process hollowing or main image replacement findings into the interception queue.
/// 调用方：ProcessScannerService::start、SnapshotService::take_startup_snapshot。
/// Called by: ProcessScannerService::start, SnapshotService::take_startup_snapshot.
/// 被调用方：InterceptionService::enqueue、InterceptionService::try_show_next。
/// Calls: InterceptionService::enqueue, InterceptionService::try_show_next.
/// 中文关键词：进程镂空，映像完整性，拦截队列，可信环境
/// English keywords: process hollowing, image integrity, interception queue, trusted baseline
pub(crate) fn enqueue_process_image_integrity_interception<C: AppContext>(
    interception: &Arc<InterceptionService>,
    ctx: &C,
    pid: u32,
    source: &str,
    process_path: &str,
    main_module_path: Option<&str>,
    reason: &str,
    risk_level: &str,
) -> InterceptionEnqueueResult {
    if ctx.is_exiting() {
        return InterceptionEnqueueResult::Rejected;
    }

    let process_name = file_name_from_path(process_path).unwrap_or_else(|| format!("PID {}", pid));
    let payload = serde_json::json!({
        "source": source,
        "targetType": "process",
        "targetPath": process_path,
        "mainModulePath": main_module_path,
        "imageIntegrityStatus": "suspicious",
        "reason": reason,
    });

    let entry = InterceptionEntry {
        pid,
        process_name,
        file_path: process_path.to_string(),
        risk_level: risk_level.to_string(),
        threat_type: Some("process_hollowing".to_string()),
        reason: format!("疑似进程镂空或主映像替换：{}", reason),
        payload: Some(payload.to_string()),
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
    };
    let result = interception.enqueue(entry);
    if result.is_enqueued() {
        interception.try_show_next(ctx);
    }
    result
}

/// 函数名称：enqueue_module_chain_anomaly_interception
/// 函数作用：把疑似 PEB/模块链被破坏导致的“映像内存存在但模块枚举缺失”结果推入拦截队列。
/// Function name: enqueue_module_chain_anomaly_interception
/// Purpose: Enqueues a module-chain anomaly where an executable image mapping exists but is absent from module enumeration.
pub(crate) fn enqueue_module_chain_anomaly_interception<C: AppContext>(
    interception: &Arc<InterceptionService>,
    ctx: &C,
    pid: u32,
    source: &str,
    process_path: &str,
    sample_mapped_path: Option<&str>,
    reason: &str,
) -> InterceptionEnqueueResult {
    if ctx.is_exiting() {
        return InterceptionEnqueueResult::Rejected;
    }

    let process_name = file_name_from_path(process_path).unwrap_or_else(|| format!("PID {}", pid));
    let payload = serde_json::json!({
        "source": source,
        "targetType": "process_module_chain",
        "targetPath": process_path,
        "sampleMappedPath": sample_mapped_path,
        "imageIntegrityStatus": "suspicious",
        "reason": reason,
    });

    let entry = InterceptionEntry {
        pid,
        process_name,
        file_path: process_path.to_string(),
        risk_level: "high".to_string(),
        threat_type: Some("module_chain_unlinked_image".to_string()),
        reason: format!("疑似 PEB/模块链破坏或模块摘链：{}", reason),
        payload: Some(payload.to_string()),
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
    };
    let result = interception.enqueue(entry);
    if result.is_enqueued() {
        interception.try_show_next(ctx);
    }
    result
}

/// 函数名称：enqueue_process_memory_anomaly_interception
/// 函数作用：把目标进程内存里的私有可执行 PE-like 区域推入拦截队列。
/// Function name: enqueue_process_memory_anomaly_interception
/// Purpose: Enqueues suspicious private executable PE-like memory regions found in the target process.
/// 安全边界：该函数只消费只读扫描结果，不修改目标进程；payload 中只写入摘要，不写入完整内存内容。
/// Security boundary: consumes read-only scan results only; stores summaries, not raw memory bytes.
pub(crate) fn enqueue_process_memory_anomaly_interception<R: Runtime>(
    interception: &Arc<InterceptionService>,
    app_handle: &AppHandle<R>,
    pid: u32,
    source: &str,
    process_path: &str,
    reason: &str,
    regions: &[SuspiciousMemoryRegion],
) {
    if app_is_exiting(app_handle) {
        return;
    }

    let process_name = file_name_from_path(process_path).unwrap_or_else(|| format!("PID {}", pid));
    let region_summaries = regions
        .iter()
        .map(|region| {
            serde_json::json!({
                "baseAddress": format!("0x{:x}", region.base_address),
                "regionSize": region.region_size,
                "protect": format!("0x{:x}", region.protect),
                "memoryType": format!("0x{:x}", region.memory_type),
                "hasMz": region.has_mz,
                "hasPe": region.has_pe,
            })
        })
        .collect::<Vec<_>>();
    let payload = serde_json::json!({
        "source": source,
        "targetType": "process_memory",
        "targetPath": process_path,
        "memoryAnomalyStatus": "suspicious",
        "reason": reason,
        "regions": region_summaries,
    });

    let entry = InterceptionEntry {
        pid,
        process_name,
        file_path: process_path.to_string(),
        risk_level: "high".to_string(),
        threat_type: Some("private_executable_pe_memory".to_string()),
        reason: format!("疑似反射加载或手工映射内存：{}", reason),
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

/// 函数名称：detect_process_image_integrity
/// 函数作用：检查进程主映像是否和磁盘路径、模块快照及内存映射类型一致，用于发现典型进程镂空或映像替换迹象。
/// Function name: detect_process_image_integrity
/// Purpose: Checks whether the process main image is consistent with the disk path, module snapshot, and memory mapping type to detect common process hollowing or image replacement signals.
/// 调用方：ProcessScannerService::start、SnapshotService::take_startup_snapshot。
/// Called by: ProcessScannerService::start, SnapshotService::take_startup_snapshot.
/// 被调用方：module_path_matches_process_path、query_main_module_mapping。
/// Calls: module_path_matches_process_path, query_main_module_mapping.
/// 参数说明：pid 为进程 ID；process_path 为 QueryFullProcessImageNameW 得到的进程路径；module_paths 为已枚举模块路径缓存。
/// Parameters: pid is the process ID; process_path is the path from QueryFullProcessImageNameW; module_paths is the cached module path list.
/// 返回值说明：Clean 表示未发现异常；Suspicious 表示应按疑似镂空拦截；Unknown 表示权限或枚举失败导致无法确认。
/// Returns: Clean means no anomaly found; Suspicious should be intercepted as possible hollowing; Unknown means access or enumeration limits prevented confirmation.
/// 错误处理：权限不足或模块缺失不静默放行，返回 Unknown 供调用方汇总或告警。
/// Error handling: Access denial or missing module information is not silently trusted; returns Unknown for caller summary or alerting.
/// 中文关键词：进程镂空，主模块，内存映像，可信环境，映像替换
/// English keywords: process hollowing, main module, memory image, trusted baseline, image replacement
pub(crate) fn detect_process_image_integrity(
    pid: u32,
    process_path: &str,
    module_paths: Option<&Vec<String>>,
) -> ProcessImageIntegrityResult {
    if !process_path_is_absolute(process_path) {
        return ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Unknown,
            reason: "process image path is not an absolute file path".to_string(),
            main_module_path: module_paths.and_then(|paths| paths.first()).cloned(),
        };
    }

    let Some(first_module_path) = module_paths.and_then(|paths| paths.first()).cloned() else {
        return ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Unknown,
            reason: "main module unavailable from module snapshot".to_string(),
            main_module_path: None,
        };
    };

    if !module_path_matches_process_path(process_path, &first_module_path) {
        return ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Suspicious,
            reason: format!(
                "process image path does not match main module path: process={}, mainModule={}",
                process_path, first_module_path
            ),
            main_module_path: Some(first_module_path),
        };
    }

    match query_main_module_mapping(pid) {
        Ok(Some(mapping)) if mapping.memory_type_is_image => ProcessImageIntegrityResult {
            status: mapping.status,
            reason: mapping.reason,
            main_module_path: Some(first_module_path),
        },
        Ok(Some(mapping)) => ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Suspicious,
            reason: format!(
                "main module memory is not MEM_IMAGE: type=0x{:x}",
                mapping.memory_type
            ),
            main_module_path: Some(first_module_path),
        },
        Ok(None) => ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Unknown,
            reason: "main module mapping unavailable".to_string(),
            main_module_path: Some(first_module_path),
        },
        Err(err) => ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Unknown,
            reason: err,
            main_module_path: Some(first_module_path),
        },
    }
}

/// 函数名称：detect_process_image_integrity_from_modules
/// 函数作用：复用调用方已经枚举到的模块信息检查主映像完整性，避免启动快照为同一 PID 重复创建模块快照。
/// Function name: detect_process_image_integrity_from_modules
/// Purpose: Reuses already enumerated module info to check main-image integrity, avoiding duplicate module snapshots for the same PID during startup snapshot.
/// 调用方：SnapshotService::take_startup_snapshot。
/// Called by: SnapshotService::take_startup_snapshot.
/// 安全边界：只复用同一次模块枚举结果；缺少主模块时仍返回 Unknown，不视为可信。
/// Security boundary: Reuses only the same module enumeration result; missing main module still returns Unknown, not trusted.
pub(crate) fn detect_process_image_integrity_from_modules(
    pid: u32,
    process_path: &str,
    modules: Option<&Vec<ProcessModuleInfo>>,
) -> ProcessImageIntegrityResult {
    if !process_path_is_absolute(process_path) {
        return ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Unknown,
            reason: "process image path is not an absolute file path".to_string(),
            main_module_path: modules
                .and_then(|modules| modules.first())
                .map(|module| module.path.clone()),
        };
    }

    let Some(main_module) = modules.and_then(|modules| modules.first()).cloned() else {
        return ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Unknown,
            reason: "main module unavailable from module snapshot".to_string(),
            main_module_path: None,
        };
    };

    if !module_path_matches_process_path(process_path, &main_module.path) {
        return ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Suspicious,
            reason: format!(
                "process image path does not match main module path: process={}, mainModule={}",
                process_path, main_module.path
            ),
            main_module_path: Some(main_module.path),
        };
    }

    match query_main_module_mapping_from_info(pid, main_module.clone()) {
        Ok(Some(mapping)) if mapping.memory_type_is_image => ProcessImageIntegrityResult {
            status: mapping.status,
            reason: mapping.reason,
            main_module_path: Some(main_module.path),
        },
        Ok(Some(mapping)) => ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Suspicious,
            reason: format!(
                "main module memory is not MEM_IMAGE: type=0x{:x}",
                mapping.memory_type
            ),
            main_module_path: Some(main_module.path),
        },
        Ok(None) => ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Unknown,
            reason: "main module mapping unavailable".to_string(),
            main_module_path: Some(main_module.path),
        },
        Err(err) => ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Unknown,
            reason: err,
            main_module_path: Some(main_module.path),
        },
    }
}

pub(crate) fn module_paths_from_info(modules: &[ProcessModuleInfo]) -> Vec<String> {
    modules.iter().map(|module| module.path.clone()).collect()
}

/// 函数名称：enumerate_process_module_info
/// 函数作用：枚举指定 PID 已加载模块路径和模块基址，供扫描与进程镂空检测共用。
/// Function name: enumerate_process_module_info
/// Purpose: Enumerates loaded module paths and base addresses for a PID so scanning and process hollowing detection can share one snapshot.
/// 调用方：enumerate_process_modules、query_main_module_mapping。
/// Called by: enumerate_process_modules, query_main_module_mapping.
/// 中文关键词：模块枚举，模块基址，进程镂空检测
/// English keywords: module enumeration, module base address, process hollowing detection
pub(crate) fn enumerate_process_module_info(pid: u32) -> Result<Vec<ProcessModuleInfo>, String> {
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
                    modules.push(ProcessModuleInfo {
                        path,
                        base_address: entry.modBaseAddr as usize,
                        image_size: entry.modBaseSize,
                    });
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

struct MainModuleMapping {
    memory_type: u32,
    memory_type_is_image: bool,
    status: ProcessImageIntegrityStatus,
    reason: String,
}

fn query_main_module_mapping(pid: u32) -> Result<Option<MainModuleMapping>, String> {
    let Some(main_module) = enumerate_process_module_info(pid)?.into_iter().next() else {
        return Ok(None);
    };
    query_main_module_mapping_from_info(pid, main_module)
}

fn query_main_module_mapping_from_info(
    pid: u32,
    main_module: ProcessModuleInfo,
) -> Result<Option<MainModuleMapping>, String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_IMAGE};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
        .map_err(|err| format!("open process for image integrity failed: {}", err))?;
        let mut info = MEMORY_BASIC_INFORMATION::default();
        let queried = VirtualQueryEx(
            handle,
            Some(main_module.base_address as *const core::ffi::c_void),
            &mut info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        if queried == 0 {
            CloseHandle(handle).ok();
            return Err("VirtualQueryEx returned no mapping information".to_string());
        }
        let memory_header =
            read_remote_pe_header(handle, main_module.base_address, main_module.image_size);
        CloseHandle(handle).ok();

        let disk_header = read_disk_pe_header(&main_module.path);
        let (status, reason) = assess_pe_header_integrity(&main_module, memory_header, disk_header);
        Ok(Some(MainModuleMapping {
            memory_type: info.Type.0,
            memory_type_is_image: info.Type == MEM_IMAGE,
            status,
            reason,
        }))
    }
}

/// 函数名称：detect_process_memory_anomalies
/// 函数作用：只读扫描目标进程虚拟内存，发现私有可执行且带 PE-like 头部的区域。
/// Function name: detect_process_memory_anomalies
/// Purpose: Read-only scan of target virtual memory to find private executable PE-like regions.
/// 检测语义：这不是“反射加载必然检出”的承诺，而是覆盖手工映射/反射加载常见遗留证据：MEM_PRIVATE + PAGE_EXECUTE* + MZ/PE。
/// Detection semantics: This is not a blanket reflective-loader guarantee; it covers common leftover evidence: MEM_PRIVATE + PAGE_EXECUTE* + MZ/PE.
pub(crate) fn detect_process_memory_anomalies(pid: u32) -> ProcessMemoryAnomalyResult {
    match scan_private_executable_pe_regions(pid) {
        Ok(regions) if regions.is_empty() => ProcessMemoryAnomalyResult {
            status: ProcessMemoryAnomalyStatus::Clean,
            reason: "no private executable PE-like memory region found".to_string(),
            regions,
        },
        Ok(regions) => ProcessMemoryAnomalyResult {
            status: ProcessMemoryAnomalyStatus::Suspicious,
            reason: format!(
                "found {} private executable PE-like memory region(s)",
                regions.len()
            ),
            regions,
        },
        Err(err) => ProcessMemoryAnomalyResult {
            status: ProcessMemoryAnomalyStatus::Unknown,
            reason: err,
            regions: Vec::new(),
        },
    }
}

/// 函数名称：detect_module_chain_anomalies
/// 函数作用：只读比对目标进程“模块枚举列表”和实际 MEM_IMAGE 映射，发现疑似 PEB Ldr/模块链被摘除的映像。
/// Function name: detect_module_chain_anomalies
/// Purpose: Read-only comparison between module enumeration and actual MEM_IMAGE mappings to find image mappings missing from the loader/module chain.
/// 检测语义：覆盖“仍有 MEM_IMAGE 映射但模块链被破坏/摘除”的证据形态；无法承诺覆盖无映像、无 PE 头、瞬时自卸载等所有隐蔽实现。
/// Detection semantics: covers evidence where a MEM_IMAGE mapping remains but is absent from the module list; it does not guarantee detection of every stealth implementation.
pub(crate) fn detect_module_chain_anomalies(
    pid: u32,
    modules: Option<&Vec<ProcessModuleInfo>>,
) -> ProcessImageIntegrityResult {
    let Some(modules) = modules else {
        return ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Unknown,
            reason: "module snapshot unavailable for module chain comparison".to_string(),
            main_module_path: None,
        };
    };

    if modules.is_empty() {
        return ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Unknown,
            reason: "module snapshot returned no modules for module chain comparison".to_string(),
            main_module_path: None,
        };
    }

    match scan_unlinked_image_regions(pid, modules) {
        Ok(regions) => module_chain_integrity_from_regions(modules, &regions),
        Err(err) => ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Unknown,
            reason: err,
            main_module_path: modules.first().map(|module| module.path.clone()),
        },
    }
}

fn module_chain_integrity_from_regions(
    modules: &[ProcessModuleInfo],
    regions: &[SuspiciousImageRegion],
) -> ProcessImageIntegrityResult {
    if regions.is_empty() {
        return ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Clean,
            reason:
                "all sampled executable MEM_IMAGE PE regions are represented in module snapshot"
                    .to_string(),
            main_module_path: modules.first().map(|module| module.path.clone()),
        };
    }

    let sample = regions
        .iter()
        .take(3)
        .map(|region| match region.mapped_path.as_deref() {
            Some(path) if !path.is_empty() => format!("0x{:x} ({})", region.base_address, path),
            _ => format!("0x{:x}", region.base_address),
        })
        .collect::<Vec<_>>()
        .join(", ");

    ProcessImageIntegrityResult {
        status: ProcessImageIntegrityStatus::Suspicious,
        reason: format!(
            "module chain mismatch: found {} executable MEM_IMAGE PE region(s) absent from module snapshot: {}",
            regions.len(),
            sample
        ),
        main_module_path: regions.first().and_then(|region| region.mapped_path.clone()),
    }
}

fn scan_private_executable_pe_regions(pid: u32) -> Result<Vec<SuspiciousMemoryRegion>, String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
        PAGE_NOACCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
        .map_err(|err| format!("open process for memory anomaly scan failed: {}", err))?;

        let mut regions = Vec::new();
        let mut address = 0usize;
        let max_address = usize::MAX;
        while address < max_address {
            let mut info = MEMORY_BASIC_INFORMATION::default();
            let queried = VirtualQueryEx(
                handle,
                Some(address as *const core::ffi::c_void),
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if queried == 0 {
                break;
            }

            let base = info.AllocationBase as usize;
            let size = info.RegionSize;
            if memory_region_is_private_executable(
                info.State.0,
                info.Type.0,
                info.Protect.0,
                MEM_COMMIT.0,
                MEM_PRIVATE.0,
                [
                    PAGE_EXECUTE.0,
                    PAGE_EXECUTE_READ.0,
                    PAGE_EXECUTE_READWRITE.0,
                    PAGE_EXECUTE_WRITECOPY.0,
                ],
                PAGE_GUARD.0 | PAGE_NOACCESS.0,
            ) {
                let read_size = size.min(MAX_PE_HEADER_READ_SIZE).max(512);
                let mut buffer = vec![0u8; read_size];
                let mut bytes_read = 0usize;
                if ReadProcessMemory(
                    handle,
                    base as *const core::ffi::c_void,
                    buffer.as_mut_ptr() as *mut core::ffi::c_void,
                    buffer.len(),
                    Some(&mut bytes_read),
                )
                .is_ok()
                {
                    let header = inspect_pe_like_header(&buffer[..bytes_read]);
                    if header.has_mz || header.has_pe {
                        regions.push(SuspiciousMemoryRegion {
                            base_address: base,
                            region_size: size,
                            protect: info.Protect.0,
                            memory_type: info.Type.0,
                            has_mz: header.has_mz,
                            has_pe: header.has_pe,
                        });
                        if regions.len() >= MAX_PRIVATE_EXECUTABLE_REGIONS_TO_REPORT {
                            break;
                        }
                    }
                }
            }

            let Some(next) = base.checked_add(size.max(0x1000)) else {
                break;
            };
            if next <= address {
                break;
            }
            address = next;
        }

        CloseHandle(handle).ok();
        Ok(regions)
    }
}

fn scan_unlinked_image_regions(
    pid: u32,
    modules: &[ProcessModuleInfo],
) -> Result<Vec<SuspiciousImageRegion>, String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, PAGE_EXECUTE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
        PAGE_NOACCESS,
    };
    use windows::Win32::System::ProcessStatus::GetMappedFileNameW;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    };

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
        .map_err(|err| format!("open process for module chain scan failed: {}", err))?;

        let mut regions = Vec::new();
        let mut seen_allocation_bases: HashSet<usize> = HashSet::new();
        let mut address = 0usize;
        let max_address = usize::MAX;
        while address < max_address {
            let mut info = MEMORY_BASIC_INFORMATION::default();
            let queried = VirtualQueryEx(
                handle,
                Some(address as *const core::ffi::c_void),
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if queried == 0 {
                break;
            }

            let base = info.BaseAddress as usize;
            let size = info.RegionSize;
            if memory_region_is_image_executable(
                info.State.0,
                info.Type.0,
                info.Protect.0,
                MEM_COMMIT.0,
                MEM_IMAGE.0,
                [
                    PAGE_EXECUTE.0,
                    PAGE_EXECUTE_READ.0,
                    PAGE_EXECUTE_READWRITE.0,
                    PAGE_EXECUTE_WRITECOPY.0,
                ],
                PAGE_GUARD.0 | PAGE_NOACCESS.0,
            ) && !module_list_contains_base_address(modules, base)
                && seen_allocation_bases.insert(base)
            {
                let read_size = size.min(MAX_PE_HEADER_READ_SIZE).max(512);
                let mut buffer = vec![0u8; read_size];
                let mut bytes_read = 0usize;
                if ReadProcessMemory(
                    handle,
                    base as *const core::ffi::c_void,
                    buffer.as_mut_ptr() as *mut core::ffi::c_void,
                    buffer.len(),
                    Some(&mut bytes_read),
                )
                .is_ok()
                {
                    let header = inspect_pe_like_header(&buffer[..bytes_read]);
                    if header.has_mz && header.has_pe {
                        let mut mapped_name_buf = vec![0u16; 4096];
                        let mapped_len = GetMappedFileNameW(
                            handle,
                            base as *const core::ffi::c_void,
                            &mut mapped_name_buf,
                        );
                        let mapped_path = if mapped_len > 0 {
                            Some(String::from_utf16_lossy(
                                &mapped_name_buf[..mapped_len as usize],
                            ))
                        } else {
                            None
                        };
                        regions.push(SuspiciousImageRegion {
                            base_address: base,
                            region_size: size,
                            protect: info.Protect.0,
                            mapped_path,
                        });
                        if regions.len() >= MAX_UNLINKED_IMAGE_REGIONS_TO_REPORT {
                            break;
                        }
                    }
                }
            }

            let Some(next) = base.checked_add(size.max(0x1000)) else {
                break;
            };
            if next <= address {
                break;
            }
            address = next;
        }

        CloseHandle(handle).ok();
        Ok(regions)
    }
}

fn memory_region_is_private_executable(
    state: u32,
    memory_type: u32,
    protect: u32,
    committed_flag: u32,
    private_flag: u32,
    executable_flags: [u32; 4],
    disallowed_protect_flags: u32,
) -> bool {
    if state != committed_flag || memory_type != private_flag {
        return false;
    }
    if protect & disallowed_protect_flags != 0 {
        return false;
    }
    executable_flags.iter().any(|flag| protect & *flag != 0)
}

fn memory_region_is_image_executable(
    state: u32,
    memory_type: u32,
    protect: u32,
    committed_flag: u32,
    image_flag: u32,
    executable_flags: [u32; 4],
    disallowed_protect_flags: u32,
) -> bool {
    if state != committed_flag || memory_type != image_flag {
        return false;
    }
    if protect & disallowed_protect_flags != 0 {
        return false;
    }
    executable_flags.iter().any(|flag| protect & *flag != 0)
}

fn module_list_contains_base_address(modules: &[ProcessModuleInfo], base_address: usize) -> bool {
    modules
        .iter()
        .any(|module| module.base_address == base_address)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeLikeHeaderProbe {
    has_mz: bool,
    has_pe: bool,
}

fn inspect_pe_like_header(bytes: &[u8]) -> PeLikeHeaderProbe {
    let has_mz = read_u16_le(bytes, 0).is_ok_and(|value| value == IMAGE_DOS_SIGNATURE);
    let pe_offset = read_i32_le(bytes, 0x3c)
        .ok()
        .filter(|offset| *offset >= 0)
        .map(|offset| offset as usize);
    let has_pe = pe_offset
        .and_then(|offset| read_u32_le(bytes, offset).ok())
        .is_some_and(|value| value == IMAGE_NT_SIGNATURE);
    PeLikeHeaderProbe { has_mz, has_pe }
}

fn module_path_matches_process_path(process_path: &str, module_path: &str) -> bool {
    let process_key = normalize_image_path_for_compare(process_path);
    let module_key = normalize_image_path_for_compare(module_path);
    process_key == module_key
}

fn assess_pe_header_integrity(
    main_module: &ProcessModuleInfo,
    memory_header: Result<PeImageHeaderSummary, String>,
    disk_header: Result<PeImageHeaderSummary, String>,
) -> (ProcessImageIntegrityStatus, String) {
    let memory_header = match memory_header {
        Ok(header) => header,
        Err(err) => return (ProcessImageIntegrityStatus::Unknown, err),
    };
    let disk_header = match disk_header {
        Ok(header) => header,
        Err(err) => return (ProcessImageIntegrityStatus::Unknown, err),
    };

    if memory_header.is_64_bit != disk_header.is_64_bit {
        return (
            ProcessImageIntegrityStatus::Suspicious,
            format!(
                "memory PE architecture differs from disk PE: memory64={}, disk64={}",
                memory_header.is_64_bit, disk_header.is_64_bit
            ),
        );
    }

    if memory_header.entry_point_rva != disk_header.entry_point_rva {
        return (
            ProcessImageIntegrityStatus::Suspicious,
            format!(
                "memory entry point RVA differs from disk: memory=0x{:x}, disk=0x{:x}",
                memory_header.entry_point_rva, disk_header.entry_point_rva
            ),
        );
    }

    let module_size = main_module.image_size;
    if module_size > 0 && memory_header.entry_point_rva >= module_size {
        return (
            ProcessImageIntegrityStatus::Suspicious,
            format!(
                "memory entry point RVA is outside main module range: entry=0x{:x}, moduleSize=0x{:x}",
                memory_header.entry_point_rva, module_size
            ),
        );
    }

    if memory_header.size_of_image > 0
        && disk_header.size_of_image > 0
        && memory_header.size_of_image != disk_header.size_of_image
    {
        return (
            ProcessImageIntegrityStatus::Suspicious,
            format!(
                "memory SizeOfImage differs from disk: memory=0x{:x}, disk=0x{:x}",
                memory_header.size_of_image, disk_header.size_of_image
            ),
        );
    }

    (
        ProcessImageIntegrityStatus::Clean,
        "main module is backed by MEM_IMAGE and PE header matches disk".to_string(),
    )
}

fn read_remote_pe_header(
    process_handle: windows::Win32::Foundation::HANDLE,
    base_address: usize,
    module_size: u32,
) -> Result<PeImageHeaderSummary, String> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

    let read_size = usize::min(
        MAX_PE_HEADER_READ_SIZE,
        usize::try_from(module_size).unwrap_or(MAX_PE_HEADER_READ_SIZE),
    )
    .max(512);
    let mut buffer = vec![0u8; read_size];
    let mut bytes_read = 0usize;

    unsafe {
        ReadProcessMemory(
            process_handle,
            base_address as *const core::ffi::c_void,
            buffer.as_mut_ptr() as *mut core::ffi::c_void,
            buffer.len(),
            Some(&mut bytes_read),
        )
        .map_err(|err| format!("ReadProcessMemory PE header failed: {}", err))?;
    }

    parse_pe_header_summary(&buffer[..bytes_read])
        .map_err(|err| format!("memory PE header invalid: {}", err))
}

fn read_disk_pe_header(path: &str) -> Result<PeImageHeaderSummary, String> {
    use std::io::Read;

    let mut file =
        std::fs::File::open(path).map_err(|err| format!("open disk PE header failed: {}", err))?;
    let mut buffer = vec![0u8; MAX_PE_HEADER_READ_SIZE];
    let bytes_read = file
        .read(&mut buffer)
        .map_err(|err| format!("read disk PE header failed: {}", err))?;

    parse_pe_header_summary(&buffer[..bytes_read])
        .map_err(|err| format!("disk PE header invalid: {}", err))
}

fn parse_pe_header_summary(bytes: &[u8]) -> Result<PeImageHeaderSummary, String> {
    if read_u16_le(bytes, 0)? != IMAGE_DOS_SIGNATURE {
        return Err("missing MZ signature".to_string());
    }

    let pe_offset = read_i32_le(bytes, 0x3c)? as isize;
    if pe_offset < 0 {
        return Err("negative PE header offset".to_string());
    }
    let pe_offset = pe_offset as usize;
    if read_u32_le(bytes, pe_offset)? != IMAGE_NT_SIGNATURE {
        return Err("missing PE signature".to_string());
    }

    let optional_header_offset = pe_offset
        .checked_add(24)
        .ok_or_else(|| "PE optional header offset overflow".to_string())?;
    let optional_magic = read_u16_le(bytes, optional_header_offset)?;
    let entry_point_rva = read_u32_le(bytes, optional_header_offset + 16)?;
    let size_of_image = read_u32_le(bytes, optional_header_offset + 56)?;
    let is_64_bit = match optional_magic {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC_VALUE => false,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC_VALUE => true,
        other => return Err(format!("unsupported optional header magic: 0x{:x}", other)),
    };

    Ok(PeImageHeaderSummary {
        entry_point_rva,
        size_of_image,
        is_64_bit,
    })
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| "u16 offset overflow".to_string())?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| format!("buffer too small for u16 at 0x{:x}", offset))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| "u32 offset overflow".to_string())?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| format!("buffer too small for u32 at 0x{:x}", offset))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_i32_le(bytes: &[u8], offset: usize) -> Result<i32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| "i32 offset overflow".to_string())?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| format!("buffer too small for i32 at 0x{:x}", offset))?;
    Ok(i32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn normalize_image_path_for_compare(path: &str) -> String {
    let trimmed = path.trim();
    let without_prefix = trimmed
        .strip_prefix(r"\\?\")
        .or_else(|| trimmed.strip_prefix(r"\??\"))
        .unwrap_or(trimmed);
    without_prefix.replace('/', "\\").to_ascii_lowercase()
}

fn process_path_is_absolute(path: &str) -> bool {
    let trimmed = path.trim();
    let without_prefix = trimmed
        .strip_prefix(r"\\?\")
        .or_else(|| trimmed.strip_prefix(r"\??\"))
        .unwrap_or(trimmed);
    std::path::Path::new(without_prefix).is_absolute()
}

/// 函数名称：scan_runtime_pid
/// 函数作用：对运行中的 PID 执行当前进程扫描逻辑；既用于新进程，也用于热 PID 复扫。
/// Function name: scan_runtime_pid
/// Purpose: Runs the current process-scanner logic for a PID; used both for new processes and hot PID rescans.
async fn scan_runtime_pid(
    engine: &Arc<EngineService>,
    cache: &Arc<ScanResultCacheService>,
    interception: &Arc<InterceptionService>,
    app_handle: &AppHandle,
    pid: u32,
    source: &str,
) {
    let image_path = query_process_image_path(pid);
    let path = match image_path {
        Some(p) if !p.is_empty() => p,
        _ => {
            eprintln!(
                "[ProcessScanner] {} PID {} no image path available",
                source, pid
            );
            return;
        }
    };

    let module_info = enumerate_process_module_info(pid);
    let modules = module_info
        .as_ref()
        .map(|items| module_paths_from_info(items))
        .map_err(|err| err.clone());
    match &modules {
        Ok(items) => {
            eprintln!(
                "[ProcessScanner] {} PID={}, path={}, loadedModules={}",
                source,
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
                "[ProcessScanner] {} PID={}, path={}, module enumeration failed: {}",
                source, pid, path, err
            );
        }
    }

    match detect_process_image_integrity(pid, &path, modules.as_ref().ok()) {
        ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Suspicious,
            reason,
            main_module_path,
        } => {
            let _ = enqueue_process_image_integrity_interception(
                interception,
                app_handle,
                pid,
                source,
                &path,
                main_module_path.as_deref(),
                &reason,
                "high",
            );
        }
        ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Unknown,
            reason,
            main_module_path,
        } => {
            eprintln!(
                "[ProcessScanner] {} process image integrity unknown PID={}, path={}, mainModule={:?}: {}",
                source, pid, path, main_module_path, reason
            );
        }
        ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Clean,
            ..
        } => {}
    }

    match detect_module_chain_anomalies(pid, module_info.as_ref().ok()) {
        ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Suspicious,
            reason,
            main_module_path,
        } => {
            let _ = enqueue_module_chain_anomaly_interception(
                interception,
                app_handle,
                pid,
                source,
                &path,
                main_module_path.as_deref(),
                &reason,
            );
        }
        ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Unknown,
            reason,
            main_module_path,
        } => {
            eprintln!(
                "[ProcessScanner] {} module chain integrity unknown PID={}, path={}, sample={:?}: {}",
                source, pid, path, main_module_path, reason
            );
        }
        ProcessImageIntegrityResult {
            status: ProcessImageIntegrityStatus::Clean,
            ..
        } => {}
    }

    match detect_process_memory_anomalies(pid) {
        ProcessMemoryAnomalyResult {
            status: ProcessMemoryAnomalyStatus::Suspicious,
            reason,
            regions,
        } => enqueue_process_memory_anomaly_interception(
            interception,
            app_handle,
            pid,
            source,
            &path,
            &reason,
            &regions,
        ),
        ProcessMemoryAnomalyResult {
            status: ProcessMemoryAnomalyStatus::Unknown,
            reason,
            ..
        } => {
            eprintln!(
                "[ProcessScanner] {} process memory anomaly scan unknown PID={}, path={}: {}",
                source, pid, path, reason
            );
        }
        ProcessMemoryAnomalyResult {
            status: ProcessMemoryAnomalyStatus::Clean,
            ..
        } => {}
    }

    scan_target_and_intercept(
        engine,
        cache,
        interception,
        app_handle,
        pid,
        "process",
        &path,
        None,
    )
    .await;

    if let Ok(module_paths) = modules {
        for module_path in module_paths {
            scan_target_and_intercept(
                engine,
                cache,
                interception,
                app_handle,
                pid,
                "module",
                &module_path,
                Some(&path),
            )
            .await;
        }
    }
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
pub(crate) fn query_process_image_path(pid: u32) -> Option<String> {
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
