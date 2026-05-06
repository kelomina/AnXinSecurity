// 进程快照拦截服务 — 启动时扫描所有运行进程及加载 DLL，暂停未签名进程
// Process snapshot interception service — scans all running processes and loaded DLLs at startup, pauses unsigned ones
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter};

use crate::services::engine_service::EngineService;
use crate::services::interception_service::{InterceptionEntry, InterceptionService};
use crate::services::path_policy_service::should_skip_security_scan;
use crate::services::process_scanner_service::{
    enumerate_process_modules, file_name_from_path, log_cached_scan_result, scan_confidence,
    scan_result_is_malware, scan_threat_type,
};
use crate::services::scan_result_cache_service::{CachedScanResult, ScanResultCacheService};
use crate::services::trust_service::TrustService;

/// 快照扫描结果 / Snapshot scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotResult {
    /// 扫描进程总数 / Total scanned processes
    #[serde(rename = "totalProcesses")]
    pub total_processes: u32,
    /// 已签名进程数 / Signed process count
    #[serde(rename = "signedProcesses")]
    pub signed_processes: u32,
    /// 未签名进程数 / Unsigned process count
    #[serde(rename = "unsignedProcesses")]
    pub unsigned_processes: u32,
    /// 已暂停进程数 / Paused process count
    #[serde(rename = "pausedProcesses")]
    pub paused_processes: u32,
    /// 已扫描模块数 / Scanned module count
    #[serde(rename = "scannedModules")]
    pub scanned_modules: u32,
    /// 恶意进程数 / Malicious process count
    #[serde(rename = "maliciousProcesses")]
    pub malicious_processes: u32,
    /// 恶意模块数 / Malicious module count
    #[serde(rename = "maliciousModules")]
    pub malicious_modules: u32,
    /// 缓存命中数 / Cache hit count
    #[serde(rename = "cacheHits")]
    pub cache_hits: u32,
    /// 扫描耗时（毫秒） / Scan duration (ms)
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
}

/// 进程快照拦截服务 — 启动时安全评估
/// Process snapshot interception service — startup security assessment
///
/// 负责：
/// - 枚举所有运行进程（通过 CreateToolhelp32Snapshot）
/// - 对每个进程执行数字签名验证
/// - 将未签名进程推入拦截队列
/// - 生成快照报告
///
/// Responsible for:
/// - Enumerating all running processes (via CreateToolhelp32Snapshot)
/// - Performing digital signature verification on each process
/// - Pushing unsigned processes to interception queue
/// - Generating snapshot report
pub struct SnapshotService {
    /// 拦截服务引用 / Interception service reference
    interception: Arc<Mutex<Option<Arc<InterceptionService>>>>,
    /// 最后快照结果 / Last snapshot result
    last_result: Arc<Mutex<Option<SnapshotResult>>>,
}

impl SnapshotService {
    /// 函数名称：new
    /// 函数作用：创建 SnapshotService 实例。
    /// Purpose: Creates a SnapshotService instance.
    /// Called by: main.rs setup()
    /// 中文关键词：进程快照，启动扫描，安全评估
    /// English keywords: process snapshot, startup scan, security assessment
    pub fn new() -> Self {
        Self {
            interception: Arc::new(Mutex::new(None)),
            last_result: Arc::new(Mutex::new(None)),
        }
    }

    /// 函数名称：set_interception_service
    /// 函数作用：设置拦截服务引用。
    /// Purpose: Sets the interception service reference.
    /// Called by: main.rs setup()
    pub fn set_interception_service(&self, svc: Arc<InterceptionService>) {
        *self.interception.lock().unwrap_or_else(|e| e.into_inner()) = Some(svc);
    }

    /// 函数名称：take_startup_snapshot
    /// 函数作用：执行启动时进程快照扫描；验证签名前实时读取排除项和允许列表，命中时视为可信跳过拦截。
    /// Function name: take_startup_snapshot
    /// Purpose: Executes startup process snapshot scan; reads exclusions and allowlist before signature verification and treats matching processes as trusted.
    /// Called by: main.rs setup() at startup (after ETW monitoring starts)
    /// 参数 trust: 信任验证服务 / Trust verification service
    /// 参数 app_handle: Tauri 应用句柄 / Tauri app handle
    /// 副作用：向前端 emit("snapshot-progress") 和 emit("snapshot-result"); 高/中风险进程入拦截队列
    /// Side effects: emits "snapshot-progress" and "snapshot-result" to frontend; high/medium risk processes enqueued
    /// 中文关键词：启动快照，进程扫描，签名验证，DLL枚举，排除项生效，允许列表生效，跳过拦截，运行时列表，路径策略，启动监控
    /// English keywords: startup snapshot, process scan, signature verification, DLL enumeration, exclusion effective, allowlist effective, skip interception, runtime list, path policy, startup monitor
    pub async fn take_startup_snapshot(
        &self,
        trust: &TrustService,
        engine: Arc<EngineService>,
        cache: Arc<ScanResultCacheService>,
        app_handle: &AppHandle,
    ) -> Result<SnapshotResult, String> {
        let start_time = std::time::Instant::now();

        // 枚举所有运行进程 / Enumerate all running processes
        let processes = enumerate_all_processes()?;
        let total = processes.len() as u32;

        // 通知前端进度 / Notify frontend of progress
        let _ = app_handle.emit(
            "snapshot-progress",
            serde_json::json!({
                "stage": "scanning",
                "total": total,
                "current": 0,
            }),
        );

        let mut signed: u32 = 0;
        let mut unsigned: u32 = 0;
        let mut paused: u32 = 0;
        let mut scanned_modules: u32 = 0;
        let mut malicious_processes: u32 = 0;
        let mut malicious_modules: u32 = 0;
        let mut cache_hits: u32 = 0;

        let interception_ref = {
            let interception_guard = self.interception.lock().unwrap_or_else(|e| e.into_inner());
            interception_guard.clone()
        };

        for (i, proc_info) in processes.iter().enumerate() {
            // 跳过自身进程 / Skip own process
            if proc_info.pid == std::process::id() {
                signed += 1;
                continue;
            }

            // 跳过系统进程（PID 0 和 4） / Skip system processes (PID 0 and 4)
            if proc_info.pid <= 4 {
                signed += 1;
                continue;
            }

            match should_skip_security_scan(&proc_info.path) {
                Ok(true) => {
                    signed += 1;
                    continue;
                }
                Ok(false) => {}
                Err(e) => {
                    eprintln!(
                        "[StartupSnapshot] Failed to load path policy for {}: {}",
                        proc_info.path, e
                    );
                }
            }

            // 验证数字签名 / Verify digital signature
            match scan_startup_target(
                &engine,
                &cache,
                interception_ref.as_ref(),
                app_handle,
                proc_info.pid,
                &proc_info.name,
                "process",
                &proc_info.path,
                None,
            )
            .await
            {
                StartupScanOutcome::Malicious { cache_hit } => {
                    malicious_processes += 1;
                    paused += 1;
                    if cache_hit {
                        cache_hits += 1;
                    }
                }
                StartupScanOutcome::Clean { cache_hit } => {
                    if cache_hit {
                        cache_hits += 1;
                    }
                }
                StartupScanOutcome::Skipped => {}
                StartupScanOutcome::Failed => {}
            }

            match enumerate_process_modules(proc_info.pid) {
                Ok(module_paths) => {
                    eprintln!(
                        "[StartupSnapshot] PID={}, path={}, loadedModules={}",
                        proc_info.pid,
                        proc_info.path,
                        module_paths.len()
                    );
                    for module_path in module_paths {
                        eprintln!(
                            "[StartupSnapshot]   module PID={}, path={}",
                            proc_info.pid, module_path
                        );
                        scanned_modules += 1;
                        match scan_startup_target(
                            &engine,
                            &cache,
                            interception_ref.as_ref(),
                            app_handle,
                            proc_info.pid,
                            &proc_info.name,
                            "module",
                            &module_path,
                            Some(&proc_info.path),
                        )
                        .await
                        {
                            StartupScanOutcome::Malicious { cache_hit } => {
                                malicious_modules += 1;
                                paused += 1;
                                if cache_hit {
                                    cache_hits += 1;
                                }
                            }
                            StartupScanOutcome::Clean { cache_hit } => {
                                if cache_hit {
                                    cache_hits += 1;
                                }
                            }
                            StartupScanOutcome::Skipped => {}
                            StartupScanOutcome::Failed => {}
                        }
                    }
                }
                Err(err) => {
                    eprintln!(
                        "[StartupSnapshot] Failed to enumerate modules for PID={}, path={}: {}",
                        proc_info.pid, proc_info.path, err
                    );
                }
            }

            let is_trusted = match trust.verify_file(&proc_info.path) {
                Ok(verdict) => verdict.trusted,
                Err(_) => false,
            };

            if is_trusted {
                signed += 1;
            } else {
                unsigned += 1;

                // 推入拦截队列 / Push to interception queue
                if let Some(ref interception) = interception_ref {
                    let entry = InterceptionEntry {
                        pid: proc_info.pid,
                        process_name: proc_info.name.clone(),
                        file_path: proc_info.path.clone(),
                        risk_level: "medium".to_string(),
                        threat_type: Some("unsigned_process".to_string()),
                        reason: format!(
                            "进程 {} 未通过数字签名验证，可能存在安全风险",
                            proc_info.name
                        ),
                        payload: None,
                        timestamp: chrono::Utc::now().timestamp_millis() as u64,
                    };
                    interception.enqueue(entry);
                    paused += 1;
                }
            }

            // 每10个进程更新一次进度 / Update progress every 10 processes
            if (i + 1) % 10 == 0 || i == processes.len() - 1 {
                let _ = app_handle.emit(
                    "snapshot-progress",
                    serde_json::json!({
                        "stage": "scanning",
                        "total": total,
                        "current": (i + 1) as u32,
                    }),
                );
            }
        }

        let result = SnapshotResult {
            total_processes: total,
            signed_processes: signed,
            unsigned_processes: unsigned,
            paused_processes: paused,
            scanned_modules,
            malicious_processes,
            malicious_modules,
            cache_hits,
            duration_ms: start_time.elapsed().as_millis() as u64,
        };

        // 保存结果 / Save result
        *self.last_result.lock().unwrap_or_else(|e| e.into_inner()) = Some(result.clone());

        // 通知前端完成 / Notify frontend of completion
        let _ = app_handle.emit("snapshot-result", &result);

        // 尝试显示第一个拦截弹窗 / Try to show first interception modal
        if let Some(ref interception) = interception_ref {
            interception.try_show_next(app_handle);
        }

        Ok(result)
    }

    /// 函数名称：get_last_result
    /// 函数作用：获取最后一次快照扫描结果。
    /// Purpose: Gets the last snapshot scan result.
    /// Called by: commands::snapshot::get_snapshot_result
    pub fn get_last_result(&self) -> Option<SnapshotResult> {
        self.last_result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// 进程基本信息 / Process basic info
enum StartupScanOutcome {
    Clean { cache_hit: bool },
    Malicious { cache_hit: bool },
    Skipped,
    Failed,
}

/// 函数名称：scan_startup_target
/// 函数作用：启动快照中扫描进程文件或加载模块，复用持久化扫描缓存，并在恶意结果时入拦截队列。
/// Function name: scan_startup_target
/// Purpose: Scans a process file or loaded module during startup snapshot, reuses persistent scan cache, and enqueues malware results.
/// 调用方：SnapshotService::take_startup_snapshot。
/// Called by: SnapshotService::take_startup_snapshot.
/// 被调用方：should_skip_security_scan、ScanResultCacheService::scan_or_get_cached、InterceptionService。
/// Calls: should_skip_security_scan, ScanResultCacheService::scan_or_get_cached, InterceptionService.
/// 副作用：可能写入扫描缓存并推送 process-intercepted 事件。
/// Side effects: May write scan cache and emit process-intercepted events.
async fn scan_startup_target(
    engine: &Arc<EngineService>,
    cache: &Arc<ScanResultCacheService>,
    interception: Option<&Arc<InterceptionService>>,
    app_handle: &AppHandle,
    pid: u32,
    process_name: &str,
    target_type: &str,
    target_path: &str,
    process_path: Option<&str>,
) -> StartupScanOutcome {
    match should_skip_security_scan(target_path) {
        Ok(true) => {
            eprintln!(
                "[StartupSnapshot] Skipped {} by exclusions or allowlist: {}",
                target_type, target_path
            );
            return StartupScanOutcome::Skipped;
        }
        Ok(false) => {}
        Err(err) => {
            eprintln!(
                "[StartupSnapshot] Failed to load path policy for {} {}: {}",
                target_type, target_path, err
            );
        }
    }

    match cache.scan_or_get_cached(engine, target_path).await {
        Ok(scan_result) => {
            log_cached_scan_result(
                "StartupSnapshot",
                pid,
                target_type,
                target_path,
                &scan_result,
            );
            if scan_result_is_malware(&scan_result.raw_result) {
                eprintln!(
                    "[StartupSnapshot] MALWARE DETECTED targetType={}, PID={}, path={}, confidence={}, cacheHit={}",
                    target_type,
                    pid,
                    target_path,
                    scan_confidence(&scan_result.raw_result),
                    scan_result.cache_hit
                );
                if let Some(interception) = interception {
                    enqueue_startup_scan_interception(
                        interception,
                        app_handle,
                        pid,
                        process_name,
                        target_type,
                        target_path,
                        process_path,
                        &scan_result,
                    );
                }
                StartupScanOutcome::Malicious {
                    cache_hit: scan_result.cache_hit,
                }
            } else {
                StartupScanOutcome::Clean {
                    cache_hit: scan_result.cache_hit,
                }
            }
        }
        Err(err) => {
            eprintln!(
                "[StartupSnapshot] Scan failed for targetType={}, PID={}, path={}: {}",
                target_type, pid, target_path, err
            );
            StartupScanOutcome::Failed
        }
    }
}

fn enqueue_startup_scan_interception(
    interception: &Arc<InterceptionService>,
    app_handle: &AppHandle,
    pid: u32,
    process_name: &str,
    target_type: &str,
    target_path: &str,
    process_path: Option<&str>,
    scan_result: &CachedScanResult,
) {
    let entry_process_name = if process_name.is_empty() {
        process_path
            .or(Some(target_path))
            .and_then(file_name_from_path)
            .unwrap_or_else(|| format!("PID {}", pid))
    } else {
        process_name.to_string()
    };
    let payload = serde_json::json!({
        "source": "startup_snapshot",
        "targetType": target_type,
        "targetPath": target_path,
        "processPath": process_path,
        "sha256": scan_result.hash_hex,
        "cacheHit": scan_result.cache_hit,
        "rawResult": scan_result.raw_result,
    });

    let entry = InterceptionEntry {
        pid,
        process_name: entry_process_name,
        file_path: target_path.to_string(),
        risk_level: "high".to_string(),
        threat_type: scan_threat_type(&scan_result.raw_result)
            .or_else(|| Some(format!("malware_{}", target_type))),
        reason: format!(
            "启动扫描发现{}存在恶意特征：{}",
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

#[derive(Debug, Clone)]
struct ProcInfo {
    pid: u32,
    name: String,
    path: String,
}

/// 枚举所有运行进程 / Enumerate all running processes
fn enumerate_all_processes() -> Result<Vec<ProcInfo>, String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_READ,
    };

    let mut result = Vec::new();

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| format!("创建进程快照失败: {}", e))?;

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe {
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                let exe_name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );

                // 获取进程完整路径 / Get process full path
                let path = if pid > 0 && pid != std::process::id() {
                    match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                        Ok(handle) => {
                            let mut buf: Vec<u16> = vec![0u16; 520];
                            let mut len = buf.len() as u32;
                            let pwstr = windows::core::PWSTR(buf.as_mut_ptr());
                            let image_path = match QueryFullProcessImageNameW(
                                handle,
                                PROCESS_NAME_FORMAT(0), // PROCESS_NAME_WIN32
                                pwstr,
                                &mut len,
                            ) {
                                Ok(()) => {
                                    let s = String::from_utf16_lossy(&buf[..len as usize]);
                                    s
                                }
                                Err(_) => exe_name.clone(),
                            };
                            CloseHandle(handle).ok();
                            image_path
                        }
                        Err(_) => exe_name.clone(),
                    }
                } else {
                    exe_name.clone()
                };

                result.push(ProcInfo {
                    pid,
                    name: exe_name,
                    path,
                });

                if !Process32NextW(snapshot, &mut entry).is_ok() {
                    break;
                }
            }
        }
        CloseHandle(snapshot).ok();
    }

    Ok(result)
}
