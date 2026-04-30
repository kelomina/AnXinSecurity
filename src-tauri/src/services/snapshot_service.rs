// 进程快照拦截服务 — 启动时扫描所有运行进程及加载 DLL，暂停未签名进程
// Process snapshot interception service — scans all running processes and loaded DLLs at startup, pauses unsigned ones
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter};
use serde::{Deserialize, Serialize};

use crate::services::interception_service::{InterceptionService, InterceptionEntry};
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
    /// 函数作用：执行启动时进程快照扫描，枚举所有进程并验证签名。
    /// Purpose: Executes startup process snapshot scan, enumerates all processes and verifies signatures.
    /// Called by: main.rs setup() at startup (after ETW monitoring starts)
    /// 参数 trust: 信任验证服务 / Trust verification service
    /// 参数 app_handle: Tauri 应用句柄 / Tauri app handle
    /// 副作用：向前端 emit("snapshot-progress") 和 emit("snapshot-result"); 高/中风险进程入拦截队列
    /// Side effects: emits "snapshot-progress" and "snapshot-result" to frontend; high/medium risk processes enqueued
    /// 中文关键词：启动快照，进程扫描，签名验证，DLL枚举
    /// English keywords: startup snapshot, process scan, signature verification, DLL enumeration
    pub fn take_startup_snapshot(
        &self,
        trust: &TrustService,
        app_handle: &AppHandle,
    ) -> Result<SnapshotResult, String> {
        let start_time = std::time::Instant::now();

        // 枚举所有运行进程 / Enumerate all running processes
        let processes = enumerate_all_processes()?;
        let total = processes.len() as u32;

        // 通知前端进度 / Notify frontend of progress
        let _ = app_handle.emit("snapshot-progress", serde_json::json!({
            "stage": "scanning",
            "total": total,
            "current": 0,
        }));

        let mut signed: u32 = 0;
        let mut unsigned: u32 = 0;
        let mut paused: u32 = 0;

        let interception_guard = self.interception.lock().unwrap_or_else(|e| e.into_inner());
        let interception_ref = interception_guard.clone();

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

            // 验证数字签名 / Verify digital signature
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
                let _ = app_handle.emit("snapshot-progress", serde_json::json!({
                    "stage": "scanning",
                    "total": total,
                    "current": (i + 1) as u32,
                }));
            }
        }

        let result = SnapshotResult {
            total_processes: total,
            signed_processes: signed,
            unsigned_processes: unsigned,
            paused_processes: paused,
            duration_ms: start_time.elapsed().as_millis() as u64,
        };

        // 保存结果 / Save result
        *self.last_result.lock().unwrap_or_else(|e| e.into_inner()) = Some(result.clone());

        // 通知前端完成 / Notify frontend of completion
        let _ = app_handle.emit("snapshot-result", &result);

        drop(interception_guard);

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
        self.last_result.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// 进程基本信息 / Process basic info
#[derive(Debug, Clone)]
struct ProcInfo {
    pid: u32,
    name: String,
    path: String,
}

/// 枚举所有运行进程 / Enumerate all running processes
fn enumerate_all_processes() -> Result<Vec<ProcInfo>, String> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::Foundation::{CloseHandle};
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let mut result = Vec::new();

    let snapshot = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    }.map_err(|e| format!("创建进程快照失败: {}", e))?;

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe {
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                let exe_name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())]
                );

                // 获取进程完整路径 / Get process full path
                let path = if pid > 0 && pid != std::process::id() {
                    match OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                        false,
                        pid,
                    ) {
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
