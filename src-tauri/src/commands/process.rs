// 进程控制命令 — 使用 libloading 动态加载 ntdll Native API
// Process control commands — uses libloading to dynamically load ntdll Native API
use crate::services::process_monitor_service::ProcessMonitorService;
use libloading::{Library, Symbol};
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Threading::*;

/// 保护进程白名单 / Protected process whitelist
const PROTECTED_PROCESSES: &[&str] = &[
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
];

/// 检查进程是否为受保护的系统进程 / Check if process is a protected system process
fn is_protected_process(pid: u32) -> Result<bool, String> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| format!("Failed to create process snapshot: {}", e))?;

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe {
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    let exe_name = String::from_utf16_lossy(
                        &entry.szExeFile[..entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len())],
                    )
                    .to_lowercase();

                    let is_protected = PROTECTED_PROCESSES
                        .iter()
                        .any(|&name| exe_name.contains(name));

                    CloseHandle(snapshot).ok();
                    return Ok(is_protected);
                }

                if !Process32NextW(snapshot, &mut entry).is_ok() {
                    break;
                }
            }
        }
        CloseHandle(snapshot).ok();
    }

    Err("Process not found".to_string())
}

/// 函数名称：suspend_process
/// 函数作用：挂起指定 PID 的进程（通过 NtSuspendProcess 动态调用）。
/// Purpose: Suspends the process identified by PID (via dynamic NtSuspendProcess call).
/// 中文关键词：挂起进程，暂停进程，进程控制，NtSuspendProcess
/// English keywords: suspend process, pause process, process control, NtSuspendProcess
#[tauri::command]
pub async fn suspend_process(pid: u32) -> Result<bool, String> {
    if is_protected_process(pid)? {
        return Err("无法操作受保护的系统进程".to_string());
    }
    if pid == std::process::id() {
        return Err("无法操作当前进程".to_string());
    }

    unsafe {
        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid)
            .map_err(|e| format!("Failed to open process (PID: {}): {}", pid, e))?;

        let result = call_nt_function("NtSuspendProcess", handle);

        CloseHandle(handle).ok();

        result
    }
}

/// 函数名称：resume_process
/// 函数作用：恢复指定 PID 的进程（通过 NtResumeProcess 动态调用）。
/// Purpose: Resumes the process identified by PID (via dynamic NtResumeProcess call).
/// 中文关键词：恢复进程，继续进程，进程控制，NtResumeProcess
/// English keywords: resume process, continue process, process control, NtResumeProcess
#[tauri::command]
pub async fn resume_process(pid: u32) -> Result<bool, String> {
    if is_protected_process(pid)? {
        return Err("无法操作受保护的系统进程".to_string());
    }

    unsafe {
        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid)
            .map_err(|e| format!("Failed to open process (PID: {}): {}", pid, e))?;

        let result = call_nt_function("NtResumeProcess", handle);

        CloseHandle(handle).ok();

        result
    }
}

/// 函数名称：terminate_process
/// 函数作用：终止指定 PID 的进程。
/// Purpose: Terminates the process identified by PID.
/// 中文关键词：终止进程，结束进程，进程控制，TerminateProcess
/// English keywords: terminate process, kill process, process control, TerminateProcess
#[tauri::command]
pub async fn terminate_process(pid: u32) -> Result<bool, String> {
    if is_protected_process(pid)? {
        return Err("无法终止受保护的系统进程".to_string());
    }
    if pid == std::process::id() {
        return Err("无法终止当前进程".to_string());
    }

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid)
            .map_err(|e| format!("Failed to open process (PID: {}): {}", pid, e))?;

        let result = TerminateProcess(handle, 1);

        CloseHandle(handle).ok();

        if result.is_ok() {
            Ok(true)
        } else {
            Err("TerminateProcess failed".to_string())
        }
    }
}

/// 动态加载 ntdll.dll 并调用指定 NT 函数 / Dynamically load ntdll.dll and call named NT function
/// 使用 libloading 避免 windows-core 版本冲突 / Uses libloading to avoid windows-core version conflicts
unsafe fn call_nt_function(func_name: &str, handle: HANDLE) -> Result<bool, String> {
    let ntdll =
        Library::new("ntdll.dll").map_err(|e| format!("Failed to load ntdll.dll: {}", e))?;

    let func: Symbol<unsafe extern "system" fn(HANDLE) -> i32> = ntdll
        .get(func_name.as_bytes())
        .map_err(|e| format!("Failed to get {}: {}", func_name, e))?;

    let status = func(handle);

    // NT_SUCCESS(status) == 0
    if status == 0 {
        Ok(true)
    } else {
        Err(format!(
            "{} failed with status: 0x{:X}",
            func_name, status as u32
        ))
    }
}

/// 内部函数：终止进程（供拦截服务调用） / Internal: terminate process (for interception service)
/// Internal function callable from other command modules for automated process termination.
/// 中文关键词：内部终止，拦截终止
/// English keywords: internal terminate, interception terminate
pub async fn terminate_process_internal(pid: u32) -> Result<bool, String> {
    if is_protected_process(pid)? {
        return Err("无法操作受保护的系统进程".to_string());
    }
    if pid == std::process::id() {
        return Err("无法操作当前进程".to_string());
    }

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid)
            .map_err(|e| format!("Failed to open process (PID: {}): {}", pid, e))?;

        let result = TerminateProcess(handle, 1);

        CloseHandle(handle).ok();

        if result.is_ok() {
            Ok(true)
        } else {
            Err("TerminateProcess failed".to_string())
        }
    }
}

/// 函数名称：start_process_watcher
/// 函数作用：启动进程监控服务，轮询新进程并对未签名进程注入 file_hook。
/// Purpose: Starts the process monitor service, polls new processes and injects file_hook into unsigned ones.
/// 调用方：前端设置页面
/// Called by: Frontend settings page
/// 中文关键词：进程监控，启动监控，注入监控
/// English keywords: process monitor, start monitor, inject monitor
#[tauri::command]
pub async fn start_process_watcher(
    watcher: tauri::State<'_, ProcessMonitorService>,
    injector_x64: String,
    injector_x86: String,
    dll_x64: String,
    dll_x86: String,
    interval_ms: u32,
) -> Result<bool, String> {
    // ProcessMonitorService 需要可变引用，但 Tauri state 是共享引用
    // 使用内部 Mutex 来获取可变性
    watcher.start(
        &injector_x64,
        &injector_x86,
        &dll_x64,
        &dll_x86,
        interval_ms,
    )
}

/// 函数名称：stop_process_watcher
/// 函数作用：停止进程监控服务。
/// Purpose: Stops the process monitor service.
/// 调用方：前端设置页面
/// Called by: Frontend settings page
/// 中文关键词：停止监控，停止进程监控
/// English keywords: stop monitor, stop process monitor
#[tauri::command]
pub async fn stop_process_watcher(
    watcher: tauri::State<'_, ProcessMonitorService>,
) -> Result<bool, String> {
    watcher.stop()?;
    Ok(true)
}

/// 函数名称：set_signed_process_list
/// 函数作用：设置已签名进程白名单，预填签名缓存。
/// Purpose: Sets the signed process whitelist, pre-fills signature cache.
/// 调用方：前端初始化时传递已知可信进程
/// Called by: Frontend on init passing known trusted processes
/// 中文关键词：签名白名单，可信进程列表
/// English keywords: signature whitelist, trusted process list
#[tauri::command]
pub async fn set_signed_process_list(
    watcher: tauri::State<'_, ProcessMonitorService>,
    paths: Vec<String>,
) -> Result<u32, String> {
    watcher.set_signed_list(&paths)
}

/// 函数名称：poll_new_pids
/// 函数作用：轮询获取新发现的进程 PID 列表。
/// Purpose: Polls for newly discovered process PID list.
/// 调用方：前端事件轮询
/// Called by: Frontend event polling
/// 中文关键词：轮询新进程，PID列表
/// English keywords: poll new processes, PID list
#[tauri::command]
pub async fn poll_new_pids(
    watcher: tauri::State<'_, ProcessMonitorService>,
) -> Result<Vec<u32>, String> {
    watcher.poll_new_pids()
}
