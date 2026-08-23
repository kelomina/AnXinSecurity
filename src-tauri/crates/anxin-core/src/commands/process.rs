// 进程控制命令 — 使用 libloading 动态加载 ntdll Native API
// Process control commands — uses libloading to dynamically load ntdll Native API
use crate::services::ipc_bridge_service::IpcBridgeService;
use crate::services::ipc_protocol::methods;
use crate::services::process_control_service::{
    resume_process_by_pid, suspend_process_by_pid, terminate_process_by_pid,
};
use crate::services::process_monitor_service::ProcessMonitorService;
use std::sync::Arc;
use tauri::{AppHandle, Manager};

/// 函数名称：suspend_process
/// 函数作用：挂起指定 PID 的进程（通过 NtSuspendProcess 动态调用）。
/// Purpose: Suspends the process identified by PID (via dynamic NtSuspendProcess call).
/// 中文关键词：挂起进程，暂停进程，进程控制，NtSuspendProcess
/// English keywords: suspend process, pause process, process control, NtSuspendProcess
#[tauri::command]
pub async fn suspend_process(pid: u32) -> Result<bool, String> {
    suspend_process_by_pid(pid)
}

/// 函数名称：resume_process
/// 函数作用：恢复指定 PID 的进程（通过 NtResumeProcess 动态调用）。
/// Purpose: Resumes the process identified by PID (via dynamic NtResumeProcess call).
/// 中文关键词：恢复进程，继续进程，进程控制，NtResumeProcess
/// English keywords: resume process, continue process, process control, NtResumeProcess
#[tauri::command]
pub async fn resume_process(pid: u32) -> Result<bool, String> {
    resume_process_by_pid(pid)
}

/// 函数名称：terminate_process
/// 函数作用：终止指定 PID 的进程。
/// Purpose: Terminates the process identified by PID.
/// 中文关键词：终止进程，结束进程，进程控制，TerminateProcess
/// English keywords: terminate process, kill process, process control, TerminateProcess
#[tauri::command]
pub async fn terminate_process(pid: u32) -> Result<bool, String> {
    terminate_process_by_pid(pid)
}

/// 函数名称：start_process_watcher
/// 函数作用：启动进程监控服务，轮询新进程并对未签名进程注入 file_hook；路径参数为空时由后端解析默认开发目录或打包资源路径。
/// Purpose: Starts the process monitor service, polls new processes and injects file_hook into unsigned ones; empty path parameters are resolved from development or bundled resource defaults.
/// 调用方：前端设置页面
/// Called by: Frontend settings page
/// 被调用方：ProcessMonitorService::start_with_resource_dir，AppHandle::path().resource_dir。
/// Calls: ProcessMonitorService::start_with_resource_dir, AppHandle::path().resource_dir.
/// 参数说明：injector_x64/injector_x86/dll_x64/dll_x86 为空时使用后端默认路径；interval_ms 为轮询间隔。
/// Parameters: injector_x64/injector_x86/dll_x64/dll_x86 use backend defaults when empty; interval_ms is the polling interval.
/// 错误处理：resource_dir 获取失败时继续使用开发目录候选；注入器或 DLL 缺失由服务层返回明确错误。
/// Error handling: resource_dir failures fall back to development candidates; missing injector or DLL paths are reported by the service layer.
/// 中文关键词：进程监控，启动监控，注入监控，默认路径，资源目录
/// English keywords: process monitor, start monitor, inject monitor, default path, resource directory
#[tauri::command]
pub async fn start_process_watcher(
    app_handle: AppHandle,
    injector_x64: String,
    injector_x86: String,
    dll_x64: String,
    dll_x86: String,
    interval_ms: u32,
) -> Result<bool, String> {
    // 双进程架构下，进程监控由服务进程管理，UI 进程无需启动
    //  In dual-process architecture, process monitoring is managed by the service process
    if app_handle
        .try_state::<Arc<IpcBridgeService>>()
        .map(|b| b.is_connected())
        .unwrap_or(false)
    {
        return Ok(true);
    }

    let watcher = app_handle
        .try_state::<ProcessMonitorService>()
        .ok_or("ProcessMonitorService not managed")?;
    let resource_dir = app_handle.path().resource_dir().ok();
    watcher.start_with_resource_dir(
        &injector_x64,
        &injector_x86,
        &dll_x64,
        &dll_x86,
        interval_ms,
        resource_dir.as_deref(),
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
pub async fn stop_process_watcher(app_handle: AppHandle) -> Result<bool, String> {
    // 双进程架构下，进程监控由服务进程管理，UI 进程无需停止
    //  In dual-process architecture, process monitoring is managed by the service process
    if app_handle
        .try_state::<Arc<IpcBridgeService>>()
        .map(|b| b.is_connected())
        .unwrap_or(false)
    {
        return Ok(true);
    }

    let watcher = app_handle
        .try_state::<ProcessMonitorService>()
        .ok_or("ProcessMonitorService not managed")?;
    watcher.stop()?;
    Ok(true)
}

/// 函数名称：get_process_watcher_status
/// 函数作用：查询 APIHook 进程监控 watcher 是否正在运行。
/// Purpose: Queries whether the APIHook process monitor watcher is running.
/// 调用方：前端 getMonitoringRuntimeStatus。
/// Called by: frontend getMonitoringRuntimeStatus.
/// 被调用方：ProcessMonitorService::is_running。
/// Calls: ProcessMonitorService::is_running.
/// 返回值说明：true 表示 watcher 已启动，false 表示未启动。
/// Returns: true when the watcher is started, false when stopped.
/// 中文关键词：APIHook状态，进程监控状态，运行态查询
/// English keywords: APIHook status, process monitor status, runtime query
#[tauri::command]
pub async fn get_process_watcher_status(app_handle: AppHandle) -> Result<bool, String> {
    // 优先查询本地 ProcessMonitorService state
    //  Check local ProcessMonitorService state first
    if let Some(watcher) = app_handle.try_state::<ProcessMonitorService>() {
        return Ok(watcher.is_running());
    }

    // 本地未管理 ProcessMonitorService（双进程架构下 UI 进程连接到服务进程时），
    // 通过 IPC 查询服务进程的状态
    //  Local ProcessMonitorService not managed (UI process connected to service process in
    //  dual-process architecture); query service process status via IPC
    if let Some(ipc_bridge) = app_handle.try_state::<Arc<IpcBridgeService>>() {
        if ipc_bridge.is_connected() {
            let result = ipc_bridge
                .request(methods::GET_STATUS, serde_json::json!({}))
                .map_err(|e| format!("Failed to query process watcher status via IPC: {}", e))?;
            // ProcessMonitorService 在服务进程中注册时即视为运行
            //  ProcessMonitorService is considered running when registered in service process
            return Ok(result
                .get("process_monitor_running")
                .and_then(|v| v.as_bool())
                .unwrap_or(false));
        }
    }

    Ok(false)
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
    app_handle: AppHandle,
    paths: Vec<String>,
) -> Result<u32, String> {
    // 双进程架构下，签名白名单由服务进程管理，UI 进程直接返回
    //  In dual-process architecture, signed list is managed by the service process
    if app_handle
        .try_state::<Arc<IpcBridgeService>>()
        .map(|b| b.is_connected())
        .unwrap_or(false)
    {
        return Ok(paths.len() as u32);
    }

    let watcher = app_handle
        .try_state::<ProcessMonitorService>()
        .ok_or("ProcessMonitorService not managed")?;
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
pub async fn poll_new_pids(app_handle: AppHandle) -> Result<Vec<u32>, String> {
    // 双进程架构下，PID 轮询由服务进程通过事件推送，UI 进程返回空列表
    //  In dual-process architecture, PID polling is handled by service process via event push
    if app_handle
        .try_state::<Arc<IpcBridgeService>>()
        .map(|b| b.is_connected())
        .unwrap_or(false)
    {
        return Ok(Vec::new());
    }

    let watcher = app_handle
        .try_state::<ProcessMonitorService>()
        .ok_or("ProcessMonitorService not managed")?;
    watcher.poll_new_pids()
}
