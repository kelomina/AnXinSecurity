// Hook 服务命令 — 文件钩子服务控制
// Hook service commands — file hook service control
use crate::services::hook_service::HookService;
use crate::services::ipc_bridge_service::IpcBridgeService;
use crate::services::ipc_protocol::methods;
use std::sync::Arc;
use tauri::{AppHandle, Manager, Runtime};

/// 函数名称：start_hook_service
/// 函数作用：启动文件钩子命名管道服务。
/// Purpose: Starts the file hook named pipe service.
/// 参数 pipe_name: 管道名称后缀，默认 "anxin_security_filehook"/ Pipe name suffix
/// 参数 app_handle: Tauri 应用句柄，用于 HookService 分发事件 / Tauri app handle for event dispatch
/// 调用方：前端 SettingsPage 或 main.rs 初始化
/// Called by: Frontend SettingsPage or main.rs initialization
/// 被调用方：HookService::start。
/// Calls: HookService::start.
/// 中文关键词：启动钩子，命名管道启动，事件分发
/// English keywords: start hook, named pipe start, event dispatch
#[tauri::command]
pub fn start_hook_service(
    app_handle: tauri::AppHandle,
    pipe_name: Option<String>,
) -> Result<bool, String> {
    // 双进程架构下，文件钩子由服务进程管理，UI 进程无需启动
    //  In dual-process architecture, file hook is managed by the service process; no need to start in UI process
    if app_handle
        .try_state::<Arc<IpcBridgeService>>()
        .map(|b| b.is_connected())
        .unwrap_or(false)
    {
        return Ok(true);
    }

    let hook = app_handle
        .try_state::<Arc<HookService>>()
        .ok_or("HookService not managed")?;
    let name = pipe_name.unwrap_or_else(|| "anxin_security_filehook".to_string());
    let ctx = crate::services::service_context::build_etw_service_context(&app_handle);
    hook.start(&name, ctx)?;
    Ok(true)
}

/// 函数名称：stop_hook_service
/// 函数作用：停止文件钩子命名管道服务。
/// Purpose: Stops the file hook named pipe service.
/// 调用方：前端 SettingsPage 或 main.rs 关闭
/// Called by: Frontend SettingsPage or main.rs shutdown
/// 中文关键词：停止钩子，关闭管道
/// English keywords: stop hook, close pipe
#[tauri::command]
pub fn stop_hook_service(app_handle: tauri::AppHandle) -> Result<bool, String> {
    // 双进程架构下，文件钩子由服务进程管理，UI 进程无需停止
    //  In dual-process architecture, file hook is managed by the service process; no need to stop in UI process
    if app_handle
        .try_state::<Arc<IpcBridgeService>>()
        .map(|b| b.is_connected())
        .unwrap_or(false)
    {
        return Ok(true);
    }

    let hook = app_handle
        .try_state::<Arc<HookService>>()
        .ok_or("HookService not managed")?;
    hook.stop()?;
    Ok(true)
}

/// 函数名称：get_hook_status
/// 函数作用：获取文件钩子服务运行状态。
/// Purpose: Gets file hook service running status.
/// 调用方：前端概览页、设置页
/// Called by: Frontend overview page, settings page
/// 中文关键词：钩子状态，运行状态，服务进程，IPC 查询
/// English keywords: hook status, running state, service process, IPC query
#[tauri::command]
pub fn get_hook_status<R: Runtime>(app_handle: AppHandle<R>) -> Result<bool, String> {
    // 优先查询本地 HookService state
    //  Check local HookService state first
    if let Some(hook) = app_handle.try_state::<Arc<HookService>>() {
        return Ok(hook.is_running());
    }

    // 本地未管理 HookService（双进程架构下 UI 进程连接到服务进程时），
    // 通过 IPC 查询服务进程的状态
    //  Local HookService not managed (UI process connected to service process in dual-process
    //  architecture); query service process status via IPC
    if let Some(ipc_bridge) = app_handle.try_state::<Arc<IpcBridgeService>>() {
        if ipc_bridge.is_connected() {
            let result = ipc_bridge
                .request(methods::GET_STATUS, serde_json::json!({}))
                .map_err(|e| format!("Failed to query hook status via IPC: {}", e))?;
            return Ok(result
                .get("file_hook_running")
                .and_then(|v| v.as_bool())
                .unwrap_or(false));
        }
    }

    // 既无本地 state 也无 IPC 连接，返回 false
    //  No local state and no IPC connection, return false
    Ok(false)
}
