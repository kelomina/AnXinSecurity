// Hook 服务命令 — 文件钩子服务控制
// Hook service commands — file hook service control
use crate::services::hook_service::HookService;
use std::sync::Arc;

/// 函数名称：start_hook_service
/// 函数作用：启动文件钩子命名管道服务。
/// Purpose: Starts the file hook named pipe service.
/// 参数 pipe_name: 管道名称后缀，默认 "anxin_security_filehook"/ Pipe name suffix
/// 调用方：前端 SettingsPage 或 main.rs 初始化
/// Called by: Frontend SettingsPage or main.rs initialization
/// 中文关键词：启动钩子，命名管道启动
/// English keywords: start hook, named pipe start
#[tauri::command]
pub fn start_hook_service(
    hook: tauri::State<'_, Arc<HookService>>,
    pipe_name: Option<String>,
) -> Result<bool, String> {
    let name = pipe_name.unwrap_or_else(|| "anxin_security_filehook".to_string());
    hook.start(&name)?;
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
pub fn stop_hook_service(hook: tauri::State<'_, Arc<HookService>>) -> Result<bool, String> {
    hook.stop()?;
    Ok(true)
}

/// 函数名称：get_hook_status
/// 函数作用：获取文件钩子服务运行状态。
/// Purpose: Gets file hook service running status.
/// 调用方：前端概览页
/// Called by: Frontend overview page
/// 中文关键词：钩子状态，运行状态
/// English keywords: hook status, running state
#[tauri::command]
pub fn get_hook_status(hook: tauri::State<'_, Arc<HookService>>) -> Result<bool, String> {
    Ok(hook.is_running())
}
