// 托盘相关命令
//  Tray icon related commands
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};

use crate::models::config::AppConfig;
use crate::services::etw_service::EtwService;
use crate::services::tray_service::TrayService;

/// 退出确认配置
/// Exit confirmation configuration returned to frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitConfirmation {
    pub keep_service: bool,
    pub prompt_enabled: bool,
}

/// 函数名称：request_exit_confirmation
/// 函数作用：从配置读取托盘退出设置，返回 ExitConfirmation 给前端。
/// Purpose: Reads tray exit settings from config and returns ExitConfirmation to frontend.
/// 调用方：前端 TrayExitPrompt 组件
/// Called by: Frontend TrayExitPrompt component
/// 中文关键词：退出确认，托盘，配置，扫描引擎，提示
/// English keywords: exit confirmation, tray, config, scanner service, prompt
#[tauri::command]
pub async fn request_exit_confirmation(
    state: State<'_, Arc<Mutex<AppConfig>>>,
) -> Result<ExitConfirmation, String> {
    let config = state.lock().map_err(|e| e.to_string())?;

    let tray_cfg = &config.tray;
    let prompt_enabled = tray_cfg.exit_keep_scanner_service_prompt.unwrap_or(true);
    let default_keep = tray_cfg.exit_keep_scanner_service_default.unwrap_or(true);

    Ok(ExitConfirmation {
        keep_service: default_keep,
        prompt_enabled,
    })
}

/// 函数名称：execute_exit
/// 函数作用：执行应用退出操作。如果 keep_service 为 false，则停止 ETW 监控、保存状态、
///   停止扫描引擎后退出；如果为 true，则保留后台服务仅关闭窗口。
/// Purpose: Executes application exit. If keep_service is false, stops ETW monitoring,
///   saves state, stops scan engine, then exits. If true, keeps background services running.
/// 调用方：前端 TrayExitPrompt 组件
/// Called by: Frontend TrayExitPrompt component
/// 副作用：通知前端 app-exiting 事件，停止 ETW 服务，停止引擎，退出进程
/// Side effects: Emits "app-exiting" event, stops ETW, stops engine, exits process
/// 中文关键词：退出，清理，停止监控，停止引擎，保存状态，优雅退出
/// English keywords: exit, cleanup, stop monitoring, stop engine, save state, graceful exit
#[tauri::command]
pub async fn execute_exit(
    app_handle: AppHandle,
    keep_service: bool,
) -> Result<(), String> {
    // 通知前端即将退出
    let _ = app_handle.emit("app-exiting", ());

    if !keep_service {
        // 停止 ETW 监控（通过 pause 方法停止轮询并释放 bridge）
        if let Some(etw_state) = app_handle.try_state::<Arc<Mutex<EtwService>>>() {
            if let Ok(etw) = etw_state.lock() {
                let _ = etw.pause();
            }
        }

        // 保存配置
        if let Some(config_state) = app_handle.try_state::<Arc<Mutex<AppConfig>>>() {
            if let Ok(config) = config_state.lock() {
                let _ = config.save();
            }
        }

        // 停止扫描引擎（通过发送退出命令）
        // 引擎自动启动服务在 main.rs 中被管理为 Arc<Mutex<EngineAutostartService>>
        // 引擎退出由其自身进程管理，在此处仅尝试发送退出信号
        use crate::services::engine_autostart_service::EngineAutostartService;
        if let Some(autostart_state) = app_handle.try_state::<Arc<Mutex<EngineAutostartService>>>() {
            if let Ok(autostart) = autostart_state.lock() {
                let _ = autostart.post_exit_command();
            }
        }
    }

    // 退出应用
    app_handle.exit(0);
    Ok(())
}

/// 函数名称：minimize_to_tray
/// 函数作用：将应用窗口最小化到系统托盘，不退出进程。
/// Purpose: Minimizes the window to system tray without exiting the process.
/// 调用方：前端标题栏关闭按钮、托盘菜单
/// Called by: Frontend titlebar close button, tray menu
/// 中文关键词：最小化，托盘，隐藏窗口，后台运行
/// English keywords: minimize, tray, hide window, background running
#[tauri::command]
pub async fn minimize_to_tray(app_handle: AppHandle) -> Result<(), String> {
    TrayService::hide_to_tray(&app_handle);
    Ok(())
}
