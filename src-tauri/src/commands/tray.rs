// 托盘相关命令
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};

use crate::models::config::AppConfig;
use crate::services::tray_service::TrayService;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitConfirmation {
    pub keep_service: bool,
    pub prompt_enabled: bool,
}

/// 请求退出确认
#[tauri::command]
pub async fn request_exit_confirmation(
    state: State<'_, Arc<Mutex<AppConfig>>>,
) -> Result<ExitConfirmation, String> {
    let config = state.lock().map_err(|e| e.to_string())?;

    // 读取托盘退出配置
    let tray_cfg = &config.tray;
    let prompt_enabled = tray_cfg.exit_keep_scanner_service_prompt.unwrap_or(true);
    let default_keep = tray_cfg.exit_keep_scanner_service_default.unwrap_or(true);

    Ok(ExitConfirmation {
        keep_service: default_keep,
        prompt_enabled,
    })
}

/// 执行退出操作
#[tauri::command]
pub async fn execute_exit(
    app_handle: AppHandle,
    keep_service: bool,
) -> Result<(), String> {
    // TODO: 如果 keep_service 为 false，需要停止扫描引擎
    // 目前扫描引擎是通过外部 exe 运行的，这里可以添加停止逻辑
    
    if !keep_service {
        // 通知前端即将退出
        let _ = app_handle.emit("app-exiting", ());
        
        // 在这里可以添加清理逻辑
        // 例如：停止 ETW 监控、保存状态等
    }

    // 退出应用
    app_handle.exit(0);
    Ok(())
}

/// 最小化窗口到托盘
#[tauri::command]
pub async fn minimize_to_tray(app_handle: AppHandle) -> Result<(), String> {
    TrayService::hide_to_tray(&app_handle);
    Ok(())
}
