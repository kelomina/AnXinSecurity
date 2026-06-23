// 托盘相关命令
//  Tray icon related commands
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, Runtime, State};

use crate::models::config::AppConfig;
use crate::services::app_lifecycle_service::AppLifecycleService;
use crate::services::engine_service::EngineService;
use crate::services::etw_service::EtwService;
use crate::services::file_monitor_service::FileMonitorService;
use crate::services::hook_service::HookService;
use crate::services::interception_service::InterceptionService;
use crate::services::process_monitor_service::ProcessMonitorService;
use crate::services::process_scanner_service::ProcessScannerService;
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
pub async fn execute_exit(app_handle: AppHandle, keep_service: bool) -> Result<(), String> {
    let first_exit_request = app_handle
        .try_state::<AppLifecycleService>()
        .map(|lifecycle| lifecycle.begin_exit())
        .unwrap_or(true);

    if !first_exit_request {
        return Ok(());
    }

    let app_handle_for_exit = app_handle.clone();
    tauri::async_runtime::spawn(async move {
        // 关键点：不要在 invoke 命令返回前销毁发起调用的 WebView。
        // 如果命令还没把 Ok 响应送回前端就 close window，Tauri/WebView2 可能会继续向旧窗口句柄 PostMessage。
        tokio::time::sleep(Duration::from_millis(75)).await;
        execute_exit_after_invoke_response(app_handle_for_exit, keep_service).await;
    });

    Ok(())
}

async fn execute_exit_after_invoke_response(app_handle: AppHandle, keep_service: bool) {
    // 通知前端即将退出。这里不走生命周期过滤，因为这是退出流程本身的最后 UI 通知。
    let _ = app_handle.emit("app-exiting", ());

    if !keep_service {
        if let Some(process_scanner) = app_handle.try_state::<ProcessScannerService>() {
            process_scanner.stop();
        }

        if let Some(process_monitor) = app_handle.try_state::<ProcessMonitorService>() {
            let _ = process_monitor.stop();
        }

        if let Some(file_monitor) = app_handle.try_state::<FileMonitorService>() {
            file_monitor.stop();
        }

        if let Some(hook) = app_handle.try_state::<Arc<HookService>>() {
            let _ = hook.stop();
        }

        // 停止 ETW 监控（通过 pause 方法停止轮询并释放 bridge）
        if let Some(etw_state) = app_handle.try_state::<Arc<Mutex<EtwService>>>() {
            if let Ok(etw) = etw_state.lock() {
                let _ = etw.pause();
            }
        }

        if let Some(engine) = app_handle.try_state::<Arc<EngineService>>() {
            let _ = engine.stop_engine().await;
        }

        // 保存配置
        if let Some(config_state) = app_handle.try_state::<Arc<Mutex<AppConfig>>>() {
            if let Ok(config) = config_state.lock() {
                let _ = config.save();
            }
        }
    }

    // 先停监控和事件来源，再恢复/清理拦截队列，避免退出窗口期又挂起新进程。
    if let Some(interception) = app_handle.try_state::<Arc<InterceptionService>>() {
        interception.clear_all();
    }

    // 这里已经等 invoke 响应返回，也已经停止后台事件源，可以安全销毁 WebView 窗口。
    // 使用 destroy() 而不是 close()：close() 会再次触发 CloseRequested 事件，隐藏的拦截窗口
    // 或前端关闭逻辑可能在退出窗口期再参与一次；destroy() 则是退出流程里的单向收口。
    // 先销毁独立拦截窗口，再销毁主窗口，避免隐藏 WebView 留到 Chromium/WebView2 最后清理时
    // 触发 Chrome_WidgetWin_0 窗口类重复注销噪声。
    destroy_webview_windows_for_exit(&app_handle);
    tokio::time::sleep(Duration::from_millis(150)).await;
    app_handle.exit(0);
}

fn destroy_webview_windows_for_exit<R: Runtime>(app_handle: &AppHandle<R>) {
    let windows = app_handle.webview_windows();
    let mut labels: Vec<String> = windows.keys().cloned().collect();

    labels.sort_by_key(|label| match label.as_str() {
        // 独立拦截窗口通常是隐藏窗口，先收掉它，避免它在 Tauri 最终 cleanup 阶段仍被保留。
        "interception" => 0,
        // 主窗口最后收，确保退出命令的 invoke 响应有最大机会先回到发起方。
        "main" => 2,
        _ => 1,
    });

    for label in labels {
        if let Some(window) = app_handle.get_webview_window(&label) {
            if let Err(err) = window.destroy() {
                eprintln!(
                    "[TrayExit] Failed to destroy webview window '{}' during exit: {}",
                    label, err
                );
            }
        }
    }
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
