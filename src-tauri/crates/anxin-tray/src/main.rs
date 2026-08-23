// AnXinTray — 托盘进程（拆分后的 Tray 角色）
//  AnXinTray - tray process (the split-out Tray role)
//
// 职责边界：
// - 系统托盘图标与菜单（打开主界面 / 完全退出）
// - 独立拦截弹窗窗口（process-intercepted / network-intercepted 的展示与决策）
// - 退出确认小窗口（exit-confirm）
// - IPC 桥接客户端：连接 AnXinService，转发事件、转发决策请求
// - 本进程不运行任何防护采集组件；主界面由 Main 进程按需提供
//
// 中文关键词：托盘进程，拦截弹窗，退出确认，IPC 桥接
// English keywords: tray process, interception window, exit confirmation, IPC bridge
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anxin_security::commands;
use anxin_security::models::config::AppConfig;
use anxin_security::services::app_lifecycle_service::AppLifecycleService;
use anxin_security::services::interception_service::InterceptionService;
use anxin_security::services::interception_window_service::prepare_interception_window;
use anxin_security::services::ipc_bridge_service::{commands as ipc_bridge_commands, IpcBridgeService};
use anxin_security::services::tray_service::TrayService;
use anxin_security::services::trust_service::TrustService;
use std::sync::{Arc, Mutex};
use tauri::{Manager, RunEvent};

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|_app, _argv, _cwd| {
            // Tray 自身单实例：第二个实例直接退出（无窗口可激活）。
            //  Tray single-instance: the second instance simply exits (no window to activate).
        }))
        .setup(|app| {
            // 注册应用生命周期状态。退出时先设置这个状态，隐藏的窗口就不会再阻止关闭。
            app.manage(AppLifecycleService::new());

            // 初始化托盘（轻量级，可保留在主线程）
            TrayService::create_tray(app.handle())
                .map_err(|e| {
                    eprintln!("Failed to create tray: {}", e);
                })
                .ok();

            // 初始化配置（轻量级 JSON 读取）——供 i18n 与退出确认配置使用
            let config = AppConfig::load().unwrap_or_default();
            app.manage(Arc::new(Mutex::new(config)));

            // 拦截服务：仅承载「已被挂起进程」的处置通道（IPC 转发失败时的安全网，
            // 方向是恢复进程而非维持挂起），不运行任何防护采集组件。
            let interception_service = Arc::new(InterceptionService::new());
            app.manage(interception_service.clone());

            // 信任验证：拦截弹窗展示签名者信息所需（轻量构造）
            app.manage(Arc::new(TrustService::new()));

            // IPC 桥接：连接服务进程并转发事件（process-intercepted → interception 窗口）
            let ipc_bridge = Arc::new(IpcBridgeService::new());
            app.manage(ipc_bridge.clone());

            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                match ipc_bridge.start(&app_handle) {
                    Ok(true) => {
                        eprintln!("[Tray] Connected to service process");
                    }
                    Ok(false) => {
                        // 服务未运行：托盘仍驻留；防护状态经 get_protection_status 呈现降级。
                        eprintln!("[Tray] Service process not running; tray stays resident");
                    }
                    Err(e) => {
                        eprintln!("[Tray] IPC bridge start failed: {} (non-fatal)", e);
                    }
                }
                // 预建隐藏的独立拦截窗口，避免首次拦截时才创建造成延迟
                if let Err(e) = prepare_interception_window(&app_handle) {
                    eprintln!("[Tray] Failed to prepare interception window: {}", e);
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // 拦截弹窗决策链路
            commands::interception::handle_interception,
            commands::interception::peek_current_interception,
            commands::interception::get_interception_queue,
            commands::interception::get_interception_status,
            commands::interception::get_interception_signer_info,
            // 网络连接询问（经 IPC 转发到服务进程）
            commands::firewall::handle_network_decision,
            commands::firewall::get_network_pending,
            // 国际化（弹窗与托盘文案）
            commands::i18n::get_locale,
            commands::i18n::get_translations,
            commands::i18n::set_locale,
            // 退出确认流程
            commands::tray::request_exit_confirmation,
            commands::tray::execute_exit,
            // IPC 状态查询
            ipc_bridge_commands::is_ipc_connected,
            ipc_bridge_commands::get_protection_status,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tray application")
        .run(|app_handle, event| match event {
            RunEvent::ExitRequested { .. } => {
                if let Some(lifecycle) = app_handle.try_state::<AppLifecycleService>() {
                    lifecycle.begin_exit();
                }
            }
            RunEvent::Exit => {
                if let Some(lifecycle) = app_handle.try_state::<AppLifecycleService>() {
                    lifecycle.begin_exit();
                }
                if let Some(interception) = app_handle.try_state::<Arc<InterceptionService>>() {
                    interception.clear_all();
                }
            }
            _ => {}
        });
}
