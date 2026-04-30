// Prevents additional console window on Windows in release, DO NOT REMOVE!!
//  禁止在 Windows release 构建中弹出控制台窗口，请勿删除！！
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod services;
mod models;
mod utils;

use tauri::Manager;
use std::sync::{Arc, Mutex};
use sqlx::SqlitePool;
use crate::models::config::AppConfig;
use crate::services::etw_service::EtwService;
use crate::services::engine_service::EngineService;
use crate::services::tray_service::TrayService;
use crate::services::quarantine_service::QuarantineService;
use crate::services::behavior_service::BehaviorService;
use crate::services::engine_autostart_service::EngineAutostartService;
use crate::services::trust_service::TrustService;
use crate::services::process_monitor_service::ProcessMonitorService;
use crate::services::hook_service::HookService;
use crate::services::interception_service::InterceptionService;
use crate::services::risk_service::RiskService;
use crate::services::snapshot_service::SnapshotService;
use crate::services::training_service::TrainingService;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            // 初始化托盘
            TrayService::create_tray(app.handle()).map_err(|e| {
                eprintln!("Failed to create tray: {}", e);
            }).ok();

            // 初始化配置
            let config = AppConfig::load().unwrap_or_default();
            app.manage(Arc::new(Mutex::new(config.clone())));

            // 初始化 ETW 服务
            let etw_service = EtwService::new();
            app.manage(etw_service);

            // 初始化扫描引擎服务 — 从配置读取 IPC 地址和端口
            let engine_host = config.scanner.ipc.host.clone();
            let engine_port = config.scanner.ipc.port;
            let engine_service = EngineService::new(&engine_host, engine_port);
            app.manage(engine_service);

            // 初始化引擎自动启动服务
            let engine_path = "Engine/Axon/axon_engine.exe";
            let autostart_service = EngineAutostartService::new(
                engine_path,
                &engine_host,
                engine_port
            );
            app.manage(Arc::new(Mutex::new(autostart_service)));

            // 初始化 SQLite 数据库池
            let mut db_root = std::env::current_dir()
                .map_err(|e| format!("Failed to get current directory: {}", e))?;
            let db_dir = std::path::Path::new(&config.behavior_analyzer.sqlite.directory);
            for comp in db_dir.components() {
                db_root.push(comp);
            }
            std::fs::create_dir_all(&db_root).map_err(|e| e.to_string())?;
            db_root.push(&config.behavior_analyzer.sqlite.file_name);
            eprintln!("[main] DB path: {}", db_root.display());

            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| format!("Failed to create tokio runtime: {}", e))?;

            let pool = rt.block_on(async {
                use sqlx::sqlite::SqliteConnectOptions;
                let opts = SqliteConnectOptions::new()
                    .filename(&db_root)
                    .create_if_missing(true);
                SqlitePool::connect_with(opts).await
                    .map_err(|e| format!("Failed to connect to database: {}", e))
            })?;

            // 运行迁移 - events 表
            rt.block_on(async {
                sqlx::query(r#"
                    CREATE TABLE IF NOT EXISTS events (
                        id TEXT PRIMARY KEY,
                        pid INTEGER,
                        process_name TEXT,
                        operation TEXT,
                        path TEXT,
                        timestamp TEXT,
                        details TEXT
                    )
                "#).execute(&pool).await.map_err(|e| e.to_string())
            })?;

            // 运行迁移 - quarantine_items 表
            let quarantine_service = QuarantineService::new();
            rt.block_on(async {
                quarantine_service.initialize_database(&pool).await
                    .map_err(|e| format!("Failed to initialize quarantine database: {}", e))
            })?;

            // 管理行为分析服务
            let behavior_service = BehaviorService::new(pool.clone());
            app.manage(Arc::new(Mutex::new(behavior_service)));

            // 初始化信任验证服务
            let trust_service = TrustService::new();
            app.manage(trust_service);

            // 初始化进程监控服务
            let process_monitor_service = ProcessMonitorService::new();
            app.manage(process_monitor_service);

            // 初始化文件钩子服务 — 命名管道服务端
            let hook_service = HookService::new();
            app.manage(Arc::new(hook_service));

            // 初始化拦截队列管理器 — 核心安全组件
            let interception_service = Arc::new(InterceptionService::new());
            app.manage(interception_service.clone());

            // 初始化风险分析服务 — 关联拦截服务和信任服务
            let risk_service = RiskService::new();
            risk_service.set_interception_service(interception_service.clone());
            app.manage(risk_service);

            // 初始化进程快照服务 — 关联拦截服务
            let snapshot_service = SnapshotService::new();
            snapshot_service.set_interception_service(interception_service.clone());
            app.manage(snapshot_service);

            // 初始化 ML 训练服务
            let training_service = TrainingService::new();
            app.manage(training_service);

            // 管理池状态
            app.manage(pool);

            // 启动 ETW 监控
            let app_handle_etw = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = start_etw_monitoring(app_handle_etw).await {
                    eprintln!("Failed to start ETW monitoring: {}", e);
                }
            });

            // 启动启动快照扫描（延迟，等待服务就绪）
            let app_handle_snapshot = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                // 等待1秒确保前端和后端服务都就绪
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                if let Some(trust) = app_handle_snapshot.try_state::<TrustService>() {
                    if let Some(snapshot) = app_handle_snapshot.try_state::<SnapshotService>() {
                        match snapshot.take_startup_snapshot(&trust, &app_handle_snapshot) {
                            Ok(result) => {
                                eprintln!(
                                    "[StartupSnapshot] Done: {} processes, {} signed, {} unsigned, {} paused ({}ms)",
                                    result.total_processes, result.signed_processes,
                                    result.unsigned_processes, result.paused_processes,
                                    result.duration_ms
                                );
                            }
                            Err(e) => eprintln!("[StartupSnapshot] Failed: {}", e),
                        }
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // 配置 (4)
            commands::config::get_config,
            commands::config::set_behavior_monitoring_enabled,
            commands::config::set_theme_mode,
            commands::config::set_animations_enabled,
            // 扫描器 (4)
            commands::scanner::scanner_health,
            commands::scanner::scan_file,
            commands::scanner::scan_batch,
            commands::scanner::cancel_scan,
            // 行为分析 V2 (3)
            commands::behavior_v2::list_behavior_events,
            commands::behavior_v2::list_behavior_processes,
            commands::behavior_v2::clear_behavior_events,
            // 行为分析 V1 (2)
            commands::behavior::pause_etw,
            commands::behavior::resume_etw,
            // 隔离区 (4)
            commands::quarantine::list_quarantine,
            commands::quarantine::isolate_file,
            commands::quarantine::restore_file,
            commands::quarantine::delete_quarantine,
            // 排除项 (4)
            commands::exclusions::list_exclusions,
            commands::exclusions::add_exclusion,
            commands::exclusions::remove_exclusion,
            commands::exclusions::add_exclusions_batch,
            // 允许列表 (4)
            commands::allowlist::list_allowlist,
            commands::allowlist::add_to_allowlist,
            commands::allowlist::remove_from_allowlist,
            commands::allowlist::add_to_allowlist_batch,
            // 托盘 (3)
            commands::tray::request_exit_confirmation,
            commands::tray::execute_exit,
            commands::tray::minimize_to_tray,
            // 进程控制 (7)
            commands::process::suspend_process,
            commands::process::resume_process,
            commands::process::terminate_process,
            commands::process::start_process_watcher,
            commands::process::stop_process_watcher,
            commands::process::set_signed_process_list,
            commands::process::poll_new_pids,
            // 引擎 (2)
            commands::engine::start_engine,
            commands::engine::stop_engine,
            // 信任验证 (6)
            commands::trust::verify_file_signature,
            commands::trust::get_signer_info,
            commands::trust::compute_file_sha256,
            commands::trust::scan_cache_lookup,
            commands::trust::scan_cache_store,
            commands::trust::set_trust_cache_config,
            // 拦截 (4) — 新增
            commands::interception::handle_interception,
            commands::interception::get_interception_queue,
            commands::interception::clear_interception_queue,
            commands::interception::get_interception_status,
            commands::interception::get_interception_signer_info,
            // 风险分析 (1) — 新增
            commands::risk::get_risk_status,
            // 进程快照 (2) — 新增
            commands::snapshot::take_startup_snapshot,
            commands::snapshot::get_snapshot_result,
            // ML训练 (3) — 新增
            commands::training::train_from_path,
            commands::training::get_training_status,
            commands::training::cancel_training,
            // 开发者设置 (2) — 新增
            commands::dev_settings::dev_settings_unlock,
            commands::dev_settings::dev_settings_save,
            // 系统信息 (2) — 新增
            commands::system::get_system_info,
            commands::system::get_running_processes,
            // 国际化 (3) — 新增
            commands::i18n::get_locale,
            commands::i18n::get_translations,
            commands::i18n::set_locale,
            // 错误追踪 (2) — 新增
            commands::error_trace::report_error,
            commands::error_trace::get_error_logs,
            // 签名库 (3) — 新增
            commands::signature_store::list_signature_versions,
            commands::signature_store::get_current_signature_version,
            commands::signature_store::rollback_signature_version,
            // 日志 (3) — 新增
            commands::logs::get_recent_logs,
            commands::logs::clear_logs,
            commands::logs::get_log_status,
            // 文件系统 (2) — 新增
            commands::fs::walk_directory,
            commands::fs::cancel_walk,
            // 文件钩子 (3) — 新增
            commands::hook::start_hook_service,
            commands::hook::stop_hook_service,
            commands::hook::get_hook_status,
            // 扫描规则 (2) — 新增
            commands::scan_rules::load_scan_rules,
            commands::scan_rules::load_mitre_rules,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

async fn start_etw_monitoring(app_handle: tauri::AppHandle) -> Result<(), String> {
    use crate::services::etw_service::EtwService;

    let app_handle_clone = app_handle.clone();
    let etw_state = app_handle.try_state::<Arc<Mutex<EtwService>>>()
        .ok_or("EtwService not managed")?;

    let etw_service = etw_state.lock().map_err(|e| e.to_string())?;
    etw_service.start(app_handle_clone)?;

    Ok(())
}
