// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod services;
mod ffi;
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
            app.manage(Arc::new(Mutex::new(config)));

            // 初始化 ETW 服务
            let etw_service = EtwService::new();
            app.manage(etw_service);

            // 初始化扫描引擎服务
            let engine_service = EngineService::new("127.0.0.1", 8765);
            app.manage(engine_service);

            // 初始化 SQLite 数据库池
            let db_path = config.behavior_analyzer.sqlite.directory.clone() 
                + "/" 
                + &config.behavior_analyzer.sqlite.file_name;

            // 确保目录存在
            if let Some(parent) = std::path::Path::new(&db_path).parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }

            let db_url = format!("sqlite:{}", db_path);
            let pool = SqlitePool::connect(&db_url).await
                .map_err(|e| format!("Failed to connect to database: {}", e))?;

            // 运行迁移 - events 表
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
            "#).execute(&pool).await.map_err(|e| e.to_string())?;

            // 运行迁移 - quarantine_items 表
            let quarantine_service = QuarantineService::new();
            quarantine_service.initialize_database(&pool).await
                .map_err(|e| format!("Failed to initialize quarantine database: {}", e))?;

            // 管理池状态
            app.manage(pool);

            // 启动 ETW 监控
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = start_etw_monitoring(app_handle).await {
                    eprintln!("Failed to start ETW monitoring: {}", e);
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::config::get_config,
            commands::config::set_behavior_monitoring_enabled,
            commands::config::set_theme_mode,
            commands::scanner::scanner_health,
            commands::scanner::scan_file,
            commands::scanner::scan_batch,
            commands::behavior::list_events,
            commands::behavior::pause_etw,
            commands::behavior::resume_etw,
            commands::behavior::clear_all_events,
            commands::quarantine::list_quarantine,
            commands::quarantine::isolate_file,
            commands::quarantine::restore_file,
            commands::quarantine::delete_quarantine,
            commands::exclusions::list_exclusions,
            commands::exclusions::add_exclusion,
            commands::exclusions::remove_exclusion,
            commands::exclusions::add_exclusions_batch,
            commands::allowlist::list_allowlist,
            commands::allowlist::add_to_allowlist,
            commands::allowlist::remove_from_allowlist,
            commands::allowlist::add_to_allowlist_batch,
            commands::tray::request_exit_confirmation,
            commands::tray::execute_exit,
            commands::tray::minimize_to_tray,
            commands::process::suspend_process,
            commands::process::resume_process,
            commands::process::terminate_process,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

async fn start_etw_monitoring(app_handle: tauri::AppHandle) -> Result<(), String> {
    use crate::services::etw_service::EtwService;

    let app_handle_clone = app_handle.clone();
    let etw_state = app_handle.try_state::<Arc<Mutex<EtwService>>>()
        .ok_or("EtwService not managed")?;
    
    let mut etw_service = etw_state.lock().map_err(|e| e.to_string())?;
    etw_service.start(app_handle_clone)?;

    Ok(())
}
