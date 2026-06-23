// Prevents additional console window on Windows in release, DO NOT REMOVE!!
//  禁止在 Windows release 构建中弹出控制台窗口，请勿删除！！
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod models;
mod services;
mod utils;

use crate::models::config::AppConfig;
use crate::services::app_lifecycle_service::AppLifecycleService;
use crate::services::behavior_service::BehaviorService;
use crate::services::engine_service::EngineService;
use crate::services::etw_service::EtwService;
use crate::services::file_monitor_service::FileMonitorService;
use crate::services::hook_service::HookService;
use crate::services::interception_diagnostics_service::append_interception_diagnostic;
use crate::services::interception_recovery_service::recover_suspended_processes_from_ledger;
use crate::services::interception_service::InterceptionService;
use crate::services::interception_window_service::prepare_interception_window;
use crate::services::process_monitor_service::ProcessMonitorService;
use crate::services::process_scanner_service::ProcessScannerService;
use crate::services::quarantine_service::QuarantineService;
use crate::services::risk_service::RiskService;
use crate::services::scan_result_cache_service::ScanResultCacheService;
use crate::services::snapshot_service::{SnapshotScanOptions, SnapshotService};
use crate::services::tray_service::TrayService;
use crate::services::trust_service::TrustService;
use sqlx::SqlitePool;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{Manager, RunEvent};

/// 函数名称：resolve_behavior_database_path
/// 函数作用：解析行为分析与隔离区共用 SQLite 数据库路径；相对路径写入 APPDATA，避免 tauri dev 监听仓库运行时文件后重载。
/// Function name: resolve_behavior_database_path
/// Purpose: Resolves the shared behavior/quarantine SQLite path; relative paths are stored under APPDATA to avoid tauri dev reloads from repository runtime writes.
/// 调用方：main setup 初始化 SQLite pool。
/// Called by: main setup while initializing the SQLite pool.
/// 被调用方：std::env::var，std::env::current_dir，std::fs::create_dir_all，migrate_legacy_behavior_database。
/// Calls: std::env::var, std::env::current_dir, std::fs::create_dir_all, migrate_legacy_behavior_database.
/// 参数说明：config 为应用配置对象，读取 behaviorAnalyzer.sqlite.directory 与 fileName。
/// Parameters: config is the application config, using behaviorAnalyzer.sqlite.directory and fileName.
/// 返回值说明：成功返回数据库文件路径；目录创建或路径解析失败返回 String。
/// Returns: database file path on success; directory creation or path resolution failures return String.
/// 内部关键变量：configured_dir 是配置目录；database_dir 是最终目录；database_path 是最终 SQLite 文件。
/// Internal variables: configured_dir is the configured directory; database_dir is the final directory; database_path is the final SQLite file.
/// 接入方式：仅在基础设施初始化阶段调用；业务命令不应自行拼接数据库路径。
/// Integration: Called only during infrastructure initialization; business commands should not compose database paths.
/// 错误处理：目录创建失败向上返回；APPDATA 缺失时回退到当前目录下的配置路径。
/// Error handling: directory creation failures propagate; missing APPDATA falls back to the configured path under the current directory.
/// 副作用：可能创建 APPDATA 下的数据库目录，并可能迁移旧数据库文件副本。
/// Side effects: may create the APPDATA database directory and copy a legacy database file.
/// 事务边界：无 Unit of Work；SQLite 连接池后续管理事务。
/// Transaction boundary: no Unit of Work; later SQLite pool usage owns transactions.
/// 并发与幂等：路径解析可重复；迁移仅在目标库不存在时复制一次。
/// Concurrency and idempotency: path resolution is repeatable; migration copies only when the target database does not exist.
/// 中文关键词：数据库路径，APPDATA，隔离区，行为数据库，开发重载，运行时数据，SQLite，路径迁移，tauri dev，配置解析
/// English keywords: database path, APPDATA, quarantine, behavior database, dev reload, runtime data, SQLite, path migration, tauri dev, config resolution
fn resolve_behavior_database_path(config: &AppConfig) -> Result<PathBuf, String> {
    let configured_dir = PathBuf::from(&config.behavior_analyzer.sqlite.directory);
    let database_dir = if configured_dir.is_absolute() {
        configured_dir.clone()
    } else {
        std::env::var("APPDATA")
            .map(|app_data| {
                PathBuf::from(app_data)
                    .join("AnXinSecurity")
                    .join(&configured_dir)
            })
            .unwrap_or_else(|_| {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(&configured_dir)
            })
    };

    std::fs::create_dir_all(&database_dir).map_err(|err| err.to_string())?;
    let database_path = database_dir.join(&config.behavior_analyzer.sqlite.file_name);

    if !database_path.exists() {
        migrate_legacy_behavior_database(
            &configured_dir,
            &config.behavior_analyzer.sqlite.file_name,
            &database_path,
        )?;
    }

    Ok(database_path)
}

/// 函数名称：migrate_legacy_behavior_database
/// 函数作用：当 APPDATA 目标数据库不存在时，从旧版仓库内相对路径复制一次 SQLite 数据库，保留隔离区记录。
/// Function name: migrate_legacy_behavior_database
/// Purpose: Copies the legacy repository-relative SQLite database once when the APPDATA target database is missing, preserving quarantine records.
/// 调用方：resolve_behavior_database_path。
/// Called by: resolve_behavior_database_path.
/// 被调用方：std::env::current_dir，PathBuf::join，std::fs::copy。
/// Calls: std::env::current_dir, PathBuf::join, std::fs::copy.
/// 参数说明：configured_dir 为旧配置目录；file_name 为数据库文件名；target_path 为 APPDATA 目标文件。
/// Parameters: configured_dir is the old configured directory; file_name is the database file; target_path is the APPDATA target file.
/// 返回值说明：成功或无旧文件返回 Ok；复制失败返回 String。
/// Returns: Ok when copied or no legacy file exists; copy failures return String.
/// 内部关键变量：candidate_roots 覆盖从项目根和 src-tauri 运行时的旧路径。
/// Internal variables: candidate_roots cover legacy paths when running from project root or src-tauri.
/// 接入方式：仅作为启动期兼容迁移，不用于常规写入。
/// Integration: startup compatibility migration only, not a regular write path.
/// 错误处理：读取当前目录失败时使用空候选；复制失败带路径上下文返回。
/// Error handling: missing current directory yields no candidates; copy failures include path context.
/// 副作用：可能向 APPDATA 复制 SQLite 数据库文件；不删除旧文件。
/// Side effects: may copy the SQLite database to APPDATA; does not delete the legacy file.
/// 事务边界：无 Unit of Work；仅在 SQLite pool 打开前执行文件复制。
/// Transaction boundary: no Unit of Work; file copy runs before opening the SQLite pool.
/// 并发与幂等：目标文件存在时不复制；重复启动不会覆盖 APPDATA 数据库。
/// Concurrency and idempotency: does not copy when target exists; repeated startup does not overwrite APPDATA data.
/// 中文关键词：旧数据库，兼容迁移，APPDATA，SQLite，隔离记录，行为记录，仓库路径，启动迁移，文件复制，幂等
/// English keywords: legacy database, compatibility migration, APPDATA, SQLite, quarantine records, behavior records, repository path, startup migration, file copy, idempotent
fn migrate_legacy_behavior_database(
    configured_dir: &PathBuf,
    file_name: &str,
    target_path: &PathBuf,
) -> Result<(), String> {
    if configured_dir.is_absolute() {
        return Ok(());
    }

    let Ok(current_dir) = std::env::current_dir() else {
        return Ok(());
    };

    let mut candidate_roots = vec![current_dir.clone()];
    if let Some(parent) = current_dir.parent() {
        candidate_roots.push(parent.to_path_buf());
    }

    for root in candidate_roots {
        let legacy_path = root.join(configured_dir).join(file_name);
        if legacy_path.exists() && legacy_path != *target_path {
            std::fs::copy(&legacy_path, target_path).map_err(|err| {
                format!(
                    "Failed to migrate legacy behavior database from {} to {}: {}",
                    legacy_path.display(),
                    target_path.display(),
                    err
                )
            })?;
            break;
        }
    }

    Ok(())
}

/// 函数名称：start_runtime_process_scanner_before_snapshot
/// 函数作用：在完整启动快照完成前启动新进程恶意扫描器，让新增进程尽早进入实时防护。
/// Function name: start_runtime_process_scanner_before_snapshot
/// Purpose: Starts the new-process malware scanner before the full startup snapshot completes so newly created processes are protected early.
/// 调用方：main setup 初始化完进程扫描服务后。
/// Called by: main setup after managing ProcessScannerService.
/// 被调用方：ProcessScannerService::start。
/// Calls: ProcessScannerService::start.
/// 参数说明：app_handle 用于读取 Tauri managed state；process_monitoring_enabled 来自启动时配置快照。
/// Parameters: app_handle reads Tauri managed state; process_monitoring_enabled comes from the startup config snapshot.
/// 错误处理：缺失 managed state 或启动失败只记录日志，不阻断应用启动。
/// Error handling: Missing managed state or startup failures are logged and do not abort app startup.
/// 中文关键词：启动顺序，启动快照，进程扫描，实时防护，防护就绪
/// English keywords: startup order, startup snapshot, process scanner, realtime protection, protection ready
fn start_runtime_process_scanner_before_snapshot(
    app_handle: &tauri::AppHandle,
    process_monitoring_enabled: bool,
) {
    if !process_monitoring_enabled {
        eprintln!("[main] Process scanner disabled by config");
        return;
    }

    match (
        app_handle.try_state::<ProcessScannerService>(),
        app_handle.try_state::<Arc<EngineService>>(),
        app_handle.try_state::<Arc<ScanResultCacheService>>(),
        app_handle.try_state::<Arc<InterceptionService>>(),
    ) {
        (Some(process_scanner), Some(engine), Some(cache), Some(interception)) => {
            process_scanner.start(
                engine.inner().clone(),
                cache.inner().clone(),
                interception.inner().clone(),
                app_handle.clone(),
                2000,
            );
            eprintln!("[main] Process scanner started before startup snapshot");
        }
        _ => eprintln!("[main] Failed to start Process scanner: required service not managed"),
    }
}

/// 函数名称：start_apihook_process_watcher_after_snapshot
/// 函数作用：启动快照完成后再启动 APIHook watcher，避免启动快照扫描到本次启动期间由自身注入的 Hook DLL。
/// Function name: start_apihook_process_watcher_after_snapshot
/// Purpose: Starts the APIHook watcher after the startup snapshot so the snapshot is not polluted by hook DLLs injected by this app during startup.
/// 调用方：main setup 的启动快照后台任务。
/// Called by: startup snapshot background task in main setup.
/// 被调用方：ProcessMonitorService::start_with_resource_dir。
/// Calls: ProcessMonitorService::start_with_resource_dir.
/// 参数说明：app_handle 用于读取 Tauri managed state；process_monitoring_enabled 来自启动时配置快照。
/// Parameters: app_handle reads Tauri managed state; process_monitoring_enabled comes from the startup config snapshot.
/// 错误处理：缺失 managed state 或启动失败只记录日志，不阻断应用启动。
/// Error handling: Missing managed state or startup failures are logged and do not abort app startup.
/// 中文关键词：启动顺序，启动快照，APIHook，自身注入，误报控制
/// English keywords: startup order, startup snapshot, APIHook, self injection, false-positive control
fn start_apihook_process_watcher_after_snapshot(
    app_handle: &tauri::AppHandle,
    process_monitoring_enabled: bool,
) {
    if !process_monitoring_enabled {
        eprintln!("[main] APIHook process watcher disabled by config");
        return;
    }

    match app_handle.try_state::<ProcessMonitorService>() {
        Some(process_monitor_service) => {
            let resource_dir = app_handle.path().resource_dir().ok();
            match process_monitor_service.start_with_resource_dir(
                "",
                "",
                "",
                "",
                2000,
                resource_dir.as_deref(),
            ) {
                Ok(_) => eprintln!("[main] APIHook process watcher started after startup snapshot"),
                Err(e) => eprintln!("[main] Failed to start APIHook process watcher: {}", e),
            }
        }
        None => eprintln!("[main] Failed to start APIHook process watcher: service not managed"),
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            // 注册应用生命周期状态。退出时先设置这个状态，隐藏的拦截窗口就不会再阻止关闭。
            app.manage(AppLifecycleService::new());

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

            // 初始化原生 Axon DLL 扫描引擎（直接加载 axon_engine.dll）
            // Initialize native Axon DLL scan engine (loads axon_engine.dll directly)
            // 先解析引擎路径，支持开发和生产多种运行场景
            // Resolve engine path first, supporting dev and production scenarios
            let (engine_dll_path, engine_root_path) = match resolve_engine_dll_path(app) {
                Ok(paths) => paths,
                Err(e) => {
                    return Err(format!("Failed to resolve engine DLL path: {}", e).into());
                }
            };
            // 初始化引擎服务（内部持有可启动/停止的原生引擎句柄）
            let engine_service = Arc::new(
                EngineService::new(
                    engine_dll_path.to_string_lossy().to_string(),
                    engine_root_path.to_string_lossy().to_string(),
                )
                .map_err(|e| format!("Failed to initialize native engine: {}", e))?,
            );
            app.manage(engine_service.clone());

            // 初始化扫描结果缓存服务：进程、模块和启动扫描共享同一份 DPAPI runtime 缓存。
            let scan_result_cache = Arc::new(ScanResultCacheService::new());
            app.manage(scan_result_cache.clone());

            // 初始化 SQLite 数据库池
            let db_root = resolve_behavior_database_path(&config)?;
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
            let trust_service = Arc::new(TrustService::new());
            app.manage(trust_service);

            // 初始化拦截队列管理器 — 核心安全组件
            let interception_service = Arc::new(InterceptionService::new());
            app.manage(interception_service.clone());
            match recover_suspended_processes_from_ledger() {
                Ok(summary) => {
                    if summary.loaded_records > 0 {
                        eprintln!(
                            "[main] Interception recovery summary: loaded={}, recovered={}, stale_or_exited={}, failed={}",
                            summary.loaded_records,
                            summary.recovered,
                            summary.stale_or_exited,
                            summary.failed
                        );
                    }
                }
                Err(err) => eprintln!("[main] Failed to recover stale interceptions: {}", err),
            }
            if let Ok(window) = prepare_interception_window(app.handle()) {
                let _ = window.hide();
            }

            // 初始化风险分析服务 — 关联拦截服务和信任服务
            let risk_service = RiskService::new();
            risk_service.set_interception_service(interception_service.clone());
            app.manage(risk_service);

            // 初始化进程监控服务（APIHook watcher）
            // Initialize process monitor service (APIHook watcher)
            let process_monitor_service = ProcessMonitorService::new();

            // 初始化文件钩子服务 — 命名管道服务端。
            // 这个接收端必须在应用启动期常驻：它本身只是轻量管道监听，不代表主动注入；
            // 进程/文件监控开关只控制 watcher/ETW 是否主动采集。若管道不常驻，受控注入器
            // 或已加载的 file_hook_detours.dll 上报时会得到 ERROR_FILE_NOT_FOUND(pipeError=2)，
            // 导致 APIHook 已经阻断了远程线程但 AnXin 收不到拦截窗口事件。
            // Initialize file hook named-pipe receiver unconditionally during setup. The receiver is
            // lightweight and does not inject by itself; monitoring toggles control active watchers.
            let hook_service = HookService::new();
            hook_service
                .start("anxin_security_filehook", app.handle().clone())
                .map_err(|e| format!("Failed to start file hook pipe service: {}", e))?;
            append_interception_diagnostic(
                "hook_pipe_service_started",
                serde_json::json!({
                    "pipeName": r"\\.\pipe\anxin_security_filehook",
                    "processMonitoringEnabled": config.process_monitoring.enabled,
                    "fileMonitoringEnabled": config.file_monitoring.enabled,
                }),
            );
            eprintln!("[main] File hook pipe service started: \\\\.\\pipe\\anxin_security_filehook");
            app.manage(Arc::new(hook_service));

            // APIHook watcher 会在启动快照完成后启动，避免自身注入的 Hook DLL 污染启动基线。
            // The APIHook watcher starts after the startup snapshot to avoid polluting the baseline with our own hook DLL.
            app.manage(process_monitor_service);

            // 初始化进程快照服务 — 关联拦截服务
            let snapshot_service = SnapshotService::new();
            snapshot_service.set_interception_service(interception_service.clone());
            app.manage(snapshot_service);

            // 初始化进程扫描服务（新进程恶意代码检测），并在完整快照前启动实时新进程防护。
            // Initialize process scanner and start realtime new-process protection before the full snapshot completes.
            let process_scanner = ProcessScannerService::new();
            app.manage(process_scanner);
            start_runtime_process_scanner_before_snapshot(
                app.handle(),
                config.process_monitoring.enabled,
            );

            // 初始化文件监控服务（ETW 文件事件检测）
            let file_monitor = FileMonitorService::new();
            if config.file_monitoring.enabled {
                if let Some(etw_state) = app.try_state::<Arc<std::sync::Mutex<EtwService>>>() {
                    if let Ok(etw) = etw_state.lock() {
                        let etw_rx = etw.subscribe();
                        file_monitor.start(
                            engine_service.clone(),
                            scan_result_cache.clone(),
                            interception_service.clone(),
                            app.handle().clone(),
                            etw_rx,
                        );
                        eprintln!("[main] File monitor started");
                    }
                }
            } else {
                eprintln!("[main] File monitor disabled by config");
            }
            app.manage(file_monitor);

            // 管理池状态
            app.manage(pool);

            // 启动 ETW 监控：配置关闭时只管理服务，不采集事件，避免“开关关了但仍在跑”。
            // Start ETW only when enabled so the persisted toggle controls runtime collection.
            if config.behavior_monitoring.enabled {
                let app_handle_etw = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = start_etw_monitoring(app_handle_etw).await {
                        eprintln!("Failed to start ETW monitoring: {}", e);
                    }
                });
            } else {
                eprintln!("[main] ETW monitoring disabled by config");
            }

            // 启动启动快照扫描（延迟，等待服务就绪）
            let app_handle_snapshot = app.handle().clone();
            let snapshot_scan_options = SnapshotScanOptions {
                slow_warn_ms: config.scanner.startup_snapshot_slow_warn_ms,
                target_scan_timeout_ms: config.scanner.timeout_ms,
                module_enumeration_timeout_ms: config
                    .scanner
                    .startup_module_enumeration_timeout_ms,
                signature_verify_timeout_ms: config.scanner.startup_signature_verify_timeout_ms,
                signature_verify_concurrency: config
                    .scanner
                    .startup_signature_verify_concurrency,
                revocation_check_timeout_ms: config.scanner.startup_revocation_check_timeout_ms,
                revocation_check_concurrency: config.scanner.startup_revocation_check_concurrency,
            };
            let process_monitoring_enabled_after_snapshot = config.process_monitoring.enabled;
            tauri::async_runtime::spawn(async move {
                // 等待1秒确保前端和后端服务都就绪
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                if let Some(trust) = app_handle_snapshot.try_state::<Arc<TrustService>>() {
                    if let Some(snapshot) = app_handle_snapshot.try_state::<SnapshotService>() {
                        let Some(engine) = app_handle_snapshot.try_state::<Arc<EngineService>>() else {
                            eprintln!("[StartupSnapshot] Failed: EngineService not managed");
                            return;
                        };
                        let Some(cache) = app_handle_snapshot.try_state::<Arc<ScanResultCacheService>>() else {
                            eprintln!("[StartupSnapshot] Failed: ScanResultCacheService not managed");
                            return;
                        };
                        match snapshot
                            .take_startup_snapshot(
                                trust.inner().clone(),
                                engine.inner().clone(),
                                cache.inner().clone(),
                                &app_handle_snapshot,
                                snapshot_scan_options,
                            )
                            .await
                        {
                            Ok(result) => {
                                eprintln!(
                                    "[StartupSnapshot] Baseline done: {} processes, {} signed, {} unsigned, {} paused, {} modules, {} pending deep module checks, {} malicious processes, {} malicious modules, {} image integrity alerts, {} unknown processes, {} unknown modules, {} module enumeration failures ({} access denied), {} cache hits ({}ms)",
                                    result.total_processes, result.signed_processes,
                                    result.unsigned_processes, result.paused_processes,
                                    result.scanned_modules, result.deep_scan_pending_modules,
                                    result.malicious_processes,
                                    result.malicious_modules, result.image_integrity_alerts,
                                    result.unknown_processes, result.unknown_modules,
                                    result.module_enumeration_failures,
                                    result.module_enumeration_access_denied,
                                    result.cache_hits,
                                    result.duration_ms
                                );
                            }
                            Err(e) => eprintln!("[StartupSnapshot] Failed: {}", e),
                        }
                    }
                }
                start_apihook_process_watcher_after_snapshot(
                    &app_handle_snapshot,
                    process_monitoring_enabled_after_snapshot,
                );
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // 配置 (6)
            commands::config::get_config,
            commands::config::set_behavior_monitoring_enabled,
            commands::config::set_process_monitoring_enabled,
            commands::config::set_file_monitoring_enabled,
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
            commands::behavior::get_etw_status,
            commands::behavior::get_etw_diagnostics_snapshot,
            commands::behavior::clear_etw_diagnostics,
            commands::behavior::export_etw_diagnostics,
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
            // 进程控制 (8)
            commands::process::suspend_process,
            commands::process::resume_process,
            commands::process::terminate_process,
            commands::process::start_process_watcher,
            commands::process::stop_process_watcher,
            commands::process::get_process_watcher_status,
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
            commands::interception::peek_current_interception,
            // 风险分析 (1) — 新增
            commands::risk::get_risk_status,
            // 进程快照 (2) — 新增
            commands::snapshot::take_startup_snapshot,
            commands::snapshot::get_snapshot_result,
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
            // 日志 (3) — 新增
            commands::logs::get_recent_logs,
            commands::logs::clear_logs,
            commands::logs::get_log_status,
            // 文件系统 (2) — 新增
            commands::fs::start_background_walk,
            commands::fs::cancel_walk,
            // 文件钩子 (3) — 新增
            commands::hook::start_hook_service,
            commands::hook::stop_hook_service,
            commands::hook::get_hook_status,
            // 扫描规则 (2) — 新增
            commands::scan_rules::load_scan_rules,
            commands::scan_rules::load_mitre_rules,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
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

async fn start_etw_monitoring(app_handle: tauri::AppHandle) -> Result<(), String> {
    use crate::services::etw_service::EtwService;

    let app_handle_clone = app_handle.clone();
    let etw_state = app_handle
        .try_state::<Arc<Mutex<EtwService>>>()
        .ok_or("EtwService not managed")?;

    let etw_service = etw_state.lock().map_err(|e| e.to_string())?;
    etw_service.start(app_handle_clone)?;

    Ok(())
}

/// 函数名称：resolve_engine_dll_path
/// 函数作用：按优先级尝试多个路径寻找 axon_engine.dll，返回 (dll_abs_path, engine_root_abs_path)。
/// Purpose: Tries multiple paths to find axon_engine.dll by priority,
///          returns (dll_abs_path, engine_root_abs_path).
///
/// 尝试顺序：
///   1. resource_dir / Engine/Axon/axon_engine.dll（生产部署）
///   2. CWD / Engine/Axon/axon_engine.dll（npm run tauri dev）
///   3. CWD/../Engine/Axon/axon_engine.dll（cargo run from src-tauri）
///
/// 中文关键词：引擎路径，路径解析，DLL查找，部署部署
/// English keywords: engine path, path resolution, DLL lookup, production deployment
fn resolve_engine_dll_path(app: &tauri::App) -> Result<(PathBuf, PathBuf), String> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    // 策略 1: resource_dir（生产部署时有效）
    if let Ok(resource_dir) = app.path().resource_dir() {
        candidates.push(resource_dir.join("Engine/Axon/axon_engine.dll"));
    }

    // 策略 2: CWD 相对路径（npm run tauri dev / npx tauri dev）
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("Engine/Axon/axon_engine.dll"));
    }

    // 策略 3: CWD 上级目录（cargo run / cargo check from src-tauri/）
    if let Ok(cwd) = std::env::current_dir() {
        if let Some(parent) = cwd.parent() {
            candidates.push(parent.join("Engine/Axon/axon_engine.dll"));
        }
    }

    // 去重后逐个检查存在性
    let mut tried_paths = Vec::new();
    for candidate in &candidates {
        let normalized = if candidate.is_absolute() {
            candidate.clone()
        } else {
            std::env::current_dir().unwrap_or_default().join(candidate)
        };
        tried_paths.push(normalized.to_string_lossy().to_string());

        if normalized.exists() {
            // 不使用 canonicalize（会添加 \\?\ 前缀导致 LoadLibraryExW 依赖解析失败）
            // Don't use canonicalize (adds \\?\ prefix which breaks dependency resolution)
            let abs_str = normalized.to_string_lossy().to_string();
            let clean_path = abs_str.strip_prefix(r"\\?\").unwrap_or(&abs_str);
            let dll_path = PathBuf::from(clean_path);
            let engine_root = dll_path
                .parent()
                .ok_or_else(|| format!("Cannot get parent of {:?}", clean_path))?
                .to_path_buf();
            eprintln!("[main] Engine DLL resolved: {:?}", dll_path);
            eprintln!("[main] Engine root: {:?}", engine_root);
            return Ok((dll_path, engine_root));
        }
    }

    Err(format!(
        "Cannot find Engine/Axon/axon_engine.dll. Tried:\n  {}",
        tried_paths.join("\n  ")
    ))
}
