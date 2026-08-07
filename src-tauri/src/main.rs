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
use crate::services::ipc_bridge_service::IpcBridgeService;
use crate::services::privilege_service::PrivilegeService;
use crate::services::process_monitor_service::ProcessMonitorService;
use crate::services::process_scanner_service::ProcessScannerService;
use crate::services::quarantine_service::QuarantineService;
use crate::services::remote_session_service::RemoteSessionService;
use crate::services::risk_service::RiskService;
use crate::services::scan_result_cache_service::ScanResultCacheService;
use crate::services::snapshot_service::{SnapshotContext, SnapshotScanOptions, SnapshotService};
use crate::services::tray_service::TrayService;
use crate::services::trust_service::TrustService;
use crate::services::windows_service;
use sqlx::SqlitePool;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{Emitter, Manager, RunEvent};

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
/// 函数名称：start_network_firewall
/// 函数作用：按配置启动网络防火墙；未启用或驱动缺失时静默跳过。
/// Function name: start_network_firewall
/// Purpose: Starts the network firewall per config; skips silently when it is
///          disabled or the driver is absent.
/// 调用方：background_init 的独立模式初始化路径。
/// Called by: the standalone-mode path of background_init.
/// 被调用方：FirewallService::start。
/// Calls: FirewallService::start.
/// 参数说明：app_handle 用于读取 Tauri managed state；config 提供 networkFirewall 段。
/// Parameters: app_handle reads Tauri managed state; config supplies the networkFirewall section.
/// 错误处理：驱动未安装是预期情况而非故障 —— 整套防护的其余部分必须照常运行，
///          因此这里只记录日志，绝不阻断启动。
/// Error handling: an uninstalled driver is expected, not a fault. The rest of the
///          protection suite must keep running, so failures are logged only and
///          never abort startup.
/// 中文关键词：防火墙启动，可选模块，降级运行，驱动缺失
/// English keywords: firewall startup, optional module, graceful degradation, missing driver
fn start_network_firewall(app_handle: &tauri::AppHandle, config: &AppConfig) {
    if !config.network_firewall.enabled {
        eprintln!("[main] Network firewall disabled by config");
        return;
    }

    let Some(firewall) =
        app_handle.try_state::<Arc<crate::services::firewall_service::FirewallService>>()
    else {
        eprintln!("[main] FirewallService not managed, skipping firewall startup");
        return;
    };

    let ctx = crate::services::service_context::build_etw_service_context(app_handle);
    match firewall.start(ctx, &config.network_firewall) {
        Ok(()) => eprintln!(
            "[main] Network firewall started (mode={})",
            config.network_firewall.mode
        ),
        Err(e) => eprintln!(
            "[main] Network firewall unavailable (non-fatal): {}. \
             Install and start the AnXinNetFilter driver to enable traffic control.",
            e
        ),
    }
}

/// 启动元核防护（仅当配置显式启用时）。
///  Starts hypervisor protection (only when the config explicitly enables it).
///
/// 元核防护会改变系统虚拟化姿态，必须由 app.json 的 hypervisorProtection.enabled
/// 显式打开后才拉起。驱动缺失、服务启动失败、设备连接失败都不是致命错误，
/// 只打印日志，不影响其他模块启动。
///  Hypervisor protection alters the system's virtualization posture, so it is
///  only brought up once hypervisorProtection.enabled is set in app.json. A
///  missing driver, a service start failure or a device connection failure are
///  all non-fatal: they are logged and do not block other modules.
fn start_hypervisor_if_enabled(app_handle: &tauri::AppHandle, config: &AppConfig) {
    if !config.hypervisor_protection.enabled {
        eprintln!("[main] Hypervisor protection disabled by config");
        return;
    }

    let Some(hypervisor) =
        app_handle.try_state::<Arc<crate::services::hypervisor_service::HypervisorService>>()
    else {
        eprintln!("[main] HypervisorService not managed, skipping hypervisor startup");
        return;
    };

    match hypervisor.start() {
        Ok(status) => eprintln!(
            "[main] Hypervisor protection started (mode={}, vendor={}, cpus={})",
            status.modeName, status.cpuVendor, status.cpuCount
        ),
        Err(e) => eprintln!(
            "[main] Hypervisor protection unavailable (non-fatal): {}. \
             Install AnXinHypervisor driver to enable hypervisor protection.",
            e
        ),
    }
}

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

/// 处理安装/卸载程序调用的驱动相关子命令。
///  Handles the driver subcommands invoked by the installer and uninstaller.
///
/// 返回 Some(exit_code) 表示本次进程是来执行子命令的，主流程不应继续启动 UI。
///  Some(exit_code) means this process was launched to run a subcommand and must not go on to
///  start the UI.
///
/// 设计原则：**安装期的驱动动作绝不能让安装失败**。
/// 内核驱动是纵深防御的一层，加载不了（签名、策略、旧系统）时用户态防护仍然完整可用，
/// 因此除了显式的卸载动作，其余子命令一律返回 0，只把原因打到 stderr 供安装日志记录。
///  Design rule: driver work during installation must never fail the install. The kernel driver is
///  one layer of defence in depth; if it cannot load (signing, policy, older systems) the user-mode
///  protection is still fully functional. Every subcommand except uninstall therefore returns 0 and
///  merely reports the reason on stderr for the installer log.
///
/// 中文关键词：命令行，驱动安装，安装程序，卸载，退出码
/// English keywords: CLI, driver install, installer, uninstall, exit code
fn handle_driver_cli() -> Option<i32> {
    use crate::services::driver_install_service::{self, DriverKind};

    let args: Vec<String> = std::env::args().collect();
    let value_after = |flag: &str| -> Option<String> {
        args.iter()
            .position(|arg| arg == flag)
            .and_then(|index| args.get(index + 1))
            .cloned()
    };

    if let Some(kind_arg) = value_after("--install-driver") {
        let Some(kind) = DriverKind::parse(&kind_arg) else {
            eprintln!("[DriverCLI] Unknown driver kind: {}", kind_arg);
            return Some(0);
        };
        let staging = value_after("--from").map(std::path::PathBuf::from);
        match driver_install_service::install_driver(kind, staging.as_deref()) {
            Ok(()) => eprintln!("[DriverCLI] Driver {:?} installed and started", kind),
            Err(err) => eprintln!(
                "[DriverCLI] Driver {:?} unavailable: {} (installation continues; \
                 user-mode protection is unaffected)",
                kind, err
            ),
        }
        return Some(0);
    }

    if let Some(pid_arg) = value_after("--protect-pid") {
        match pid_arg.parse::<u32>() {
            Ok(pid) => match driver_install_service::protect_pid(pid) {
                Ok(()) => eprintln!("[DriverCLI] PID {} is now protected", pid),
                Err(err) => eprintln!("[DriverCLI] Could not protect PID {}: {}", pid, err),
            },
            Err(_) => eprintln!("[DriverCLI] Invalid PID: {}", pid_arg),
        }
        return Some(0);
    }

    if let Some(dir_arg) = value_after("--protect-dir") {
        let dir = std::path::PathBuf::from(&dir_arg);
        match driver_install_service::protect_directory(&dir) {
            Ok(()) => eprintln!("[DriverCLI] Directory {} is now protected", dir.display()),
            Err(err) => eprintln!(
                "[DriverCLI] Could not protect directory {}: {}",
                dir.display(),
                err
            ),
        }
        // 驱动自身服务键的注册表保护由 AnXinFileProtect.sys 在加载时硬编码保护
        // （SVC_KEY_*_STR），不再需要安装期用死的 REG_KEY IOCTL 逐键登记。
        //  The driver service keys are protected at load time by AnXinFileProtect.sys's
        //  hardcoded CmCallback list (SVC_KEY_*_STR); no per-key registration needed here.
        return Some(0);
    }

    if args.iter().any(|arg| arg == "--query-file-protect") {
        eprintln!("[DriverCLI] Querying file protection driver...");
        let paths = crate::utils::driver_client::query_file_protection_paths();
        if paths.is_empty() {
            eprintln!("[DriverCLI] No protected paths found (driver may not be running or path registration failed)");
        } else {
            eprintln!(
                "[DriverCLI] Found {} protected path(s):",
                paths.len()
            );
            for (i, p) in paths.iter().enumerate() {
                eprintln!("  [{}] {}", i, p);
            }
        }
        return Some(0);
    }

    if args.iter().any(|arg| arg == "--uninstall-drivers") {
        // 用户主动卸载：把每一步的结果都打出来，方便卸载日志追查残留
        //  User-initiated uninstall: report every step so leftovers are traceable in the log
        for line in driver_install_service::uninstall_drivers() {
            eprintln!("[DriverCLI] {}", line);
        }
        return Some(0);
    }

    None
}

fn main() {
    // 安装/卸载程序会以子命令方式调用本程序执行驱动动作，这些调用不启动 UI。
    // 必须放在最前面：此时不需要 Tauri 运行时，也不该初始化任何防护组件。
    //  The installer and uninstaller invoke this binary with driver subcommands that must not start
    //  the UI. Handled first: no Tauri runtime is needed and no protection component should start.
    if let Some(code) = handle_driver_cli() {
        std::process::exit(code);
    }

    // 检查是否以服务模式启动（--service 参数）
    //  Check if launched in service mode (--service argument)
    if windows_service::is_service_mode() {
        // 通过 service dispatcher 启动 — SCM 通过 dispatcher 调用 ServiceMain
        //  Start via service dispatcher - SCM calls ServiceMain via dispatcher
        if let Err(e) = windows_service::dispatch() {
            eprintln!("[Service] Fatal error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // UI 进程以普通用户权限运行，防护由服务进程（SYSTEM）提供
    //  UI process runs with normal user privileges; protection is provided by service process (SYSTEM)
    // 如果服务进程未运行，UI 进程会尝试独立运行（功能受限模式）
    //  If service process is not running, UI process will try standalone mode (limited functionality)
    let is_elevated = PrivilegeService::is_elevated();
    if is_elevated {
        eprintln!("[Main] UI process running with administrator privileges (standalone mode)");
    } else {
        eprintln!("[Main] UI process running with normal user privileges - will connect to service process");
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // 单实例互斥：第二个实例启动时，唤醒已有主窗口而非启动新实例。
            // Single-instance mutex: when a second instance launches, activate the existing main window instead.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            // 注册应用生命周期状态。退出时先设置这个状态，隐藏的拦截窗口就不会再阻止关闭。
            app.manage(AppLifecycleService::new());

            // 初始化托盘（轻量级，可保留在主线程）
            TrayService::create_tray(app.handle())
                .map_err(|e| {
                    eprintln!("Failed to create tray: {}", e);
                })
                .ok();

            // 初始化配置（轻量级 JSON 读取）
            let config = AppConfig::load().unwrap_or_default();
            app.manage(Arc::new(Mutex::new(config.clone())));

            // 初始化 ETW 服务（轻量级构造，仅创建结构体，不启动监控）
            let etw_service = EtwService::new();
            app.manage(etw_service);

            // 轻量级服务注册（构造函数不阻塞，不加载 DLL）
            //  Lightweight service registration (constructors don't block, no DLL loading)
            // 引擎、ETW 监控、文件钩子、文件监控等重量级组件在 background_init 中根据 IPC 连接状态决定是否构造
            //  Heavyweight components (engine, ETW monitor, file hook, file monitor) are constructed
            //  in background_init based on IPC connection status
            let scan_result_cache = Arc::new(ScanResultCacheService::new());
            app.manage(scan_result_cache.clone());

            let trust_service = Arc::new(TrustService::new());
            app.manage(trust_service);

            let interception_service = Arc::new(InterceptionService::new());
            app.manage(interception_service.clone());

            let risk_service = RiskService::new();
            risk_service.set_interception_service(interception_service.clone());
            app.manage(risk_service);

            let process_monitor_service = ProcessMonitorService::new();
            app.manage(process_monitor_service);

            let snapshot_service = SnapshotService::new();
            snapshot_service.set_interception_service(interception_service.clone());
            app.manage(snapshot_service);

            let process_scanner = ProcessScannerService::new();
            app.manage(process_scanner);

            let file_monitor = FileMonitorService::new();
            app.manage(file_monitor);

            // 启动远程会话检测服务（轻量级，定期检测 RDP 和远程控制软件）
            //  Start remote session detection service (lightweight, periodic RDP and remote control software detection)
            let remote_session_service = Arc::new(RemoteSessionService::new());
            remote_session_service.start(app.handle().clone());
            app.manage(remote_session_service);

            // IPC 桥接服务 — 用于连接服务进程（前后端分离模式）
            //  IPC bridge service - for connecting to service process (frontend-backend separation mode)
            // 实际启动在 background_init 中进行，此处只注册到 Tauri state 供 commands 使用
            //  Actual start happens in background_init; here only registered to Tauri state for commands
            let ipc_bridge = Arc::new(IpcBridgeService::new());
            app.manage(ipc_bridge);

            // 网络防火墙服务 — 只注册，不自动启动。
            //  Network firewall service - registered only, never auto-started.
            // 防火墙会切断用户网络，必须由 app.json 的 networkFirewall.enabled
            // 显式打开后才由 background_init 拉起；单纯升级到带这个模块的版本
            // 绝不能默默开始拦截流量。
            //  A firewall can cut the user off the network, so it is only brought
            //  up by background_init once networkFirewall.enabled is set in
            //  app.json. Merely upgrading to a build containing this module must
            //  never start blocking traffic on its own.
            let firewall_service =
                Arc::new(crate::services::firewall_service::FirewallService::new());
            app.manage(firewall_service);

            // 元核防护服务 — 只注册，不自动启动。
            //  Hypervisor service - registered only, never auto-started.
            // 元核防护会改变系统虚拟化姿态，必须由 app.json 的
            // hypervisorProtection.enabled 显式打开后才由 background_init 拉起；
            // 单纯升级到带这个模块的版本绝不能默默开始虚拟化。
            //  Hypervisor protection alters the system's virtualization posture,
            //  so it is only brought up by background_init once
            //  hypervisorProtection.enabled is set in app.json. Merely upgrading
            //  to a build containing this module must never start virtualizing
            //  on its own.
            let hypervisor_service =
                Arc::new(crate::services::hypervisor_service::HypervisorService::new());
            app.manage(hypervisor_service);

            // 将所有重量级初始化移到后台异步任务，让窗口立即创建显示加载页面
            // Move all heavyweight initialization to background async task so window shows immediately
            let app_handle = app.handle().clone();
            let config_for_init = config.clone();
            tauri::async_runtime::spawn(async move {
                background_init(app_handle, config_for_init).await;
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
            // 网络防火墙 (11) — 新增
            commands::firewall::get_firewall_status,
            commands::firewall::start_firewall,
            commands::firewall::stop_firewall,
            commands::firewall::set_firewall_enabled,
            commands::firewall::set_firewall_mode,
            commands::firewall::reload_firewall_rules,
            commands::firewall::flush_firewall_cache,
            commands::firewall::handle_network_decision,
            commands::firewall::get_network_pending,
            commands::firewall::get_network_events,
            commands::firewall::get_network_stats,
            commands::firewall::is_netfilter_installed,
            commands::firewall::install_netfilter_driver,
            // 元核防护 (4) — 新增
            commands::hypervisor::get_hypervisor_status,
            commands::hypervisor::start_hypervisor,
            commands::hypervisor::stop_hypervisor,
            commands::hypervisor::set_hypervisor_enabled,
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
            // 权限检查 (2) — 新增
            commands::privilege::get_privilege_status,
            commands::privilege::is_protection_available,
            // IPC 桥接 (2) — 前后端分离
            crate::services::ipc_bridge_service::commands::is_ipc_connected,
            crate::services::ipc_bridge_service::commands::get_protection_status,
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

    let etw_state = app_handle
        .try_state::<Arc<Mutex<EtwService>>>()
        .ok_or("EtwService not managed")?;

    let ctx = crate::services::service_context::build_etw_service_context(&app_handle);
    let etw_service = etw_state.lock().map_err(|e| e.to_string())?;
    etw_service.start(ctx)?;

    Ok(())
}

/// 函数名称：background_init
/// 函数作用：在后台异步执行所有重量级初始化（SQLite、拦截恢复、文件钩子、ETW、启动快照），
///           不阻塞 Tauri setup 闭包，让窗口立即创建显示加载页面。
/// Purpose: Runs all heavyweight initialization (SQLite, interception recovery, file hook, ETW,
///           startup snapshot) asynchronously in background without blocking Tauri setup,
///           allowing the window to be created immediately to show the loading page.
/// 调用方：main setup 闭包通过 tauri::async_runtime::spawn 调用。
/// Called by: main setup closure via tauri::async_runtime::spawn.
/// 中文关键词：后台初始化，异步初始化，SQLite，拦截恢复，文件钩子，ETW，启动快照
/// English keywords: background init, async init, SQLite, interception recovery, file hook, ETW, startup snapshot
async fn background_init(app_handle: tauri::AppHandle, config: AppConfig) {
    eprintln!("[main] Background initialization started");

    // 初始化 SQLite 数据库池（异步，不阻塞主线程）
    let db_root = match resolve_behavior_database_path(&config) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("[main] Failed to resolve database path: {}", e);
            return;
        }
    };
    eprintln!("[main] DB path: {}", db_root.display());

    use sqlx::sqlite::SqliteConnectOptions;
    let opts = SqliteConnectOptions::new()
        .filename(&db_root)
        .create_if_missing(true);
    let pool = match SqlitePool::connect_with(opts).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[main] Failed to connect to database: {}", e);
            return;
        }
    };

    // 运行迁移 - events 表
    if let Err(e) = sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            pid INTEGER,
            process_name TEXT,
            operation TEXT,
            path TEXT,
            timestamp TEXT,
            details TEXT
        )
    "#,
    )
    .execute(&pool)
    .await
    {
        eprintln!("[main] Failed to create events table: {}", e);
        return;
    }

    // 运行迁移 - quarantine_items 表
    let quarantine_service = QuarantineService::new();
    if let Err(e) = quarantine_service.initialize_database(&pool).await {
        eprintln!("[main] Failed to initialize quarantine database: {}", e);
        return;
    }

    // 管理行为分析服务和数据库池
    let behavior_service = BehaviorService::new(pool.clone());
    app_handle.manage(Arc::new(Mutex::new(behavior_service)));
    app_handle.manage(pool);
    eprintln!("[main] SQLite initialized");

    // 启动 IPC 桥接服务 — 尝试连接服务进程
    //  Start IPC bridge service - try to connect to service process
    // 如果连接成功，防护组件由服务进程运行，UI 进程不重复启动
    //  If connected, protection components run in service process; UI process doesn't start them
    let service_connected = {
        if let Some(ipc_bridge) = app_handle.try_state::<Arc<IpcBridgeService>>() {
            match ipc_bridge.start(&app_handle) {
                Ok(true) => {
                    eprintln!("[main] IPC bridge connected to service process - protection will be provided by service");
                    true
                }
                Ok(false) => {
                    eprintln!("[main] IPC bridge: service process not running - UI will run in standalone mode");
                    false
                }
                Err(e) => {
                    eprintln!(
                        "[main] IPC bridge start failed: {} - falling back to standalone mode",
                        e
                    );
                    false
                }
            }
        } else {
            eprintln!("[main] IpcBridgeService not registered, running in standalone mode");
            false
        }
    };

    // 拦截恢复
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

    // 准备拦截窗口
    if let Ok(window) = prepare_interception_window(&app_handle) {
        let _ = window.hide();
    }

    // 如果 IPC 已连接服务进程，跳过本地防护组件启动（由服务进程提供防护）
    //  If IPC connected to service process, skip local protection startup (provided by service process)
    if service_connected {
        eprintln!("[main] Skipping local protection startup (service process mode)");
        // 通知前端连接已建立
        //  Notify frontend that connection is established
        let _ = app_handle.emit(
            "ipc-connection-status",
            serde_json::json!({"connected": true}),
        );
        eprintln!("[main] Background initialization completed (service mode)");
        return;
    }

    // 独立模式：UI 进程需要自己加载引擎（IPC 未连接服务进程）
    //  Standalone mode: UI process needs to load engine itself (IPC not connected to service process)
    eprintln!("[main] Standalone mode - loading engine locally");
    let (engine_dll_path, engine_root_path) = match resolve_engine_dll_path(&app_handle) {
        Ok(paths) => paths,
        Err(e) => {
            eprintln!("[main] Failed to resolve engine DLL path: {}", e);
            return;
        }
    };
    let engine_service = match EngineService::new(
        engine_dll_path.to_string_lossy().to_string(),
        engine_root_path.to_string_lossy().to_string(),
    ) {
        Ok(svc) => Arc::new(svc),
        Err(e) => {
            eprintln!("[main] Failed to initialize native engine: {}", e);
            return;
        }
    };
    engine_service.spawn_background_load();
    app_handle.manage(engine_service);

    // 启动文件钩子命名管道服务端
    let hook_service = HookService::new();
    let hook_ctx = crate::services::service_context::build_etw_service_context(&app_handle);
    if let Err(e) = hook_service.start("anxin_security_filehook", hook_ctx) {
        // 管道起不来意味着 APIHook 上报链路整条失效，必须留下可追查的记录，
        // 而不是只打一行 stderr —— 生产环境没人看得到控制台。
        //  A dead pipe means the whole APIHook reporting path is down; it must leave a traceable
        //  record rather than a single stderr line nobody sees in production.
        append_interception_diagnostic(
            "hook_pipe_service_failed",
            serde_json::json!({
                "pipeName": r"\\.\pipe\anxin_security_filehook",
                "pipeError": e.to_string(),
            }),
        );
        eprintln!(
            "[main] Failed to start file hook pipe service: pipeError={}",
            e
        );
    } else {
        append_interception_diagnostic(
            "hook_pipe_service_started",
            serde_json::json!({
                "pipeName": r"\\.\pipe\anxin_security_filehook",
                "processMonitoringEnabled": config.process_monitoring.enabled,
                "fileMonitoringEnabled": config.file_monitoring.enabled,
            }),
        );
        eprintln!("[main] File hook pipe service started: \\\\.\\pipe\\anxin_security_filehook");
        app_handle.manage(Arc::new(hook_service));
    }

    // 启动进程扫描器
    start_runtime_process_scanner_before_snapshot(&app_handle, config.process_monitoring.enabled);

    // 启动网络防火墙（仅当配置显式启用时）
    //  Start the network firewall, only when the config explicitly enables it
    start_network_firewall(&app_handle, &config);

    // 启动元核防护（仅当配置显式启用时）
    //  Start hypervisor protection, only when the config explicitly enables it
    start_hypervisor_if_enabled(&app_handle, &config);

    // 启动文件监控服务
    if config.file_monitoring.enabled {
        if let Some(etw_state) = app_handle.try_state::<Arc<std::sync::Mutex<EtwService>>>() {
            if let Ok(etw) = etw_state.lock() {
                if let (Some(engine), Some(cache), Some(interception)) = (
                    app_handle.try_state::<Arc<EngineService>>(),
                    app_handle.try_state::<Arc<ScanResultCacheService>>(),
                    app_handle.try_state::<Arc<InterceptionService>>(),
                ) {
                    let etw_rx = etw.subscribe();
                    if let Some(file_monitor) = app_handle.try_state::<FileMonitorService>() {
                        let file_monitor_ctx =
                            crate::services::service_context::build_etw_service_context(
                                &app_handle,
                            );
                        file_monitor.start(
                            engine.inner().clone(),
                            cache.inner().clone(),
                            interception.inner().clone(),
                            file_monitor_ctx,
                            etw_rx,
                        );
                        eprintln!("[main] File monitor started");
                    }
                }
            }
        }
    } else {
        eprintln!("[main] File monitor disabled by config");
    }

    // 启动 ETW 监控
    if config.behavior_monitoring.enabled {
        let app_handle_etw = app_handle.clone();
        if let Err(e) = start_etw_monitoring(app_handle_etw).await {
            eprintln!("[main] Failed to start ETW monitoring: {}", e);
        }
    } else {
        eprintln!("[main] ETW monitoring disabled by config");
    }

    // 启动启动快照扫描
    let snapshot_scan_options = SnapshotScanOptions {
        slow_warn_ms: config.scanner.startup_snapshot_slow_warn_ms,
        target_scan_timeout_ms: config.scanner.timeout_ms,
        module_enumeration_timeout_ms: config.scanner.startup_module_enumeration_timeout_ms,
        signature_verify_timeout_ms: config.scanner.startup_signature_verify_timeout_ms,
        signature_verify_concurrency: config.scanner.startup_signature_verify_concurrency,
        revocation_check_timeout_ms: config.scanner.startup_revocation_check_timeout_ms,
        revocation_check_concurrency: config.scanner.startup_revocation_check_concurrency,
    };
    let process_monitoring_enabled_after_snapshot = config.process_monitoring.enabled;

    // 等待引擎和前端就绪。
    // 这段等待直接计入用户可见的启动可信基线时间，必须保持短：
    // 后续的启动快照本身还要跑十几秒，前端在此期间显示分阶段进度，
    // 不需要在开始前先空等一秒。
    //  This wait counts directly against the user-visible startup baseline time and must stay
    //  short: the startup snapshot itself still takes tens of seconds while the frontend shows
    //  staged progress, so there is no reason to idle for a full second beforehand.
    tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;

    if let (Some(trust), Some(snapshot), Some(engine), Some(cache)) = (
        app_handle.try_state::<Arc<TrustService>>(),
        app_handle.try_state::<SnapshotService>(),
        app_handle.try_state::<Arc<EngineService>>(),
        app_handle.try_state::<Arc<ScanResultCacheService>>(),
    ) {
        match snapshot
            .take_startup_snapshot(
                trust.inner().clone(),
                engine.inner().clone(),
                cache.inner().clone(),
                &SnapshotContext::Tauri(app_handle.clone()),
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

    start_apihook_process_watcher_after_snapshot(
        &app_handle,
        process_monitoring_enabled_after_snapshot,
    );

    eprintln!("[main] Background initialization completed");
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
fn resolve_engine_dll_path(app_handle: &tauri::AppHandle) -> Result<(PathBuf, PathBuf), String> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    // 策略 1: resource_dir（生产部署时有效）
    // Tauri resources 配置 "../Engine/**/*" 会在安装目录下产生 "_up_/Engine/Axon/" 布局
    // 同时也检查直接的 "Engine/Axon/" 布局（兼容未来配置调整）
    if let Ok(resource_dir) = app_handle.path().resource_dir() {
        candidates.push(resource_dir.join("_up_/Engine/Axon/axon_engine.dll"));
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
