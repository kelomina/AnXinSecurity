// Prevents additional console window on Windows in release, DO NOT REMOVE!!
//  禁止在 Windows release 构建中弹出控制台窗口，请勿删除！！
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anxin_security::commands;

use anxin_security::models::config::AppConfig;
use anxin_security::services::app_lifecycle_service::AppLifecycleService;
use anxin_security::services::behavior_service::BehaviorService;
use anxin_security::services::etw_service::EtwService;
use anxin_security::services::file_monitor_service::FileMonitorService;
use anxin_security::services::interception_service::InterceptionService;
use anxin_security::services::ipc_bridge_service::IpcBridgeService;
use anxin_security::services::privilege_service::PrivilegeService;
use anxin_security::services::process_monitor_service::ProcessMonitorService;
use anxin_security::services::process_scanner_service::ProcessScannerService;
use anxin_security::services::quarantine_service::QuarantineService;
use anxin_security::services::remote_session_service::RemoteSessionService;
use anxin_security::services::risk_service::RiskService;
use anxin_security::services::scan_result_cache_service::ScanResultCacheService;
use anxin_security::services::snapshot_service::SnapshotService;
use anxin_security::services::trust_service::TrustService;
use sqlx::SqlitePool;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{Emitter, Manager, RunEvent};

/// 函数名称：acquire_main_singleton
/// 函数作用：Main 进程单实例守卫。tauri-plugin-single-instance 依赖查找既有实例
///           隐藏窗口来退出第二实例，在本环境实测不可靠（出现双 Main 共存），改为
///           进程入口直接持有命名互斥体。
/// Function name: acquire_main_singleton
/// Purpose: Single-instance guard for the Main process. The single-instance plugin's
///           hidden-window lookup proved unreliable here (two Mains coexisted), so
///           hold a named mutex at the process entry instead.
fn acquire_main_singleton() -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
    use windows::Win32::System::Threading::CreateMutexW;

    // Global\ 跨会话互斥优先，失败回退 Local\（与 Tray 守卫同一策略）。
    //  Global\ first for cross-session exclusion; fall back to Local\.
    for prefix in ["Global\\", "Local\\"] {
        let name: Vec<u16> = format!("{prefix}AnXinMainSingletonMutex\0").encode_utf16().collect();
        let attrs: Option<*const windows::Win32::Security::SECURITY_ATTRIBUTES> = None;
        match unsafe { CreateMutexW(attrs, false, PCWSTR(name.as_ptr())) } {
            Ok(_) => {
                let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
                // 有意不关闭句柄：互斥体需随进程生命周期保持持有。
                //  Intentionally leak the handle: held for the process lifetime.
                return !already;
            }
            Err(e) => eprintln!("[Main] mutex create failed ({prefix}): {}", e),
        }
    }
    eprintln!("[Main] singleton mutex unavailable - allowing start");
    true
}

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

/// 行为库保留期边界：`now - retention_days` 的 RFC3339 字符串（清理 DELETE 用）。
///  Behavior-DB retention boundary: RFC3339 string of `now - retention_days`.
fn behavior_retention_boundary(retention_days: u64) -> String {
    let now = chrono::Utc::now();
    let before = now - chrono::Duration::days(retention_days as i64);
    before.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
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
    use anxin_security::services::driver_install_service::{self, DriverKind};

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
        let paths = anxin_security::utils::driver_client::query_file_protection_paths();
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

    if args.iter().any(|arg| arg == "--authorize-uninstall") {
        // 卸载/升级授权：打开 AnXinFileProtect minifilter 的授权窗口（VUL-098/101），
        // 供 NSIS 在 sc create/Delete /REBOOTOK 前调用。窗口约 15 分钟自动失效。
        //  Open the minifilter's uninstall/upgrade window (VUL-098/101), invoked by
        //  NSIS before sc create / Delete /REBOOTOK. Expires after ~15 minutes.
        match anxin_security::utils::driver_client::authorize_uninstall() {
            Ok(()) => eprintln!("[DriverCLI] Uninstall window authorized"),
            Err(err) => eprintln!("[DriverCLI] Could not authorize uninstall window: {err}"),
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

    if let Some(kv_arg) = value_after("--set-config") {
        // 对抗测试：以应用自身进程身份（通过 FileProtect IsCallerAuthorized）写入
        // 安装目录内的 app.json 配置字段（如 headlessAutoTerminate=true）。
        //  Antagonist test: write a config field into the in-dir app.json as the app
        //  process itself (passes FileProtect's IsCallerAuthorized check).
        //
        // 提权门禁：写入安装目录内的配置等同改动防护行为，非提权进程不得使用。
        //  Elevation gate: rewriting in-dir config alters protection behavior, so only
        //  an elevated process may use this subcommand.
        if !PrivilegeService::is_elevated() {
            eprintln!("[DriverCLI] --set-config requires elevation");
            return Some(1);
        }
        let Some((key, value)) = kv_arg.split_once('=') else {
            eprintln!("[DriverCLI] --set-config expects KEY=VALUE, got: {}", kv_arg);
            return Some(1);
        };
        match AppConfig::set_cli_value(key, value) {
            Ok(path) => eprintln!(
                "[DriverCLI] Config {}={} written to {}",
                key,
                value,
                path.display()
            ),
            Err(err) => eprintln!("[DriverCLI] Failed to set config {}: {}", kv_arg, err),
        }
        return Some(0);
    }

    if let Some(src_arg) = value_after("--write-etw-rules") {
        // 对抗测试：以应用自身进程身份（通过 FileProtect IsCallerAuthorized）写入 ETW 规则。
        // 目标路径通过 AppConfig::resolve_etw_rules_path() 与加载器使用相同候选顺序，
        // 确保写入与 app.json 同目录（优先 _up_/config），修复写入位置不匹配导致规则不加载的问题。
        //
        // 提权门禁：写入安装目录内的规则文件等同改动防护行为，非提权进程不得使用。
        if !PrivilegeService::is_elevated() {
            eprintln!("[DriverCLI] --write-etw-rules requires elevation");
            return Some(1);
        }
        let src = std::path::PathBuf::from(&src_arg);
        if !src.exists() {
            eprintln!("[DriverCLI] Source not found: {}", src.display());
            return Some(1);
        }
        match anxin_security::models::config::AppConfig::write_etw_rules(&src) {
            Ok(path) => {
                let n = std::fs::metadata(&src).map(|m| m.len()).unwrap_or(0);
                eprintln!("[DriverCLI] ETW rules written: {} -> {} ({} bytes)", src.display(), path.display(), n);
            }
            Err(e) => eprintln!("[DriverCLI] Failed to write ETW rules: {}", e),
        }
        return Some(0);
    }

    None
}

fn main() {
    // 安装/卸载程序会以子命令方式调用本程序执行驱动动作，这些调用不启动 UI。
    // 必须放在最前面（先于单实例守卫）：CLI 进程短命即退，不得占用 Main 的
    // 单实例互斥体，否则安装期之后 Tray 将无法拉起主界面。
    //  The installer and uninstaller invoke this binary with driver subcommands that must not start
    //  the UI. Handled first, BEFORE the singleton guard: CLI processes are short-lived
    //  and must not hold Main's singleton mutex, or the tray could never launch the UI
    //  again after an install.
    if let Some(code) = handle_driver_cli() {
        std::process::exit(code);
    }

    // VUL-108 临时诊断：--cpasu-probe 在本进程上下文执行与 launch_ui_process
    // 完全相同的跨会话创建序列，输出每一步结果以定位差异。
    //  VUL-108 temp diagnostics: --cpasu-probe runs the exact cross-session
    //  creation sequence inside this process context.
    if let Some(v) = std::env::args().skip_while(|a| a != "--set-diag").nth(1) {
        match u32::from_str_radix(&v, 16) {
            Ok(flags) => {
                use anxin_security::utils::driver_client::DriverClient;
                let c = DriverClient::new();
                match c.connect().and_then(|_| c.set_diag_flags(flags)) {
                    Ok(_) => println!("[diag] flags=0x{:X} set", flags),
                    Err(e) => println!("[diag] failed: {}", e),
                }
            }
            Err(e) => println!("bad hex: {}", e),
        }
        std::process::exit(0);
    }

    if std::env::args().any(|arg| arg == "--query-trace") {
        use anxin_security::utils::driver_client::DriverClient;
        let c = DriverClient::new();
        match c.connect().and_then(|_| c.query_trace()) {
            Ok(trace) => println!("{}", trace),
            Err(e) => println!("[query-trace] failed: {}", e),
        }
        std::process::exit(0);
    }

    if std::env::args().any(|arg| arg == "--cpasu-probe") {
        let r = anxin_security::services::windows_service::cpasu_diagnostic_probe();
        std::fs::write("C:\\Windows\\Temp\\svc-probe.txt", &r).ok();
        println!("{}", r);
        std::process::exit(0);
    }

    if !acquire_main_singleton() {
        eprintln!("[Main] another instance is running - exiting");
        return;
    }

    // UI 进程以普通用户权限运行；防护由独立服务进程（AnXinService.exe，SYSTEM）提供。
    // 服务未运行且本进程提权时，由 background_init 引导拉起前台服务
    // （见 bootstrap_protection_service_foreground）。
    //  The UI process runs with normal user privileges; protection is provided by the
    //  dedicated service process (AnXinService.exe, SYSTEM). When the service is not
    //  running and this process is elevated, background_init bootstraps the foreground
    //  service (see bootstrap_protection_service_foreground).
    let is_elevated = PrivilegeService::is_elevated();
    if is_elevated {
        eprintln!("[Main] UI process running with administrator privileges (standalone mode)");
    } else {
        eprintln!("[Main] UI process running with normal user privileges - will connect to service process");
    }

    tauri::Builder::default()
        // 单实例已由 acquire_main_singleton 的命名互斥体保证；插件式单实例
        // （隐藏窗口查找）在本环境实测不可靠，已移除。
        //  Single-instance is now guaranteed by the named mutex in
        //  acquire_main_singleton; the plugin-based approach (hidden-window lookup)
        //  proved unreliable in this environment and has been removed.
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            // 注册应用生命周期状态。退出时先设置这个状态，隐藏的拦截窗口就不会再阻止关闭。
            app.manage(AppLifecycleService::new());

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
                Arc::new(anxin_security::services::firewall_service::FirewallService::new());
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
                Arc::new(anxin_security::services::hypervisor_service::HypervisorService::new());
            app.manage(hypervisor_service);

            // 进程监控采集服务 — 只注册，不自动启动。
            //  Process monitor collector - registered only, never auto-started.
            // 由 background_init 按 app.json 的 procMonitor.enabled 决定是否拉起；
            // 驱动未安装/加载失败按功能降级处理，不影响其他模块。
            //  Brought up by background_init when procMonitor.enabled is set in
            //  app.json; a missing/failed driver degrades the feature without
            //  affecting the rest of the suite.
            let process_lifecycle_service = Arc::new(
                anxin_security::services::process_lifecycle_service::ProcessLifecycleService::new(),
            );
            app.manage(process_lifecycle_service);

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
            // 托盘 (4) — close_main_window 供标题栏关闭按钮退出 Main 进程
            commands::tray::request_exit_confirmation,
            commands::tray::execute_exit,
            commands::tray::minimize_to_tray,
            commands::tray::close_main_window,
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
            // 进程生命周期监控 (3) — 新增
            commands::process_lifecycle::get_proc_monitor_health,
            commands::process_lifecycle::get_process_tree,
            commands::process_lifecycle::list_lifecycle_events,
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
            anxin_security::services::ipc_bridge_service::commands::is_ipc_connected,
            anxin_security::services::ipc_bridge_service::commands::get_protection_status,
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

    // 运行迁移 - process_lifecycle 表（§4.7，与 windows_service.rs 建库路径一致）
    if let Err(e) = BehaviorService::initialize_lifecycle_table(&pool).await {
        eprintln!("[main] Failed to create process_lifecycle table: {}", e);
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

    // 定时清理行为库（保留期外事件删除，防 DB 无限占盘）。
    //  Spawn the periodic behavior-DB retention prune (deletes rows past the
    //  retention window so the DB cannot grow without bound).
    let behavior_prune_svc = {
        let state = app_handle.state::<Arc<Mutex<BehaviorService>>>();
        state.inner().clone()
    };
    let retention_days = config.behavior_analyzer.retention_days;
    let max_db_bytes = config.behavior_analyzer.max_db_bytes;
    tauri::async_runtime::spawn(async move {
        use tokio::time::{interval, Duration};
        // 启动后先清一次，之后每小时检查
        let mut ticker = interval(Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            let svc = behavior_prune_svc
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            // 容量上限优先（1GiB 硬约束）：超限先删最老数据并 VACUUM
            //  Size cap first (hard bound): when over, delete the oldest rows and VACUUM.
            match svc.db_size_bytes().await {
                Ok(size) if size > max_db_bytes => {
                    if let Err(err) = svc.prune_by_size_limit(max_db_bytes).await {
                        eprintln!("[main] behavior size-limit prune failed: {}", err);
                    }
                }
                Ok(_) => {}
                Err(err) => eprintln!("[main] behavior db size check failed: {}", err),
            }
            // 保留期清理（retentionDays 窗口外数据删除）
            let before = behavior_retention_boundary(retention_days);
            match svc.prune_older_than(&before).await {
                Ok((e, l)) => {
                    if e > 0 || l > 0 {
                        eprintln!("[main] behavior retention prune: {} events, {} lifecycle", e, l);
                    }
                }
                Err(err) => eprintln!("[main] behavior retention prune failed: {}", err),
            }
        }
    });

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

    // 拆分架构：Main 不再承担拦截队列所有权，也不再预建拦截窗口（归 Tray 进程）。
    // 旧 Main 本地的挂起进程台账恢复已随所有权一并移除——由服务进程的
    // InterceptionService 负责「无客户端可询问即回滚恢复」的安全路径。
    //  Split architecture: Main no longer owns the interception queue nor pre-creates
    //  the interception window (owned by the Tray process). The legacy local
    //  suspended-process ledger recovery is removed together with that ownership —
    //  the service process's InterceptionService handles the safe
    //  "no client to ask → roll back and resume" path.

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

    // 拆分架构：UI 进程不再内嵌任何防护组件。服务未运行时的引导策略：
    // - 提权运行的 Main → 自动拉起同目录 AnXinService.exe --foreground（子进程继承提权），
    //   bridge 的重连监控会在服务 IPC 就绪后自动接上。
    // - 非提权运行 → 保持降级（get_protection_status 呈现 standalone），不擅自触发 UAC。
    //  Split architecture: the UI process embeds no protection components anymore.
    //  Bootstrap policy when the service is not running:
    //  - Elevated Main → spawn the sibling AnXinService.exe --foreground automatically
    //    (the child inherits elevation); the bridge reconnect monitor picks it up.
    //  - Non-elevated → stay degraded (get_protection_status reports standalone); never
    //    trigger a UAC prompt on our own.
    if PrivilegeService::is_elevated() {
        bootstrap_protection_service_foreground();
    } else {
        eprintln!("[main] Service not running and process is not elevated - staying degraded");
    }

    eprintln!("[main] Background initialization completed");
}

/// 函数名称：bootstrap_protection_service_foreground
/// 函数作用：拉起同目录的后端服务程序（AnXinService.exe / anxin-service.exe）以前台模式
///           运行防护后端；找不到拆分后的服务程序时记录降级原因后返回。
/// Function name: bootstrap_protection_service_foreground
/// Purpose: Spawns the sibling backend service executable (AnXinService.exe /
///          anxin-service.exe) to run the protection backend in foreground mode; logs and
///          returns when the split service binary cannot be found.
fn bootstrap_protection_service_foreground() {
    let Ok(self_exe) = std::env::current_exe() else {
        eprintln!("[main] Cannot resolve current exe, skipping service bootstrap");
        return;
    };
    let Some(dir) = self_exe.parent() else {
        eprintln!("[main] Cannot resolve exe directory, skipping service bootstrap");
        return;
    };

    for name in ["AnXinService.exe", "anxin-service.exe"] {
        let candidate = dir.join(name);
        if !candidate.exists() {
            continue;
        }
        match std::process::Command::new(&candidate).arg("--foreground").spawn() {
            Ok(child) => eprintln!(
                "[main] Bootstrapped protection service {} (pid {})",
                candidate.display(),
                child.id()
            ),
            Err(e) => eprintln!(
                "[main] Failed to spawn protection service {}: {}",
                candidate.display(),
                e
            ),
        }
        return;
    }

    eprintln!("[main] Protection service binary not found next to Main; staying degraded");
}
