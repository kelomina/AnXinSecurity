// Windows 系统服务入口 — 在服务进程中真正启动防护组件
//  Windows system service entry — actually starts protection components in service process
//
// 当主程序以 --service 参数启动时，作为 Windows NT 服务运行。
//  When the main program is launched with --service argument, it runs as a Windows NT service.
//
// 服务在开机时由 SCM 自动启动，以 LocalSystem 权限运行。
//  The service is auto-started by SCM at boot, runs as LocalSystem.
//
// 服务模式的职责：
//  Service mode responsibilities:
// - 向 SCM 注册并维持服务运行状态（保证开机自启）
// - 在 Tokio runtime 中从零构造 ServiceContext 并启动所有防护组件
//   （ETW、文件钩子、文件监控、拦截服务、扫描引擎）
// - 启动 IPC 服务器（命名管道），提供状态查询、事件推送、拦截决策 API
// - 订阅事件总线，将防护组件产生的事件转发给已连接的 UI 进程
// - 接收 SCM STOP 控制时优雅关闭所有组件
//
// 中文关键词：Windows 服务，NT 服务，SCM，防护组件启动，IPC 服务器，事件转发
// English keywords: Windows service, NT service, SCM, protection startup, IPC server, event forwarding
use std::ffi::OsString;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

use crate::services::ipc_server::IpcServer;
use crate::services::service_context::{build_service_context, ServiceContext};

/// 服务名称
///  Service name
pub const SERVICE_NAME: &str = "AnXinSecurityService";
#[allow(dead_code)]
pub const SERVICE_DISPLAY_NAME: &str = "AnXin Security Protection Service";
#[allow(dead_code)]
pub const SERVICE_DESCRIPTION: &str = "AnXin Security background protection service - provides ETW behavior monitoring, process monitoring, and file hooks at system startup.";

/// 文件钩子管道名称（与 Tauri 主进程保持一致）
///  File hook pipe name (kept consistent with Tauri main process)
const FILE_HOOK_PIPE_NAME: &str = "anxin_security_filehook";

/// 需要转发到 UI 进程的事件名列表
///  List of event names to forward to UI process
const FORWARDABLE_EVENTS: &[&str] = &[
    "etw-event",
    "file-hook-event",
    "process-intercepted",
    "log-event",
    "behavior-event",
    "risk-event",
    "interception-decision",
    "file-monitor-event",
];

/// 启动 Windows 服务入口
///  Entry point for starting the Windows service
///
/// 服务启动流程：
///  Service startup flow:
/// 1. 向 SCM 注册控制处理器
/// 2. 通知 SCM 进入 StartPending
/// 3. 解析引擎 DLL 路径和数据库路径
/// 4. 创建 Tokio runtime
/// 5. 在 runtime 中构造 ServiceContext（含所有防护组件）
/// 6. 启动 IPC 服务器（独立线程）
/// 7. 启动事件总线 → IPC 桥接任务
/// 8. 启动文件钩子、ETW、文件监控
/// 9. 通知 SCM 进入 Running
/// 10. 等待 SCM STOP 信号
/// 11. 优雅关闭：停止 IPC、停止防护组件、关闭 runtime
/// 12. 通知 SCM 进入 Stopped
pub fn run_service() -> Result<(), String> {
    // 服务停止信号
    //  Service stop signal
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_clone = stop_flag.clone();

    // 注册服务控制处理器
    //  Register service control handler
    let event_handler = move |control_event: ServiceControl| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                eprintln!("[Service] Received STOP control");
                stop_flag_clone.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .map_err(|e| format!("Failed to register service control handler: {}", e))?;

    // 通知 SCM 服务正在启动（hint=30s，给防护组件初始化留出时间）
    //  Notify SCM that the service is starting (hint=30s to allow protection components to initialize)
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::ServiceSpecific(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        })
        .map_err(|e| format!("Failed to set StartPending status: {}", e))?;

    eprintln!("[Service] AnXin Security service starting (full protection mode)");

    // 启动防护组件 — 失败时仍进入 Running 状态，由 IPC 暴露降级状态给 UI
    //  Start protection components - on failure still enter Running state; degraded status is exposed to UI via IPC
    let started_at = chrono::Utc::now().timestamp_millis() as u64;
    let runtime_guard = match start_protection_runtime(status_handle.clone(), started_at, stop_flag.clone()) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("[Service] Failed to start protection runtime: {}", e);
            // 即使启动失败也要通知 SCM 进入 Stopped，否则 SCM 会认为服务卡死
            //  Even on startup failure, notify SCM to enter Stopped, otherwise SCM considers the service hung
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::ServiceSpecific(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            });
            return Err(format!("Protection runtime startup failed: {}", e));
        }
    };

    // 通知 SCM 服务已运行
    //  Notify SCM that the service is running
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::ServiceSpecific(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(|e| format!("Failed to set Running status: {}", e))?;

    eprintln!("[Service] AnXin Security service is running (full protection active)");

    // 服务启动成功后，在用户会话中拉起 UI 进程（普通用户权限）
    //  After service starts successfully, launch UI process in user session (normal user privileges)
    // 服务以 SYSTEM 在 Session 0 运行，UI 进程需要在用户会话（Session 1+）中运行
    //  Service runs as SYSTEM in Session 0, UI process needs to run in user session (Session 1+)
    if let Err(e) = launch_ui_process() {
        eprintln!("[Service] Failed to launch UI process: {}", e);
        // UI 拉起失败不阻断服务运行，用户可手动启动 UI
        //  UI launch failure doesn't block service; user can manually start UI
    }

    // 服务主循环：等待停止信号
    //  Service main loop: wait for stop signal
    while !stop_flag.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(1));
    }

    // 通知 SCM 服务正在停止（hint=15s，给优雅关闭留出时间）
    //  Notify SCM that the service is stopping (hint=15s for graceful shutdown)
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::ServiceSpecific(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(15),
            process_id: None,
        })
        .map_err(|e| format!("Failed to set StopPending status: {}", e))?;

    eprintln!("[Service] Stopping protection runtime...");
    // 丢弃 runtime_guard 会触发 Drop：先停止 IPC，再关闭 Tokio runtime
    //  Dropping runtime_guard triggers Drop: stop IPC first, then shut down Tokio runtime
    drop(runtime_guard);

    // 通知 SCM 服务已停止
    //  Notify SCM that the service has stopped
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::ServiceSpecific(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .map_err(|e| format!("Failed to set Stopped status: {}", e))?;

    eprintln!("[Service] AnXin Security service stopped");
    Ok(())
}

// ============================================================================
// ProtectionRuntime — 封装防护组件运行时（Tokio runtime + IPC + 防护任务）
//  ProtectionRuntime - encapsulates protection runtime (Tokio runtime + IPC + protection tasks)
// ============================================================================

/// 防护运行时 — 持有 Tokio runtime 和 IPC 服务器，Drop 时按顺序关闭
///  Protection runtime - holds Tokio runtime and IPC server, shuts down in order on Drop
struct ProtectionRuntime {
    /// IPC 服务器句柄（Drop 时调用 stop）
    ///  IPC server handle (stop called on Drop)
    ipc_server: Arc<IpcServer>,
    /// Tokio runtime — 必须最后关闭，确保所有 spawn 的任务能正常结束
    ///  Tokio runtime - must be shut down last to ensure all spawned tasks complete
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for ProtectionRuntime {
    fn drop(&mut self) {
        eprintln!("[Service] Stopping IPC server...");
        self.ipc_server.stop();

        // 给 IPC 客户端线程一点时间完成正在处理的请求
        //  Give IPC client threads a moment to finish in-flight requests
        std::thread::sleep(Duration::from_millis(500));

        if let Some(runtime) = self.runtime.take() {
            eprintln!("[Service] Shutting down Tokio runtime...");
            // 使用 shutdown_background 让后台任务收到关闭信号但不阻塞当前线程
            //  Use shutdown_background to signal background tasks without blocking current thread
            runtime.shutdown_background();
        }
        eprintln!("[Service] Protection runtime stopped");
    }
}

/// 启动防护运行时 — 创建 Tokio runtime、构造 ServiceContext、启动所有防护组件和 IPC 服务器
///  Start protection runtime - create Tokio runtime, build ServiceContext, start all protection components and IPC server
fn start_protection_runtime(
    _status_handle: windows_service::service_control_handler::ServiceStatusHandle,
    started_at: u64,
    stop_flag: Arc<AtomicBool>,
) -> Result<ProtectionRuntime, String> {
    // 注意：windows-service 0.7 中 ServiceStatusHandle 是 register 返回的句柄类型，
    // 这里仅作为占位参数保留，实际状态更新由 run_service 直接完成。
    //  Note: In windows-service 0.7, ServiceStatusHandle is the handle returned by register.
    //  Here it's only a placeholder parameter; actual status updates are done directly by run_service.
    // 解析引擎 DLL 路径（服务进程没有 Tauri App，使用 CWD 相对路径）
    //  Resolve engine DLL path (service process has no Tauri App, use CWD-relative paths)
    let (engine_dll_path, engine_root_path) = resolve_engine_dll_path_for_service()
        .map_err(|e| format!("Failed to resolve engine DLL path: {}", e))?;
    eprintln!(
        "[Service] Engine DLL path: {}",
        engine_dll_path.display()
    );

    // 创建 Tokio runtime（多线程，支持 spawn_blocking）
    //  Create Tokio runtime (multi-threaded, supports spawn_blocking)
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("anxin-service")
        .build()
        .map_err(|e| format!("Failed to create Tokio runtime: {}", e))?;

    // 在 runtime 上下文中构造 ServiceContext 和启动防护组件
    //  Build ServiceContext and start protection components inside runtime context
    let ctx = runtime.block_on(async {
        // 初始化 SQLite 数据库（与主进程使用相同的 APPDATA 路径策略）
        //  Initialize SQLite database (uses same APPDATA path strategy as main process)
        let pool = init_database_pool()
            .await
            .map_err(|e| format!("Failed to initialize database pool: {}", e))?;

        // 构造 ServiceContext（含所有防护组件实例）
        //  Build ServiceContext (contains all protection component instances)
        let ctx = build_service_context(
            engine_dll_path.to_string_lossy().to_string(),
            engine_root_path.to_string_lossy().to_string(),
            pool,
        )
        .map_err(|e| format!("Failed to build service context: {}", e))?;

        Ok::<ServiceContext, String>(ctx)
    })?;

    // 启动 IPC 服务器（独立线程，但需要 Tokio runtime handle 来调用 async 引擎方法）
    //  Start IPC server (separate thread, but needs Tokio runtime handle to call async engine methods)
    let runtime_handle = runtime.handle();
    let ipc_server = Arc::new(IpcServer::new(ctx.clone(), started_at, runtime_handle.clone()));
    let ipc_server_for_thread = ipc_server.clone();
    std::thread::Builder::new()
        .name("anxin-ipc-server".to_string())
        .spawn(move || {
            if let Err(e) = ipc_server_for_thread.start() {
                eprintln!("[Service] IPC server error: {}", e);
            }
        })
        .map_err(|e| format!("Failed to spawn IPC server thread: {}", e))?;

    // 在 Tokio runtime 中启动事件总线 → IPC 桥接任务
    //  Start event bus → IPC bridge task in Tokio runtime
    let ctx_for_bridge = ctx.clone();
    let ipc_server_for_bridge = ipc_server.clone();
    runtime.spawn(async move {
        event_bridge_loop(ctx_for_bridge, ipc_server_for_bridge).await;
    });

    // 在 Tokio runtime 中启动防护组件（ETW、文件钩子、文件监控）
    //  Start protection components in Tokio runtime (ETW, file hook, file monitor)
    let ctx_for_protection = ctx.clone();
    let stop_flag_for_protection = stop_flag.clone();
    runtime.spawn(async move {
        if let Err(e) = start_protection_components(ctx_for_protection).await {
            eprintln!("[Service] Protection components startup error: {}", e);
        }
        // 防护组件启动后，此任务保持存活以持有 ServiceContext 引用
        //  After protection components start, this task stays alive to hold ServiceContext reference
        // 直到 stop_flag 被设置或 runtime 被关闭
        //  Until stop_flag is set or runtime is shut down
        while !stop_flag_for_protection.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    Ok(ProtectionRuntime {
        ipc_server,
        runtime: Some(runtime),
    })
}

/// 启动所有防护组件（ETW、文件钩子、文件监控）
///  Start all protection components (ETW, file hook, file monitor)
///
/// 此函数在 Tokio runtime 上下文中调用，确保内部 spawn 的任务能正确绑定到 runtime。
///  This function is called in Tokio runtime context to ensure spawned tasks bind to the runtime correctly.
async fn start_protection_components(ctx: ServiceContext) -> Result<(), String> {
    use std::sync::Mutex;

    // 启动文件钩子命名管道服务端
    //  Start file hook named pipe server
    if let Some(hook_service) = ctx.get::<crate::services::hook_service::HookService>() {
        match hook_service.start(FILE_HOOK_PIPE_NAME, ctx.clone()) {
            Ok(_rx) => {
                eprintln!(
                    "[Service] File hook pipe service started: \\\\.\\pipe\\{}",
                    FILE_HOOK_PIPE_NAME
                );
            }
            Err(e) => {
                eprintln!("[Service] Failed to start file hook service: {}", e);
                // 文件钩子失败不阻断其他组件启动
                //  File hook failure does not block other components from starting
            }
        }
    } else {
        eprintln!("[Service] HookService not registered in context");
    }

    // 启动 ETW 监控
    //  Start ETW monitoring
    if let Some(etw_service) = ctx.get::<Mutex<crate::services::etw_service::EtwService>>() {
        let etw = etw_service.lock().map_err(|e| e.to_string())?;
        match etw.start(ctx.clone()) {
            Ok(()) => {
                eprintln!("[Service] ETW monitoring started");
            }
            Err(e) => {
                eprintln!("[Service] Failed to start ETW monitoring: {}", e);
                // ETW 失败不阻断文件监控启动
                //  ETW failure does not block file monitor from starting
            }
        }
    } else {
        eprintln!("[Service] EtwService not registered in context");
    }

    // 启动文件监控服务（依赖 ETW 广播接收器、引擎、缓存、拦截服务）
    //  Start file monitor service (depends on ETW broadcast receiver, engine, cache, interception)
    if let (Some(etw_service), Some(engine), Some(cache), Some(interception), Some(file_monitor)) = (
        ctx.get::<Mutex<crate::services::etw_service::EtwService>>(),
        ctx.get::<crate::services::engine_service::EngineService>(),
        ctx.get::<crate::services::scan_result_cache_service::ScanResultCacheService>(),
        ctx.get::<crate::services::interception_service::InterceptionService>(),
        ctx.get::<crate::services::file_monitor_service::FileMonitorService>(),
    ) {
        let etw = etw_service.lock().map_err(|e| e.to_string())?;
        let etw_rx = etw.subscribe();
        file_monitor.start(engine, cache, interception, ctx.clone(), etw_rx);
        eprintln!("[Service] File monitor started");
    } else {
        eprintln!("[Service] Missing dependencies for file monitor startup");
    }

    Ok(())
}

/// 事件总线 → IPC 桥接循环
///  Event bus → IPC bridge loop
///
/// 订阅事件总线上的关键事件，将它们转发给所有已连接的 UI 进程。
///  Subscribes to key events on the event bus and forwards them to all connected UI processes.
async fn event_bridge_loop(ctx: ServiceContext, ipc_server: Arc<IpcServer>) {
    use tokio::sync::broadcast;

    // 为每个需要转发的事件创建一个订阅
    //  Create a subscription for each event to forward
    let event_bus = ctx.event_bus().clone();
    let mut receivers: Vec<(String, broadcast::Receiver<crate::services::event_bus::EventPayload>)> =
        Vec::new();
    for event_name in FORWARDABLE_EVENTS {
        let rx = event_bus.subscribe(event_name);
        receivers.push((event_name.to_string(), rx));
    }

    eprintln!(
        "[Service] Event bridge started, forwarding {} event types",
        receivers.len()
    );

    // 使用 tokio::select! 同时监听所有事件接收器
    //  Use tokio::select! to listen to all event receivers simultaneously
    // 由于接收器数量固定且不大，使用递归宏或简单的轮询方式
    //  Since the number of receivers is fixed and small, use a simple polling approach
    loop {
        // 轮询每个接收器，使用非阻塞 try_recv
        //  Poll each receiver using non-blocking try_recv
        for (event_name, rx) in &mut receivers {
            match rx.try_recv() {
                Ok(payload) => {
                    // 转发到所有已连接的 UI 进程
                    //  Forward to all connected UI processes
                    ipc_server.broadcast_event(&payload.event, payload.payload.clone());
                }
                Err(broadcast::error::TryRecvError::Empty) => {
                    // 暂无事件，继续
                    //  No events yet, continue
                }
                Err(broadcast::error::TryRecvError::Closed) => {
                    eprintln!("[Service] Event channel '{}' closed", event_name);
                    return;
                }
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    eprintln!(
                        "[Service] Event channel '{}' lagged by {} events",
                        event_name, n
                    );
                }
            }
        }
        // 短暂休眠避免空轮询消耗 CPU
        //  Short sleep to avoid busy-waiting CPU consumption
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ============================================================================
// 服务进程的路径解析和数据库初始化
//  Path resolution and database initialization for service process
// ============================================================================

/// 解析引擎 DLL 路径（服务进程版本，不依赖 Tauri App）
///  Resolve engine DLL path (service process version, no Tauri App dependency)
///
/// 尝试顺序：
///  Try order:
/// 1. exe 所在目录 / Engine/Axon/axon_engine.dll
/// 2. CWD / Engine/Axon/axon_engine.dll
/// 3. CWD/../Engine/Axon/axon_engine.dll
fn resolve_engine_dll_path_for_service() -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
    use std::path::PathBuf;

    let mut candidates: Vec<PathBuf> = Vec::new();

    // 策略 1: 可执行文件所在目录（生产部署时有效）
    //  Strategy 1: Executable directory (effective in production deployment)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join("Engine/Axon/axon_engine.dll"));
            candidates.push(exe_dir.join("_up_/Engine/Axon/axon_engine.dll"));
        }
    }

    // 策略 2: CWD 相对路径（开发环境）
    //  Strategy 2: CWD-relative path (development environment)
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("Engine/Axon/axon_engine.dll"));
    }

    // 策略 3: CWD 上级目录（cargo run from src-tauri/）
    //  Strategy 3: CWD parent directory (cargo run from src-tauri/)
    if let Ok(cwd) = std::env::current_dir() {
        if let Some(parent) = cwd.parent() {
            candidates.push(parent.join("Engine/Axon/axon_engine.dll"));
        }
    }

    // 去重后逐个检查存在性
    //  Deduplicate and check existence
    let mut tried_paths = Vec::new();
    for candidate in &candidates {
        let normalized = if candidate.is_absolute() {
            candidate.clone()
        } else {
            std::env::current_dir()
                .unwrap_or_default()
                .join(candidate)
        };
        tried_paths.push(normalized.to_string_lossy().to_string());

        if normalized.exists() {
            let engine_root = normalized
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("."));
            return Ok((normalized, engine_root));
        }
    }

    Err(format!(
        "axon_engine.dll not found in any candidate path: {}",
        tried_paths.join(", ")
    ))
}

/// 初始化 SQLite 数据库池（与主进程使用相同的 APPDATA 路径策略）
///  Initialize SQLite database pool (uses same APPDATA path strategy as main process)
async fn init_database_pool() -> Result<sqlx::SqlitePool, String> {
    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::SqlitePool;

    // 加载应用配置
    //  Load application config
    let config = crate::models::config::AppConfig::load().unwrap_or_default();

    // 解析数据库路径（与 main.rs resolve_behavior_database_path 相同的策略）
    //  Resolve database path (same strategy as main.rs resolve_behavior_database_path)
    let db_path = resolve_database_path_for_service(&config)?;
    eprintln!("[Service] Database path: {}", db_path.display());

    let opts = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true);
    let pool = SqlitePool::connect_with(opts)
        .await
        .map_err(|e| format!("Failed to connect to database: {}", e))?;

    // 运行必要的表迁移（与 main.rs background_init 相同）
    //  Run necessary table migrations (same as main.rs background_init)
    sqlx::query(
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
    .map_err(|e| format!("Failed to create events table: {}", e))?;

    // 初始化隔离区表
    //  Initialize quarantine table
    let quarantine_service = crate::services::quarantine_service::QuarantineService::new();
    quarantine_service
        .initialize_database(&pool)
        .await
        .map_err(|e| format!("Failed to initialize quarantine database: {}", e))?;

    Ok(pool)
}

/// 解析数据库路径（服务进程版本，与 main.rs resolve_behavior_database_path 等价）
///  Resolve database path (service process version, equivalent to main.rs resolve_behavior_database_path)
fn resolve_database_path_for_service(
    config: &crate::models::config::AppConfig,
) -> Result<std::path::PathBuf, String> {
    use std::path::PathBuf;

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

    Ok(database_path)
}

/// 检查命令行参数是否包含 --service
///  Check if command line arguments contain --service
pub fn is_service_mode() -> bool {
    std::env::args().any(|arg| arg == "--service")
}

// ============================================================================
// UI 进程拉起 — 服务以 SYSTEM 在 Session 0 运行，需要在用户会话中启动 UI 进程
//  UI process launch - service runs as SYSTEM in Session 0, UI needs to run in user session
// ============================================================================

/// 在用户会话中启动 UI 进程（不带 --service 参数）
///  Launch UI process in user session (without --service argument)
///
/// 服务以 SYSTEM 权限在 Session 0 运行，UI 进程需要在用户登录会话（Session 1+）中运行。
///  Service runs as SYSTEM in Session 0, UI process needs to run in user login session (Session 1+).
///
/// 实现方式：
///  Implementation:
/// 1. 获取活跃控制台会话 ID（WTSGetActiveConsoleSessionId）
/// 2. 查询该会话的用户令牌（WTSQueryUserToken）
/// 3. 创建用户环境块（CreateEnvironmentBlock）
/// 4. 使用 CreateProcessAsUserW 在用户会话中启动进程
///
/// 注意：如果无用户登录（如系统启动时），此函数会静默跳过。
///  Note: If no user is logged in (e.g. at boot), this function silently skips.
fn launch_ui_process() -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::System::Environment::CreateEnvironmentBlock;
    use windows::Win32::System::RemoteDesktop::{
        WTSGetActiveConsoleSessionId, WTSQueryUserToken,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, PROCESS_INFORMATION, STARTUPINFOW,
        CREATE_UNICODE_ENVIRONMENT, CREATE_NO_WINDOW,
    };

    // 1. 获取活跃控制台会话 ID
    //  1. Get active console session ID
    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    if session_id == 0xFFFFFFFF {
        eprintln!("[Service] No active console session, skipping UI launch");
        return Ok(());
    }
    eprintln!("[Service] Active console session: {}", session_id);

    // 2. 查询该会话的用户令牌
    //  2. Query user token for this session
    let mut user_token = windows::Win32::Foundation::HANDLE::default();
    unsafe {
        WTSQueryUserToken(session_id, &mut user_token)
            .map_err(|e| format!("WTSQueryUserToken failed: {}", e))?;
    }

    // 3. 创建用户环境块
    //  3. Create user environment block
    let mut env_block: *mut std::ffi::c_void = std::ptr::null_mut();
    unsafe {
        let _ = CreateEnvironmentBlock(&mut env_block, user_token, false);
    }

    // 4. 获取可执行文件路径（UI 进程使用同一个 exe，不带 --service 参数）
    //  4. Get executable path (UI process uses same exe, without --service argument)
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get current exe path: {}", e))?;
    let exe_path_str = exe_path.to_string_lossy().to_string();
    eprintln!("[Service] Launching UI process: {}", exe_path_str);

    // 5. 构造命令行（CreateProcessAsUserW 需要可修改的宽字符缓冲区）
    //  5. Build command line (CreateProcessAsUserW needs mutable wide char buffer)
    let mut command_line: Vec<u16> = format!("\"{}\"", exe_path_str)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // 6. 构造 STARTUPINFO
    //  6. Build STARTUPINFO
    let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    // 使用桌面"winsta0\\default"确保在用户会话中显示窗口
    //  Use desktop "winsta0\\default" to ensure window shows in user session
    let desktop: Vec<u16> = "winsta0\\default\0".encode_utf16().collect();
    startup_info.lpDesktop = windows::core::PWSTR(desktop.as_ptr() as *mut _);

    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // 7. 调用 CreateProcessAsUserW
    //  7. Call CreateProcessAsUserW
    let exe_path_wide: Vec<u16> = exe_path_str
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let result = unsafe {
        CreateProcessAsUserW(
            user_token,
            PCWSTR(exe_path_wide.as_ptr()),
            windows::core::PWSTR(command_line.as_mut_ptr()),
            Some(&SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: false.into(),
            }),
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            Some(env_block),
            PCWSTR(std::ptr::null()),
            &startup_info,
            &mut process_info,
        )
    };

    // 清理环境块
    //  Clean up environment block
    if !env_block.is_null() {
        unsafe {
            let _ = windows::Win32::System::Environment::DestroyEnvironmentBlock(env_block);
        }
    }

    // 清理句柄
    //  Clean up handles
    unsafe {
        if result.is_ok() {
            let _ = CloseHandle(process_info.hThread);
            let _ = CloseHandle(process_info.hProcess);
            eprintln!(
                "[Service] UI process launched successfully (PID: {})",
                process_info.dwProcessId
            );
        }
        let _ = CloseHandle(user_token);
    }

    result.map_err(|e| format!("CreateProcessAsUserW failed: {}", e))?;
    Ok(())
}

/// 启动服务 dispatcher — 阻塞直到服务停止
///  Start service dispatcher - blocks until service stops
///
/// 这是 --service 模式的真正入口。SCM 通过 dispatcher 调用 ServiceMain。
///  This is the real entry for --service mode. SCM calls ServiceMain via dispatcher.
pub fn dispatch() -> Result<(), String> {
    // define_windows_service! 宏生成 extern "system" fn 类型的 ServiceMain 入口点
    //  The macro generates an extern "system" fn ServiceMain entry point
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| format!("Failed to start service dispatcher: {}", e))
}

// 定义 FFI ServiceMain 入口点 — 宏生成 extern "system" fn 并调用 my_service_main
//  Define FFI ServiceMain entry point - macro generates extern "system" fn and calls my_service_main
windows_service::define_windows_service!(ffi_service_main, my_service_main);

/// ServiceMain 实现 — SCM 通过 dispatcher 调用此函数
///  ServiceMain implementation - called by SCM via dispatcher
fn my_service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("[Service] Fatal error in ServiceMain: {}", e);
        // run_service 内部已处理 SCM 状态通知，这里只记录日志
        //  run_service already handled SCM status notification, here we just log
    }
}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_service_mode_detects_flag() {
        // 默认情况下测试进程不含 --service 参数
        //  By default, the test process does not contain --service argument
        // 这个测试只验证函数可调用且返回布尔值
        //  This test only verifies the function is callable and returns a boolean
        let _ = is_service_mode();
    }

    #[test]
    fn forwardable_events_not_empty() {
        assert!(!FORWARDABLE_EVENTS.is_empty());
        // 确保关键事件都在转发列表中
        //  Ensure key events are in the forward list
        assert!(FORWARDABLE_EVENTS.contains(&"etw-event"));
        assert!(FORWARDABLE_EVENTS.contains(&"process-intercepted"));
        assert!(FORWARDABLE_EVENTS.contains(&"file-hook-event"));
    }

    #[test]
    fn service_name_constants_defined() {
        assert!(!SERVICE_NAME.is_empty());
        assert!(!SERVICE_DISPLAY_NAME.is_empty());
        assert!(!SERVICE_DESCRIPTION.is_empty());
    }
}
