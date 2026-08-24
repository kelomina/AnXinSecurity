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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

/// 服务停止信号的全局注册点：服务主循环（SCM 模式 / 前台模式）在启动时注册自己的
/// 停止标志，IPC `shutdown_service` 等外部请求通过 [`request_service_shutdown`] 置位。
///  Global registry of the service stop signal: the service main loop (SCM mode /
///  foreground mode) registers its stop flag at startup; external requests such as the
///  IPC `shutdown_service` method set it via [`request_service_shutdown`].
static SERVICE_STOP_SIGNAL: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

/// 服务模式文件日志路径：服务进程无控制台，stderr 全部丢失；关键生命周期
/// 事件（启动/停止/UI 拉起/组件失败）双写到该文件供现场排查。
///  Service-mode file log path: a service process has no console and its stderr is
///  lost; key lifecycle events (start/stop/UI launch/component failures) are
///  dual-written to this file for on-site troubleshooting.
fn service_log_path() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("PROGRAMDATA").unwrap_or_else(|_| r"C:\ProgramData".into()))
        .join("AnXinSecurity")
        .join("logs")
        .join("service.log")
}

/// 双写一条服务日志：保留原有 stderr 行为，同时追加到文件（失败静默——日志
/// 绝不能反过来影响防护流程）。
///  Dual-write one service log line: keeps the original stderr behaviour and appends
///  to the file (failures are swallowed — logging must never affect protection).
pub fn service_log(msg: &str) {
    eprintln!("{}", msg);
    let path = service_log_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "[{}] {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"), msg);
    }
}

/// 请求优雅停止防护服务（幂等）：仅置位停止标志，真正的组件收尾由持有
/// ProtectionRuntime 的主循环执行。
///  Request a graceful protection-service shutdown (idempotent): only sets the stop flag;
///  actual component teardown is performed by the main loop owning ProtectionRuntime.
pub fn request_service_shutdown() {
    match SERVICE_STOP_SIGNAL.get() {
        Some(flag) => flag.store(true, Ordering::SeqCst),
        None => eprintln!("[Service] shutdown requested but no service loop registered"),
    }
}

/// 需要转发到 UI 进程的事件名列表
///  List of event names to forward to UI process
const FORWARDABLE_EVENTS: &[&str] = &[
    "etw-event",
    "file-hook-event",
    "process-intercepted",
    "log-event",
    "behavior-event",
    // 事件名必须与 risk_service.rs 的 emit 完全一致：此前这里写的是 "risk-event"，
    // 而全仓无人 emit 该名字，真正发出的是 "etw-risk-event"（前端 src/api/risk.ts 也听这个），
    // 导致服务模式下每一次风险研判结果都被丢弃。
    //  Must match the emit in risk_service.rs exactly: this used to read "risk-event", which
    //  nothing emits — the real event is "etw-risk-event" (also what src/api/risk.ts listens
    //  for) — so every risk assessment was dropped in service mode.
    "etw-risk-event",
    "interception-decision",
    "file-monitor-event",
    "snapshot-progress",
    "snapshot-result",
    // 网络防火墙：连接事件与待裁决通知必须能从服务进程到达 UI，
    // 否则弹窗永远不会出现，用户只能干等驱动超时。
    //  Network firewall: connection events and verdict requests must reach the UI
    //  from the service process, otherwise the prompt never appears and the user
    //  can only wait for the driver to time out.
    "network-event",
    "network-intercepted",
    // 进程监控采集：生命周期事件与 BYOVD 回调失明告警必须能从服务进程到达 UI，
    // 否则 ProcessLifecyclePage 在服务模式下收不到实时数据与高危告警。
    //  Process monitor: lifecycle events and the BYOVD callback-blindness alert
    //  must reach the UI from the service process.
    "process-lifecycle-event",
    "process-monitor-tampered",
    // 服务生命周期：shutdown_service 被接受后向所有客户端广播，让 Main 等其余
    // GUI 进程自行优雅退出（Tray 发起方自己忽略该事件）。
    //  Service lifecycle: after shutdown_service is accepted, broadcast so remaining
    //  GUI processes (Main etc.) exit gracefully on their own (the requesting Tray
    //  ignores this event itself).
    "service-exiting",
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
    // 注册到全局停止点，供 IPC shutdown_service 等外部请求置位。
    //  Register to the global stop point so external requests (IPC shutdown_service) can set it.
    let _ = SERVICE_STOP_SIGNAL.set(stop_flag.clone());
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
    let runtime_guard =
        match start_protection_runtime(started_at, stop_flag.clone()) {
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
        service_log(&format!("[Service] Failed to launch UI process: {}", e));
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

/// 前台模式运行防护后端（无 SCM）：行为与 SCM 服务一致，但生命周期由 Ctrl+C /
/// 控制台关闭或 IPC `shutdown_service` 驱动。供开发调试与「standalone 引导启动」使用。
///  Run the protection backend in foreground mode (no SCM): same behavior as the SCM
///  service but driven by Ctrl+C / console close or IPC `shutdown_service`. Used for
///  development and for the standalone bootstrap path.
///
/// 中文关键词：前台模式，Ctrl+C，调试，独立模式，引导启动
/// English keywords: foreground mode, ctrl-c, debugging, standalone, bootstrap
pub fn run_foreground() -> Result<(), String> {
    let stop_flag = Arc::new(AtomicBool::new(false));
    let _ = SERVICE_STOP_SIGNAL.set(stop_flag.clone());

    eprintln!("[Service] Foreground protection runtime starting");
    let started_at = chrono::Utc::now().timestamp_millis() as u64;
    let runtime_guard = start_protection_runtime(started_at, stop_flag.clone())?;

    if let Err(e) = launch_ui_process() {
        service_log(&format!("[Service] Failed to launch UI process: {} (non-fatal)", e));
    }

    // Ctrl+C / 控制台关闭 → 置位停止标志。用独立的 current-thread runtime 阻塞等待信号，
    // 不占用防护 runtime 的 worker。
    //  Ctrl+C / console close → set stop flag. A dedicated current-thread runtime blocks on
    //  the signal so the protection runtime's workers are untouched.
    {
        let flag = stop_flag.clone();
        std::thread::Builder::new()
            .name("anxin-signal".to_string())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                if let Ok(rt) = rt {
                    let _ = rt.block_on(async {
                        let _ = tokio::signal::ctrl_c().await;
                    });
                }
                eprintln!("[Service] Stop signal received (foreground)");
                flag.store(true, Ordering::SeqCst);
            })
            .map_err(|e| format!("Failed to spawn signal thread: {}", e))?;
    }

    while !stop_flag.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(1));
    }

    eprintln!("[Service] Stopping foreground protection runtime...");
    drop(runtime_guard);
    eprintln!("[Service] Foreground protection runtime stopped");
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
    started_at: u64,
    stop_flag: Arc<AtomicBool>,
) -> Result<ProtectionRuntime, String> {
    // 解析引擎 DLL 路径（服务进程没有 Tauri App，使用 CWD 相对路径）
    //  Resolve engine DLL path (service process has no Tauri App, use CWD-relative paths)
    let (engine_dll_path, engine_root_path) = resolve_engine_dll_path_for_service()
        .map_err(|e| format!("Failed to resolve engine DLL path: {}", e))?;
    eprintln!("[Service] Engine DLL path: {}", engine_dll_path.display());

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
    let ipc_server = Arc::new(IpcServer::new(
        ctx.clone(),
        started_at,
        runtime_handle.clone(),
    ));
    // 注册进上下文，供 ServiceContext::show_interception_window 判断"是否还有 UI 可询问"。
    // 没有已连接的 UI 客户端时不得挂起进程——没人能回答的拦截等于永久冻结。
    //  Registered so ServiceContext::show_interception_window can tell whether any UI is left to
    //  ask. With no connected UI client a suspension can never be answered, i.e. it is a freeze.
    ctx.register::<IpcServer>(ipc_server.clone());
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

    // 定时清理行为库（保留期外事件删除 + 容量上限触发最老数据清理，每小时一次）。
    //  Periodic behavior-DB cleanup (retention prune + size-cap oldest-row purge, hourly).
    let ctx_for_prune = ctx.clone();
    let (retention_days, max_db_bytes) = crate::models::config::AppConfig::load()
        .map(|c| {
            (
                c.behavior_analyzer.retention_days,
                c.behavior_analyzer.max_db_bytes,
            )
        })
        .unwrap_or((3, 1024 * 1024 * 1024));
    runtime.spawn(async move {
        use tokio::time::{interval, Duration};
        let mut ticker = interval(Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            let Some(behavior) = ctx_for_prune.get::<
                std::sync::Mutex<crate::services::behavior_service::BehaviorService>,
            >()
            else {
                continue;
            };
            // 锁内 clone（BehaviorService 内部是 Arc，廉价），释放锁后 async 调用，
            // 避免 std MutexGuard 跨 await（不 Send）。
            let svc = behavior.lock().unwrap_or_else(|e| e.into_inner()).clone();
            // 容量上限优先：超限删最老数据并 VACUUM
            match svc.db_size_bytes().await {
                Ok(size) if size > max_db_bytes => {
                    if let Err(err) = svc.prune_by_size_limit(max_db_bytes).await {
                        eprintln!("[Service] behavior size-limit prune failed: {}", err);
                    }
                }
                Ok(_) => {}
                Err(err) => eprintln!("[Service] behavior db size check failed: {}", err),
            }
            // 保留期清理
            let now = chrono::Utc::now();
            let before = (now - chrono::Duration::days(retention_days as i64))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            match svc.prune_older_than(&before).await {
                Ok((e, l)) => {
                    if e > 0 || l > 0 {
                        eprintln!(
                            "[Service] behavior retention prune: {} events, {} lifecycle",
                            e, l
                        );
                    }
                }
                Err(err) => eprintln!("[Service] behavior retention prune failed: {}", err),
            }
        }
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

    // 尝试连接 AnXinProcProtect 内核驱动并注册本进程 PID。
    // 在独立线程中执行且不等待：驱动登记是"防御纵深"，不必阻塞服务进入 Running。
    // DeviceIoControl / FilterSendMessage 是同步且无超时的，若驱动已加载但分发例程
    // 不响应，在主线程上执行会把服务卡死在 StartPending，超过 SCM 的 30s wait_hint
    // 即被杀 —— 这正是"无法启动服务"的症状。移出关键路径后，驱动卡死只阻塞这个
    // 后台线程，服务照常进入 Running、UI 照常可连。
    //  Attempt to connect to AnXinProcProtect kernel driver and register own PID.
    //  Runs on a detached thread and is not awaited: driver registration is defence in
    //  depth and must not delay the service entering Running. DeviceIoControl /
    //  FilterSendMessage are synchronous with no timeout — if a driver is loaded but its
    //  dispatch does not answer, executing this on the main thread wedges the service in
    //  StartPending past SCM's 30s wait_hint, which is exactly the "service fails to
    //  start" symptom. Off the critical path, a hung driver only blocks this background
    //  thread while the service starts normally and the UI can still connect.
    std::thread::Builder::new()
        .name("anxin-driver-init".to_string())
        .spawn(|| {
            if let Err(e) = init_driver_protection() {
                eprintln!(
                    "[Service] Driver protection not available (non-fatal): {}",
                    e
                );
                // 驱动缺失不阻断服务功能，仅丢失内核级进程保护
                //  Driver absence does not block service; only kernel-level process protection is lost
            }
        })
        .map_err(|e| format!("Failed to spawn driver init thread: {}", e))?;

    Ok(ProtectionRuntime {
        ipc_server,
        runtime: Some(runtime),
    })
}

/// 连接到 AnXinProcProtect 驱动并注册当前进程 PID 为受保护进程。
///  Connect to AnXinProcProtect driver and register the current process PID as protected.
///
/// 如果驱动未安装或未运行，返回错误但不 panic。
///  If the driver is not installed or not running, returns an error but does not panic.
fn init_driver_protection() -> Result<(), String> {
    use crate::utils::driver_client::DriverClient;

    let client = DriverClient::new();
    client
        .connect()
        .map_err(|e| format!("Failed to connect to driver device: {}", e))?;

    // 1. Register own PID for process handle protection
    //     Register own PID for process handle protection
    let pid = std::process::id();
    client
        .add_pid(pid)
        .map_err(|e| format!("Failed to register PID {} with driver: {}", pid, e))?;
    eprintln!(
        "[Service] Driver process protection activated for PID {}",
        pid
    );

    // 2. Register current WindowStation for window handle protection
    //     Register current WindowStation for window handle protection
    //    The service runs as SYSTEM in Session 0; its WinSta object is registered
    //    so that unauthorized callers cannot enumerate desktops or interact with
    //    Service-owned windows.
    //    Note: The UI process (running in user session) should also register its
    //    own WinSta separately. This will be added in a future update.
    match register_winsta_with_driver(&client) {
        Ok(()) => eprintln!("[Service] Driver window station protection activated"),
        Err(e) => eprintln!(
            "[Service] Window station protection unavailable: {} (non-fatal)",
            e
        ),
    }

    // 连接保持打开，确保本进程在受保护列表中的状态持续有效
    //  Keep connection open to ensure this process stays in the protected list
    // 当 DriverClient 被 drop 时会自动关闭句柄
    //  Handle is auto-closed when DriverClient is dropped
    std::mem::forget(client);

    // 3. Register critical file/directory paths for file system protection
    //     Register critical file/directory paths for file system protection
    if let Err(e) = register_file_protection() {
        eprintln!(
            "[Service] File protection registration unavailable: {} (non-fatal)",
            e
        );
    }

    Ok(())
}

/// 解析并注册受保护的文件/目录路径到 AnXinFileProtect.sys 微过滤器。
///  Resolves and registers protected file/directory paths with AnXinFileProtect.sys minifilter.
///
/// 将需要保护的目录路径转换为 NT 命名空间格式后，通过 FilterConnectCommunicationPort
/// 发送到 AnXinFileProtect 驱动。注册后，非授权进程无法修改/删除这些路径下的文件。
///  Converts protected directory paths to NT namespace format and sends them to the
///  AnXinFileProtect driver via FilterConnectCommunicationPort. After registration,
///  unauthorized processes cannot modify/delete files under these paths.
fn register_file_protection() -> Result<(), String> {
    // 要保护的目录路径（DOS 格式）
    // Protected directory paths (DOS format)
    let exe_path = std::env::current_exe().map_err(|e| format!("Failed to get exe path: {}", e))?;
    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| "Failed to get exe directory".to_string())?;

    let protected_dirs = vec![
        exe_dir.to_path_buf(), // 安装目录
    ];

    // 解析每个目录的 NT 路径并发送到驱动
    // Resolve each directory to NT path and send to driver
    //
    // VUL-097 加固：对每个目录同时注册设备路径（\Device\HarddiskVolumeN\...）与
    // Win32 命名空间路径（\??\C:\...）。minifilter 的 FltGetFileNameInformation 在
    // 不同打开方式下可能返回这两种格式之一；注册双格式可保证前缀匹配（IsPathProtected）
    // 不受回调名称格式影响，避免运行期漏保护。
    let mut nt_paths = Vec::new();
    for dir in &protected_dirs {
        match resolve_nt_path(dir) {
            Ok(nt_path) => {
                eprintln!(
                    "[Service] File protection path (device): {} -> {}",
                    dir.display(),
                    nt_path
                );
                nt_paths.push(nt_path);
            }
            Err(e) => {
                eprintln!(
                    "[Service] Warning: failed to resolve NT path for {}: {}",
                    dir.display(),
                    e
                );
            }
        }
        // Win32 命名空间形式（可能失败，如卷无盘符，则仅保留设备形式）
        match resolve_win32_namespace_path(dir) {
            Ok(win32_path) => {
                eprintln!(
                    "[Service] File protection path (win32): {} -> {}",
                    dir.display(),
                    win32_path
                );
                nt_paths.push(win32_path);
            }
            Err(e) => {
                eprintln!(
                    "[Service] Note: no win32-namespace form for {}: {}",
                    dir.display(),
                    e
                );
            }
        }
    }

    if nt_paths.is_empty() {
        return Err("No valid file protection paths resolved".to_string());
    }

    let refs: Vec<&str> = nt_paths.iter().map(|s| s.as_str()).collect();
    crate::utils::driver_client::register_file_protection_paths(&refs)
}

/// 将 DOS 路径转换为 NT 命名空间路径（如 C:\... → \Device\HarddiskVolume1\...）
///  Converts a DOS path (C:\...) to NT namespace path (\Device\HarddiskVolume1\...)
pub(crate) fn resolve_nt_path(path: &std::path::Path) -> Result<String, String> {
    resolve_nt_path_with_flag(
        path,
        windows::Win32::Storage::FileSystem::VOLUME_NAME_NT,
    )
}

/// VUL-097 加固：额外解析 Win32 命名空间路径（如 C:\... → \??\C:\...）。
///  minifilter 对部分打开方式可能返回 \??\C:\... 形式的名称；同时注册设备路径
///  与 Win32 命名空间路径，无论回调返回哪种格式都能前缀匹配，避免运行期漏保护。
///  Also register the Win32-namespace form (\??\C:\...) of each protected dir so
///  prefix matching succeeds regardless of which name format the minifilter sees.
pub(crate) fn resolve_win32_namespace_path(path: &std::path::Path) -> Result<String, String> {
    let dos = resolve_nt_path_with_flag(
        path,
        windows::Win32::Storage::FileSystem::VOLUME_NAME_DOS,
    )?;
    // VOLUME_NAME_DOS 返回 \\?\C:\...；对象管理器中的 Win32 命名空间形式为 \??\C:\...
    if let Some(stripped) = dos.strip_prefix(r"\\?\") {
        Ok(format!(r"\??\{stripped}"))
    } else {
        Ok(dos)
    }
}

/// 以指定卷名标志解析 NT 命名空间路径。
fn resolve_nt_path_with_flag(
    path: &std::path::Path,
    volume_flag: windows::Win32::Storage::FileSystem::GETFINALPATHNAMEBYHANDLE_FLAGS,
) -> Result<String, String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::CreateFileW;

    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Open a handle to the directory
    let handle = unsafe {
        CreateFileW(
            windows::core::PCWSTR(path_wide.as_ptr()),
            windows::Win32::Storage::FileSystem::FILE_GENERIC_READ.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows::Win32::Storage::FileSystem::FILE_SHARE_WRITE
                | windows::Win32::Storage::FileSystem::FILE_SHARE_DELETE,
            None,
            windows::Win32::Storage::FileSystem::OPEN_EXISTING,
            windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    };

    let handle =
        handle.map_err(|e| format!("Failed to open directory '{}': {}", path.display(), e))?;

    // Get NT path using GetFinalPathNameByHandle with the requested volume flag
    // First call to get the required buffer size
    let required_len = unsafe {
        windows::Win32::Storage::FileSystem::GetFinalPathNameByHandleW(handle, &mut [], volume_flag)
    };

    if required_len == 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            let _ = CloseHandle(handle);
        }
        return Err(format!("GetFinalPathNameByHandle (size) failed: {}", err));
    }

    let mut buf = vec![0u16; required_len as usize];
    let len = unsafe {
        windows::Win32::Storage::FileSystem::GetFinalPathNameByHandleW(handle, &mut buf, volume_flag)
    };

    unsafe {
        let _ = CloseHandle(handle);
    }

    if len == 0 || len > required_len {
        let err = std::io::Error::last_os_error();
        return Err(format!("GetFinalPathNameByHandle failed: {}", err));
    }

    // GetFinalPathNameByHandle returns path with \\?\ prefix
    let raw = &buf[..len as usize];
    let path_str = String::from_utf16_lossy(raw);

    // Strip the \\?\ prefix if present
    let nt_path = if let Some(stripped) = path_str.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        path_str
    };

    Ok(nt_path)
}

/// Opens the current process's WindowStation and registers it with the driver.
///
/// This uses `OpenWindowStationW` to get a handle to "WinSta0" (the default
/// interactive window station), then sends the handle to the driver via IOCTL.
/// The driver uses `ObReferenceObjectByHandle` to get the kernel object pointer
/// and stores it for its WinSta ObCallback.
fn register_winsta_with_driver(
    client: &crate::utils::driver_client::DriverClient,
) -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::System::StationsAndDesktops::{CloseWindowStation, OpenWindowStationW};
    use windows::Win32::UI::WindowsAndMessaging::WINSTA_ALL_ACCESS;

    // Encode "WinSta0" to UTF-16
    let name: Vec<u16> = "WinSta0\0".encode_utf16().collect();

    // SAFETY: OpenWindowStationW opens the default window station.
    let winsta_handle =
        unsafe { OpenWindowStationW(PCWSTR(name.as_ptr()), false, WINSTA_ALL_ACCESS as u32) }
            .map_err(|e| format!("OpenWindowStationW failed: {}", e))?;

    let handle_value = winsta_handle.0 as u64;
    let result = client.add_winsta(handle_value);

    // Close the R3 handle (driver holds its own kernel reference)
    unsafe {
        let _ = CloseWindowStation(winsta_handle);
    }

    result.map_err(|e| format!("Failed to register WinSta with driver: {}", e))
}

/// 启动所有防护组件（ETW、文件钩子、文件监控）
///  Start all protection components (ETW, file hook, file monitor)
///
/// 此函数在 Tokio runtime 上下文中调用，确保内部 spawn 的任务能正确绑定到 runtime。
///  This function is called in Tokio runtime context to ensure spawned tasks bind to the runtime correctly.
async fn start_protection_components(ctx: ServiceContext) -> Result<(), String> {
    use std::sync::Mutex;

    // 应用 headless 自动终止模式开关（无 UI 服务场景专用）。开启后，服务进程在
    // recommendAction=block 的拦截因无 UI 客户端无法弹窗时，直接终止目标进程而非
    // 回滚放行（fail-closed）。配置读不到时保持默认 fail-open。
    //  Apply the headless auto-terminate switch (headless service scenario only). When on,
    //  a block intercept that cannot prompt because no UI client is connected terminates
    //  the target process instead of rollback-release (fail-closed). Defaults to fail-open
    //  when the config cannot be read.
    if let Some(interception) = ctx.get::<crate::services::interception_service::InterceptionService>()
    {
        match crate::models::config::AppConfig::load() {
            Ok(config) => {
                interception.set_headless_auto_terminate(config.headless_auto_terminate);
                eprintln!(
                    "[Service] Headless auto-terminate mode: {}",
                    if config.headless_auto_terminate {
                        "ENABLED"
                    } else {
                        "disabled"
                    }
                );
            }
            Err(err) => eprintln!(
                "[Service] Failed to load config for headless auto-terminate switch (defaulting to disabled): {}",
                err
            ),
        }
    }

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

    // 启动网络防火墙（严格遵守 networkFirewall.enabled 开关）
    //  Start the network firewall, strictly honouring the networkFirewall.enabled switch
    //
    // 与 ETW 的处理刻意相反：配置读不到时 ETW 默认继续采集（多采集无害），
    // 而防火墙默认保持关闭。一个读不到配置就自作主张开始拦截流量的防火墙，
    // 可能让用户在完全没有预期的情况下失去网络，且没有任何界面可以关掉它。
    //  Deliberately the opposite of the ETW handling above: when the config cannot
    //  be read ETW keeps collecting (extra telemetry is harmless), whereas the
    //  firewall stays off. A firewall that starts blocking on its own because it
    //  could not read a config file could cut the user off the network with no
    //  warning and no reachable UI to turn it back off.
    match crate::models::config::AppConfig::load() {
        Ok(config) if config.network_firewall.enabled => {
            match ctx.get::<crate::services::firewall_service::FirewallService>() {
                Some(firewall) => match firewall.start(ctx.clone(), &config.network_firewall) {
                    Ok(()) => eprintln!(
                        "[Service] Network firewall started (mode={})",
                        config.network_firewall.mode
                    ),
                    Err(e) => eprintln!(
                        "[Service] Network firewall unavailable (non-fatal): {}. \
                         Install and start the AnXinNetFilter driver to enable traffic control.",
                        e
                    ),
                },
                None => eprintln!("[Service] FirewallService not registered in context"),
            }
        }
        Ok(_) => eprintln!("[Service] Network firewall disabled by config"),
        Err(err) => eprintln!(
            "[Service] Failed to load config for the firewall switch: {} (leaving it disabled)",
            err
        ),
    }

    // 启动进程监控采集（严格遵守 procMonitor.enabled 开关；驱动缺失按降级处理）
    //  Start the process monitor collector, honouring the procMonitor.enabled switch;
    //  a missing driver degrades gracefully.
    match crate::models::config::AppConfig::load() {
        Ok(config) if config.proc_monitor.enabled => {
            match ctx.get::<crate::services::process_lifecycle_service::ProcessLifecycleService>() {
                Some(collector) => match collector.start(ctx.clone()) {
                    Ok(()) => eprintln!("[Service] Process lifecycle collector started"),
                    Err(e) => eprintln!(
                        "[Service] Process lifecycle collector unavailable (non-fatal): {}. \
                         Install and start the AnXinProcMon driver to enable process lifecycle monitoring.",
                        e
                    ),
                },
                None => eprintln!("[Service] ProcessLifecycleService not registered in context"),
            }
        }
        Ok(_) => eprintln!("[Service] Process lifecycle collector disabled by config"),
        Err(err) => eprintln!(
            "[Service] Failed to load config for the process monitor switch: {} (leaving it disabled)",
            err
        ),
    }

    // 启动 ETW 监控（必须遵守 behaviorMonitoring 开关）
    //  Start ETW monitoring, honouring the behaviorMonitoring switch
    //
    // 此前这里无条件 start，与 main.rs 独立模式的条件启动不一致：
    // 用户关掉行为监控后重启服务，服务照样采集。
    //  This used to start unconditionally, diverging from the conditional start in main.rs:
    //  after the user turned behaviour monitoring off, restarting the service resumed collection.
    let behavior_monitoring_enabled = match crate::models::config::AppConfig::load() {
        Ok(config) => config.behavior_monitoring.enabled,
        Err(err) => {
            // 读不到配置时保持采集：安全产品默认开启防护，宁可多采集也不静默失防
            //  Keep collecting when the config cannot be read: a security product defaults to
            //  protection on rather than silently disarming
            eprintln!(
                "[Service] Failed to load config for behavior monitoring switch: {} (defaulting to enabled)",
                err
            );
            true
        }
    };

    if !behavior_monitoring_enabled {
        eprintln!("[Service] ETW monitoring disabled by config (behaviorMonitoring.enabled=false)");
    } else if let Some(etw_service) = ctx.get::<Mutex<crate::services::etw_service::EtwService>>() {
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

    // 启动文件监控服务（依赖 ETW 广播接收器、引擎、缓存、拦截服务），
    // 必须遵守 fileMonitoring.enabled 开关——此前无条件启动，用户关掉
    // 文件监控后重启服务照样监视，与 main.rs 独立模式的条件启动不一致。
    //  Start file monitor service (depends on ETW broadcast receiver, engine, cache,
    //  interception), honouring the fileMonitoring.enabled switch. It used to start
    //  unconditionally, so disabling file monitoring and restarting the service still
    //  monitored files, diverging from the conditional start in main.rs.
    let file_monitoring_enabled = match crate::models::config::AppConfig::load() {
        Ok(config) => config.file_monitoring.enabled,
        Err(err) => {
            // 读不到配置时保持监控：安全产品默认开启防护，宁可多采集也不静默失防
            //  Keep monitoring when the config cannot be read: a security product defaults
            //  to protection on rather than silently disarming
            eprintln!(
                "[Service] Failed to load config for file monitoring switch: {} (defaulting to enabled)",
                err
            );
            true
        }
    };

    if !file_monitoring_enabled {
        eprintln!("[Service] File monitor disabled by config (fileMonitoring.enabled=false)");
    } else if let (Some(etw_service), Some(engine), Some(cache), Some(interception), Some(file_monitor)) = (
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

    // 启动进程监控（APIHook watcher，遵守 processMonitoring.enabled 开关）。
    // 注意服务进程无法运行 ProcessScannerService（其 start() 需要 AppHandle 弹出
    // 拦截窗口），因此这里只启动 APIHook 注入监控；新进程扫描在服务模式下不运行。
    //  Start process monitoring (APIHook watcher), honouring the processMonitoring.enabled
    //  switch. The service process cannot run ProcessScannerService (its start() needs an
    //  AppHandle to show the interception modal), so only the APIHook injection watcher
    //  starts here; new-process scanning does not run in service mode.
    let process_monitoring_enabled = match crate::models::config::AppConfig::load() {
        Ok(config) => config.process_monitoring.enabled,
        Err(err) => {
            // 读不到配置时保持监控：安全产品默认开启防护，宁可多采集也不静默失防
            eprintln!(
                "[Service] Failed to load config for process monitoring switch: {} (defaulting to enabled)",
                err
            );
            true
        }
    };

    if !process_monitoring_enabled {
        eprintln!("[Service] Process monitor disabled by config (processMonitoring.enabled=false)");
    } else if let Some(watcher) = ctx
        .get::<crate::services::process_monitor_service::ProcessMonitorService>()
    {
        match watcher.start_with_resource_dir("", "", "", "", 2000, None) {
            Ok(_) => eprintln!("[Service] Process monitor (APIHook) started"),
            Err(e) => eprintln!(
                "[Service] Process monitor unavailable (non-fatal): {}. APIHook injector/dll not found.",
                e
            ),
        }
    } else {
        eprintln!("[Service] ProcessMonitorService not registered in context");
    }

    // 启动启动快照扫描（在服务进程中执行，结果通过 event_bus → IPC 转发给 UI 进程）
    //  Run startup snapshot scan in service process; results forwarded to UI via event_bus → IPC
    spawn_startup_snapshot_in_service(ctx.clone());

    Ok(())
}

/// 在服务进程中异步执行启动快照扫描
///  Run startup snapshot scan asynchronously in the service process
///
/// 加载配置构造 SnapshotScanOptions，等待引擎后台加载完成，然后用 SnapshotContext::Service 调用
/// take_startup_snapshot。事件通过 event_bus → IPC 桥接转发给 UI 进程。
///  Loads config to build SnapshotScanOptions, waits for engine background load, then calls
/// take_startup_snapshot with SnapshotContext::Service. Events are forwarded to UI via event_bus → IPC.
fn spawn_startup_snapshot_in_service(ctx: ServiceContext) {
    use crate::services::snapshot_service::{SnapshotContext, SnapshotScanOptions};

    // 加载配置构造扫描选项 / Load config to build scan options
    let config = match crate::models::config::AppConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "[Service] Failed to load config for startup snapshot, using defaults: {}",
                e
            );
            crate::models::config::AppConfig::default()
        }
    };
    let snapshot_options = SnapshotScanOptions {
        slow_warn_ms: config.scanner.startup_snapshot_slow_warn_ms,
        target_scan_timeout_ms: config.scanner.timeout_ms,
        module_enumeration_timeout_ms: config.scanner.startup_module_enumeration_timeout_ms,
        signature_verify_timeout_ms: config.scanner.startup_signature_verify_timeout_ms,
        signature_verify_concurrency: config.scanner.startup_signature_verify_concurrency,
        revocation_check_timeout_ms: config.scanner.startup_revocation_check_timeout_ms,
        revocation_check_concurrency: config.scanner.startup_revocation_check_concurrency,
    };

    let trust = ctx.get::<crate::services::trust_service::TrustService>();
    let engine = ctx.get::<crate::services::engine_service::EngineService>();
    let cache = ctx.get::<crate::services::scan_result_cache_service::ScanResultCacheService>();
    let snapshot = ctx.get::<crate::services::snapshot_service::SnapshotService>();

    let (Some(trust), Some(engine), Some(cache), Some(snapshot)) = (trust, engine, cache, snapshot)
    else {
        eprintln!(
            "[Service] Missing dependencies for startup snapshot (trust/engine/cache/snapshot)"
        );
        return;
    };

    let snapshot_ctx = SnapshotContext::Service(ctx.clone());
    tauri::async_runtime::spawn(async move {
        // 确保引擎已加载（start_engine 幂等：已加载时立即返回，未加载时同步加载）
        //  Ensure engine is loaded (start_engine is idempotent: returns immediately if loaded, loads synchronously otherwise)
        if let Err(e) = engine.start_engine().await {
            eprintln!(
                "[Service] Engine load failed before snapshot, continuing anyway: {}",
                e
            );
        }

        eprintln!("[Service] Starting startup snapshot in service process");
        match snapshot
            .take_startup_snapshot(trust, engine, cache, &snapshot_ctx, snapshot_options)
            .await
        {
            Ok(result) => {
                eprintln!(
                    "[Service] Startup snapshot done: {} processes, {} signed, {} unsigned, {} paused, {} modules, {} malicious processes, {} malicious modules, {} image integrity alerts, {}ms",
                    result.total_processes,
                    result.signed_processes,
                    result.unsigned_processes,
                    result.paused_processes,
                    result.scanned_modules,
                    result.malicious_processes,
                    result.malicious_modules,
                    result.image_integrity_alerts,
                    result.duration_ms
                );
            }
            Err(e) => {
                eprintln!("[Service] Startup snapshot failed: {}", e);
            }
        }
    });
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
    let mut receivers: Vec<(
        String,
        broadcast::Receiver<crate::services::event_bus::EventPayload>,
    )> = Vec::new();
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
fn resolve_engine_dll_path_for_service() -> Result<(std::path::PathBuf, std::path::PathBuf), String>
{
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
            std::env::current_dir().unwrap_or_default().join(candidate)
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

    // 建 process_lifecycle 表（§4.7，与 main.rs background_init 一致）
    //  Create the process_lifecycle table (same as main.rs background_init)
    crate::services::behavior_service::BehaviorService::initialize_lifecycle_table(&pool)
        .await
        .map_err(|e| format!("Failed to create process_lifecycle table: {}", e))?;

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
/// 解析托盘进程 exe 路径：优先同目录的拆分后托盘进程（AnXinTray.exe / anxin-tray.exe），
/// 都不存在时回退自身（单 exe 兼容期行为）。
///  Resolve the tray-process exe path: prefer the split tray process in the same
///  directory (AnXinTray.exe / anxin-tray.exe); fall back to self during the single-exe
///  compatibility window.
fn resolve_tray_exe_path() -> std::path::PathBuf {
    let Ok(self_exe) = std::env::current_exe() else {
        return std::path::PathBuf::from("anxin-security.exe");
    };
    if let Some(dir) = self_exe.parent() {
        for name in ["AnXinTray.exe", "anxin-tray.exe"] {
            let candidate = dir.join(name);
            if candidate.exists() {
                return candidate;
            }
        }
    }
    self_exe
}

fn launch_ui_process() -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenPrimary, SECURITY_ATTRIBUTES, TOKEN_ALL_ACCESS,
    };
    use windows::Win32::System::Environment::CreateEnvironmentBlock;
    use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
        STARTF_USESHOWWINDOW, STARTUPINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{AllowSetForegroundWindow, SW_SHOWNORMAL};

    // 1. 获取活跃控制台会话 ID
    //  1. Get active console session ID
    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    if session_id == 0xFFFFFFFF {
        service_log("[Service] No active console session, skipping UI launch");
        return Ok(());
    }
    service_log(&format!("[Service] Active console session: {}", session_id));

    // 2. 查询该会话的用户令牌。
    //    服务 AUTO_START 常早于用户自动登录完成，此时 WTSQueryUserToken 报
    //    0x800703F0（令牌不存在）——这是时序问题而非故障；轮询等待登录就绪，
    //    总窗口 90s（覆盖慢盘冷启动），期间每 5s 重试一次。
    //  2. Query the session's user token. AUTO_START services routinely beat the
    //     user autologon, where WTSQueryUserToken fails with 0x800703F0 (token does
    //     not exist) — a timing issue, not a fault. Poll until logon is ready: retry
    //     every 5s within a 90s window (covers slow cold boots).
    let mut user_token = windows::Win32::Foundation::HANDLE::default();
    {
        const LOGON_WAIT_TOTAL_MS: u64 = 90_000;
        const LOGON_WAIT_STEP_MS: u64 = 5_000;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(LOGON_WAIT_TOTAL_MS);
        loop {
            let mut attempt_err = None;
            unsafe {
                if let Err(e) = WTSQueryUserToken(session_id, &mut user_token) {
                    attempt_err = Some(e);
                }
            }
            match attempt_err {
                None => break,
                Some(e) => {
                    if std::time::Instant::now() >= deadline {
                        let msg = format!("[Service] WTSQueryUserToken failed after {}s wait: {}", LOGON_WAIT_TOTAL_MS / 1000, e);
                        service_log(&msg);
                        return Err(format!("WTSQueryUserToken failed: {}", e));
                    }
                    service_log(&format!(
                        "[Service] user token not ready yet ({}) - waiting for logon",
                        e.code()
                    ));
                    std::thread::sleep(std::time::Duration::from_millis(LOGON_WAIT_STEP_MS));
                }
            }
        }
    }

    // 2.5 复制为主令牌：WTSQueryUserToken 返回的令牌句柄在受保护的服务进程内
    //     会被自保驱动的句柄审计降级为 Identification 模拟级别（VUL-103 副作用），
    //     直接传给 CreateProcessAsUserW 会报 0x80070542 BAD_IMPERSONATION_LEVEL。
    //     按 MSDN 指引先显式 DuplicateTokenEx 出 TokenPrimary + SecurityImpersonation。
    //  2.5 Duplicate into a primary token: inside the protected service process the
    //      self-protection driver's handle audit downgrades the WTSQueryUserToken
    //      handle to Identification level (side effect of the VUL-103 fix), so passing
    //      it straight to CreateProcessAsUserW fails with 0x80070542
    //      BAD_IMPERSONATION_LEVEL. Follow the MSDN guidance and explicitly
    //      DuplicateTokenEx to TokenPrimary + SecurityImpersonation first.
    let mut primary_token = windows::Win32::Foundation::HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            user_token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary_token,
        )
        .map_err(|e| {
            let msg = format!("[Service] DuplicateTokenEx failed: {}", e);
            service_log(&msg);
            format!("DuplicateTokenEx failed: {}", e)
        })?;
    }
    service_log("[Service] user token duplicated to primary (SecurityImpersonation)");

    // 3. 创建用户环境块
    //  3. Create user environment block
    let mut env_block: *mut std::ffi::c_void = std::ptr::null_mut();
    unsafe {
        let _ = CreateEnvironmentBlock(&mut env_block, user_token, false);
    }

    // 4. 获取可执行文件路径（拆分后为同目录的 Tray 进程；兼容期回退自身，不带 --service）
    //  4. Get executable path (the split Tray process next to us; falls back to self without --service)
    let exe_path = resolve_tray_exe_path();
    let exe_path_str = exe_path.to_string_lossy().to_string();
    service_log(&format!("[Service] Launching UI process: {}", exe_path_str));

    // 获取 exe 所在目录作为工作目录，避免继承 System32
    //  Get exe parent dir as working directory to avoid inheriting System32
    let exe_dir = exe_path
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| ".".to_string());
    let exe_dir_wide: Vec<u16> = exe_dir.encode_utf16().chain(std::iter::once(0)).collect();

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
    // 显式指定窗口显示方式，确保跨会话启动时窗口被正常激活
    //  Explicitly set show window flag so the window is properly activated across sessions
    startup_info.dwFlags = STARTF_USESHOWWINDOW;
    startup_info.wShowWindow = SW_SHOWNORMAL.0 as u16;

    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // 7. 调用 CreateProcessAsUserW
    //  7. Call CreateProcessAsUserW
    //    注意：不使用 CREATE_NO_WINDOW，它会导致 GUI 进程的输入句柄被设为 INVALID，
    //    并阻止窗口正常激活。跨会话启动 GUI 进程时应让系统自行处理窗口创建。
    //    Note: Do not use CREATE_NO_WINDOW; it sets GUI process input handles to INVALID
    //    and prevents proper window activation. Let the system handle window creation for
    //    cross-session GUI process launches.
    let exe_path_wide: Vec<u16> = exe_path_str
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let result = unsafe {
        CreateProcessAsUserW(
            primary_token,
            PCWSTR(exe_path_wide.as_ptr()),
            windows::core::PWSTR(command_line.as_mut_ptr()),
            Some(&SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: false.into(),
            }),
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT,
            Some(env_block),
            PCWSTR(exe_dir_wide.as_ptr()),
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
            // 允许 UI 进程获取 foreground 权限，否则窗口可见但无法接收鼠标点击输入。
            //   Allow the UI process to obtain foreground rights; otherwise the window
            //   is visible but cannot receive mouse click input.
            let _ = AllowSetForegroundWindow(process_info.dwProcessId);
            let _ = CloseHandle(process_info.hThread);
            let _ = CloseHandle(process_info.hProcess);
            service_log(&format!(
                "[Service] UI process launched successfully (PID: {})",
                process_info.dwProcessId
            ));

            // 向驱动注册 UI 进程 PID，确保 UI 进程受到内核级进程保护。
            //  Register the UI process PID with the driver for kernel-level process protection.
            // 注意：ProcessNotifyCallback 中虽然也会尝试自动保护，但 SeLocateProcessImageName
            // 在进程创建回调中可能失败（进程尚未完全初始化），因此这里显式注册作为主保护路径。
            //  Note: ProcessNotifyCallback also tries to auto-protect, but
            //  SeLocateProcessImageName may fail during the process creation callback
            //  (process not yet fully initialized). The explicit registration here is
            //  the primary protection path.
            register_ui_process_pid(process_info.dwProcessId);
        }
        let _ = CloseHandle(primary_token);
        let _ = CloseHandle(user_token);
    }

    if let Err(ref e) = result {
        service_log(&format!("[Service] CreateProcessAsUserW failed: {}", e));
    }
    result.map_err(|e| format!("CreateProcessAsUserW failed: {}", e))?;
    Ok(())
}

/// 向驱动显式注册 GUI 进程 PID，确保内核级进程保护生效。
///  Explicitly register a GUI process PID with the driver for kernel-level protection.
///
/// 拆分后两个调用方：服务启动时拉起的 Tray 进程（launch_ui_process），以及
/// 任何通过 IPC 身份校验的 GUI 客户端（Main 由 Tray 按需拉起，服务端在握手
/// 时自动登记，见 ipc_server::handle_client）。
///  Two callers after the split: the Tray process spawned at service start
///  (launch_ui_process), and any GUI client that passed IPC identity verification
///  (Main is spawned by Tray on demand; the server registers it during the IPC
///  handshake, see ipc_server::handle_client).
pub fn register_ui_process_pid(pid: u32) {
    use crate::utils::driver_client::DriverClient;

    let client = DriverClient::new();
    match client.connect() {
        Ok(()) => match client.add_pid(pid) {
            Ok(()) => {
                eprintln!(
                    "[Service] UI process PID {} registered with driver for protection",
                    pid
                );
            }
            Err(e) => {
                eprintln!(
                    "[Service] Failed to register UI PID {} with driver: {}",
                    pid, e
                );
            }
        },
        Err(e) => {
            eprintln!(
                "[Service] Failed to connect to driver for UI PID registration: {}",
                e
            );
        }
    }
    // 保持连接打开，确保 PID 在保护列表中持续有效
    //  Keep the connection open to ensure the PID stays in the protected list
    std::mem::forget(client);
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
        assert!(FORWARDABLE_EVENTS.contains(&"etw-risk-event"));
    }

    /// 转发白名单里的事件名必须真的有人 emit，否则就是死条目（曾经的 "risk-event"）。
    /// 反过来，risk_service 发出的事件名必须在白名单里，否则服务模式下会被静默丢弃。
    ///  Every name in the forward whitelist must actually be emitted by someone, otherwise it is
    ///  a dead entry (as "risk-event" was). Conversely, what risk_service emits must be listed,
    ///  or it gets silently dropped in service mode.
    #[test]
    fn forwardable_events_have_no_dead_entries() {
        let risk_service_source = [
            "src/services/risk_service.rs",
            "src-tauri/src/services/risk_service.rs",
        ]
        .into_iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .expect("risk_service.rs 应可读取");

        assert!(
            risk_service_source.contains("\"etw-risk-event\""),
            "risk_service.rs 应发出 etw-risk-event；若已改名，请同步更新转发白名单"
        );
        assert!(
            !FORWARDABLE_EVENTS.contains(&"risk-event"),
            "risk-event 是死条目，全仓无人 emit，不得留在白名单里制造已转发的假象"
        );
    }

    #[test]
    fn service_name_constants_defined() {
        assert!(!SERVICE_NAME.is_empty());
        assert!(!SERVICE_DISPLAY_NAME.is_empty());
        assert!(!SERVICE_DESCRIPTION.is_empty());
    }

    /// request_service_shutdown 在未注册主循环时不 panic；注册后置位停止标志。
    ///  request_service_shutdown must not panic before a service loop registers; after
    ///  registration it sets the stop flag.
    #[test]
    fn shutdown_request_sets_registered_stop_flag() {
        // 未注册时调用必须安全（OnceLock 为空分支）。
        //  Calling without registration must be safe (empty OnceLock branch).
        let _ = SERVICE_STOP_SIGNAL.set(Arc::new(AtomicBool::new(false)));
        let flag = SERVICE_STOP_SIGNAL.get().expect("flag registered").clone();
        assert!(!flag.load(Ordering::SeqCst));
        request_service_shutdown();
        assert!(
            flag.load(Ordering::SeqCst),
            "shutdown request must set the registered stop flag"
        );
    }
}
