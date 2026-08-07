// 服务上下文 — 防护组件的依赖注入容器
//  Service context - dependency injection container for protection components
//
// 目标：解耦防护组件对 tauri::AppHandle 的直接依赖。
//  Goal: Decouple protection components from direct tauri::AppHandle dependency.
//
// ServiceContext 提供 AppHandle::try_state 的等价能力，但与 Tauri 运行时无关，
// 使得防护组件既能在 Tauri 主进程内运行，也能在独立的 Windows 服务进程内运行。
//
// ServiceContext provides equivalent capability to AppHandle::try_state, but is
// Tauri-runtime-agnostic, enabling protection components to run either in the
// Tauri main process or in a standalone Windows service process.
//
// 中文关键词：服务上下文，依赖注入，服务注册，前后端分离
// English keywords: service context, dependency injection, service registry, frontend-backend separation
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ============================================================================
// TypeMap — 基于 Any 的类型注册表
//  TypeMap - Any-based type registry
// ============================================================================

/// 类型化服务条目：存储 Arc<dyn Any + Send + Sync>
///  Typed service entry: stores Arc<dyn Any + Send + Sync>
type AnyArc = Arc<dyn Any + Send + Sync>;

/// 服务注册表 — 按类型存储共享服务实例
///  Service registry - stores shared service instances by type
///
/// 用法：调用 `register::<T>(arc)` 注册，调用 `get::<T>()` 获取。
///  Usage: call `register::<T>(arc)` to register, `get::<T>()` to retrieve.
#[derive(Default)]
pub struct ServiceRegistry {
    entries: Mutex<HashMap<std::any::TypeId, AnyArc>>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// 注册一个服务实例。重复注册同一类型会覆盖。
    ///  Register a service instance. Re-registering the same type overwrites.
    pub fn register<T: Any + Send + Sync + 'static>(&self, service: Arc<T>) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.insert(std::any::TypeId::of::<T>(), service as AnyArc);
    }

    /// 获取已注册服务的克隆 Arc。未注册时返回 None。
    ///  Get a cloned Arc of a registered service. Returns None if not registered.
    pub fn get<T: Any + Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .get(&std::any::TypeId::of::<T>())
            .and_then(|arc| arc.clone().downcast::<T>().ok())
    }
}

impl std::fmt::Debug for ServiceRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.entries.lock().map(|e| e.len()).unwrap_or(0);
        f.debug_struct("ServiceRegistry")
            .field("registered_types", &count)
            .finish()
    }
}

// ============================================================================
// ServiceContext — 防护组件运行所需的全部外部依赖
//  ServiceContext - all external dependencies required by protection components
// ============================================================================

// ============================================================================
// UiBridge — UI 进程的窗口与事件投递能力
//  UiBridge - window and event delivery capability of the UI process
// ============================================================================

/// UI 桥接 — 把事件与窗口操作转交给 Tauri 运行时。
///  UI bridge - hands events and window operations over to the Tauri runtime.
///
/// 为什么需要它：`ServiceContext` 原本只把事件写进 `EventBus`，而在 Tauri 主进程里
/// 没有任何订阅者（唯一的订阅者是服务进程的 event_bridge_loop），事件被静默丢弃；
/// `show_interception_window` 也被实现成 no-op，导致进程被挂起却不弹窗。
/// 装上本桥接后，UI 进程的 ServiceContext 具备与 AppHandle 等价的投递能力。
///  Why it exists: `ServiceContext` used to write events only into the `EventBus`, which
/// has no subscriber inside the Tauri main process (the only subscriber is the service
/// process event_bridge_loop), so events were silently dropped; `show_interception_window`
/// was a no-op, so processes were suspended without ever showing a modal.
///
/// 必须保持**对象安全**（不能有泛型方法），因此 payload 统一用 `serde_json::Value`。
///  Must stay object-safe (no generic methods), hence `serde_json::Value` payloads.
///
/// 调用方：ServiceContext 的 emit / emit_to / show_interception_window
/// Called by: ServiceContext emit / emit_to / show_interception_window
///
/// 中文关键词：UI 桥接，事件投递，拦截窗口，对象安全
/// English keywords: UI bridge, event delivery, interception window, object safety
pub trait UiBridge: Send + Sync {
    /// 广播事件到前端 / Broadcast an event to the frontend
    fn emit_json(&self, event: &str, payload: serde_json::Value) -> Result<(), String>;

    /// 定向发射事件到指定窗口 / Emit an event to a specific window
    fn emit_to_json(
        &self,
        label: &str,
        event: &str,
        payload: serde_json::Value,
    ) -> Result<(), String>;

    /// 显示拦截窗口 / Show the interception window
    fn show_interception_window(&self) -> Result<(), String>;

    /// 隐藏拦截窗口 / Hide the interception window
    fn hide_interception_window(&self);
}

/// 服务上下文 — 封装防护组件运行所需的依赖
///  Service context - encapsulates dependencies for protection components
///
/// 包含：
///  Contains:
/// - `registry`: 服务注册表（替代 AppHandle::try_state）
/// - `lifecycle`: 应用生命周期信号（替代 app_is_exiting）
/// - `event_bus`: 事件总线（替代 app_handle.emit）
/// - `ui`: 可选 UI 桥接。UI 进程有；服务进程为 None（无 GUI）
///
/// 设计原则：
///  Design principles:
/// - 防护组件只依赖 ServiceContext，不直接依赖 tauri::AppHandle
/// - ServiceContext 可以在 Tauri 主进程和服务进程中以相同方式构造
/// - 服务进程里事件经 event_bus → IPC 转发；UI 进程里经 ui 桥接直达 Tauri
#[derive(Clone)]
pub struct ServiceContext {
    registry: Arc<ServiceRegistry>,
    lifecycle: Arc<crate::services::app_lifecycle_service::AppLifecycleService>,
    event_bus: Arc<crate::services::event_bus::EventBus>,
    ui: Option<Arc<dyn UiBridge>>,
}

impl ServiceContext {
    /// 创建新的服务上下文（无 UI 桥接，用于服务进程与测试）
    ///  Create a new service context (no UI bridge; for the service process and tests)
    pub fn new(
        registry: Arc<ServiceRegistry>,
        lifecycle: Arc<crate::services::app_lifecycle_service::AppLifecycleService>,
        event_bus: Arc<crate::services::event_bus::EventBus>,
    ) -> Self {
        Self {
            registry,
            lifecycle,
            event_bus,
            ui: None,
        }
    }

    /// 装上 UI 桥接，返回带桥接的上下文。
    ///  Attaches a UI bridge and returns the context carrying it.
    ///
    /// 只应在 Tauri UI 进程中调用；服务进程没有 GUI，保持 None。
    ///  Only call this inside the Tauri UI process; the service process has no GUI.
    pub fn with_ui_bridge(mut self, ui: Arc<dyn UiBridge>) -> Self {
        self.ui = Some(ui);
        self
    }

    /// 是否具备 UI 投递能力（用于诊断与测试）
    ///  Whether UI delivery is available (for diagnostics and tests)
    pub fn has_ui_bridge(&self) -> bool {
        self.ui.is_some()
    }

    /// 获取已注册服务（替代 AppHandle::try_state）
    ///  Get registered service (replaces AppHandle::try_state)
    pub fn get<T: Any + Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.registry.get::<T>()
    }

    /// 注册服务（替代 app.manage）
    ///  Register service (replaces app.manage)
    pub fn register<T: Any + Send + Sync + 'static>(&self, service: Arc<T>) {
        self.registry.register::<T>(service);
    }

    /// 检查应用是否正在退出（替代 app_is_exiting）
    ///  Check if app is exiting (replaces app_is_exiting)
    pub fn is_exiting(&self) -> bool {
        self.lifecycle.is_exiting()
    }

    /// 标记应用开始退出
    ///  Mark app as beginning to exit
    #[allow(dead_code)]
    pub fn begin_exit(&self) -> bool {
        self.lifecycle.begin_exit()
    }

    /// 发射事件（替代 app_handle.emit）
    ///  Emit event (replaces app_handle.emit)
    ///
    /// 始终写入事件总线（服务进程靠它经 IPC 转发给 UI 进程）；
    /// 若装了 UI 桥接（UI 进程），再直接投递到 Tauri 前端。
    /// 两条路径互不重复：UI 进程没有总线订阅者，服务进程没有 UI 桥接。
    ///  Always writes to the event bus (the service process forwards from there over IPC);
    /// when a UI bridge is attached (UI process) it also delivers straight to the Tauri
    /// frontend. The two paths never double-deliver: the UI process has no bus subscriber
    /// and the service process has no UI bridge.
    pub fn emit<S: serde::Serialize + Clone + Send + 'static>(
        &self,
        event: &str,
        payload: S,
    ) -> Result<(), String> {
        self.event_bus.emit(event, payload.clone())?;
        if let Some(ui) = &self.ui {
            let value = serde_json::to_value(payload)
                .map_err(|e| format!("Failed to serialize event payload: {}", e))?;
            ui.emit_json(event, value)?;
        }
        Ok(())
    }

    /// 订阅事件总线中的事件（用于前端桥接层）
    ///  Subscribe to events in the event bus (for frontend bridge layer)
    #[allow(dead_code)]
    pub fn subscribe(
        &self,
        event: &str,
    ) -> tokio::sync::broadcast::Receiver<crate::services::event_bus::EventPayload> {
        self.event_bus.subscribe(event)
    }

    /// 获取事件总线引用
    ///  Get event bus reference
    pub fn event_bus(&self) -> &Arc<crate::services::event_bus::EventBus> {
        &self.event_bus
    }

    /// 获取注册表引用
    ///  Get registry reference
    #[allow(dead_code)]
    pub fn registry(&self) -> &Arc<ServiceRegistry> {
        &self.registry
    }

    /// 获取生命周期引用
    ///  Get lifecycle reference
    #[allow(dead_code)]
    pub fn lifecycle(&self) -> &Arc<crate::services::app_lifecycle_service::AppLifecycleService> {
        &self.lifecycle
    }
}

impl std::fmt::Debug for ServiceContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceContext")
            .field("registry", &self.registry)
            .field("is_exiting", &self.is_exiting())
            .field("has_ui_bridge", &self.ui.is_some())
            .finish()
    }
}

// ============================================================================
// TauriUiBridge — 用 Tauri AppHandle 实现 UiBridge
//  TauriUiBridge - UiBridge backed by a Tauri AppHandle
// ============================================================================

/// Tauri 运行时的 UI 桥接实现。
///  UiBridge implementation backed by the Tauri runtime.
///
/// 调用方：build_etw_service_context（UI 进程构造 ServiceContext 时装上）
/// Called by: build_etw_service_context (attached when the UI process builds a ServiceContext)
///
/// 中文关键词：Tauri 桥接，事件发射，拦截窗口
/// English keywords: Tauri bridge, event emit, interception window
pub struct TauriUiBridge<R: tauri::Runtime> {
    app: tauri::AppHandle<R>,
}

impl<R: tauri::Runtime> TauriUiBridge<R> {
    pub fn new(app: tauri::AppHandle<R>) -> Self {
        Self { app }
    }
}

impl<R: tauri::Runtime> UiBridge for TauriUiBridge<R> {
    fn emit_json(&self, event: &str, payload: serde_json::Value) -> Result<(), String> {
        use tauri::Emitter;
        Emitter::emit(&self.app, event, payload).map_err(|e| e.to_string())
    }

    fn emit_to_json(
        &self,
        label: &str,
        event: &str,
        payload: serde_json::Value,
    ) -> Result<(), String> {
        use tauri::Emitter;
        Emitter::emit_to(&self.app, label, event, payload).map_err(|e| e.to_string())
    }

    fn show_interception_window(&self) -> Result<(), String> {
        crate::services::interception_window_service::show_interception_window(&self.app)
            .map(|_| ())
    }

    fn hide_interception_window(&self) {
        crate::services::interception_window_service::hide_interception_window(&self.app);
    }
}

// ============================================================================
// AppContext — 统一 AppHandle 和 ServiceContext 的能力抽象
//  AppContext - unified capability abstraction for AppHandle and ServiceContext
// ============================================================================

/// 应用上下文抽象 — 封装防护组件所需的运行时能力。
///  Application context abstraction - encapsulates runtime capabilities needed by protection components.
///
/// `tauri::AppHandle` 和 `ServiceContext` 都实现此 trait，
/// 使得 `try_show_next`、`analyze_event` 等函数可以同时接受两种上下文。
///  Both `tauri::AppHandle` and `ServiceContext` implement this trait,
/// allowing functions like `try_show_next`, `analyze_event` to accept either context.
pub trait AppContext: Send + Sync {
    /// 检查应用是否正在退出（替代 app_is_exiting）
    ///  Check if app is exiting (replaces app_is_exiting)
    fn is_exiting(&self) -> bool;

    /// 发射事件到所有订阅者（替代 app_handle.emit）
    ///  Emit event to all subscribers (replaces app_handle.emit)
    fn emit_event<S: serde::Serialize + Clone + Send + 'static>(
        &self,
        event: &str,
        payload: S,
    ) -> Result<(), String>;

    /// 发射事件到指定窗口（替代 app_handle.emit_to）。
    /// ServiceContext 实现回退到广播。
    ///  Emit event to a specific window (replaces app_handle.emit_to).
    /// ServiceContext implementation falls back to broadcast.
    fn emit_to<S: serde::Serialize + Clone + Send + 'static>(
        &self,
        label: &str,
        event: &str,
        payload: S,
    ) -> Result<(), String>;

    /// 尝试弹出拦截窗口（替代 show_interception_window）。
    /// ServiceContext 实现为 no-op（服务模式下无 GUI）。
    ///  Try to show interception window (replaces show_interception_window).
    /// ServiceContext implementation is a no-op (no GUI in service mode).
    fn show_interception_window(&self) -> Result<(), String>;

    /// 隐藏拦截窗口（替代 hide_interception_window）。
    /// ServiceContext 实现为 no-op（服务模式下无 GUI）。
    ///  Hide interception window (replaces hide_interception_window).
    /// ServiceContext implementation is a no-op (no GUI in service mode).
    fn hide_interception_window(&self);
}

// 为 &T 实现 AppContext，使得 &AppHandle 和 &ServiceContext 都能直接使用
//  Implement AppContext for &T so that &AppHandle and &ServiceContext can be used directly
impl<T: AppContext + ?Sized> AppContext for &T {
    fn is_exiting(&self) -> bool {
        (**self).is_exiting()
    }

    fn emit_event<S: serde::Serialize + Clone + Send + 'static>(
        &self,
        event: &str,
        payload: S,
    ) -> Result<(), String> {
        (**self).emit_event(event, payload)
    }

    fn emit_to<S: serde::Serialize + Clone + Send + 'static>(
        &self,
        label: &str,
        event: &str,
        payload: S,
    ) -> Result<(), String> {
        (**self).emit_to(label, event, payload)
    }

    fn show_interception_window(&self) -> Result<(), String> {
        (**self).show_interception_window()
    }

    fn hide_interception_window(&self) {
        (**self).hide_interception_window()
    }
}

impl AppContext for ServiceContext {
    fn is_exiting(&self) -> bool {
        self.is_exiting()
    }

    fn emit_event<S: serde::Serialize + Clone + Send + 'static>(
        &self,
        event: &str,
        payload: S,
    ) -> Result<(), String> {
        self.emit(event, payload)
    }

    fn emit_to<S: serde::Serialize + Clone + Send + 'static>(
        &self,
        label: &str,
        event: &str,
        payload: S,
    ) -> Result<(), String> {
        // UI 进程：保留 label，定向投递到目标窗口（拦截窗口靠它收事件）
        //  UI process: preserve the label and deliver to the target window
        if let Some(ui) = &self.ui {
            let value = serde_json::to_value(payload)
                .map_err(|e| format!("Failed to serialize event payload: {}", e))?;
            // 同时写总线，保持与 emit 一致的可观测性 / mirror to the bus for observability
            self.event_bus.emit(event, value.clone())?;
            return ui.emit_to_json(label, event, value);
        }
        // 服务进程无窗口，回退到广播，由 IPC 桥接在 UI 侧还原定向
        //  No windows in the service process; broadcast and let the IPC bridge re-target
        self.emit(event, payload)
    }

    fn show_interception_window(&self) -> Result<(), String> {
        // UI 进程：真正建/显示拦截窗口
        //  UI process: actually show the window
        if let Some(ui) = &self.ui {
            return ui.show_interception_window();
        }

        // 服务进程无 GUI，弹窗由 IPC 推给 UI 进程。但必须确认真的有 UI 可推：
        // 一个已被挂起、却没有任何界面能询问用户的进程，就是永久冻结。
        // 这里返回 Err 会让 InterceptionService 走与建窗失败一致的回滚路径
        //（恢复进程 + 保留告警与诊断记录）。
        //  The service process has no GUI and pushes the prompt to the UI over IPC, but there
        //  must actually be a UI to push to: a suspended process with no interface to ask the
        //  user is a permanent freeze. Returning Err routes InterceptionService through the same
        //  rollback as a window-creation failure (resume the process, keep the alert).
        if let Some(server) = self.get::<crate::services::ipc_server::IpcServer>() {
            if server.client_count() == 0 {
                return Err(
                    "no UI client is connected to answer the interception prompt".to_string(),
                );
            }
        }
        Ok(())
    }

    fn hide_interception_window(&self) {
        if let Some(ui) = &self.ui {
            ui.hide_interception_window();
        }
    }
}

// ============================================================================
// 桥接函数 — 从 Tauri AppHandle 构造 ServiceContext
//  Bridge function - builds ServiceContext from Tauri AppHandle
// ============================================================================

/// 函数名称：build_etw_service_context
/// 函数作用：从 Tauri AppHandle 构造 ServiceContext，作为 ETW 服务从 Tauri 运行时向独立服务进程迁移的过渡桥接。
/// Purpose: Builds a ServiceContext from a Tauri AppHandle, serving as a transitional bridge for ETW service migration.
/// 调用方：main.rs start_etw_monitoring、commands::behavior::resume_etw、commands::config::set_behavior_monitoring_enabled
/// Called by: main.rs start_etw_monitoring, commands::behavior::resume_etw, commands::config::set_behavior_monitoring_enabled
/// 中文关键词：服务上下文，桥接，ETW，依赖注入
/// English keywords: service context, bridge, ETW, dependency injection
pub fn build_etw_service_context(app_handle: &tauri::AppHandle) -> ServiceContext {
    use crate::services::app_lifecycle_service::AppLifecycleService;
    use crate::services::behavior_service::BehaviorService;
    use crate::services::event_bus::EventBus;
    use crate::services::interception_service::InterceptionService;
    use crate::services::process_scanner_service::ProcessScannerService;
    use crate::services::risk_service::RiskService;
    use crate::services::trust_service::TrustService;
    use tauri::Manager;

    let registry = Arc::new(ServiceRegistry::new());
    let lifecycle = Arc::new(AppLifecycleService::new());
    let event_bus = Arc::new(EventBus::new(256));
    // 本函数只在 Tauri UI 进程中被调用（服务进程走 build_service_context），
    // 因此无条件装上 UI 桥接：事件直达前端，拦截窗口可真正弹出。
    // This function is only ever called inside the Tauri UI process (the service process
    // uses build_service_context), so the UI bridge is always attached: events reach the
    // frontend directly and the interception window can actually be shown.
    let ctx = ServiceContext::new(registry, lifecycle, event_bus)
        .with_ui_bridge(Arc::new(TauriUiBridge::new(app_handle.clone())));

    // 注册已 Arc 包装的共享服务 / Register Arc-wrapped shared services
    if let Some(trust) = app_handle.try_state::<Arc<TrustService>>() {
        ctx.register::<TrustService>(trust.inner().clone());
    }
    if let Some(interception) = app_handle.try_state::<Arc<InterceptionService>>() {
        ctx.register::<InterceptionService>(interception.inner().clone());
    }
    if let Some(behavior) = app_handle.try_state::<Arc<Mutex<BehaviorService>>>() {
        ctx.register::<Mutex<BehaviorService>>(behavior.inner().clone());
    }

    // RiskService 和 ProcessScannerService 在 Tauri state 中以直接值管理（非 Arc），
    // 桥接时创建新实例；dedup 状态不共享，但 InterceptionService 有自己的 PID 去重。
    // RiskService and ProcessScannerService are managed as direct values (not Arc) in Tauri state;
    // new instances are created for the bridge. Dedup state is not shared, but InterceptionService has its own PID dedup.
    let risk_service = RiskService::new();
    if let Some(interception) = app_handle.try_state::<Arc<InterceptionService>>() {
        risk_service.set_interception_service(interception.inner().clone());
    }
    ctx.register::<RiskService>(Arc::new(risk_service));

    ctx.register::<ProcessScannerService>(Arc::new(ProcessScannerService::new()));

    ctx
}

// ============================================================================
// 服务进程模式 — 从零构造 ServiceContext（不依赖 Tauri AppHandle）
//  Service process mode - builds ServiceContext from scratch (no Tauri AppHandle)
// ============================================================================

/// 函数名称：build_service_context
/// 函数作用：在独立服务进程中从零构造 ServiceContext，创建所有防护组件实例并注册到注册表。
/// Purpose: Builds ServiceContext from scratch in a standalone service process, creating all protection component instances and registering them in the registry.
/// 调用方：windows_service::run_service。
/// Called by: windows_service::run_service.
/// 参数说明：engine_dll_path 和 engine_root_path 由调用方解析后传入；pool 由调用方在 Tokio runtime 中创建后传入。
/// Parameters: engine_dll_path and engine_root_path are resolved by the caller; pool is created by the caller inside a Tokio runtime.
/// 返回值说明：返回填充好的 ServiceContext，包含 TrustService、InterceptionService、RiskService、BehaviorService、ProcessScannerService、EngineService、ScanResultCacheService 等服务实例。
/// Returns: A populated ServiceContext containing TrustService, InterceptionService, RiskService, BehaviorService, ProcessScannerService, EngineService, ScanResultCacheService, etc.
/// 错误处理：路径为空时返回错误；引擎构造失败返回错误。
/// Error handling: Returns error on empty paths or engine construction failure.
/// 中文关键词：服务上下文，服务进程，从零构造，独立模式
/// English keywords: service context, service process, build from scratch, standalone mode
pub fn build_service_context(
    engine_dll_path: String,
    engine_root_path: String,
    pool: sqlx::SqlitePool,
) -> Result<ServiceContext, String> {
    use crate::services::app_lifecycle_service::AppLifecycleService;
    use crate::services::behavior_service::BehaviorService;
    use crate::services::engine_service::EngineService;
    use crate::services::event_bus::EventBus;
    use crate::services::file_monitor_service::FileMonitorService;
    use crate::services::hook_service::HookService;
    use crate::services::interception_service::InterceptionService;
    use crate::services::process_scanner_service::ProcessScannerService;
    use crate::services::risk_service::RiskService;
    use crate::services::scan_result_cache_service::ScanResultCacheService;
    use crate::services::snapshot_service::SnapshotService;
    use crate::services::trust_service::TrustService;

    let registry = Arc::new(ServiceRegistry::new());
    let lifecycle = Arc::new(AppLifecycleService::new());
    let event_bus = Arc::new(EventBus::new(256));
    let ctx = ServiceContext::new(registry, lifecycle, event_bus);

    // 创建并注册所有防护组件 / Create and register all protection components

    // 信任验证服务 / Trust verification service
    let trust_service = Arc::new(TrustService::new());
    ctx.register::<TrustService>(trust_service.clone());

    // 拦截服务 / Interception service
    let interception_service = Arc::new(InterceptionService::new());
    ctx.register::<InterceptionService>(interception_service.clone());

    // 网络防火墙服务 / Network firewall service
    // 只注册不启动：驱动句柄要等 windows_service 读到配置确认已启用后再打开。
    // 服务进程是唯一持有 \\.\AnXinNetFilter 句柄的地方，UI 的全部防火墙操作
    // 都经 IPC 落到这个实例上。
    //  Registered but not started: the driver handle is opened only after
    //  windows_service reads the config and confirms the module is enabled. The
    //  service process is the sole holder of the \\.\AnXinNetFilter handle, and
    //  every firewall operation from the UI lands on this instance over IPC.
    let firewall_service = Arc::new(crate::services::firewall_service::FirewallService::new());
    ctx.register::<crate::services::firewall_service::FirewallService>(firewall_service);

    // 启动快照服务（依赖 InterceptionService） / Startup snapshot service (depends on InterceptionService)
    let snapshot_service = Arc::new(SnapshotService::new());
    snapshot_service.set_interception_service(interception_service.clone());
    ctx.register::<SnapshotService>(snapshot_service);

    // 风险分析服务（依赖 InterceptionService） / Risk analysis service (depends on InterceptionService)
    let risk_service = RiskService::new();
    risk_service.set_interception_service(interception_service.clone());
    ctx.register::<RiskService>(Arc::new(risk_service));

    // 行为分析服务（依赖 SQLite pool） / Behavior analysis service (depends on SQLite pool)
    let behavior_service = BehaviorService::new(pool);
    ctx.register::<Mutex<BehaviorService>>(Arc::new(Mutex::new(behavior_service)));

    // 进程扫描器 / Process scanner
    let process_scanner = Arc::new(ProcessScannerService::new());
    ctx.register::<ProcessScannerService>(process_scanner);

    // 进程监控（APIHook watcher）——服务进程可启动，供 SET_PROCESS_MONITORING
    // 与服务启动门控使用。注意 ProcessScannerService 因依赖 AppHandle 在服务模式
    // 不运行，进程监控的服务端能力仅限 APIHook 注入监控。
    //  Process monitor (APIHook watcher) — startable in the service process, used by
    //  SET_PROCESS_MONITORING and the service startup gate. ProcessScannerService does
    //  not run in service mode (it needs an AppHandle), so the service-side process
    //  monitoring capability is limited to APIHook injection watching.
    let process_monitor = Arc::new(crate::services::process_monitor_service::ProcessMonitorService::new());
    ctx.register::<crate::services::process_monitor_service::ProcessMonitorService>(process_monitor);

    // 扫描引擎服务（构造但不立即加载，后台异步加载） / Scan engine service (constructed but loads asynchronously in background)
    let engine_service = Arc::new(EngineService::new(engine_dll_path, engine_root_path)?);
    engine_service.spawn_background_load();
    ctx.register::<EngineService>(engine_service.clone());

    // 扫描结果缓存 / Scan result cache
    let scan_result_cache = Arc::new(ScanResultCacheService::new());
    ctx.register::<ScanResultCacheService>(scan_result_cache.clone());

    // 文件监控服务（占位，启动时调用 start） / File monitor service (placeholder, started via start())
    let file_monitor = Arc::new(FileMonitorService::new());
    ctx.register::<FileMonitorService>(file_monitor.clone());

    // 文件钩子服务（占位，启动时调用 start） / File hook service (placeholder, started via start())
    let hook_service = Arc::new(HookService::new());
    ctx.register::<HookService>(hook_service.clone());

    // ETW 服务（占位，启动时调用 start） / ETW service (placeholder, started via start())
    let etw_service = crate::services::etw_service::EtwService::new();
    ctx.register::<Mutex<crate::services::etw_service::EtwService>>(etw_service);

    Ok(ctx)
}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_register_and_get() {
        let registry = ServiceRegistry::new();
        let service = Arc::new(42i32);
        registry.register::<i32>(service);

        let retrieved = registry.get::<i32>();
        assert!(retrieved.is_some());
        assert_eq!(*retrieved.unwrap(), 42);
    }

    #[test]
    fn registry_get_unregistered_returns_none() {
        let registry = ServiceRegistry::new();
        let retrieved: Option<Arc<String>> = registry.get::<String>();
        assert!(retrieved.is_none());
    }

    #[test]
    fn registry_overwrite_on_duplicate() {
        let registry = ServiceRegistry::new();
        registry.register::<i32>(Arc::new(10));
        registry.register::<i32>(Arc::new(20));

        let retrieved = registry.get::<i32>().unwrap();
        assert_eq!(*retrieved, 20);
    }

    /// 没有 UI 桥接、也没有注册 IpcServer 时（纯单元测试环境）保持放行，
    /// 不能因为拿不到 IpcServer 就把所有拦截判成失败。
    ///  With neither a UI bridge nor a registered IpcServer (plain unit-test setup) the call
    ///  stays permissive: a missing IpcServer must not fail every interception.
    #[test]
    fn show_interception_window_is_ok_without_ipc_server_registered() {
        let ctx = ServiceContext::new(
            Arc::new(ServiceRegistry::new()),
            Arc::new(crate::services::app_lifecycle_service::AppLifecycleService::new()),
            Arc::new(crate::services::event_bus::EventBus::new(16)),
        );
        assert!(!ctx.has_ui_bridge());
        assert!(AppContext::show_interception_window(&ctx).is_ok());
    }

    #[test]
    fn context_delegates_to_components() {
        let registry = Arc::new(ServiceRegistry::new());
        let lifecycle =
            Arc::new(crate::services::app_lifecycle_service::AppLifecycleService::new());
        let event_bus = Arc::new(crate::services::event_bus::EventBus::new(64));
        let ctx = ServiceContext::new(registry, lifecycle, event_bus);

        // 注册服务后能取到
        ctx.register::<String>(Arc::new("hello".to_string()));
        assert_eq!(*ctx.get::<String>().unwrap(), "hello");

        // 生命周期代理
        assert!(!ctx.is_exiting());
        assert!(ctx.begin_exit());
        assert!(ctx.is_exiting());
    }
}
