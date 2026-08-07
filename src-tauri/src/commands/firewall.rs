// 网络防火墙命令 — 前端与 FirewallService 之间的薄转发层
//  Network firewall commands - a thin forwarding layer between the frontend and
//  FirewallService
//
// 双进程架构下驱动句柄只存在于服务进程（打开 \\.\AnXinNetFilter 需要 SYSTEM
// 或管理员权限），所以每个命令都遵循同一条路径：
//   IPC 已连接 → 转发给服务进程；否则 → 操作本进程管理的 FirewallService。
//  In the dual-process architecture the driver handle lives only in the service
//  process (opening \\.\AnXinNetFilter needs SYSTEM or Administrators), so every
//  command follows the same path: forward over IPC when connected, otherwise act
//  on the FirewallService managed by this process.
//
// 按 AGENTS.md 的分层要求，这里只做参数校验和透传，不写任何业务逻辑。
//  Per the layering rule in AGENTS.md this file only validates and forwards; no
//  business logic lives here.
//
// 中文关键词：防火墙命令，IPC 转发，参数校验
// English keywords: firewall commands, IPC forwarding, parameter validation

use std::sync::Arc;

use crate::services::firewall_service::{
    FirewallEventRecord, FirewallService, FirewallStatus, PendingConnection, VerdictOutcome,
};
use crate::services::ipc_bridge_service::IpcBridgeService;
use crate::services::ipc_protocol::methods;
use tauri::{AppHandle, Manager, Runtime};

/// 单次拉取网络事件的默认条数 / Default number of network events per fetch
const DEFAULT_EVENT_LIMIT: usize = 200;
/// 单次拉取网络事件的上限，防止 IPC 消息过大
///  Upper bound per fetch so a single IPC message cannot grow unbounded
const MAX_EVENT_LIMIT: usize = 500;

// ============================================================================
// 内部辅助 / Internal helpers
// ============================================================================

/// 判断当前是否应该把请求转发给服务进程。
///  Whether the request should be forwarded to the service process.
fn ipc_bridge<R: Runtime>(app_handle: &AppHandle<R>) -> Option<Arc<IpcBridgeService>> {
    app_handle
        .try_state::<Arc<IpcBridgeService>>()
        .map(|state| state.inner().clone())
        .filter(|bridge| bridge.is_connected())
}

/// 取本进程管理的 FirewallService。
///  Resolves the FirewallService managed by this process.
fn local_service<R: Runtime>(app_handle: &AppHandle<R>) -> Result<Arc<FirewallService>, String> {
    app_handle
        .try_state::<Arc<FirewallService>>()
        .map(|state| state.inner().clone())
        .ok_or_else(|| "FirewallService is not available in this process".to_string())
}

/// 把 IPC 返回的 JSON 反序列化成具体类型。
///  Deserializes an IPC JSON result into a concrete type.
fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T, String> {
    serde_json::from_value(value).map_err(|e| format!("failed to decode IPC response: {}", e))
}

// ============================================================================
// 状态与生命周期 / Status and lifecycle
// ============================================================================

/// 函数名称：get_firewall_status
/// 函数作用：查询防火墙运行状态，供概览页与设置页展示。
/// Purpose: Queries the firewall runtime status for the overview and settings pages.
/// 调用方：前端 src/api/firewall.ts::getFirewallStatus
/// Called by: the frontend src/api/firewall.ts::getFirewallStatus
/// 返回值：FirewallStatus；驱动缺失时 driverConnected 为 false 而不是报错
/// Returns: FirewallStatus; a missing driver yields driverConnected=false, not an error
/// 中文关键词：防火墙状态，驱动连接，降级展示
/// English keywords: firewall status, driver connection, degraded display
#[tauri::command]
pub fn get_firewall_status<R: Runtime>(app_handle: AppHandle<R>) -> Result<FirewallStatus, String> {
    if let Some(bridge) = ipc_bridge(&app_handle) {
        let value = bridge
            .request(methods::GET_FIREWALL_STATUS, serde_json::json!({}))
            .map_err(|e| format!("failed to query firewall status over IPC: {}", e))?;
        return decode(value);
    }

    // 本进程没有 FirewallService 时返回全 false 的状态而不是错误：
    // 前端只需要知道「没在跑」，弹一个红色错误对用户没有任何帮助。
    //  With no local FirewallService, return an all-false status rather than an
    //  error: the frontend only needs to know it is not running, and a red error
    //  banner helps the user with nothing.
    match local_service(&app_handle) {
        Ok(service) => Ok(service.status()),
        Err(_) => Ok(FirewallStatus::default()),
    }
}

/// 函数名称：start_firewall
/// 函数作用：连接驱动、下发配置与规则并启动事件泵。
/// Purpose: Connects to the driver, pushes config and rules, starts the event pump.
/// 调用方：前端设置页开启防火墙、服务进程启动流程
/// Called by: the frontend settings page and the service startup path
/// 错误处理：驱动缺失返回 Err，由前端提示「驱动未安装」而不是崩溃
/// Error handling: a missing driver returns Err for the frontend to surface as
///                 "driver not installed" rather than crashing
/// 中文关键词：启动防火墙，驱动连接
/// English keywords: firewall start, driver connection
// 注意：这里用具体的 tauri::AppHandle 而不是泛型 Runtime，
// 因为 build_etw_service_context 需要 UI 桥接，只在 Tauri 主进程存在。
//  Note: this takes the concrete tauri::AppHandle rather than a generic Runtime
//  because build_etw_service_context needs the UI bridge, which only exists in
//  the Tauri main process.
#[tauri::command]
pub fn start_firewall(app_handle: tauri::AppHandle) -> Result<bool, String> {
    // 服务进程模式下防火墙由服务自己管理，UI 侧无需也无权启动
    //  In service mode the service owns the firewall; the UI neither needs nor
    //  is allowed to start it
    if ipc_bridge(&app_handle).is_some() {
        return Ok(true);
    }

    let service = local_service(&app_handle)?;
    let config = crate::models::config::AppConfig::load()
        .map_err(|e| format!("failed to load app config: {}", e))?;

    let ctx = crate::services::service_context::build_etw_service_context(&app_handle);
    service.start(ctx, &config.network_firewall)?;
    Ok(true)
}

/// 函数名称：stop_firewall
/// 函数作用：停止事件泵并断开驱动，驱动随即恢复全放行。
/// Purpose: Stops the pump and disconnects; the driver reverts to permitting all.
/// 调用方：前端设置页关闭防火墙、应用退出
/// Called by: the frontend settings page and application shutdown
/// 中文关键词：停止防火墙，恢复放行
/// English keywords: firewall stop, revert to permit
#[tauri::command]
pub fn stop_firewall<R: Runtime>(app_handle: AppHandle<R>) -> Result<bool, String> {
    if ipc_bridge(&app_handle).is_some() {
        return Ok(true);
    }

    local_service(&app_handle)?.stop();
    Ok(true)
}

// ============================================================================
// 配置 / Configuration
// ============================================================================

/// 函数名称：set_firewall_enabled
/// 函数作用：设置防火墙总开关，写入 app.json 后立即下发给驱动。
/// Purpose: Sets the master switch, persisting to app.json and pushing to the driver.
/// 参数 enabled: 是否启用 / whether to enable
/// 调用方：前端 SettingsPage 的防火墙开关
/// Called by: the firewall switch in the frontend SettingsPage
/// 副作用：写 config/app.json
/// Side effects: writes config/app.json
/// 中文关键词：总开关，配置持久化
/// English keywords: master switch, config persistence
#[tauri::command]
pub fn set_firewall_enabled<R: Runtime>(
    app_handle: AppHandle<R>,
    enabled: bool,
) -> Result<bool, String> {
    if let Some(bridge) = ipc_bridge(&app_handle) {
        bridge
            .request(
                methods::SET_FIREWALL_ENABLED,
                serde_json::json!({ "enabled": enabled }),
            )
            .map_err(|e| format!("failed to set the firewall switch over IPC: {}", e))?;
        return Ok(true);
    }

    let service = local_service(&app_handle)?;

    let mut config = crate::models::config::AppConfig::load()
        .map_err(|e| format!("failed to load app config: {}", e))?;
    config.network_firewall.enabled = enabled;

    // VUL-040 事务顺序：与 ipc_server SET_FIREWALL_ENABLED 一致——开启必须先被
    // 驱动接受才落盘，否则「配置声称开启、驱动实际没拦」；关闭则如实落盘。
    //  VUL-040 transaction order, mirroring SET_FIREWALL_ENABLED in ipc_server:
    //  enabling must be accepted by the driver before it is persisted, while
    //  disabling is always safe to persist.
    if enabled {
        service.apply_config(&config.network_firewall)?;
    } else if service.is_driver_connected() {
        service.apply_config(&config.network_firewall)?;
    }
    config
        .save()
        .map_err(|e| format!("failed to persist app config: {}", e))?;

    Ok(true)
}

/// 函数名称：set_firewall_mode
/// 函数作用：切换运行模式（silent / prompt / learn）。
/// Purpose: Switches the operating mode (silent / prompt / learn).
/// 参数 mode: 模式名，非法值返回 Err 而不是静默回落
/// Parameters: mode name; an illegal value errors rather than silently falling back
/// 调用方：前端 SettingsPage 的模式选择
/// Called by: the mode selector in the frontend SettingsPage
/// 中文关键词：运行模式，静默，询问，学习
/// English keywords: operating mode, silent, prompt, learn
#[tauri::command]
pub fn set_firewall_mode<R: Runtime>(
    app_handle: AppHandle<R>,
    mode: String,
) -> Result<bool, String> {
    let normalized = mode.trim().to_ascii_lowercase();

    // 在命令层就拒绝非法值。让它一路传到驱动再被静默回落成 silent，
    // 用户会看到界面显示一个模式、实际行为却是另一个。
    //  Reject illegal values here. Letting one reach the driver and be silently
    //  coerced to silent would show the user one mode while behaving as another.
    if !matches!(normalized.as_str(), "silent" | "prompt" | "learn") {
        return Err(format!(
            "unknown firewall mode '{}', expected silent / prompt / learn",
            mode
        ));
    }

    if let Some(bridge) = ipc_bridge(&app_handle) {
        bridge
            .request(
                methods::SET_FIREWALL_MODE,
                serde_json::json!({ "mode": normalized }),
            )
            .map_err(|e| format!("failed to set the firewall mode over IPC: {}", e))?;
        return Ok(true);
    }

    let service = local_service(&app_handle)?;

    let mut config = crate::models::config::AppConfig::load()
        .map_err(|e| format!("failed to load app config: {}", e))?;
    config.network_firewall.mode = normalized;
    config
        .save()
        .map_err(|e| format!("failed to persist app config: {}", e))?;

    service.apply_config(&config.network_firewall)?;
    Ok(true)
}

/// 函数名称：reload_firewall_rules
/// 函数作用：重新读取 config/firewall_rules.json 并整表下发。
/// Purpose: Re-reads config/firewall_rules.json and pushes all three tables.
/// 返回值：编译告警列表（被跳过的规则、被截断的表），空列表表示全部规则生效
/// Returns: compile warnings (skipped rules, truncated tables); empty means all applied
/// 调用方：前端防火墙页的「重新加载规则」按钮
/// Called by: the "reload rules" button on the frontend firewall page
/// 中文关键词：规则重载，编译告警
/// English keywords: rule reload, compile warnings
#[tauri::command]
pub fn reload_firewall_rules<R: Runtime>(app_handle: AppHandle<R>) -> Result<Vec<String>, String> {
    if let Some(bridge) = ipc_bridge(&app_handle) {
        let value = bridge
            .request(methods::RELOAD_FIREWALL_RULES, serde_json::json!({}))
            .map_err(|e| format!("failed to reload firewall rules over IPC: {}", e))?;

        return Ok(value
            .get("warnings")
            .and_then(|w| serde_json::from_value(w.clone()).ok())
            .unwrap_or_default());
    }

    local_service(&app_handle)?.apply_rules()
}

/// 函数名称：flush_firewall_cache
/// 函数作用：清空内核裁决缓存，让所有连接重新走一遍规则与询问。
/// Purpose: Flushes the kernel verdict cache so every connection is re-evaluated.
/// 调用方：前端防火墙页的「清除记住的选择」按钮
/// Called by: the "clear remembered choices" button on the frontend firewall page
/// 中文关键词：清空缓存，重新询问
/// English keywords: flush cache, re-prompt
#[tauri::command]
pub fn flush_firewall_cache<R: Runtime>(app_handle: AppHandle<R>) -> Result<bool, String> {
    if let Some(bridge) = ipc_bridge(&app_handle) {
        bridge
            .request(methods::FLUSH_FIREWALL_CACHE, serde_json::json!({}))
            .map_err(|e| format!("failed to flush the verdict cache over IPC: {}", e))?;
        return Ok(true);
    }

    local_service(&app_handle)?.flush_cache()?;
    Ok(true)
}

// ============================================================================
// 裁决与数据 / Verdicts and data
// ============================================================================

/// 函数名称：handle_network_decision
/// 函数作用：把用户在弹窗上的允许/阻止决策回送给驱动。
/// Purpose: Sends the user's allow/block choice from the prompt back to the driver.
///
/// 参数 decision_id: 驱动分配的决策编号，来自 network-intercepted 事件
/// 参数 action: "allow" 或 "block"
/// 参数 remember: 记住本次「进程 + 目标」组合
/// 参数 remember_process: 记住该进程访问任意目标
/// Parameters: decision_id from the network-intercepted event; action "allow" or
///             "block"; remember caches this process+destination pair;
///             remember_process caches the process for every destination.
///
/// 返回值：alreadyResolved 为真表示驱动已因超时先行处理，用户点晚了 —— 这不是
///        错误，前端应当把弹窗收掉并提示「已按超时策略处理」。
/// Returns: alreadyResolved=true means the driver's timeout got there first. That
///          is not an error; the frontend should dismiss the prompt and say the
///          timeout policy was applied.
///
/// 调用方：前端拦截窗口的允许/阻止按钮
/// Called by: the allow/block buttons in the frontend interception window
/// 中文关键词：网络裁决，记住选择，超时竞态
/// English keywords: network verdict, remember choice, timeout race
#[tauri::command]
pub fn handle_network_decision<R: Runtime>(
    app_handle: AppHandle<R>,
    decision_id: u64,
    action: String,
    remember: Option<bool>,
    remember_process: Option<bool>,
) -> Result<serde_json::Value, String> {
    let normalized = action.trim().to_ascii_lowercase();
    if !matches!(normalized.as_str(), "allow" | "block") {
        return Err(format!(
            "unknown network decision '{}', expected allow / block",
            action
        ));
    }

    let remember = remember.unwrap_or(false);
    let remember_process = remember_process.unwrap_or(false);

    if let Some(bridge) = ipc_bridge(&app_handle) {
        let value = bridge
            .request(
                methods::HANDLE_NETWORK_DECISION,
                serde_json::json!({
                    "decisionId": decision_id,
                    "action": normalized,
                    "remember": remember,
                    "rememberProcess": remember_process,
                }),
            )
            .map_err(|e| format!("failed to submit the network verdict over IPC: {}", e))?;
        return Ok(value);
    }

    let outcome = local_service(&app_handle)?.decide(
        decision_id,
        normalized == "allow",
        remember,
        remember_process,
    )?;

    Ok(serde_json::json!({
        "ok": true,
        "alreadyResolved": outcome == VerdictOutcome::AlreadyResolved,
    }))
}

/// 函数名称：get_network_pending
/// 函数作用：获取当前待用户裁决的连接队列。
/// Purpose: Gets the queue of connections currently awaiting a user verdict.
/// 调用方：前端拦截窗口打开时补齐队列、防火墙页展示
/// Called by: the interception window when it opens, and the firewall page
/// 中文关键词：待决队列，弹窗补齐
/// English keywords: pending queue, prompt backfill
#[tauri::command]
pub fn get_network_pending<R: Runtime>(
    app_handle: AppHandle<R>,
) -> Result<Vec<PendingConnection>, String> {
    if let Some(bridge) = ipc_bridge(&app_handle) {
        let value = bridge
            .request(methods::GET_NETWORK_PENDING, serde_json::json!({}))
            .map_err(|e| format!("failed to read the pending queue over IPC: {}", e))?;
        return decode(value);
    }

    match local_service(&app_handle) {
        Ok(service) => Ok(service.pending_connections()),
        Err(_) => Ok(Vec::new()),
    }
}

/// 函数名称：get_network_events
/// 函数作用：获取最近的网络事件，按时间倒序。
/// Purpose: Gets recent network events, newest first.
/// 参数 limit: 条数上限，缺省 200，硬上限 500
/// Parameters: limit, defaulting to 200 and hard-capped at 500
/// 调用方：前端防火墙页的事件表格
/// Called by: the event table on the frontend firewall page
/// 中文关键词：事件列表，倒序，条数上限
/// English keywords: event list, newest first, result cap
#[tauri::command]
pub fn get_network_events<R: Runtime>(
    app_handle: AppHandle<R>,
    limit: Option<usize>,
) -> Result<Vec<FirewallEventRecord>, String> {
    let limit = limit.unwrap_or(DEFAULT_EVENT_LIMIT).min(MAX_EVENT_LIMIT);

    if let Some(bridge) = ipc_bridge(&app_handle) {
        let value = bridge
            .request(
                methods::GET_NETWORK_EVENTS,
                serde_json::json!({ "limit": limit }),
            )
            .map_err(|e| format!("failed to read network events over IPC: {}", e))?;
        return decode(value);
    }

    match local_service(&app_handle) {
        Ok(service) => Ok(service.recent_events(limit)),
        Err(_) => Ok(Vec::new()),
    }
}

/// 函数名称：get_network_stats
/// 函数作用：获取驱动侧按进程的流量统计与队列健康指标。
/// Purpose: Gets per-process traffic statistics and queue health from the driver.
/// 调用方：前端防火墙页的流量视图
/// Called by: the traffic view on the frontend firewall page
/// 中文关键词：流量统计，进程维度，队列健康
/// English keywords: traffic statistics, per-process, queue health
#[tauri::command]
pub fn get_network_stats<R: Runtime>(
    app_handle: AppHandle<R>,
) -> Result<serde_json::Value, String> {
    if let Some(bridge) = ipc_bridge(&app_handle) {
        return bridge
            .request(methods::GET_NETWORK_STATS, serde_json::json!({}))
            .map_err(|e| format!("failed to read traffic statistics over IPC: {}", e));
    }

    local_service(&app_handle)?.traffic_stats()
}

// ============================================================================
// 驱动安装 / Driver installation
// ============================================================================

/// 函数名称：is_netfilter_installed
/// 函数作用：检查 AnXinNetFilter 驱动服务是否已安装。
/// Purpose: Checks whether the AnXinNetFilter driver service is installed.
///
/// 调用方：前端 FirewallPage 首次进入时检测，决定是否显示安装提示。
/// Called by: the frontend FirewallPage on first entry, to decide whether to
///             show the install prompt.
///
/// 返回值：true = 服务已存在（无需安装）；false = 服务不存在（需安装+重启）。
/// Returns: true = service exists (no install needed); false = missing (install + reboot needed).
///
/// 中文关键词：驱动检测，服务存在，安装提示
/// English keywords: driver detection, service existence, install prompt
#[tauri::command]
pub fn is_netfilter_installed() -> bool {
    crate::services::driver_install_service::is_driver_installed(
        crate::services::driver_install_service::DriverKind::NetworkFilter,
    )
}

/// 函数名称：install_netfilter_driver
/// 函数作用：安装 AnXinNetFilter 驱动（复制 .sys + 创建 SYSTEM_START 服务）。
/// Purpose: Installs the AnXinNetFilter driver (copy .sys + create SYSTEM_START service).
///
/// 安装后驱动不会立即加载——SYSTEM_START 驱动在下次系统重启时由内核加载。
/// 调用方应在收到 Ok 后提示用户重启电脑。
///  The driver does not load immediately after install — a SYSTEM_START driver
///  is loaded by the kernel on the next system reboot. The caller should prompt
///  the user to reboot after receiving Ok.
///
/// 调用方：前端 FirewallPage 安装提示弹窗的「安装」按钮。
/// Called by: the "Install" button in the FirewallPage install prompt.
///
/// 错误处理：驱动文件缺失、服务创建失败、权限不足均返回 Err，由前端展示。
/// Error handling: missing driver file, service creation failure, or insufficient
///                 privileges return Err for the frontend to display.
///
/// 中文关键词：驱动安装，复制文件，创建服务，重启提示
/// English keywords: driver install, copy file, create service, reboot prompt
#[tauri::command]
pub fn install_netfilter_driver() -> Result<bool, String> {
    crate::services::driver_install_service::install_driver(
        crate::services::driver_install_service::DriverKind::NetworkFilter,
        None,
    )
    .map(|_| true)
}
