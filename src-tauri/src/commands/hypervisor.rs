// 元核防护命令 — 前端与 HypervisorService 之间的薄转发层
//  Hypervisor protection commands - a thin forwarding layer between the
//  frontend and HypervisorService
//
// 双进程架构下驱动句柄只存在于服务进程，所以每个命令都遵循同一条路径：
//   IPC 已连接 → 转发给服务进程；否则 → 操作本进程管理的 HypervisorService。
//  In the dual-process architecture the driver handle lives only in the
//  service process, so every command follows the same path: forward over IPC
//  when connected, otherwise act on the HypervisorService managed by this
//  process.
//
// 按 AGENTS.md 的分层要求，这里只做参数校验和透传，不写任何业务逻辑。
//  Per the layering rule in AGENTS.md this file only validates and forwards;
//  no business logic lives here.
//
// 中文关键词：元核防护命令，IPC 转发，参数校验
// English keywords: hypervisor commands, IPC forwarding, parameter validation

use std::sync::Arc;

use crate::services::hypervisor_service::{HypervisorService, HypervisorStatus};
use crate::services::ipc_bridge_service::IpcBridgeService;
use crate::services::ipc_protocol::methods;
use tauri::{AppHandle, Manager, Runtime};

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

/// 取本进程管理的 HypervisorService。
///  Resolves the HypervisorService managed by this process.
fn local_service<R: Runtime>(
    app_handle: &AppHandle<R>,
) -> Result<Arc<HypervisorService>, String> {
    app_handle
        .try_state::<Arc<HypervisorService>>()
        .map(|state| state.inner().clone())
        .ok_or_else(|| "HypervisorService is not available in this process".to_string())
}

/// 把 IPC 返回的 JSON 反序列化成具体类型。
///  Deserializes an IPC JSON result into a concrete type.
fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T, String> {
    serde_json::from_value(value).map_err(|e| format!("failed to decode IPC response: {}", e))
}

// ============================================================================
// 状态与生命周期 / Status and lifecycle
// ============================================================================

/// 函数名称：get_hypervisor_status
/// 函数作用：查询元核防护运行状态，供概览页与设置页展示。
/// Purpose: Queries the hypervisor runtime status for the overview and settings pages.
/// 调用方：前端 src/api/hypervisor.ts::getHypervisorStatus
/// Called by: the frontend src/api/hypervisor.ts::getHypervisorStatus
/// 返回值：HypervisorStatus；驱动缺失时 driverConnected 为 false 而不是报错
/// Returns: HypervisorStatus; a missing driver yields driverConnected=false, not an error
/// 中文关键词：元核防护状态，驱动连接，降级展示
/// English keywords: hypervisor status, driver connection, degraded display
#[tauri::command]
pub fn get_hypervisor_status<R: Runtime>(
    app_handle: AppHandle<R>,
) -> Result<HypervisorStatus, String> {
    if let Some(bridge) = ipc_bridge(&app_handle) {
        let value = bridge
            .request(methods::GET_HYPERVISOR_STATUS, serde_json::json!({}))
            .map_err(|e| format!("failed to query hypervisor status over IPC: {}", e))?;
        return decode(value);
    }

    // 本进程没有 HypervisorService 时返回全 false 的状态而不是错误：
    // 前端只需要知道「没在跑」，弹一个红色错误对用户没有任何帮助。
    //  With no local HypervisorService, return an all-false status rather than an
    //  error: the frontend only needs to know it is not running, and a red error
    //  banner helps the user with nothing.
    match local_service(&app_handle) {
        Ok(service) => Ok(service.status()),
        Err(_) => Ok(HypervisorStatus::default()),
    }
}

/// 函数名称：start_hypervisor
/// 函数作用：环境检查 → 启动驱动服务 → 连接设备 → 查询状态。
/// Purpose: Environment check → start driver service → connect device → query status.
/// 调用方：前端设置页开启元核防护开关
/// Called by: the frontend settings page hypervisor switch
/// 错误处理：驱动未安装返回 Err，由前端提示「驱动未安装」而不是崩溃
/// Error handling: a missing driver returns Err for the frontend to surface as
///                 "driver not installed" rather than crashing
/// 中文关键词：启动元核防护，环境检查，驱动连接
/// English keywords: hypervisor start, environment check, driver connection
#[tauri::command]
pub fn start_hypervisor(app_handle: tauri::AppHandle) -> Result<HypervisorStatus, String> {
    // 服务进程模式下元核防护由服务自己管理，UI 侧无需也无权启动
    //  In service mode the service owns the hypervisor; the UI neither needs
    //  nor is allowed to start it
    if ipc_bridge(&app_handle).is_some() {
        return Ok(HypervisorStatus::default());
    }

    let service = local_service(&app_handle)?;
    service.start()
}

/// 函数名称：stop_hypervisor
/// 函数作用：停止元核防护，断开设备连接并停止驱动服务。
/// Purpose: Stops hypervisor protection, disconnects the device and stops the driver service.
/// 调用方：前端设置页关闭元核防护开关
/// Called by: the frontend settings page hypervisor switch
/// 中文关键词：停止元核防护，恢复默认
/// English keywords: hypervisor stop, revert to default
#[tauri::command]
pub fn stop_hypervisor<R: Runtime>(app_handle: AppHandle<R>) -> Result<bool, String> {
    if ipc_bridge(&app_handle).is_some() {
        return Ok(true);
    }

    local_service(&app_handle)?.stop()?;
    Ok(true)
}

// ============================================================================
// 配置 / Configuration
// ============================================================================

/// 函数名称：set_hypervisor_enabled
/// 函数作用：设置元核防护总开关，持久化到 app.json。不直接启动/停止驱动——
///           前端先调用此命令持久化配置，再调用 start_hypervisor/stop_hypervisor。
/// Purpose: Sets the master switch, persisting to app.json. Does not directly
///          start/stop the driver — the frontend persists config with this
///          command, then calls start_hypervisor/stop_hypervisor.
/// 参数 enabled: 是否启用 / whether to enable
/// 调用方：前端 SettingsPage 的元核防护开关
/// Called by: the hypervisor switch in the frontend SettingsPage
/// 副作用：写 config/app.json
/// Side effects: writes config/app.json
/// 中文关键词：总开关，配置持久化
/// English keywords: master switch, config persistence
#[tauri::command]
pub fn set_hypervisor_enabled<R: Runtime>(
    app_handle: AppHandle<R>,
    enabled: bool,
) -> Result<bool, String> {
    if let Some(bridge) = ipc_bridge(&app_handle) {
        bridge
            .request(
                methods::SET_HYPERVISOR_ENABLED,
                serde_json::json!({ "enabled": enabled }),
            )
            .map_err(|e| format!("failed to set the hypervisor switch over IPC: {}", e))?;
        return Ok(true);
    }

    let mut config = crate::models::config::AppConfig::load()
        .map_err(|e| format!("failed to load app config: {}", e))?;
    config.hypervisor_protection.enabled = enabled;
    config
        .save()
        .map_err(|e| format!("failed to persist app config: {}", e))?;

    Ok(true)
}
