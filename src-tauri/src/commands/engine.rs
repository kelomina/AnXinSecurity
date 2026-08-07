use crate::services::engine_service::EngineService;
use crate::services::ipc_bridge_service::IpcBridgeService;
use crate::services::ipc_protocol::methods as ipc_methods;
use std::sync::Arc;
use tauri::{AppHandle, Manager, State};

/// 函数名称：start_engine
/// 函数作用：启动扫描引擎。优先本地执行；若 UI 进程未持有 EngineService（IPC 已连接服务进程）则转发到服务进程。
/// Purpose: Starts the scan engine. Executes locally when EngineService is held by the UI process;
///   otherwise forwards to the service process via IPC.
/// 调用方：前端 scanner.startEngine API。
/// Called by: Frontend scanner.startEngine API.
/// 被调用方：EngineService::start_engine 或 IpcBridgeService::request(START_ENGINE)。
/// Calls: EngineService::start_engine or IpcBridgeService::request(START_ENGINE).
/// 中文关键词：启动引擎，加载DLL，扫描引擎状态，IPC 转发
/// English keywords: start engine, load DLL, scan engine state, IPC forward
#[tauri::command]
pub async fn start_engine(
    app_handle: AppHandle,
    ipc_bridge: State<'_, Arc<IpcBridgeService>>,
) -> Result<bool, String> {
    if let Some(engine) = app_handle.try_state::<Arc<EngineService>>() {
        // 独立模式：UI 进程持有本地引擎
        //  Standalone mode: UI process holds local engine
        return engine.start_engine().await;
    }
    // 服务模式：转发到服务进程
    //  Service mode: forward to service process
    let response = ipc_bridge
        .request(ipc_methods::START_ENGINE, serde_json::json!({}))
        .map_err(|e| format!("IPC 转发启动引擎失败：{}", e))?;
    response
        .get("ok")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| "服务进程返回的启动引擎响应格式无效".to_string())
}

/// 函数名称：stop_engine
/// 函数作用：停止扫描引擎。优先本地执行；若 UI 进程未持有 EngineService 则转发到服务进程。
/// Purpose: Stops the scan engine. Executes locally when EngineService is held by the UI process;
///   otherwise forwards to the service process via IPC.
/// 调用方：前端 scanner.stopEngine API。
/// Called by: Frontend scanner.stopEngine API.
/// 被调用方：EngineService::stop_engine 或 IpcBridgeService::request(STOP_ENGINE)。
/// Calls: EngineService::stop_engine or IpcBridgeService::request(STOP_ENGINE).
/// 中文关键词：停止引擎，释放DLL，扫描引擎状态，IPC 转发
/// English keywords: stop engine, release DLL, scan engine state, IPC forward
#[tauri::command]
pub async fn stop_engine(
    app_handle: AppHandle,
    ipc_bridge: State<'_, Arc<IpcBridgeService>>,
) -> Result<bool, String> {
    if let Some(engine) = app_handle.try_state::<Arc<EngineService>>() {
        return engine.stop_engine().await;
    }
    let response = ipc_bridge
        .request(ipc_methods::STOP_ENGINE, serde_json::json!({}))
        .map_err(|e| format!("IPC 转发停止引擎失败：{}", e))?;
    response
        .get("ok")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| "服务进程返回的停止引擎响应格式无效".to_string())
}
