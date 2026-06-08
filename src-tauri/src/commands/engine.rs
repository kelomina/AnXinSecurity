use crate::services::engine_service::EngineService;
use std::sync::Arc;

/// 函数名称：start_engine
/// 函数作用：真实启动原生扫描引擎，加载 axon_engine.dll 并创建引擎句柄。
/// Purpose: Actually starts the native scan engine by loading axon_engine.dll and creating the engine handle.
/// 调用方：前端 scanner.startEngine API。
/// Called by: Frontend scanner.startEngine API.
/// 被调用方：EngineService::start_engine。
/// Calls: EngineService::start_engine.
/// 中文关键词：启动引擎，加载DLL，扫描引擎状态
/// English keywords: start engine, load DLL, scan engine state
#[tauri::command]
pub async fn start_engine(engine: tauri::State<'_, Arc<EngineService>>) -> Result<bool, String> {
    engine.start_engine().await
}

/// 函数名称：stop_engine
/// 函数作用：真实停止原生扫描引擎，释放引擎句柄并阻止后续扫描直到再次启动。
/// Purpose: Actually stops the native scan engine, releases its handle, and blocks later scans until restarted.
/// 调用方：前端 scanner.stopEngine API。
/// Called by: Frontend scanner.stopEngine API.
/// 被调用方：EngineService::stop_engine。
/// Calls: EngineService::stop_engine.
/// 中文关键词：停止引擎，释放DLL，扫描引擎状态
/// English keywords: stop engine, release DLL, scan engine state
#[tauri::command]
pub async fn stop_engine(engine: tauri::State<'_, Arc<EngineService>>) -> Result<bool, String> {
    engine.stop_engine().await
}
