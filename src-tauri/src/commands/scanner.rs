use tauri::State;
use crate::services::engine_service::EngineService;

use std::sync::Arc;

/// 函数名称：scanner_health
/// 函数作用：检查扫描引擎健康状态，返回引擎状态 JSON。
/// Purpose: Checks the scan engine health and returns status JSON.
/// 调用方：前端 OverviewPage (30 秒轮询)
/// Called by: Frontend OverviewPage (30s polling)
/// 中文关键词：引擎健康检查，扫描引擎，心跳检测，健康状态
/// English keywords: engine health check, scan engine, heartbeat, health status
#[tauri::command]
pub async fn scanner_health(
    engine: State<'_, Arc<EngineService>>,
) -> Result<serde_json::Value, String> {
    engine.health_check().await
}

/// 函数名称：scan_file
/// 函数作用：扫描单个文件，返回扫描结果 JSON。
/// Purpose: Scans a single file and returns scan result JSON.
/// 调用方：前端 ScanPage scanFile API (单文件扫描)
/// Called by: Frontend ScanPage scanFile API (single file scan)
/// 参数：file_path — 文件路径；options — 扫描选项（可选）
/// 中文关键词：文件扫描，单文件扫描，威胁扫描，安全扫描
/// English keywords: file scan, single file scan, threat scan, security scan
#[tauri::command]
pub async fn scan_file(
    engine: State<'_, Arc<EngineService>>,
    file_path: String,
    options: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let opts = options.unwrap_or_default();
    engine.scan_file(&file_path, opts).await
}

/// 函数名称：scan_batch
/// 函数作用：批量扫描多个文件，返回批量扫描结果 JSON。
/// Purpose: Scans multiple files in batch and returns batch scan result JSON.
/// 调用方：前端 ScanPage scanBatch API (多文件扫描)
/// Called by: Frontend ScanPage scanBatch API (multi-file scan)
/// 参数：file_paths — 文件路径列表；options — 扫描选项（可选）
/// 中文关键词：批量扫描，多文件扫描，批量检测
/// English keywords: batch scan, multi-file scan, batch detection
#[tauri::command]
pub async fn scan_batch(
    engine: State<'_, Arc<EngineService>>,
    file_paths: Vec<String>,
    options: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let opts = options.unwrap_or_default();
    engine.scan_batch(&file_paths, opts).await
}

/// 函数名称：cancel_scan
/// 函数作用：取消当前正在进行的扫描操作。向扫描引擎发送取消请求。
/// Purpose: Cancels the current scan operation. Sends a cancel request to the scan engine.
/// 调用方：前端 ScanPage 取消按钮 → scannerStore.cancelScan()
/// Called by: Frontend ScanPage cancel button → scannerStore.cancelScan()
/// 副作用：向引擎 TCP 连接发送 cancel 命令请求
/// Side effect: Sends cancel command to engine via TCP
/// 中文关键词：取消扫描，中断扫描，停止扫描，取消操作
/// English keywords: cancel scan, abort scan, stop scan, cancel operation
#[tauri::command]
pub async fn cancel_scan(
    engine: State<'_, Arc<EngineService>>,
) -> Result<bool, String> {
    engine.cancel_scan().await
}
