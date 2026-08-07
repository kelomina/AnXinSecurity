use crate::services::engine_service::EngineService;
use crate::services::ipc_bridge_service::IpcBridgeService;
use crate::services::ipc_protocol::methods as ipc_methods;
use crate::services::path_policy_service::should_skip_security_scan;
use std::sync::Arc;
use tauri::{AppHandle, Manager, State};

/// 函数名称：scanner_health
/// 函数作用：检查扫描引擎健康状态。优先本地查询；若 UI 进程未持有 EngineService（IPC 已连接服务进程）则转发到服务进程。
/// Purpose: Checks scan engine health. Queries locally when EngineService is held by the UI process;
///   otherwise forwards to the service process via IPC.
/// 调用方：前端 OverviewPage (30 秒轮询)
/// Called by: Frontend OverviewPage (30s polling)
/// 中文关键词：引擎健康检查，扫描引擎，心跳检测，健康状态，IPC 转发
/// English keywords: engine health check, scan engine, heartbeat, health status, IPC forward
#[tauri::command]
pub async fn scanner_health(
    app_handle: AppHandle,
    ipc_bridge: State<'_, Arc<IpcBridgeService>>,
) -> Result<serde_json::Value, String> {
    if let Some(engine) = app_handle.try_state::<Arc<EngineService>>() {
        return engine.health_check().await;
    }
    ipc_bridge
        .request(ipc_methods::SCANNER_HEALTH, serde_json::json!({}))
        .map_err(|e| format!("IPC 转发查询引擎健康失败：{}", e))
}

/// 函数名称：scan_file
/// 函数作用：扫描单个文件。优先本地执行；若 UI 进程未持有 EngineService 则转发到服务进程。
///   服务进程模式下，路径策略检查（排除项/允许列表）也在服务进程执行，避免策略不一致。
/// Function name: scan_file
/// Purpose: Scans a single file. Executes locally when EngineService is held by the UI process;
///   otherwise forwards to the service process where path policy is also applied.
/// 调用方：前端 ScanPage scanFile API。
/// Called by: Frontend ScanPage scanFile API.
/// 参数说明：file_path 为待扫描文件路径；options 为可选扫描选项。
/// Parameters: file_path is the file to scan; options contains optional scan options.
/// 返回值说明：Result<serde_json::Value, String>，返回前端 ScanResult 兼容 JSON；取消时返回错误。
/// Returns: Result<serde_json::Value, String>, returning frontend ScanResult-compatible JSON; error on cancel.
/// 中文关键词：文件扫描，排除项生效，允许列表生效，跳过扫描，取消检查，威胁扫描，IPC 转发
/// English keywords: file scan, exclusion effective, allowlist effective, skip scan, cancel check, threat scan, IPC forward
#[tauri::command]
pub async fn scan_file(
    app_handle: AppHandle,
    ipc_bridge: State<'_, Arc<IpcBridgeService>>,
    file_path: String,
    options: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    if let Some(engine) = app_handle.try_state::<Arc<EngineService>>() {
        // 独立模式：本地路径策略检查 + 本地扫描
        //  Standalone mode: local path policy check + local scan
        engine.reset_cancel_flag();
        if should_skip_security_scan(&file_path)? {
            return Ok(skipped_scan_result(&file_path));
        }
        return engine
            .scan_file(&file_path, options.unwrap_or_default())
            .await;
    }
    // 服务模式：转发到服务进程，路径策略检查也在服务进程执行
    //  Service mode: forward to service process where path policy is also applied
    let params = serde_json::json!({
        "filePath": file_path,
        "options": options.unwrap_or(serde_json::Value::Null),
    });
    ipc_bridge
        .request(ipc_methods::SCAN_FILE, params)
        .map_err(|e| format!("IPC 转发扫描文件失败：{}", e))
}

/// 函数名称：scan_batch
/// 函数作用：批量扫描多个文件。优先本地执行；若 UI 进程未持有 EngineService 则转发到服务进程。
///   服务进程模式下，扫描循环和取消检查都在服务进程执行。
/// Function name: scan_batch
/// Purpose: Scans multiple files. Executes locally when EngineService is held by the UI process;
///   otherwise forwards to the service process where the scan loop and cancel check execute.
/// 调用方：前端 ScanPage scanBatch API。
/// Called by: Frontend ScanPage scanBatch API.
/// 参数说明：file_paths 为待扫描路径列表；options 为可选扫描选项。
/// Parameters: file_paths is the list to scan; options contains optional scan options.
/// 返回值说明：Result<serde_json::Value, String>，包含 results、totalFiles、threatsFound、cancelled。
/// Returns: Result<serde_json::Value, String>, containing results, totalFiles, threatsFound, and cancelled.
/// 中文关键词：批量扫描，排除项生效，允许列表生效，跳过扫描，取消检查，多文件扫描，IPC 转发
/// English keywords: batch scan, exclusion effective, allowlist effective, skip scan, cancel check, multi-file scan, IPC forward
#[tauri::command]
pub async fn scan_batch(
    app_handle: AppHandle,
    ipc_bridge: State<'_, Arc<IpcBridgeService>>,
    file_paths: Vec<String>,
    options: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    if let Some(engine) = app_handle.try_state::<Arc<EngineService>>() {
        // 独立模式：本地批量扫描
        //  Standalone mode: local batch scan
        let opts = options.unwrap_or_default();
        let mut results: Vec<serde_json::Value> = Vec::new();

        engine.reset_cancel_flag();

        for file_path in &file_paths {
            if engine.is_cancelled() {
                return Ok(serde_json::json!({
                    "results": results,
                    "totalFiles": file_paths.len(),
                    "threatsFound": results.iter().filter(|r| r.get("verdict").and_then(|v| v.as_str()) == Some("malware")).count(),
                    "scannedFiles": results.len(),
                    "cancelled": true,
                }));
            }

            if should_skip_security_scan(file_path)? {
                results.push(skipped_scan_result(file_path));
            } else {
                results.push(engine.scan_file(file_path, opts.clone()).await?);
            }
        }

        let threats_found = results
            .iter()
            .filter(|result| {
                result.get("verdict").and_then(|value| value.as_str()) == Some("malware")
            })
            .count();

        return Ok(serde_json::json!({
            "results": results,
            "totalFiles": file_paths.len(),
            "threatsFound": threats_found,
        }));
    }
    // 服务模式：转发到服务进程
    //  Service mode: forward to service process
    let params = serde_json::json!({
        "filePaths": file_paths,
        "options": options.unwrap_or(serde_json::Value::Null),
    });
    ipc_bridge
        .request(ipc_methods::SCAN_BATCH, params)
        .map_err(|e| format!("IPC 转发批量扫描失败：{}", e))
}

/// 函数名称：cancel_scan
/// 函数作用：取消当前正在进行的扫描操作。优先本地执行；若 UI 进程未持有 EngineService 则转发到服务进程。
/// Purpose: Cancels the current scan operation. Executes locally when EngineService is held by the UI process;
///   otherwise forwards to the service process via IPC.
/// 调用方：前端 ScanPage 取消按钮 → scannerStore.cancelScan()
/// Called by: Frontend ScanPage cancel button → scannerStore.cancelScan()
/// 中文关键词：取消扫描，中断扫描，停止扫描，取消标志，IPC 转发
/// English keywords: cancel scan, abort scan, stop scan, cancel flag, IPC forward
#[tauri::command]
pub async fn cancel_scan(
    app_handle: AppHandle,
    ipc_bridge: State<'_, Arc<IpcBridgeService>>,
) -> Result<bool, String> {
    if let Some(engine) = app_handle.try_state::<Arc<EngineService>>() {
        return engine.cancel_scan().await;
    }
    let response = ipc_bridge
        .request(ipc_methods::CANCEL_SCAN, serde_json::json!({}))
        .map_err(|e| format!("IPC 转发取消扫描失败：{}", e))?;
    response
        .get("ok")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| "服务进程返回的取消扫描响应格式无效".to_string())
}

fn skipped_scan_result(file_path: &str) -> serde_json::Value {
    serde_json::json!({
        "fileId": file_path,
        "verdict": "clean",
        "threatType": "",
        "severity": 0,
        "description": "Skipped by exclusions or allowlist",
    })
}
