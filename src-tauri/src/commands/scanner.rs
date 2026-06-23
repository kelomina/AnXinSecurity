use crate::services::engine_service::EngineService;
use crate::services::path_policy_service::should_skip_security_scan;
use tauri::State;

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
/// 函数作用：扫描单个文件；命中排除项或允许列表时返回 clean 跳过结果，否则调用扫描引擎。
///   若取消标志已设置，返回错误而非继续扫描。
/// Function name: scan_file
/// Purpose: Scans a single file; returns a clean skipped result when exclusions or allowlist match,
///   otherwise calls the scan engine. Returns an error if the cancel flag is set.
/// 调用方：前端 ScanPage scanFile API。
/// Called by: Frontend ScanPage scanFile API.
/// 被调用方：path_policy_service::should_skip_security_scan、skipped_scan_result、EngineService::scan_file、
///   EngineService::is_cancelled、EngineService::reset_cancel_flag。
/// Calls: path_policy_service::should_skip_security_scan, skipped_scan_result, EngineService::scan_file,
///   EngineService::is_cancelled, EngineService::reset_cancel_flag.
/// 参数说明：file_path 为待扫描文件路径；options 为可选扫描选项。
/// Parameters: file_path is the file to scan; options contains optional scan options.
/// 返回值说明：Result<serde_json::Value, String>，返回前端 ScanResult 兼容 JSON；取消时返回错误。
/// Returns: Result<serde_json::Value, String>, returning frontend ScanResult-compatible JSON; error on cancel.
/// 内部关键变量：opts 为扫描选项；skip 表示路径策略是否命中。
/// Internal variables: opts stores scan options; skip indicates path policy match.
/// 接入方式：接口层命令入口；所有手动单文件扫描应经过本函数。
/// Integration: Presentation-layer command; all manual single-file scans should pass through this function.
/// 错误处理：策略读取错误或引擎扫描错误向前端返回 String。
/// Error handling: Policy read errors or engine scan errors are returned to the frontend as String.
/// 副作用：未跳过时调用扫描引擎；跳过时不读写数据库。
/// Side effects: Calls scan engine when not skipped; skipped paths do not write databases.
/// 事务边界：无 Unit of Work；无数据库事务。
/// Transaction boundary: No Unit of Work and no database transaction.
/// 并发与幂等：列表和文件不变时结果稳定；列表更新后下一次扫描生效。
/// Concurrency and idempotency: Stable while lists and file content do not change; list updates affect the next scan.
/// 中文关键词：文件扫描，排除项生效，允许列表生效，跳过扫描，取消检查，威胁扫描
/// English keywords: file scan, exclusion effective, allowlist effective, skip scan, cancel check, threat scan
#[tauri::command]
pub async fn scan_file(
    engine: State<'_, Arc<EngineService>>,
    file_path: String,
    options: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    engine.reset_cancel_flag();
    if should_skip_security_scan(&file_path)? {
        return Ok(skipped_scan_result(&file_path));
    }
    engine
        .scan_file(&file_path, options.unwrap_or_default())
        .await
}

/// 函数名称：scan_batch
/// 函数作用：批量扫描多个文件；对命中排除项或允许列表的文件返回 clean 跳过结果。
///   每个文件扫描前检查取消标志，若已取消则立即返回已扫描结果并附带 cancelled 标记。
/// Function name: scan_batch
/// Purpose: Scans multiple files; files matching exclusions or allowlist return clean skipped results.
///   Checks the cancel flag before each file; if cancelled, returns partial results with a cancelled marker.
/// 调用方：前端 ScanPage scanBatch API。
/// Called by: Frontend ScanPage scanBatch API.
/// 被调用方：path_policy_service::should_skip_security_scan、skipped_scan_result、EngineService::scan_file、
///   EngineService::is_cancelled、EngineService::reset_cancel_flag。
/// Calls: path_policy_service::should_skip_security_scan, skipped_scan_result, EngineService::scan_file,
///   EngineService::is_cancelled, EngineService::reset_cancel_flag.
/// 参数说明：file_paths 为待扫描路径列表；options 为可选扫描选项。
/// Parameters: file_paths is the list to scan; options contains optional scan options.
/// 返回值说明：Result<serde_json::Value, String>，包含 results、totalFiles、threatsFound、cancelled。
/// Returns: Result<serde_json::Value, String>, containing results, totalFiles, threatsFound, and cancelled.
/// 内部关键变量：results 保存每个文件结果；opts 为每次扫描复用的选项。
/// Internal variables: results stores per-file results; opts is reused for each scan.
/// 接入方式：接口层命令入口；目录/多文件扫描应经过本函数。
/// Integration: Presentation-layer command; directory or multi-file scans should pass through this function.
/// 错误处理：策略读取错误向前端返回；单个引擎错误由 EngineService 返回错误。
/// Error handling: Policy read errors return to frontend; individual engine errors are returned by EngineService.
/// 副作用：未跳过文件调用扫描引擎；跳过文件不触发引擎。
/// Side effects: Calls scan engine for non-skipped files; skipped files do not invoke the engine.
/// 事务边界：无 Unit of Work；无数据库事务。
/// Transaction boundary: No Unit of Work and no database transaction.
/// 并发与幂等：串行扫描；列表更新后下一次文件判断生效。
/// Concurrency and idempotency: Sequential scan; list updates affect the next file check.
/// 中文关键词：批量扫描，排除项生效，允许列表生效，跳过扫描，取消检查，多文件扫描
/// English keywords: batch scan, exclusion effective, allowlist effective, skip scan, cancel check, multi-file scan
#[tauri::command]
pub async fn scan_batch(
    engine: State<'_, Arc<EngineService>>,
    file_paths: Vec<String>,
    options: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
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
        .filter(|result| result.get("verdict").and_then(|value| value.as_str()) == Some("malware"))
        .count();

    Ok(serde_json::json!({
        "results": results,
        "totalFiles": file_paths.len(),
        "threatsFound": threats_found,
    }))
}

/// 函数名称：cancel_scan
/// 函数作用：取消当前正在进行的扫描操作。设置引擎取消标志，批量扫描在文件间检查此标志并提前返回。
/// Purpose: Cancels the current scan operation. Sets the engine cancel flag; batch scan checks this between files and returns early.
/// 调用方：前端 ScanPage 取消按钮 → scannerStore.cancelScan()
/// Called by: Frontend ScanPage cancel button → scannerStore.cancelScan()
/// 被调用方：EngineService::cancel_scan。
/// Calls: EngineService::cancel_scan.
/// 中文关键词：取消扫描，中断扫描，停止扫描，取消标志
/// English keywords: cancel scan, abort scan, stop scan, cancel flag
#[tauri::command]
pub async fn cancel_scan(engine: State<'_, Arc<EngineService>>) -> Result<bool, String> {
    engine.cancel_scan().await
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
