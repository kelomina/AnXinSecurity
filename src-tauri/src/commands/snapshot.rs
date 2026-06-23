// 进程快照命令 — 启动时进程快照扫描
// Snapshot commands — startup process snapshot scanning
use crate::models::config::AppConfig;
use crate::services::engine_service::EngineService;
use crate::services::scan_result_cache_service::ScanResultCacheService;
use crate::services::snapshot_service::{
    SnapshotPerformanceStats, SnapshotResult, SnapshotScanOptions, SnapshotService,
};
use crate::services::trust_service::TrustService;
use std::sync::{Arc, Mutex};

/// 函数名称：take_startup_snapshot
/// 函数作用：执行启动时进程快照扫描，枚举所有运行进程，检查主映像完整性并验证签名。
/// Purpose: Executes startup process snapshot scan, enumerates all running processes, checks main-image integrity, and verifies signatures.
/// 副作用：未签名或疑似镂空进程推入拦截队列；向前端 emit("snapshot-progress") 和 emit("snapshot-result")
/// 调用方：main.rs 启动流程 / 前端手动触发
/// Called by: main.rs startup flow / frontend manual trigger
/// 中文关键词：启动快照，进程扫描，签名验证，进程镂空，映像完整性
/// English keywords: startup snapshot, process scan, signature verification, process hollowing, image integrity
#[tauri::command]
pub async fn take_startup_snapshot(
    snapshot: tauri::State<'_, SnapshotService>,
    trust: tauri::State<'_, Arc<TrustService>>,
    engine: tauri::State<'_, Arc<EngineService>>,
    cache: tauri::State<'_, Arc<ScanResultCacheService>>,
    config: tauri::State<'_, Arc<Mutex<AppConfig>>>,
    app_handle: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    let scan_options = {
        let config = config.lock().map_err(|e| e.to_string())?;
        SnapshotScanOptions {
            slow_warn_ms: config.scanner.startup_snapshot_slow_warn_ms,
            target_scan_timeout_ms: config.scanner.timeout_ms,
            module_enumeration_timeout_ms: config.scanner.startup_module_enumeration_timeout_ms,
            signature_verify_timeout_ms: config.scanner.startup_signature_verify_timeout_ms,
            signature_verify_concurrency: config.scanner.startup_signature_verify_concurrency,
            revocation_check_timeout_ms: config.scanner.startup_revocation_check_timeout_ms,
            revocation_check_concurrency: config.scanner.startup_revocation_check_concurrency,
        }
    };
    let result = snapshot
        .take_startup_snapshot(
            trust.inner().clone(),
            engine.inner().clone(),
            cache.inner().clone(),
            &app_handle,
            scan_options,
        )
        .await?;
    Ok(serde_json::to_value(&result).unwrap_or_default())
}

/// 函数名称：get_snapshot_result
/// 函数作用：获取最后一次快照扫描结果。
/// Purpose: Gets the last snapshot scan result.
/// 调用方：前端概览页
/// Called by: Frontend overview page
/// 中文关键词：快照结果，扫描结果
/// English keywords: snapshot result, scan result
#[tauri::command]
pub async fn get_snapshot_result(
    snapshot: tauri::State<'_, SnapshotService>,
) -> Result<serde_json::Value, String> {
    match snapshot.get_last_result() {
        Some(r) => Ok(serde_json::to_value(&r).unwrap_or_default()),
        None => Ok(serde_json::to_value(empty_snapshot_result()).unwrap_or_default()),
    }
}

fn empty_snapshot_result() -> SnapshotResult {
    SnapshotResult {
        baseline_complete: false,
        deep_scan_completed: false,
        deep_scan_pending_modules: 0,
        deep_scan_pending_processes: 0,
        total_processes: 0,
        signed_processes: 0,
        unsigned_processes: 0,
        paused_processes: 0,
        scanned_modules: 0,
        malicious_processes: 0,
        malicious_modules: 0,
        image_integrity_alerts: 0,
        unsigned_module_alerts: 0,
        masquerade_alerts: 0,
        revocation_alerts: 0,
        revocation_unknown_critical: 0,
        unknown_processes: 0,
        unknown_modules: 0,
        module_enumeration_failures: 0,
        module_enumeration_access_denied: 0,
        cache_hits: 0,
        performance: SnapshotPerformanceStats::default(),
        duration_ms: 0,
    }
}
