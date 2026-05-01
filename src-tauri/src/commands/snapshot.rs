// 进程快照命令 — 启动时进程快照扫描
// Snapshot commands — startup process snapshot scanning
use crate::services::snapshot_service::SnapshotService;
use crate::services::trust_service::TrustService;

/// 函数名称：take_startup_snapshot
/// 函数作用：执行启动时进程快照扫描，枚举所有运行进程并验证签名。
/// Purpose: Executes startup process snapshot scan, enumerates all running processes and verifies signatures.
/// 副作用：未签名进程推入拦截队列；向前端 emit("snapshot-progress") 和 emit("snapshot-result")
/// 调用方：main.rs 启动流程 / 前端手动触发
/// Called by: main.rs startup flow / frontend manual trigger
/// 中文关键词：启动快照，进程扫描，签名验证
/// English keywords: startup snapshot, process scan, signature verification
#[tauri::command]
pub async fn take_startup_snapshot(
    snapshot: tauri::State<'_, SnapshotService>,
    trust: tauri::State<'_, TrustService>,
    app_handle: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    let result = snapshot.take_startup_snapshot(&trust, &app_handle)?;
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
        None => Ok(serde_json::json!({
            "totalProcesses": 0,
            "signedProcesses": 0,
            "unsignedProcesses": 0,
            "pausedProcesses": 0,
            "durationMs": 0,
        })),
    }
}
