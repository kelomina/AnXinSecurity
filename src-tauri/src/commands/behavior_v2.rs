use tauri::State;
use std::sync::{Arc, Mutex};
use crate::services::behavior_service::BehaviorService;

#[tauri::command]
pub async fn list_behavior_events(
    behavior_state: State<'_, Arc<Mutex<BehaviorService>>>,
    query: Option<serde_json::Value>,
) -> Result<Vec<serde_json::Value>, String> {
    let query_val = query.unwrap_or_default();
    let pid = query_val.get("pid").and_then(|v| v.as_u64());
    let limit = query_val.get("limit").and_then(|v| v.as_u64()).unwrap_or(100);

    // Clone 内部 Arc 避免持有 MutexGuard 跨越 await 边界
    // Clone inner Arc to avoid holding MutexGuard across await boundary
    let service = {
        let guard = behavior_state.lock().map_err(|e| e.to_string())?;
        guard.clone()
    };
    service.list_events(pid, limit).await
}

#[tauri::command]
pub async fn list_behavior_processes(
    behavior_state: State<'_, Arc<Mutex<BehaviorService>>>,
    limit: Option<u64>,
) -> Result<Vec<serde_json::Value>, String> {
    let limit_val = limit.unwrap_or(50);

    let service = {
        let guard = behavior_state.lock().map_err(|e| e.to_string())?;
        guard.clone()
    };
    service.list_processes(limit_val).await
}

#[tauri::command]
pub async fn clear_behavior_events(
    behavior_state: State<'_, Arc<Mutex<BehaviorService>>>,
) -> Result<bool, String> {
    let service = {
        let guard = behavior_state.lock().map_err(|e| e.to_string())?;
        guard.clone()
    };
    service.clear_all().await
}
