use tauri::{State, AppHandle, Manager};
use sqlx::{SqlitePool, Row};
use std::sync::{Arc, Mutex};
use crate::services::etw_service::EtwService;

#[tauri::command]
pub async fn list_events(
    pool: State<'_, SqlitePool>,
    query: Option<serde_json::Value>,
) -> Result<Vec<serde_json::Value>, String> {
    let db = pool.inner();
    let query_val = query.unwrap_or_default();

    let pid = query_val.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
    let limit = query_val.get("limit").and_then(|v| v.as_u64()).unwrap_or(100);

    let rows = sqlx::query("SELECT * FROM events WHERE pid = ? ORDER BY timestamp DESC LIMIT ?")
        .bind(pid as i64)
        .bind(limit as i64)
        .fetch_all(db)
        .await
        .map_err(|e| e.to_string())?;

    let result: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "id": row.get::<i64, _>("id"),
                "pid": row.get::<i64, _>("pid"),
                "event_type": row.get::<String, _>("event_type"),
                "timestamp": row.get::<String, _>("timestamp"),
            })
        })
        .collect();

    Ok(result)
}

#[tauri::command]
pub fn pause_etw(app_handle: AppHandle) -> Result<bool, String> {
    let etw_state = app_handle.try_state::<Arc<Mutex<EtwService>>>()
        .ok_or("EtwService not managed")?;
    
    let etw_service = etw_state.lock().map_err(|e| e.to_string())?;
    etw_service.pause()?;
    
    Ok(true)
}

#[tauri::command]
pub fn resume_etw(app_handle: AppHandle) -> Result<bool, String> {
    let app_handle_clone = app_handle.clone();
    let etw_state = app_handle.try_state::<Arc<Mutex<EtwService>>>()
        .ok_or("EtwService not managed")?;
    
    let etw_service = etw_state.lock().map_err(|e| e.to_string())?;
    etw_service.resume(app_handle_clone)?;
    
    Ok(true)
}

#[tauri::command]
pub async fn clear_all_events(pool: State<'_, SqlitePool>) -> Result<bool, String> {
    let db = pool.inner();

    sqlx::query("DELETE FROM events")
        .execute(db)
        .await
        .map_err(|e| e.to_string())?;

    Ok(true)
}
