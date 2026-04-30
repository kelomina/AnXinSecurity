use tauri::State;
use crate::services::engine_service::EngineService;

#[tauri::command]
pub async fn scanner_health(
    engine: State<'_, EngineService>,
) -> Result<serde_json::Value, String> {
    engine.health_check().await
}

#[tauri::command]
pub async fn scan_file(
    engine: State<'_, EngineService>,
    file_path: String,
    options: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let opts = options.unwrap_or_default();
    engine.scan_file(&file_path, opts).await
}

#[tauri::command]
pub async fn scan_batch(
    engine: State<'_, EngineService>,
    file_paths: Vec<String>,
    options: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let opts = options.unwrap_or_default();
    engine.scan_batch(&file_paths, opts).await
}
