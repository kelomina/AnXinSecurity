/// 启动扫描引擎（原生 DLL 始终加载，此命令为 no-op）
#[tauri::command]
pub async fn start_engine() -> Result<bool, String> {
    Ok(true)
}

/// 停止扫描引擎（原生 DLL 始终加载，此命令为 no-op）
#[tauri::command]
pub async fn stop_engine() -> Result<bool, String> {
    Ok(true)
}
