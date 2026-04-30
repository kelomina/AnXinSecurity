use tauri::{AppHandle, Manager};
use std::sync::{Arc, Mutex};
use crate::services::etw_service::EtwService;

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
