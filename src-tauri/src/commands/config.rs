use tauri::State;
use std::sync::{Arc, Mutex};
use crate::models::config::AppConfig;

#[tauri::command]
pub fn get_config(state: State<Arc<Mutex<AppConfig>>>) -> Result<AppConfig, String> {
    let config = state.lock().map_err(|e| e.to_string())?;
    Ok(config.clone())
}

#[tauri::command]
pub fn set_behavior_monitoring_enabled(
    state: State<Arc<Mutex<AppConfig>>>,
    enabled: bool,
) -> Result<(), String> {
    let mut config = state.lock().map_err(|e| e.to_string())?;
    config.behavior_monitoring.enabled = enabled;
    config.save().map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn set_theme_mode(
    state: State<Arc<Mutex<AppConfig>>>,
    mode: String,
) -> Result<(), String> {
    let mut config = state.lock().map_err(|e| e.to_string())?;
    config.ui.theme_mode = mode;
    config.save().map_err(|e| e.to_string())?;
    Ok(())
}
