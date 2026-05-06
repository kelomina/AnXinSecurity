use crate::models::config::AppConfig;
use std::sync::{Arc, Mutex};
use tauri::State;

/// 函数名称：get_config
/// 函数作用：获取当前应用配置，返回完整 AppConfig 对象。
/// Purpose: Returns the current application configuration as an AppConfig object.
/// 调用方：前端 configStore.loadConfig() → OverviewPage / SettingsPage
/// Called by: Frontend configStore.loadConfig() → OverviewPage / SettingsPage
/// 中文关键词：配置，获取配置，应用设置，读取配置
/// English keywords: config, get config, app settings, read config
#[tauri::command]
pub fn get_config(state: State<Arc<Mutex<AppConfig>>>) -> Result<AppConfig, String> {
    let config = state.lock().map_err(|e| e.to_string())?;
    Ok(config.clone())
}

/// 函数名称：set_behavior_monitoring_enabled
/// 函数作用：启用或禁用行为监控，修改配置并持久化保存。
/// Purpose: Enables or disables behavior monitoring, modifies config and persists it.
/// 调用方：前端 SettingsPage 行为监控开关
/// Called by: Frontend SettingsPage behavior monitoring toggle
/// 副作用：修改配置并写入 config/app.json
/// Side effect: Modifies config and writes to config/app.json
/// 中文关键词：行为监控，启用，禁用，设置，持久化
/// English keywords: behavior monitoring, enable, disable, setting, persist
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

/// 函数名称：set_theme_mode
/// 函数作用：设置 UI 主题模式（system/light/dark），修改配置并持久化保存。
/// Purpose: Sets the UI theme mode (system/light/dark), modifies config and persists it.
/// 调用方：前端 SettingsPage 主题选择器
/// Called by: Frontend SettingsPage theme selector
/// 副作用：修改配置并写入 config/app.json
/// Side effect: Modifies config and writes to config/app.json
/// 中文关键词：主题，主题模式，浅色模式，深色模式，跟随系统
/// English keywords: theme, theme mode, light mode, dark mode, system
#[tauri::command]
pub fn set_theme_mode(state: State<Arc<Mutex<AppConfig>>>, mode: String) -> Result<(), String> {
    let mut config = state.lock().map_err(|e| e.to_string())?;
    config.ui.theme_mode = mode;
    config.save().map_err(|e| e.to_string())?;
    Ok(())
}

/// 函数名称：set_process_monitoring_enabled
/// 函数作用：启用或禁用进程监控，持久化到配置文件。
/// Purpose: Enables or disables process monitoring, persisted to config file.
/// 调用方：前端 SettingsPage 进程监控开关
/// Called by: Frontend SettingsPage process monitoring toggle
/// 副作用：修改配置并写入 config/app.json
/// Side effect: Modifies config and writes to config/app.json
/// 中文关键词：进程监控，启用，禁用，设置，持久化
/// English keywords: process monitoring, enable, disable, setting, persist
#[tauri::command]
pub fn set_process_monitoring_enabled(
    state: tauri::State<'_, std::sync::Arc<std::sync::Mutex<AppConfig>>>,
    enabled: bool,
) -> Result<(), String> {
    let mut config = state.lock().map_err(|e| e.to_string())?;
    config.process_monitoring.enabled = enabled;
    config.save().map_err(|e| e.to_string())?;
    Ok(())
}

/// 函数名称：set_file_monitoring_enabled
/// 函数作用：启用或禁用文件监控，持久化到配置文件。
/// Purpose: Enables or disables file monitoring, persisted to config file.
/// 调用方：前端 SettingsPage 文件监控开关
/// Called by: Frontend SettingsPage file monitoring toggle
/// 副作用：修改配置并写入 config/app.json
/// Side effect: Modifies config and writes to config/app.json
/// 中文关键词：文件监控，启用，禁用，设置，持久化
/// English keywords: file monitoring, enable, disable, setting, persist
#[tauri::command]
pub fn set_file_monitoring_enabled(
    state: tauri::State<'_, std::sync::Arc<std::sync::Mutex<AppConfig>>>,
    enabled: bool,
) -> Result<(), String> {
    let mut config = state.lock().map_err(|e| e.to_string())?;
    config.file_monitoring.enabled = enabled;
    config.save().map_err(|e| e.to_string())?;
    Ok(())
}

/// 函数名称：set_animations_enabled
/// 函数作用：启用或禁用 UI 动画效果，修改配置并持久化保存。
/// Purpose: Enables or disables UI animations, modifies config and persists it.
/// 调用方：前端 SettingsPage 动画开关 → themeStore.toggleAnimations()
/// Called by: Frontend SettingsPage animation toggle → themeStore.toggleAnimations()
/// 副作用：修改配置并写入 config/app.json
/// Side effect: Modifies config and writes to config/app.json
/// 中文关键词：动画，动画效果，启用，禁用，UI动画，页面过渡
/// English keywords: animation, animation effect, enable, disable, UI animation, page transition
#[tauri::command]
pub fn set_animations_enabled(
    state: State<Arc<Mutex<AppConfig>>>,
    enabled: bool,
) -> Result<(), String> {
    let mut config = state.lock().map_err(|e| e.to_string())?;
    config.ui.animations = enabled;
    config.save().map_err(|e| e.to_string())?;
    Ok(())
}
