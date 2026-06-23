use crate::models::config::AppConfig;
use crate::services::engine_service::EngineService;
use crate::services::etw_service::EtwService;
use crate::services::file_monitor_service::FileMonitorService;
use crate::services::hook_service::HookService;
use crate::services::interception_service::InterceptionService;
use crate::services::process_monitor_service::ProcessMonitorService;
use crate::services::process_scanner_service::ProcessScannerService;
use crate::services::scan_result_cache_service::ScanResultCacheService;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager, State};

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
    app_handle: AppHandle,
    state: State<Arc<Mutex<AppConfig>>>,
    enabled: bool,
) -> Result<(), String> {
    let etw_state = app_handle
        .try_state::<Arc<Mutex<EtwService>>>()
        .ok_or("EtwService not managed")?;
    let etw_service = etw_state.lock().map_err(|e| e.to_string())?;
    if enabled {
        etw_service.resume(app_handle.clone())?;
    } else {
        etw_service.pause()?;
    }

    persist_behavior_monitoring_enabled(&state, enabled)?;

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
/// 函数作用：启用或禁用进程监控，先同步启动/停止 APIHook watcher 与新进程扫描器，再持久化到配置文件。
/// Purpose: Enables or disables process monitoring by starting/stopping the APIHook watcher and new-process scanner before persisting the config file.
/// 调用方：前端 SettingsPage 进程监控开关
/// Called by: Frontend SettingsPage process monitoring toggle
/// 被调用方：ProcessMonitorService::start_with_resource_dir，ProcessMonitorService::stop，ProcessScannerService::start，ProcessScannerService::stop，AppConfig::save
/// Calls: ProcessMonitorService::start_with_resource_dir, ProcessMonitorService::stop, ProcessScannerService::start, ProcessScannerService::stop, AppConfig::save
/// 副作用：启动/停止 APIHook 后台线程与新进程扫描任务，修改配置并写入 config/app.json
/// Side effect: Starts/stops the APIHook background watcher and new-process scanner, modifies config and writes to config/app.json
/// 中文关键词：进程监控，APIHook，新进程扫描，启用，禁用，运行态闭环，持久化
/// English keywords: process monitoring, APIHook, new process scanner, enable, disable, runtime loop, persist
#[tauri::command]
pub fn set_process_monitoring_enabled(
    app_handle: AppHandle,
    state: tauri::State<'_, std::sync::Arc<std::sync::Mutex<AppConfig>>>,
    enabled: bool,
) -> Result<(), String> {
    let watcher = app_handle
        .try_state::<ProcessMonitorService>()
        .ok_or("ProcessMonitorService not managed")?;
    let process_scanner = app_handle
        .try_state::<ProcessScannerService>()
        .ok_or("ProcessScannerService not managed")?;
    let hook = app_handle
        .try_state::<Arc<HookService>>()
        .ok_or("HookService not managed")?;
    let file_monitoring_enabled = {
        let config = state.lock().map_err(|e| e.to_string())?;
        config.file_monitoring.enabled
    };

    if enabled {
        let resource_dir = app_handle.path().resource_dir().ok();
        hook.start("anxin_security_filehook", app_handle.clone())?;
        watcher.start_with_resource_dir("", "", "", "", 2000, resource_dir.as_deref())?;
        let engine = app_handle
            .try_state::<Arc<EngineService>>()
            .ok_or("EngineService not managed")?;
        let cache = app_handle
            .try_state::<Arc<ScanResultCacheService>>()
            .ok_or("ScanResultCacheService not managed")?;
        let interception = app_handle
            .try_state::<Arc<InterceptionService>>()
            .ok_or("InterceptionService not managed")?;
        process_scanner.start(
            engine.inner().clone(),
            cache.inner().clone(),
            interception.inner().clone(),
            app_handle.clone(),
            2000,
        );
    } else {
        watcher.stop()?;
        process_scanner.stop();
        if !file_monitoring_enabled {
            hook.stop()?;
        }
    }

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
    app_handle: AppHandle,
    state: tauri::State<'_, std::sync::Arc<std::sync::Mutex<AppConfig>>>,
    enabled: bool,
) -> Result<(), String> {
    let file_monitor = app_handle
        .try_state::<FileMonitorService>()
        .ok_or("FileMonitorService not managed")?;
    let hook = app_handle
        .try_state::<Arc<HookService>>()
        .ok_or("HookService not managed")?;
    let process_monitoring_enabled = {
        let config = state.lock().map_err(|e| e.to_string())?;
        config.process_monitoring.enabled
    };

    if enabled {
        hook.start("anxin_security_filehook", app_handle.clone())?;
        let engine = app_handle
            .try_state::<Arc<EngineService>>()
            .ok_or("EngineService not managed")?;
        let cache = app_handle
            .try_state::<Arc<ScanResultCacheService>>()
            .ok_or("ScanResultCacheService not managed")?;
        let interception = app_handle
            .try_state::<Arc<InterceptionService>>()
            .ok_or("InterceptionService not managed")?;
        let etw_state = app_handle
            .try_state::<Arc<Mutex<EtwService>>>()
            .ok_or("EtwService not managed")?;
        let etw_rx = {
            let etw = etw_state.lock().map_err(|e| e.to_string())?;
            etw.subscribe()
        };
        file_monitor.start(
            engine.inner().clone(),
            cache.inner().clone(),
            interception.inner().clone(),
            app_handle.clone(),
            etw_rx,
        );
    } else {
        file_monitor.stop();
        if !process_monitoring_enabled {
            hook.stop()?;
        }
    }

    persist_file_monitoring_enabled(&state, enabled)?;

    Ok(())
}

/// 函数名称：persist_behavior_monitoring_enabled
/// 函数作用：只持久化 EDR 行为监控配置，不控制运行态服务。
/// Purpose: Persists only the EDR behavior monitoring setting without controlling runtime services.
/// 调用方：set_behavior_monitoring_enabled。
/// Called by: set_behavior_monitoring_enabled.
/// 中文关键词：行为监控配置，持久化，运行态分离
/// English keywords: behavior monitoring config, persist, runtime separation
fn persist_behavior_monitoring_enabled(
    state: &State<Arc<Mutex<AppConfig>>>,
    enabled: bool,
) -> Result<(), String> {
    let mut config = state.lock().map_err(|e| e.to_string())?;
    config.behavior_monitoring.enabled = enabled;
    config.save().map_err(|e| e.to_string())
}

/// 函数名称：persist_file_monitoring_enabled
/// 函数作用：只持久化文件监控配置，不控制运行态服务。
/// Purpose: Persists only the file monitoring setting without controlling runtime services.
/// 调用方：set_file_monitoring_enabled。
/// Called by: set_file_monitoring_enabled.
/// 中文关键词：文件监控配置，持久化，运行态分离
/// English keywords: file monitoring config, persist, runtime separation
fn persist_file_monitoring_enabled(
    state: &State<Arc<Mutex<AppConfig>>>,
    enabled: bool,
) -> Result<(), String> {
    let mut config = state.lock().map_err(|e| e.to_string())?;
    config.file_monitoring.enabled = enabled;
    config.save().map_err(|e| e.to_string())
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
