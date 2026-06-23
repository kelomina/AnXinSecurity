/**
 * 应用配置 API 封装
 * Application configuration API wrapper
 *
 * 封装配置获取、设置主题、行为监控开关、动画开关和托盘退出相关调用。
 * Wraps config retrieval, theme setting, behavior monitoring toggle, animation toggle, and tray exit calls.
 */
import { invoke } from '@tauri-apps/api/core'

/** 应用配置（前端子集）/App configuration (frontend subset) */
export interface AppConfig {
  brand: string
  themeColor: string
  defaultPage: string
  minimizeToTray: boolean
  behaviorMonitoring: {
    enabled: boolean
  }
  processMonitoring: {
    enabled: boolean
  }
  fileMonitoring: {
    enabled: boolean
  }
  scanner: {
    timeoutMs: number
    startupSnapshotSlowWarnMs: number
    startupModuleEnumerationTimeoutMs: number
    startupSignatureVerifyTimeoutMs: number
    startupSignatureVerifyConcurrency: number
    startupRevocationCheckTimeoutMs: number
    startupRevocationCheckConcurrency: number
  }
  ui: {
    themeMode: string
    animations: boolean
  }
}

/** 退出确认配置/Exit confirmation configuration */
export interface ExitConfirmation {
  keep_service: boolean
  prompt_enabled: boolean
}

/**
 * 函数名称：getConfig
 * 函数作用：获取完整应用配置。
 * Purpose: Retrieves the full application configuration.
 * 调用方：configStore.loadConfig() → App.tsx useEffect
 * Called by: configStore.loadConfig() → App.tsx useEffect
 * 中文关键词：配置获取，应用设置，读取配置
 * English keywords: config retrieval, app settings, read config
 */
export async function getConfig(): Promise<AppConfig> {
  return await invoke('get_config')
}

/**
 * 函数名称：setBehaviorMonitoringEnabled
 * 函数作用：启用或禁用行为监控，持久化到配置文件。
 * Purpose: Enables or disables behavior monitoring, persisted to config file.
 * 调用方：SettingsPage 行为监控开关 / configStore.setBehaviorMonitoring()
 * Called by: SettingsPage behavior monitoring toggle / configStore.setBehaviorMonitoring()
 * 副作用：写入 config/app.json
 * Side effect: Writes to config/app.json
 * 中文关键词：行为监控，启用监控，禁用监控，监控开关
 * English keywords: behavior monitoring, enable monitoring, disable monitoring, monitoring toggle
 */
export async function setBehaviorMonitoringEnabled(enabled: boolean): Promise<void> {
  return await invoke('set_behavior_monitoring_enabled', { enabled })
}

/**
 * 函数名称：setThemeMode
 * 函数作用：设置 UI 主题模式（system/light/dark），持久化到配置文件。
 * Purpose: Sets UI theme mode (system/light/dark), persisted to config file.
 * 调用方：SettingsPage 主题选择器 / themeStore.setThemeMode()
 * Called by: SettingsPage theme selector / themeStore.setThemeMode()
 * 副作用：写入 config/app.json
 * Side effect: Writes to config/app.json
 * 中文关键词：主题设置，主题切换，浅色深色模式
 * English keywords: theme setting, theme switch, light dark mode
 */
export async function setThemeMode(mode: string): Promise<void> {
  return await invoke('set_theme_mode', { mode })
}

/**
 * 函数名称：setAnimationsEnabled
 * 函数作用：启用或禁用 UI 动画效果，持久化到配置文件。
 * Purpose: Enables or disables UI animations, persisted to config file.
 * 调用方：SettingsPage 动画开关 / themeStore.toggleAnimations()
 * Called by: SettingsPage animation toggle / themeStore.toggleAnimations()
 * 副作用：写入 config/app.json
 * Side effect: Writes to config/app.json
 * 中文关键词：动画设置，动画开关，启用动画，禁用动画，UI动画
 * English keywords: animation setting, animation toggle, enable animation, disable animation, UI animation
 */
export async function setAnimationsEnabled(enabled: boolean): Promise<void> {
  return await invoke('set_animations_enabled', { enabled })
}

/**
 * 函数名称：requestExitConfirmation
 * 函数作用：获取托盘退出确认配置。
 * Purpose: Retrieves tray exit confirmation configuration.
 * 调用方：TrayExitPrompt 组件
 * Called by: TrayExitPrompt component
 * 中文关键词：退出确认，托盘退出，退出配置
 * English keywords: exit confirmation, tray exit, exit config
 */
export async function requestExitConfirmation(): Promise<ExitConfirmation> {
  return await invoke('request_exit_confirmation')
}

/**
 * 函数名称：executeExit
 * 函数作用：执行应用退出操作。
 * Purpose: Executes application exit operation.
 * 调用方：TrayExitPrompt 组件
 * Called by: TrayExitPrompt component
 * 参数：keepService — 是否保留后台扫描引擎服务运行
 * 副作用：停止服务或仅关闭窗口，退出进程
 * 中文关键词：执行退出，退出应用，关闭应用
 * English keywords: execute exit, exit app, close app
 */
export async function executeExit(keepService: boolean): Promise<void> {
  return await invoke('execute_exit', { keepService })
}

/**
 * 函数名称：setProcessMonitoringEnabled
 * 函数作用：启用或禁用进程监控，持久化到配置文件。
 * Purpose: Enables or disables process monitoring, persisted to config file.
 * 调用方：SettingsPage 进程监控开关
 * Called by: SettingsPage process monitoring toggle
 * 副作用：写入 config/app.json
 * Side effect: Writes to config/app.json
 * 中文关键词：进程监控，启用监控，禁用监控
 * English keywords: process monitoring, enable, disable
 */
export async function setProcessMonitoringEnabled(enabled: boolean): Promise<void> {
  return await invoke('set_process_monitoring_enabled', { enabled })
}

/**
 * 函数名称：setFileMonitoringEnabled
 * 函数作用：启用或禁用文件监控，持久化到配置文件。
 * Purpose: Enables or disables file monitoring, persisted to config file.
 * 调用方：SettingsPage 文件监控开关
 * Called by: SettingsPage file monitoring toggle
 * 副作用：写入 config/app.json
 * Side effect: Writes to config/app.json
 * 中文关键词：文件监控，启用监控，禁用监控
 * English keywords: file monitoring, enable, disable
 */
export async function setFileMonitoringEnabled(enabled: boolean): Promise<void> {
  return await invoke('set_file_monitoring_enabled', { enabled })
}

/**
 * 函数名称：minimizeToTray
 * 函数作用：将窗口最小化到系统托盘。
 * Purpose: Minimizes the window to system tray.
 * 调用方：TitleBar 关闭按钮 / 托盘菜单
 * Called by: TitleBar close button / tray menu
 * 中文关键词：最小化，托盘，隐藏窗口
 * English keywords: minimize, tray, hide window
 */
export async function minimizeToTray(): Promise<void> {
  return await invoke('minimize_to_tray')
}
