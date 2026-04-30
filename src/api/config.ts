import { invoke } from '@tauri-apps/api/core'

export interface AppConfig {
  brand: string
  themeColor: string
  defaultPage: string
  minimizeToTray: boolean
  behaviorMonitoring: {
    enabled: boolean
  }
  ui: {
    themeMode: string
    animations: boolean
  }
}

export interface ExitConfirmation {
  keep_service: boolean
  prompt_enabled: boolean
}

export async function getConfig(): Promise<AppConfig> {
  return await invoke('get_config')
}

export async function setBehaviorMonitoringEnabled(enabled: boolean): Promise<void> {
  return await invoke('set_behavior_monitoring_enabled', { enabled })
}

export async function setThemeMode(mode: string): Promise<void> {
  return await invoke('set_theme_mode', { mode })
}

export async function setAnimationsEnabled(enabled: boolean): Promise<void> {
  // 注意：此命令需要在后端实现，目前仅在前端状态管理
  // TODO: 实现后端命令 set_animations_enabled
  console.log('Animation setting changed:', enabled)
}

// 托盘相关 API
export async function requestExitConfirmation(): Promise<ExitConfirmation> {
  return await invoke('request_exit_confirmation')
}

export async function executeExit(keepService: boolean): Promise<void> {
  return await invoke('execute_exit', { keepService })
}

export async function minimizeToTray(): Promise<void> {
  return await invoke('minimize_to_tray')
}
