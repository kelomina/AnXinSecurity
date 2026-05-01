/**
 * 开发者设置 API 封装
 * Developer settings API wrapper
 */
import { invoke } from '@tauri-apps/api/core'

export async function devSettingsUnlock(password: string): Promise<Record<string, unknown>> {
  return await invoke('dev_settings_unlock', { password })
}

export async function devSettingsSave(password: string, data: unknown): Promise<boolean> {
  return await invoke('dev_settings_save', { password, data })
}
