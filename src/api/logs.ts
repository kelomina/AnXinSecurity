/**
 * 日志 API 封装
 * Log API wrapper
 */
import { invoke } from '@tauri-apps/api/core'

export async function getRecentLogs(): Promise<string[]> {
  return await invoke('get_recent_logs')
}

export async function clearLogs(): Promise<boolean> {
  return await invoke('clear_logs')
}

export async function getLogStatus(): Promise<{ bufferSize: number; maxCapacity: number }> {
  return await invoke('get_log_status')
}
