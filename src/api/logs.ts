/**
 * 日志 API 封装
 * Log API wrapper
 */
import { invoke } from '@tauri-apps/api/core'
import { listen, UnlistenFn } from '@tauri-apps/api/event'

export async function getRecentLogs(): Promise<string[]> {
  return await invoke('get_recent_logs')
}

export async function clearLogs(): Promise<boolean> {
  return await invoke('clear_logs')
}

export async function getLogStatus(): Promise<{ bufferSize: number; maxCapacity: number }> {
  return await invoke('get_log_status')
}

/**
 * 函数名称：onLogEvent
 * 函数作用：监听后端实时日志追加事件。
 * Purpose: Listens for backend real-time log append events.
 * 调用方：OverviewPage 实时事件日志面板。
 * Called by: OverviewPage real-time event log panel.
 */
export function onLogEvent(callback: (line: string) => void): () => void {
  let unlisten: UnlistenFn | null = null
  let disposed = false

  listen<string>('log-event', (event) => {
    callback(event.payload)
  }).then((fn) => {
    if (disposed) {
      fn()
    } else {
      unlisten = fn
    }
  })

  return () => {
    disposed = true
    if (unlisten) {
      unlisten()
    }
  }
}
