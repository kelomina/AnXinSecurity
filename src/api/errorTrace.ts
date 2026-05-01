/**
 * 错误追踪 API 封装
 * Error trace API wrapper
 *
 * 封装前端错误上报和日志查询。
 * Wraps frontend error reporting and log querying.
 */
import { invoke } from '@tauri-apps/api/core'

/**
 * 函数名称：reportError
 * 函数作用：将前端错误上报到主进程日志。
 * Purpose: Reports frontend errors to the main process log.
 * 参数 error: 错误堆栈信息 / Error stack info
 * 参数 source: 错误来源 / Error source
 * 副作用：写入 logs/error_trace.log
 */
export async function reportError(error: string, source?: string): Promise<boolean> {
  return await invoke('report_error', { error, source })
}

/**
 * 函数名称：getErrorLogs
 * 函数作用：获取最近的错误日志。
 * Purpose: Gets recent error logs.
 * Returns: 最近 100 条错误日志
 */
export async function getErrorLogs(): Promise<string[]> {
  return await invoke('get_error_logs')
}
