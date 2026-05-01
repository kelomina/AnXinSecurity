/**
 * 进程控制 API 封装
 * Process control API wrapper
 *
 * 封装进程暂停、恢复、终止、拦截操作。
 * Wraps process suspend, resume, terminate, and interception operations.
 */
import { invoke } from '@tauri-apps/api/core'

/**
 * 函数名称：suspendProcess
 * 函数作用：挂起指定 PID 的进程。
 * Purpose: Suspends the process identified by PID.
 */
export async function suspendProcess(pid: number): Promise<boolean> {
  return await invoke('suspend_process', { pid })
}

/**
 * 函数名称：resumeProcess
 * 函数作用：恢复指定 PID 的进程。
 * Purpose: Resumes the process identified by PID.
 */
export async function resumeProcess(pid: number): Promise<boolean> {
  return await invoke('resume_process', { pid })
}

/**
 * 函数名称：terminateProcess
 * 函数作用：终止指定 PID 的进程。
 * Purpose: Terminates the process identified by PID.
 */
export async function terminateProcess(pid: number): Promise<boolean> {
  return await invoke('terminate_process', { pid })
}

/**
 * 函数名称：handleInterception
 * 函数作用：处理用户拦截决策（放行/阻止）。
 * Purpose: Handles user interception decision (allow/block).
 */
export async function handleInterception(pid: number, action: 'allow' | 'block'): Promise<boolean> {
  return await invoke('handle_interception', { pid, action })
}

/**
 * 函数名称：getInterceptionQueue
 * 函数作用：获取当前拦截队列中的暂停进程 PID。
 * Purpose: Gets paused process PIDs in current interception queue.
 */
export async function getInterceptionQueue(): Promise<number[]> {
  return await invoke('get_interception_queue')
}

/**
 * 函数名称：clearInterceptionQueue
 * 函数作用：清空拦截队列。
 * Purpose: Clears the interception queue.
 */
export async function clearInterceptionQueue(): Promise<boolean> {
  return await invoke('clear_interception_queue')
}
