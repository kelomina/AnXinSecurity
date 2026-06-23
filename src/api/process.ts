/**
 * 进程控制 API 封装
 * Process control API wrapper
 *
 * 封装进程暂停、恢复、终止、拦截和进程监控服务操作。
 * Wraps process suspend, resume, terminate, interception, and process watcher operations.
 */
import { invoke } from '@tauri-apps/api/core'
import { resolveResource } from '@tauri-apps/api/path'

/** 启动进程监控需要的原生文件路径/Native paths required to start process watcher */
export interface ProcessWatcherStartOptions {
  injectorX64: string
  injectorX86: string
  dllX64: string
  dllX86: string
  intervalMs: number
}

const DEFAULT_PROCESS_WATCHER_INTERVAL_MS = 2000

/**
 * 函数名称：defaultProcessWatcherStartOptions
 * 函数作用：生成空路径默认启动参数，让后端沿已有默认候选路径解析进程监控注入器和 DLL。
 * Purpose: Builds default start options with empty paths so the backend resolves watcher injector and DLL paths through its existing candidate paths.
 * 调用方：configStore.setProcessMonitoring。
 * Called by: configStore.setProcessMonitoring.
 * 返回值说明：返回 start_process_watcher 所需的强类型参数对象，四个路径为空字符串。
 * Returns: strongly typed options required by start_process_watcher with four empty paths.
 * 中文关键词：进程监控，默认参数，后端路径解析，运行态控制
 * English keywords: process watcher, default options, backend path resolution, runtime control
 */
export function defaultProcessWatcherStartOptions(): ProcessWatcherStartOptions {
  return {
    injectorX64: '',
    injectorX86: '',
    dllX64: '',
    dllX86: '',
    intervalMs: DEFAULT_PROCESS_WATCHER_INTERVAL_MS
  }
}

/**
 * 函数名称：createProcessWatcherStartOptions
 * 函数作用：创建显式路径启动参数；用于后续需要由前端指定原生文件位置的场景。
 * Purpose: Creates explicit path start options for future scenarios where the frontend must specify native file locations.
 * 调用方：当前未发现明确调用方。
 * Called by: No confirmed caller at present.
 * 参数说明：nativePaths 为四个原生文件路径；intervalMs 可覆盖默认轮询间隔。
 * Parameters: nativePaths contains four native file paths; intervalMs can override the default polling interval.
 * 返回值说明：返回 start_process_watcher 所需的强类型参数对象。
 * Returns: strongly typed options required by start_process_watcher.
 * 中文关键词：进程监控，显式路径，强类型参数
 * English keywords: process watcher, explicit path, strongly typed options
 */
export function createProcessWatcherStartOptions(
  nativePaths: Omit<ProcessWatcherStartOptions, 'intervalMs'>,
  intervalMs = DEFAULT_PROCESS_WATCHER_INTERVAL_MS
): ProcessWatcherStartOptions {
  return { ...nativePaths, intervalMs }
}

/**
 * 函数名称：resolveDefaultProcessWatcherStartOptions
 * 函数作用：从 Tauri 资源目录解析进程监控注入器和 file_hook DLL 的路径。
 * Purpose: Resolves process watcher injector and file_hook DLL paths from the Tauri resource directory.
 * 调用方：当前未发现明确调用方；保留给需要前端显式传路径的场景。
 * Called by: No confirmed caller at present; kept for scenarios requiring frontend-explicit paths.
 * 被调用方：@tauri-apps/api/path.resolveResource。
 * Calls: @tauri-apps/api/path.resolveResource.
 * 返回值说明：返回 start_process_watcher 所需的强类型参数对象。
 * Returns: strongly typed options required by start_process_watcher.
 * 错误处理：资源路径解析失败时向上抛出，由设置开关回滚 UI 状态。
 * Error handling: resource resolution failures are thrown so the settings toggle can roll back UI state.
 * 中文关键词：进程监控，原生资源路径，注入器，文件钩子，默认参数
 * English keywords: process watcher, native resource path, injector, file hook, default options
 */
export async function resolveDefaultProcessWatcherStartOptions(): Promise<ProcessWatcherStartOptions> {
  const [injectorX64, injectorX86, dllX64, dllX86] = await Promise.all([
    resolveResource('native/bin/win32-x64/file_hook_injector.exe'),
    resolveResource('native/bin/win32-x86/file_hook_injector.exe'),
    resolveResource('native/bin/win32-x64/file_hook_detours.dll'),
    resolveResource('native/bin/win32-x86/file_hook_detours.dll'),
  ])

  return {
    injectorX64,
    injectorX86,
    dllX64,
    dllX86,
    intervalMs: DEFAULT_PROCESS_WATCHER_INTERVAL_MS
  }
}

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

/**
 * 函数名称：peekCurrentInterception
 * 函数作用：获取当前正在展示的拦截条目（若有），供拦截窗口初始化后主动拉取。
 * Purpose: Gets the currently shown interception entry (if any) for the interception window to pull after initialization.
 */
export async function peekCurrentInterception(): Promise<Record<string, unknown> | null> {
  return await invoke('peek_current_interception')
}

/**
 * 函数名称：startProcessWatcher
 * 函数作用：启动后端进程监控服务，轮询新进程并对需要监控的进程注入文件 Hook。
 * Purpose: Starts the backend process watcher, polling new processes and injecting file Hook where needed.
 * 调用方：configStore.setProcessMonitoring。
 * Called by: configStore.setProcessMonitoring.
 * 被调用方：Tauri invoke start_process_watcher。
 * Calls: Tauri invoke start_process_watcher.
 * 参数说明：options 包含 x64/x86 注入器、x64/x86 DLL 和轮询间隔。
 * Parameters: options contains x64/x86 injector paths, x64/x86 DLL paths, and polling interval.
 * 返回值说明：后端返回 true 表示命令执行成功。
 * Returns: backend returns true when command succeeds.
 * 中文关键词：启动进程监控，新进程轮询，注入器，运行态控制
 * English keywords: start process watcher, new process polling, injector, runtime control
 */
export async function startProcessWatcher(options: ProcessWatcherStartOptions): Promise<boolean> {
  return await invoke('start_process_watcher', {
    injectorX64: options.injectorX64,
    injectorX86: options.injectorX86,
    dllX64: options.dllX64,
    dllX86: options.dllX86,
    intervalMs: options.intervalMs
  })
}

/**
 * 函数名称：stopProcessWatcher
 * 函数作用：停止后端进程监控服务。
 * Purpose: Stops the backend process watcher service.
 * 调用方：configStore.setProcessMonitoring。
 * Called by: configStore.setProcessMonitoring.
 * 被调用方：Tauri invoke stop_process_watcher。
 * Calls: Tauri invoke stop_process_watcher.
 * 返回值说明：后端返回 true 表示命令执行成功。
 * Returns: backend returns true when command succeeds.
 * 中文关键词：停止进程监控，运行态控制
 * English keywords: stop process watcher, runtime control
 */
export async function stopProcessWatcher(): Promise<boolean> {
  return await invoke('stop_process_watcher')
}

/**
 * 函数名称：getProcessWatcherStatus
 * 函数作用：读取 APIHook 进程监控 watcher 是否正在运行。
 * Purpose: Reads whether the APIHook process watcher is running.
 * 调用方：getMonitoringRuntimeStatus。
 * Called by: getMonitoringRuntimeStatus.
 * 被调用方：Tauri invoke get_process_watcher_status。
 * Calls: Tauri invoke get_process_watcher_status.
 * 返回值说明：true 表示 APIHook watcher 已启动，false 表示未启动。
 * Returns: true when the APIHook watcher is started, false when stopped.
 * 中文关键词：APIHook状态，进程监控状态，运行态查询
 * English keywords: APIHook status, process watcher status, runtime query
 */
export async function getProcessWatcherStatus(): Promise<boolean> {
  return await invoke('get_process_watcher_status')
}

/**
 * 函数名称：pollNewPids
 * 函数作用：读取进程监控服务发现的新 PID 列表，后端读取后会清空队列。
 * Purpose: Reads newly discovered PIDs from the process watcher; backend drains the queue after reading.
 * 调用方：OverviewPage 或后续实时进程提示组件。
 * Called by: OverviewPage or future real-time process notification components.
 * 被调用方：Tauri invoke poll_new_pids。
 * Calls: Tauri invoke poll_new_pids.
 * 返回值说明：返回新发现的 PID 数组。
 * Returns: array of newly discovered PIDs.
 * 中文关键词：新PID，进程轮询，进程监控状态
 * English keywords: new PID, process polling, process watcher status
 */
export async function pollNewPids(): Promise<number[]> {
  return await invoke('poll_new_pids')
}
