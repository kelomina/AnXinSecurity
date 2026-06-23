/**
 * 行为分析 API 封装
 * Behavior analysis API wrapper
 *
 * 封装 ETW 事件查询、进程列表、暂停/恢复监控、Hook 控制状态和实时事件监听。
 * Wraps ETW event queries, process listing, pause/resume monitoring, Hook control status, and real-time event listening.
 */
import { invoke } from '@tauri-apps/api/core'
import { listen, UnlistenFn } from '@tauri-apps/api/event'
import { getProcessWatcherStatus } from './process'

/** ETW 事件数据结构/ETW event data structure */
export interface EtwEvent {
  id?: string
  type: string
  timestamp: string
  pid: number
  tid: number
  provider: string
  processName?: string
  operation?: string
  path?: string
  details?: string
  data?: Record<string, unknown>
}

/** 文件 Hook 事件数据结构/File hook event data structure */
export interface FileHookEvent extends EtwEvent {
  type: 'file_hook' | string
  source?: string
  processPath?: string
  riskLevel?: string
  threatType?: string
}

/** 事件查询参数/Event query parameters */
export interface EventQuery {
  pid?: number
  limit?: number
  offset?: number
}

/** 行为监控进程摘要/Behavior monitoring process summary */
export interface BehaviorProcess {
  pid: number
  processName: string
  eventCount: number
  lastSeen: string
}

/** 监控运行态/Monitoring runtime status */
export interface EtwRuntimeStatus {
  running: boolean
  collecting: boolean
}

/** 监控运行态/Monitoring runtime status */
export interface MonitoringRuntimeStatus {
  etwRunning: boolean
  etwCollecting: boolean
  processWatcherRunning: boolean
  hookRunning: boolean
}

/** ETW 现场诊断缓存中的单条事件摘要 / One summarized event in the ETW field diagnostics cache */
export interface EtwDiagnosticEvent {
  timestamp: string
  stage: string
  provider?: string
  operation?: string
  pid?: number
  tid?: number
  eventId?: number
  opcode?: number
  processName?: string
  path?: string
  rawUserDataLength?: number
  rawUserDataPreview?: string
  ruleId?: string
  threatType?: string
  matched: boolean
  dropped: boolean
  dropReason?: string
  parseError?: string
  rawTextPreview?: string
  value?: unknown
}

/** ETW 现场诊断快照 / ETW field diagnostics snapshot */
export interface EtwDiagnosticsSnapshot {
  startedAt: string
  snapshotAt: string
  running: boolean
  collecting: boolean
  capacity: number
  aggregateCapacity: number
  aggregateEvictions: number
  totalPolled: number
  totalRaw: number
  totalParseErrors: number
  totalDroppedSystemPid: number
  totalAfterFilter: number
  totalNormalized: number
  totalMatched: number
  pollBatches: number
  lastPollEventCount: number
  providerCounts: Record<string, number>
  operationCounts: Record<string, number>
  providerOperationCounts: Record<string, number>
  ruleCounts: Record<string, number>
  threatCounts: Record<string, number>
  dropCounts: Record<string, number>
  recentRaw: EtwDiagnosticEvent[]
  recentNormalized: EtwDiagnosticEvent[]
  aggregateBuckets: EtwDiagnosticBucket[]
}

/** ETW 现场诊断聚合桶 / ETW field diagnostics aggregate bucket */
export interface EtwDiagnosticBucket {
  key: string
  stage: string
  firstSeen: string
  lastSeen: string
  count: number
  provider?: string
  operation?: string
  pid?: number
  eventId?: number
  opcode?: number
  processName?: string
  pathKey?: string
  rawUserDataLength?: number
  ruleId?: string
  threatType?: string
  matched: boolean
  dropped: boolean
  dropReason?: string
  parseError?: string
  sample: EtwDiagnosticEvent
}

/**
 * 函数名称：listEvents
 * 函数作用：查询历史行为事件列表，支持按 PID 过滤和分页。
 * Purpose: Queries historical behavior events, supports PID filtering and pagination.
 * 调用方：BehaviorPage (首次加载历史事件)
 * Called by: BehaviorPage (initial history load)
 * 中文关键词：行为事件，事件列表，历史事件，ETW事件查询
 * English keywords: behavior event, event list, historical event, ETW event query
 */
export async function listEvents(query?: EventQuery): Promise<EtwEvent[]> {
  return await invoke('list_behavior_events', { query })
}

/**
 * 函数名称：listProcesses
 * 函数作用：查询被监控的进程摘要列表。
 * Purpose: Queries the list of monitored process summaries.
 * 调用方：BehaviorPage (进程列表视图)
 * Called by: BehaviorPage (process list view)
 * 中文关键词：进程列表，进程摘要，监控进程，行为进程
 * English keywords: process list, process summary, monitored process, behavior process
 */
export async function listProcesses(limit?: number): Promise<BehaviorProcess[]> {
  return await invoke('list_behavior_processes', { limit })
}

/**
 * 函数名称：pauseEtw
 * 函数作用：暂停 ETW 行为监控，停止采集实时事件。
 * Purpose: Pauses ETW behavior monitoring, stops collecting real-time events.
 * 调用方：BehaviorPage (暂停按钮)
 * Called by: BehaviorPage (pause button)
 * 副作用：停止 ETW 事件轮询，停止向前端推送事件
 * Side effect: Stops ETW event polling, stops event push to frontend
 * 中文关键词：暂停监控，暂停ETW，停止采集，暂停行为分析
 * English keywords: pause monitoring, pause ETW, stop collection, pause behavior analysis
 */
export async function pauseEtw(): Promise<void> {
  return await invoke('pause_etw')
}

/**
 * 函数名称：resumeEtw
 * 函数作用：恢复 ETW 行为监控，重新开始采集实时事件。
 * Purpose: Resumes ETW behavior monitoring, restarts collecting real-time events.
 * 调用方：BehaviorPage (恢复按钮)
 * Called by: BehaviorPage (resume button)
 * 副作用：重新创建 ETW bridge 并启动事件轮询
 * Side effect: Recreates ETW bridge and restarts event polling
 * 中文关键词：恢复监控，恢复ETW，重新采集，恢复行为分析
 * English keywords: resume monitoring, resume ETW, restart collection, resume behavior analysis
 */
export async function resumeEtw(): Promise<void> {
  return await invoke('resume_etw')
}

/**
 * 函数名称：getEtwStatus
 * 函数作用：读取 ETW 服务线程和采集开关的真实运行态。
 * Purpose: Reads the real runtime status of the ETW service thread and collection flag.
 * 调用方：getMonitoringRuntimeStatus、OverviewPage、SettingsPage。
 * Called by: getMonitoringRuntimeStatus, OverviewPage, SettingsPage.
 * 被调用方：Tauri invoke get_etw_status。
 * Calls: Tauri invoke get_etw_status.
 * 返回值说明：running 表示 ETW 服务线程已启动，collecting 表示当前正在采集事件。
 * Returns: running means the ETW service thread is started, collecting means events are being collected.
 * 中文关键词：ETW状态，行为监控状态，运行态查询
 * English keywords: ETW status, behavior monitoring status, runtime query
 */
export async function getEtwStatus(): Promise<EtwRuntimeStatus> {
  return await invoke('get_etw_status')
}

/**
 * 函数名称：getEtwDiagnosticsSnapshot
 * 函数作用：读取后端 ETW 现场诊断环形缓存，用于确认真实收到哪些 provider、operation 和规则命中。
 * Purpose: Reads the backend ETW field diagnostics ring buffer to verify observed providers, operations, and rule hits.
 * 调用方：BehaviorPage 现场诊断面板。
 * Called by: BehaviorPage field diagnostics panel.
 * 中文关键词：ETW诊断，现场缓存，事件统计，注入复现
 * English keywords: ETW diagnostics, field cache, event statistics, injection reproduction
 */
export async function getEtwDiagnosticsSnapshot(): Promise<EtwDiagnosticsSnapshot> {
  return await invoke('get_etw_diagnostics_snapshot')
}

/**
 * 函数名称：clearEtwDiagnostics
 * 函数作用：清空 ETW 诊断缓存，让下一轮受控复现从干净窗口开始。
 * Purpose: Clears the ETW diagnostics cache so the next controlled reproduction starts from a clean window.
 */
export async function clearEtwDiagnostics(): Promise<boolean> {
  return await invoke('clear_etw_diagnostics')
}

/**
 * 函数名称：exportEtwDiagnostics
 * 函数作用：把 ETW 诊断缓存导出到 APPDATA runtime JSON 文件，并返回文件绝对路径。
 * Purpose: Exports the ETW diagnostics cache to an APPDATA runtime JSON file and returns its absolute path.
 */
export async function exportEtwDiagnostics(): Promise<string> {
  return await invoke('export_etw_diagnostics')
}

/**
 * 函数名称：getHookStatus
 * 函数作用：读取文件 Hook 命名管道服务是否正在运行。
 * Purpose: Reads whether the file Hook named-pipe service is running.
 * 调用方：configStore.refreshMonitoringRuntimeStatus、OverviewPage。
 * Called by: configStore.refreshMonitoringRuntimeStatus, OverviewPage.
 * 被调用方：Tauri invoke get_hook_status。
 * Calls: Tauri invoke get_hook_status.
 * 返回值说明：true 表示 Hook 服务正在运行，false 表示已停止。
 * Returns: true when Hook service is running, false when stopped.
 * 错误处理：后端命令失败时向上抛出，由调用方展示或记录。
 * Error handling: Backend command failures are thrown to callers for display or logging.
 * 中文关键词：Hook状态，文件钩子，运行态状态，真实状态
 * English keywords: hook status, file hook, runtime status, real status
 */
export async function getHookStatus(): Promise<boolean> {
  return await invoke('get_hook_status')
}

/**
 * 函数名称：startHookService
 * 函数作用：启动文件 Hook 命名管道服务，用于接收注入进程上报的文件操作事件。
 * Purpose: Starts the file Hook named-pipe service to receive file-operation events from injected processes.
 * 调用方：configStore.setFileMonitoring。
 * Called by: configStore.setFileMonitoring.
 * 被调用方：Tauri invoke start_hook_service。
 * Calls: Tauri invoke start_hook_service.
 * 参数说明：pipeName 为可选管道名称；不传时后端使用默认值。
 * Parameters: pipeName is optional; backend default is used when omitted.
 * 返回值说明：后端返回 true 表示命令执行成功。
 * Returns: backend returns true when command succeeds.
 * 中文关键词：启动Hook，文件监控，命名管道，运行态控制
 * English keywords: start hook, file monitoring, named pipe, runtime control
 */
export async function startHookService(pipeName?: string): Promise<boolean> {
  return await invoke('start_hook_service', { pipeName })
}

/**
 * 函数名称：stopHookService
 * 函数作用：停止文件 Hook 命名管道服务。
 * Purpose: Stops the file Hook named-pipe service.
 * 调用方：configStore.setFileMonitoring。
 * Called by: configStore.setFileMonitoring.
 * 被调用方：Tauri invoke stop_hook_service。
 * Calls: Tauri invoke stop_hook_service.
 * 返回值说明：后端返回 true 表示命令执行成功。
 * Returns: backend returns true when command succeeds.
 * 中文关键词：停止Hook，文件监控，运行态控制
 * English keywords: stop hook, file monitoring, runtime control
 */
export async function stopHookService(): Promise<boolean> {
  return await invoke('stop_hook_service')
}

/**
 * 函数名称：getMonitoringRuntimeStatus
 * 函数作用：读取 ETW、APIHook watcher 和 Hook 管道三条监控链路的真实运行态。
 * Purpose: Reads the real runtime status of the ETW, APIHook watcher, and Hook pipe monitoring chains.
 * 调用方：OverviewPage 初始化/轮询、configStore.refreshMonitoringRuntimeStatus。
 * Called by: OverviewPage initialization/polling, configStore.refreshMonitoringRuntimeStatus.
 * 被调用方：getEtwStatus、getProcessWatcherStatus、getHookStatus。
 * Calls: getEtwStatus, getProcessWatcherStatus, getHookStatus.
 * 返回值说明：返回三条监控链路的后端真实状态，不使用占位值。
 * Returns: backend-confirmed status for all three monitoring chains, without placeholder values.
 * 错误处理：任一状态读取失败时向上抛出。
 * Error handling: Any status read failure is thrown.
 * 中文关键词：运行态状态，概览状态，Hook状态，ETW状态，APIHook状态
 * English keywords: runtime status, overview status, hook status, ETW status, APIHook status
 */
export async function getMonitoringRuntimeStatus(): Promise<MonitoringRuntimeStatus> {
  const [etwStatus, processWatcherRunning, hookRunning] = await Promise.all([
    getEtwStatus(),
    getProcessWatcherStatus(),
    getHookStatus()
  ])
  return {
    etwRunning: etwStatus.running,
    etwCollecting: etwStatus.collecting,
    processWatcherRunning,
    hookRunning
  }
}

/**
 * 函数名称：clearAllEvents
 * 函数作用：清除所有历史行为事件记录。
 * Purpose: Clears all historical behavior event records.
 * 调用方：BehaviorPage (清除按钮)
 * Called by: BehaviorPage (clear button)
 * 副作用：删除数据库中所有事件记录，不可恢复
 * Side effect: Deletes all event records from database, irreversible
 * 中文关键词：清除事件，清空历史，删除事件，重置行为分析
 * English keywords: clear events, clear history, delete events, reset behavior analysis
 */
export async function clearAllEvents(): Promise<boolean> {
  return await invoke('clear_behavior_events')
}

/**
 * 函数名称：onEtwEvent
 * 函数作用：监听高价值实时 ETW 事件推送。高频普通事件保留在诊断缓存和行为库，不逐条推给前端。
 * Purpose: Listens for high-value realtime ETW event pushes. High-volume ordinary events stay in diagnostics/history instead of being pushed one by one.
 * 调用方：BehaviorPage (实时事件流)
 * Called by: BehaviorPage (real-time event stream)
 * 参数：callback — 接收 EtwEvent 的回调函数
 * 返回值：取消监听的清理函数
 * 中文关键词：实时告警，事件监听，ETW高价值事件，前端降噪
 * English keywords: realtime alert, event listener, high-value ETW event, frontend noise reduction
 */
export function onEtwEvent(
  callback: (event: EtwEvent) => void
): () => void {
  let unlisten: UnlistenFn | null = null

  listen('etw-event', (event) => {
    callback(event.payload as EtwEvent)
  }).then((fn) => {
    unlisten = fn
  })

  return () => {
    if (unlisten) {
      unlisten()
    }
  }
}

/**
 * 函数名称：onFileHookEvent
 * 函数作用：监听文件 Hook 专用事件。后端也会把同一事件兼容发送到 etw-event，本函数用于需要区分来源的页面。
 * Purpose: Listens for dedicated file Hook events. Backend also emits the same event to etw-event for compatibility; this wrapper is for pages that need source-specific handling.
 * 调用方：BehaviorPage、OverviewPage。
 * Called by: BehaviorPage, OverviewPage.
 * 参数说明：callback 接收 FileHookEvent 的回调函数。
 * Parameters: callback receives a FileHookEvent.
 * 返回值说明：取消监听的清理函数。
 * Returns: cleanup function that removes the listener.
 * 中文关键词：文件Hook事件，file-hook-event，类型安全监听，实时文件监控
 * English keywords: file hook event, file-hook-event, typed listener, real-time file monitoring
 */
export function onFileHookEvent(
  callback: (event: FileHookEvent) => void
): () => void {
  let unlisten: UnlistenFn | null = null

  listen<FileHookEvent>('file-hook-event', (event) => {
    callback(event.payload)
  }).then((fn) => {
    unlisten = fn
  })

  return () => {
    if (unlisten) {
      unlisten()
    }
  }
}
