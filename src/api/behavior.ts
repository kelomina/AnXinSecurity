/**
 * 行为分析 API 封装
 * Behavior analysis API wrapper
 *
 * 封装 ETW 事件查询、进程列表、暂停/恢复监控和实时事件监听。
 * Wraps ETW event queries, process listing, pause/resume monitoring, and real-time event listening.
 */
import { invoke } from '@tauri-apps/api/core'
import { listen, UnlistenFn } from '@tauri-apps/api/event'

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
 * 函数作用：监听实时 ETW 事件推送。后端通过 Tauri Events 推送每个捕获到的 ETW 事件。
 * Purpose: Listens for real-time ETW event pushes from the backend via Tauri Events.
 * 调用方：BehaviorPage (实时事件流)
 * Called by: BehaviorPage (real-time event stream)
 * 参数：callback — 接收 EtwEvent 的回调函数
 * 返回值：取消监听的清理函数
 * 中文关键词：实时事件，事件监听，ETW事件流，实时推送
 * English keywords: real-time event, event listener, ETW event stream, real-time push
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
