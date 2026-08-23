/**
 * 进程生命周期监控 API — ProcessLifecyclePage 的后端桥接
 * Process lifecycle monitoring API - backend bridge for ProcessLifecyclePage
 *
 * 中文关键词：进程生命周期，健康状态，进程树，生命周期事件，探针告警
 * English keywords: process lifecycle, health status, process tree, lifecycle events, probe alert
 */
import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'

/** 进程监控采集模块健康状态（§4.6 get_proc_monitor_health）
 *  Process monitor health (§4.6 get_proc_monitor_health) */
export interface ProcMonitorHealth {
  connected: boolean
  driverMajor: number
  driverMinor: number
  driverPatch: number
  lifecycleDepth: number
  behaviorDepth: number
  lifecycleDropped: number
  behaviorDropped: number
  lastCallbackTickMs: number
  probeTotal: number
  probeReportedOk: number
  probeMissedRounds: number
  tamperedAlerts: number
  lastReconcileCount: number
  tableSize: number
}

/** 进程树节点（§4.6 get_process_tree） / Process-tree node */
export interface ProcessTreeNode {
  pid: number
  parentPid: number
  sessionId: number
  createTime: number
  restored: boolean
  imagePath: string | null
  alive: boolean
  children: ProcessTreeNode[]
}

/** 生命周期事件（§4.6 list_lifecycle_events） / Lifecycle event */
export interface LifecycleEvent {
  pid: number
  parentPid: number
  eventType: number
  eventTime: number
  tsMs: number
  sessionId: number
  exitStatus: number
  flags: number
  imagePath: string | null
  restored: boolean
}

/** 回调失明告警事件 payload / Callback-blindness alert payload */
export interface TamperedAlert {
  severity: string
  missingSeconds: number
  missedRounds: number
  alertCount: number
  reconciledProcesses: number
  hint: string
}

/** 生命周期实时事件（process-lifecycle-event 的 payload） / Real-time lifecycle event */
export interface LifecyclePush {
  event: 'create' | 'exit'
  pid: number
  parentPid?: number
  sessionId?: number
  exitStatus?: number
  flags?: number
  ts?: number
  imagePath?: string | null
}

/** 事件类型数字到名称 / Numeric event type to name */
export const EVENT_TYPE_NAMES: Record<number, string> = {
  1: 'create',
  2: 'exit',
  3: 'image-load',
  4: 'remote-thread',
  5: 'file-create',
  6: 'file-write',
  7: 'file-delete',
  8: 'file-rename',
  9: 'reg-setvalue',
  10: 'reg-createkey',
  11: 'reg-delete',
  12: 'reg-rename',
  13: 'net-connect',
  14: 'ipc-connect',
  15: 'drop-marker',
}

/** 事件标志位（ANX_PROC_FLAG_*） / Event flags */
export const PROC_FLAG_PPID_SPOOFED = 0x0001
export const PROC_FLAG_TOKEN_ELEVATED = 0x0002
export const PROC_FLAG_TOKEN_HIGH_INTEGRITY = 0x0004

/**
 * 函数名称：getProcMonitorHealth
 * 函数作用：查询进程监控采集模块的健康状态与探针统计。
 * Purpose: Queries the process monitor health and probe statistics.
 * 调用方：ProcessLifecyclePage
 * Called by: ProcessLifecyclePage
 * 中文关键词：健康状态，探针统计，驱动连接
 * English keywords: health status, probe stats, driver connection
 */
export async function getProcMonitorHealth(): Promise<ProcMonitorHealth> {
  return await invoke<ProcMonitorHealth>('get_proc_monitor_health')
}

/**
 * 函数名称：getProcessTree
 * 函数作用：返回当前状态表的进程树（父子链 + 存活/孤儿标记）。
 * Purpose: Returns the process tree from the current table.
 * 调用方：ProcessLifecyclePage
 * Called by: ProcessLifecyclePage
 * 中文关键词：进程树，父子链，孤儿标记
 * English keywords: process tree, parent-child chain, orphan marking
 */
export async function getProcessTree(): Promise<ProcessTreeNode[]> {
  return await invoke<ProcessTreeNode[]>('get_process_tree')
}

/**
 * 函数名称：listLifecycleEvents
 * 函数作用：返回最近的进程生命周期事件（上限 500 条）。
 * Purpose: Returns the most recent lifecycle events (cap 500).
 * 调用方：ProcessLifecyclePage
 * Called by: ProcessLifecyclePage
 * 中文关键词：生命周期事件，历史查询
 * English keywords: lifecycle events, history query
 */
export async function listLifecycleEvents(
  limit?: number
): Promise<LifecycleEvent[]> {
  return await invoke<LifecycleEvent[]>('list_lifecycle_events', {
    limit: limit ?? 500,
  })
}

/**
 * 函数名称：onProcessLifecycleEvent
 * 函数作用：监听实时生命周期事件推送（create / exit）。
 * Purpose: Listens for real-time lifecycle event pushes.
 * 调用方：ProcessLifecyclePage
 * Called by: ProcessLifecyclePage
 * 返回值：取消监听的清理函数 / Returns: unlisten cleanup
 * 中文关键词：实时事件，生命周期监听
 * English keywords: realtime event, lifecycle listener
 */
export function onProcessLifecycleEvent(
  callback: (event: LifecyclePush) => void
): () => void {
  let unlisten: UnlistenFn | null = null
  let disposed = false

  listen<LifecyclePush>('process-lifecycle-event', (event) => {
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

/**
 * 函数名称：onProcessMonitorTampered
 * 函数作用：监听回调失明高危告警（BYOVD 探针超时）。
 * Purpose: Listens for the callback-blindness high-risk alert (BYOVD probe timeout).
 * 调用方：ProcessLifecyclePage
 * Called by: ProcessLifecyclePage
 * 返回值：取消监听的清理函数 / Returns: unlisten cleanup
 * 中文关键词：高危告警，回调失明，BYOVD
 * English keywords: high-risk alert, callback blindness, BYOVD
 */
export function onProcessMonitorTampered(
  callback: (alert: TamperedAlert) => void
): () => void {
  let unlisten: UnlistenFn | null = null
  let disposed = false

  listen<TamperedAlert>('process-monitor-tampered', (event) => {
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
