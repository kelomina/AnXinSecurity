/**
 * 启动快照 API 封装
 * Startup snapshot API wrapper
 *
 * 封装启动快照进度和结果事件监听，供启动阶段页面展示真实初始化进度。
 * Wraps startup snapshot progress/result listeners for the startup phase screen.
 */
import { listen, UnlistenFn } from '@tauri-apps/api/event'

/** 启动快照进度事件载荷 / Startup snapshot progress event payload */
export interface SnapshotProgressEvent {
  stage: string
  current: number
  total: number
}

/** 启动快照性能采样 / Startup snapshot performance sample */
export interface SnapshotPerformanceStats {
  baselineDurationMs?: number
  deepScanDurationMs?: number
  processEnumerationMs?: number
  pathPolicyLoadMs?: number
  processLoopMs?: number
  moduleEnumerationMs?: number
  signatureVerificationMs?: number
  signatureVerifyConcurrency?: number
  targetScanMs?: number
  moduleReferences?: number
  uniqueModulePaths?: number
  uniqueScanPaths?: number
}

/** 启动快照结果载荷 / Startup snapshot result payload */
export interface SnapshotResult {
  baselineComplete: boolean
  deepScanCompleted: boolean
  deepScanPendingModules: number
  deepScanPendingProcesses: number
  totalProcesses: number
  signedProcesses: number
  unsignedProcesses: number
  pausedProcesses: number
  scannedModules: number
  maliciousProcesses: number
  maliciousModules: number
  imageIntegrityAlerts: number
  unsignedModuleAlerts: number
  masqueradeAlerts: number
  revocationAlerts: number
  revocationUnknownCritical: number
  unknownProcesses: number
  unknownModules: number
  moduleEnumerationFailures: number
  moduleEnumerationAccessDenied: number
  cacheHits: number
  performance?: SnapshotPerformanceStats
  durationMs: number
}

/**
 * 函数名称：onSnapshotProgress
 * 函数作用：监听后端启动快照进度事件。
 * Purpose: Listens for backend startup snapshot progress events.
 * 调用方：App 启动阶段页面。
 * Called by: App startup phase screen.
 */
export function onSnapshotProgress(
  callback: (progress: SnapshotProgressEvent) => void
): () => void {
  let unlisten: UnlistenFn | null = null
  let disposed = false

  listen<SnapshotProgressEvent>('snapshot-progress', (event) => {
    callback(event.payload)
  }).then((fn) => {
    if (disposed) {
      fn()
      return
    }
    unlisten = fn
  })

  return () => {
    disposed = true
    if (unlisten) {
      unlisten()
    }
  }
}

/**
 * 函数名称：onSnapshotResult
 * 函数作用：监听后端启动快照结果事件。
 * Purpose: Listens for backend startup snapshot result events.
 * 调用方：App 启动阶段页面。
 * Called by: App startup phase screen.
 */
export function onSnapshotResult(
  callback: (result: SnapshotResult) => void
): () => void {
  let unlisten: UnlistenFn | null = null
  let disposed = false

  listen<SnapshotResult>('snapshot-result', (event) => {
    callback(event.payload)
  }).then((fn) => {
    if (disposed) {
      fn()
      return
    }
    unlisten = fn
  })

  return () => {
    disposed = true
    if (unlisten) {
      unlisten()
    }
  }
}
