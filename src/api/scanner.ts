/**
 * 扫描引擎 API 封装
 * Scanner engine API wrapper
 * 
 * 封装所有扫描引擎相关的 Tauri invoke 调用和事件监听。
 * Wraps all scan-engine-related Tauri invoke calls and event listeners.
 */
import { invoke } from '@tauri-apps/api/core'
import { listen, UnlistenFn } from '@tauri-apps/api/event'

/** 扫描选项/Scan options */
export interface ScanOptions {
  maxFileSizeMB?: number
  commonExtensionsOnly?: boolean
}

/** 扫描结果/Scan result for a single file */
export interface ScanResult {
  fileId: string
  verdict: 'clean' | 'malware' | 'suspicious' | 'unknown'
  threatType?: string
  severity?: number
  description?: string
}

/** 批量扫描结果/Batch scan result containing multiple file results */
export interface BatchScanResult {
  results: ScanResult[]
  totalFiles: number
  threatsFound: number
  scannedFiles?: number
  cancelled?: boolean
}

/** 扫描进度事件载荷/Scan progress event payload */
export interface ScanProgressEvent {
  current: number
  total: number
  currentFile?: string
  percentage: number
}

/** 引擎健康状态/Engine health status */
export interface EngineHealth {
  status: string
  version?: string
  uptime?: number
}

/**
 * 函数名称：scannerHealth
 * 函数作用：检查扫描引擎健康状态，返回引擎状态信息。
 * Purpose: Checks the scan engine health and returns engine status info.
 * 调用方：OverviewPage (30 秒轮询)
 * Called by: OverviewPage (30s polling)
 * 中文关键词：引擎健康检查，心跳，扫描引擎状态
 * English keywords: engine health check, heartbeat, scan engine status
 */
export async function scannerHealth(): Promise<EngineHealth> {
  return await invoke('scanner_health')
}

/**
 * 函数名称：scanFile
 * 函数作用：扫描单个文件，返回扫描结果。
 * Purpose: Scans a single file and returns the scan result.
 * 调用方：scannerStore.startScan() (单文件选定时)
 * Called by: scannerStore.startScan() (when single file selected)
 * 参数：filePath — 文件绝对路径 / options — 扫描选项（可选）
 * 中文关键词：文件扫描，单文件扫描，威胁检测
 * English keywords: file scan, single file scan, threat detection
 */
export async function scanFile(
  filePath: string,
  options?: ScanOptions
): Promise<ScanResult> {
  return await invoke('scan_file', { filePath, options })
}

/**
 * 函数名称：scanBatch
 * 函数作用：批量扫描多个文件，返回批量扫描结果。
 * Purpose: Scans multiple files in batch and returns batch scan results.
 * 调用方：scannerStore.startScan() (多文件选定时)
 * Called by: scannerStore.startScan() (when multiple files selected)
 * 参数：filePaths — 文件路径数组 / options — 扫描选项（可选）
 * 中文关键词：批量扫描，多文件扫描，批量检测
 * English keywords: batch scan, multi-file scan, batch detection
 */
export async function scanBatch(
  filePaths: string[],
  options?: ScanOptions
): Promise<BatchScanResult> {
  return await invoke('scan_batch', { filePaths, options })
}

/**
 * 函数名称：cancelScan
 * 函数作用：取消当前正在进行的扫描操作。
 * Purpose: Cancels the current ongoing scan operation.
 * 调用方：scannerStore.cancelScan()
 * Called by: scannerStore.cancelScan()
 * 中文关键词：取消扫描，中断扫描，停止扫描
 * English keywords: cancel scan, abort scan, stop scan
 */
export async function cancelScan(): Promise<boolean> {
  return await invoke('cancel_scan')
}

/**
 * 函数名称：startEngine
 * 函数作用：启动扫描引擎进程。
 * Purpose: Starts the scan engine process.
 * 调用方：OverviewPage / SettingsPage
 * Called by: OverviewPage / SettingsPage
 * 中文关键词：启动引擎，引擎启动，启动扫描服务
 * English keywords: start engine, engine start, start scan service
 */
export async function startEngine(): Promise<boolean> {
  return await invoke('start_engine')
}

/**
 * 函数名称：stopEngine
 * 函数作用：停止扫描引擎进程。
 * Purpose: Stops the scan engine process.
 * 调用方：SettingsPage / execute_exit
 * Called by: SettingsPage / execute_exit
 * 中文关键词：停止引擎，引擎停止，关闭扫描服务
 * English keywords: stop engine, engine stop, shutdown scan service
 */
export async function stopEngine(): Promise<boolean> {
  return await invoke('stop_engine')
}

/**
 * 函数名称：onScanProgress
 * 函数作用：监听扫描进度事件。当后端逐文件扫描时通过 Tauri Events 推送进度。
 * Purpose: Listens for scan progress events emitted by the backend during batch scanning.
 * 调用方：scannerStore.startScan() (设置进度监听)
 * Called by: scannerStore.startScan() (sets up progress listener)
 * 参数：callback — 接收 ScanProgressEvent 的回调函数
 * 返回值：取消监听的清理函数
 * 中文关键词：扫描进度，进度监听，实时进度，逐文件进度
 * English keywords: scan progress, progress listener, real-time progress, per-file progress
 */
export function onScanProgress(
  callback: (progress: ScanProgressEvent) => void
): () => void {
  let unlisten: UnlistenFn | null = null

  listen('scan-progress', (event) => {
    callback(event.payload as ScanProgressEvent)
  }).then((fn) => {
    unlisten = fn
  })

  return () => {
    if (unlisten) {
      unlisten()
    }
  }
}
