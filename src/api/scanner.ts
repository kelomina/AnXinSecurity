import { invoke } from '@tauri-apps/api/core'
import { listen, UnlistenFn } from '@tauri-apps/api/event'

export interface ScanOptions {
  maxFileSizeMB?: number
  commonExtensionsOnly?: boolean
}

export interface ScanResult {
  fileId: string
  verdict: 'clean' | 'malware' | 'suspicious' | 'unknown'
  threatType?: string
  severity?: number
  description?: string
}

export async function scannerHealth(): Promise<any> {
  return await invoke('scanner_health')
}

export async function scanFile(
  filePath: string,
  options?: ScanOptions
): Promise<ScanResult> {
  return await invoke('scan_file', { filePath, options })
}

export async function scanBatch(
  filePaths: string[],
  options?: ScanOptions
): Promise<any> {
  return await invoke('scan_batch', { filePaths, options })
}

export function onTrainProgress(
  callback: (progress: any) => void
): () => void {
  let unlisten: UnlistenFn | null = null

  listen('train-progress', (event) => {
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
