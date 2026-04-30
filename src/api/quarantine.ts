import { invoke } from '@tauri-apps/api/core'

export interface QuarantineItem {
  id: string
  originalPath: string
  fileHash: string
  fileSize: number
  threatType?: string
  threatFamily?: string
  status: 'quarantined' | 'restored' | 'deleted'
  isolatedAt: string
  restoredAt?: string
  description?: string
}

export async function listQuarantine(): Promise<QuarantineItem[]> {
  return await invoke('list_quarantine')
}

export async function isolateFile(
  filePath: string,
  threatType?: string
): Promise<QuarantineItem> {
  return await invoke('isolate_file', { filePath, threatType })
}

export async function restoreFile(id: string): Promise<boolean> {
  return await invoke('restore_file', { id })
}

export async function deleteQuarantine(id: string): Promise<boolean> {
  return await invoke('delete_quarantine', { id })
}

// 辅助函数
export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

export function formatDate(isoString: string): string {
  return new Date(isoString).toLocaleString('zh-CN')
}
