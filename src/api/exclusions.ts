import { invoke } from '@tauri-apps/api/core'

export interface ExclusionEntry {
  path: string
  entry_type: 'file' | 'directory' | 'process'
  description?: string
  created_at: string
}

/**
 * 获取排除项列表
 */
export async function listExclusions(): Promise<ExclusionEntry[]> {
  return await invoke('list_exclusions')
}

/**
 * 添加排除项
 */
export async function addExclusion(
  path: string,
  entryType: 'file' | 'directory' | 'process',
  description?: string
): Promise<boolean> {
  return await invoke('add_exclusion', { path, entryType, description })
}

/**
 * 移除排除项
 */
export async function removeExclusion(path: string): Promise<boolean> {
  return await invoke('remove_exclusion', { path })
}

/**
 * 批量添加排除项
 */
export async function addExclusionsBatch(entries: ExclusionEntry[]): Promise<number> {
  return await invoke('add_exclusions_batch', { entries })
}
