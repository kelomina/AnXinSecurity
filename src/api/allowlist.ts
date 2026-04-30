import { invoke } from '@tauri-apps/api/core'

export interface AllowlistEntry {
  path: string
  hash?: string
  description?: string
  created_at: string
}

/**
 * 获取启动允许列表
 */
export async function listAllowlist(): Promise<AllowlistEntry[]> {
  return await invoke('list_allowlist')
}

/**
 * 添加到启动允许列表
 */
export async function addToAllowlist(path: string, description?: string): Promise<boolean> {
  return await invoke('add_to_allowlist', { path, description })
}

/**
 * 从启动允许列表移除
 */
export async function removeFromAllowlist(path: string): Promise<boolean> {
  return await invoke('remove_from_allowlist', { path })
}

/**
 * 批量添加到允许列表
 */
export async function addToAllowlistBatch(entries: AllowlistEntry[]): Promise<number> {
  return await invoke('add_to_allowlist_batch', { entries })
}
