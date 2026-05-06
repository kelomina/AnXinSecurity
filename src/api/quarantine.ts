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

interface RawQuarantineItem {
  id: string
  original_path?: string
  originalPath?: string
  file_hash?: string
  fileHash?: string
  file_size?: number
  fileSize?: number
  threat_type?: string
  threatType?: string
  threat_family?: string
  threatFamily?: string
  status: QuarantineItem['status']
  isolated_at?: string
  isolatedAt?: string
  restored_at?: string
  restoredAt?: string
  description?: string
}

/**
 * 函数名称：normalizeQuarantineItem
 * 函数作用：把后端返回的隔离区记录统一转换为前端 camelCase 数据结构。
 * English purpose: Converts backend quarantine records into the frontend camelCase shape.
 * 调用方：listQuarantine、isolateFile。
 * Called by: listQuarantine, isolateFile.
 * 被调用方：无外部服务；仅读取 RawQuarantineItem 字段。
 * Calls: No external services; reads RawQuarantineItem fields only.
 * 参数说明：item 为后端隔离区 DTO，可包含 snake_case 或兼容 camelCase 字段。
 * Parameters: item is a backend quarantine DTO and may contain snake_case or compatible camelCase fields.
 * 返回值说明：QuarantineItem；缺失可选字段保持 undefined，缺失数值字段使用 0 防止 UI 计算崩溃。
 * Returns: QuarantineItem; optional fields stay undefined and missing numeric fields use 0 to prevent UI calculation crashes.
 * 内部关键变量：originalPath、fileHash、fileSize、isolatedAt 用于统一字段命名。
 * Internal variables: originalPath, fileHash, fileSize, isolatedAt normalize field names.
 * 接入方式：仅在 API 适配层调用，不应在组件中重复做字段兼容。
 * Integration: Use only in the API adapter layer; components should not duplicate field compatibility.
 * 错误处理：不抛异常；对缺失字段提供安全默认值，由界面展示未知值。
 * Error handling: Does not throw; provides safe defaults for missing fields and lets UI show unknown values.
 * 副作用：无数据库、文件、网络或配置副作用。
 * Side effects: No database, file, network, or config side effects.
 * 事务边界：无 Unit of Work；无 commit/rollback。
 * Transaction boundary: No Unit of Work; no commit/rollback.
 * 并发与幂等：纯函数，可重复调用。
 * Concurrency and idempotency: Pure and repeatable.
 * 中文关键词：隔离区，字段归一化，snake_case，camelCase，originalPath，fileSize，页面崩溃，数据适配，前端API，类型安全
 * English keywords: quarantine, field normalization, snake_case, camelCase, originalPath, fileSize, page crash, data adapter, frontend API, type safety
 */
function normalizeQuarantineItem(item: RawQuarantineItem): QuarantineItem {
  return {
    id: item.id,
    originalPath: item.originalPath ?? item.original_path ?? '',
    fileHash: item.fileHash ?? item.file_hash ?? '',
    fileSize: item.fileSize ?? item.file_size ?? 0,
    threatType: item.threatType ?? item.threat_type,
    threatFamily: item.threatFamily ?? item.threat_family,
    status: item.status,
    isolatedAt: item.isolatedAt ?? item.isolated_at ?? '',
    restoredAt: item.restoredAt ?? item.restored_at,
    description: item.description,
  }
}

export async function listQuarantine(): Promise<QuarantineItem[]> {
  const items = await invoke<RawQuarantineItem[]>('list_quarantine')
  return items.map(normalizeQuarantineItem)
}

export async function isolateFile(
  filePath: string,
  threatType?: string
): Promise<QuarantineItem> {
  const item = await invoke<RawQuarantineItem>('isolate_file', { filePath, threatType })
  return normalizeQuarantineItem(item)
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
