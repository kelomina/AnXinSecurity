/**
 * 隔离区状态管理 Store
 * Quarantine state management store
 *
 * 管理隔离区文件的加载、恢复、删除和选择状态。
 * Manages quarantine file loading, restoring, deleting, and selection state.
 */
import { create } from 'zustand'
import { listQuarantine, restoreFile, deleteQuarantine, type QuarantineItem } from '../api/quarantine'

interface QuarantineState {
  items: QuarantineItem[]
  loading: boolean
  error: string | null
  selectedIds: string[]
  searchQuery: string

  loadItems: () => Promise<void>
  restoreItem: (id: string) => Promise<void>
  deleteItem: (id: string) => Promise<void>
  batchRestore: () => Promise<void>
  batchDelete: () => Promise<void>
  toggleSelection: (id: string) => void
  selectAll: () => void
  clearSelection: () => void
  setSearchQuery: (query: string) => void
  refresh: () => Promise<void>
  clearError: () => void
}

/**
 * 获取过滤后的项目（根据搜索/状态）
 * Get filtered items (by search query)
 */
const getFilteredItems = (items: QuarantineItem[], query: string) => {
  if (!query.trim()) return items
  const lower = query.toLowerCase()
  return items.filter(item =>
    item.originalPath.toLowerCase().includes(lower) ||
    (item.threatType && item.threatType.toLowerCase().includes(lower))
  )
}

export const useQuarantineStore = create<QuarantineState>((set, get) => ({
  items: [],
  loading: false,
  error: null,
  selectedIds: [],
  searchQuery: '',

  /**
   * 函数名称：loadItems
   * 函数作用：从后端加载隔离区文件列表。
   * Purpose: Loads quarantine file list from backend.
   * 调用方：QuarantinePage useEffect / 各类操作后刷新
   * Called by: QuarantinePage useEffect / refresh after operations
   * 中文关键词：加载列表，刷新隔离区，获取数据
   * English keywords: load list, refresh quarantine, fetch data
   */
  loadItems: async () => {
    set({ loading: true, error: null })
    try {
      const items = await listQuarantine()
      set({ items, loading: false })
    } catch (err) {
      set({ error: err instanceof Error ? err.message : '加载失败', loading: false })
    }
  },

  /**
   * 函数名称：restoreItem
   * 函数作用：恢复单个隔离文件到原始位置。
   * Purpose: Restores a single quarantined file to its original location.
   * 调用方：QuarantinePage 恢复按钮
   * Called by: QuarantinePage restore button
   * 中文关键词：恢复文件，还原隔离，单个恢复
   * English keywords: restore file, undo quarantine, single restore
   */
  restoreItem: async (id: string) => {
    try {
      await restoreFile(id)
      await get().refresh()
    } catch (err) {
      set({ error: err instanceof Error ? err.message : '恢复失败' })
      throw err
    }
  },

  /**
   * 函数名称：deleteItem
   * 函数作用：安全删除单个隔离文件。
   * Purpose: Securely deletes a single quarantined file.
   * 调用方：QuarantinePage 删除按钮
   * Called by: QuarantinePage delete button
   * 中文关键词：删除文件，安全擦除，单个删除
   * English keywords: delete file, secure wipe, single delete
   */
  deleteItem: async (id: string) => {
    try {
      await deleteQuarantine(id)
      await get().refresh()
    } catch (err) {
      set({ error: err instanceof Error ? err.message : '删除失败' })
      throw err
    }
  },

  /**
   * 函数名称：batchRestore
   * 函数作用：批量恢复选中的隔离文件。逐个串行执行，单个失败不影响后续。
   * Purpose: Batch restores selected quarantined files. Serial execution, one failure doesn't affect others.
   * 调用方：QuarantinePage 批量恢复按钮
   * Called by: QuarantinePage batch restore button
   * 中文关键词：批量恢复，选中恢复，批量操作
   * English keywords: batch restore, selected restore, batch operation
   */
  batchRestore: async () => {
    const { selectedIds } = get()
    let errorCount = 0
    for (const id of selectedIds) {
      try {
        await restoreFile(id)
      } catch (err) {
        console.error(`Failed to restore ${id}:`, err)
        errorCount++
      }
    }
    if (errorCount > 0) {
      set({ error: `${errorCount} 个文件恢复失败` })
    }
    await get().refresh()
    set({ selectedIds: [] })
  },

  /**
   * 函数名称：batchDelete
   * 函数作用：批量安全删除选中的隔离文件。逐个串行执行。
   * Purpose: Batch securely deletes selected quarantined files. Serial execution.
   * 调用方：QuarantinePage 批量删除按钮
   * Called by: QuarantinePage batch delete button
   * 中文关键词：批量删除，批量安全擦除，选中删除
   * English keywords: batch delete, batch secure wipe, selected delete
   */
  batchDelete: async () => {
    const { selectedIds } = get()
    let errorCount = 0
    for (const id of selectedIds) {
      try {
        await deleteQuarantine(id)
      } catch (err) {
        console.error(`Failed to delete ${id}:`, err)
        errorCount++
      }
    }
    if (errorCount > 0) {
      set({ error: `${errorCount} 个文件删除失败` })
    }
    await get().refresh()
    set({ selectedIds: [] })
  },

  /**
   * 切换单个项目选择 / Toggle single item selection
   */
  toggleSelection: (id: string) => {
    const { selectedIds } = get()
    const newIds = selectedIds.includes(id)
      ? selectedIds.filter(i => i !== id)
      : [...selectedIds, id]
    set({ selectedIds: newIds })
  },

  /**
   * 全选当前过滤结果 / Select all filtered items
   */
  selectAll: () => {
    const { items, searchQuery } = get()
    const filtered = getFilteredItems(items, searchQuery)
    set({ selectedIds: filtered.map(i => i.id) })
  },

  clearSelection: () => set({ selectedIds: [] }),

  setSearchQuery: (query: string) => set({ searchQuery: query }),

  refresh: async () => {
    await get().loadItems()
  },

  clearError: () => set({ error: null }),
}))
