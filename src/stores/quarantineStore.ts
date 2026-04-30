import { create } from 'zustand'
import { listQuarantine, restoreFile, deleteQuarantine, type QuarantineItem } from '../api/quarantine'

interface QuarantineState {
  items: QuarantineItem[]
  loading: boolean
  error: string | null
  selectedIds: string[]

  loadItems: () => Promise<void>
  restoreItem: (id: string) => Promise<void>
  deleteItem: (id: string) => Promise<void>
  toggleSelection: (id: string) => void
  clearSelection: () => void
  refresh: () => Promise<void>
}

export const useQuarantineStore = create<QuarantineState>((set, get) => ({
  items: [],
  loading: false,
  error: null,
  selectedIds: [],

  loadItems: async () => {
    set({ loading: true, error: null })
    try {
      const items = await listQuarantine()
      set({ items, loading: false })
    } catch (err) {
      set({ error: err instanceof Error ? err.message : '加载失败', loading: false })
    }
  },

  restoreItem: async (id: string) => {
    try {
      await restoreFile(id)
      await get().refresh()
    } catch (err) {
      set({ error: err instanceof Error ? err.message : '恢复失败' })
      throw err
    }
  },

  deleteItem: async (id: string) => {
    try {
      await deleteQuarantine(id)
      await get().refresh()
    } catch (err) {
      set({ error: err instanceof Error ? err.message : '删除失败' })
      throw err
    }
  },

  toggleSelection: (id: string) => {
    const { selectedIds } = get()
    const newIds = selectedIds.includes(id)
      ? selectedIds.filter(i => i !== id)
      : [...selectedIds, id]
    set({ selectedIds: newIds })
  },

  clearSelection: () => set({ selectedIds: [] }),

  refresh: async () => {
    await get().loadItems()
  },
}))
