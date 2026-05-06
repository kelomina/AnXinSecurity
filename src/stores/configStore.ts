import { create } from 'zustand'
import { getConfig, setBehaviorMonitoringEnabled, setProcessMonitoringEnabled, setFileMonitoringEnabled, AppConfig } from '../api/config'
import { ExclusionEntry, listExclusions, addExclusion, removeExclusion } from '../api/exclusions'
import { AllowlistEntry, listAllowlist, addToAllowlist, removeFromAllowlist } from '../api/allowlist'

type TrustItemSource = 'allowlist' | 'exclusion'

export interface TrustItemEntry {
  path: string
  entry_type: 'file' | 'directory' | 'process'
  hash?: string
  description?: string
  created_at: string
  sources: TrustItemSource[]
}

interface ConfigState {
  config: AppConfig | null
  currentPage: string
  loading: boolean
  exclusions: ExclusionEntry[]
  allowlist: AllowlistEntry[]
  trustItems: TrustItemEntry[]
  engineStatus: 'stopped' | 'running' | 'starting'
  loadConfig: () => Promise<void>
  setCurrentPage: (page: string) => void
  setBehaviorMonitoring: (enabled: boolean) => void
  setProcessMonitoring: (enabled: boolean) => void
  setFileMonitoring: (enabled: boolean) => void
  setEngineStatus: (status: 'stopped' | 'running' | 'starting') => void
  loadExclusions: () => Promise<void>
  addExclusion: (path: string, entryType: 'file' | 'directory' | 'process', description?: string) => Promise<void>
  removeExclusion: (path: string) => Promise<void>
  loadAllowlist: () => Promise<void>
  addToAllowlist: (path: string, description?: string) => Promise<void>
  removeFromAllowlist: (path: string) => Promise<void>
  loadTrustItems: () => Promise<void>
  addTrustItem: (path: string, entryType: 'file' | 'directory' | 'process', description?: string) => Promise<void>
  removeTrustItem: (path: string) => Promise<void>
}

const normalizeTrustPath = (path: string) => path.trim().replace(/\//g, '\\').toLowerCase()

/**
 * 函数名称：mergeTrustItems
 * 函数作用：把运行时排除项和启动允许列表合并为设置页展示和操作用的统一信任项目。
 * Function name: mergeTrustItems
 * Purpose: Merges runtime exclusions and startup allowlist entries into unified trust items for settings-page display and actions.
 * 调用方：configStore 的 loadExclusions、loadAllowlist、loadTrustItems。
 * Called by: configStore loadExclusions, loadAllowlist, and loadTrustItems.
 * 被调用方：normalizeTrustPath、Map。
 * Calls: normalizeTrustPath and Map.
 * 参数说明：exclusions 为排除项列表；allowlist 为启动允许列表。
 * Parameters: exclusions is the exclusion list; allowlist is the startup allowlist.
 * 返回值说明：返回按创建时间倒序排列的 TrustItemEntry 数组；同一路径会合并 sources。
 * Returns: TrustItemEntry array sorted by created_at descending; entries with the same path are merged by sources.
 * 错误处理：纯内存合并，不抛出业务错误。
 * Error handling: Pure in-memory merge and does not throw business errors.
 * 副作用：无文件、配置或网络写入。
 * Side effects: No file, config, or network writes.
 * 中文关键词：信任项目，功能合并，排除项，允许列表，路径合并，设置页，运行时列表，扫描跳过，监控跳过，去重
 * English keywords: trust item, function merge, exclusion, allowlist, path merge, settings page, runtime list, scan skip, monitor skip, deduplicate
 */
export const mergeTrustItems = (
  exclusions: ExclusionEntry[],
  allowlist: AllowlistEntry[]
): TrustItemEntry[] => {
  const mergedItems = new Map<string, TrustItemEntry>()

  for (const exclusion of exclusions) {
    mergedItems.set(normalizeTrustPath(exclusion.path), {
      path: exclusion.path,
      entry_type: exclusion.entry_type,
      description: exclusion.description,
      created_at: exclusion.created_at,
      sources: ['exclusion']
    })
  }

  for (const allowedItem of allowlist) {
    const key = normalizeTrustPath(allowedItem.path)
    const existingItem = mergedItems.get(key)

    if (existingItem) {
      mergedItems.set(key, {
        ...existingItem,
        hash: allowedItem.hash ?? existingItem.hash,
        description: existingItem.description ?? allowedItem.description,
        created_at: existingItem.created_at <= allowedItem.created_at ? existingItem.created_at : allowedItem.created_at,
        sources: existingItem.sources.includes('allowlist')
          ? existingItem.sources
          : [...existingItem.sources, 'allowlist']
      })
      continue
    }

    mergedItems.set(key, {
      path: allowedItem.path,
      entry_type: 'file',
      hash: allowedItem.hash,
      description: allowedItem.description,
      created_at: allowedItem.created_at,
      sources: ['allowlist']
    })
  }

  return Array.from(mergedItems.values()).sort((leftItem, rightItem) =>
    rightItem.created_at.localeCompare(leftItem.created_at)
  )
}

export const useConfigStore = create<ConfigState>((set, get) => ({
  config: null,
  currentPage: 'overview',
  loading: true,
  exclusions: [],
  allowlist: [],
  trustItems: [],
  engineStatus: 'stopped',

  loadConfig: async () => {
    try {
      const config = await getConfig()
      set({ config, loading: false })
    } catch (e) {
      console.error('Failed to load config:', e)
      set({ loading: false })
    }
  },

  setCurrentPage: (page: string) => {
    set({ currentPage: page })
  },

  setBehaviorMonitoring: (enabled: boolean) => {
    set((state) => {
      const cfg = state.config ?? {
        brand: '',
        themeColor: '',
        defaultPage: '',
        minimizeToTray: false,
        behaviorMonitoring: { enabled },
        processMonitoring: { enabled: true },
        fileMonitoring: { enabled: true },
        ui: { themeMode: 'system', animations: true }
      }
      return {
        config: { ...cfg, behaviorMonitoring: { enabled } }
      }
    })
    setBehaviorMonitoringEnabled(enabled).catch((e) => {
      console.error('[configStore] Failed to persist behavior monitoring:', e)
    })
  },

  setProcessMonitoring: (enabled: boolean) => {
    set((state) => {
      const cfg = state.config ?? {
        brand: '',
        themeColor: '',
        defaultPage: '',
        minimizeToTray: false,
        behaviorMonitoring: { enabled: false },
        processMonitoring: { enabled },
        fileMonitoring: { enabled: true },
        ui: { themeMode: 'system', animations: true }
      }
      return { config: { ...cfg, processMonitoring: { enabled } } }
    })
    setProcessMonitoringEnabled(enabled).catch((e) => {
      console.error('[configStore] Failed to persist process monitoring:', e)
    })
  },

  setFileMonitoring: (enabled: boolean) => {
    set((state) => {
      const cfg = state.config ?? {
        brand: '',
        themeColor: '',
        defaultPage: '',
        minimizeToTray: false,
        behaviorMonitoring: { enabled: false },
        processMonitoring: { enabled: true },
        fileMonitoring: { enabled },
        ui: { themeMode: 'system', animations: true }
      }
      return { config: { ...cfg, fileMonitoring: { enabled } } }
    })
    setFileMonitoringEnabled(enabled).catch((e) => {
      console.error('[configStore] Failed to persist file monitoring:', e)
    })
  },

  setEngineStatus: (status: 'stopped' | 'running' | 'starting') => {
    set({ engineStatus: status })
  },

  // 排除项管理
  loadExclusions: async () => {
    try {
      const exclusions = await listExclusions()
      set((state) => ({ exclusions, trustItems: mergeTrustItems(exclusions, state.allowlist) }))
    } catch (e) {
      console.error('Failed to load exclusions:', e)
    }
  },

  addExclusion: async (path: string, entryType: 'file' | 'directory' | 'process', description?: string) => {
    try {
      await addExclusion(path, entryType, description)
      await get().loadExclusions()
    } catch (e) {
      console.error('Failed to add exclusion:', e)
      throw e
    }
  },

  removeExclusion: async (path: string) => {
    try {
      await removeExclusion(path)
      await get().loadExclusions()
    } catch (e) {
      console.error('Failed to remove exclusion:', e)
      throw e
    }
  },

  // 启动允许列表管理
  loadAllowlist: async () => {
    try {
      const allowlist = await listAllowlist()
      set((state) => ({ allowlist, trustItems: mergeTrustItems(state.exclusions, allowlist) }))
    } catch (e) {
      console.error('Failed to load allowlist:', e)
    }
  },

  addToAllowlist: async (path: string, description?: string) => {
    try {
      await addToAllowlist(path, description)
      await get().loadAllowlist()
    } catch (e) {
      console.error('Failed to add to allowlist:', e)
      throw e
    }
  },

  removeFromAllowlist: async (path: string) => {
    try {
      await removeFromAllowlist(path)
      await get().loadAllowlist()
    } catch (e) {
      console.error('Failed to remove from allowlist:', e)
      throw e
    }
  },

  /**
   * 统一信任项目读取 / Unified trust-item load.
   * 调用方：SettingsPage；被调用方：listExclusions、listAllowlist、mergeTrustItems。
   * Called by: SettingsPage; calls listExclusions, listAllowlist, and mergeTrustItems.
   */
  loadTrustItems: async () => {
    try {
      const [exclusions, allowlist] = await Promise.all([listExclusions(), listAllowlist()])
      set({ exclusions, allowlist, trustItems: mergeTrustItems(exclusions, allowlist) })
    } catch (e) {
      console.error('Failed to load trust items:', e)
      throw e
    }
  },

  /**
   * 统一信任项目添加 / Unified trust-item add.
   * 文件项同时写入排除项和允许列表；目录/进程项只写入排除项，避免允许列表哈希读取目录失败。
   * File entries are written to both exclusions and allowlist; directory/process entries only use exclusions.
   */
  addTrustItem: async (
    path: string,
    entryType: 'file' | 'directory' | 'process',
    description?: string
  ) => {
    try {
      await get().loadTrustItems()
      const normalizedPath = normalizeTrustPath(path)
      const { exclusions, allowlist } = get()
      const matchedExclusion = exclusions.find((entry) => normalizeTrustPath(entry.path) === normalizedPath)
      const matchedAllowlist = allowlist.find((entry) => normalizeTrustPath(entry.path) === normalizedPath)

      if (!matchedExclusion) {
        await addExclusion(path, entryType, description)
      }

      if (entryType === 'file' && !matchedAllowlist) {
        await addToAllowlist(path, description)
      }

      await get().loadTrustItems()
    } catch (e) {
      console.error('Failed to add trust item:', e)
      throw e
    }
  },

  /**
   * 统一信任项目删除 / Unified trust-item remove.
   * 调用方：SettingsPage；被调用方：removeExclusion、removeFromAllowlist、loadTrustItems。
   * Called by: SettingsPage; calls removeExclusion, removeFromAllowlist, and loadTrustItems.
   */
  removeTrustItem: async (path: string) => {
    try {
      await get().loadTrustItems()
      const normalizedPath = normalizeTrustPath(path)
      const { exclusions, allowlist } = get()
      const matchedExclusion = exclusions.find((entry) => normalizeTrustPath(entry.path) === normalizedPath)
      const matchedAllowlist = allowlist.find((entry) => normalizeTrustPath(entry.path) === normalizedPath)

      if (matchedExclusion) {
        await removeExclusion(matchedExclusion.path)
      }

      if (matchedAllowlist) {
        await removeFromAllowlist(matchedAllowlist.path)
      }

      await get().loadTrustItems()
    } catch (e) {
      console.error('Failed to remove trust item:', e)
      throw e
    }
  }
}))
