import { create } from 'zustand'
import { getConfig, setBehaviorMonitoringEnabled, setProcessMonitoringEnabled, setFileMonitoringEnabled, AppConfig } from '../api/config'
import { getMonitoringRuntimeStatus, type MonitoringRuntimeStatus } from '../api/behavior'
import { ExclusionEntry, listExclusions, addExclusion, removeExclusion } from '../api/exclusions'
import { AllowlistEntry, listAllowlist, addToAllowlist, removeFromAllowlist } from '../api/allowlist'

type TrustItemSource = 'allowlist' | 'exclusion'
type MonitoringControlKey = 'behavior' | 'process' | 'file'

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
  monitoringRuntimeStatus: MonitoringRuntimeStatus | null
  monitoringControlPending: MonitoringControlKey | null
  monitoringControlError: string | null
  loadConfig: () => Promise<void>
  setCurrentPage: (page: string) => void
  refreshMonitoringRuntimeStatus: () => Promise<void>
  setBehaviorMonitoring: (enabled: boolean) => Promise<void>
  setProcessMonitoring: (enabled: boolean) => Promise<void>
  setFileMonitoring: (enabled: boolean) => Promise<void>
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

const fallbackConfig = (
  behaviorEnabled = false,
  processEnabled = true,
  fileEnabled = true
): AppConfig => ({
  brand: '',
  themeColor: '',
  defaultPage: '',
  minimizeToTray: false,
  behaviorMonitoring: { enabled: behaviorEnabled },
  processMonitoring: { enabled: processEnabled },
  fileMonitoring: { enabled: fileEnabled },
  scanner: {
    timeoutMs: 10000,
    startupSnapshotSlowWarnMs: 30000,
    startupModuleEnumerationTimeoutMs: 1000,
    startupSignatureVerifyTimeoutMs: 1000,
    startupSignatureVerifyConcurrency: 0,
    startupRevocationCheckTimeoutMs: 5000,
    startupRevocationCheckConcurrency: 4
  },
  ui: { themeMode: 'system', animations: true }
})

const monitoringErrorMessage = (label: string, error: unknown) =>
  `${label}失败：${error instanceof Error ? error.message : String(error)}`

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
  monitoringRuntimeStatus: null,
  monitoringControlPending: null,
  monitoringControlError: null,

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

  /**
   * 函数名称：refreshMonitoringRuntimeStatus
   * 函数作用：刷新前端可查询的真实监控运行态状态，当前包含 Hook 服务状态。
   * Function name: refreshMonitoringRuntimeStatus
   * Purpose: Refreshes queryable real monitoring runtime state, currently including Hook service status.
   * 调用方：OverviewPage、SettingsPage 初始化、监控开关操作完成后。
   * Called by: OverviewPage, SettingsPage initialization, after monitoring toggles complete.
   * 被调用方：getMonitoringRuntimeStatus。
   * Calls: getMonitoringRuntimeStatus.
   * 错误处理：读取失败时记录错误并把 monitoringControlError 写入 Store，供页面展示。
   * Error handling: Logs failures and writes monitoringControlError to the Store for page display.
   * 中文关键词：运行态状态，Hook状态，设置页，概览页
   * English keywords: runtime status, Hook status, settings page, overview page
   */
  refreshMonitoringRuntimeStatus: async () => {
    try {
      const monitoringRuntimeStatus = await getMonitoringRuntimeStatus()
      set({ monitoringRuntimeStatus })
    } catch (e) {
      const message = monitoringErrorMessage('刷新监控运行状态', e)
      console.error('[configStore] Failed to refresh monitoring runtime status:', e)
      set({ monitoringControlError: message })
    }
  },

  /**
   * 函数名称：setBehaviorMonitoring
   * 函数作用：切换 EDR 行为监控配置；后端配置命令同步控制 ETW resume/pause 运行态，失败时回滚 UI 配置。
   * Function name: setBehaviorMonitoring
   * Purpose: Toggles EDR behavior monitoring config; the backend config command controls ETW resume/pause runtime state and failures roll UI config back.
   * 调用方：SettingsPage EDR 行为监控开关。
   * Called by: SettingsPage EDR behavior monitoring toggle.
   * 被调用方：setBehaviorMonitoringEnabled、refreshMonitoringRuntimeStatus。
   * Calls: setBehaviorMonitoringEnabled, refreshMonitoringRuntimeStatus.
   * 参数说明：enabled 为目标开关状态。
   * Parameters: enabled is the target toggle state.
   * 错误处理：任一后端调用失败都会恢复 previousConfig，写入 monitoringControlError，并继续向上抛出异常。
   * Error handling: Any backend failure restores previousConfig, writes monitoringControlError, and rethrows.
   * 中文关键词：EDR开关，ETW控制，配置保存，失败回滚
   * English keywords: EDR toggle, ETW control, config persistence, rollback on failure
   */
  setBehaviorMonitoring: async (enabled: boolean) => {
    const previousConfig = get().config
    set((state) => {
      const cfg = state.config ?? fallbackConfig(enabled)
      return {
        config: { ...cfg, behaviorMonitoring: { enabled } },
        monitoringControlPending: 'behavior',
        monitoringControlError: null
      }
    })
    try {
      await setBehaviorMonitoringEnabled(enabled)
      await get().refreshMonitoringRuntimeStatus()
    } catch (e) {
      const message = monitoringErrorMessage(enabled ? '启动 EDR 行为监控' : '停止 EDR 行为监控', e)
      console.error('[configStore] Failed to control behavior monitoring:', e)
      set({ config: previousConfig, monitoringControlError: message })
      throw e
    } finally {
      set({ monitoringControlPending: null })
    }
  },

  /**
   * 函数名称：setProcessMonitoring
   * 函数作用：切换进程监控配置；后端配置命令同步控制 start_process_watcher/stop_process_watcher 运行态，失败时回滚 UI 配置。
   * Function name: setProcessMonitoring
   * Purpose: Toggles process monitoring config; the backend config command controls start_process_watcher/stop_process_watcher runtime state and failures roll UI config back.
   * 调用方：SettingsPage 进程监控开关。
   * Called by: SettingsPage process monitoring toggle.
   * 被调用方：setProcessMonitoringEnabled、refreshMonitoringRuntimeStatus。
   * Calls: setProcessMonitoringEnabled, refreshMonitoringRuntimeStatus.
   * 参数说明：enabled 为目标开关状态。
   * Parameters: enabled is the target toggle state.
   * 错误处理：资源路径解析或后端命令失败时恢复 previousConfig，写入 monitoringControlError，并继续向上抛出异常。
   * Error handling: Resource resolution or backend command failures restore previousConfig, write monitoringControlError, and rethrow.
   * 中文关键词：进程监控开关，start_process_watcher，stop_process_watcher，失败回滚
   * English keywords: process monitoring toggle, start_process_watcher, stop_process_watcher, rollback on failure
   */
  setProcessMonitoring: async (enabled: boolean) => {
    const previousConfig = get().config
    set((state) => {
      const cfg = state.config ?? fallbackConfig(false, enabled, true)
      return {
        config: { ...cfg, processMonitoring: { enabled } },
        monitoringControlPending: 'process',
        monitoringControlError: null
      }
    })
    try {
      await setProcessMonitoringEnabled(enabled)
      await get().refreshMonitoringRuntimeStatus()
    } catch (e) {
      const message = monitoringErrorMessage(enabled ? '启动进程监控' : '停止进程监控', e)
      console.error('[configStore] Failed to control process monitoring:', e)
      set({ config: previousConfig, monitoringControlError: message })
      throw e
    } finally {
      set({ monitoringControlPending: null })
    }
  },

  /**
   * 函数名称：setFileMonitoring
   * 函数作用：切换文件监控配置；后端配置命令同步控制 FileMonitor 与共享 Hook 命名管道，失败时回滚 UI 配置。
   * Function name: setFileMonitoring
   * Purpose: Toggles file monitoring config; the backend config command controls FileMonitor and the shared Hook named pipe, and failures roll UI config back.
   * 调用方：SettingsPage 文件监控开关。
   * Called by: SettingsPage file monitoring toggle.
   * 被调用方：setFileMonitoringEnabled、refreshMonitoringRuntimeStatus。
   * Calls: setFileMonitoringEnabled, refreshMonitoringRuntimeStatus.
   * 参数说明：enabled 为目标开关状态。
   * Parameters: enabled is the target toggle state.
   * 错误处理：配置保存或 Hook 控制失败时恢复 previousConfig，写入 monitoringControlError，并继续向上抛出异常。
   * Error handling: Config persistence or Hook control failures restore previousConfig, write monitoringControlError, and rethrow.
   * 中文关键词：文件监控开关，Hook服务，file-hook-event，失败回滚
   * English keywords: file monitoring toggle, Hook service, file-hook-event, rollback on failure
   */
  setFileMonitoring: async (enabled: boolean) => {
    const previousConfig = get().config
    set((state) => {
      const cfg = state.config ?? fallbackConfig(false, true, enabled)
      return {
        config: { ...cfg, fileMonitoring: { enabled } },
        monitoringControlPending: 'file',
        monitoringControlError: null
      }
    })
    try {
      await setFileMonitoringEnabled(enabled)
      await get().refreshMonitoringRuntimeStatus()
    } catch (e) {
      const message = monitoringErrorMessage(enabled ? '启动文件监控' : '停止文件监控', e)
      console.error('[configStore] Failed to control file monitoring:', e)
      set({ config: previousConfig, monitoringControlError: message })
      throw e
    } finally {
      set({ monitoringControlPending: null })
    }
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
