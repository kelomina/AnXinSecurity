import { create } from 'zustand'
import { getConfig, setBehaviorMonitoringEnabled, setProcessMonitoringEnabled, setFileMonitoringEnabled, AppConfig } from '../api/config'
import { ExclusionEntry, listExclusions, addExclusion, removeExclusion } from '../api/exclusions'
import { AllowlistEntry, listAllowlist, addToAllowlist, removeFromAllowlist } from '../api/allowlist'

interface ConfigState {
  config: AppConfig | null
  currentPage: string
  loading: boolean
  exclusions: ExclusionEntry[]
  allowlist: AllowlistEntry[]
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
}

export const useConfigStore = create<ConfigState>((set, get) => ({
  config: null,
  currentPage: 'overview',
  loading: true,
  exclusions: [],
  allowlist: [],
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
      set({ exclusions })
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
      set({ allowlist })
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
  }
}))
