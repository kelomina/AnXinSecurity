const { contextBridge, ipcRenderer } = require('electron')
const fs = require('fs')
const path = require('path')
const os = require('os')
const ExclusionsManager = require('./exclusions_manager')
const fsAsync = require('./fs_async')
const scanCache = require('./scan_cache')


function loadConfig() {
  const p = path.join(__dirname, '../../config/app.json')
  try {
    const raw = fs.readFileSync(p, 'utf-8')
    return JSON.parse(raw)
  } catch {
    return {
      brand: 'AnXin Security',
      themeColor: '#1677ff',
      defaultPage: 'overview',
      minimizeToTray: true,
      tray: { exitKeepScannerServicePrompt: true, exitKeepScannerServiceDefault: true },
      ui: { animations: true, window: { minWidth: 400, minHeight: 800 } },
      engine: { autoStart: true, exeRelativePath: 'Engine\\Axon_v2\\Axon_ml.exe', processName: 'Axon_ml.exe', args: [], exitTimeoutMs: 1000 },
      scanner: {
        timeoutMs: 10000,
        healthPollIntervalMs: 30000,
        tuningEnabled: true,
        maxTokens: 16,
        ipc: { enabled: true, prefer: true, host: '127.0.0.1', port: 8765, connectTimeoutMs: 500, timeoutMs: 10000 },
        tuning: {
          fastLatencyMs: 300,
          slowLatencyMs: 1000,
          minPoolSize: 8,
          maxPoolSize: 256,
          minRatePerSecond: 8,
          maxRatePerSecond: 256,
          adjustStep: 4
        }
      },
      scan: {
        traversalTimeoutMs: 2000,
        walkerBatchSize: 256,
        rulesFile: 'config/scan_rules.json',
        cachePersistIntervalMs: 1000,
        metricsUpdateIntervalMs: 200,
        uiYieldEveryFiles: 25,
        queueCompactionThreshold: 5000
      },
      scan_cache: {
        file: 'config/scan_cache.json'
      },
      behaviorMonitoring: { enabled: false },
      behaviorAnalyzer: { enabled: true, flushIntervalMs: 500, sqlite: { mode: 'file', directory: '%TEMP%', fileName: 'anxin_etw_behavior.db' } }
    }
  }
}

let cfg = loadConfig()
function saveConfig() {
  try {
    const p = path.join(__dirname, '../../config/app.json')
    fs.writeFileSync(p, JSON.stringify(cfg, null, 2), 'utf-8')
    try { ipcRenderer.send('config-updated', cfg) } catch {}
  } catch {}
}

function loadI18n() {
  try {
    const locale = (cfg && cfg.locale) ? cfg.locale : 'zh-CN'
    const p = path.join(__dirname, `../../config/i18n/${locale}.json`)
    const raw = fs.readFileSync(p, 'utf-8')
    return JSON.parse(raw)
  } catch {
    try {
      const fallback = path.join(__dirname, '../../config/i18n/zh-CN.json')
      const raw = fs.readFileSync(fallback, 'utf-8')
      return JSON.parse(raw)
    } catch {
      return {}
    }
  }
}

let i18nDict = loadI18n()
let walkers = {}
let walkerSeq = 1

function getAppRoot() {
  try {
    return path.resolve(__dirname, '..', '..')
  } catch {
    return ''
  }
}

const exclusionsManager = new ExclusionsManager(
  path.join(__dirname, '../../config/app.json'),
  [
    getAppRoot(),
    'C:\\Program Files\\WindowsApps'
  ]
)

function getScanExcludeList() {
  const list = []
  try {
    const imm = exclusionsManager.getImmutableDirs()
    imm.forEach(p => { if (p) list.push({ type: 'dir', path: p }) })
  } catch {}
  try {
    const dyn = exclusionsManager.getList()
    dyn.forEach(it => {
      if (it && it.path) list.push({ type: it.type === 'dir' ? 'dir' : 'file', path: it.path })
    })
  } catch {}
  return list
}

const api = {
  config: {
    get: () => cfg,
    setLocale: (locale) => {
      if (typeof locale !== 'string' || !locale) return
      cfg.locale = locale
      saveConfig()
      i18nDict = loadI18n()
    },
    setTuningEnabled: (enabled) => {
      cfg.scanner = cfg.scanner || {}
      cfg.scanner.tuningEnabled = !!enabled
      saveConfig()
    },
    setBehaviorMonitoringEnabled: (enabled) => {
      cfg.behaviorMonitoring = cfg.behaviorMonitoring || {}
      cfg.behaviorMonitoring.enabled = !!enabled
      saveConfig()
    },
    setMaxTokens: (n) => {
      const v = parseInt(n, 10)
      if (!Number.isFinite(v)) return
      const clamped = Math.max(1, Math.min(256, v))
      cfg.scanner = cfg.scanner || {}
      cfg.scanner.maxTokens = clamped
      saveConfig()
    },
    setMaxFileSizeMB: (n) => {
      const v = parseInt(n, 10)
      if (!Number.isFinite(v)) return
      const clamped = Math.max(1, Math.min(10240, v))
      cfg.scanner = cfg.scanner || {}
      cfg.scanner.maxFileSizeMB = clamped
      saveConfig()
    }
  },
  scanner: {
    health: async () => {
      return ipcRenderer.invoke('scanner:health')
    },
    scanFile: async (filePath, options) => {
      const opts = options && typeof options === 'object' ? options : {}
      return ipcRenderer.invoke('scanner:scanFile', { filePath, requestId: opts.requestId || '' })
    },
    abort: async (requestId) => {
      return ipcRenderer.invoke('scanner:abort', requestId || '')
    }
  },
  i18n: {
    t: (key) => i18nDict[key] || key,
    getLocale: () => (cfg && cfg.locale) ? cfg.locale : 'zh-CN'
  },
  ui: {
    debug: (tag, payload) => { try { ipcRenderer.send('ui-debug', { tag, payload }) } catch {} }
  },
  trayExitPrompt: {
    submit: (requestId, keep) => {
      const id = typeof requestId === 'string' ? requestId : ''
      if (!id) return
      const v = keep === true ? true : (keep === false ? false : null)
      try { ipcRenderer.send('tray-exit-prompt:submit', { requestId: id, keep: v }) } catch {}
    }
  },
  system: {
    cpuUsage: () => process.cpuUsage(),
    cpuCount: () => os.cpus().length,
    getRunningProcesses: () => {
      return ipcRenderer.invoke('system-get-running-processes')
    }
  },
  resolvePath: (p) => {
    if (!p) return ''
    return p.replace(/%([^%]+)%/g, (_, n) => process.env[n] || '')
  },
  fs: {
    isDirectory: (p) => {
      try {
        return fs.statSync(p).isDirectory()
      } catch {
        return false
      }
    },
    fileSize: (p) => {
      try {
        const st = fs.statSync(p)
        return st.size
      } catch {
        return -1
      }
    },
    listDriveRoots: () => {
      const roots = []
      const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
      for (let i = 0; i < letters.length; i++) {
        const root = letters[i] + ':\\'
        try {
          if (fs.existsSync(root)) {
            roots.push(root)
          }
        } catch {}
      }
      roots.sort((a, b) => a.localeCompare(b))
      return roots
    },
    createWalker: (root) => {
      const id = walkerSeq++
      walkers[id] = { stack: [root] }
      return id
    },
    walkerNext: (id, limit) => {
      const w = walkers[id]
      if (!w) return { files: [], done: true }
      const out = []
      const lim = Number.isFinite(limit) ? Math.max(1, limit) : 1024
      while (out.length < lim && w.stack.length > 0) {
        const d = w.stack.pop()
        let entries
        try {
          entries = fs.readdirSync(d, { withFileTypes: true })
        } catch {
          entries = null
        }
        if (!entries) continue
        for (const e of entries) {
          const full = path.join(d, e.name)
          if (e.isDirectory()) {
            w.stack.push(full)
          } else {
            out.push(full)
            if (out.length >= lim) break
          }
        }
      }
      const done = w.stack.length === 0
      if (done) delete walkers[id]
      return { files: out, done }
    },
    destroyWalker: (id) => {
      if (walkers[id]) delete walkers[id]
    },
    listFilesRecursively: (dir, maxCount) => {
      const out = []
      const stack = [dir]
      while (stack.length) {
        const d = stack.pop()
        let entries
        try {
          entries = fs.readdirSync(d, { withFileTypes: true })
        } catch {
          continue
        }
        for (const e of entries) {
          const full = path.join(d, e.name)
          if (e.isDirectory()) stack.push(full)
          else out.push(full)
          if (maxCount && out.length >= maxCount) return out
        }
      }
      return out
    }
  },
  fsAsync: {
    isDirectory: (p) => fsAsync.isDirectory(p),
    fileSize: (p) => fsAsync.fileSize(p),
    listFilesRecursively: (dir, maxCount) => fsAsync.listFilesRecursively(dir, maxCount),
    listDriveRoots: () => fsAsync.listDriveRoots(),
    createWalker: (roots) => fsAsync.createWalker(roots, { excludeList: getScanExcludeList() }),
    walkerNext: (id, limit) => fsAsync.walkerNext(id, limit),
    destroyWalker: (id) => fsAsync.destroyWalker(id)
  },
  scanRules: {
    load: async () => {
      const rel = cfg && cfg.scan && typeof cfg.scan.rulesFile === 'string' ? cfg.scan.rulesFile : 'config/scan_rules.json'
      const p = path.resolve(__dirname, '../..', rel)
      try {
        const raw = await fs.promises.readFile(p, 'utf-8')
        return JSON.parse(raw)
      } catch {
        return null
      }
    }
  },
  scanCache: {
    restore: () => scanCache.restore(cfg),
    saveCurrent: (session) => scanCache.saveCurrent(cfg, session),
    clearCurrent: () => scanCache.clearCurrent(cfg),
    markHandled: (handledAt) => scanCache.markHandled(cfg, handledAt),
    clearAll: () => scanCache.clearAll(cfg)
  },
  dialog: {
    openFile: async () => {
      console.log('预加载: 请求打开文件选择框')
      return ipcRenderer.invoke('open-file-dialog')
    },
    openDirectory: async () => {
      console.log('预加载: 请求打开目录选择框')
      return ipcRenderer.invoke('open-directory-dialog')
    }
  },
  logs: {
    list: () => ipcRenderer.invoke('logs:list'),
    onLog: (callback) => {
      const handler = (event, data) => callback(data)
      ipcRenderer.on('etw-log', handler)
      return () => ipcRenderer.removeListener('etw-log', handler)
    }
  },
  intercept: {
    onShow: (callback) => {
      const handler = (_event, data) => callback(data)
      ipcRenderer.on('intercept:show', handler)
      return () => ipcRenderer.removeListener('intercept:show', handler)
    }
  },
  process: {
    suspend: (pid) => ipcRenderer.invoke('process-suspend', pid),
    resume: (pid) => ipcRenderer.invoke('process-resume', pid),
    terminate: (pid) => ipcRenderer.invoke('process-terminate', pid)
  },
  behavior: {
    getDbPath: () => ipcRenderer.invoke('behavior-get-db-path'),
    listProcesses: (query) => ipcRenderer.invoke('behavior-list-processes', query || {}),
    listEvents: (query) => ipcRenderer.invoke('behavior-list-events', query || {}),
    clearAll: () => ipcRenderer.invoke('behavior-clear-all'),
    pauseEtw: () => ipcRenderer.invoke('behavior-pause-etw'),
    clearDb: () => ipcRenderer.invoke('behavior-clear-db'),
    resumeEtw: () => ipcRenderer.invoke('behavior-resume-etw')
  },
  quarantine: {
    list: () => {
      console.log('预加载: 请求获取隔离列表')
      return ipcRenderer.invoke('quarantine-list')
    },
    isolate: async (filePath) => {
      console.log('预加载: 请求隔离文件', filePath)
      return ipcRenderer.invoke('quarantine-isolate', filePath)
    },
    restore: async (id) => {
      console.log('预加载: 请求恢复文件', id)
      return ipcRenderer.invoke('quarantine-restore', id)
    },
    delete: async (id) => {
      console.log('预加载: 请求删除隔离记录', id)
      return ipcRenderer.invoke('quarantine-delete', id)
    }
  },
  exclusions: {
    list: () => exclusionsManager.getList(),
    addFile: (p) => exclusionsManager.addFile(p),
    addDir: (p) => exclusionsManager.addDir(p),
    remove: (p) => exclusionsManager.remove(p),
    isExcluded: (p) => exclusionsManager.isExcluded(p),
    getImmutableDirs: () => exclusionsManager.getImmutableDirs()
  },

}

contextBridge.exposeInMainWorld('api', api)
module.exports = api
