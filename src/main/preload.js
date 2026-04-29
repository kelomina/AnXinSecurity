const { contextBridge, ipcRenderer, crashReporter, app } = require('electron')
const fs = require('fs')
const path = require('path')
const ExclusionsManager = require('./exclusions_manager')
const fsAsync = require('./fs_async')
const scanCache = require('./scan_cache')


/**
 * - 函数: `loadConfig`
 * - Function: `loadConfig`
 * - 作用: 读取预加载层使用的应用配置文件，并在配置缺失或损坏时回退到内置默认配置，保证渲染层桥接 API 可以稳定启动。
 * - Purpose: Reads the application config consumed by the preload layer and falls back to an embedded default config when the file is missing or broken, ensuring renderer bridge APIs can still boot reliably.
 * - 调用方: 模块初始化阶段通过 `let cfg = loadConfig()` 调用本函数加载当前配置快照。
 * - Callers: The module initialization path calls it through `let cfg = loadConfig()` to load the current config snapshot.
 * - 被调方: `path.join`、`fs.readFileSync`、`JSON.parse`。
 * - Callees: `path.join`, `fs.readFileSync`, and `JSON.parse`.
 * - 变量说明: 无显式入参；`p` 为配置文件绝对路径；`raw` 为原始 JSON 文本；返回值为配置对象。
 * - Variables: There are no explicit parameters; `p` is the absolute config path, `raw` is the raw JSON text, and the return value is the config object.
 * - 接入方式: 预加载层若需要重新加载整份配置，应继续复用本函数，而不是在多个位置重复拼接 `config/app.json`。
 * - Integration: If the preload layer needs to reload the full config later, it should reuse this helper instead of rebuilding the `config/app.json` lookup in multiple places.
 * - 错误处理: 配置读取或解析失败时返回内置默认配置对象，不抛异常阻断渲染层注入。
 * - Error Handling: Config read or parse failures return the embedded default object instead of throwing and blocking renderer injection.
 * - 关键词: 预加载配置装载 | preload config load | 默认配置回退 | default config fallback | 渲染桥接初始化 | renderer bridge bootstrap | app.json读取 | app.json read | 配置容错 | config fault tolerance
 */
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
      ui: { animations: true, themeMode: 'system', window: { minWidth: 400, minHeight: 800 } },
      engine: { autoStart: false, exeRelativePath: "", processName: "", args: [], exitTimeoutMs: 1000 },
      scanner: {
        timeoutMs: 10000,
        healthPollIntervalMs: 30000,
        tuningEnabled: true,
        maxTokens: 16,
        nativeDll: { enabled: true, prefer: true },
        ipc: { enabled: false, prefer: false, host: '127.0.0.1', port: 8765, connectTimeoutMs: 500, timeoutMs: 10000 },
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
        commonExtensionsOnly: false,
        cachePersistIntervalMs: 1000,
        metricsUpdateIntervalMs: 200,
        uiYieldEveryFiles: 25,
        queueCompactionThreshold: 5000
      },
      scan_cache: {
        file: 'config/scan_cache.json'
      },
      behaviorMonitoring: { enabled: false },
      behaviorAnalyzer: { enabled: true, flushIntervalMs: 500, sqlite: { mode: 'file', directory: 'data/behavior', fileName: 'anxin_etw_behavior.db' } }
    }
  }
}

let cfg = loadConfig()

/**
 * - 函数: `resolveCrashDir`
 * - Function: `resolveCrashDir`
 * - 作用: 解析并准备渲染进程崩溃转储目录，确保 crash reporter 在本地写盘时有稳定目录可用。
 * - Purpose: Resolves and prepares the renderer crash-dump directory so the crash reporter always has a stable local destination.
 * - 调用方: `startRendererCrashReporter`。
 * - Callers: `startRendererCrashReporter`.
 * - 被调方: `path.join`、`fs.existsSync`、`fs.mkdirSync`。
 * - Callees: `path.join`, `fs.existsSync`, and `fs.mkdirSync`.
 * - 变量说明: 无显式入参；`base` 为项目根目录；`dir` 为最终崩溃日志目录。
 * - Variables: There are no explicit parameters; `base` is the project root and `dir` is the final crash-log directory.
 * - 接入方式: 任何需要定位本地 crash dump 存储目录的预加载逻辑都应复用本函数。
 * - Integration: Any preload logic that needs the local crash-dump storage directory should reuse this helper.
 * - 错误处理: 创建目录失败会被静默吞掉，但函数仍返回目标路径，让上层决定后续行为。
 * - Error Handling: Directory-creation failures are swallowed silently, but the function still returns the target path so callers can decide what to do next.
 * - 关键词: 崩溃转储目录 | crash dump directory | 渲染进程日志 | renderer crash logs | 本地写盘路径 | local dump path | 目录预创建 | directory precreation | crash reporter 基础路径 | crash reporter base path
 */
function resolveCrashDir() {
  const base = path.join(__dirname, '../../')
  const dir = path.join(base, 'data', 'logs', 'crash')
  try { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }) } catch {}
  return dir
}

/**
 * - 函数: `startRendererCrashReporter`
 * - Function: `startRendererCrashReporter`
 * - 作用: 在预加载阶段为渲染进程初始化本地 crash reporter，并把崩溃输出路径同时同步到 Electron 与环境变量。
 * - Purpose: Initializes the local renderer crash reporter during preload startup and synchronizes the crash-output directory into both Electron and the environment.
 * - 调用方: 模块加载后立即通过 `startRendererCrashReporter()` 执行一次初始化。
 * - Callers: It is invoked immediately once during module load through `startRendererCrashReporter()`.
 * - 被调方: `resolveCrashDir`、`app.setPath`、`crashReporter.start`。
 * - Callees: `resolveCrashDir`, `app.setPath`, and `crashReporter.start`.
 * - 变量说明: 无显式入参；`dir` 为最终使用的崩溃目录。
 * - Variables: There are no explicit parameters; `dir` is the crash directory used by the reporter.
 * - 接入方式: 预加载层仅应在启动时执行一次；如果以后需要开关控制，也应继续以本函数为初始化入口。
 * - Integration: The preload layer should run this only once at startup; if on/off control is added later, keep this helper as the initialization entry.
 * - 错误处理: 外围和局部调用都包在 `try/catch` 中，启动失败不会阻断预加载脚本继续暴露 API。
 * - Error Handling: Both outer and inner calls are wrapped in `try/catch`, so reporter startup failures do not block the preload script from exposing APIs.
 * - 关键词: 渲染进程崩溃上报 | renderer crash reporting | preload初始化 | preload initialization | crashReporter.start | 崩溃目录同步 | crash directory sync | Electron路径设置 | Electron path setup
 */
function startRendererCrashReporter() {
  try {
    const dir = resolveCrashDir()
    try { if (app && typeof app.setPath === 'function') app.setPath('crashDumps', dir) } catch {}
    try { process.env.ELECTRON_CRASH_REPORTER_DIRECTORY = dir } catch {}
    crashReporter.start({
      submitURL: '',
      uploadToServer: false,
      compress: true,
      crashesDirectory: dir
    })
  } catch {}
}

startRendererCrashReporter()
/**
 * - 函数: `saveConfig`
 * - Function: `saveConfig`
 * - 作用: 将当前预加载内存中的配置快照写回 `config/app.json`，并通知主进程或其他订阅方配置已更新。
 * - Purpose: Persists the current preload-side config snapshot back to `config/app.json` and notifies the main process or other subscribers that config changed.
 * - 调用方: `api.config` 下的多个设置接口在修改 `cfg` 后都会调用本函数。
 * - Callers: Multiple setters under `api.config` call this helper after mutating `cfg`.
 * - 被调方: `path.join`、`fs.writeFileSync`、`JSON.stringify`、`ipcRenderer.send`。
 * - Callees: `path.join`, `fs.writeFileSync`, `JSON.stringify`, and `ipcRenderer.send`.
 * - 变量说明: 无显式入参；`p` 为配置文件路径；`cfg` 为闭包内维护的当前配置对象。
 * - Variables: There are no explicit parameters; `p` is the config-file path and `cfg` is the closure-level config object being persisted.
 * - 接入方式: 预加载层内所有配置写回都应通过本函数收口，保证持久化和更新通知行为一致。
 * - Integration: All preload-side config persistence should funnel through this helper so file writes and update notifications remain consistent.
 * - 错误处理: 写盘或通知失败会被吞掉，避免渲染层设置面板因 I/O 异常直接崩溃。
 * - Error Handling: File-write and notification failures are swallowed so renderer-side settings panels do not crash on I/O issues.
 * - 关键词: 配置写回 | config persistence | app.json保存 | app.json save | 配置更新通知 | config updated event | preload设置保存 | preload settings save | 闭包配置快照 | closure config snapshot
 */
function saveConfig() {
  try {
    const p = path.join(__dirname, '../../config/app.json')
    fs.writeFileSync(p, JSON.stringify(cfg, null, 2), 'utf-8')
    try { ipcRenderer.send('config-updated', cfg) } catch {}
  } catch {}
}

/**
 * - 函数: `loadI18n`
 * - Function: `loadI18n`
 * - 作用: 根据当前配置语言加载对应多语言词典，并在目标语言缺失时回退到 `zh-CN`。
 * - Purpose: Loads the locale dictionary selected by current config and falls back to `zh-CN` when the requested language is unavailable.
 * - 调用方: 模块初始化阶段和 `api.config.setLocale()` 修改语言后都会调用本函数。
 * - Callers: Used during module initialization and again after `api.config.setLocale()` changes the current locale.
 * - 被调方: `path.join`、`fs.readFileSync`、`JSON.parse`。
 * - Callees: `path.join`, `fs.readFileSync`, and `JSON.parse`.
 * - 变量说明: 无显式入参；`locale` 为当前配置语言；`p` 为目标语言包路径；`fallback` 为中文回退语言包路径；`raw` 为原始 JSON 文本。
 * - Variables: There are no explicit parameters; `locale` is the configured locale, `p` is the target dictionary path, `fallback` is the Chinese fallback dictionary path, and `raw` is the raw JSON text.
 * - 接入方式: 渲染层若需要重新装载词典，应继续通过更新 `cfg.locale` 后调用本函数，而不是直接修改 `i18nDict`。
 * - Integration: If the renderer needs to reload dictionaries later, it should update `cfg.locale` and call this helper instead of mutating `i18nDict` directly.
 * - 错误处理: 目标语言包读取失败时回退中文；中文也失败时返回空对象，保证 `i18n.t()` 至少可回退 key。
 * - Error Handling: If the requested locale file fails, it falls back to Chinese; if that also fails, it returns an empty object so `i18n.t()` can still fall back to raw keys.
 * - 关键词: 多语言词典装载 | i18n dictionary load | locale回退 | locale fallback | zh-CN默认语言 | zh-CN default locale | 预加载翻译表 | preload translation table | 配置切换语言 | config locale switch
 */
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

/**
 * - 函数: `getAppRoot`
 * - Function: `getAppRoot`
 * - 作用: 返回应用项目根目录，供排除目录、扫描规则和其他基于相对路径的预加载逻辑统一定位。
 * - Purpose: Returns the application project root so exclusion lists, scan rules, and other relative-path preload flows can resolve from one shared anchor.
 * - 调用方: `ExclusionsManager` 初始化逻辑以及其他需要项目根目录的预加载辅助流程。
 * - Callers: Used by `ExclusionsManager` initialization and other preload helpers that need the project root.
 * - 被调方: `path.resolve`。
 * - Callees: `path.resolve`.
 * - 变量说明: 无显式入参；返回值为项目根目录绝对路径，失败时回退为空字符串。
 * - Variables: There are no explicit parameters; the return value is the absolute project root path and falls back to an empty string on failure.
 * - 接入方式: 预加载层若要从项目根目录派生其他路径，应优先复用本函数。
 * - Integration: Any preload logic that derives further paths from the project root should reuse this helper first.
 * - 错误处理: `path.resolve` 异常时返回空字符串，不向上抛出。
 * - Error Handling: It returns an empty string if `path.resolve` throws and does not rethrow the exception.
 * - 关键词: 应用根目录 | app root | 预加载基础路径 | preload base path | 相对路径锚点 | relative path anchor | 排除目录初始化 | exclusion bootstrap | 根目录解析 | root path resolution
 */
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

/**
 * - 函数: `getScanExcludeList`
 * - Function: `getScanExcludeList`
 * - 作用: 合并不可变排除目录与用户动态排除项，生成给异步文件遍历器使用的扫描排除列表。
 * - Purpose: Merges immutable exclusion directories with user-defined dynamic exclusions to build the scan exclusion list consumed by the async file walker.
 * - 调用方: `api.fsAsync.createWalker()` 会调用本函数把排除清单传给 `fs_async`。
 * - Callers: `api.fsAsync.createWalker()` calls this helper to pass the exclusion list into `fs_async`.
 * - 被调方: `exclusionsManager.getImmutableDirs`、`exclusionsManager.getList`、数组 `forEach`、数组 `push`。
 * - Callees: `exclusionsManager.getImmutableDirs`, `exclusionsManager.getList`, array `forEach`, and array `push`.
 * - 变量说明: 无显式入参；`list` 为最终排除项数组；`imm` 为不可变目录列表；`dyn` 为动态排除列表；`it` 为动态排除项。
 * - Variables: There are no explicit parameters; `list` is the final exclusion array, `imm` is the immutable directory list, `dyn` is the dynamic exclusion list, and `it` is a dynamic exclusion entry.
 * - 接入方式: 任何需要给扫描或遍历逻辑提供统一排除列表的预加载函数都应复用本函数。
 * - Integration: Any preload helper that needs a unified exclusion list for scanning or traversal should reuse this function.
 * - 错误处理: 获取不可变目录或动态列表失败时分别静默跳过，尽量返回已有可用排除项。
 * - Error Handling: Failures while loading immutable or dynamic exclusions are skipped independently so the function returns whatever valid exclusions remain.
 * - 关键词: 扫描排除列表 | scan exclusion list | 不可变目录 | immutable directories | 动态排除项 | dynamic exclusions | walker过滤输入 | walker filter input | exclusionsManager聚合 | exclusionsManager aggregation
 */
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
    },
    setScanCommonExtensionsOnly: (enabled) => {
      cfg.scan = cfg.scan || {}
      cfg.scan.commonExtensionsOnly = !!enabled
      saveConfig()
    },
    setUiAnimationsEnabled: (enabled) => {
      cfg.ui = cfg.ui || {}
      cfg.ui.animations = !!enabled
      saveConfig()
    },
    setThemeMode: (mode) => {
      const m = typeof mode === 'string' ? mode.trim() : ''
      if (m !== 'system' && m !== 'dark' && m !== 'light') return
      cfg.ui = cfg.ui || {}
      cfg.ui.themeMode = m
      saveConfig()
    }
  },
  devSettings: {
    unlock: async (password) => {
      return ipcRenderer.invoke('dev-settings:unlock', { password: password || '' })
    },
    save: async (password, data) => {
      return ipcRenderer.invoke('dev-settings:save', { password: password || '', data: data || {} })
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
    scanBatch: async (filePaths, options) => {
      const opts = options && typeof options === 'object' ? options : {}
      return ipcRenderer.invoke('scanner:scanBatch', { filePaths, requestId: opts.requestId || '' })
    },
    verifyTrust: async (filePath) => {
      return ipcRenderer.invoke('scanner:verifyTrust', { filePath: filePath || '' })
    },
    trainFromPath: async (path, isWhite, files) => {
      const payload = { path: path || '', isWhite: isWhite === true }
      if (Array.isArray(files)) payload.files = files
      return ipcRenderer.invoke('scanner:trainFromPath', payload)
    },
    onTrainProgress: (callback) => {
      /**
       * - 函数: `handler`
       * - Function: `handler`
       * - 作用: 作为 `scanner:trainProgress` 事件的桥接回调，把主进程训练进度数据安全转交给渲染层订阅者。
       * - Purpose: Acts as the bridge callback for `scanner:trainProgress`, safely forwarding main-process training progress data to the renderer subscriber.
       * - 调用方: `ipcRenderer` 在收到 `scanner:trainProgress` 事件时调用本函数。
       * - Callers: `ipcRenderer` invokes this handler when the `scanner:trainProgress` event is emitted.
       * - 被调方: 外部传入的 `callback`。
       * - Callees: The externally supplied `callback`.
       * - 变量说明: `_event` 为 Electron 事件对象；`data` 为训练进度载荷；`callback` 为渲染层订阅函数。
       * - Variables: `_event` is the Electron event object, `data` is the training-progress payload, and `callback` is the renderer subscriber.
       * - 接入方式: 仅作为 `onTrainProgress()` 内部监听器使用，对外通过返回的取消订阅函数解绑。
       * - Integration: It should stay internal to `onTrainProgress()` and be removed through the returned unsubscribe closure.
       * - 错误处理: 用户回调抛错时会被内部吞掉，避免监听链路被异常打断。
       * - Error Handling: Exceptions thrown by the user callback are swallowed so the event-listening chain is not interrupted.
       * - 关键词: 训练进度事件 | training progress event | IPC桥接回调 | IPC bridge callback | 渲染层订阅 | renderer subscription | 安全转发 | safe forwarding | 取消监听闭包 | unsubscribe closure
       */
      const handler = (_event, data) => {
        try { callback(data) } catch {}
      }
      ipcRenderer.on('scanner:trainProgress', handler)
      return () => ipcRenderer.removeListener('scanner:trainProgress', handler)
    },
    abort: async (requestId) => {
      return ipcRenderer.invoke('scanner:abort', requestId || '')
    }
  },
  signatureStore: {
    listVersions: async () => {
      return ipcRenderer.invoke('signature-store:listVersions')
    },
    getCurrentVersion: async () => {
      return ipcRenderer.invoke('signature-store:getCurrentVersion')
    },
    rollback: async (versionId) => {
      return ipcRenderer.invoke('signature-store:rollback', { versionId: versionId || '' })
    }
  },
  i18n: {
    t: (key) => i18nDict[key] || key,
    getLocale: () => (cfg && cfg.locale) ? cfg.locale : 'zh-CN'
  },
  ui: {
    debug: (tag, payload) => { try { ipcRenderer.send('ui-debug', { tag, payload }) } catch {} },
    setTitleBarOverlay: (config) => { try { ipcRenderer.send('set-title-bar-overlay', config || {}) } catch {} }
  },
  errorTrace: {
    report: (payload) => { try { ipcRenderer.send('error-trace', payload || {}) } catch {} }
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
      /**
       * - 函数: `handler`
       * - Function: `handler`
       * - 作用: 作为 `etw-log` 日志事件监听器，把主进程推送的日志记录转交给渲染层日志面板。
       * - Purpose: Serves as the `etw-log` event listener that forwards main-process log entries to the renderer log view.
       * - 调用方: `ipcRenderer` 在收到 `etw-log` 事件时调用本函数。
       * - Callers: `ipcRenderer` calls this handler when the `etw-log` event arrives.
       * - 被调方: 外部传入的 `callback`。
       * - Callees: The externally supplied `callback`.
       * - 变量说明: `event` 为 Electron 事件对象；`data` 为日志数据；`callback` 为日志订阅函数。
       * - Variables: `event` is the Electron event object, `data` is the log payload, and `callback` is the log subscriber.
       * - 接入方式: 仅由 `logs.onLog()` 内部注册和注销，不应在外部直接复用该局部函数。
       * - Integration: It should only be registered and removed inside `logs.onLog()` and should not be reused externally.
       * - 错误处理: 本函数本身不包 `try/catch`，默认把回调异常继续抛给监听栈，便于开发期尽早暴露问题。
       * - Error Handling: It intentionally does not wrap the callback in `try/catch`, allowing callback exceptions to surface through the listener stack during development.
       * - 关键词: 日志事件转发 | log event forwarding | etw-log监听 | etw-log listener | 渲染日志面板 | renderer log panel | IPC日志桥接 | IPC log bridge | 取消订阅函数 | unsubscribe function
       */
      const handler = (event, data) => callback(data)
      ipcRenderer.on('etw-log', handler)
      return () => ipcRenderer.removeListener('etw-log', handler)
    }
  },
  intercept: {
    onShow: (callback) => {
      /**
       * - 函数: `handler`
       * - Function: `handler`
       * - 作用: 作为 `intercept:show` 事件桥接器，把主进程下发的拦截展示数据交给渲染层弹窗页面。
       * - Purpose: Acts as the bridge for `intercept:show`, delivering main-process interception payloads to the renderer dialog page.
       * - 调用方: `ipcRenderer` 在收到 `intercept:show` 事件时调用本函数。
       * - Callers: `ipcRenderer` invokes this handler when the `intercept:show` event is emitted.
       * - 被调方: 外部传入的 `callback`。
       * - Callees: The externally supplied `callback`.
       * - 变量说明: `_event` 为 Electron 事件对象；`data` 为拦截弹窗所需数据；`callback` 为渲染层展示回调。
       * - Variables: `_event` is the Electron event object, `data` is the payload required by the interception dialog, and `callback` is the renderer display callback.
       * - 接入方式: 仅用于 `intercept.onShow()` 内部监听注册，并通过返回的解绑函数移除。
       * - Integration: It is only meant for listener registration inside `intercept.onShow()` and should be removed through the returned unsubscribe function.
       * - 错误处理: 本函数不额外拦截回调异常，保持事件消费错误可被上层感知。
       * - Error Handling: It does not add extra callback exception handling so event-consumption failures remain visible to upper layers.
       * - 关键词: 拦截展示事件 | intercept show event | 弹窗数据桥接 | dialog payload bridge | IPC监听回调 | IPC listener callback | 渲染层拦截页 | renderer interception page | 事件解绑 | event unsubscribe
       */
      const handler = (_event, data) => callback(data)
      ipcRenderer.on('intercept:show', handler)
      return () => ipcRenderer.removeListener('intercept:show', handler)
    },
    action: (action, pid) => {
      return ipcRenderer.invoke('intercept-action', { action: action || '', pid })
    },
    getSignerInfo: (filePath) => {
      return ipcRenderer.invoke('intercept-signer', filePath || '')
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
