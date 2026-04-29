const { app, BrowserWindow, Tray, Menu, nativeImage, dialog, ipcMain, crashReporter } = require('electron')
const { Worker } = require('worker_threads')
const path = require('path')
const fs = require('fs')
const os = require('os')
const net = require('net')
const { execFile } = require('child_process')
const { startIfNeeded, checkEngineHealth } = require('./engine_autostart')
const { createScannerClient } = require('./scanner_client')
const quarantineManager = require('./quarantine_manager')
const processes = require('./processes')
const scanCache = require('./scan_cache')
const CryptoManager = require('./crypto_manager')
const { createBehaviorAnalyzer } = require('./behavior_analyzer')
const { runStartupSequence } = require('./startup_sequence')
const { resolveMainWindowOptions } = require('./window_options')
const { formatEtwEventForConsole, formatEtwEventForParsedConsole, resolveEtwOpMeaning, createRateLimiter, sanitizeText, normalizeWindowsPathText, isBehaviorMonitoringEnabled, isCleanText, isLikelyProcessImageText, resolveFileFromBaseDirs } = require('./utils')
const { createEtwPidCache } = require('./etw_pid_cache')
const { createInterceptionQueue } = require('./interception_manager')
const { resolveTrayExitMode } = require('./tray_exit_mode')
const { normalizePathKey, isMalware, getPayloadPaths, decideSnapshotActions } = require('./snapshot_engine_policy')
const StartupAllowlistManager = require('./startup_allowlist_manager')
const { startProcessWatcher, stopProcessWatcher, setSignedPaths, pollNewPid } = require('./process_watcher')

const CONFIG_PATH = path.join(__dirname, '../../config/app.json')

let winapi = null
try {
  winapi = require('./winapi')
} catch {}

try { app.commandLine.appendSwitch('disable-background-timer-throttling') } catch {}

const gotTheLock = app.requestSingleInstanceLock()
if (!gotTheLock) {
  app.quit()
} else {
  app.on('second-instance', () => {
    if (win) {
      if (win.isMinimized()) win.restore()
      win.show()
      win.focus()
    }
  })
}

/**
 * - 函数: `loadConfig`
 * - Function: `loadConfig`
 * - 作用: 读取主进程启动配置，优先从 `CONFIG_PATH` 加载 `app.json`，失败时返回一份可启动 UI、扫描器与行为分析器的默认配置，保证主窗口、托盘、扫描引擎和 ETW 监控具备最小可用参数。
 * - Purpose: Loads the main-process runtime configuration from `CONFIG_PATH` and falls back to a boot-safe default config so the UI, scanner, tray, behavior analyzer, and ETW-related flows can still start with sane defaults.
 * - 调用方: 模块初始化阶段的 `let config = loadConfig()`，以及运行期重新读取配置的 IPC 处理逻辑。
 * - Callers: The module bootstrap assignment `let config = loadConfig()` and IPC handlers that reload configuration at runtime.
 * - 被调方: `fs.readFileSync`、`JSON.parse`。
 * - Callees: `fs.readFileSync`, `JSON.parse`.
 * - 变量说明: 无显式入参；`raw` 为配置文件原始 JSON 文本；`catch` 分支返回的对象为主进程兜底配置快照。
 * - Variables: No explicit parameters; `raw` stores the raw JSON text from disk; the object returned in the `catch` branch is the fallback bootstrap config snapshot.
 * - 接入方式: 供主进程内部直接调用；若新增配置热更新链路，应在读取后同步覆盖全局 `config`，并让依赖方重新按最新配置取值。
 * - Integration: Call it directly inside the main process; if you add a config hot-reload path, update the global `config` after reading so downstream components consume the latest values.
 * - 错误处理: 捕获文件不存在、权限不足、JSON 损坏等异常，不向上抛错，而是返回内置默认配置，避免 Electron 主进程在启动阶段因配置异常直接崩溃。
 * - Error Handling: Catches missing-file, permission, and invalid-JSON failures and returns a built-in default config instead of throwing, preventing the Electron main process from crashing during bootstrap.
 * - 关键词: 配置加载 | config load | 主进程 | main process | 默认配置 | fallback config | 托盘 | tray | 行为分析 | behavior analyzer
 */
function loadConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_PATH, 'utf-8')
    return JSON.parse(raw)
  } catch {
    return {
      brand: 'AnXin Security',
      themeColor: '#4CA2FF',
      defaultPage: 'overview',
      minimizeToTray: true,
      tray: { exitKeepScannerServicePrompt: true, exitKeepScannerServiceDefault: true },
      ui: { animations: true, window: { minWidth: 800, minHeight: 600 } },  
      scan: { commonExtensionsOnly: false },
      scanner: {
        timeoutMs: 10000,
        healthPollIntervalMs: 30000,
        maxFileSizeMB: 500,
        ipc: { enabled: false, prefer: false, host: '127.0.0.1', port: 8765, connectTimeoutMs: 500, timeoutMs: 10000 }
      },
      behaviorMonitoring: { enabled: true },
      behaviorAnalyzer: { enabled: true, flushIntervalMs: 500, sqlite: { mode: 'file', directory: 'data/behavior', fileName: 'anxin_etw_behavior.db' } }
    }
  }
}

/**
 * - 函数: `saveConfig`
 * - Function: `saveConfig`
 * - 作用: 将最新应用配置同步写回 `CONFIG_PATH`，主要服务于开发者设置解锁、初始化和保存场景，保证内存中的 `config` 与磁盘配置文件保持一致。
 * - Purpose: Persists the latest application config to `CONFIG_PATH`, mainly for developer-settings unlock, bootstrap, and save flows so the in-memory `config` stays aligned with the on-disk file.
 * - 调用方: `ipcMain.handle('dev-settings:unlock')`、`ipcMain.handle('dev-settings:save')` 等更新开发者设置密文后的保存流程。
 * - Callers: Save paths such as `ipcMain.handle('dev-settings:unlock')` and `ipcMain.handle('dev-settings:save')` after the encrypted developer-settings payload is updated.
 * - 被调方: `fs.writeFileSync`、`JSON.stringify`。
 * - Callees: `fs.writeFileSync`, `JSON.stringify`.
 * - 变量说明: `nextCfg` 为待持久化的完整配置对象，通常已经包含最新 `devSettings.payload`、`devSettings.updatedAt` 等字段。
 * - Variables: `nextCfg` is the full config object to persist and usually already carries updated fields such as `devSettings.payload` and `devSettings.updatedAt`.
 * - 接入方式: 仅在主进程内、且调用方已经完成配置对象归一化后再调用 `saveConfig(nextCfg)`；若新增配置保存入口，应优先复用本函数以统一落盘路径和序列化格式。
 * - Integration: Call `saveConfig(nextCfg)` only inside the main process after the caller has normalized the config object; new config-persistence entry points should reuse this function to keep the write path and JSON formatting consistent.
 * - 错误处理: 写文件异常会被静默吞掉，不向上抛出；调用方会继续执行并自行决定是否用返回值或后续状态反馈用户，因此该函数适合“尽力写盘”而非强一致事务。
 * - Error Handling: File-write failures are swallowed silently instead of being rethrown; callers continue their own flow and decide how to report state, so this function is designed for best-effort persistence rather than strict transactional guarantees.
 * - 关键词: 配置落盘 | config persistence | 开发者设置 | developer settings | 主进程配置 | main process config | JSON写入 | JSON write | 静默失败 | silent failure
 */
function saveConfig(nextCfg) {
  try {
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(nextCfg, null, 2), 'utf-8')
  } catch {}
}

/**
 * - 函数: `normalizeDevSettingsData`
 * - Function: `normalizeDevSettingsData`
 * - 作用: 归一化开发者设置解密/保存流程中的路径数据，把历史字段名和数组形态统一收敛为 `blackPath`、`whitePath` 和新的 `updatedAt`，确保后续加密保存时结构稳定。
 * - Purpose: Normalizes path data used by developer-settings unlock/save flows, collapsing legacy field names and array-shaped inputs into `blackPath`, `whitePath`, and a fresh `updatedAt` so the encrypted payload keeps a stable shape.
 * - 调用方: `ipcMain.handle('dev-settings:unlock')` 在初始化默认开发者设置时，以及 `ipcMain.handle('dev-settings:save')` 在持久化前整理用户提交数据时调用。
 * - Callers: Called by `ipcMain.handle('dev-settings:unlock')` when bootstrapping default developer settings and by `ipcMain.handle('dev-settings:save')` before persisting user-submitted data.
 * - 被调方: 内部辅助函数 `pickPath`、`Date.now`、字符串 `trim` 与数组遍历逻辑。
 * - Callees: The local helper `pickPath`, `Date.now`, string `trim`, and array traversal logic.
 * - 变量说明: `input` 为待整理的开发者设置原始对象；`src` 为经过对象守卫后的安全输入；返回对象中的 `blackPath`/`whitePath` 是标准化黑白名单路径，`updatedAt` 是本次归一化时间戳。
 * - Variables: `input` is the raw developer-settings object, `src` is the guarded safe input, and the returned `blackPath`/`whitePath` are normalized allow/deny paths while `updatedAt` records when normalization happened.
 * - 接入方式: 仅在主进程开发者设置链路中调用；如果后续扩展更多兼容字段，应继续在本函数内合并，而不是让 IPC 处理器分别处理不同版本的数据形态。
 * - Integration: Use it only inside the main-process developer-settings flow; if more compatibility fields are introduced later, merge them here instead of scattering version-specific shaping logic across IPC handlers.
 * - 错误处理: 不主动抛错，遇到非对象、空字符串或无效数组成员时直接回退为空路径，并始终返回可序列化对象，避免解密初始化和保存流程因为脏数据中断。
 * - Error Handling: It never throws; non-object inputs, empty strings, and invalid array members fall back to empty paths, and the function always returns a serializable object so dirty data does not break unlock/save flows.
 * - 关键词: 开发者设置归一化 | developer settings normalization | 黑白名单路径 | allow deny paths | 兼容字段 | compatibility fields | IPC保存前处理 | pre-save shaping | 时间戳刷新 | timestamp refresh
 */
function normalizeDevSettingsData(input) {
  const src = input && typeof input === 'object' ? input : {}
  /**
   * - 函数: `pickPath`
   * - Function: `pickPath`
   * - 作用: 从“字符串或字符串数组”中选取第一条有效路径文本（trim 后非空），用于兼容历史配置字段与多形态输入。
   * - Purpose: Picks the first valid path text (non-empty after trim) from a string or an array of strings, supporting legacy fields and multi-shape inputs.
   * - 调用方: `normalizeDevSettingsData` 返回值组装（用于 `blackPath/black` 与 `whitePath/white` 的兼容合并）。
   * - Callers: Used by `normalizeDevSettingsData` while assembling its return object (merging compatibility fields `blackPath/black` and `whitePath/white`).
   * - 被调方: `String.prototype.trim`、`Array.isArray`。
   * - Callees: `String.prototype.trim`, `Array.isArray`.
   * - 变量说明: `value` 为候选路径输入（string 或 string[]）；`it` 为数组遍历项；`v` 为 trim 后的候选值。
   * - Variables: `value` is the candidate input (string or string[]); `it` is the array item; `v` is the trimmed candidate value.
   * - 接入方式: 仅作为 `normalizeDevSettingsData` 的局部辅助函数使用；若后续出现更多“字符串或数组”的配置字段，优先复用本函数的语义而不是在多处复制遍历逻辑。
   * - Integration: Internal helper of `normalizeDevSettingsData`; if more config fields become “string or array”, reuse this semantics instead of duplicating traversal logic elsewhere.
   * - 错误处理: 对非 string / 非 string[] 的输入直接回退为空字符串；不抛异常，保证开发者设置解锁/保存链路对脏数据有容错。
   * - Error Handling: Falls back to an empty string for non-string/non-string[] inputs; never throws, keeping dev-settings unlock/save tolerant to dirty data.
   * - 关键词: 路径选取 | path pick | 兼容字段 | compatibility fields | 黑白名单 | allow deny | 字符串数组 | string array | trim去空白 | trim | normalizeDevSettingsData | dev-settings | 容错 | tolerant | 空字符串回退 | empty fallback | 归一化 | normalization
   */
  const pickPath = (value) => {
    if (typeof value === 'string') return value.trim()
    if (Array.isArray(value)) {
      for (const it of value) {
        const v = typeof it === 'string' ? it.trim() : ''
        if (v) return v
      }
    }
    return ''
  }
  return {
    blackPath: pickPath(src.blackPath) || pickPath(src.black),
    whitePath: pickPath(src.whitePath) || pickPath(src.white),
    updatedAt: Date.now()
  }
}

let tray
let win
let splash
let splashStatusText = ''
let allowBacklogDuringSplash = false
let mainWindowReadyResolve = null
const mainWindowReadyPromise = new Promise((resolve) => { mainWindowReadyResolve = resolve })
let config = loadConfig()
const startupAllowlist = new StartupAllowlistManager(CONFIG_PATH)
let startupEngineEnsured = false
const behavior = createBehaviorAnalyzer(config)
const scannerClient = createScannerClient(() => config)
let i18nDict = {}

const trayExitPromptPending = new Map()
ipcMain.on('tray-exit-prompt:submit', (_event, payload) => {
  const p = payload && typeof payload === 'object' ? payload : {}
  const requestId = typeof p.requestId === 'string' ? p.requestId : ''
  if (!requestId) return
  const pending = trayExitPromptPending.get(requestId)
  if (!pending) return
  trayExitPromptPending.delete(requestId)

  const keep = p.keep === true ? true : (p.keep === false ? false : null)
  try { if (pending.win && !pending.win.isDestroyed()) pending.win.close() } catch {}
  try { pending.resolve(keep) } catch {}
})

/**
 * - 函数: `loadI18n`
 * - Function: `loadI18n`
 * - 作用: 按当前 `config.locale` 读取对应语言包，为启动阶段的 Splash/Main Window 文案和运行期配置切换后的翻译缓存提供字典数据。
 * - Purpose: Loads the locale dictionary selected by `config.locale`, supplying translations for Splash/Main Window startup text and runtime refreshes after config changes.
 * - 调用方: `runStartupSequence({ prepareUi })` 在 UI 启动前的初始化流程，以及运行期配置应用逻辑中刷新 `i18nDict` 的代码路径。
 * - Callers: The `runStartupSequence({ prepareUi })` initialization flow before UI bootstrap and the runtime config-application path that refreshes `i18nDict`.
 * - 被调方: `path.join`、`fs.readFileSync`、`JSON.parse`。
 * - Callees: `path.join`, `fs.readFileSync`, `JSON.parse`.
 * - 变量说明: 无显式入参；`locale` 为当前配置指定的语言代码；`p` 为目标语言包路径；`fallback` 为兜底使用的 `zh-CN` 语言包路径；`raw` 保存读出的 JSON 文本。
 * - Variables: No explicit parameters; `locale` is the configured locale code, `p` is the target dictionary path, `fallback` is the `zh-CN` fallback path, and `raw` stores the loaded JSON text.
 * - 接入方式: 在主进程更新 `config.locale` 或需要重新装配翻译字典时调用；新增界面若依赖主进程翻译缓存，应复用本函数而不是直接读语言包文件。
 * - Integration: Invoke it when the main process updates `config.locale` or needs to rebuild the translation cache; new UI flows that depend on the main-process dictionary should reuse this function instead of reading locale files directly.
 * - 错误处理: 优先尝试当前语言包，失败后回退到 `zh-CN`，若回退仍失败则返回空对象 `{}`，从而避免因为语言文件缺失阻断启动或配置热更新。
 * - Error Handling: It first tries the configured locale, falls back to `zh-CN` on failure, and finally returns `{}` if the fallback also fails, preventing missing locale files from blocking startup or hot config refresh.
 * - 关键词: 国际化字典 | i18n dictionary | 语言回退 | locale fallback | 主进程翻译 | main process translation | 启动文案 | startup text | 配置切换 | config refresh
 */
function loadI18n() {
  try {
    const locale = (config && config.locale) ? config.locale : 'zh-CN'
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
/**
 * - 函数: `t`
 * - Function: `t`
 * - 作用: 从当前 i18n 字典中读取本地化文案，未命中时回退为原始 key，供托盘、启动页和各类弹窗统一取词。
 * - Purpose: Reads localized text from the current i18n dictionary and falls back to the raw key when missing, so the tray, splash screen, and dialogs can share one text lookup helper.
 * - 调用方: `createSplash`、`createTray`、`updateSplashStatus` 以及主进程内其他 UI 文案输出点。
 * - Callers: `createSplash`, `createTray`, `updateSplashStatus`, and other UI text output sites in the main process.
 * - 被调方: `i18nDict` 的键访问与 `||` 回退表达式。
 * - Callees: Property access on `i18nDict` and the `||` fallback expression.
 * - 变量说明: `key` 为国际化词条键名；返回值为命中的本地化文案或原始 key。
 * - Variables: `key` is the i18n entry key; the return value is either the localized text or the original key.
 * - 接入方式: 主进程内凡是需要展示固定文案的 UI 构建点，都应优先通过本函数读取翻译结果，而不是直接硬编码字符串。
 * - Integration: Any main-process UI construction site that needs fixed text should prefer this helper over hard-coded strings.
 * - 错误处理: 不抛异常；字典缺失键值时直接返回 `key`，保证 UI 至少仍可显示可识别文本。
 * - Error Handling: It does not throw; when a dictionary entry is missing, it returns `key` directly so the UI still shows recognizable text.
 * - 关键词: 国际化取词 | i18n lookup | 文案回退 | text fallback | 主进程翻译 | main-process translation | 启动页文案 | splash text | 托盘文案 | tray text
 */
function t(key) { return i18nDict[key] || key }

/**
 * - 函数: `resolveErrorLogDir`
 * - Function: `resolveErrorLogDir`
 * - 作用: 解析并确保崩溃/追踪日志目录存在，返回主进程用于落盘的 crash/trace 日志目录路径。
 * - Purpose: Resolves and ensures the crash/trace log directory exists, returning the directory path used by the main process for writing logs.
 * - 调用方: `ensureCrashDumpPath`（设置 crashDumps 目录）、`appendErrorTrace`（写入 error/trace.log 前解析目录）。
 * - Callers: `ensureCrashDumpPath` (sets the crashDumps directory), `appendErrorTrace` (resolves before writing error/trace logs).
 * - 被调方: `path.join`、`fs.existsSync`、`fs.mkdirSync`。
 * - Callees: `path.join`, `fs.existsSync`, `fs.mkdirSync`.
 * - 变量说明: 无显式入参；`base` 为项目根的相对基路径；`dir` 为最终日志目录（`data/logs/crash`）。
 * - Variables: No explicit parameters; `base` is the relative project-root base path; `dir` is the final log directory (`data/logs/crash`).
 * - 接入方式: 仅供主进程内部调用；如需要新增其他“可写目录”解析，建议复用本函数的“存在性检查 + recursive mkdir”模式，保持落盘策略一致。
 * - Integration: Main-process internal only; if more writable directories are introduced, reuse the “exists check + recursive mkdir” pattern to keep the persistence strategy consistent.
 * - 错误处理: 创建目录失败会被吞掉并仍返回 `dir`，由上层在写文件失败时兜底；本函数不抛异常，避免在启动期因权限/路径问题阻断进程启动。
 * - Error Handling: Directory creation failures are swallowed and `dir` is still returned so upper layers can fall back on write failures; it never throws to avoid blocking startup on permission/path issues.
 * - 关键词: 错误日志目录 | error log dir | 崩溃转储 | crash dumps | 追踪日志 | trace log | data/logs/crash | mkdirSync递归 | recursive mkdir | 启动期落盘 | startup persistence | resolveErrorLogDir | appendErrorTrace | ensureCrashDumpPath | 权限容错 | permission tolerant | 主进程日志 | main logs
 */
function resolveErrorLogDir() {
  const base = path.join(__dirname, '../../')
  const dir = path.join(base, 'data', 'logs', 'crash')
  try { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }) } catch {}
  return dir
}

/**
 * - 函数: `ensureCrashDumpPath`
 * - Function: `ensureCrashDumpPath`
 * - 作用: 为 Electron `crashReporter` 配置 crash dump 输出目录，并同步写入环境变量，确保崩溃转储与日志统一落到可写路径。
 * - Purpose: Configures the crash dump output directory for Electron `crashReporter` and mirrors it into an environment variable so crash dumps and logs land in a writable, consistent location.
 * - 调用方: `initCrashReporter`（启动 crashReporter 前设置目录）。
 * - Callers: `initCrashReporter` (sets the directory before starting crashReporter).
 * - 被调方: `resolveErrorLogDir`、`app.setPath('crashDumps', ...)`、`process.env`。
 * - Callees: `resolveErrorLogDir`, `app.setPath('crashDumps', ...)`, `process.env`.
 * - 变量说明: 无显式入参；`dir` 为 crash dump 目录（同日志目录）；`ELECTRON_CRASH_REPORTER_DIRECTORY` 用于兼容 Electron/底层进程读取目录的场景。
 * - Variables: No explicit parameters; `dir` is the crash dump directory (shared with log dir); `ELECTRON_CRASH_REPORTER_DIRECTORY` is used for compatibility with Electron/lower-level readers.
 * - 接入方式: 仅供主进程启动期调用；如果引入“运行期切换日志目录”的能力，需要同步更新 `app.setPath` 与环境变量，并评估对 crashReporter 的影响。
 * - Integration: Use during main-process startup; if runtime directory switching is added, update both `app.setPath` and env var and assess crashReporter implications.
 * - 错误处理: `app.setPath` 与 env 写入失败均会被吞掉；函数仍返回 `dir` 供上层记录或写 trace，不阻断启动流程。
 * - Error Handling: Failures in `app.setPath` and env updates are swallowed; it still returns `dir` for upstream logging without blocking startup.
 * - 关键词: 崩溃转储目录 | crash dumps dir | crashReporter | app.setPath | 环境变量 | env var | ELECTRON_CRASH_REPORTER_DIRECTORY | 启动期初始化 | startup init | 可写目录 | writable dir | resolveErrorLogDir | initCrashReporter | 日志目录复用 | shared log dir | 容错 | tolerant
 */
function ensureCrashDumpPath() {
  const dir = resolveErrorLogDir()
  try { app.setPath('crashDumps', dir) } catch {}
  try { process.env.ELECTRON_CRASH_REPORTER_DIRECTORY = dir } catch {}
  return dir
}

/**
 * - 函数: `normalizeErrorPayload`
 * - Function: `normalizeErrorPayload`
 * - 作用: 将任意异常对象/字符串归一化为 `{ message, stack }` 结构，便于 `appendErrorTrace` 在日志中稳定落盘并减少不可序列化字段带来的噪声。
 * - Purpose: Normalizes any error object or string into a `{ message, stack }` shape so `appendErrorTrace` can persist stable logs and avoid noise from non-serializable fields.
 * - 调用方: `initCrashReporter`（启动失败记录）、`process.on('uncaughtException')`、`process.on('unhandledRejection')` 等异常捕获链路。
 * - Callers: `initCrashReporter` (startup failure logging) and exception-capture hooks such as `process.on('uncaughtException')` and `process.on('unhandledRejection')`.
 * - 被调方: `String(...)`。
 * - Callees: `String(...)`.
 * - 变量说明: `err` 为原始异常输入（可能为 Error/object/string/任意）；返回值的 `message` 为可读文本，`stack` 为调用栈字符串（若存在）。
 * - Variables: `err` is the raw input (Error/object/string/anything); the returned `message` is readable text and `stack` is a stack string when present.
 * - 接入方式: 只在需要把异常写入 trace/error 日志的路径使用；如未来扩展日志字段（例如 error code），应在本函数内集中提取，保持输出结构统一。
 * - Integration: Use it on paths that write exceptions into trace/error logs; if you later add fields (e.g. an error code), extract them here to keep the output shape consistent.
 * - 错误处理: 对空值返回 `UnknownError`；对字符串直接包装；对对象缺失字段时使用 `String(err)` 回退；不抛异常，保证异常处理链路本身稳定。
 * - Error Handling: Returns `UnknownError` on nullish values; wraps strings; falls back to `String(err)` when fields are missing; never throws so the error-handling chain stays robust.
 * - 关键词: 异常归一化 | error normalize | message stack | 日志落盘 | log persistence | uncaughtException | unhandledRejection | initCrashReporter | appendErrorTrace | JSON可序列化 | JSON safe | UnknownError | 防御编程 | defensive
 */
function normalizeErrorPayload(err) {
  if (!err) return { message: 'UnknownError', stack: '' }
  if (typeof err === 'string') return { message: err, stack: '' }
  return {
    message: err.message ? String(err.message) : String(err),
    stack: err.stack ? String(err.stack) : ''
  }
}

/**
 * - 函数: `appendErrorTrace`
 * - Function: `appendErrorTrace`
 * - 作用: 将主进程中的关键事件/异常信息以 JSON 行的形式追加写入本地日志文件；按 payload 语义自动分流到 `error.log` 或 `trace.log`，用于排障与崩溃复盘。
 * - Purpose: Appends main-process events/exceptions as JSON lines into local log files, auto-routing entries to `error.log` or `trace.log` based on payload semantics for debugging and crash forensics.
 * - 调用方: `initCrashReporter`、`touchErrorLog`、`createWindow` 渲染进程异常监听、`process.on('uncaughtException')`、`process.on('unhandledRejection')`、`ipcMain.on('error-trace')`、`app.on('render-process-gone')` 等。
 * - Callers: `initCrashReporter`, `touchErrorLog`, `createWindow` renderer-failure hooks, `process.on('uncaughtException')`, `process.on('unhandledRejection')`, `ipcMain.on('error-trace')`, `app.on('render-process-gone')`, etc.
 * - 被调方: `resolveErrorLogDir`、`String(...)`、`RegExp.prototype.test`、`path.join`、`JSON.stringify`、`fs.appendFileSync`。
 * - Callees: `resolveErrorLogDir`, `String(...)`, `RegExp.prototype.test`, `path.join`, `JSON.stringify`, `fs.appendFileSync`.
 * - 变量说明: `payload` 为待写入的对象（建议包含 `ts`、`source` 等字段）；`isError` 用于判断是否写入 `error.log`；`fileName/filePath` 为目标文件。
 * - Variables: `payload` is the object to persist (recommended to include `ts` and `source`); `isError` decides whether to write to `error.log`; `fileName/filePath` is the target file.
 * - 接入方式: 在主进程任何需要“可落盘”的诊断点，直接调用 `appendErrorTrace({ ts: Date.now(), source: '...', ... })`；若来源是异常对象，先用 `normalizeErrorPayload` 归一化再合并到 payload。
 * - Integration: Use `appendErrorTrace({ ts: Date.now(), source: '...', ... })` at any main-process diagnostic point; for exceptions, normalize via `normalizeErrorPayload` and merge into the payload.
 * - 错误处理: 内部整体 `try/catch` 吞掉所有写盘异常，避免在异常处理路径再次抛错造成“二次崩溃”；无法写入时仅丢弃该条记录。
 * - Error Handling: Wrapped in a broad `try/catch` to swallow all write failures, preventing “crash-in-crash-handler”; when writing fails the entry is simply dropped.
 * - 关键词: 错误追踪 | error trace | trace.log | error.log | JSONL | appendFileSync | 崩溃复盘 | crash forensics | 主进程诊断 | main diagnostics | normalizeErrorPayload | resolveErrorLogDir | source ts | 事件落盘 | event persistence | 容错写盘 | best-effort write
 */
function appendErrorTrace(payload) {
  try {
    const dir = resolveErrorLogDir()
    const isError = payload && (
      /error|fail|exception/i.test(String(payload.stage || '')) ||
      /error|fail|exception/i.test(String(payload.source || '')) ||
      payload.stack || payload.message
    )
    const fileName = isError ? 'error.log' : 'trace.log'
    const filePath = path.join(dir, fileName)
    const line = JSON.stringify(payload)
    fs.appendFileSync(filePath, line + '\n')
  } catch {}
}

/**
 * - 函数: `initCrashReporter`
 * - Function: `initCrashReporter`
 * - 作用: 初始化 Electron `crashReporter`（本地压缩、不上传），并将启动结果写入本地 trace/error 日志，便于后续排查崩溃与启动异常。
 * - Purpose: Initializes Electron `crashReporter` (local-only, compressed, no upload) and records the outcome into local trace/error logs for troubleshooting crashes and startup issues.
 * - 调用方: `app.whenReady()` 启动序列（`runStartupSequence` 之前的基础设施初始化阶段）。
 * - Callers: The `app.whenReady()` bootstrap sequence (infrastructure init before `runStartupSequence`).
 * - 被调方: `ensureCrashDumpPath`、`crashReporter.start`、`appendErrorTrace`、`normalizeErrorPayload`、`Date.now`。
 * - Callees: `ensureCrashDumpPath`, `crashReporter.start`, `appendErrorTrace`, `normalizeErrorPayload`, `Date.now`.
 * - 变量说明: 无显式入参；`dir` 为 crash dumps 目录；`crashReporter.start(...)` 配置中 `uploadToServer=false` 表示不上传。
 * - Variables: No explicit parameters; `dir` is the crash dumps directory; `uploadToServer=false` indicates local-only collection.
 * - 接入方式: 仅建议在启动期调用一次；若你需要在开发/调试模式下调整 crashReporter 参数，应在本函数内基于 `config.devSettings` 或环境变量集中控制，避免散落在多个启动点。
 * - Integration: Call once during startup; if you need to tweak parameters for dev/debug mode, gate them here via `config.devSettings` or env vars to avoid scattering logic.
 * - 错误处理: `crashReporter.start` 或目录设置失败会被捕获，并写入 `appendErrorTrace({ source:'crash_reporter_failed', ... })`；不向外抛异常，确保 UI/安全组件启动链路继续推进。
 * - Error Handling: Failures in directory setup or `crashReporter.start` are caught and recorded via `appendErrorTrace({ source:'crash_reporter_failed', ... })`; it never throws so UI/security bootstrap continues.
 * - 关键词: crashReporter启动 | crashReporter start | 崩溃收集 | crash collection | 本地不上传 | no upload | 启动初始化 | startup init | ensureCrashDumpPath | appendErrorTrace | normalizeErrorPayload | 压缩 | compress | 可写目录 | writable dir | 异常落盘 | error persistence
 */
function initCrashReporter() {
  try {
    const dir = ensureCrashDumpPath()
    crashReporter.start({
      submitURL: '',
      uploadToServer: false,
      compress: true,
      crashesDirectory: dir
    })
    appendErrorTrace({ ts: Date.now(), source: 'crash_reporter_started', dir })
  } catch (e) {
    appendErrorTrace({ ts: Date.now(), source: 'crash_reporter_failed', ...normalizeErrorPayload(e) })
  }
}

let errorLogTouched = false
/**
 * - 函数: `touchErrorLog`
 * - Function: `touchErrorLog`
 * - 作用: 在启动早期“触发一次”本地 trace 日志落盘，确保日志目录创建与文件追加路径尽早验证，避免首条关键异常发生时才首次触盘导致更多不确定性。
 * - Purpose: Touches local trace logging once during early startup to validate directory creation and append paths early, reducing uncertainty when the first critical exception occurs.
 * - 调用方: 文件加载后立即调用 `touchErrorLog('startup_early')`，以及 `app.whenReady()` 中的默认调用 `touchErrorLog()`。
 * - Callers: Invoked immediately after module load via `touchErrorLog('startup_early')`, and also from `app.whenReady()` via `touchErrorLog()`.
 * - 被调方: `appendErrorTrace`、`Date.now`。
 * - Callees: `appendErrorTrace`, `Date.now`.
 * - 变量说明: `source` 为可选来源标识；`errorLogTouched` 为一次性门闩，避免重复写入；`src` 为最终写入的 source 文本（默认 `'startup'`）。
 * - Variables: `source` is an optional origin tag; `errorLogTouched` is a one-shot latch to prevent duplicates; `src` is the final source text (defaults to `'startup'`).
 * - 接入方式: 仅作为启动期诊断工具使用；如新增更细粒度的启动阶段标记，可在调用处传入不同的 `source`，但不建议移除一次性门闩以免日志噪声膨胀。
 * - Integration: Startup-only diagnostic helper; for more granular stage markers, pass different `source` values at call sites, but keep the one-shot latch to avoid log noise.
 * - 错误处理: 依赖 `appendErrorTrace` 的内部吞错；本函数自身不抛异常、不阻断启动流程。
 * - Error Handling: Relies on `appendErrorTrace` swallowing write failures; this function never throws and never blocks startup.
 * - 关键词: 启动触盘 | startup touch | 日志预热 | log warmup | 一次性门闩 | one-shot latch | errorLogTouched | appendErrorTrace | startup_early | 目录创建验证 | dir validation | trace.log | 主进程诊断 | main diagnostics | 容错 | tolerant | source标记 | source tag
 */
function touchErrorLog(source) {
  if (errorLogTouched) return
  errorLogTouched = true
  const src = typeof source === 'string' && source ? source : 'startup'
  appendErrorTrace({ ts: Date.now(), source: src })
}
touchErrorLog('startup_early')

process.on('uncaughtException', (err) => {
  appendErrorTrace({ ts: Date.now(), source: 'main_uncaughtException', ...normalizeErrorPayload(err) })
})

process.on('unhandledRejection', (reason) => {
  const payload = normalizeErrorPayload(reason)
  appendErrorTrace({ ts: Date.now(), source: 'main_unhandledRejection', ...payload })
})

process.on('exit', (code) => {
  appendErrorTrace({ ts: Date.now(), source: 'main_exit', code })
})

let etwWorker = null
const eventLogs = []
let etwConsoleLimiter = null
let etwConsoleLimiterMax = null
const etwPidCache = createEtwPidCache()
const pendingTrustedAdd = { paths: new Set(), pids: new Set() }
let interceptionSnapshotWorker = null
let interceptionSnapshotStarted = false
let isSnapshotScanning = false
let scanPromiseResolve = null
const scanPromise = new Promise((resolve) => { scanPromiseResolve = resolve })
let interceptionResumeInFlight = false
let interceptionWin = null
let interceptionWinReady = false
let interceptionWinLocked = true
let etwRiskWorker = null
let hookIpcServer = null
const hookIpcSockets = new Set()
const hookPipePath = '\\\\.\\pipe\\anxin_security_filehook'
const hookInjectedPids = new Set()
let hookNoticeCount = 0
let processWatcherStarted = false
let verifiedSignedPaths = []
let processWatcherPidTimer = null

/**
 * - 函数: `normalizeLowerPath`
 * - Function: `normalizeLowerPath`
 * - 作用: 将任意路径字符串规整为“去首尾空白 + 小写 + 反斜杠分隔”的比较用形式，供目录包含判断、ETW 过滤与注入白名单逻辑复用。
 * - Purpose: Normalizes an input path into a comparison-friendly form (trimmed, lowercased, backslash-separated) so directory containment checks, ETW filtering, and injection allowlist logic can reuse a consistent representation.
 * - 调用方: `normalizeLowerDir`、`shouldSkipEtwForAppDirByImage`、`shouldSkipEtwForAppDirByPath`、`startEtwWorker`、`injectHookIntoUnsignedProcesses`。
 * - Callers: `normalizeLowerDir`, `shouldSkipEtwForAppDirByImage`, `shouldSkipEtwForAppDirByPath`, `startEtwWorker`, and `injectHookIntoUnsignedProcesses`.
 * - 被调方: `String.prototype.trim`、`String.prototype.toLowerCase`、`String.prototype.replace`。
 * - Callees: `String.prototype.trim`, `String.prototype.toLowerCase`, and `String.prototype.replace`.
 * - 变量说明: `p` 为原始路径字符串；返回值为规整后的路径（可能为空字符串）。
 * - Variables: `p` is the raw path string; the return value is the normalized path (possibly an empty string).
 * - 接入方式: 在需要做路径等价比较或目录前缀判断前，先调用本函数把输入路径规整为统一形态，再交给 `isUnderDir` 等判定函数使用。
 * - Integration: Before performing path equality checks or directory-prefix decisions, normalize the input with this helper first, then feed the result into predicate helpers such as `isUnderDir`.
 * - 错误处理: 若 `p` 非字符串则直接返回空字符串；本函数不抛异常，确保路径过滤链路稳定。
 * - Error Handling: Returns an empty string when `p` is not a string; it does not throw, keeping path-filtering chains stable.
 * - 关键词: 路径归一化 | path normalization | 小写化 | lowercase | 反斜杠替换 | slash-to-backslash | 去空白 | trim | 前缀比较 | prefix compare | ETW过滤 | ETW filtering | 注入白名单 | injection allowlist | 目录判断 | directory check | 规整路径 | canonicalize | normalizeLowerPath
 */
function normalizeLowerPath(p) {
  if (typeof p !== 'string') return ''
  return p.trim().toLowerCase().replace(/\//g, '\\')
}

/**
 * - 函数: `pushHookIpcEvent`
 * - Function: `pushHookIpcEvent`
 * - 作用: 将来自文件 Hook 命名管道的消息统一转换为事件对象，写入 `eventLogs` 环形缓存，并在开启行为监控时投递到 `behavior.ingest`，同时可选推送到渲染进程日志面板。
 * - Purpose: Converts file-hook pipe messages into a normalized event object, stores it in the `eventLogs` ring buffer, optionally forwards it to `behavior.ingest` when monitoring is enabled, and may also push it to the renderer log panel.
 * - 调用方: `startHookIpcServer` 的 socket 数据解析分支（解析到一条 JSON 行后调用）。
 * - Callers: The socket data-parsing branch in `startHookIpcServer` (invoked per parsed JSON line).
 * - 被调方: `Date#toISOString`、`eventLogs.unshift/pop`、`isBehaviorMonitoringEnabled`、`behavior.ingest`、`BrowserWindow#isDestroyed`、`win.webContents.send`。
 * - Callees: `Date#toISOString`, `eventLogs.unshift/pop`, `isBehaviorMonitoringEnabled`, `behavior.ingest`, `BrowserWindow#isDestroyed`, `win.webContents.send`.
 * - 变量说明: `message` 为 hook 原始消息对象；`api/pid/tid/target` 为提取后的关键字段；`ev` 为标准化事件结构；`eventLogs` 最多保留 500 条以限制内存。
 * - Variables: `message` is the raw hook message; `api/pid/tid/target` are extracted fields; `ev` is the normalized event; `eventLogs` keeps up to 500 entries to bound memory.
 * - 接入方式: 仅供 hook IPC 管道接入点使用；若未来增加更多 hook 事件类型，建议在 `ev.data` 中扩展字段而保持外层结构稳定，避免行为库与 UI 解析逻辑分叉。
 * - Integration: Intended for the hook IPC pipe entry only; if more hook event types are added, extend fields inside `ev.data` while keeping the outer shape stable to avoid diverging behavior DB and UI parsing.
 * - 错误处理: 对缺失字段使用默认值；`behavior.ingest` 与 `webContents.send` 的异常会被吞掉，避免因为行为库或 UI 不可用阻断 hook 事件接入。
 * - Error Handling: Defaults missing fields; swallows failures from `behavior.ingest` and `webContents.send` so behavior DB or UI availability does not block hook ingestion.
 * - 关键词: Hook管道 | hook pipe | 事件转换 | event shaping | eventLogs缓存 | ring buffer | behavior.ingest | 渲染推送 | renderer push | CreateFileHook | Detours | 命名管道 | named pipe | pid tid | 安全吞错 | swallow errors | 日志面板 | log panel
 */
function pushHookIpcEvent(message) {
  const msg = message && typeof message === 'object' ? message : {}
  const api = typeof msg.api === 'string' && msg.api ? msg.api : 'CreateFile'
  const pid = Number.isFinite(msg.pid) ? msg.pid : parseInt(String(msg.pid), 10)
  const tid = Number.isFinite(msg.tid) ? msg.tid : parseInt(String(msg.tid), 10)
  const target = typeof msg.path === 'string' ? msg.path : ''
  const ev = {
    ts: new Date().toISOString(),
    provider: 'FileHook',
    op: api,
    pid: Number.isFinite(pid) && pid > 0 ? pid : 0,
    tid: Number.isFinite(tid) && tid > 0 ? tid : 0,
    target,
    data: {
      type: 'CreateFileHook',
      source: 'Detours',
      api
    }
  }
  eventLogs.unshift(ev)
  if (eventLogs.length > 500) eventLogs.pop()
  if (isBehaviorMonitoringEnabled(config)) {
    try { behavior.ingest(ev) } catch {}
  }
  if (win && !win.isDestroyed()) {
    try { win.webContents.send('etw-log', ev) } catch {}
  }
}

/**
 * - 函数: `startHookIpcServer`
 * - Function: `startHookIpcServer`
 * - 作用: 启动文件 Hook 的命名管道服务器，接收 hook 侧实时消息（含心跳与事件），解析 JSON 行并转交给 `pushHookIpcEvent`；同时尝试调用 `winapi.setPipeSecurity` 放开管道权限，便于受控进程连接。
 * - Purpose: Starts the file-hook named-pipe server to receive real-time hook messages (heartbeat and events), parse JSON lines, and forward them to `pushHookIpcEvent`; also attempts `winapi.setPipeSecurity` to relax pipe ACL for controlled processes.
 * - 调用方: `runStartupSequence({ runBlockingScan })` 与 `runStartupSequence({ startSecurityComponents })` 中的 Hook 初始化/复用路径。
 * - Callers: Hook initialization/reuse paths inside `runStartupSequence({ runBlockingScan })` and `runStartupSequence({ startSecurityComponents })`.
 * - 被调方: `net.createServer`、`Set#add/#delete/#clear`、`socket.setEncoding`、`socket.on`、`String#indexOf/slice/trim`、`JSON.parse`、`pushHookIpcEvent`、`server.listen`、`winapi.setPipeSecurity`、`process.env`。
 * - Callees: `net.createServer`, `Set#add/#delete/#clear`, `socket.setEncoding`, `socket.on`, `String#indexOf/slice/trim`, `JSON.parse`, `pushHookIpcEvent`, `server.listen`, `winapi.setPipeSecurity`, `process.env`.
 * - 变量说明: 无显式入参；`hookPipePath` 为管道名；`hookIpcServer` 为 server 单例；`hookIpcSockets` 追踪已连接 socket；`buf` 为按行拼包缓存；`hookNoticeCount` 控制启动期日志打印次数。
 * - Variables: No explicit parameters; `hookPipePath` is the pipe name; `hookIpcServer` is the server singleton; `hookIpcSockets` tracks active sockets; `buf` is the line-buffer; `hookNoticeCount` limits early logs.
 * - 接入方式: 只应在主进程启动或安全组件启动阶段调用，重复调用会被 `hookIpcServer` 单例短路；若调整管道协议（如改为 length-prefix），需同步更新此处的拆包逻辑与 hook 侧实现。
 * - Integration: Call during main-process startup/security bootstrap; repeated calls are short-circuited by the `hookIpcServer` singleton; if the pipe protocol changes (e.g., length-prefix), update both this framing logic and the hook-side implementation.
 * - 错误处理: JSON 解析与消息处理异常会被吞掉以保持连接可用；server 启动失败会记录日志但不抛异常；权限放开失败只记录结果，不阻断后续 hook 连接尝试。
 * - Error Handling: Swallows JSON parsing and message-handling errors to keep the connection alive; server startup failures are logged but not thrown; ACL relaxation failures are logged and do not block subsequent hook connections.
 * - 关键词: 命名管道 | named pipe | Hook IPC | hook IPC | hookPipePath | JSON行协议 | JSON lines | 心跳 | heartbeat | setPipeSecurity | 管道权限 | pipe ACL | pushHookIpcEvent | socket缓冲 | socket buffer | 单例server | singleton server | Hook初始化 | hook bootstrap
 */
function startHookIpcServer() {
  if (hookIpcServer) return
  try {
    const server = net.createServer((socket) => {
      hookIpcSockets.add(socket)
      let buf = ''
      socket.setEncoding('utf8')
      socket.on('data', (chunk) => {
        buf += typeof chunk === 'string' ? chunk : String(chunk || '')
        while (true) {
          const idx = buf.indexOf('\n')
          if (idx < 0) break
          const line = buf.slice(0, idx).trim()
          buf = buf.slice(idx + 1)
          if (!line) continue
          try {
            const parsed = JSON.parse(line)
            if (parsed && parsed.type === 'heartbeat') {
              try { socket.write('{"type":"heartbeat_ack"}\n') } catch {}
              continue
            }
            pushHookIpcEvent(parsed)
            if (hookNoticeCount < 5) {
              hookNoticeCount += 1
              const api = parsed && typeof parsed.api === 'string' ? parsed.api : ''
              const pid = parsed && Number.isFinite(parsed.pid) ? parsed.pid : ''
              const p = parsed && typeof parsed.path === 'string' ? parsed.path : ''
              const src = parsed && typeof parsed.source === 'string' ? parsed.source : ''
              const out = `主进程: 收到Hook消息 api=${api} pid=${pid} path=${p || '-'} source=${src || '-'}`
              console.log(out)
            }
          } catch {}
        }
      })
      socket.on('error', () => {})
      socket.on('close', () => {
        hookIpcSockets.delete(socket)
      })
    })
    server.on('error', (err) => {
      console.log('主进程: 管道服务器错误', err.message)
    })
    server.on('listening', () => {
      console.log('主进程: 命名管道服务器已启动', hookPipePath)
      let ok = false
      let code = 0
      let name = ''
      let type = ''
      try {
        if (winapi && typeof winapi.setPipeSecurity === 'function') {
          const res = winapi.setPipeSecurity(hookPipePath)
          ok = !!(res && res.ok)
          code = res && Number.isFinite(res.code) ? res.code : 0
          name = res && typeof res.name === 'string' ? res.name : ''
          type = res && typeof res.type === 'string' ? res.type : ''
        }
      } catch {}
      if (ok) console.log('主进程: 命名管道权限已放开', name, type)
      else console.log('主进程: 命名管道权限放开失败', code, name, type)
    })
    server.listen(hookPipePath)
    hookIpcServer = server
    try { process.env.ANXIN_HOOK_PIPE = hookPipePath } catch {}
    console.log('主进程: 正在启动命名管道服务器...')
  } catch (err) {
    console.log('主进程: 启动管道服务器失败', err.message)
  }
}

/**
 * - 函数: `stopHookIpcServer`
 * - Function: `stopHookIpcServer`
 * - 作用: 停止并释放 Hook 命名管道服务器与所有已连接 socket，避免应用退出或 ETW worker 停止期间遗留句柄导致进程悬挂。
 * - Purpose: Stops and releases the hook named-pipe server and all active sockets, preventing leaked handles from hanging the process during app shutdown or ETW worker stop.
 * - 调用方: `app.on('before-quit')` 退出链路（无论是否存在 ETW worker，都会在最终退出前调用）。
 * - Callers: The shutdown flow in `app.on('before-quit')` (called before quitting regardless of ETW worker presence).
 * - 被调方: `Promise`、`socket.destroy`、`Set#clear`、`server.close`。
 * - Callees: `Promise`, `socket.destroy`, `Set#clear`, `server.close`.
 * - 变量说明: 无显式入参；`hookIpcServer` 为当前 server 单例；`hookIpcSockets` 为活跃连接集合；返回 Promise 在 `server.close` 回调或异常兜底路径中 resolve。
 * - Variables: No explicit parameters; `hookIpcServer` is the current server singleton; `hookIpcSockets` is the active connection set; the returned Promise resolves from the `server.close` callback or fallback paths.
 * - 接入方式: 在退出/重启相关流程中 await 本函数，确保 socket 全部销毁后再继续停止其他组件（如 `behavior.stop()`），避免并发关闭导致的时序问题。
 * - Integration: Await this function in shutdown/restart flows to ensure all sockets are destroyed before stopping other components (e.g. `behavior.stop()`), reducing timing hazards.
 * - 错误处理: 始终 resolve（即使 server.close 抛错或 server 不存在），以保证退出流程不会卡死；单个 socket.destroy 异常会被吞掉。
 * - Error Handling: Always resolves (even if `server.close` throws or the server is missing) so shutdown cannot hang; individual `socket.destroy` failures are swallowed.
 * - 关键词: Hook停止 | hook stop | 命名管道关闭 | pipe close | socket销毁 | destroy sockets | 退出清理 | shutdown cleanup | before-quit | stopHookIpcServer | hookIpcServer单例 | singleton | 句柄泄漏 | handle leak | Promise收尾 | promise finalize | 安全退出 | graceful quit
 */
function stopHookIpcServer() {
  return new Promise((resolve) => {
    const server = hookIpcServer
    hookIpcServer = null
    for (const s of hookIpcSockets) {
      try { s.destroy() } catch {}
    }
    hookIpcSockets.clear()
    if (!server) return resolve()
    try {
      server.close(() => resolve())
    } catch {
      resolve()
    }
  })
}

/**
 * - 函数: `normalizeLowerDir`
 * - Function: `normalizeLowerDir`
 * - 作用: 将目录路径规整为“比较用小写目录前缀”（末尾保证带 `\\`），用于后续 `startsWith` 前缀判断稳定命中。
 * - Purpose: Normalizes a directory path into a comparison-friendly lowercase directory prefix (guaranteeing a trailing `\\`) so subsequent `startsWith` prefix checks behave deterministically.
 * - 调用方: `systemRootDirLower`、`appDirLower` 初始化链路；以及任何需要把目录作为前缀参与 `isUnderDir` 判定的逻辑。
 * - Callers: The initialization of `systemRootDirLower` and `appDirLower`, plus any logic that needs a directory prefix for `isUnderDir` checks.
 * - 被调方: `normalizeLowerPath`、`String.prototype.endsWith`。
 * - Callees: `normalizeLowerPath` and `String.prototype.endsWith`.
 * - 变量说明: `p` 为原始目录路径；`s` 为规整后的目录路径；返回值为带末尾反斜杠的目录前缀（可能为空字符串）。
 * - Variables: `p` is the raw directory path; `s` is the normalized directory path; the return value is a directory prefix with a trailing backslash (possibly an empty string).
 * - 接入方式: 当你需要把某个目录作为“包含判定前缀”时，先用本函数规整目录，再把结果传给 `isUnderDir(lowerPath, lowerDir)`。
 * - Integration: When a directory needs to serve as a “containment prefix”, normalize it with this helper first, then pass it into `isUnderDir(lowerPath, lowerDir)`.
 * - 错误处理: 依赖 `normalizeLowerPath` 对非字符串输入回退为空字符串；本函数不抛异常。
 * - Error Handling: Relies on `normalizeLowerPath` to fall back to an empty string for non-string input; this function does not throw.
 * - 关键词: 目录归一化 | directory normalization | 末尾反斜杠 | trailing backslash | 前缀目录 | directory prefix | startsWith判定 | startsWith check | isUnderDir前置 | isUnderDir prerequisite | appDirLower | systemRootDirLower | normalizeLowerDir | normalizeLowerPath | 路径规整 | path canonicalization
 */
function normalizeLowerDir(p) {
  let s = normalizeLowerPath(p)
  if (s && !s.endsWith('\\')) s += '\\'
  return s
}

const systemRootDirLower = normalizeLowerDir(process.env.SystemRoot || 'C:\\Windows')
const appDirLower = normalizeLowerDir(path.dirname(process.execPath || ''))

/**
 * - 函数: `isUnderDir`
 * - Function: `isUnderDir`
 * - 作用: 判断“已规整为小写/反斜杠形式的路径”是否位于“已规整目录前缀”之下，用于应用目录噪声过滤与注入目标范围判定。
 * - Purpose: Checks whether a normalized lowercased/backslash path is under a normalized directory prefix, used for app-directory noise filtering and injection target scoping.
 * - 调用方: `shouldSkipEtwForAppDirByImage`、`shouldSkipEtwForAppDirByPath`、`startEtwWorker`、`injectHookIntoUnsignedProcesses`。
 * - Callers: `shouldSkipEtwForAppDirByImage`, `shouldSkipEtwForAppDirByPath`, `startEtwWorker`, and `injectHookIntoUnsignedProcesses`.
 * - 被调方: `String.prototype.startsWith`。
 * - Callees: `String.prototype.startsWith`.
 * - 变量说明: `lowerPath` 为已通过 `normalizeLowerPath` 规整后的路径；`lowerDir` 为已通过 `normalizeLowerDir` 规整后的目录前缀（通常带末尾 `\\`）；返回值为布尔值。
 * - Variables: `lowerPath` is the path normalized by `normalizeLowerPath`; `lowerDir` is the directory prefix normalized by `normalizeLowerDir` (usually with a trailing `\\`); the return value is a boolean.
 * - 接入方式: 先用 `normalizeLowerPath`/`normalizeLowerDir` 规整入参，再调用本函数；不要直接用原始路径做 `startsWith`，避免大小写/分隔符差异导致误判。
 * - Integration: Normalize inputs with `normalizeLowerPath`/`normalizeLowerDir` first, then call this helper; do not run `startsWith` on raw paths to avoid mismatches from casing or separators.
 * - 错误处理: 任一入参为空时返回 `false`；本函数不抛异常，仅通过布尔返回值参与控制流。
 * - Error Handling: Returns `false` when either input is blank; it does not throw and participates in control flow only via a boolean result.
 * - 关键词: 目录包含判定 | directory containment | 前缀匹配 | prefix match | 规范化路径 | normalized path | 目录前缀 | directory prefix | 末尾反斜杠 | trailing backslash | 路径过滤 | path filtering | ETW降噪 | ETW noise reduction | 注入范围 | injection scope | startsWith | isUnderDir
 */
function isUnderDir(lowerPath, lowerDir) {
  if (!lowerPath || !lowerDir) return false
  return lowerPath.startsWith(lowerDir)
}

/**
 * - 函数: `resolveMaybeRelativePath`
 * - Function: `resolveMaybeRelativePath`
 * - 作用: 将可能为相对路径的输入规整为“尽量可落盘”的绝对路径；对已是绝对路径/设备路径的输入保持原样，并在多基础目录中尝试解析相对路径。
 * - Purpose: Converts a possibly-relative input into an on-disk resolvable absolute path when possible; keeps already-absolute/device paths unchanged, and attempts to resolve relative paths against multiple base directories.
 * - 调用方: `startEtwWorker`（ETW 文件事件路径解析/回填）、`injectHookIntoUnsignedProcesses`（注入链路的映像/目标路径解析）。
 * - Callers: `startEtwWorker` (ETW file-event path resolution/backfill) and `injectHookIntoUnsignedProcesses` (image/target path resolution for the injection flow).
 * - 被调方: `String.prototype.trim`、`String.prototype.startsWith`、`RegExp.prototype.test`、`String.prototype.replace`、`Array.prototype.push`、`path.dirname`、`app.getPath`、`app.getAppPath`、`resolveFileFromBaseDirs`。
 * - Callees: `String.prototype.trim`, `String.prototype.startsWith`, `RegExp.prototype.test`, `String.prototype.replace`, `Array.prototype.push`, `path.dirname`, `app.getPath`, `app.getAppPath`, and `resolveFileFromBaseDirs`.
 * - 变量说明: `p` 为输入路径；`s` 为去空白后的路径字符串；`rel` 为相对路径（去掉前导 `\\` 后的形式）；`bases` 为基础目录列表（按优先级尝试）；`resolved` 为解析出的绝对路径（可能为空字符串）。
 * - Variables: `p` is the input path; `s` is the trimmed string; `rel` is the relative path form (leading `\\` stripped); `bases` is the prioritized base directory list; `resolved` is the resolved absolute path (may be an empty string).
 * - 接入方式: 当你拿到的路径可能来自 ETW/Hook/规则匹配等外部来源，且可能是相对路径时，先调用本函数做统一解析，再进入 `fileExists`、`normalizeLowerPath`、扫描或注入等后续链路。
 * - Integration: When a path originates from ETW/Hook/rule matches and may be relative, call this helper first, then feed the result into downstream steps such as `fileExists`, `normalizeLowerPath`, scanning, or injection.
 * - 错误处理: 输入非字符串或空字符串直接返回空字符串；对目录获取与应用路径读取使用局部 `try/catch` 静默降级；若解析失败则回退返回原始 `s`，避免路径链路因异常而中断。
 * - Error Handling: Returns an empty string for non-string/blank inputs; uses local `try/catch` to silently degrade when retrieving base directories; falls back to the original `s` when resolution fails, preventing the path pipeline from breaking.
 * - 关键词: 相对路径解析 relative-path resolve | 多基目录回退 multi-base fallback | 设备路径 device path | UNC路径 UNC path | execPath 基目录 execPath base | Electron 路径 getAppPath | ETW 路径回填 ETW backfill | 注入路径解析 injection path | resolveFileFromBaseDirs | 路径降级 fallback
 */
function resolveMaybeRelativePath(p) {
  const s = typeof p === 'string' ? p.trim() : ''
  if (!s) return ''
  if (s.startsWith('\\\\?\\') || s.startsWith('\\\\.\\') || /^[a-zA-Z]:[\\/]/.test(s) || s.startsWith('\\\\')) return s
  const rel = s.startsWith('\\') ? s.replace(/^\\+/, '') : s
  const bases = []
  try { bases.push(path.dirname(process.execPath || '')) } catch {}
  try { bases.push(path.dirname(app.getPath('exe') || '')) } catch {}
  try { bases.push(app.getAppPath()) } catch {}
  const resolved = resolveFileFromBaseDirs(bases.filter(Boolean), rel)
  return resolved || s
}

/**
 * - 函数: `ensureEtwRiskWorker`
 * - Function: `ensureEtwRiskWorker`
 * - 作用: 确保 ETW 风险研判 worker 单例已启动，并把 worker 输出的 `risk_payload` 接入拦截队列，形成“ETW事件 → 风险扫描/研判 → 拦截弹窗”的异步链路。
 * - Purpose: Ensures the ETW risk-analysis worker singleton is running, and wires its `risk_payload` output into the interception queue, forming an async pipeline of “ETW event → risk scan/analysis → interception UI”.
 * - 调用方: `startEtwWorker`（启动 ETW 线程前的准备阶段；以及在 ETW 消息处理中需要投递 `rule_match` 给风险 worker 时）。
 * - Callers: `startEtwWorker` (during ETW bootstrap; and from its message handler when forwarding `rule_match` into the risk worker).
 * - 被调方: `path.join`、`fs.existsSync`、`Worker`、`Worker#on`、`interceptionQueue.enqueuePausedProcess`、`console.log`、`console.warn`、`path.dirname`、`process.execPath`、`process.env`、`Worker#postMessage`。
 * - Callees: `path.join`, `fs.existsSync`, `Worker`, `Worker#on`, `interceptionQueue.enqueuePausedProcess`, `console.log`, `console.warn`, `path.dirname`, `process.execPath`, `process.env`, and `Worker#postMessage`.
 * - 变量说明: 无显式入参；`etwRiskWorker` 为模块级单例；`workerPath` 为风险 worker 脚本路径；`msg`/`m` 为 worker 回传消息；`appDir`/`systemRoot` 为下发给 worker 的基础目录；`sc`/`scan` 为下发的 scanner/scan 配置片段。
 * - Variables: There are no explicit parameters; `etwRiskWorker` is the module-level singleton; `workerPath` is the risk-worker script path; `msg`/`m` is the worker message; `appDir`/`systemRoot` are base dirs pushed to the worker; `sc`/`scan` are the scanner/scan config fragments sent to the worker.
 * - 接入方式: 仅主进程内部使用；在需要调用 `rw.postMessage(...)` 之前先调用本函数获取 worker 实例，并在返回 `null` 时走安全降级（例如跳过风险研判）。
 * - Integration: Use it only inside the main process; call it before `rw.postMessage(...)` and handle a `null` return by safely degrading (e.g. skipping risk analysis).
 * - 错误处理: 脚本不存在时返回 `null`；创建 worker 或配置下发失败会被捕获并回退为 `null`，同时把 `etwRiskWorker` 置空，避免后续误用半初始化实例；worker 回传 `status`/`error` 仅做日志记录，不抛异常、不阻断 ETW 主链路。
 * - Error Handling: Returns `null` if the script is missing; worker creation or config bootstrap failures are caught and collapse to `null` (also resetting `etwRiskWorker` to avoid using a half-initialized instance); `status`/`error` messages are logged only and never throw or block the ETW main path.
 * - 关键词: ETW风险Worker | ETW risk worker | Worker单例 | worker singleton | 风险研判投递 | risk forwarding | risk_payload拦截 | risk payload interception | 拦截队列 | interception queue | 配置下发 | config bootstrap | rule_match转发 | rule_match forwarding | worker_threads | ensureEtwRiskWorker | startEtwWorker
 */
function ensureEtwRiskWorker() {
  if (etwRiskWorker) return etwRiskWorker
  try {
    const workerPath = path.join(__dirname, 'workers/etw_risk_worker.js')
    if (!fs.existsSync(workerPath)) return null
    etwRiskWorker = new Worker(workerPath)
    etwRiskWorker.on('message', (msg) => {
      const m = msg && typeof msg === 'object' ? msg : null
      if (!m) return
      if (m.type === 'risk_payload' && m.payload) {
        interceptionQueue.enqueuePausedProcess(m.payload)
        return
      }
      if (m.type === 'status' && m.message) {
        console.log('ETW_RISK:', m.message)
        return
      }
      if (m.type === 'error' && m.message) {
        console.warn('ETW_RISK_ERROR:', m.message, m.details || null)
      }
    })
    try {
      const appDir = path.dirname(process.execPath || '')
      const systemRoot = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows'
      const sc = (config && config.scanner) ? config.scanner : {}
      const scan = (config && config.scan) ? config.scan : {}
      etwRiskWorker.postMessage({ type: 'config', appDir, systemRoot, scanner: sc, scan })
    } catch {}
    return etwRiskWorker
  } catch {
    etwRiskWorker = null
    return null
  }
}
const interceptionQueue = createInterceptionQueue({
  showFn: (payload) => {
    if (isSnapshotScanning) return false
    if (splash && !splash.isDestroyed() && !allowBacklogDuringSplash) return false
    try {
      console.log('主进程: 发送拦截弹窗', payload.pid)
      const w = ensureInterceptionWindow()
      if (!w) return false
      if (!interceptionWinReady) return false
      w.webContents.send('intercept:show', payload)
      try { w.show() } catch {}
      try { w.setAlwaysOnTop(true, 'screen-saver') } catch {}
      try { w.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true }) } catch {}
      try { w.focus() } catch {}
      try { w.moveTop() } catch {}
      return true
    } catch {
      return false
    }
  }
})
try {
  const etwCfg = (config && config.etw) ? config.etw : {}
  const icfg = (etwCfg && etwCfg.interception && typeof etwCfg.interception === 'object') ? etwCfg.interception : null
  interceptionQueue.configure(icfg)
} catch {}
let etwPidSnapshotAt = 0
let etwPidSnapshotInFlight = false
let etwControlSeq = 1
const etwControlPending = new Map()
let etwStartPending = null
let etwLastStatus = null
let etwLastError = null

/**
 * - 函数: `resolveAppIconPath`
 * - Function: `resolveAppIconPath`
 * - 作用: 在应用安装目录、资源目录等候选基础目录中解析统一的 `favicon.ico` 路径，供主窗口、启动页、托盘弹窗和拦截窗口复用。
 * - Purpose: Resolves a shared `favicon.ico` path from candidate base directories such as the app install path and resources path, so the main window, splash screen, tray prompt, and interception window can reuse one icon source.
 * - 调用方: `ensureInterceptionWindow`、`createSplash`、`createWindow`、`showTrayExitPrompt`、`createTray`。
 * - Callers: `ensureInterceptionWindow`, `createSplash`, `createWindow`, `showTrayExitPrompt`, and `createTray`.
 * - 被调方: `getEngineBaseDirs`、`resolveFileFromBaseDirs`。
 * - Callees: `getEngineBaseDirs` and `resolveFileFromBaseDirs`.
 * - 变量说明: 无显式入参；返回值为找到的图标绝对路径，未找到时返回空字符串。
 * - Variables: There are no explicit parameters; the return value is the resolved absolute icon path, or an empty string when nothing is found.
 * - 接入方式: 主进程中凡是需要给 Electron `BrowserWindow` 或托盘图标提供统一品牌图标路径时，都应复用本函数。
 * - Integration: Reuse it anywhere the main process needs a shared branded icon path for Electron `BrowserWindow` instances or tray assets.
 * - 错误处理: 目录枚举或文件解析异常时统一回退为空字符串，由调用方决定是否使用内置图标或无图标配置。
 * - Error Handling: Falls back to an empty string when directory enumeration or file resolution fails, leaving it to the caller to use a built-in icon or no icon configuration.
 * - 关键词: 应用图标解析 | app icon resolution | favicon定位 | favicon lookup | 基础目录搜索 | base-directory search | 窗口图标复用 | window icon reuse | 托盘图标来源 | tray icon source
 */
function resolveAppIconPath() {
  try {
    return resolveFileFromBaseDirs(getEngineBaseDirs(), 'favicon.ico')
  } catch {
    return ''
  }
}

/**
 * - 函数: `getProcessNameFromPath`
 * - Function: `getProcessNameFromPath`
 * - 作用: 从进程映像路径提取可展示的进程名，供 ETW 命中事件和快照拦截弹窗复用。
 * - Purpose: Extracts a displayable process name from an image path so ETW hit events and snapshot interception dialogs can reuse the same label.
 * - 调用方: `ensureInterceptionSnapshotWorker`、`startEtwWorker`。
 * - Callers: `ensureInterceptionSnapshotWorker` and `startEtwWorker`.
 * - 被调方: `path.basename`、`sanitizeText`。
 * - Callees: `path.basename` and `sanitizeText`.
 * - 变量说明: `p` 为原始进程映像路径；`n` 为截取出的文件名。
 * - Variables: `p` is the raw process image path; `n` is the extracted basename.
 * - 接入方式: 主进程内凡是需要从完整映像路径回填 UI 友好进程名时，都应优先复用本函数。
 * - Integration: Reuse it anywhere in the main process that needs a UI-friendly process name derived from a full image path.
 * - 错误处理: 路径为空或文件名提取失败时返回空字符串，避免异常打断消息分发链路。
 * - Error Handling: Returns an empty string when the path is blank or basename extraction fails, avoiding disruptions in the message-routing flow.
 * - 关键词: 进程名提取 | process name extraction | 映像路径解析 | image path parsing | ETW展示名 | ETW display name | 拦截弹窗名称 | interception dialog name | 文本净化 | text sanitization
 */
function getProcessNameFromPath(p) {
  if (typeof p !== 'string' || !p) return ''
  try {
    const n = path.basename(p)
    return sanitizeText(typeof n === 'string' ? n : '')
  } catch { return '' }
}

/**
 * - 函数: `refreshEtwPidCacheConfig`
 * - Function: `refreshEtwPidCacheConfig`
 * - 作用: 按当前 ETW 配置刷新主进程 PID 缓存的容量和 TTL，保证快照补种与实时事件使用同一缓存策略。
 * - Purpose: Refreshes the main-process PID cache capacity and TTL from the current ETW config so snapshot seeding and live events share the same cache policy.
 * - 调用方: `takeEtwPidSnapshot`、`startEtwWorker`。
 * - Callers: `takeEtwPidSnapshot` and `startEtwWorker`.
 * - 被调方: `Number.isFinite`、`Math.max`、`Math.floor`、`etwPidCache.configure`。
 * - Callees: `Number.isFinite`, `Math.max`, `Math.floor`, and `etwPidCache.configure`.
 * - 变量说明: `etwCfg` 为 ETW 配置对象；`max` 为缓存最大条目数；`ttlMs` 为 PID 记录存活时间。
 * - Variables: `etwCfg` is the ETW config object; `max` is the cache entry limit; `ttlMs` is the PID-record lifetime.
 * - 接入方式: 每次 ETW worker 启动或进行 PID 快照补种前，先调用本函数让缓存策略和配置文件保持同步。
 * - Integration: Call it before ETW worker startup or PID snapshot seeding so cache policy stays aligned with the config file.
 * - 错误处理: 非法配置值回退到默认 `2048` 和 `300000ms`，不抛异常。
 * - Error Handling: Invalid config values fall back to the defaults `2048` and `300000ms` without throwing.
 * - 关键词: ETW缓存配置刷新 | ETW cache config refresh | PID缓存容量 | PID cache capacity | TTL同步 | TTL sync | 快照补种策略 | snapshot seeding policy | 主进程缓存调参 | main process cache tuning
 */
function refreshEtwPidCacheConfig(etwCfg) {
  const max = Number.isFinite(etwCfg.processNameCacheMax) ? Math.max(0, Math.floor(etwCfg.processNameCacheMax)) : 2048
  const ttlMs = Number.isFinite(etwCfg.processNameCacheTtlMs) ? Math.max(0, Math.floor(etwCfg.processNameCacheTtlMs)) : 300000
  etwPidCache.configure({ max, ttlMs })
}

/**
 * - 函数: `pruneEtwPidCache`
 * - Function: `pruneEtwPidCache`
 * - 作用: 触发主进程 ETW PID 缓存的过期和容量淘汰，避免快照补种后缓存膨胀。
 * - Purpose: Triggers expiration and capacity eviction for the main-process ETW PID cache so snapshot seeding does not let the cache grow unchecked.
 * - 调用方: `takeEtwPidSnapshot`、`startEtwWorker`。
 * - Callers: `takeEtwPidSnapshot` and `startEtwWorker`.
 * - 被调方: `etwPidCache.prune`。
 * - Callees: `etwPidCache.prune`.
 * - 变量说明: `now` 为当前时间戳，供缓存内部判断 TTL 是否到期。
 * - Variables: `now` is the current timestamp used by the cache to determine TTL expiration.
 * - 接入方式: 在批量灌入快照结果或 ETW 事件高峰后调用，保持缓存条目新鲜度。
 * - Integration: Call it after bulk snapshot imports or ETW event bursts to keep cache entries fresh.
 * - 错误处理: 依赖缓存对象内部的容错逻辑，本函数本身不额外抛异常。
 * - Error Handling: Relies on the cache object's internal fault tolerance and does not throw on its own.
 * - 关键词: ETW缓存淘汰 | ETW cache pruning | TTL过期清理 | TTL expiration cleanup | 容量裁剪 | capacity trimming | 快照后整理 | post-snapshot cleanup | 缓存保鲜 | cache freshness
 */
function pruneEtwPidCache(now) {
  etwPidCache.prune(now)
}

/**
 * - 函数: `upsertEtwPid`
 * - Function: `upsertEtwPid`
 * - 作用: 将 ETW 事件中的 PID 与映像路径写入主进程缓存，为后续风险命中补全进程信息。
 * - Purpose: Writes a PID and image path from ETW events into the main-process cache so later risk hits can enrich process metadata.
 * - 调用方: `startEtwWorker` 的 ETW 消息处理分支。
 * - Callers: The ETW message-handling branches inside `startEtwWorker`.
 * - 被调方: `etwPidCache.upsert`。
 * - Callees: `etwPidCache.upsert`.
 * - 变量说明: `pid` 为进程 ID；`imagePath` 为进程映像路径；`now` 为写入时间戳。
 * - Variables: `pid` is the process ID; `imagePath` is the process image path; `now` is the write timestamp.
 * - 接入方式: 当 ETW worker 拿到可信的进程创建或路径信息时，优先通过本函数补种缓存。
 * - Integration: Use it to seed the cache whenever the ETW worker obtains reliable process-create or image-path metadata.
 * - 错误处理: 具体脏数据过滤由底层缓存承担，本包装函数不额外抛异常。
 * - Error Handling: Dirty-input filtering is handled by the underlying cache, and this wrapper does not throw extra errors.
 * - 关键词: ETW PID写入 | ETW PID upsert | 进程路径补种 | process path seeding | 风险事件补全 | risk event enrichment | 主进程缓存写入 | main process cache write | 实时事件缓存 | live event cache
 */
function upsertEtwPid(pid, imagePath, now) {
  etwPidCache.upsert(pid, imagePath, now)
}

/**
 * - 函数: `removeEtwPid`
 * - Function: `removeEtwPid`
 * - 作用: 在进程退出或缓存纠正时删除对应 PID 的 ETW 缓存记录。
 * - Purpose: Removes the ETW cache record for a PID when the process exits or cached metadata needs correction.
 * - 调用方: `startEtwWorker` 的进程结束事件处理分支。
 * - Callers: The process-exit event handling branch inside `startEtwWorker`.
 * - 被调方: `etwPidCache.remove`。
 * - Callees: `etwPidCache.remove`.
 * - 变量说明: `pid` 为需要失效化的进程 ID。
 * - Variables: `pid` is the process ID whose cache entry should be invalidated.
 * - 接入方式: 收到 ETW 进程退出事件或确认 PID 信息失真时，通过本函数统一清理缓存。
 * - Integration: Use it as the single cache cleanup path when ETW reports a process exit or when PID metadata is known to be stale.
 * - 错误处理: 具体 PID 合法性校验由底层缓存处理，本函数保持轻量包装。
 * - Error Handling: PID validation is handled by the underlying cache, keeping this wrapper lightweight.
 * - 关键词: ETW PID删除 | ETW PID removal | 进程退出清理 | process exit cleanup | 缓存失效化 | cache invalidation | 主进程缓存清除 | main process cache cleanup | 脏记录移除 | stale record removal
 */
function removeEtwPid(pid) {
  etwPidCache.remove(pid)
}

/**
 * - 函数: `resolveEtwProcessInfo`
 * - Function: `resolveEtwProcessInfo`
 * - 作用: 从主进程 PID 缓存中回查 ETW 事件对应的进程路径和名称，减少 ETW 原始事件缺字段时的信息缺口。
 * - Purpose: Resolves the cached process path and name for an ETW event from the main-process PID cache, reducing metadata gaps when raw ETW events are incomplete.
 * - 调用方: `startEtwWorker`。
 * - Callers: `startEtwWorker`.
 * - 被调方: `etwPidCache.resolve`。
 * - Callees: `etwPidCache.resolve`.
 * - 变量说明: `pid` 为待查询进程 ID；`now` 为当前时间戳；`etwCfg` 为保留的 ETW 配置入参，目前不直接参与解析逻辑。
 * - Variables: `pid` is the process ID to query; `now` is the current timestamp; `etwCfg` is a preserved ETW config parameter that is not directly used by the current resolve logic.
 * - 接入方式: 当 ETW worker 回传事件缺少可靠进程路径时，先通过本函数尝试回填。
 * - Integration: Use it first when ETW worker events lack a reliable process path and need cache-based enrichment.
 * - 错误处理: 缓存未命中或缓存项已失效时返回 `null`，由调用方继续走降级逻辑。
 * - Error Handling: Returns `null` when the cache misses or the cached entry has expired, letting the caller continue with fallback logic.
 * - 关键词: ETW进程信息解析 | ETW process info resolution | PID缓存回查 | PID cache lookup | 元数据补全 | metadata enrichment | 主进程缓存命中 | main process cache hit | 路径回填 | path backfill
 */
function resolveEtwProcessInfo(pid, now, etwCfg) {
  return etwPidCache.resolve(pid, now)
}

/**
 * - 函数: `takeEtwPidSnapshot`
 * - Function: `takeEtwPidSnapshot`
 * - 作用: 主动采集一次 PID 映像快照并灌入 ETW 缓存，为 ETW 启动初期提供进程元数据种子。
 * - Purpose: Actively captures one PID image snapshot and seeds it into the ETW cache so ETW startup has initial process metadata available.
 * - 调用方: `startEtwWorker`。
 * - Callers: `startEtwWorker`.
 * - 被调方: `ensureInterceptionSnapshotWorker`、`refreshEtwPidCacheConfig`、`requestInterceptionPidSnapshot`、`winapi.getProcessImageSnapshot`、`etwPidCache.bulkUpsert`、`pruneEtwPidCache`、`etwWorker.postMessage`。
 * - Callees: `ensureInterceptionSnapshotWorker`, `refreshEtwPidCacheConfig`, `requestInterceptionPidSnapshot`, `winapi.getProcessImageSnapshot`, `etwPidCache.bulkUpsert`, `pruneEtwPidCache`, and `etwWorker.postMessage`.
 * - 变量说明: `etwCfg` 为 ETW 配置；`snapCfg` 为 PID 快照子配置；`w` 为快照 worker 实例；`canSync` 表示是否可直接使用同步 WinAPI；`maxPids` 为本次采样上限；`list` 为快照结果列表。
 * - Variables: `etwCfg` is the ETW config; `snapCfg` is the PID snapshot sub-config; `w` is the snapshot worker instance; `canSync` indicates whether synchronous WinAPI fallback is available; `maxPids` is the snapshot cap; `list` is the snapshot result list.
 * - 接入方式: 作为 ETW 启动后的预热步骤调用；优先走 worker 请求，失败时回退到主线程同步快照。
 * - Integration: Use it as a warmup step after ETW startup; prefer the worker request path and fall back to synchronous main-thread snapshotting if needed.
 * - 错误处理: 通过时间节流、并发闸门、本地 `try/catch` 和 worker/WinAPI 双路径回退保证快照补种尽量完成且不阻断 ETW 主流程。
 * - Error Handling: Uses throttling, an in-flight guard, local `try/catch`, and dual worker/WinAPI fallback paths so snapshot seeding completes opportunistically without blocking the ETW main flow.
 * - 关键词: ETW PID快照补种 | ETW PID snapshot seeding | 启动预热 | startup warmup | Worker快照请求 | worker snapshot request | 同步WinAPI回退 | synchronous WinAPI fallback | 进程元数据种子 | process metadata seed
 */
async function takeEtwPidSnapshot() {
  if (etwPidSnapshotInFlight) return
  const etwCfg = (config && config.etw) ? config.etw : {}
  const snapCfg = (etwCfg && etwCfg.pidSnapshot && typeof etwCfg.pidSnapshot === 'object') ? etwCfg.pidSnapshot : {}
  const enabled = snapCfg.enabled !== false
  if (!enabled) return
  const w = ensureInterceptionSnapshotWorker()
  const canSync = !!(winapi && typeof winapi.getProcessImageSnapshot === 'function')
  if (!w && !canSync) return

  const maxPids = Number.isFinite(snapCfg.maxPids) ? Math.max(256, Math.floor(snapCfg.maxPids)) : 8192
  const now = Date.now()
  if (etwPidSnapshotAt && now - etwPidSnapshotAt < 10000) return
  etwPidSnapshotAt = now
  etwPidSnapshotInFlight = true
  try {
    refreshEtwPidCacheConfig(etwCfg)
    let list = []
    if (w) {
      const reqId = String(interceptionControlSeq++)
      const out = await requestInterceptionPidSnapshot(w, reqId, maxPids, 12000)
      list = out && out.ok && Array.isArray(out.list) ? out.list : []
    }
    if ((!list || !list.length) && canSync) {
      list = winapi.getProcessImageSnapshot(maxPids)
    }
    etwPidCache.bulkUpsert(list, now)
    try {
      if (etwWorker) etwWorker.postMessage({ type: 'trusted_seed_snapshot', list })
    } catch {}
    pruneEtwPidCache(now)
  } catch {
  } finally {
    etwPidSnapshotInFlight = false
  }
}

let interceptionControlSeq = 1
const interceptionControlPending = new Map()

/**
 * - 函数: `ensureInterceptionSnapshotWorker`
 * - Function: `ensureInterceptionSnapshotWorker`
 * - 作用: 懒创建并维护快照拦截 worker，将 `paused`、`scan_done`、`pid_snapshot_done`、`resume_many_done` 四类消息路由回主进程状态机。
 * - Purpose: Lazily creates and maintains the snapshot interception worker, routing the `paused`, `scan_done`, `pid_snapshot_done`, and `resume_many_done` messages back into the main-process state machine.
 * - 调用方: `takeEtwPidSnapshot`、`requestInterceptionResumeMany`、`startInterceptionSnapshotScan`。
 * - Callers: `takeEtwPidSnapshot`, `requestInterceptionResumeMany`, and `startInterceptionSnapshotScan`.
 * - 被调方: `Worker`、`path.join`、`fs.existsSync`、`getProcessNameFromPath`、`interceptionQueue.enqueuePausedProcess`、`handleSnapshotScanDone`、`interceptionQueue.tryShowNext`、`interceptionControlPending.get`。
 * - Callees: `Worker`, `path.join`, `fs.existsSync`, `getProcessNameFromPath`, `interceptionQueue.enqueuePausedProcess`, `handleSnapshotScanDone`, `interceptionQueue.tryShowNext`, and `interceptionControlPending.get`.
 * - 变量说明: `workerPath` 为 worker 脚本路径；`msg`/`m` 为 worker 回传消息；`typ` 为消息类型；`payload` 为暂停进程入队对象；`requestId` 为控制类请求标识。
 * - Variables: `workerPath` is the worker script path; `msg` and `m` are worker messages; `typ` is the message type; `payload` is the paused-process queue object; `requestId` is the control-request identifier.
 * - 接入方式: 主进程中凡是需要快照扫描、批量恢复或 PID 快照请求的链路，都应先通过本函数拿到单例 worker。
 * - Integration: Any main-process flow that needs snapshot scanning, batch resume, or PID snapshot requests should obtain the singleton worker through this helper first.
 * - 错误处理: 脚本缺失、worker 创建失败、error/exit 事件都会把单例置空；消息处理中对非法 PID、丢失请求和局部异常采用静默回退。
 * - Error Handling: Missing scripts, worker creation failures, and worker `error` or `exit` events all reset the singleton to `null`; message handling silently falls back on invalid PIDs, missing requests, and local failures.
 * - 关键词: 快照Worker单例 | snapshot worker singleton | 主线程消息路由 | main-thread message routing | 暂停进程入队 | paused process enqueue | 控制请求回执 | control request acknowledgment | Worker懒创建 | worker lazy creation
 */
function ensureInterceptionSnapshotWorker() {
  if (interceptionSnapshotWorker) return interceptionSnapshotWorker
  try {
    const workerPath = path.join(__dirname, 'workers/interception_snapshot_worker.js')
    if (!fs.existsSync(workerPath)) return null
    interceptionSnapshotWorker = new Worker(workerPath)
    interceptionSnapshotWorker.on('message', (msg) => {
      const m = msg && typeof msg === 'object' ? msg : null
      const typ = m && typeof m.type === 'string' ? m.type : ''
      if (typ === 'paused') {
        const pid = Number.isFinite(m.pid) ? m.pid : parseInt(String(m.pid), 10)
        if (!Number.isFinite(pid) || pid <= 0) return
        const imagePath = typeof m.imagePath === 'string' ? m.imagePath : ''
        const unsignedDlls = Array.isArray(m.unsignedDlls) ? m.unsignedDlls.filter(x => typeof x === 'string' && x) : []
        const scanType = typeof m.scanType === 'string' ? m.scanType : ''
        const processSigned = m.processSigned === true
        let ruleId = 'unsigned_dll'
        if (scanType === 'process') ruleId = 'process_signature_invalid'
        else if (scanType === 'dll') ruleId = 'dll_signature_invalid'
        else if (scanType === 'joint') ruleId = 'process_and_dll_signature_invalid'
        let severity = 2
        if (scanType === 'joint') severity = 3
        const recommendAction = 'block'
        const threatType = scanType === 'joint' ? '联合签名异常' : (scanType === 'process' ? '进程签名异常' : 'DLL签名异常')
        const payload = {
          pid,
          paused: m.paused === true,
          triggeredAt: Date.now(),
          threatType,
          severity,
          recommendAction,
          match: { ruleId, provider: 'Process', op: 'Snapshot', target: '' },
          process: { name: getProcessNameFromPath(imagePath), imagePath },
          event: { provider: 'Process', data: { type: 'Reputation', scanType, processSigned, unsignedDlls } }
        }
        interceptionQueue.enqueuePausedProcess(payload)
        return
      }
      if (typ === 'pid_snapshot_done') {
        const requestId = typeof m.requestId === 'string' ? m.requestId : ''
        if (!requestId) return
        const pending = interceptionControlPending.get(requestId)
        if (!pending) return
        interceptionControlPending.delete(requestId)
        try { if (pending.timer) clearTimeout(pending.timer) } catch {}
        try { pending.resolve(m) } catch {}
        return
      }
      if (typ === 'scan_done') {
        handleSnapshotScanDone().finally(() => {
          isSnapshotScanning = false
          if (scanPromiseResolve) scanPromiseResolve(true)
          try { interceptionQueue.tryShowNext() } catch {}
        })
        return
      }
      if (typ === 'resume_many_done') {
        const requestId = typeof m.requestId === 'string' ? m.requestId : ''
        if (!requestId) return
        const pending = interceptionControlPending.get(requestId)
        if (!pending) return
        interceptionControlPending.delete(requestId)
        try { if (pending.timer) clearTimeout(pending.timer) } catch {}
        try { pending.resolve(m) } catch {}
      }
    })
    interceptionSnapshotWorker.on('error', () => {
      interceptionSnapshotWorker = null
    })
    interceptionSnapshotWorker.on('exit', () => {
      interceptionSnapshotWorker = null
    })
    return interceptionSnapshotWorker
  } catch {
    interceptionSnapshotWorker = null
    return null
  }
}

/**
 * - 函数: `ensureInterceptionWindow`
 * - Function: `ensureInterceptionWindow`
 * - 作用: 懒创建并维护拦截处置窗口单例，在有待处理拦截项时负责展示 UI，并控制窗口不可被普通关闭操作提前销毁。
 * - Purpose: Lazily creates and maintains the interception-handling window singleton, showing the UI when intercepted items are pending and preventing ordinary close actions from destroying it too early.
 * - 调用方: 主进程中需要展示拦截队列弹窗的链路，例如拦截队列调度逻辑。
 * - Callers: Main-process flows that need to display the interception-queue dialog, such as interception queue scheduling logic.
 * - 被调方: `resolveAppIconPath`、`BrowserWindow`、`path.join`、`interceptionWin.isDestroyed`、`interceptionWin.setMenuBarVisibility`、`interceptionWin.removeMenu`、`interceptionWin.loadFile`、`interceptionQueue.tryShowNext`。
 * - Callees: `resolveAppIconPath`, `BrowserWindow`, `path.join`, `interceptionWin.isDestroyed`, `interceptionWin.setMenuBarVisibility`, `interceptionWin.removeMenu`, `interceptionWin.loadFile`, and `interceptionQueue.tryShowNext`.
 * - 变量说明: 无显式入参；`iconPath` 为品牌图标路径；`iconOpt` 为窗口图标配置；`interceptionWinReady` 标记窗口是否可展示内容；`interceptionWinLocked` 控制是否允许用户关闭窗口。
 * - Variables: There are no explicit parameters; `iconPath` is the branded icon path; `iconOpt` is the window icon configuration; `interceptionWinReady` marks whether the window is ready to show content; `interceptionWinLocked` controls whether the user is allowed to close the window.
 * - 接入方式: 任何需要展示拦截结果窗口的主进程入口都应先调用本函数获取单例，再通过队列机制推送展示内容。
 * - Integration: Any main-process entry that needs the interception result window should call this helper first to obtain the singleton, then push content through the queue mechanism.
 * - 错误处理: 已存在且未销毁的窗口直接复用；关闭事件中若应用未退出且窗口仍被锁定，则阻止关闭并重新聚焦；真正销毁后会重置全局状态。
 * - Error Handling: Reuses the existing window when it is still alive; in the close handler, it blocks closure and refocuses the window when the app is not quitting and the window remains locked; once destroyed, it resets the related global state.
 * - 关键词: 拦截窗口单例 | interception window singleton | 弹窗锁定 | dialog lock | 拦截队列展示 | interception queue display | 窗口延迟创建 | lazy window creation | 关闭拦截 | close prevention
 */
function ensureInterceptionWindow() {
  if (interceptionWin && !interceptionWin.isDestroyed()) return interceptionWin
  const iconPath = resolveAppIconPath()
  const iconOpt = iconPath ? { icon: iconPath } : {}
  interceptionWinReady = false
  interceptionWinLocked = true
  interceptionWin = new BrowserWindow({
    ...iconOpt,
    width: 540,
    height: 420,
    resizable: false,
    minimizable: false,
    maximizable: false,
    fullscreenable: false,
    frame: false,
    show: false,
    alwaysOnTop: true,
    skipTaskbar: true,
    transparent: false,
    backgroundColor: '#00000000',
    backgroundMaterial: 'acrylic',
    opacity: 0.98,
    hasShadow: true,
    roundedCorners: true,
    webPreferences: {
      preload: path.join(__dirname, './preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      backgroundThrottling: false
    }
  })
  try { interceptionWin.setMenuBarVisibility(false) } catch {}
  try { interceptionWin.removeMenu() } catch {}
  interceptionWin.on('close', (e) => {
    if (isQuitting) return
    if (interceptionWinLocked) {
      try { e.preventDefault() } catch {}
      try { interceptionWin.show() } catch {}
      try { interceptionWin.focus() } catch {}
    }
  })
  interceptionWin.on('closed', () => {
    interceptionWin = null
    interceptionWinReady = false
    interceptionWinLocked = true
  })
  interceptionWin.loadFile(path.join(__dirname, '../renderer/interception.html'))
  interceptionWin.once('ready-to-show', () => {
    interceptionWinReady = true
    try { interceptionQueue.tryShowNext() } catch {}
  })
  return interceptionWin
}

/**
 * - 函数: `tryStartAutoScanForInterception`
 * - Function: `tryStartAutoScanForInterception`
 * - 作用: 在拦截弹窗命中后尝试自动触发文件扫描，优先挑选进程映像或首个可疑 DLL 作为扫描目标。
 * - Purpose: Tries to trigger an automatic file scan after an interception hit, preferring the process image or the first suspicious DLL as the scan target.
 * - 调用方: 拦截处置链中生成或展示拦截 payload 的主进程逻辑。
 * - Callers: Main-process logic that generates or displays interception payloads in the interception handling flow.
 * - 被调方: `Array.isArray`、`Array.prototype.filter`、`Array.prototype.push`、`setTimeout`、`Date.now`、`Math.random`、`scannerClient.scanFile`。
 * - Callees: `Array.isArray`, `Array.prototype.filter`, `Array.prototype.push`, `setTimeout`, `Date.now`, `Math.random`, and `scannerClient.scanFile`.
 * - 变量说明: `payload` 为拦截事件载荷；`p` 为归一化后的 payload；`proc` 为进程信息对象；`img` 为进程映像路径；`ev`/`d` 为事件与事件数据；`unsignedDlls` 为未签名 DLL 列表；`scanType` 为拦截类型；`targets` 为最终待自动扫描路径列表；`requestId` 为每次扫描请求标识。
 * - Variables: `payload` is the interception event payload; `p` is the normalized payload; `proc` is the process info object; `img` is the process image path; `ev` and `d` are the event and event data; `unsignedDlls` is the unsigned DLL list; `scanType` is the interception type; `targets` is the final list of paths to auto-scan; `requestId` is the identifier for each scan request.
 * - 接入方式: 当拦截命中后希望自动为用户预热一次样本扫描时，直接把拦截 payload 传给本函数即可。
 * - Integration: Pass the interception payload into this helper whenever an interception hit should opportunistically warm up a file scan for the user.
 * - 错误处理: payload 非法、扫描器不可用、目标路径缺失时直接跳过；匹配字段兜底提取失败和 `scanFile` 异常都会被静默吞掉，避免影响拦截 UI 主流程。
 * - Error Handling: Invalid payloads, unavailable scanner clients, or missing target paths are skipped immediately; fallback extraction failures and `scanFile` errors are swallowed so the interception UI flow is not affected.
 * - 关键词: 拦截后自动扫描 | post-interception auto scan | 进程映像预扫 | process image pre-scan | 可疑DLL预扫 | suspicious DLL pre-scan | 异步延后触发 | deferred async trigger | 扫描预热 | scan warmup
 */
function tryStartAutoScanForInterception(payload) {
  const p = payload && typeof payload === 'object' ? payload : null
  if (!p) return
  if (!scannerClient || typeof scannerClient.scanFile !== 'function') return
  const proc = p.process && typeof p.process === 'object' ? p.process : null
  const img = proc && typeof proc.imagePath === 'string' ? proc.imagePath : ''
  const ev = p.event && typeof p.event === 'object' ? p.event : null
  const d = ev && ev.data && typeof ev.data === 'object' ? ev.data : null
  const unsignedDlls = d && Array.isArray(d.unsignedDlls) ? d.unsignedDlls.filter(x => typeof x === 'string' && x) : []
  const scanType = d && typeof d.scanType === 'string' ? d.scanType : ''
  const targets = []
  if ((scanType === 'process' || scanType === 'joint') && img) targets.push(img)
  if ((scanType === 'dll' || scanType === 'joint') && unsignedDlls.length) targets.push(unsignedDlls[0])
  if (!targets.length) {
    try {
      const m = p.match && typeof p.match === 'object' ? p.match : null
      const provider = m && typeof m.provider === 'string' ? m.provider : ''
      const target = m && typeof m.target === 'string' ? m.target : ''
      if (provider === 'File' && target) targets.push(target)
    } catch {}
  }
  if (!targets.length) return
  setTimeout(() => {
    for (const t of targets) {
      const requestId = `intercept_scan_${Date.now()}_${Math.random().toString(16).slice(2)}`
      scannerClient.scanFile(t, requestId).catch(() => {})
    }
  }, 10)
}

/**
 * - 函数: `shouldSkipEtwForAppDirByImage`
 * - Function: `shouldSkipEtwForAppDirByImage`
 * - 作用: 基于进程映像路径判断是否应跳过应用目录下的 ETW 事件，减少自监控噪声。
 * - Purpose: Determines whether ETW events should be skipped for processes whose image path is under the app directory, reducing self-generated monitoring noise.
 * - 调用方: 当前文件暂无直接调用点（保留为与 ETW 过滤链路复用的工具函数）。
 * - Callers: No direct call sites in this file at the moment (kept as a reusable helper for ETW filtering flows).
 * - 被调方: `normalizeLowerPath`、`isUnderDir`。
 * - Callees: `normalizeLowerPath` and `isUnderDir`.
 * - 变量说明: `imagePath` 为进程映像路径；`lower` 为归一化后的路径（小写、反斜杠）；`appDirLower` 为应用目录的归一化路径前缀。
 * - Variables: `imagePath` is the process image path; `lower` is the normalized path (lowercased, backslashes); `appDirLower` is the normalized app directory prefix.
 * - 接入方式: 当 ETW 事件只提供进程映像路径，需要跳过应用自身目录下的进程/行为时调用本函数。
 * - Integration: Use it when ETW context provides only a process image path and you need to ignore processes/activities originating from the app’s own directory.
 * - 错误处理: `imagePath` 为空或归一化结果为空时返回 `false`；通过布尔回退保持 ETW 分发链路不抛异常。
 * - Error Handling: Returns `false` when `imagePath` is empty or normalization yields an empty string; relies on boolean fallbacks so the ETW dispatch chain does not throw.
 * - 关键词: ETW目录跳过 | ETW directory skip | 应用目录过滤 | app directory filter | 进程映像路径 | process image path | 路径归一化 | path normalization | 自监控降噪 | self-noise reduction | skip decision | filter helper | image-based skip | appDirLower | normalizeLowerPath
 */
function shouldSkipEtwForAppDirByImage(imagePath) {
  const lower = normalizeLowerPath(imagePath || '')
  return !!(lower && isUnderDir(lower, appDirLower))
}

/**
 * - 函数: `shouldSkipEtwForAppDirByPath`
 * - Function: `shouldSkipEtwForAppDirByPath`
 * - 作用: 基于文件路径判断是否应跳过应用目录下的 ETW 文件事件，避免把应用自身读写当作风险线索处理。
 * - Purpose: Determines whether ETW file events should be skipped when the file path is under the app directory, preventing the app’s own I/O from being treated as a risk signal.
 * - 调用方: `startEtwWorker`（处理 ETW File 事件时的早期过滤分支）。
 * - Callers: `startEtwWorker` (an early-filter branch when handling ETW File events).
 * - 被调方: `normalizeLowerPath`、`isUnderDir`。
 * - Callees: `normalizeLowerPath` and `isUnderDir`.
 * - 变量说明: `filePath` 为 ETW 事件里的文件路径（例如 `fileName`）；`lower` 为归一化后的路径；`appDirLower` 为应用目录归一化前缀。
 * - Variables: `filePath` is the file path from ETW events (e.g. `fileName`); `lower` is the normalized path; `appDirLower` is the normalized app directory prefix.
 * - 接入方式: 在 ETW 文件事件落到风险分析或拦截队列之前调用本函数，作为“应用目录噪声”过滤器的统一入口。
 * - Integration: Call it before ETW file events are forwarded to risk analysis or interception queues, as the unified “app-directory noise” filter entry.
 * - 错误处理: `filePath` 为空或归一化失败时返回 `false`；仅通过布尔返回值参与控制流，不抛异常。
 * - Error Handling: Returns `false` when `filePath` is empty or normalization fails; participates in control flow only via boolean returns and does not throw.
 * - 关键词: ETW文件事件 | ETW file event | 应用目录跳过 | app-dir skip | 文件路径过滤 | file path filter | 路径归一化 | path normalization | 噪声抑制 | noise suppression | file-based skip | startEtwWorker | isUnderDir | appDirLower | normalizeLowerPath
 */
function shouldSkipEtwForAppDirByPath(filePath) {
  const lower = normalizeLowerPath(filePath || '')
  return !!(lower && isUnderDir(lower, appDirLower))
}

/**
 * - 函数: `requestInterceptionPidSnapshot`
 * - Function: `requestInterceptionPidSnapshot`
 * - 作用: 向快照 worker 发起一次 PID 快照请求，并以 Promise 形式等待对应回执。
 * - Purpose: Sends one PID snapshot request to the snapshot worker and waits for the matching acknowledgment through a Promise.
 * - 调用方: `takeEtwPidSnapshot`。
 * - Callers: `takeEtwPidSnapshot`.
 * - 被调方: `Promise`、`setTimeout`、`Math.max`、`interceptionControlPending.has`、`interceptionControlPending.set`、`w.postMessage`。
 * - Callees: `Promise`, `setTimeout`, `Math.max`, `interceptionControlPending.has`, `interceptionControlPending.set`, and `w.postMessage`.
 * - 变量说明: `w` 为目标 worker；`requestId` 为请求标识；`maxPids` 为快照上限；`timeoutMs` 为超时时间；`rid` 为规范化后的请求 ID；`timer` 为超时定时器。
 * - Variables: `w` is the target worker; `requestId` is the request identifier; `maxPids` is the snapshot cap; `timeoutMs` is the timeout; `rid` is the normalized request ID; `timer` is the timeout timer.
 * - 接入方式: 主进程拿到 worker 单例和请求 ID 后调用本函数，并在 `pid_snapshot_done` 回执中自动收口 Promise。
 * - Integration: Call it after obtaining the worker singleton and a request ID in the main process; the Promise settles automatically when `pid_snapshot_done` arrives.
 * - 错误处理: 缺少 worker 或请求 ID 时立即失败；超时、发送失败或回执丢失时返回 `{ ok: false }` 风格结果并清理挂起表。
 * - Error Handling: Fails immediately when the worker or request ID is missing; timeouts, send failures, or missing acknowledgments resolve to `{ ok: false }` style results and clean up the pending map.
 * - 关键词: Worker PID快照请求 | worker PID snapshot request | Promise回执等待 | Promise acknowledgment wait | 控制挂起表 | control pending map | 超时回退 | timeout fallback | 快照请求消息 | snapshot request message
 */
function requestInterceptionPidSnapshot(w, requestId, maxPids, timeoutMs) {
  const rid = typeof requestId === 'string' ? requestId : ''
  if (!rid || !w) return Promise.resolve({ ok: false })
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      if (interceptionControlPending.has(rid)) interceptionControlPending.delete(rid)
      resolve({ ok: false, timeout: true })
    }, Math.max(250, timeoutMs || 0))
    try { if (timer.unref) timer.unref() } catch {}
    interceptionControlPending.set(rid, { resolve, timer })
    try { w.postMessage({ type: 'pid_snapshot', requestId: rid, maxPids }) } catch {
      try { clearTimeout(timer) } catch {}
      if (interceptionControlPending.has(rid)) interceptionControlPending.delete(rid)
      resolve({ ok: false })
    }
  })
}

/**
 * - 函数: `requestInterceptionResumeMany`
 * - Function: `requestInterceptionResumeMany`
 * - 作用: 向快照 worker 发送批量恢复请求，用于释放已经由快照扫描挂起的进程集合。
 * - Purpose: Sends a batch resume request to the snapshot worker so processes suspended by snapshot scanning can be released together.
 * - 调用方: `resumeAllInterceptedProcesses`、`handleSnapshotScanDone`。
 * - Callers: `resumeAllInterceptedProcesses` and `handleSnapshotScanDone`.
 * - 被调方: `ensureInterceptionSnapshotWorker`、`Promise`、`Array.isArray`、`Array.prototype.map`、`Array.prototype.filter`、`Number.isFinite`、`parseInt`、`setTimeout`、`w.postMessage`。
 * - Callees: `ensureInterceptionSnapshotWorker`, `Promise`, `Array.isArray`, `Array.prototype.map`, `Array.prototype.filter`, `Number.isFinite`, `parseInt`, `setTimeout`, and `w.postMessage`.
 * - 变量说明: `pids` 为待恢复 PID 列表；`timeoutMs` 为等待上限；`list` 为过滤后的有效 PID 数组；`requestId` 为本次批量恢复请求标识；`timer` 为超时定时器。
 * - Variables: `pids` is the PID list to resume; `timeoutMs` is the wait limit; `list` is the filtered valid PID array; `requestId` is the batch-resume request ID; `timer` is the timeout timer.
 * - 接入方式: 在需要统一恢复被拦截进程时调用本函数，并等待 `resume_many_done` 回执决定后续清理动作。
 * - Integration: Use it whenever suspended intercepted processes need a coordinated release, then wait for `resume_many_done` before performing follow-up cleanup.
 * - 错误处理: 空 PID 列表直接返回跳过结果；无 worker、超时或发送失败时返回失败对象并清理挂起请求。
 * - Error Handling: Returns a skipped result for empty PID lists, and returns a failure object while cleaning pending requests when the worker is unavailable, times out, or fails to send.
 * - 关键词: Worker批量恢复请求 | worker batch resume request | 挂起进程释放 | suspended process release | 请求超时回退 | request timeout fallback | 恢复回执等待 | resume acknowledgment wait | PID批处理 | PID batching
 */
function requestInterceptionResumeMany(pids, timeoutMs = 15000) {
  const ps = Array.isArray(pids) ? pids : []
  const list = ps.map(x => (Number.isFinite(x) ? x : parseInt(String(x), 10))).filter(x => Number.isFinite(x) && x > 0)
  if (list.length === 0) return Promise.resolve({ ok: true, skipped: true, total: 0, resumed: 0 })
  const w = ensureInterceptionSnapshotWorker()
  if (!w) return Promise.resolve({ ok: false, error: 'NO_WORKER' })
  const requestId = String(interceptionControlSeq++)
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      if (interceptionControlPending.has(requestId)) interceptionControlPending.delete(requestId)
      resolve({ ok: false, timeout: true })
    }, Math.max(250, timeoutMs || 0))
    try { if (timer.unref) timer.unref() } catch {}
    interceptionControlPending.set(requestId, { resolve, timer })
    try { w.postMessage({ type: 'resume_many', requestId, pids: list }) } catch {
      try { clearTimeout(timer) } catch {}
      if (interceptionControlPending.has(requestId)) interceptionControlPending.delete(requestId)
      resolve({ ok: false })
    }
  })
}

/**
 * - 函数: `resumeAllInterceptedProcesses`
 * - Function: `resumeAllInterceptedProcesses`
 * - 作用: 在退出或人工收口场景下统一恢复当前拦截队列中所有被挂起的进程。
 * - Purpose: Restores all currently suspended processes in the interception queue during shutdown or manual cleanup flows.
 * - 调用方: `handleTrayExitClick`。
 * - Callers: `handleTrayExitClick`.
 * - 被调方: `interceptionQueue.getPausedPids`、`requestInterceptionResumeMany`、`interceptionQueue.clearAll`。
 * - Callees: `interceptionQueue.getPausedPids`, `requestInterceptionResumeMany`, and `interceptionQueue.clearAll`.
 * - 变量说明: 无显式入参；`pids` 为当前队列中的挂起 PID 列表；`res` 为批量恢复结果。
 * - Variables: There are no explicit parameters; `pids` is the suspended PID list from the queue; `res` is the batch-resume result.
 * - 接入方式: 应仅在需要整体清空拦截态时调用，避免和逐条人工处置流程混用。
 * - Integration: Use it only when the interception state needs to be cleared wholesale, not alongside per-item manual handling.
 * - 错误处理: 通过 `interceptionResumeInFlight` 防重入；无论恢复成功与否都会清空队列，异常时返回 `false`。
 * - Error Handling: Uses `interceptionResumeInFlight` as a reentry guard; it clears the queue regardless of resume outcome and returns `false` on exceptions.
 * - 关键词: 拦截队列总恢复 | interception queue full resume | 退出前释放 | release before exit | 挂起PID清空 | suspended PID clearing | 防重入恢复 | reentry-safe resume | 总收口 | global cleanup
 */
async function resumeAllInterceptedProcesses() {
  if (interceptionResumeInFlight) return false
  interceptionResumeInFlight = true
  try {
    const pids = interceptionQueue.getPausedPids()
    if (pids.length === 0) return true
    const res = await requestInterceptionResumeMany(pids, 20000)
    interceptionQueue.clearAll()
    return !!(res && res.ok !== false)
  } catch {
    interceptionQueue.clearAll()
    return false
  } finally {
    interceptionResumeInFlight = false
  }
}

/**
 * - 函数: `handleSnapshotScanDone`
 * - Function: `handleSnapshotScanDone`
 * - 作用: 在快照扫描结束后，对已挂起目标做二次引擎扫描、形成放行/恢复决策并同步允许名单。
 * - Purpose: After snapshot scanning finishes, performs a second engine scan on paused targets, builds allow/resume decisions, and syncs the allowlist.
 * - 调用方: `ensureInterceptionSnapshotWorker` 在接收 `scan_done` 消息后调用。
 * - Callers: Called by `ensureInterceptionSnapshotWorker` after receiving the `scan_done` message.
 * - 被调方: `interceptionQueue.getAllPausedPayloads`、`getPayloadPaths`、`scanPathsWithEngine`、`decideSnapshotActions`、`startupAllowlist.addFiles`、`requestInterceptionResumeMany`、`interceptionQueue.clearPid`、`interceptionSnapshotWorker.postMessage`。
 * - Callees: `interceptionQueue.getAllPausedPayloads`, `getPayloadPaths`, `scanPathsWithEngine`, `decideSnapshotActions`, `startupAllowlist.addFiles`, `requestInterceptionResumeMany`, `interceptionQueue.clearPid`, and `interceptionSnapshotWorker.postMessage`.
 * - 变量说明: `paused` 为当前挂起 payload 列表；`scanTargets` 为待二扫路径集合；`scanByPath` 为引擎扫描结果映射；`plan` 为放行、恢复和清理决策。
 * - Variables: `paused` is the current paused-payload list; `scanTargets` is the set of paths for second-pass scanning; `scanByPath` is the engine scan result map; `plan` is the allow, resume, and cleanup decision bundle.
 * - 接入方式: 仅作为快照 worker 的 `scan_done` 收口处理器使用，不建议从其他普通扫描链路直接复用。
 * - Integration: Use it only as the `scan_done` closeout handler for the snapshot worker rather than calling it from ordinary scan flows.
 * - 错误处理: 任何二次扫描或决策异常都会被记录到控制台，但不会影响 `scan_done` 之后的主线程状态复位。
 * - Error Handling: Any second-pass scan or decision error is logged to the console without preventing the main-thread reset sequence after `scan_done`.
 * - 关键词: 快照扫描收口 | snapshot scan closeout | 二次引擎扫描 | second-pass engine scan | 放行决策 | allow decision | 恢复计划 | resume plan | 允许名单同步 | allowlist sync
 */
async function handleSnapshotScanDone() {
  try {
    const paused = interceptionQueue.getAllPausedPayloads()
    if (!paused.length) return

    const scanTargets = new Set()
    for (const p of paused) {
      const list = getPayloadPaths(p)
      for (const x of list) scanTargets.add(x)
    }

    const scanByPath = await scanPathsWithEngine(Array.from(scanTargets))
    const plan = decideSnapshotActions(paused, scanByPath)

    if (plan.allowPaths.length > 0) {
      try { startupAllowlist.addFiles(plan.allowPaths) } catch {}
    }

    if (plan.allowPaths.length > 0 && interceptionSnapshotWorker) {
      interceptionSnapshotWorker.postMessage({ type: 'allow_dlls', paths: plan.allowPaths })
    }

    if (plan.clearPids.length > 0) {
      for (const pid of plan.clearPids) interceptionQueue.clearPid(pid)
    }

    if (plan.resumePids.length > 0) {
      await requestInterceptionResumeMany(plan.resumePids, 20000)
    }
  } catch (e) {
    console.error('Snapshot scan done handler error:', e)
  }
}

/**
 * - 函数: `scanPathsWithEngine`
 * - Function: `scanPathsWithEngine`
 * - 作用: 对快照扫描命中的进程文件和 DLL 路径执行二次引擎扫描，并按路径返回扫描结果映射。
 * - Purpose: Performs a second engine scan for process files and DLL paths captured by snapshot scanning, then returns a path-keyed result map.
 * - 调用方: `handleSnapshotScanDone`。
 * - Callers: `handleSnapshotScanDone`.
 * - 被调方: `Array.isArray`、`Set`、`Map`、`normalizePathKey`、`Number.isFinite`、`Math.max`、`Math.min`、`require('os').cpus`、内部 `scanOne`、`Promise.all`。
 * - Callees: `Array.isArray`, `Set`, `Map`, `normalizePathKey`, `Number.isFinite`, `Math.max`, `Math.min`, `require('os').cpus`, the inner `scanOne`, and `Promise.all`.
 * - 变量说明: `paths` 为待扫描原始路径集合；`list` 为过滤后的非空路径；`onlyCommonExt` 控制是否只扫常见可执行扩展名；`maxMB` 为文件大小上限；`unique` 为去重后的任务列表；`results` 为路径到扫描结果的映射；`idx` 为并发游标；`concurrency` 为并发 worker 数。
 * - Variables: `paths` is the raw path collection to scan; `list` is the filtered non-empty path list; `onlyCommonExt` controls whether only common executable extensions are scanned; `maxMB` is the file-size cap; `unique` is the deduplicated work list; `results` is the path-to-scan-result map; `idx` is the shared concurrency cursor; `concurrency` is the worker count.
 * - 接入方式: 仅在快照扫描结束后的二次判定阶段调用，把 `getPayloadPaths(...)` 收集到的路径数组传入即可。
 * - Integration: Use it during the second-pass decision phase after snapshot scanning by passing in the path array collected from `getPayloadPaths(...)`.
 * - 错误处理: 空路径列表直接返回空 `Map`；单文件扫描异常由内部 `scanOne` 吞掉，确保并发批处理不会因个别路径失败而中断。
 * - Error Handling: Returns an empty `Map` for empty input; per-file scan failures are absorbed by the inner `scanOne` so the concurrent batch is not interrupted by individual path errors.
 * - 关键词: 二次引擎扫描 | second-pass engine scan | 路径去重 | path deduplication | 并发扫描池 | concurrent scan pool | 快照后复检 | post-snapshot rescan | 结果映射 | result map
 */
async function scanPathsWithEngine(paths) {
  const list = Array.isArray(paths) ? paths.filter(x => typeof x === 'string' && x) : []
  if (!list.length) return new Map()

  const scanCfg = (config && config.scan) ? config.scan : {}
  const onlyCommonExt = scanCfg.commonExtensionsOnly === true

  const cfg = (config && config.scanner) ? config.scanner : {}
  const maxMB = Number.isFinite(cfg.maxFileSizeMB) ? Math.max(1, Math.floor(cfg.maxFileSizeMB)) : 500
  const fsMod = fs

  const unique = []
  const seen = new Set()
  for (const p of list) {
    const k = normalizePathKey(p)
    if (!k || seen.has(k)) continue
    seen.add(k)
    unique.push(p)
  }

  const results = new Map()
  let idx = 0
  const concurrency = Math.min(12, Math.max(2, require('os').cpus().length || 4))

  /**
   * - 函数: `scanOne`
   * - Function: `scanOne`
   * - 作用: 对单个路径执行文件存在性、大小和扩展名检查后，向扫描引擎发起一次真实扫描请求。
   * - Purpose: Validates one path for existence, size, and extension, then sends a real scan request to the scanning engine.
   * - 调用方: 外层 `scanPathsWithEngine` 的并发 worker 循环。
   * - Callers: The concurrent worker loop inside the outer `scanPathsWithEngine`.
   * - 被调方: `normalizePathKey`、`results.has`、`path.extname`、`fsMod.promises.stat`、`Number.isFinite`、`Date.now`、`Math.random`、`scannerClient.scanFile`、`results.set`。
   * - Callees: `normalizePathKey`, `results.has`, `path.extname`, `fsMod.promises.stat`, `Number.isFinite`, `Date.now`, `Math.random`, `scannerClient.scanFile`, and `results.set`.
   * - 变量说明: `p` 为当前待扫描路径；`key` 为规范化路径键；`ext` 为文件扩展名；`stat` 为文件元数据；`requestId` 为本次引擎扫描请求 ID；`res` 为扫描结果对象。
   * - Variables: `p` is the current path to scan; `key` is the normalized path key; `ext` is the file extension; `stat` is the file metadata; `requestId` is the engine-scan request ID; `res` is the scan result object.
   * - 接入方式: 只应作为 `scanPathsWithEngine` 的内部步骤使用，通过共享闭包读取 `results`、`onlyCommonExt`、`maxMB` 等上下文。
   * - Integration: It should only be used as an internal step of `scanPathsWithEngine`, relying on the shared closure state such as `results`, `onlyCommonExt`, and `maxMB`.
   * - 错误处理: 路径无效、文件过大、`stat` 失败或引擎扫描异常时都会直接跳过当前项，不向外抛错。
   * - Error Handling: Invalid paths, oversized files, `stat` failures, or engine scan exceptions all cause the current item to be skipped without throwing outward.
   * - 关键词: 单文件引擎扫描 | single-file engine scan | 文件大小过滤 | file size filter | 扩展名过滤 | extension filter | 请求ID生成 | request ID generation | 结果写回 | result write-back
   */
  async function scanOne(p) {
    const key = normalizePathKey(p)
    if (!key || results.has(key)) return
    if (onlyCommonExt) {
      const ext = path.extname(p).toLowerCase()
      if (ext !== '.exe' && ext !== '.dll') return
    }
    try {
      const stat = await fsMod.promises.stat(p)
      if (stat && Number.isFinite(stat.size) && stat.size > maxMB * 1024 * 1024) return
    } catch {
      return
    }
    try {
      const requestId = String(Date.now()) + '-' + String(Math.random())
      const res = await scannerClient.scanFile(p, requestId)
      if (res && typeof res === 'object') results.set(key, res)
    } catch {
    }
  }

  const workers = Array.from({ length: concurrency }).map(async () => {
    while (true) {
      const cur = idx++
      if (cur >= unique.length) break
      await scanOne(unique[cur])
    }
  })
  await Promise.all(workers)
  return results
}


/**
 * - 函数: `startInterceptionSnapshotScan`
 * - Function: `startInterceptionSnapshotScan`
 * - 作用: 按 ETW 拦截配置启动一次进程快照签名扫描，把排除目录和允许名单下发给快照 worker。
 * - Purpose: Starts one process-snapshot signature scan from the ETW interception config and pushes exclusion directories plus allowlist files into the snapshot worker.
 * - 调用方: `startEtwWorker`。
 * - Callers: `startEtwWorker`.
 * - 被调方: `ensureInterceptionSnapshotWorker`、`interceptionQueue.configure`、`Number.isFinite`、`Math.max`、`Math.floor`、`path.dirname`、`app.getPath`、`app.getAppPath`、`startupAllowlist.getFiles`、`w.postMessage`。
 * - Callees: `ensureInterceptionSnapshotWorker`, `interceptionQueue.configure`, `Number.isFinite`, `Math.max`, `Math.floor`, `path.dirname`, `app.getPath`, `app.getAppPath`, `startupAllowlist.getFiles`, and `w.postMessage`.
 * - 变量说明: `etwCfg` 为 ETW 配置；`icfg` 为拦截子配置；`w` 为快照 worker；`maxPids`、`modulesBufferBytes`、`skipSystemDll`、`maxUnsignedDllsPerProcess` 为扫描参数；`exclusionPaths` 与 `allowlistFiles` 为路径过滤输入。
 * - Variables: `etwCfg` is the ETW config; `icfg` is the interception sub-config; `w` is the snapshot worker; `maxPids`, `modulesBufferBytes`, `skipSystemDll`, and `maxUnsignedDllsPerProcess` are scan parameters; `exclusionPaths` and `allowlistFiles` are path-filter inputs.
 * - 接入方式: ETW worker 启动完成后调用一次即可；若后续想重复触发，需先处理 `interceptionSnapshotStarted` 的单次启动闸门。
 * - Integration: Call it once after ETW worker startup; if repeated triggering is needed later, handle the `interceptionSnapshotStarted` one-shot gate first.
 * - 错误处理: 配置关闭、worker 不可用或启动异常时都会安全结束，并同步释放 `isSnapshotScanning`/`scanPromiseResolve` 状态。
 * - Error Handling: When configuration is disabled, the worker is unavailable, or startup throws, it exits safely and releases the `isSnapshotScanning` and `scanPromiseResolve` state.
 * - 关键词: 快照拦截启动 | snapshot interception start | ETW联动扫描 | ETW-linked scan | 排除目录下发 | exclusion path push | 允许名单下发 | allowlist push | 单次扫描闸门 | one-shot scan gate
 */
function startInterceptionSnapshotScan() {
  try {
    const etwCfg = (config && config.etw) ? config.etw : {}
    const icfg = (etwCfg && etwCfg.interception && typeof etwCfg.interception === 'object') ? etwCfg.interception : {}
    interceptionQueue.configure(icfg)
    if (icfg.enabled !== true) { isSnapshotScanning = false; if (scanPromiseResolve) scanPromiseResolve(true); return }
    if (icfg.snapshotVerifyOnEtwStart === false) { isSnapshotScanning = false; if (scanPromiseResolve) scanPromiseResolve(true); return }
    if (interceptionSnapshotStarted) return
    interceptionSnapshotStarted = true
    isSnapshotScanning = true
    const w = ensureInterceptionSnapshotWorker()
    if (!w) { isSnapshotScanning = false; if (scanPromiseResolve) scanPromiseResolve(true); return }
    const maxPids = Number.isFinite(icfg.snapshotMaxPids) ? Math.max(256, Math.floor(icfg.snapshotMaxPids)) : 8192
    const modulesBufferBytes = Number.isFinite(icfg.modulesBufferBytes) ? Math.max(4096, Math.floor(icfg.modulesBufferBytes)) : 65536
    const skipSystemDll = icfg.skipSystemDll !== false
    const maxUnsignedDllsPerProcess = Number.isFinite(icfg.maxUnsignedDllsPerProcess) ? Math.max(1, Math.floor(icfg.maxUnsignedDllsPerProcess)) : 16

    const exclusionPaths = []
    try {
      const sysRoot = process.env.SystemRoot || process.env.WINDIR
      if (sysRoot) exclusionPaths.push(sysRoot)
      exclusionPaths.push(path.dirname(app.getPath('exe')))
      exclusionPaths.push(app.getAppPath())
    } catch {}

    let allowlistFiles = []
    try { allowlistFiles = startupAllowlist.getFiles() } catch { allowlistFiles = [] }
    w.postMessage({ type: 'scan', config: { maxPids, modulesBufferBytes, skipSystemDll, maxUnsignedDllsPerProcess, exclusionPaths, allowlistFiles } })
  } catch {
    isSnapshotScanning = false
    if (scanPromiseResolve) scanPromiseResolve(true)
  }
}

/**
 * - 函数: `startEtwWorker`
 * - Function: `startEtwWorker`
 * - 作用: 启动主进程侧 ETW 工作线程，并把 ETW 原始事件、规则命中、暂停/恢复控制结果接入主窗口、行为分析器、拦截队列和风险研判 worker，属于行为监控链路的总入口之一。
 * - Purpose: Starts the ETW worker thread on the main-process side and wires ETW logs, rule matches, and pause/resume control results into the UI, behavior analyzer, interception queue, and risk-analysis worker.
 * - 调用方: `behavior-resume-etw` IPC 恢复流程，以及主进程安全组件初始化阶段的 ETW 启动逻辑。
 * - Callers: The `behavior-resume-etw` IPC recovery flow and the ETW startup path during security-component initialization in the main process.
 * - 被调方: `ensureEtwRiskWorker`、`Worker`、`resolveEtwProcessInfo`、`resolveMaybeRelativePath`、`normalizeLowerPath`、`isUnderDir`、`getProcessNameFromPath`、`interceptionQueue.enqueuePausedProcess`、`behavior.ingest`、`win.webContents.send`。
 * - Callees: `ensureEtwRiskWorker`, `Worker`, `resolveEtwProcessInfo`, `resolveMaybeRelativePath`, `normalizeLowerPath`, `isUnderDir`, `getProcessNameFromPath`, `interceptionQueue.enqueuePausedProcess`, `behavior.ingest`, `win.webContents.send`.
 * - 变量说明: 无显式入参；`workerPath` 为 ETW worker 脚本路径；`msg` 为 worker 回传消息；`pid`、`imagePath`、`ev`、`scanPath` 用于拼装进程命中、文件事件与风险扫描上下文；`rw` 为 ETW 风险分析 worker 实例。
 * - Variables: No explicit parameters; `workerPath` is the ETW worker script path; `msg` is the worker message payload; `pid`, `imagePath`, `ev`, and `scanPath` build process-hit and file-event context; `rw` is the ETW risk worker instance.
 * - 接入方式: 仅供主进程内部调用；若新增行为监控启动点，应先保证 `config.etw`、`behavior`、`interceptionQueue` 和窗口消息通道已初始化，再调用本函数，避免 worker 启动后事件无处消费。
 * - Integration: Use it only inside the main process; if you add another behavior-monitoring bootstrap path, ensure `config.etw`, `behavior`, `interceptionQueue`, and the window messaging channel are ready before calling it so worker events have valid consumers.
 * - 错误处理: 对脚本缺失、消息路由、风险 worker 投递、路径解析和 UI 通知中的局部异常采用兜底捕获；启动失败时记录 `etwLastError`/`etwLastStatus` 并安全清理挂起状态，避免 ETW 控制链路卡死。
 * - Error Handling: Uses defensive `try/catch` blocks around script lookup, message routing, risk-worker forwarding, path resolution, and UI notifications; on startup failure it updates `etwLastError`/`etwLastStatus` and clears pending state to avoid wedging the ETW control flow.
 * - 关键词: ETW启动 | ETW startup | 行为监控 | behavior monitoring | 规则命中 | rule match | 风险研判 | risk analysis | 进程拦截 | process interception
 */
function startEtwWorker() {
  if (etwWorker) return
  try {
    ensureEtwRiskWorker()
    const workerPath = path.join(__dirname, 'workers/etw_worker.js')
    if (!fs.existsSync(workerPath)) {
      console.warn('主进程: ETW Worker 脚本未找到:', workerPath)
      return
    }
    etwWorker = new Worker(workerPath)

    try {
      const paths = Array.from(pendingTrustedAdd.paths)
      const pids = Array.from(pendingTrustedAdd.pids)
      if ((paths && paths.length) || (pids && pids.length)) {
        etwWorker.postMessage({ type: 'trusted_add', paths, pids })
        pendingTrustedAdd.paths.clear()
        pendingTrustedAdd.pids.clear()
      }
    } catch {}
    
    etwWorker.on('message', (msg) => {
      if (msg && (msg.type === 'paused' || msg.type === 'resumed')) {
        const reqId = msg.requestId
        const pending = etwControlPending.get(reqId)
        if (pending) {
          etwControlPending.delete(reqId)
          try { if (pending.timer) clearTimeout(pending.timer) } catch {}
          try { pending.resolve(msg) } catch {}
        }
        return
      }
      if (msg && msg.type === 'match') {
        const pid = Number.isFinite(msg.pid) ? msg.pid : parseInt(String(msg.pid), 10)
        if (!Number.isFinite(pid) || pid <= 0) return
        const m = msg.match && typeof msg.match === 'object' ? msg.match : {}
        const ruleId = typeof m.ruleId === 'string' ? m.ruleId : ''
        const threatType = typeof m.threatType === 'string' ? m.threatType : ''
        const severity = Number.isFinite(m.severity) ? m.severity : 4
        const recommendAction = typeof m.recommendAction === 'string' ? m.recommendAction : 'block'

        const now = Date.now()
        let procInfo = resolveEtwProcessInfo(pid, now, (config && config.etw) ? config.etw : {}) || null
        let imagePath = procInfo && typeof procInfo.imagePath === 'string' ? procInfo.imagePath : ''
        if (!imagePath && winapi && typeof winapi.getProcessImagePathByPid === 'function') {
          try { imagePath = winapi.getProcessImagePathByPid(pid) || '' } catch { imagePath = '' }
        }
        imagePath = resolveMaybeRelativePath(imagePath)
        const lowerImage = normalizeLowerPath(imagePath || '')
        if (lowerImage && isUnderDir(lowerImage, appDirLower)) return

        const ev = msg.event && typeof msg.event === 'object' ? msg.event : null
        const targetLower = normalizeLowerPath(ev && typeof ev.target === 'string' ? ev.target : '')
        if (targetLower && isUnderDir(targetLower, appDirLower)) return
        if (ruleId === 'test_rule_trigger') {
          const payload = {
            pid,
            paused: false,
            triggeredAt: Date.now(),
            threatType: threatType || '规则引擎测试命中',
            severity: 1,
            recommendAction: 'allow',
            match: { ruleId, provider: ev && ev.provider ? ev.provider : '', op: ev && ev.op ? ev.op : '', target: ev && ev.target ? ev.target : '' },
            process: { name: getProcessNameFromPath(imagePath), imagePath },
            event: { provider: ev && ev.provider ? ev.provider : 'ETW', data: msg },
            context: Array.isArray(msg.context) ? msg.context : []
          }
          interceptionQueue.enqueuePausedProcess(payload)
          return
        }

        const provider = ev && typeof ev.provider === 'string' ? ev.provider : ''
        const op = ev && typeof ev.op === 'string' ? ev.op : ''
        const target = ev && typeof ev.target === 'string' ? ev.target : ''
        const scanPath = (provider === 'File' || (provider === 'Process' && op === 'Start')) ? target : ''
        if (!scanPath) return
        const rw = ensureEtwRiskWorker()
        if (!rw) return
        try {
          rw.postMessage({
            type: 'rule_match',
            pid,
            processName: getProcessNameFromPath(imagePath),
            imagePath,
            provider,
            op,
            scanPath,
            ruleId,
            threatType,
            severity,
            recommendAction,
            match: msg.match || null,
            context: Array.isArray(msg.context) ? msg.context : []
          })
        } catch {}
        return
      }
      if (msg.type === 'log') {
        const ev = msg.event && typeof msg.event === 'object' ? msg.event : null
        const p = ev && typeof ev.provider === 'string' ? ev.provider : ''
        const d = ev && ev.data && typeof ev.data === 'object' ? ev.data : null
        const etwCfg = (config && config.etw) ? config.etw : {}

        try {
          if (p === 'Process' && d) {
            refreshEtwPidCacheConfig(etwCfg)
            const now = Date.now()
            pruneEtwPidCache(now)
            const typ = typeof d.type === 'string' ? d.type : ''
            const subjectPid = Number.isFinite(d.processId) ? d.processId : null
            if (typ === 'Start') {
              const pid = subjectPid
              if (pid != null) {
                let img = null
                if (winapi && typeof winapi.getProcessImagePathByPid === 'function') {
                  try { img = winapi.getProcessImagePathByPid(pid) } catch {}
                }
                if (!img) img = (typeof d.imageName === 'string' && d.imageName) ? d.imageName : null
                if (img) img = resolveMaybeRelativePath(img)
                if (img) upsertEtwPid(pid, img, now)
                if (img) {
                  const rw = ensureEtwRiskWorker()
                  if (rw) {
                    const icfg = (etwCfg && etwCfg.interception && typeof etwCfg.interception === 'object') ? etwCfg.interception : {}
                    const modulesBufferBytes = Number.isFinite(icfg.modulesBufferBytes) ? Math.max(4096, Math.floor(icfg.modulesBufferBytes)) : 262144
                    try {
                      rw.postMessage({ type: 'process_start', pid, imagePath: img, processName: getProcessNameFromPath(img), modulesBufferBytes })
                    } catch {}
                  }
                }
              }
            } else if (typ === 'Stop') {
              if (subjectPid != null) {
                removeEtwPid(subjectPid)
              }
            }
          }
        } catch {}

        try {
          if (p === 'File' && d && typeof d.fileName === 'string' && d.fileName) {
            const actorPid = Number.isFinite(ev.pid) ? ev.pid : parseInt(String(ev.pid), 10)
            const fileName = d.fileName
            const op0 = typeof d.type === 'string' ? d.type : ''
            const op = (op0 === 'Open' || op0 === 'Modify' || op0 === 'Rename' || op0 === 'Create') ? op0 : ''
            if (Number.isFinite(actorPid) && actorPid > 0 && op && !shouldSkipEtwForAppDirByPath(fileName)) {
              const rw = ensureEtwRiskWorker()
              if (!rw) return
              const now2 = Date.now()
              const procInfo = resolveEtwProcessInfo(actorPid, now2, etwCfg) || null
              let actorImg = procInfo && typeof procInfo.imagePath === 'string' ? procInfo.imagePath : ''
              if (!actorImg && winapi && typeof winapi.getProcessImagePathByPid === 'function') {
                try { actorImg = winapi.getProcessImagePathByPid(actorPid) || '' } catch { actorImg = '' }
              }
              actorImg = resolveMaybeRelativePath(actorImg)
              try {
                rw.postMessage({ type: 'file_event', pid: actorPid, processName: getProcessNameFromPath(actorImg), actorImage: actorImg, filePath: fileName, op: op === 'Create' ? 'Open' : op })
              } catch {}
            }
          }
        } catch {}

        eventLogs.unshift(msg.event)
        if (eventLogs.length > 500) eventLogs.pop()
        if (isBehaviorMonitoringEnabled(config)) {
          try { behavior.ingest(msg.event) } catch {}
        }

        const logToConsole = etwCfg.logToConsole !== false
        const logParsedToConsole = etwCfg.logParsedToConsole === true
        const resolveProcessName = etwCfg.resolveProcessName === true
        const maxPerSecond = Number.isFinite(etwCfg.consoleMaxPerSecond) ? Math.max(0, Math.floor(etwCfg.consoleMaxPerSecond)) : 200

        if ((logToConsole || logParsedToConsole) && maxPerSecond > 0) {
          if (!etwConsoleLimiter || etwConsoleLimiterMax !== maxPerSecond) {
            etwConsoleLimiter = createRateLimiter(maxPerSecond)
            etwConsoleLimiterMax = maxPerSecond
          }
          const allow = etwConsoleLimiter ? etwConsoleLimiter() : true
          if (allow) {
            if (logToConsole) {
              const line = formatEtwEventForConsole(msg.event)
              if (line) console.log('ETW:', line)
            }
            if (logParsedToConsole) {
              const line = formatEtwEventForParsedConsole(msg.event)
              if (line) console.log('ETW:', line)
            }
          }
        }
        
        if (win && !win.isDestroyed()) {
          win.webContents.send('etw-log', msg.event)
        }
      } else if (msg.type === 'error') {
        const code = msg && msg.code ? msg.code : 'ETW_ERROR'
        etwLastError = { at: Date.now(), code, message: msg && msg.message ? msg.message : '', details: msg && msg.details ? msg.details : null }
        if (etwStartPending) {
          const p = etwStartPending
          etwStartPending = null
          try { if (p.timer) clearTimeout(p.timer) } catch {}
          try { p.resolve(false) } catch {}
        }
      } else if (msg.type === 'status') {
        etwLastStatus = { at: Date.now(), message: msg.message }
        if (etwStartPending) {
          const text = msg && msg.message ? String(msg.message) : ''
          const isStarted = text.includes('Monitoring started') || text.includes('ETW disabled by config')
          if (isStarted) {
            const p = etwStartPending
            etwStartPending = null
            try { if (p.timer) clearTimeout(p.timer) } catch {}
            try { p.resolve(true) } catch {}
            try { setImmediate(() => { takeEtwPidSnapshot(); startInterceptionSnapshotScan() }) } catch {}
          }
        }
        try {
          const text2 = msg && msg.message ? String(msg.message) : ''
          if (text2.includes('Monitoring started')) setImmediate(() => { takeEtwPidSnapshot(); startInterceptionSnapshotScan() })
        } catch {}
      }
    })
    
    etwWorker.on('error', (err) => {
      etwLastError = { at: Date.now(), code: 'ETW_WORKER_CRASH', message: err && err.message ? String(err.message) : String(err || ''), details: null }
      if (etwStartPending) {
        const p = etwStartPending
        etwStartPending = null
        try { if (p.timer) clearTimeout(p.timer) } catch {}
        try { p.resolve(false) } catch {}
      }
      etwWorker = null
    })
    
    etwWorker.on('exit', (code) => {
      etwLastStatus = { at: Date.now(), message: `worker exited (${code})` }
      if (etwStartPending) {
        const p = etwStartPending
        etwStartPending = null
        try { if (p.timer) clearTimeout(p.timer) } catch {}
        try { p.resolve(false) } catch {}
      }
      etwWorker = null
    })
    
    void requestEtwStart()
    
  } catch (e) {
    console.error('主进程: 启动 ETW Worker 失败:', e)
  }
}

/**
 * - 函数: `requestEtwStart`
 * - Function: `requestEtwStart`
 * - 作用: 向 `etwWorker` 发送启动指令并等待启动结果回执，通过 `etwStartPending` 把并发调用折叠为单个 Promise，避免重复 start 请求导致 ETW 线程状态错乱。
 * - Purpose: Sends a start command to `etwWorker` and waits for the startup acknowledgement, deduplicating concurrent calls via `etwStartPending` to avoid duplicated start requests and inconsistent ETW state.
 * - 调用方: `startEtwWorker`（启动 worker 后触发启动握手）、`ipcMain.handle('behavior-resume-etw')`（恢复链路在重启 worker 后触发启动握手）。
 * - Callers: `startEtwWorker` (triggers the start handshake after creating the worker), `ipcMain.handle('behavior-resume-etw')` (triggers the handshake after restarting the worker during resume).
 * - 被调方: `Promise`、`setTimeout`、`Math.max`、`timer.unref`、`Worker#postMessage`、`clearTimeout`。
 * - Callees: `Promise`, `setTimeout`, `Math.max`, `timer.unref`, `Worker#postMessage`, `clearTimeout`.
 * - 变量说明: `timeoutMs` 为等待启动回执的超时毫秒；`cfg` 为下发给 ETW worker 的 `config.etw`；`etwStartPending` 保存当前 in-flight 启动请求的 `{ promise, resolve, timer }`，用于去重与超时回收。
 * - Variables: `timeoutMs` is the timeout (ms) to wait for the startup acknowledgement; `cfg` is the `config.etw` payload; `etwStartPending` stores the in-flight start request `{ promise, resolve, timer }` for dedupe and timeout cleanup.
 * - 接入方式: 仅在 `etwWorker` 已由 `startEtwWorker()` 创建并已注册 message 路由之后调用；若你新增“ETW 重启/恢复”路径，应复用本函数获取统一的超时与去重语义，并依赖 `startEtwWorker` 的 `status` 消息分支来 resolve。
 * - Integration: Call only after `etwWorker` is created by `startEtwWorker()` and its message routing is installed; if you add more ETW restart/resume paths, reuse this function for consistent timeout/dedupe semantics and rely on the `status`-message branch in `startEtwWorker` to resolve.
 * - 错误处理: `etwWorker` 不存在时直接返回 `false`；超时触发时清空 `etwStartPending` 并 resolve `false`；`postMessage` 失败时清理定时器并 resolve `false`；本函数不抛出异常，避免阻断 UI/IPC 控制链路。
 * - Error Handling: Returns `false` if `etwWorker` is missing; on timeout it clears `etwStartPending` and resolves `false`; if `postMessage` fails it clears the timer and resolves `false`; it never throws to avoid breaking UI/IPC control flows.
 * - 关键词: ETW启动请求 | ETW start request | 启动握手 | start handshake | 幂等去重 | idempotent dedupe | 超时控制 | timeout | etwStartPending | startEtwWorker | Worker#postMessage | config.etw | 状态回执 | status ack
 */
function requestEtwStart(timeoutMs = 5000) {
  if (!etwWorker) return Promise.resolve(false)
  if (etwStartPending) return etwStartPending.promise
  const cfg = (config && config.etw) ? config.etw : null
  let resolveFn = null
  const promise = new Promise((resolve) => { resolveFn = resolve })
  const timer = setTimeout(() => {
    if (etwStartPending && etwStartPending.resolve === resolveFn) {
      etwStartPending = null
      resolveFn(false)
    }
  }, Math.max(250, timeoutMs || 0))
  try { if (timer.unref) timer.unref() } catch {}
  etwStartPending = { promise, resolve: resolveFn, timer }
  try {
    etwWorker.postMessage({ type: 'start', config: cfg })
  } catch {
    try { clearTimeout(timer) } catch {}
    etwStartPending = null
    resolveFn(false)
  }
  return promise
}

/**
 * - 函数: `controlEtwWorker`
 * - Function: `controlEtwWorker`
 * - 作用: 向 ETW worker 发送控制指令（例如 `pause` / `resume`），并通过 `requestId` 与 `etwControlPending` 等待对应回执，实现 IPC 侧对 ETW 监控会话的可控暂停/恢复。
 * - Purpose: Sends a control command (e.g. `pause` / `resume`) to the ETW worker and waits for the corresponding acknowledgement via `requestId` and `etwControlPending`, enabling controllable pause/resume of the ETW monitoring session from IPC.
 * - 调用方: `ipcMain.handle('behavior-pause-etw')`、`ipcMain.handle('behavior-clear-all')`（清库前暂停/结束后恢复）、`ipcMain.handle('behavior-resume-etw')`（恢复监控）。
 * - Callers: `ipcMain.handle('behavior-pause-etw')`, `ipcMain.handle('behavior-clear-all')` (pause before clearing DB and resume after), `ipcMain.handle('behavior-resume-etw')` (resume monitoring).
 * - 被调方: `String`、`Promise`、`Map#set`、`Map#has`、`Map#delete`、`setTimeout`、`timer.unref`、`Worker#postMessage`、`clearTimeout`。
 * - Callees: `String`, `Promise`, `Map#set`, `Map#has`, `Map#delete`, `setTimeout`, `timer.unref`, `Worker#postMessage`, `clearTimeout`.
 * - 变量说明: `type` 为控制类型（通常为 `'pause'`/`'resume'`）；`reqId` 为递增序列生成的请求标识；`etwControlSeq` 为模块级序列号；`etwControlPending` 为 `{ requestId -> { resolve, timer } }` 的等待表；返回值对象中 `ok/timeout/skipped` 描述控制结果。
 * - Variables: `type` is the control type (typically `'pause'`/`'resume'`); `reqId` is the request identifier generated from a monotonically increasing sequence; `etwControlSeq` is the module-level counter; `etwControlPending` maps `{ requestId -> { resolve, timer } }`; the return object fields `ok/timeout/skipped` describe the outcome.
 * - 接入方式: 仅在 `startEtwWorker()` 已创建 worker 且其 message 处理分支会对 `paused/resumed` 回执进行 resolve 的前提下使用；新增控制类型时需确保 ETW worker 也会以同一 `requestId` 返回回执，否则会触发超时回收。
 * - Integration: Use only when `startEtwWorker()` has created the worker and its message handler resolves `paused/resumed` acknowledgements; if you add new control types, ensure the ETW worker replies with the same `requestId`, otherwise this call will timeout and be cleaned up.
 * - 错误处理: 无 worker 时返回 `{ ok: true, skipped: true }` 作为安全降级；超时返回 `{ ok: false, timeout: true }` 并清理等待表；`postMessage` 失败返回 `{ ok: false }` 并清理等待表与定时器；不抛异常以避免阻断 IPC handler。
 * - Error Handling: If the worker is missing it safely degrades to `{ ok: true, skipped: true }`; on timeout it returns `{ ok: false, timeout: true }` and cleans the pending map; if `postMessage` fails it returns `{ ok: false }` and cleans the map and timer; it never throws to avoid breaking IPC handlers.
 * - 关键词: ETW控制 | ETW control | 暂停恢复 | pause resume | 请求回执 | request ack | requestId | etwControlPending | IPC控制链路 | IPC control | Worker#postMessage | 超时回收 | timeout cleanup | behavior-resume-etw
 */
function controlEtwWorker(type) {
  if (!etwWorker) return Promise.resolve({ ok: true, skipped: true })
  const reqId = String(etwControlSeq++)
  return new Promise((resolve) => {
    const pending = { resolve, timer: null }
    etwControlPending.set(reqId, pending)
    const timer = setTimeout(() => {
      if (etwControlPending.has(reqId)) etwControlPending.delete(reqId)
      resolve({ ok: false, timeout: true })
    }, 5000)
    try { if (timer.unref) timer.unref() } catch {}
    pending.timer = timer
    try {
      etwWorker.postMessage({ type, requestId: reqId })
    } catch {
      clearTimeout(timer)
      if (etwControlPending.has(reqId)) etwControlPending.delete(reqId)
      resolve({ ok: false })
    }
  })
}

/**
 * - 函数: `createSplash`
 * - Function: `createSplash`
 * - 作用: 创建应用启动阶段的 Splash 窗口，负责展示品牌名、启动状态与本地化文案，并在主窗口就绪前提供轻量过渡 UI。
 * - Purpose: Creates the startup Splash window that shows branding, startup status, and localized text, providing a lightweight transition UI before the main window is ready.
 * - 调用方: `runStartupSequence({ prepareUi })` 中的界面预热流程，在 `createWindow()` 之前调用以尽早向用户展示启动反馈。
 * - Callers: The UI warm-up step inside `runStartupSequence({ prepareUi })`, where it runs before `createWindow()` to show startup feedback as early as possible.
 * - 被调方: `resolveAppIconPath`、`BrowserWindow`、`path.join`、`splash.loadFile`、`t`、`splash.webContents.executeJavaScript`、`splash.show`。
 * - Callees: `resolveAppIconPath`, `BrowserWindow`, `path.join`, `splash.loadFile`, `t`, `splash.webContents.executeJavaScript`, `splash.show`.
 * - 变量说明: 无显式入参；`iconPath`/`iconOpt` 用于按平台装配窗口图标；全局 `splash` 保存当前启动窗口实例；`locale` 为页面 `<html lang>` 使用的语言代码；`statusText` 为启动状态文案。
 * - Variables: No explicit parameters; `iconPath` and `iconOpt` prepare the platform icon, the global `splash` stores the active startup window, `locale` drives the page `<html lang>`, and `statusText` holds the visible startup message.
 * - 接入方式: 仅应在主进程启动 UI 生命周期时调用一次；若新增启动阶段状态展示，应继续复用全局 `splash` 实例和本函数内的文案注入逻辑，而不是额外创建并行启动窗口。
 * - Integration: It should be called once during the main-process UI bootstrap; if you add more startup-state feedback, reuse the global `splash` instance and the text-injection flow here instead of creating another parallel startup window.
 * - 错误处理: 窗口创建流程本身依赖 Electron 抛错；而 `ready-to-show` 与 `dom-ready` 中的 UI 注入异常会被局部吞掉，避免因为文案或脚本注入失败影响后续主窗口启动。
 * - Error Handling: The window-construction path relies on Electron to surface fatal errors, while failures inside `ready-to-show` and `dom-ready` hooks are swallowed locally so text/script injection issues do not block the main-window bootstrap.
 * - 关键词: 启动画面 | splash window | 启动状态 | startup status | 品牌展示 | brand display | 本地化注入 | localization injection | 主窗口过渡 | window bootstrap
 */
function createSplash() {
  const iconPath = resolveAppIconPath()
  const iconOpt = iconPath ? { icon: iconPath } : {}
  splash = new BrowserWindow({
    ...iconOpt,
    width: 400,
    height: 300,
    show: false,
    transparent: false,
    backgroundColor: '#00000000',
    backgroundMaterial: 'acrylic',
    opacity: 0.98,
    frame: false,
    hasShadow: true,
    roundedCorners: true,
    alwaysOnTop: true,
    skipTaskbar: true,
    resizable: false,
    webPreferences: { nodeIntegration: false, backgroundThrottling: false }
  })
  splash.loadFile(path.join(__dirname, '../renderer/splash.html'))
  console.log('主进程: 创建Splash窗口')
  splash.once('ready-to-show', () => {
    try { if (splash && !splash.isDestroyed()) splash.show() } catch {}
  })
  splash.webContents.on('dom-ready', () => {
    try {
      const locale = (config && config.locale) ? config.locale : 'zh-CN'
      splash.webContents.executeJavaScript(`document.documentElement.lang=${JSON.stringify(locale)}`)
      const statusText = splashStatusText || t('splash_starting')
      console.log('主进程: Splash dom-ready, 设置状态:', statusText)
      splash.webContents.executeJavaScript(`(function(){var b=document.getElementById('splash-brand');if(b)b.textContent=${JSON.stringify(t('brand_name'))};var s=document.getElementById('splash-status');if(s)s.textContent=${JSON.stringify(statusText)};})()`)
    } catch {}
  })
}

/**
 * - 函数: `updateSplashStatus`
 * - Function: `updateSplashStatus`
 * - 作用: 更新启动 Splash 窗口中展示的状态文案，并把最新状态缓存到 `splashStatusText`，供 `createSplash().dom-ready` 首次渲染与后续动态更新复用。
 * - Purpose: Updates the status text shown in the startup Splash window and caches the latest text in `splashStatusText` for both the initial `createSplash().dom-ready` render and later incremental updates.
 * - 调用方: `runStartupSequence({ runBlockingScan })` 在扫描阶段切换状态时调用（例如 `updateSplashStatus(t('splash_initializing_scan'))`）。
 * - Callers: Called by `runStartupSequence({ runBlockingScan })` when switching Splash status during scanning (e.g. `updateSplashStatus(t('splash_initializing_scan'))`).
 * - 被调方: `console.log`、`BrowserWindow#isDestroyed`、`WebContents#executeJavaScript`、`JSON.stringify`。
 * - Callees: `console.log`, `BrowserWindow#isDestroyed`, `WebContents#executeJavaScript`, `JSON.stringify`.
 * - 变量说明: `text` 为要显示的状态文案；`splashStatusText` 为模块级缓存；`splash` 为全局 Splash 窗口实例。
 * - Variables: `text` is the status string to display; `splashStatusText` is the module-level cache; `splash` is the global Splash window instance.
 * - 接入方式: 仅在主进程启动阶段（Splash 已创建或即将创建）调用；如果新增更多启动步骤状态展示，统一通过本函数更新，避免在多处直接 `executeJavaScript` 注入导致文案来源分散。
 * - Integration: Use it only during main-process startup (when the Splash exists or will exist soon); if you add more startup-step statuses, route all updates through this function instead of injecting text via `executeJavaScript` in multiple places.
 * - 错误处理: Splash 未创建或已销毁时仅更新缓存并返回；JS 注入失败会被局部 `try/catch` 吞掉，不影响启动主链路继续执行。
 * - Error Handling: If the Splash is not created or already destroyed, it only updates the cache and returns; JS injection failures are swallowed by a local `try/catch` so the startup main path is not blocked.
 * - 关键词: 启动状态 | splash status | 状态文案 | status text | 启动窗口 | splash window | 文案注入 | executeJavaScript | 全局缓存 | splashStatusText | 主进程UI | main process UI | 扫描阶段 | runBlockingScan | i18n文案 | i18n | 安全降级 | graceful fallback
 */
function updateSplashStatus(text) {
   splashStatusText = text
   console.log('主进程: 更新Splash状态:', text)
   if (splash && !splash.isDestroyed()) {
    try {
      splash.webContents.executeJavaScript(`(function(){var s=document.getElementById('splash-status');if(s)s.textContent=${JSON.stringify(text)};})()`)
    } catch {}
  }
}

/**
 * - 函数: `createWindow`
 * - Function: `createWindow`
 * - 作用: 创建 Electron 主窗口并装配无边框玻璃风格、预加载脚本、主页面加载、渲染进程异常追踪及最小化到托盘行为，是桌面 UI 生命周期的主入口。
 * - Purpose: Creates the Electron main window, configures the frameless glass-style shell, preload script, renderer bootstrap, renderer-failure tracing, and minimize-to-tray behavior, serving as the primary UI lifecycle entry point.
 * - 调用方: `app.whenReady()` 阶段的 `runStartupSequence().prepareUi`，以及 `app.on('activate')` 中的窗口重建逻辑。
 * - Callers: The `runStartupSequence().prepareUi` stage inside `app.whenReady()` and the window re-creation logic in `app.on('activate')`.
 * - 被调方: `resolveAppIconPath`、`resolveMainWindowOptions`、`BrowserWindow`、`path.join`、`win.loadFile`、`appendErrorTrace`、`mainWindowReadyResolve`。
 * - Callees: `resolveAppIconPath`, `resolveMainWindowOptions`, `BrowserWindow`, `path.join`, `win.loadFile`, `appendErrorTrace`, `mainWindowReadyResolve`.
 * - 变量说明: 无显式入参；`iconPath`/`iconOpt` 负责窗口图标；`bounds` 为按配置计算出的尺寸与位置；全局 `win` 保存当前主窗口实例，供托盘与 IPC 逻辑复用。
 * - Variables: No explicit parameters; `iconPath`/`iconOpt` describe the window icon; `bounds` contains the size and position resolved from config; the global `win` holds the active main window instance for tray and IPC flows.
 * - 接入方式: 仅供主进程内部调用；若新增二次创建窗口场景，应复用本函数并确保 `preload.js`、渲染页路径和 `mainWindowReadyPromise` 协同一致，避免启动队列与 splash 状态不同步。
 * - Integration: Use it only inside the main process; if you introduce another window-recreation path, reuse this function and keep `preload.js`, the renderer entry, and `mainWindowReadyPromise` aligned so splash and startup sequencing stay in sync.
 * - 错误处理: 通过 `render-process-gone`、`unresponsive` 事件补充渲染进程崩溃痕迹；对菜单栏处理和 ready 回调采用保护性 `try/catch`，降低窗口创建后因附属能力失败而中断主流程的风险。
 * - Error Handling: Captures renderer crashes via `render-process-gone` and `unresponsive` tracing; menu-bar cleanup and ready-resolution are wrapped defensively so auxiliary failures do not break the main window bootstrap path.
 * - 关键词: 主窗口 | main window | 无边框 | frameless | 托盘最小化 | minimize to tray | 预加载 | preload | 渲染恢复 | renderer recovery
 */
function createWindow() {
  const iconPath = resolveAppIconPath()
  const iconOpt = iconPath ? { icon: iconPath } : {}
  const bounds = resolveMainWindowOptions(config)
  win = new BrowserWindow({
    ...bounds,
    ...iconOpt,
    transparent: true,
    backgroundColor: '#00000000',
    frame: false,
    hasShadow: true,
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: 'rgba(0,0,0,0)',
      symbolColor: '#ffffff',
      height: 30
    },
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, './preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      backgroundThrottling: false
    }
  })
  console.log('主进程: 创建主窗口')
  win.loadFile(path.join(__dirname, '../renderer/index.html'))
  win.webContents.on('render-process-gone', (_event, details) => {
    appendErrorTrace({ ts: Date.now(), source: 'renderer_gone', details })
  })
  win.webContents.on('unresponsive', () => {
    appendErrorTrace({ ts: Date.now(), source: 'renderer_unresponsive' })
  })
  try { win.setMenuBarVisibility(false) } catch {}
  try { win.removeMenu() } catch {}
  win.webContents.once('did-finish-load', () => {
    console.log('主进程: 窗口内容加载完成')
    try { if (mainWindowReadyResolve) mainWindowReadyResolve(true) } catch {}
  })
  win.on('close', (e) => {
    if (config.minimizeToTray) {
      e.preventDefault()
      win.hide()
    }
  })
}

let trayExitInProgress = false

/**
 * - 函数: `quitAppOnlyFromTray`
 * - Function: `quitAppOnlyFromTray`
 * - 作用: 从托盘退出当前 Electron 应用，但保留外部扫描服务进程继续运行。
 * - Purpose: Exits only the current Electron application from the tray while keeping the external scanning service alive.
 * - 调用方: `handleTrayExitClick` 在用户选择“保留扫描服务”时调用。
 * - Callers: Called by `handleTrayExitClick` when the user chooses to keep the scanning service.
 * - 被调方: `scanCache.clearAll`、`app.quit`。
 * - Callees: `scanCache.clearAll` and `app.quit`.
 * - 变量说明: 无显式入参；本函数直接使用全局 `config` 更新最小化到托盘策略。
 * - Variables: There are no explicit parameters; the function directly uses the global `config` to update the minimize-to-tray policy.
 * - 接入方式: 仅在托盘退出链中、且退出模式解析为 `keep_service` 时调用，避免被普通窗口关闭流程误用。
 * - Integration: Use it only inside the tray-exit chain when the resolved exit mode is `keep_service`, avoiding accidental reuse in ordinary window-close flows.
 * - 错误处理: 清理扫描缓存和修改配置时的异常会被吞掉，最终仍强制执行 `app.quit()`。
 * - Error Handling: Exceptions from clearing the scan cache or updating config are swallowed, and `app.quit()` still runs at the end.
 * - 关键词: 托盘仅退应用 | tray app-only quit | 保留扫描服务 | keep scanning service | 扫描缓存清理 | scan cache cleanup | 最小化托盘关闭 | minimize-to-tray disable | 应用退出 | app quit
 */
function quitAppOnlyFromTray() {
  try {
    scanCache.clearAll(config).catch(() => {})
    config.minimizeToTray = false
  } catch {}
  app.quit()
}

/**
 * - 函数: `quitAllFromTray`
 * - Function: `quitAllFromTray`
 * - 作用: 从托盘退出应用并尝试通知扫描服务优雅停机，必要时在 Windows 上兜底结束服务进程。
 * - Purpose: Exits from the tray and attempts to shut down the scanning service gracefully, with a Windows fallback to terminate the service process when needed.
 * - 调用方: `handleTrayExitClick` 在用户选择“同时退出服务”或无需弹窗确认时调用。
 * - Callers: Called by `handleTrayExitClick` when the user chooses to exit the service too or when no confirmation prompt is needed.
 * - 被调方: `scanCache.clearAll`、`Number.isFinite`、`app.quit`、`require('./engine_autostart')`、`postExitCommand`、`killProcessWin32`。
 * - Callees: `scanCache.clearAll`, `Number.isFinite`, `app.quit`, `require('./engine_autostart')`, `postExitCommand`, and `killProcessWin32`.
 * - 变量说明: 无显式入参；`scannerCfg` 为扫描器配置；`ipc` 为服务通信配置；`ipcEnabled` 表示 IPC 是否启用；`timeout` 为服务退出等待时长；`engineCfg` 为引擎配置；`processName` 为兜底强杀目标进程名；`mod` 为引擎自启动模块。
 * - Variables: There are no explicit parameters; `scannerCfg` is the scanner config; `ipc` is the service IPC config; `ipcEnabled` indicates whether IPC is enabled; `timeout` is the graceful-shutdown wait time; `engineCfg` is the engine config; `processName` is the fallback process name to kill; `mod` is the engine autostart module.
 * - 接入方式: 作为托盘退出链中“应用和服务一起退出”的统一出口使用，外部不应自行拼接服务关闭和应用退出逻辑。
 * - Integration: Use it as the single exit path for `quit app + service` in the tray-exit chain; external code should not manually compose service shutdown and app exit steps.
 * - 错误处理: 配置读取异常或服务停机流程失败时直接退回 `app.quit()`；若优雅停机未成功且平台为 Windows，则尝试 `killProcessWin32` 兜底。
 * - Error Handling: Falls back to `app.quit()` when config access or service-shutdown logic fails; if graceful shutdown does not succeed on Windows, it tries `killProcessWin32` as a fallback.
 * - 关键词: 托盘全退出 | tray full quit | 扫描服务停机 | scanner service shutdown | IPC退出命令 | IPC exit command | Windows兜底强杀 | Windows fallback kill | 应用服务同退 | app and service exit
 */
function quitAllFromTray() {
  try {
    scanCache.clearAll(config).catch(() => {})
    config.minimizeToTray = false
    const scannerCfg = (config && config.scanner) ? config.scanner : {}
    const ipc = (scannerCfg && scannerCfg.ipc) ? scannerCfg.ipc : {}
    const ipcEnabled = ipc && ipc.enabled === false ? false : true
    const timeout = (config && config.engine && Number.isFinite(config.engine.exitTimeoutMs))
      ? config.engine.exitTimeoutMs
      : (Number.isFinite(ipc.timeoutMs) ? ipc.timeoutMs : ((scannerCfg && scannerCfg.timeoutMs) ? scannerCfg.timeoutMs : 1000))
    const engineCfg = (config && config.engine) ? config.engine : {}
    if (engineCfg.autoStart === false || !ipcEnabled) return app.quit()
    const processName = engineCfg.processName || ''
    const mod = require('./engine_autostart')
    mod.postExitCommand({ ipc }, timeout, null).then((res) => {
      const ok = res && res.ok && res.status === 'shutting_down'
      if (!ok && process.platform === 'win32') return mod.killProcessWin32(processName)
      return null
    }).finally(() => { app.quit() })
  } catch {
    app.quit()
  }
}

/**
 * - 函数: `showTrayExitPrompt`
 * - Function: `showTrayExitPrompt`
 * - 作用: 弹出托盘退出确认窗口，让用户选择退出时是否保留扫描服务，并返回异步选择结果。
 * - Purpose: Opens the tray-exit confirmation window so the user can decide whether to keep the scanning service, then returns the selection asynchronously.
 * - 调用方: `handleTrayExitClick`。
 * - Callers: `handleTrayExitClick`.
 * - 被调方: `Promise`、`Date.now`、`Math.random`、`path.join`、`resolveAppIconPath`、`BrowserWindow`、`trayExitPromptPending.set`、`trayExitPromptPending.get`、`trayExitPromptPending.delete`、`promptWin.loadFile`。
 * - Callees: `Promise`, `Date.now`, `Math.random`, `path.join`, `resolveAppIconPath`, `BrowserWindow`, `trayExitPromptPending.set`, `trayExitPromptPending.get`, `trayExitPromptPending.delete`, and `promptWin.loadFile`.
 * - 变量说明: `defaultKeep` 表示提示框默认是否勾选保留服务；`requestId` 为本次弹窗请求标识；`p` 为弹窗 HTML 路径；`iconPath`/`iconOpt` 为窗口图标配置；`promptWin` 为退出确认窗口实例；`pending` 为挂起中的 Promise 控制对象。
 * - Variables: `defaultKeep` indicates whether the prompt should default to keeping the service; `requestId` is the request identifier for this prompt; `p` is the HTML path; `iconPath` and `iconOpt` are the window icon settings; `promptWin` is the confirmation window instance; `pending` is the stored Promise control object.
 * - 接入方式: 托盘退出前需要用户选择保留策略时调用，并依赖渲染层通过 `requestId` 回传最终布尔值或取消结果。
 * - Integration: Call it before tray exit when user confirmation is required, and rely on the renderer layer to return the final boolean choice or a cancel result through `requestId`.
 * - 错误处理: 若窗口被直接关闭，会在 `closed` 事件中自动以 `null` 结算 Promise；其余窗口展示异常依赖 Electron 默认行为回退。
 * - Error Handling: If the window closes directly, the Promise resolves to `null` in the `closed` handler; other window-display issues fall back to Electron's default behavior.
 * - 关键词: 托盘退出弹窗 | tray exit prompt | 保留服务选择 | keep service choice | Promise挂起表 | Promise pending map | 退出确认窗口 | exit confirmation window | 请求ID关联 | request ID correlation
 */
function showTrayExitPrompt(defaultKeep) {
  const requestId = `${Date.now()}_${Math.random().toString(16).slice(2)}`
  return new Promise((resolve) => {
    const p = path.join(__dirname, '../renderer/tray_exit_prompt.html')
    const iconPath = resolveAppIconPath()
    const iconOpt = iconPath ? { icon: iconPath } : {}
    const promptWin = new BrowserWindow({
      ...iconOpt,
      width: 420,
      height: 220,
      resizable: false,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      frame: false,
      show: false,
      alwaysOnTop: true,
      skipTaskbar: true,
      transparent: false,
      backgroundColor: '#00000000',
      backgroundMaterial: 'acrylic',
      opacity: 0.98,
      hasShadow: true,
      roundedCorners: true,
      webPreferences: {
        preload: path.join(__dirname, './preload.js'),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: false,
        backgroundThrottling: false
      }
    })

    trayExitPromptPending.set(requestId, { resolve, win: promptWin })
    promptWin.on('closed', () => {
      const pending = trayExitPromptPending.get(requestId)
      if (!pending) return
      trayExitPromptPending.delete(requestId)
      try { pending.resolve(null) } catch {}
    })

    promptWin.loadFile(p, { query: { requestId, defaultKeep: defaultKeep ? '1' : '0' } })
    promptWin.once('ready-to-show', () => {
      try { promptWin.show() } catch {}
      try { promptWin.focus() } catch {}
    })
  })
}

/**
 * - 函数: `handleTrayExitClick`
 * - Function: `handleTrayExitClick`
 * - 作用: 处理托盘退出操作，在退出前统一恢复被拦截挂起的进程，并根据用户选择决定是否保留扫描服务。
 * - Purpose: Handles the tray-exit action by resuming suspended intercepted processes before exit and deciding whether the scanning service should remain running.
 * - 调用方: `createTray` 中的退出菜单点击事件。
 * - Callers: The exit-menu click handler inside `createTray`.
 * - 被调方: `resumeAllInterceptedProcesses`、`quitAllFromTray`、`showTrayExitPrompt`、`resolveTrayExitMode`、`quitAppOnlyFromTray`。
 * - Callees: `resumeAllInterceptedProcesses`, `quitAllFromTray`, `showTrayExitPrompt`, `resolveTrayExitMode`, and `quitAppOnlyFromTray`.
 * - 变量说明: 无显式入参；`trayCfg` 为托盘退出相关配置；`defaultKeep` 表示提示框默认是否保留扫描服务；`keep` 为用户选择；`mode` 为解析后的退出模式。
 * - Variables: There are no explicit parameters; `trayCfg` is the tray-exit configuration; `defaultKeep` indicates whether the prompt defaults to keeping the scanning service; `keep` is the user's selection; `mode` is the resolved exit mode.
 * - 接入方式: 仅作为托盘“退出”菜单项的收口入口使用，外部若要复用退出逻辑，应调用本函数而不是直接拼装多个退出步骤。
 * - Integration: Use it only as the closeout entry for the tray `Exit` menu item; any external reuse of tray-exit behavior should call this function instead of manually composing the exit steps.
 * - 错误处理: 通过 `trayExitInProgress` 防止重复点击重入；无论用户是否保留服务，恢复挂起进程的异常都会被吞掉，最终在 `finally` 中释放退出锁。
 * - Error Handling: Uses `trayExitInProgress` to prevent reentry from repeated clicks; regardless of whether the service is kept, resume failures are swallowed and the exit lock is always released in `finally`.
 * - 关键词: 托盘退出收口 | tray exit closeout | 挂起进程恢复 | suspended process resume | 保留扫描服务 | keep scanner service | 退出模式选择 | exit mode selection | 防重入退出 | reentry-safe exit
 */
async function handleTrayExitClick() {
  if (trayExitInProgress) return
  trayExitInProgress = true

  const trayCfg = (config && config.tray) ? config.tray : {}
  try {
    if (trayCfg.exitKeepScannerServicePrompt === false) {
      try { await resumeAllInterceptedProcesses() } catch {}
      return quitAllFromTray()
    }

    const defaultKeep = trayCfg.exitKeepScannerServiceDefault !== false
    const keep = await showTrayExitPrompt(defaultKeep)
    if (keep == null) return
    const mode = resolveTrayExitMode({ keep, defaultKeep })
    try { await resumeAllInterceptedProcesses() } catch {}
    if (mode === 'keep_service') return quitAppOnlyFromTray()
    return quitAllFromTray()
  } finally {
    trayExitInProgress = false
  }
}

/**
 * - 函数: `createTray`
 * - Function: `createTray`
 * - 作用: 创建系统托盘图标和右键菜单，为主窗口显示与托盘退出链提供统一入口。
 * - Purpose: Creates the system tray icon and context menu, providing a unified entry for showing the main window and triggering the tray-exit chain.
 * - 调用方: 主进程启动完成后的初始化链路。
 * - Callers: The main-process initialization flow after startup is ready.
 * - 被调方: `resolveAppIconPath`、`nativeImage.createFromPath`、`nativeImage.createFromDataURL`、`Tray`、`console.log`、`Menu.buildFromTemplate`、`t`、`handleTrayExitClick`、`tray.setToolTip`、`tray.setContextMenu`、`tray.on`。
 * - Callees: `resolveAppIconPath`, `nativeImage.createFromPath`, `nativeImage.createFromDataURL`, `Tray`, `console.log`, `Menu.buildFromTemplate`, `t`, `handleTrayExitClick`, `tray.setToolTip`, `tray.setContextMenu`, and `tray.on`.
 * - 变量说明: 无显式入参；`iconPath` 为优先图标路径；`image` 为最终托盘图像；`pngBase64` 为内置兜底图标；`menu` 为托盘上下文菜单。
 * - Variables: There are no explicit parameters; `iconPath` is the preferred icon path; `image` is the final tray image; `pngBase64` is the built-in fallback icon; `menu` is the tray context menu.
 * - 接入方式: 应在主窗口创建后调用一次完成托盘初始化；若重复调用，需要先处理全局 `tray` 实例覆盖问题。
 * - Integration: Call it once after the main window is created to initialize tray support; repeated calls require handling replacement of the global `tray` instance first.
 * - 错误处理: 自定义图标加载失败时回退到内置 Base64 小图标；菜单点击逻辑使用现有窗口和退出函数，不在此处额外抛错。
 * - Error Handling: Falls back to the built-in Base64 icon when loading a custom tray icon fails; menu-click logic reuses existing window and exit helpers without adding extra throws here.
 * - 关键词: 系统托盘创建 | system tray creation | 托盘菜单 | tray context menu | 图标兜底 | icon fallback | 主窗口显示入口 | main window show entry | 托盘退出入口 | tray exit entry
 */
function createTray() {
  const iconPath = resolveAppIconPath()
  let image = null
  try {
    if (iconPath) image = nativeImage.createFromPath(iconPath)
  } catch {}
  if (!image || (typeof image.isEmpty === 'function' && image.isEmpty())) {
    const pngBase64 =
      'iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAGElEQVQYlWP8////fwYGBgYGJgYGBgYAAG1uCkqO3W1QAAAAAElFTkSuQmCC'
    image = nativeImage.createFromDataURL('data:image/png;base64,' + pngBase64)
  }
  tray = new Tray(image)
  console.log('主进程: 创建系统托盘')
  const menu = Menu.buildFromTemplate([
    { label: t('tray_show_main'), click: () => { win.show() } },
    { label: t('tray_exit'), click: () => { void handleTrayExitClick() } }
  ])
  tray.setToolTip(t('brand_name') || config.brand || 'AnXin Security')
  tray.setContextMenu(menu)
  tray.on('double-click', () => { win.show() })
}

/**
 * - 函数: `getEngineBaseDirs`
 * - Function: `getEngineBaseDirs`
 * - 作用: 汇总扫描引擎与品牌资源可能所在的基础目录，供图标解析、Hook 二进制解析和引擎启动定位复用。
 * - Purpose: Collects candidate base directories where the scanning engine and branded assets may live, so icon resolution, hook binary lookup, and engine startup location logic can reuse one source.
 * - 调用方: `resolveAppIconPath`、`resolveHookBinaryPath`、`startIfNeeded` 调用链中的基础目录注入逻辑。
 * - Callers: `resolveAppIconPath`, `resolveHookBinaryPath`, and the base-directory injection logic used by the `startIfNeeded` call chain.
 * - 被调方: `process.cwd`、`app.getAppPath`、`app.getPath`、`path.dirname`、`Array.prototype.push`、`Array.prototype.filter`、`Set`。
 * - Callees: `process.cwd`, `app.getAppPath`, `app.getPath`, `path.dirname`, `Array.prototype.push`, `Array.prototype.filter`, and `Set`.
 * - 变量说明: 无显式入参；`out` 为候选目录数组，最终会经过 `filter(Boolean)` 和 `Set` 去空去重。
 * - Variables: There are no explicit parameters; `out` is the candidate-directory array, which is later cleaned with `filter(Boolean)` and deduplicated with `Set`.
 * - 接入方式: 当主进程需要在多个可能安装目录中搜索图标、DLL、可执行文件时，应先通过本函数获取基础目录列表。
 * - Integration: Use it first whenever the main process needs to search across multiple possible install directories for icons, DLLs, or executables.
 * - 错误处理: 每个目录来源都独立包裹在 `try/catch` 中，单个来源失败不会影响其他来源收集；最终至少返回一个可安全迭代的数组。
 * - Error Handling: Each directory source is wrapped in its own `try/catch`, so one failure does not block the others; the function always returns an array that is safe to iterate.
 * - 关键词: 引擎基础目录 | engine base directories | 安装目录枚举 | install directory enumeration | 图标资源搜索 | icon resource search | Hook路径定位 | hook path lookup | 目录去重 | directory deduplication
 */
function getEngineBaseDirs() {
  const out = []
  try { out.push(process.cwd()) } catch {}
  try { out.push(app.getAppPath()) } catch {}
  try { out.push(path.dirname(app.getPath('exe'))) } catch {}
  try { if (process.resourcesPath) out.push(process.resourcesPath) } catch {}
  return [...new Set(out.filter(Boolean))]
}

/**
 * - 函数: `fileExists`
 * - Function: `fileExists`
 * - 作用: 对单个路径执行安全的存在性判断，供 Hook 制品解析和进程映像路径校验复用。
 * - Purpose: Performs a safe existence check for a single path so hook artifact resolution and process image-path validation can reuse one helper.
 * - 调用方: `resolveFirstExistingFile`、`injectHookIntoUnsignedProcesses`。
 * - Callers: `resolveFirstExistingFile` and `injectHookIntoUnsignedProcesses`.
 * - 被调方: `fs.existsSync`。
 * - Callees: `fs.existsSync`.
 * - 变量说明: `p` 为待检查文件路径；返回值为布尔值，表示该路径当前是否可访问且存在。
 * - Variables: `p` is the file path to check; the return value is a boolean indicating whether that path is currently accessible and present.
 * - 接入方式: 主进程中凡是只需要做轻量存在性判断、且不希望把文件系统异常向外传播的场景，都应优先复用本函数。
 * - Integration: Reuse it anywhere in the main process that needs a lightweight existence check without allowing filesystem errors to propagate outward.
 * - 错误处理: 路径为空或 `existsSync` 抛异常时统一返回 `false`，避免文件查找链路被 I/O 异常中断。
 * - Error Handling: Returns `false` when the path is empty or when `existsSync` throws, preventing I/O failures from interrupting the file-resolution chain.
 * - 关键词: 文件存在判断 | file existence check | 安全路径校验 | safe path validation | Hook文件校验 | hook file validation | 映像路径检查 | image path check | IO异常吞掉 | I/O failure swallow
 */
function fileExists(p) {
  try {
    return !!(p && fs.existsSync(p))
  } catch {
    return false
  }
}

/**
 * - 函数: `resolveFirstExistingFile`
 * - Function: `resolveFirstExistingFile`
 * - 作用: 按候选路径顺序返回首个真实存在的文件，用于多目录回退查找场景。
 * - Purpose: Returns the first real file that exists in the candidate-path order, supporting multi-directory fallback lookup scenarios.
 * - 调用方: `resolveHookBinaryPath`。
 * - Callers: `resolveHookBinaryPath`.
 * - 被调方: `fileExists`。
 * - Callees: `fileExists`.
 * - 变量说明: `candidates` 为按优先级排列的候选路径数组；循环变量 `p` 为当前待验证路径；返回值为首个命中的路径或空字符串。
 * - Variables: `candidates` is the priority-ordered candidate path array; loop variable `p` is the current path being validated; the return value is either the first hit path or an empty string.
 * - 接入方式: 当路径来源可能分布在安装目录、资源目录和开发目录等多个位置时，先构造候选数组，再交给本函数统一挑选首个有效文件。
 * - Integration: When paths may live in install directories, resource directories, development directories, or other locations, build the candidate list first and let this helper pick the first valid file.
 * - 错误处理: 依赖 `fileExists` 吞掉底层文件系统异常；若所有候选均未命中，则稳定返回空字符串而不抛错。
 * - Error Handling: Relies on `fileExists` to absorb underlying filesystem exceptions; if no candidates match, it returns an empty string without throwing.
 * - 关键词: 首个命中文件 | first matching file | 候选路径回退 | candidate path fallback | 多目录查找 | multi-directory lookup | 文件定位顺序 | file lookup order | 空字符串回退 | empty-string fallback
 */
function resolveFirstExistingFile(candidates) {
  for (const p of candidates) {
    if (fileExists(p)) return p
  }
  return ''
}

/**
 * - 函数: `resolveHookBinaryPath`
 * - Function: `resolveHookBinaryPath`
 * - 作用: 按架构目录和文件名搜索 Hook 注入器或 DLL 的实际落盘路径，兼容开发目录、打包资源目录和运行时基础目录。
 * - Purpose: Searches for the on-disk path of a hook injector or DLL by architecture directory and file name, covering development folders, packaged resource folders, and runtime base directories.
 * - 调用方: `resolveHookArtifacts`。
 * - Callers: `resolveHookArtifacts`.
 * - 被调方: `path.join`、`getEngineBaseDirs`、`resolveFirstExistingFile`、`Array.prototype.push`。
 * - Callees: `path.join`, `getEngineBaseDirs`, `resolveFirstExistingFile`, and `Array.prototype.push`.
 * - 变量说明: `archDir` 为架构目录，如 `win32-x64`；`fileName` 为目标制品文件名；`candidates` 为按优先级累计的候选路径数组；`bases` 为基础目录列表。
 * - Variables: `archDir` is the architecture directory such as `win32-x64`; `fileName` is the target artifact file name; `candidates` is the priority-ordered candidate path array; `bases` is the base-directory list.
 * - 接入方式: 需要单独定位某个 Hook 可执行文件或 DLL 时调用本函数，并把目标架构目录和文件名作为入参传入。
 * - Integration: Call it whenever a specific hook executable or DLL must be located, passing the target architecture directory and file name.
 * - 错误处理: 单个候选目录拼接失败会被静默跳过；最终通过 `resolveFirstExistingFile` 返回首个存在路径，若全部未命中则回退为空字符串。
 * - Error Handling: Failures while building individual candidate directories are silently skipped; the final result comes from `resolveFirstExistingFile`, which falls back to an empty string if nothing matches.
 * - 关键词: Hook二进制定位 | hook binary lookup | 架构目录搜索 | architecture directory search | 打包资源回退 | packaged resource fallback | 候选路径列表 | candidate path list | 注入器定位 | injector location
 */
function resolveHookBinaryPath(archDir, fileName) {
  const candidates = []
  try {
    if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
      candidates.push(path.join(process.resourcesPath, 'native', archDir, fileName))
      candidates.push(path.join(process.resourcesPath, 'native', 'bin', archDir, fileName))
    }
  } catch {}
  try { candidates.push(path.join(__dirname, `../../native/bin/${archDir}/${fileName}`)) } catch {}
  try { candidates.push(path.join(__dirname, `../../native/${archDir}/${fileName}`)) } catch {}
  const bases = getEngineBaseDirs()
  for (const base of bases) {
    candidates.push(path.join(base, 'native', 'bin', archDir, fileName))
    candidates.push(path.join(base, 'native', archDir, fileName))
  }
  return resolveFirstExistingFile(candidates)
}

/**
 * - 函数: `resolveHookArtifacts`
 * - Function: `resolveHookArtifacts`
 * - 作用: 组装 x64 与 x86 两套 Hook 注入制品清单，供未签名进程注入链路按目标架构选用。
 * - Purpose: Builds the x64 and x86 hook artifact manifest so the unsigned-process injection flow can choose the correct binaries for the target architecture.
 * - 调用方: `injectHookIntoUnsignedProcesses`、主进程启动阶段的 Hook 预检链路。
 * - Callers: `injectHookIntoUnsignedProcesses` and the hook preflight path during main-process startup.
 * - 被调方: `resolveHookBinaryPath`。
 * - Callees: `resolveHookBinaryPath`.
 * - 变量说明: 无显式入参；返回对象中的 `x64`、`x86` 分别保存对应架构的 `injector` 与 `dll` 路径。
 * - Variables: There are no explicit parameters; the returned object's `x64` and `x86` fields each hold the `injector` and `dll` paths for that architecture.
 * - 接入方式: 需要一次性拿到所有 Hook 制品路径时调用本函数，避免在注入循环里重复手写不同架构的文件名组合。
 * - Integration: Use it when all hook artifact paths are needed together, avoiding repeated manual filename combinations inside injection loops.
 * - 错误处理: 本函数本身不抛异常，路径命中失败会体现在返回对象的空字符串字段中，由调用方继续决定是否跳过或报错。
 * - Error Handling: The function itself does not throw; lookup failures appear as empty-string fields in the returned object, leaving the caller to decide whether to skip or error.
 * - 关键词: Hook制品清单 | hook artifact manifest | x64注入器 | x64 injector | x86注入器 | x86 injector | DLL路径组装 | DLL path assembly | 架构资源映射 | architecture resource mapping
 */
function resolveHookArtifacts() {
  return {
    x64: {
      injector: resolveHookBinaryPath('win32-x64', 'file_hook_injector.exe'),
      dll: resolveHookBinaryPath('win32-x64', 'file_hook_detours.dll')
    },
    x86: {
      injector: resolveHookBinaryPath('win32-x86', 'file_hook_injector.exe'),
      dll: resolveHookBinaryPath('win32-x86', 'file_hook_detours.dll')
    }
  }
}

/**
 * - 函数: `execFileAsync`
 * - Function: `execFileAsync`
 * - 作用: 将 `child_process.execFile` 包装为统一的 Promise 结果对象，供 Hook 注入流程以非抛异常方式获取退出码、标准输出和错误文本。
 * - Purpose: Wraps `child_process.execFile` into a unified Promise result object so the hook-injection flow can inspect exit codes, stdout, and error text without relying on thrown exceptions.
 * - 调用方: `injectHookForPid` 在尝试执行不同架构的注入器时调用。
 * - Callers: Called by `injectHookForPid` while trying injector binaries for different architectures.
 * - 被调方: `execFile`、`Promise`、`String`、`trim`、`Number.isFinite`。
 * - Callees: `execFile`, `Promise`, `String`, `trim`, `Number.isFinite`.
 * - 变量说明: `file` 为待执行的注入器路径；`args` 为命令参数数组；`timeoutMs` 为子进程超时；`output` 合并标准输出与错误输出；`ec` 为归一化退出码。
 * - Variables: `file` is the injector executable path, `args` is the command argument list, `timeoutMs` is the child-process timeout, `output` merges stdout and stderr, and `ec` is the normalized exit code.
 * - 接入方式: 适合作为主进程内短生命周期外部工具调用封装；如果后续新增 Hook、快照或修复工具执行路径，优先复用本函数以保持返回结构一致。
 * - Integration: Use it as the short-lived external-tool execution wrapper in the main process; if new hook, snapshot, or repair utilities are introduced later, prefer reusing this function to keep result payloads consistent.
 * - 错误处理: 不向上抛出 `execFile` 回调中的异常，而是统一解析为 `{ ok, exitCode, output, error }` 结果对象，由调用方根据退出码决定是否重试、换架构或直接失败。
 * - Error Handling: Instead of rethrowing callback failures from `execFile`, it normalizes them into a `{ ok, exitCode, output, error }` object so callers can decide whether to retry, switch architecture, or fail fast.
 * - 关键词: 子进程封装 | child process wrapper | 注入器执行 | injector execution | 退出码归一化 | exit code normalization | Promise结果 | promise result | 输出合并 | output merge
 */
function execFileAsync(file, args, timeoutMs) {
  return new Promise((resolve) => {
    execFile(file, args, { windowsHide: true, timeout: timeoutMs }, (error, stdout, stderr) => {
      const output = `${stdout || ''}${stderr || ''}`.trim()
      if (!error) return resolve({ ok: true, exitCode: 0, output })
      const ec = Number.isFinite(error.code) ? error.code : null
      resolve({ ok: false, exitCode: ec, output, error: error && error.message ? String(error.message) : '' })
    })
  })
}

/**
 * - 函数: `injectHookForPid`
 * - Function: `injectHookForPid`
 * - 作用: 针对单个进程 PID 依次尝试 x64/x86 注入器，将 Detours DLL 注入到目标进程，并把不同退出码翻译为主进程可消费的成功/失败原因。
 * - Purpose: Attempts x64/x86 injectors in sequence for one target PID, injects the Detours DLL into that process, and translates injector exit codes into success/failure reasons the main process can consume.
 * - 调用方: `injectHookIntoUnsignedProcesses` 在枚举到未签名可处理进程后逐个调用。
 * - Callers: Called by `injectHookIntoUnsignedProcesses` for each unsigned process selected from the snapshot.
 * - 被调方: `execFileAsync`、`String`、`Number.isFinite`、`Math.floor`。
 * - Callees: `execFileAsync`, `String`, `Number.isFinite`, `Math.floor`.
 * - 变量说明: `pid` 为目标进程 ID；`artifacts` 保存 x64/x86 注入器与 DLL 路径；`attempts` 为可尝试的架构列表；`argPid` 为归一化后的整数 PID；`res` 为单次注入器执行结果。
 * - Variables: `pid` is the target process id, `artifacts` contains injector and DLL paths for x64/x86, `attempts` is the candidate architecture list, `argPid` is the normalized integer PID, and `res` is one injector execution result.
 * - 接入方式: 仅应由进程枚举与批量注入逻辑调用；若新增按需单进程补注入能力，建议仍复用本函数，以保持退出码解释和多架构回退策略一致。
 * - Integration: It should be invoked only by process-enumeration and bulk-injection flows; if on-demand single-process reinjection is added later, reuse this function so exit-code interpretation and multi-architecture fallback remain consistent.
 * - 错误处理: 缺少注入器、PID 非法时直接返回结构化失败原因；退出码 `12` 视为可切换到下一架构继续尝试，`10/14` 会立即返回具体失败码，其余情况最终汇总为 `inject_all_failed`。
 * - Error Handling: It returns structured failure reasons immediately for missing artifacts or invalid PIDs; exit code `12` is treated as a signal to try the next architecture, `10/14` fail fast with a specific reason, and remaining failures collapse to `inject_all_failed`.
 * - 关键词: 进程注入 | process injection | 多架构回退 | multi-arch fallback | 注入退出码 | injector exit code | PID处理 | PID normalization | DLL注入 | DLL injection
 */
async function injectHookForPid(pid, artifacts) {
  const attempts = []
  if (artifacts && artifacts.x64 && artifacts.x64.injector && artifacts.x64.dll) {
    attempts.push({ arch: 'x64', injector: artifacts.x64.injector, dll: artifacts.x64.dll })
  }
  if (artifacts && artifacts.x86 && artifacts.x86.injector && artifacts.x86.dll) {
    attempts.push({ arch: 'x86', injector: artifacts.x86.injector, dll: artifacts.x86.dll })
  }
  if (!attempts.length) return { ok: false, reason: 'injector_or_dll_missing' }

  const argPid = Number.isFinite(pid) ? Math.floor(pid) : parseInt(String(pid), 10)
  if (!Number.isFinite(argPid) || argPid <= 0) return { ok: false, reason: 'pid_invalid' }

  for (const it of attempts) {
    const res = await execFileAsync(it.injector, ['--pid', String(argPid), '--dll', it.dll], 12000)
    if (res.ok) return { ok: true, arch: it.arch, output: res.output }
    if (res.exitCode === 12) continue
    if (res.exitCode === 10 || res.exitCode === 14) return { ok: false, reason: `inject_failed_${res.exitCode}`, arch: it.arch, output: res.output || res.error || '' }
  }
  return { ok: false, reason: 'inject_all_failed' }
}

/**
 * - 函数: `injectHookIntoUnsignedProcesses`
 * - Function: `injectHookIntoUnsignedProcesses`
 * - 作用: 在启动阻塞扫描阶段枚举当前系统进程，筛掉本程序自身、受信路径和已注入 PID，只对未签名且路径有效的外部进程尝试注入 Hook，并汇总签名/无效/失败统计供后续策略使用。
 * - Purpose: Enumerates running processes during the blocking startup scan, skips the app itself, trusted paths, and already-injected PIDs, then attempts hook injection only for unsigned external processes with valid paths while producing summary stats for later policy decisions.
 * - 调用方: `runStartupSequence({ runBlockingScan })` 中的启动扫描阶段。
 * - Callers: Called by the startup scan phase inside `runStartupSequence({ runBlockingScan })`.
 * - 被调方: `resolveHookArtifacts`、`winapi.getProcessImageSnapshot`、`winapi.verifyTrust`、`resolveMaybeRelativePath`、`isUnderDir`、`normalizeLowerPath`、`fileExists`、`injectHookForPid`、`setSignedPaths` 关联链路的上游数据准备。
 * - Callees: `resolveHookArtifacts`, `winapi.getProcessImageSnapshot`, `winapi.verifyTrust`, `resolveMaybeRelativePath`, `isUnderDir`, `normalizeLowerPath`, `fileExists`, `injectHookForPid`, plus upstream data preparation for the `setSignedPaths` flow.
 * - 变量说明: 无显式入参；`artifacts` 为注入器产物集合；`snapshots` 为系统进程快照；`unique` 保存 PID 到镜像路径的唯一映射；`signedSet` 记录已验证签名路径；`injected/skippedSigned/skippedInvalid/failed` 为统计计数。
 * - Variables: No explicit parameters; `artifacts` holds injector artifacts, `snapshots` is the process-image snapshot, `unique` maps unique PIDs to image paths, `signedSet` records verified signed paths, and `injected`/`skippedSigned`/`skippedInvalid`/`failed` track summary counters.
 * - 接入方式: 适合作为主进程启动期的一次性批量注入入口；若后续增加定时重扫或人工触发重试，应继续复用本函数输出的汇总结构，而不是在多处散落各自的进程筛选规则。
 * - Integration: Use it as the one-shot bulk injection entry during main-process startup; if periodic rescans or manual retries are added later, reuse this function and its summary output instead of duplicating process-filtering rules in multiple places.
 * - 错误处理: 对非 Windows、缺失 `winapi` 能力、缺少注入产物等场景直接返回空统计；进程快照和签名验证采用局部兜底继续遍历，单 PID 注入失败只累计 `failed`，不会中断整批启动扫描。
 * - Error Handling: It returns an empty summary for non-Windows environments, missing `winapi` capabilities, or missing injector artifacts; snapshot and trust-verification failures are handled locally so iteration continues, and a per-PID injection failure only increments `failed` instead of aborting the whole startup scan.
 * - 关键词: 启动注入扫描 | startup injection scan | 未签名进程 | unsigned process | 进程快照 | process snapshot | 签名验证 | trust verification | 批量统计 | bulk summary
 */
async function injectHookIntoUnsignedProcesses() {
  if (process.platform !== 'win32') return { total: 0, injected: 0, skippedSigned: 0, skippedInvalid: 0, failed: 0, signedPaths: [] }
  if (!winapi || typeof winapi.getProcessImageSnapshot !== 'function' || typeof winapi.verifyTrust !== 'function') {
    return { total: 0, injected: 0, skippedSigned: 0, skippedInvalid: 0, failed: 0, signedPaths: [] }
  }
  const artifacts = resolveHookArtifacts()
  if (!(artifacts.x64.injector && artifacts.x64.dll) && !(artifacts.x86.injector && artifacts.x86.dll)) {
    return { total: 0, injected: 0, skippedSigned: 0, skippedInvalid: 0, failed: 0, signedPaths: [] }
  }

  let snapshots = []
  try { snapshots = winapi.getProcessImageSnapshot(8192) || [] } catch { snapshots = [] }
  const unique = new Map()
  for (const it of snapshots) {
    const pid = Number.isFinite(it && it.pid) ? it.pid : parseInt(String(it && it.pid), 10)
    if (!Number.isFinite(pid) || pid <= 4 || pid === process.pid) continue
    if (hookInjectedPids.has(pid)) continue
    const imagePath = resolveMaybeRelativePath(typeof (it && it.imagePath) === 'string' ? it.imagePath : '')
    if (!imagePath) continue
    if (isUnderDir(normalizeLowerPath(imagePath), appDirLower)) continue
    if (!unique.has(pid)) unique.set(pid, imagePath)
  }

  let injected = 0
  let skippedSigned = 0
  let skippedInvalid = 0
  let failed = 0
  const signedSet = new Set()
  for (const [pid, imagePath] of unique) {
    let isSigned = false
    try { isSigned = winapi.verifyTrust(imagePath) === true } catch { isSigned = false }
    if (isSigned) {
      skippedSigned++
      signedSet.add(imagePath)
      continue
    }
    if (!fileExists(imagePath)) {
      skippedInvalid++
      continue
    }
    const ret = await injectHookForPid(pid, artifacts)
    if (ret && ret.ok) {
      injected++
      hookInjectedPids.add(pid)
      console.log(`主进程: 注入成功 pid=${pid}, arch=${ret.arch}`)
    } else {
      failed++
      console.log(`主进程: 注入失败 pid=${pid}, reason=${ret ? ret.reason : 'unknown'}`)
    }
  }

  const result = { total: unique.size, injected, skippedSigned, skippedInvalid, failed, signedPaths: [...signedSet] }
  console.log('主进程: 注入统计', result)
  return result
}

/**
 * - 函数: `sleep`
 * - Function: `sleep`
 * - 作用: 返回一个在指定毫秒后 resolve 的 Promise，用于启动期轮询/退避等待，避免使用阻塞式 sleep 影响主进程事件循环。
 * - Purpose: Returns a Promise that resolves after the given milliseconds, used for startup polling/backoff delays without blocking the main-process event loop.
 * - 调用方: `waitForEngineHealthy`（轮询扫描引擎健康状态时的间隔等待）。
 * - Callers: `waitForEngineHealthy` (delay between scan-engine health polls).
 * - 被调方: `setTimeout`、`Math.max`、`Promise`。
 * - Callees: `setTimeout`, `Math.max`, `Promise`.
 * - 变量说明: `ms` 为期望等待的毫秒数（允许传入非数值或负数）；内部用 `Math.max(0, ms || 0)` 规整为非负延迟。
 * - Variables: `ms` is the requested delay in milliseconds (may be non-numeric or negative); it is normalized to a non-negative delay via `Math.max(0, ms || 0)`.
 * - 接入方式: 在任何需要“异步等待”而不是阻塞 CPU 的地方 `await sleep(ms)`；启动/轮询链路应优先复用本函数，避免散落的 `new Promise(setTimeout...)` 影响可读性与一致性。
 * - Integration: Use `await sleep(ms)` wherever an async delay is needed instead of blocking; startup/polling flows should reuse this helper to avoid scattered `new Promise(setTimeout...)` patterns and keep semantics consistent.
 * - 错误处理: 不抛异常；对非数值/负数输入做非负归一化；延迟调度由 Node 定时器机制保证，调用方可通过上层超时逻辑控制整体等待上限。
 * - Error Handling: Never throws; normalizes non-numeric/negative inputs into a non-negative delay; scheduling is handled by Node timers and callers should enforce an overall timeout at a higher level if needed.
 * - 关键词: 异步等待 | async delay | setTimeout | Promise | 轮询退避 | polling backoff | 启动屏障 | startup barrier | waitForEngineHealthy | 非阻塞 | non-blocking | 毫秒延迟 | ms delay | 参数归一化 | input normalization | 事件循环 | event loop | sleep helper | 工具函数 | utility
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms || 0)))
}

/**
 * - 函数: `waitForEngineHealthy`
 * - Function: `waitForEngineHealthy`
 * - 作用: 在启动阶段轮询扫描引擎健康状态，直到 IPC 通道报告可用或达到最大重试次数，保证后续 ETW 快照与启动扫描在引擎就绪后再继续推进。
 * - Purpose: Polls the scan-engine health state during startup until the IPC channel reports readiness or the retry budget is exhausted, ensuring later ETW snapshots and startup scans continue only after the engine is usable.
 * - 调用方: `runStartupSequence({ runBlockingScan })` 在 `startIfNeeded(...)` 之后、正式进入后续安全组件初始化之前调用。
 * - Callers: Called by `runStartupSequence({ runBlockingScan })` right after `startIfNeeded(...)` and before the rest of the security-component bootstrap continues.
 * - 被调方: `checkEngineHealth`、`sleep`、`Number.isFinite`、`Math.max`、`Math.floor`。
 * - Callees: `checkEngineHealth`, `sleep`, `Number.isFinite`, `Math.max`, `Math.floor`.
 * - 变量说明: `ipc` 为扫描引擎的 IPC 连接配置；`pollIntervalMs` 为外部传入的健康检查间隔；`interval` 为归一化后的最小轮询间隔；`retries` 记录已轮询次数；`ok` 表示单次健康检查结果。
 * - Variables: `ipc` is the scan-engine IPC config, `pollIntervalMs` is the requested polling interval, `interval` is the normalized minimum delay, `retries` counts polling attempts, and `ok` is the result of each health check.
 * - 接入方式: 适合作为主进程启动期的等待屏障；如果后续有更多依赖引擎可用性的链路，应在对应启动流程中 await 本函数，而不是复制轮询循环。
 * - Integration: Use it as the startup readiness barrier in the main process; if more flows start depending on engine readiness later, await this function in those boot paths instead of duplicating the polling loop.
 * - 错误处理: 不直接处理 `checkEngineHealth` 内部细节，而是依赖其布尔结果持续轮询；连续超过 100 次仍未健康时返回 `false`，由上层决定是否继续、降级或仅记录日志。
 * - Error Handling: It does not handle low-level `checkEngineHealth` failures directly and instead relies on the returned boolean to keep polling; after more than 100 failed checks it returns `false`, letting upper layers decide whether to continue, downgrade, or just log the condition.
 * - 关键词: 引擎健康等待 | engine health wait | 启动屏障 | startup barrier | IPC轮询 | IPC polling | 重试上限 | retry budget | 引擎就绪 | engine readiness
 */
async function waitForEngineHealthy(ipc, pollIntervalMs) {
  let retries = 0
  const interval = Number.isFinite(pollIntervalMs) ? Math.max(50, Math.floor(pollIntervalMs)) : 3000
  while (true) {
    const ok = await checkEngineHealth({ ipc })
    if (ok) return true
    if (retries > 100) return false
    retries++
    await sleep(interval)
  }
}

app.whenReady().then(() => {
  try { Menu.setApplicationMenu(null) } catch {}
  touchErrorLog()
  initCrashReporter()
  const engineCfg = (config && config.engine) ? config.engine : {}
  const scannerCfg = (config && config.scanner) ? config.scanner : {}
  const ipc = (scannerCfg && scannerCfg.ipc) ? scannerCfg.ipc : {}
  const pollIntervalMs = Number.isFinite(scannerCfg.healthPollIntervalMs) ? scannerCfg.healthPollIntervalMs : 3000

  runStartupSequence({
    prepareUi: async () => {
      i18nDict = loadI18n()
      createSplash()
      createWindow()
      createTray()
    },
    runBlockingScan: async () => {
      startHookIpcServer()
      const scanRes = await injectHookIntoUnsignedProcesses()
      if (scanRes && Array.isArray(scanRes.signedPaths)) {
        verifiedSignedPaths = scanRes.signedPaths
        if (verifiedSignedPaths.length) {
          try { setSignedPaths(verifiedSignedPaths) } catch {}
        }
      }
      if (engineCfg.autoStart !== false) {
        const engineArgs = (engineCfg && Array.isArray(engineCfg.args)) ? engineCfg.args : []
        await startIfNeeded({ engine: { ...engineCfg, args: engineArgs }, ipc, baseDirs: getEngineBaseDirs() })
        await waitForEngineHealthy(ipc, pollIntervalMs)
        startupEngineEnsured = true
      }
      updateSplashStatus(t('splash_initializing_scan'))
      await takeEtwPidSnapshot()
      startInterceptionSnapshotScan()
      await scanPromise
    },
    startBacklogProcessing: async () => {
      await mainWindowReadyPromise
      allowBacklogDuringSplash = true
      try { interceptionQueue.tryShowNext() } catch {}
    },
    startSecurityComponents: async () => {
      try { behavior.start() } catch {}
      try { behavior.setWriteEnabled(isBehaviorMonitoringEnabled(config)) } catch {}
      startHookIpcServer()
      if (!processWatcherStarted) {
        const artifacts = resolveHookArtifacts()
        const res = startProcessWatcher({
          injectorX64: artifacts.x64 && artifacts.x64.injector ? artifacts.x64.injector : '',
          injectorX86: artifacts.x86 && artifacts.x86.injector ? artifacts.x86.injector : '',
          dllX64: artifacts.x64 && artifacts.x64.dll ? artifacts.x64.dll : '',
          dllX86: artifacts.x86 && artifacts.x86.dll ? artifacts.x86.dll : '',
          intervalMs: 100
        })
        if (res && res.ok) {
          processWatcherStarted = true
          console.log('主进程: 进程监控已启动')
          if (verifiedSignedPaths.length) {
            try { setSignedPaths(verifiedSignedPaths) } catch {}
          }
          if (!processWatcherPidTimer) {
            processWatcherPidTimer = setInterval(() => {
              let pid = 0
              let tries = 0
              while (tries < 50) {
                try { pid = pollNewPid() } catch { pid = 0 }
                if (!pid) break
                console.log(`主进程: 监控到新进程 pid=${pid}`)
                tries += 1
              }
            }, 200)
          }
        } else {
          console.log('主进程: 进程监控启动失败')
        }
      }
      //startEtwWorker()
      if (engineCfg.autoStart !== false && !startupEngineEnsured) {
        const engineArgs = (engineCfg && Array.isArray(engineCfg.args)) ? engineCfg.args : []
        const res = await startIfNeeded({ engine: { ...engineCfg, args: engineArgs }, ipc, baseDirs: getEngineBaseDirs() })
        if (res) {
          if (res.started) console.log('主进程: 已后台启动引擎服务', res.path)
          else if (res.reason === 'already_running') console.log('主进程: 引擎服务已在运行')
          else if (res.reason === 'exe_not_found') console.log('主进程: 未找到引擎可执行文件，跳过自动启动')
          else if (res.reason === 'spawn_failed') console.log('主进程: 启动引擎服务失败', res.path)
        }
      }
    },
    waitSecurityReady: async () => {
      if (engineCfg.autoStart === false) return
      await waitForEngineHealthy(ipc, pollIntervalMs)
    },
    finalizeUi: async () => {
      if (splash && !splash.isDestroyed()) splash.destroy()
      allowBacklogDuringSplash = false
      if (win && !win.isDestroyed()) {
        win.show()
        win.focus()
      }
    }
  }).catch(() => {})
  ipcMain.on('config-updated', (_event, nextCfg) => {
    if (!nextCfg || typeof nextCfg !== 'object') return
    config = nextCfg
    try { behavior.setWriteEnabled(isBehaviorMonitoringEnabled(config)) } catch {}
    try { i18nDict = loadI18n() } catch {}
    etwConsoleLimiter = null
    etwConsoleLimiterMax = null
    try {
      const etwCfg = (config && config.etw) ? config.etw : {}
      const icfg = (etwCfg && etwCfg.interception && typeof etwCfg.interception === 'object') ? etwCfg.interception : null
      interceptionQueue.configure(icfg)
    } catch {}
    try { if (etwWorker) etwWorker.postMessage({ type: 'config', config: (config && config.etw) ? config.etw : null }) } catch {}
  })
  ipcMain.handle('open-file-dialog', async () => {
    const browser = BrowserWindow.getFocusedWindow() || win
    console.log('主进程: 打开文件选择对话框')
    const res = await dialog.showOpenDialog(browser, {
      title: t('dialog_choose_file_title'),
      properties: ['openFile', 'dontAddToRecent']
    })
    if (res.canceled || !res.filePaths || !res.filePaths.length) return null
    console.log('主进程: 选择文件', res.filePaths[0])
    return res.filePaths[0]
  })
  ipcMain.handle('open-directory-dialog', async () => {
    const browser = BrowserWindow.getFocusedWindow() || win
    console.log('主进程: 打开目录选择对话框')
    const res = await dialog.showOpenDialog(browser, {
      title: t('dialog_choose_directory_title'),
      properties: ['openDirectory', 'dontAddToRecent']
    })
    if (res.canceled || !res.filePaths || !res.filePaths.length) return null
    console.log('主进程: 选择目录', res.filePaths[0])
    return res.filePaths[0]
  })

  ipcMain.handle('dev-settings:unlock', async (_event, payload) => {
    const p = payload && typeof payload === 'object' ? payload : {}
    const password = typeof p.password === 'string' ? p.password : ''
    if (!password) return { ok: false, error: 'password_required' }
    const cm = new CryptoManager(CONFIG_PATH, 'devSettings')
    cm.setPassword(password)
    const cfg = loadConfig()
    const dev = cfg && cfg.devSettings ? cfg.devSettings : {}
    const encPayload = dev && dev.payload ? dev.payload : null
    if (!encPayload) {
      const initData = normalizeDevSettingsData({ blackPath: '', whitePath: '' })
      const enc = cm.encryptText(JSON.stringify(initData))
      cfg.devSettings = cfg.devSettings || {}
      cfg.devSettings.payload = enc
      cfg.devSettings.updatedAt = Date.now()
      saveConfig(cfg)
      config = cfg
      return { ok: true, data: initData }
    }
    try {
      const text = cm.decryptText(encPayload)
      const data = normalizeDevSettingsData(JSON.parse(text))
      const enc = cm.encryptText(JSON.stringify(data))
      cfg.devSettings = cfg.devSettings || {}
      cfg.devSettings.payload = enc
      cfg.devSettings.updatedAt = Date.now()
      saveConfig(cfg)
      config = cfg
      return { ok: true, data }
    } catch {
      return { ok: false, error: 'password_invalid' }
    }
  })

  ipcMain.handle('dev-settings:save', async (_event, payload) => {
    const p = payload && typeof payload === 'object' ? payload : {}
    const password = typeof p.password === 'string' ? p.password : ''
    if (!password) return { ok: false, error: 'password_required' }
    const data = normalizeDevSettingsData(p.data)
    const cm = new CryptoManager(CONFIG_PATH, 'devSettings')
    cm.setPassword(password)
    try {
      const enc = cm.encryptText(JSON.stringify(data))
      const cfg = loadConfig()
      cfg.devSettings = cfg.devSettings || {}
      cfg.devSettings.payload = enc
      cfg.devSettings.updatedAt = Date.now()
      saveConfig(cfg)
      config = cfg
      return { ok: true, data }
    } catch {
      return { ok: false, error: 'save_failed' }
    }
  })

  ipcMain.handle('quarantine-list', () => quarantineManager.getList())
  ipcMain.handle('quarantine-isolate', (event, filePath) => quarantineManager.quarantine(filePath))
  ipcMain.handle('quarantine-restore', (event, id) => quarantineManager.restore(id))
  ipcMain.handle('quarantine-delete', (event, id) => quarantineManager.delete(id))
  ipcMain.handle('process-suspend', async (_event, pid) => {
    const p = Number.isFinite(pid) ? pid : parseInt(String(pid), 10)
    if (!Number.isFinite(p) || p <= 0) return false
    if (!winapi || typeof winapi.suspendProcessByPid !== 'function') return false
    try { return winapi.suspendProcessByPid(p) === true } catch { return false }
  })
  ipcMain.handle('process-resume', async (_event, pid) => {
    const p = Number.isFinite(pid) ? pid : parseInt(String(pid), 10)
    if (!Number.isFinite(p) || p <= 0) return false
    
    let wasPaused = false
    try {
      const pausedPids = interceptionQueue.getPausedPids()
      wasPaused = pausedPids.includes(p)
    } catch {}

    const payload = interceptionQueue.markActionResult(p, true)

    if (wasPaused) {
      try {
        if (payload && payload.pid === p) {
          const evt = payload.event
          if (evt && evt.data && evt.data.type === 'UnsignedDll' && Array.isArray(evt.data.unsignedDlls)) {
            const w = ensureInterceptionSnapshotWorker()
            if (w) w.postMessage({ type: 'allow_dlls', paths: evt.data.unsignedDlls })
          }
        }
      } catch {}

      if (winapi && typeof winapi.resumeProcessByPid === 'function') {
        try { winapi.resumeProcessByPid(p) } catch {}
      }
    }
    
    try {
      if (interceptionQueue.isIdle() && interceptionWin && !interceptionWin.isDestroyed()) interceptionWin.hide()
    } catch {}
    return true
  })
  ipcMain.handle('process-terminate', async (_event, pid) => {
    const p = Number.isFinite(pid) ? pid : parseInt(String(pid), 10)
    if (!Number.isFinite(p) || p <= 0) return false
    
    try { interceptionQueue.markActionResult(p, true) } catch {}

    if (!winapi || typeof winapi.terminateProcessByPid !== 'function') return false
    try {
      const ok = winapi.terminateProcessByPid(p) === true
      try {
        if (interceptionQueue.isIdle() && interceptionWin && !interceptionWin.isDestroyed()) interceptionWin.hide()
      } catch {}
      return ok
    } catch {
      return false
    }
  })
  ipcMain.handle('intercept-action', async (_event, payload) => {
    const p = payload && typeof payload === 'object' ? payload : {}
    const action = typeof p.action === 'string' ? p.action : ''
    const pid = Number.isFinite(p.pid) ? p.pid : parseInt(String(p.pid), 10)
    if (!Number.isFinite(pid) || pid <= 0) return false
    const active = interceptionQueue.getActivePayload()
    if (!active || active.pid !== pid) return false
    if (action === 'allow') {
      let wasPaused = false
      try { wasPaused = interceptionQueue.getPausedPids().includes(pid) } catch {}
      const handled = interceptionQueue.markActionResult(pid, true)
      if (wasPaused) {
        try {
          if (handled && handled.pid === pid) {
            const evt = handled.event
            if (evt && evt.data && typeof evt.data === 'object' && Array.isArray(evt.data.unsignedDlls)) {
              const w = ensureInterceptionSnapshotWorker()
              if (w) w.postMessage({ type: 'allow_dlls', paths: evt.data.unsignedDlls })
            }
          }
        } catch {}
        if (winapi && typeof winapi.resumeProcessByPid === 'function') {
          try { winapi.resumeProcessByPid(pid) } catch {}
        }
      }
      try {
        if (interceptionQueue.isIdle() && interceptionWin && !interceptionWin.isDestroyed()) interceptionWin.hide()
      } catch {}
      return true
    }
    if (action === 'block') {
      try {
        interceptionQueue.markActionResult(pid, true)
      } catch {}
      let ok = false
      if (winapi && typeof winapi.terminateProcessByPid === 'function') {
        try { ok = winapi.terminateProcessByPid(pid) === true } catch { ok = false }
      }
      try {
        if (interceptionQueue.isIdle() && interceptionWin && !interceptionWin.isDestroyed()) interceptionWin.hide()
      } catch {}
      return ok === true
    }
    return false
  })
  ipcMain.handle('intercept-signer', async (_event, filePath) => {
    const p = typeof filePath === 'string' ? filePath : ''
    if (!p) return null
    if (!winapi || typeof winapi.getSignerInfo !== 'function') return null
    try { return winapi.getSignerInfo(p) } catch { return null }
  })
  ipcMain.handle('logs:list', () => eventLogs)
  ipcMain.handle('system-get-running-processes', () => processes.getRunningProcesses())
  ipcMain.handle('behavior-get-db-path', () => behavior.getDbPath())
  ipcMain.handle('behavior-pause-etw', async () => {
    try {
      const res = await controlEtwWorker('pause')
      return !!(res && res.ok)
    } catch {
      return false
    }
  })
  ipcMain.handle('behavior-clear-db', async () => {
    try {
      const ok = await behavior.clearAll()
      return ok === true
    } catch {
      return false
    }
  })
  ipcMain.handle('behavior-clear-all', async () => {
    try {
      const paused = await controlEtwWorker('pause')
      if (!(paused && paused.ok)) return false
      const ok = await behavior.clearAll()
      return ok === true
    } catch {
      return false
    } finally {
      try { await controlEtwWorker('resume') } catch {}
    }
  })
  ipcMain.handle('behavior-resume-etw', async () => {
    try {
      if (!etwWorker) {
        startEtwWorker()
        return await requestEtwStart(6000)
      }
      const res = await controlEtwWorker('resume')
      if (res && res.ok) return true
      try { if (etwWorker) await etwWorker.terminate() } catch {}
      etwWorker = null
      startEtwWorker()
      return await requestEtwStart(6000)
    } catch {
      return false
    }
  })
  ipcMain.handle('behavior-list-processes', async (_event, query) => {
    const list = await behavior.listProcesses(query || {})
    const arr = Array.isArray(list) ? list : []
    const now = Date.now()
    const etwCfg = (config && config.etw) ? config.etw : {}
    const uiCfg = (config && config.behaviorUi) ? config.behaviorUi : {}
    const resolveProcessName = uiCfg.resolveProcessName !== false
    if (!resolveProcessName) return arr
    refreshEtwPidCacheConfig(etwCfg)
    pruneEtwPidCache(now)
    const devicePathToDosPath = (winapi && typeof winapi.devicePathToDosPath === 'function') ? winapi.devicePathToDosPath : null
    return arr.map((p) => {
      const pid = Number.isFinite(p && p.pid) ? p.pid : null
      const out = Object.assign({}, p)
      if (typeof out.image === 'string' && out.image) out.image = normalizeWindowsPathText(out.image, devicePathToDosPath)
      if (typeof out.name === 'string' && out.name) out.name = sanitizeText(out.name)
      if (pid != null) {
        const info = resolveEtwProcessInfo(pid, now, etwCfg)
        if (info && info.imagePath && !out.image) out.image = normalizeWindowsPathText(info.imagePath, devicePathToDosPath)
        if (info && info.name) out.name = sanitizeText(info.name)
      }
      if (out.name && !isCleanText(out.name)) out.name = ''
      if (!out.name && out.image) out.name = getProcessNameFromPath(out.image)
      if (out.name && !isCleanText(out.name)) out.name = ''
      return out
    })
  })
  ipcMain.handle('behavior-list-events', async (_event, query) => {
    const list = await behavior.listEvents(query || {})
    const arr = Array.isArray(list) ? list : []
    const now = Date.now()
    const etwCfg = (config && config.etw) ? config.etw : {}
    const uiCfg = (config && config.behaviorUi) ? config.behaviorUi : {}
    const resolveProcessName = uiCfg.resolveProcessName !== false
    if (!resolveProcessName) return arr
    refreshEtwPidCacheConfig(etwCfg)
    pruneEtwPidCache(now)
    const devicePathToDosPath = (winapi && typeof winapi.devicePathToDosPath === 'function') ? winapi.devicePathToDosPath : null
    /**
     * - 函数: `normalizePath`
     * - Function: `normalizePath`
     * - 作用: 在 `behavior-list-events` 的 UI 数据整形阶段统一规范化路径类字段（含 file/registry/image 等），把 device path 之类的来源文本转换为更适合展示/筛选的 Windows 路径形式。
     * - Purpose: Normalizes path-like fields during the UI shaping step of `behavior-list-events` (file/registry/image, etc.), converting device-path-like inputs into a Windows-path form more suitable for display and filtering.
     * - 调用方: `ipcMain.handle('behavior-list-events')` 内部 `arr.map(...)` 过程中对 `file_path`、`reg_key`、`actor_processImage`、`subject_processImage` 以及 `raw_json.data.*` 的规范化调用。
     * - Callers: Used inside `ipcMain.handle('behavior-list-events')` during `arr.map(...)` for normalizing `file_path`, `reg_key`, `actor_processImage`, `subject_processImage`, and `raw_json.data.*`.
     * - 被调方: `normalizeWindowsPathText`（基于可选的 `devicePathToDosPath` 适配器执行转换）。
     * - Callees: `normalizeWindowsPathText` (optionally using the `devicePathToDosPath` adapter to convert device paths).
     * - 变量说明: `v` 为待规范化的原始文本；`devicePathToDosPath` 为可选的设备路径到 DOS 路径的转换函数（来自 `winapi.devicePathToDosPath`）。
     * - Variables: `v` is the raw text to normalize; `devicePathToDosPath` is an optional device-path-to-DOS-path converter (from `winapi.devicePathToDosPath`).
     * - 接入方式: 仅用于本 handler 内部；如后续新增更多需要展示/检索的路径字段，优先复用 `normalizePath` 统一规范化，而不是在 map 内重复写转换逻辑。
     * - Integration: Internal to this handler only; if more path fields are added later for display/search, reuse `normalizePath` instead of duplicating conversion logic inside the map.
     * - 错误处理: 不在本函数内部吞异常（由上游确保传入为字符串字段）；转换失败时由 `normalizeWindowsPathText` 的防御逻辑降级为原值或可展示的近似值。
     * - Error Handling: This helper does not swallow exceptions itself (the caller guards for string inputs); conversion failures are handled defensively by `normalizeWindowsPathText`, which degrades to the original or a best-effort display value.
     * - 关键词: 路径规范化 | path normalize | 设备路径 | device path | DOS路径 | DOS path | ETW事件 | behavior events | UI整形 | UI shaping | raw_json | JSON parse | Windows路径 | Windows path | normalizeWindowsPathText | devicePathToDosPath | 行为列表 | behavior-list-events
     */
    const normalizePath = (v) => {
      return normalizeWindowsPathText(v, devicePathToDosPath)
    }
    return arr.map((ev) => {
      const out = Object.assign({}, ev)
      const actorPid = Number.isFinite(out.actor_pid) ? out.actor_pid : null
      const subjectPid = Number.isFinite(out.subject_pid) ? out.subject_pid : null
      const actorImage = (typeof out.actor_image === 'string' && out.actor_image) ? out.actor_image : null
      const subjectImage = (typeof out.subject_image === 'string' && out.subject_image) ? out.subject_image : null
      if (typeof out.actor_processImage === 'string' && out.actor_processImage) out.actor_processImage = sanitizeText(out.actor_processImage)
      if (typeof out.subject_processImage === 'string' && out.subject_processImage) out.subject_processImage = sanitizeText(out.subject_processImage)
      if (typeof out.actor_processName === 'string' && out.actor_processName) out.actor_processName = sanitizeText(out.actor_processName)
      if (typeof out.subject_processName === 'string' && out.subject_processName) out.subject_processName = sanitizeText(out.subject_processName)
      if (!out.actor_processImage && actorImage) out.actor_processImage = actorImage
      if (!out.subject_processImage && subjectImage) out.subject_processImage = subjectImage
      if (typeof out.file_path === 'string' && out.file_path) out.file_path = normalizePath(out.file_path)
      if (typeof out.reg_key === 'string' && out.reg_key) out.reg_key = normalizePath(out.reg_key)
      if (!out.actor_processName && out.actor_processImage) out.actor_processName = getProcessNameFromPath(out.actor_processImage)
      if (!out.subject_processName && out.subject_processImage) out.subject_processName = getProcessNameFromPath(out.subject_processImage)
      if (actorPid != null) {
        const info = resolveEtwProcessInfo(actorPid, now, etwCfg)
        if (info && info.name) out.actor_processName = sanitizeText(info.name)
        if (info && info.imagePath) out.actor_processImage = info.imagePath
      }
      if (subjectPid != null) {
        const info = resolveEtwProcessInfo(subjectPid, now, etwCfg)
        if (info && info.name) out.subject_processName = sanitizeText(info.name)
        if (info && info.imagePath) out.subject_processImage = info.imagePath
      }
      if (typeof out.actor_processImage === 'string' && out.actor_processImage) out.actor_processImage = normalizePath(out.actor_processImage)
      if (typeof out.subject_processImage === 'string' && out.subject_processImage) out.subject_processImage = normalizePath(out.subject_processImage)
      if (typeof out.raw_json === 'string' && out.raw_json) {
        try {
          const obj = JSON.parse(out.raw_json)
          if (obj && typeof obj === 'object') {
            const d = obj.data && typeof obj.data === 'object' ? obj.data : null
            if (d) {
              if (typeof d.keyPath === 'string' && d.keyPath) d.keyPath = normalizePath(d.keyPath)
              if (typeof d.fileName === 'string' && d.fileName) d.fileName = normalizePath(d.fileName)
              if (typeof d.imageName === 'string' && d.imageName) d.imageName = normalizePath(d.imageName)
              out.raw_json = JSON.stringify(obj)
            }
          }
        } catch {}
      }
      if (out.actor_processName && !isCleanText(out.actor_processName)) out.actor_processName = ''
      if (out.subject_processName && !isCleanText(out.subject_processName)) out.subject_processName = ''
      if (!out.actor_processName && out.actor_processImage) out.actor_processName = getProcessNameFromPath(out.actor_processImage)
      if (!out.subject_processName && out.subject_processImage) out.subject_processName = getProcessNameFromPath(out.subject_processImage)
      return out
    })
  })
  ipcMain.handle('scanner:health', async () => scannerClient.health())
  ipcMain.handle('scanner:scanFile', async (_event, payload) => {
    const p = payload && typeof payload === 'object' ? payload : {}
    return scannerClient.scanFile(p.filePath, p.requestId)
  })
  ipcMain.handle('scanner:scanBatch', async (_event, payload) => {
    const p = payload && typeof payload === 'object' ? payload : {}
    return scannerClient.scanBatch(p.filePaths, p.requestId)
  })
  ipcMain.handle('scanner:verifyTrust', async (_event, payload) => {
    const p = payload && typeof payload === 'object' ? payload : {}
    const filePath = typeof p.filePath === 'string' ? p.filePath : ''
    if (!filePath) return false
    if (!winapi || typeof winapi.verifyTrust !== 'function') return false
    try { return winapi.verifyTrust(filePath) === true } catch { return false }
  })
  ipcMain.handle('scanner:trainFromPath', async (_event, payload) => {
    const p = payload && typeof payload === 'object' ? payload : {}
    const samplePath = typeof p.path === 'string' ? p.path : ''
    const isWhite = p.isWhite === true
    let files = Array.isArray(p.files) ? p.files.filter(Boolean) : []
    if (!files.length && samplePath) files = [samplePath]
    const workerPath = path.join(__dirname, 'workers/training_worker.js')
    if (!fs.existsSync(workerPath)) {
      if (files.length > 1 && scannerClient && typeof scannerClient.trainPaths === 'function') {
        return scannerClient.trainPaths(files, isWhite)
      }
      return scannerClient.trainFromPath(samplePath, isWhite)
    }
    if (!files.length) {
      return { ok: false, total: 0, trained: 0, failed: 0 }
    }
    const sender = _event && _event.sender ? _event.sender : null
    const cfgSnapshot = {
      scanner: (config && config.scanner) ? config.scanner : {},
      scan: (config && config.scan) ? config.scan : {}
    }
    return new Promise((resolve) => {
      const totalAll = files.length
      let doneAll = 0
      let resolved = false
      /**
       * - 函数: `postProgress`
       * - Function: `postProgress`
       * - 作用: 向触发 `scanner:trainFromPath` 的渲染进程回推训练进度事件，用于 UI 展示“总数/已完成/当前文件”的实时反馈。
       * - Purpose: Pushes training progress events back to the renderer that invoked `scanner:trainFromPath`, enabling UI feedback with “total/done/current file”.
       * - 调用方: 本 Promise 内部的 `w.on('message')` 分支（`count` 时初始化进度、`progress` 时更新进度）。
       * - Callers: Invoked by the `w.on('message')` branches inside this Promise (`count` initializes progress, `progress` updates progress).
       * - 被调方: `sender.send('scanner:trainProgress', ...)`。
       * - Callees: `sender.send('scanner:trainProgress', ...)`.
       * - 变量说明: `file` 为当前正在处理的文件路径（可为空字符串）；`sender` 为 `_event.sender`；`totalAll` 为训练样本总数；`doneAll` 为已完成数量。
       * - Variables: `file` is the currently processed file path (may be an empty string); `sender` is `_event.sender`; `totalAll` is total samples; `doneAll` is completed count.
       * - 接入方式: 仅供本 handler 内部使用；如新增更多进度字段，应在此处扩展 payload 结构并保持事件名不变，避免前端订阅分裂。
       * - Integration: Internal to this handler; if more progress fields are needed, extend the payload here while keeping the event name stable to avoid fragmenting frontend subscriptions.
       * - 错误处理: `sender` 不存在时静默跳过；本函数不抛异常，避免 worker 训练链路因 UI 回推失败而中断。
       * - Error Handling: Silently skips when `sender` is missing; never throws so UI push failures do not break the training worker pipeline.
       * - 关键词: 训练进度 | train progress | IPC回推 | IPC push | sender.send | scanner:trainProgress | 当前文件 | current file | total done | Worker消息 | worker message | trainFromPath | 渲染订阅 | renderer subscription | UI反馈 | UI feedback | 安全降级 | graceful fallback
       */
      const postProgress = (file) => {
        if (sender) sender.send('scanner:trainProgress', { total: totalAll, done: doneAll, current: file || '' })
      }
      const w = new Worker(workerPath)
      /**
       * - 函数: `finalize`
       * - Function: `finalize`
       * - 作用: 统一收尾并 resolve `scanner:trainFromPath` 的 Promise，确保只 resolve 一次，同时尝试终止训练 worker 并在缺省场景下回填失败统计。
       * - Purpose: Finalizes and resolves the `scanner:trainFromPath` Promise exactly once, attempting to terminate the training worker and providing a default failure summary when no result is available.
       * - 调用方: `w.on('message')` 在收到 `done` 时调用；`w.on('error')` 在 worker 异常时调用；也可能被未来新增的超时/取消分支复用。
       * - Callers: Called by `w.on('message')` when receiving `done`, by `w.on('error')` on worker failure, and can be reused by future timeout/cancel branches.
       * - 被调方: `Worker#terminate`、Promise 的 `resolve(...)`。
       * - Callees: `Worker#terminate`, the Promise `resolve(...)`.
       * - 变量说明: `result` 为 worker 回传的训练结果对象；`resolved` 为“是否已完成”的一次性门闩；`w` 为训练 worker；`totalAll` 为样本总数，用于构造默认失败结果。
       * - Variables: `result` is the training result object from the worker; `resolved` is a one-shot latch; `w` is the training worker; `totalAll` is the sample count used to build the default failure result.
       * - 接入方式: 仅用于本 Promise 的生命周期管理；如新增超时/取消逻辑，应该调用 `finalize(...)` 以复用“一次 resolve + 终止 worker + 默认结果”的一致语义。
       * - Integration: Use it only for this Promise lifecycle; if timeout/cancel logic is added, call `finalize(...)` to reuse the consistent semantics of “resolve once + terminate worker + default result”.
       * - 错误处理: 通过 `resolved` 防止重复 resolve；`terminate()` 异常会被吞掉；`result` 缺失时回退为 `{ ok:false, total, trained:0, failed:total }`，避免前端拿到 `undefined`。
       * - Error Handling: Uses `resolved` to prevent double-resolve; swallows `terminate()` errors; falls back to `{ ok:false, total, trained:0, failed:total }` when `result` is missing to avoid returning `undefined` to the UI.
       * - 关键词: 收尾 | finalize | 一次resolve | resolve once | 终止worker | terminate worker | 默认结果 | default result | 训练结果 | train result | 异常兜底 | error fallback | Promise生命周期 | Promise lifecycle | scanner:trainFromPath | worker message | resolved门闩 | resolved latch
       */
      const finalize = (result) => {
        if (resolved) return
        resolved = true
        try { w.terminate() } catch {}
        resolve(result || { ok: false, total: totalAll, trained: 0, failed: totalAll })
      }
      w.on('message', (msg) => {
        if (!msg) return
        if (msg.type === 'count') {
          doneAll = 0
          postProgress('')
          return
        }
        if (msg.type === 'progress') {
          doneAll = Number.isFinite(msg.done) ? msg.done : doneAll
          postProgress(msg.current || '')
          return
        }
        if (msg.type === 'done') {
          const res = msg.result && typeof msg.result === 'object' ? msg.result : { ok: false, total: totalAll, trained: 0, failed: totalAll }
          finalize(res)
        }
      })
      w.on('error', () => finalize())
      w.postMessage({ type: 'train', isWhite, files, config: cfgSnapshot })
    })
  })
  ipcMain.handle('scanner:abort', async (_event, requestId) => scannerClient.abort(requestId))
  ipcMain.handle('signature-store:listVersions', async () => {
    if (!scannerClient || !scannerClient.signatureStore || !scannerClient.signatureStore.listVersions) return []
    return scannerClient.signatureStore.listVersions()
  })
  ipcMain.handle('signature-store:getCurrentVersion', async () => {
    if (!scannerClient || !scannerClient.signatureStore || !scannerClient.signatureStore.getCurrentVersion) return ''
    return scannerClient.signatureStore.getCurrentVersion()
  })
  ipcMain.handle('signature-store:rollback', async (_event, payload) => {
    if (!scannerClient || !scannerClient.signatureStore || !scannerClient.signatureStore.rollback) return false
    const p = payload && typeof payload === 'object' ? payload : {}
    return scannerClient.signatureStore.rollback(typeof p.versionId === 'string' ? p.versionId : '')
  })

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
    else win.show()
  })
  ipcMain.on('ui-debug', (_evt, data) => {
    try {
      const tag = data && data.tag
      const payload = data && data.payload
      console.log('渲染进程调试:', tag, payload)
    } catch (e) {
      console.log('渲染进程调试: 解析失败', e && e.message)
    }
  })
  ipcMain.on('error-trace', (_evt, payload) => {
    const p = payload && typeof payload === 'object' ? payload : {}
    appendErrorTrace({ ts: Date.now(), source: 'renderer_trace', ...p })
  })
  ipcMain.on('set-title-bar-overlay', (_evt, config) => {
    try {
      if (win && !win.isDestroyed()) {
        win.setTitleBarOverlay(config)
      }
    } catch {}
  })
})

let isQuitting = false
app.on('render-process-gone', (_event, _wc, details) => {
  appendErrorTrace({ ts: Date.now(), source: 'app_render_gone', details })
})
app.on('child-process-gone', (_event, details) => {
  appendErrorTrace({ ts: Date.now(), source: 'app_child_gone', details })
})
app.on('before-quit', (e) => {
  if (isQuitting) return
  
  if (etwWorker) {
    e.preventDefault()
    isQuitting = true
    
    const forceQuit = setTimeout(() => {
      console.warn('主进程: ETW Worker 停止超时，将断开连接并退出')
      if (etwWorker) etwWorker.unref()
      Promise.resolve()
        .then(() => stopHookIpcServer())
        .then(() => behavior.stop())
        .catch(() => {})
        .finally(() => app.quit())
    }, 5000)
    
    etwWorker.once('exit', () => {
      clearTimeout(forceQuit)
      Promise.resolve()
        .then(() => stopHookIpcServer())
        .then(() => behavior.stop())
        .catch(() => {})
        .finally(() => app.quit())
    })
    
    etwWorker.postMessage({ type: 'stop' })
  } else {
    e.preventDefault()
    isQuitting = true
    Promise.resolve()
      .then(() => stopHookIpcServer())
      .then(() => behavior.stop())
      .catch(() => {})
      .finally(() => app.quit())
  }
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
