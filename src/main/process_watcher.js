const fs = require('fs')
const path = require('path')
const koffi = require('koffi')

let lib = null
let startFn = null
let stopFn = null
let setSignedFn = null
let pollFn = null

/**
 * - 函数: `fileExists`
 * - Function: `fileExists`
 * - 作用: 安全判断候选 DLL 路径是否存在，供进程监控原生库定位流程复用。
 * - Purpose: Safely checks whether a candidate DLL path exists so the native process-watcher resolution flow can reuse it.
 * - 调用方: `resolveProcessWatcherPath`。
 * - Callers: `resolveProcessWatcherPath`.
 * - 被调方: `fs.existsSync`。
 * - Callees: `fs.existsSync`.
 * - 变量说明: `p` 为待检查的文件路径字符串。
 * - Variables: `p` is the file-path string to verify.
 * - 接入方式: 仅作为当前模块内部文件存在性探测助手使用，避免在路径枚举处重复写异常保护。
 * - Integration: Use it only as the internal existence-check helper so path enumeration does not duplicate try/catch guards.
 * - 错误处理: `existsSync` 抛异常时返回 `false`，保证候选路径探测继续执行。
 * - Error Handling: Returns `false` if `existsSync` throws so candidate probing can continue safely.
 * - 关键词: 文件存在检查 | file existence check | DLL探测 | DLL probing | 原生库定位 | native library resolution | 安全回退 | safe fallback | 路径校验 | path validation
 */
function fileExists(p) {
  try { return !!(p && fs.existsSync(p)) } catch { return false }
}

/**
 * - 函数: `resolveProcessWatcherPath`
 * - Function: `resolveProcessWatcherPath`
 * - 作用: 按打包资源目录与开发目录顺序解析 `process_watcher.dll` 的实际位置，作为原生监控入口的统一路径来源。
 * - Purpose: Resolves the real `process_watcher.dll` location from packaged-resource and development directories in order, serving as the single path source for native monitoring startup.
 * - 调用方: `tryLoad`。
 * - Callers: `tryLoad`.
 * - 被调方: `path.join`、`fileExists`。
 * - Callees: `path.join` and `fileExists`.
 * - 变量说明: `candidates` 为按优先级收集的候选 DLL 路径列表；循环变量 `p` 为当前探测路径。
 * - Variables: `candidates` stores candidate DLL paths by priority; loop variable `p` is the current path being probed.
 * - 接入方式: 仅供原生库加载前调用；若后续新增安装目录或架构目录，应优先在本函数补充候选列表。
 * - Integration: Call it only before native-library loading; if new install or architecture directories are added later, extend the candidate list here first.
 * - 错误处理: 单个候选路径拼接失败会被静默跳过；全部候选都不可用时返回空字符串。
 * - Error Handling: A failed candidate-path assembly is skipped silently, and the function returns an empty string when no candidate is usable.
 * - 关键词: DLL路径解析 | DLL path resolution | 打包资源目录 | packaged resources | 开发目录回退 | development fallback | 候选路径探测 | candidate path probing | 进程监控库 | process watcher library
 */
function resolveProcessWatcherPath() {
  const candidates = []
  try {
    if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
      candidates.push(path.join(process.resourcesPath, 'native', 'win32-x64', 'process_watcher.dll'))
      candidates.push(path.join(process.resourcesPath, 'native', 'bin', 'win32-x64', 'process_watcher.dll'))
    }
  } catch {}
  try { candidates.push(path.join(__dirname, '../../native/bin/win32-x64/process_watcher.dll')) } catch {}
  try { candidates.push(path.join(__dirname, '../../native/win32-x64/process_watcher.dll')) } catch {}
  for (const p of candidates) {
    if (fileExists(p)) return p
  }
  return ''
}

/**
 * - 函数: `tryLoad`
 * - Function: `tryLoad`
 * - 作用: 懒加载进程监控原生 DLL，并绑定启动、停止、签名名单同步和新 PID 轮询四个导出函数。
 * - Purpose: Lazily loads the native process-watcher DLL and binds the four exported functions for start, stop, signed-list sync, and new-PID polling.
 * - 调用方: `startProcessWatcher`、`setSignedPaths`。
 * - Callers: `startProcessWatcher` and `setSignedPaths`.
 * - 被调方: `resolveProcessWatcherPath`、`koffi.load`、`lib.func`。
 * - Callees: `resolveProcessWatcherPath`, `koffi.load`, and `lib.func`.
 * - 变量说明: `dllPath` 为解析出的原生库路径；模块级变量 `lib`、`startFn`、`stopFn`、`setSignedFn`、`pollFn` 分别缓存库句柄和导出函数。
 * - Variables: `dllPath` is the resolved native-library path; module-level variables `lib`, `startFn`, `stopFn`, `setSignedFn`, and `pollFn` cache the library handle and exports.
 * - 接入方式: 作为所有原生调用前的统一加载闸门使用；不要在调用方重复直接 `koffi.load`。
 * - Integration: Use it as the shared load gate before any native call; callers should not perform their own direct `koffi.load`.
 * - 错误处理: DLL 不存在或导出绑定失败时清空所有缓存句柄并返回 `false`，避免保留半初始化状态。
 * - Error Handling: If the DLL is missing or export binding fails, it clears every cached handle and returns `false` so no half-initialized state remains.
 * - 关键词: 原生库懒加载 | native lazy load | Koffi绑定 | Koffi binding | 导出函数缓存 | export caching | 监控初始化闸门 | monitor init gate | DLL加载失败回退 | DLL load fallback
 */
function tryLoad() {
  if (lib && startFn && stopFn) return true
  const dllPath = resolveProcessWatcherPath()
  if (!dllPath) return false
  try {
    lib = koffi.load(dllPath)
    startFn = lib.func('__cdecl', 'ProcessWatcher_Start', 'int', ['string16', 'string16', 'string16', 'string16', 'int'])
    stopFn = lib.func('__cdecl', 'ProcessWatcher_Stop', 'void', [])
    setSignedFn = lib.func('__cdecl', 'ProcessWatcher_SetSignedList', 'int', ['string16', 'int'])
    pollFn = lib.func('__cdecl', 'ProcessWatcher_PollNewPid', 'int', [])
    return true
  } catch {
    lib = null
    startFn = null
    stopFn = null
    setSignedFn = null
    pollFn = null
    return false
  }
}

/**
 * - 函数: `startProcessWatcher`
 * - Function: `startProcessWatcher`
 * - 作用: 启动原生进程监控器，并将双架构注入器与 Hook DLL 路径、轮询间隔下发给底层监控 DLL。
 * - Purpose: Starts the native process watcher and passes the dual-architecture injector paths, Hook DLL paths, and polling interval into the underlying monitoring DLL.
 * - 调用方: `main.js` 的 `startSecurityComponents` 启动阶段。
 * - Callers: The `startSecurityComponents` startup stage in `main.js`.
 * - 被调方: `tryLoad`、`Math.floor`、`startFn`。
 * - Callees: `tryLoad`, `Math.floor`, and `startFn`.
 * - 变量说明: `opts` 为启动配置；`injectorX64`/`injectorX86` 为两种架构的注入器路径；`dllX64`/`dllX86` 为 Hook DLL 路径；`intervalMs` 为原生监控轮询周期。
 * - Variables: `opts` is the startup config; `injectorX64` and `injectorX86` are injector paths for both architectures; `dllX64` and `dllX86` are Hook DLL paths; `intervalMs` is the native watcher poll interval.
 * - 接入方式: 通过 `const { startProcessWatcher } = require('./process_watcher')` 接入，并在主进程完成 Hook 工件解析后调用。
 * - Integration: Integrate via `const { startProcessWatcher } = require('./process_watcher')` and call it after the main process resolves Hook artifacts.
 * - 错误处理: 原生库不可用、注入器缺失或 DLL 缺失时返回带 `reason` 的失败对象；不抛异常，由上层决定是否降级。
 * - Error Handling: Returns a failure object with `reason` when the native library is unavailable or injector/DLL paths are missing; it does not throw and lets upper layers decide whether to degrade.
 * - 关键词: 进程监控启动 | process watcher start | Hook注入器路径 | hook injector path | 双架构支持 | dual architecture | 原生监控DLL | native monitor DLL | 启动结果回传 | startup result
 */
function startProcessWatcher(opts) {
  if (!tryLoad()) return { ok: false, reason: 'dll_missing' }
  const cfg = opts && typeof opts === 'object' ? opts : {}
  const injectorX64 = cfg.injectorX64 || ''
  const injectorX86 = cfg.injectorX86 || ''
  const dllX64 = cfg.dllX64 || ''
  const dllX86 = cfg.dllX86 || ''
  const intervalMs = Number.isFinite(cfg.intervalMs) ? Math.floor(cfg.intervalMs) : 100
  if (!injectorX64 && !injectorX86) return { ok: false, reason: 'injector_missing' }
  if (!dllX64 && !dllX86) return { ok: false, reason: 'dll_missing' }
  const res = startFn(injectorX64, injectorX86, dllX64, dllX86, intervalMs)
  return { ok: res === 1 }
}

/**
 * - 函数: `stopProcessWatcher`
 * - Function: `stopProcessWatcher`
 * - 作用: 请求原生进程监控器停止运行，供应用退出或安全组件关闭时释放底层监控循环。
 * - Purpose: Requests the native process watcher to stop so app shutdown or security-component teardown can release the underlying monitoring loop.
 * - 调用方: 主进程退出或安全组件停机流程。
 * - Callers: Main-process shutdown or security-component teardown flows.
 * - 被调方: `stopFn`。
 * - Callees: `stopFn`.
 * - 变量说明: 无显式入参；`stopFn` 为原生 DLL 导出的停止函数缓存。
 * - Variables: There are no explicit parameters; `stopFn` is the cached stop export from the native DLL.
 * - 接入方式: 通过 `const { stopProcessWatcher } = require('./process_watcher')` 接入，在确认原生监控已启动后调用即可。
 * - Integration: Integrate via `const { stopProcessWatcher } = require('./process_watcher')` and call it once the native watcher has been started.
 * - 错误处理: 未加载原生函数时直接忽略；调用停止函数异常时静默吞掉，避免退出链路被阻断。
 * - Error Handling: It does nothing when the native function is unavailable, and swallows stop-call failures so the shutdown path is not blocked.
 * - 关键词: 进程监控停止 | process watcher stop | 原生停止调用 | native stop call | 退出释放 | shutdown release | 安全组件停机 | security teardown | 停止容错 | stop fault tolerance
 */
function stopProcessWatcher() {
  if (stopFn) {
    try { stopFn() } catch {}
  }
}

/**
 * - 函数: `setSignedPaths`
 * - Function: `setSignedPaths`
 * - 作用: 将主进程已验证为可信签名的路径列表同步给原生监控器，减少重复拦截与重复验证。
 * - Purpose: Synchronizes the main process's already trusted signed-path list into the native watcher to reduce repeated interception and repeated trust checks.
 * - 调用方: `main.js` 中进程监控启动后的可信路径下发流程。
 * - Callers: The trusted-path sync flow in `main.js` after the process watcher starts.
 * - 被调方: `tryLoad`、`Array.isArray`、`Array.prototype.filter`、`Array.prototype.join`、`setSignedFn`。
 * - Callees: `tryLoad`, `Array.isArray`, `Array.prototype.filter`, `Array.prototype.join`, and `setSignedFn`.
 * - 变量说明: `paths` 为待同步的可信路径数组；`list` 为过滤后的有效字符串路径列表；`payload` 为按换行拼接后的原生输入文本；`added` 为原生层接受的条目数。
 * - Variables: `paths` is the trusted-path array to sync; `list` is the filtered string-path list; `payload` is the newline-joined native input; `added` is the number of entries accepted by the native layer.
 * - 接入方式: 通过 `const { setSignedPaths } = require('./process_watcher')` 接入；当可信签名集合刷新后应再次调用本函数同步原生侧状态。
 * - Integration: Integrate via `const { setSignedPaths } = require('./process_watcher')`; call it again whenever the trusted-signed set is refreshed so native state stays aligned.
 * - 错误处理: 原生库未加载时返回 `{ ok: false }`；空列表视为成功但不下发；函数本身不抛异常。
 * - Error Handling: Returns `{ ok: false }` when the native library is unavailable, treats an empty list as a successful no-op, and does not throw.
 * - 关键词: 可信路径同步 | trusted path sync | 签名白名单下发 | signed allowlist push | 原生监控过滤 | native watcher filtering | 重复验证减少 | duplicate verification reduction | 路径批量同步 | batch path sync
 */
function setSignedPaths(paths) {
  if (!tryLoad()) return { ok: false }
  const list = Array.isArray(paths) ? paths.filter(p => typeof p === 'string' && p) : []
  if (!list.length) return { ok: true, added: 0 }
  const payload = list.join('\n')
  const added = setSignedFn(payload, payload.length)
  return { ok: true, added }
}

/**
 * - 函数: `pollNewPid`
 * - Function: `pollNewPid`
 * - 作用: 从原生进程监控器轮询一个新发现的 PID，供主进程定时器批量消费并触发后续注入或分析逻辑。
 * - Purpose: Polls one newly discovered PID from the native watcher so the main-process timer can consume it in batches and trigger follow-up injection or analysis logic.
 * - 调用方: `main.js` 中的 `processWatcherPidTimer` 轮询循环。
 * - Callers: The `processWatcherPidTimer` polling loop in `main.js`.
 * - 被调方: `pollFn`。
 * - Callees: `pollFn`.
 * - 变量说明: 无显式入参；`pollFn` 为原生 DLL 导出的新 PID 轮询函数。
 * - Variables: There are no explicit parameters; `pollFn` is the native DLL export used to poll new PIDs.
 * - 接入方式: 通过 `const { pollNewPid } = require('./process_watcher')` 接入，并由上层循环重复调用直到返回 `0`。
 * - Integration: Integrate via `const { pollNewPid } = require('./process_watcher')` and keep calling it from the upper loop until it returns `0`.
 * - 错误处理: 原生轮询函数未准备好或执行失败时返回 `0`，上层可将其视为“当前无新 PID”。
 * - Error Handling: Returns `0` when the native polling function is unavailable or fails, allowing the caller to treat that state as “no new PID right now.”
 * - 关键词: 新PID轮询 | new PID polling | 原生监控队列 | native watcher queue | 主进程消费 | main process consumption | 定时轮询 | timer polling | 空结果回退 | empty result fallback
 */
function pollNewPid() {
  if (!pollFn) return 0
  try { return pollFn() | 0 } catch { return 0 }
}

module.exports = {
  startProcessWatcher,
  stopProcessWatcher,
  setSignedPaths,
  pollNewPid
}
