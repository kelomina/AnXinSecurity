const { parentPort } = require('worker_threads')
const path = require('path')

const scanCache = new Map()

let winapi = null
try {
  winapi = require('../winapi')
} catch {}

let scanInFlight = false

/**
 * - 函数: `postMessage`
 * - Function: `postMessage`
 * - 作用: 将 worker 侧扫描、恢复和快照结果安全回传给主线程，统一封装消息发送出口。
 * - Purpose: Safely sends scan, resume, and snapshot results from the worker back to the main thread through one shared message gateway.
 * - 调用方: `scanSnapshot`、`resumeMany`、`pidSnapshot`，以及消息分发中的失败回调。
 * - Callers: `scanSnapshot`, `resumeMany`, `pidSnapshot`, plus the failure callbacks in the message dispatcher.
 * - 被调方: `parentPort.postMessage`。
 * - Callees: `parentPort.postMessage`.
 * - 变量说明: `payload` 为发送给主线程的消息对象，通常包含 `type`、`requestId`、`pid`、`list` 等字段。
 * - Variables: `payload` is the message object sent to the main thread and usually contains fields such as `type`, `requestId`, `pid`, or `list`.
 * - 接入方式: 仅供 worker 内部复用；新增消息类型时优先复用本函数而不是直接操作 `parentPort`。
 * - Integration: Reuse it only inside the worker; when adding new message types, prefer this helper over calling `parentPort` directly.
 * - 错误处理: 无主线程端口或发送异常时静默吞掉，避免 worker 因消息回传失败而中断主链路。
 * - Error Handling: It silently swallows missing-port or send failures so the worker does not break the primary flow just because result reporting fails.
 * - 关键词: Worker消息回传 | worker message relay | 主线程通信 | main thread communication | 扫描结果上报 | scan result reporting | 请求响应桥接 | request-response bridge | 安全发送 | safe message send
 */
function postMessage(payload) {
  if (!parentPort) return
  try { parentPort.postMessage(payload) } catch {}
}

/**
 * - 函数: `sleepImmediate`
 * - Function: `sleepImmediate`
 * - 作用: 在大批量扫描或恢复循环中主动让出一次事件循环，降低 worker 长时间占用线程的风险。
 * - Purpose: Yields once to the event loop inside heavy scan or resume loops so the worker is less likely to monopolize its thread for too long.
 * - 调用方: `scanSnapshot`、`resumeMany`。
 * - Callers: `scanSnapshot` and `resumeMany`.
 * - 被调方: `Promise`、`setImmediate`。
 * - Callees: `Promise` and `setImmediate`.
 * - 变量说明: 无显式入参；`resolve` 为 Promise 完成回调。
 * - Variables: There are no explicit parameters; `resolve` is the Promise completion callback.
 * - 接入方式: 在长循环的固定步长处 `await sleepImmediate()` 即可，无需引入额外定时器。
 * - Integration: Add `await sleepImmediate()` at fixed intervals inside long loops without introducing extra timers.
 * - 错误处理: `setImmediate` 不可用时立即 `resolve()`，确保让步失败不会阻塞扫描流程。
 * - Error Handling: It resolves immediately when `setImmediate` is unavailable so a failed yield never blocks the scan flow.
 * - 关键词: 事件循环让步 | event loop yield | Worker防卡顿 | worker responsiveness | 批量扫描节流 | batch scan throttling | 长循环切片 | long loop slicing | 轻量等待 | lightweight wait
 */
function sleepImmediate() {
  return new Promise((resolve) => {
    try { setImmediate(resolve) } catch { resolve() }
  })
}

/**
 * - 函数: `asBool`
 * - Function: `asBool`
 * - 作用: 将 worker 扫描配置中的布尔项做最小归一化，保证配置解析结果稳定。
 * - Purpose: Minimally normalizes boolean fields in the worker scan config so configuration parsing stays stable.
 * - 调用方: `resolveConfig`。
 * - Callers: `resolveConfig`.
 * - 被调方: 无。
 * - Callees: None.
 * - 变量说明: `v` 为待解析的布尔输入；`def` 为默认布尔值。
 * - Variables: `v` is the boolean-like input to parse; `def` is the default boolean value.
 * - 接入方式: 仅在配置归一化层复用；如新增布尔开关，可直接经由本函数收口默认值逻辑。
 * - Integration: Reuse it only in the config-normalization layer; any new boolean switch can route through this helper to share default handling.
 * - 错误处理: 非显式 `true` 或 `false` 的输入统一回退到默认值，不抛异常。
 * - Error Handling: Any input other than explicit `true` or `false` falls back to the default without throwing.
 * - 关键词: 布尔归一化 | boolean normalization | 扫描配置解析 | scan config parsing | 默认值回退 | default fallback | Worker配置 | worker config | 开关收口 | flag normalization
 */
function asBool(v, def) {
  if (v === true) return true
  if (v === false) return false
  return def === true
}

/**
 * - 函数: `asInt`
 * - Function: `asInt`
 * - 作用: 将数值配置和消息参数归一化为受上下界约束的整数，避免 worker 接收异常规模的扫描输入。
 * - Purpose: Normalizes numeric config and message parameters into bounded integers so the worker does not accept abnormal scan sizes.
 * - 调用方: `resolveConfig`、`pidSnapshot`。
 * - Callers: `resolveConfig` and `pidSnapshot`.
 * - 被调方: `parseInt`、`Number.isFinite`、`Math.floor`、`Math.min`、`Math.max`。
 * - Callees: `parseInt`, `Number.isFinite`, `Math.floor`, `Math.min`, and `Math.max`.
 * - 变量说明: `v` 为待解析输入；`def` 为默认值；`min` 与 `max` 为允许范围边界；`n` 与 `x` 为归一化过程中的中间数值。
 * - Variables: `v` is the raw input; `def` is the default value; `min` and `max` are range bounds; `n` and `x` are intermediate normalized numbers.
 * - 接入方式: 对所有来自主线程的整数配置优先走本函数，保持 worker 侧限制一致。
 * - Integration: Route integer-like values from the main thread through this helper first so worker-side bounds stay consistent.
 * - 错误处理: 解析失败时回退到默认值；超出边界时裁剪到合法区间。
 * - Error Handling: Falls back to the default when parsing fails and clamps the result into the legal range when bounds are exceeded.
 * - 关键词: 整数归一化 | integer normalization | 参数限幅 | parameter clamping | Worker输入保护 | worker input guard | 数值默认值 | numeric default | 边界控制 | range control
 */
function asInt(v, def, min, max) {
  const n = Number.isFinite(v) ? v : parseInt(String(v), 10)
  if (!Number.isFinite(n)) return def
  const x = Math.floor(n)
  if (Number.isFinite(min)) return Math.min(Number.isFinite(max) ? max : x, Math.max(min, x))
  if (Number.isFinite(max)) return Math.min(max, x)
  return x
}

/**
 * - 函数: `resolveConfig`
 * - Function: `resolveConfig`
 * - 作用: 将主线程传入的快照扫描配置解析为 worker 内部可直接执行的规范化配置对象。
 * - Purpose: Parses the snapshot-scan configuration from the main thread into a normalized object that the worker can execute directly.
 * - 调用方: `scanSnapshot`。
 * - Callers: `scanSnapshot`.
 * - 被调方: `asInt`、`asBool`、`Array.isArray`、`Array.prototype.filter`。
 * - Callees: `asInt`, `asBool`, `Array.isArray`, and `Array.prototype.filter`.
 * - 变量说明: `cfg` 为主线程传入的原始配置；`c` 为经过对象守卫后的安全配置视图。
 * - Variables: `cfg` is the raw config received from the main thread; `c` is the guarded config view after the object check.
 * - 接入方式: `scan` 消息进入 worker 后先调用本函数，再使用返回值驱动整个扫描流程。
 * - Integration: Call it first after the `scan` message enters the worker, then drive the entire scan flow from the normalized return value.
 * - 错误处理: 非对象配置或字段类型不合法时回退到默认配置，不抛异常。
 * - Error Handling: Falls back to defaults when the config is not an object or its fields are invalid, without throwing.
 * - 关键词: 扫描配置解析 | scan config resolution | Worker参数规范化 | worker parameter normalization | 默认扫描策略 | default scan policy | 路径名单过滤 | path list filtering | 配置收口 | config consolidation
 */
function resolveConfig(cfg) {
  const c = cfg && typeof cfg === 'object' ? cfg : {}
  return {
    maxPids: asInt(c.maxPids, 8192, 256, 65536),
    modulesBufferBytes: asInt(c.modulesBufferBytes, 65536, 4096, 1024 * 1024),
    skipSystemDll: asBool(c.skipSystemDll, true),
    maxUnsignedDllsPerProcess: asInt(c.maxUnsignedDllsPerProcess, 16, 1, 256),
    exclusionPaths: Array.isArray(c.exclusionPaths) ? c.exclusionPaths.filter(x => typeof x === 'string' && x) : [],
    allowlistFiles: Array.isArray(c.allowlistFiles) ? c.allowlistFiles.filter(x => typeof x === 'string' && x) : []
  }
}

/**
 * - 函数: `normalizeDirLower`
 * - Function: `normalizeDirLower`
 * - 作用: 将目录路径归一化为小写反斜杠并补齐结尾分隔符，便于做目录前缀匹配。
 * - Purpose: Normalizes a directory path into lowercase backslash form with a trailing separator so prefix-based directory checks stay reliable.
 * - 调用方: `shouldSkipInterception`、`scanSnapshot`。
 * - Callers: `shouldSkipInterception` and `scanSnapshot`.
 * - 被调方: `String.prototype.toLowerCase`、`String.prototype.replace`、`String.prototype.endsWith`。
 * - Callees: `String.prototype.toLowerCase`, `String.prototype.replace`, and `String.prototype.endsWith`.
 * - 变量说明: `p` 为原始目录路径；`s` 为归一化后的目录路径字符串。
 * - Variables: `p` is the raw directory path; `s` is the normalized directory-path string.
 * - 接入方式: 所有目录级白名单、排除目录和系统目录判断都应先走本函数统一格式。
 * - Integration: Run every directory-level allowlist, exclusion, and system-directory check through this helper first so formatting stays consistent.
 * - 错误处理: 非字符串输入退化为空字符串，后续前缀判断自然返回未命中。
 * - Error Handling: Non-string inputs degrade to an empty string, causing later prefix checks to miss naturally.
 * - 关键词: 目录路径归一化 | directory path normalization | 小写反斜杠 | lowercase backslashes | 前缀匹配准备 | prefix match preparation | 排除目录判断 | exclusion directory check | 路径格式统一 | path format unification
 */
function normalizeDirLower(p) {
  let s = typeof p === 'string' ? p : ''
  s = s.toLowerCase().replace(/\//g, '\\')
  if (s && !s.endsWith('\\')) s += '\\'
  return s
}

/**
 * - 函数: `isPathUnderDir`
 * - Function: `isPathUnderDir`
 * - 作用: 判断已归一化路径是否位于指定目录前缀下，作为排除规则和系统目录规则的基础谓词。
 * - Purpose: Checks whether a normalized path sits under a given directory prefix, acting as the basic predicate for exclusion and system-directory rules.
 * - 调用方: `shouldSkipInterception`。
 * - Callers: `shouldSkipInterception`.
 * - 被调方: `String.prototype.startsWith`。
 * - Callees: `String.prototype.startsWith`.
 * - 变量说明: `lowerPath` 为已归一化的小写路径；`lowerDir` 为已归一化的小写目录前缀。
 * - Variables: `lowerPath` is the normalized lowercase path; `lowerDir` is the normalized lowercase directory prefix.
 * - 接入方式: 只在路径已通过 `normalizeDirLower` 或 `normalizeLowerPath` 统一格式后调用，避免误判。
 * - Integration: Call it only after the inputs have been standardized by `normalizeDirLower` or `normalizeLowerPath` so false matches are avoided.
 * - 错误处理: 任一输入为空时返回 `false`，避免把未知路径错误地归到排除目录下。
 * - Error Handling: Returns `false` when either input is empty so unknown paths are not incorrectly classified under an excluded directory.
 * - 关键词: 目录前缀判断 | directory prefix check | 路径归属匹配 | path containment match | 排除规则谓词 | exclusion predicate | 小写路径比较 | lowercase path compare | 快速前缀检测 | fast prefix detection
 */
function isPathUnderDir(lowerPath, lowerDir) {
  if (!lowerPath || !lowerDir) return false
  return lowerPath.startsWith(lowerDir)
}

/**
 * - 函数: `shouldSkipInterception`
 * - Function: `shouldSkipInterception`
 * - 作用: 按系统目录、应用自身目录和用户排除目录规则判断某路径是否应跳过拦截扫描。
 * - Purpose: Decides whether a path should skip interception scanning based on system-directory, application-directory, and user exclusion rules.
 * - 调用方: `scanSnapshot`。
 * - Callers: `scanSnapshot`.
 * - 被调方: `isPathUnderDir`、`normalizeDirLower`。
 * - Callees: `isPathUnderDir` and `normalizeDirLower`.
 * - 变量说明: `lowerPath` 为已归一化目标路径；`systemRootLower` 为系统目录根路径；`appDirLower` 为应用目录；`exclusions` 为已归一化排除目录数组。
 * - Variables: `lowerPath` is the normalized target path; `systemRootLower` is the system-root path; `appDirLower` is the app directory; `exclusions` is the normalized exclusion-directory array.
 * - 接入方式: 在进程映像和模块 DLL 做签名判定前先调用本函数，减少无意义扫描。
 * - Integration: Call it before trust verification on process images and module DLLs so unnecessary scans are skipped early.
 * - 错误处理: 空路径直接视为应跳过；目录规则匹配失败则返回 `false`，由后续扫描继续处理。
 * - Error Handling: Empty paths are skipped immediately, while rule misses return `false` so later scanning can continue.
 * - 关键词: 拦截跳过规则 | interception skip rule | 系统目录豁免 | system directory exemption | 应用目录豁免 | app directory exemption | 用户排除路径 | user exclusion paths | 前置过滤 | pre-scan filtering
 */
function shouldSkipInterception(lowerPath, systemRootLower, appDirLower, exclusions) {
  if (!lowerPath) return true
  if (isPathUnderDir(lowerPath, normalizeDirLower(systemRootLower))) return true
  if (isPathUnderDir(lowerPath, appDirLower)) return true
  for (const ex of exclusions) {
    if (isPathUnderDir(lowerPath, ex)) return true
  }
  return false
}

/**
 * - 函数: `normalizeLowerPath`
 * - Function: `normalizeLowerPath`
 * - 作用: 将文件路径标准化为小写反斜杠形式，供签名缓存、允许名单和排除规则做一致比较。
 * - Purpose: Converts a file path into lowercase backslash form so signature cache, allowlist, and exclusion rules compare paths consistently.
 * - 调用方: `scanSnapshot`。
 * - Callers: `scanSnapshot`.
 * - 被调方: `String.prototype.toLowerCase`、`String.prototype.replace`。
 * - Callees: `String.prototype.toLowerCase` and `String.prototype.replace`.
 * - 变量说明: `p` 为原始文件路径输入。
 * - Variables: `p` is the raw file-path input.
 * - 接入方式: 任何文件级路径参与 `Set` 命中或白名单判断前，应先经过本函数。
 * - Integration: Any file-level path should pass through this helper before it participates in `Set` lookups or allowlist checks.
 * - 错误处理: 非字符串输入退化为空字符串，后续比较会自然失败而不是抛异常。
 * - Error Handling: Non-string inputs degrade to an empty string so downstream comparisons fail safely instead of throwing.
 * - 关键词: 文件路径归一化 | file path normalization | 小写路径缓存键 | lowercase cache key | 白名单匹配 | allowlist matching | 签名缓存键 | signature cache key | 路径比较一致性 | path comparison consistency
 */
function normalizeLowerPath(p) {
  return (typeof p === 'string' ? p : '').toLowerCase().replace(/\//g, '\\')
}

/**
 * - 函数: `isAllowlisted`
 * - Function: `isAllowlisted`
 * - 作用: 判断文件路径是否命中主线程下发的允许名单，用于快速跳过已知可信文件。
 * - Purpose: Checks whether a file path matches the allowlist sent from the main thread so known trusted files can be skipped quickly.
 * - 调用方: `scanSnapshot`。
 * - Callers: `scanSnapshot`.
 * - 被调方: `Set.prototype.has`。
 * - Callees: `Set.prototype.has`.
 * - 变量说明: `lowerPath` 为已归一化的小写文件路径；`allowFiles` 为允许名单集合。
 * - Variables: `lowerPath` is the normalized lowercase file path; `allowFiles` is the allowlist set.
 * - 接入方式: 在做签名验证前先查允许名单，以降低 `verifyTrust` 调用频率。
 * - Integration: Check the allowlist before trust verification so calls to `verifyTrust` happen less often.
 * - 错误处理: 路径为空或允许名单不可用时返回 `false`，让后续流程继续正常扫描。
 * - Error Handling: Returns `false` when the path is empty or the allowlist is unavailable so later scanning can proceed normally.
 * - 关键词: 允许名单命中 | allowlist hit | 可信文件跳过 | trusted file skip | 签名验证减载 | trust verification reduction | 路径集合查找 | path set lookup | 快速白名单 | fast allowlist
 */
function isAllowlisted(lowerPath, allowFiles) {
  if (!lowerPath) return false
  if (!allowFiles || typeof allowFiles.has !== 'function') return false
  return allowFiles.has(lowerPath)
}

/**
 * - 函数: `scanSnapshot`
 * - Function: `scanSnapshot`
 * - 作用: 扫描当前进程快照中的可疑目标，必要时先挂起进程，再联动进程签名与模块签名判断，把异常目标以 `paused` 消息回传主线程。
 * - Purpose: Scans suspicious targets in the current process snapshot, suspends them when needed, then combines process-signature and module-signature checks before reporting abnormal targets back through `paused` messages.
 * - 调用方: 主线程通过 `type: 'scan'` 消息触发，入口位于 `main.js` 的 `ensureInterceptionSnapshotWorker` 调度链路。
 * - Callers: Triggered by the main thread through the `type: 'scan'` message in the `ensureInterceptionSnapshotWorker` dispatch flow inside `main.js`.
 * - 被调方: `resolveConfig`、`normalizeDirLower`、`normalizeLowerPath`、`isAllowlisted`、`shouldSkipInterception`、`sleepImmediate`、`postMessage`、`winapi.getProcessImageSnapshot`、`winapi.getProcessModules`、`winapi.verifyTrust`、`winapi.suspendProcessByPid`、`winapi.resumeProcessByPid`、`winapi.devicePathToDosPath`。
 * - Callees: `resolveConfig`, `normalizeDirLower`, `normalizeLowerPath`, `isAllowlisted`, `shouldSkipInterception`, `sleepImmediate`, `postMessage`, `winapi.getProcessImageSnapshot`, `winapi.getProcessModules`, `winapi.verifyTrust`, `winapi.suspendProcessByPid`, `winapi.resumeProcessByPid`, and `winapi.devicePathToDosPath`.
 * - 变量说明: `cfg` 为主线程传入的扫描配置；`conf` 为归一化后的配置；`arr` 为进程快照数组；`targets` 为待分析目标；`allowFiles` 为允许名单集合；`scanCache` 为已验证可信路径缓存；`unsignedDlls` 为当前进程发现的未签名 DLL 列表。
 * - Variables: `cfg` is the raw scan config from the main thread; `conf` is the normalized config; `arr` is the process snapshot array; `targets` holds the processes to analyze; `allowFiles` is the allowlist set; `scanCache` stores already trusted paths; `unsignedDlls` is the list of unsigned DLLs found for the current process.
 * - 接入方式: 主线程创建 worker 后发送 `scan` 消息，并监听 `paused` 与 `scan_done` 事件完成后续处置。
 * - Integration: Create the worker in the main thread, send a `scan` message, then listen for `paused` and `scan_done` events to drive follow-up handling.
 * - 错误处理: 通过能力前置检查、循环内局部 `try/catch`、`scanInFlight` 并发闸门和 `finally` 中的 `scan_done` 保障扫描链路始终可收口。
 * - Error Handling: Uses capability guards, per-step local `try/catch` blocks, the `scanInFlight` concurrency gate, and a `scan_done` post in `finally` so the scan pipeline always closes cleanly.
 * - 关键词: 进程快照扫描 | process snapshot scan | 可疑进程挂起 | suspicious process suspension | 模块签名核验 | module trust verification | Worker扫描链路 | worker scan pipeline | 主线程回报 | main thread reporting
 */
async function scanSnapshot(cfg) {
  if (scanInFlight) return
  scanInFlight = true
  try {
    if (!winapi) return
    if (typeof winapi.getProcessImageSnapshot !== 'function') return
    if (typeof winapi.getProcessModules !== 'function') return
    if (typeof winapi.verifyTrust !== 'function') return
    if (typeof winapi.suspendProcessByPid !== 'function') return
    if (typeof winapi.resumeProcessByPid !== 'function') return

    const conf = resolveConfig(cfg)
    const systemRootLower = String(process.env.SystemRoot || 'C:\\Windows').toLowerCase()
    const appDirLower = normalizeDirLower(path.dirname(process.execPath || ''))
    const exclusions = conf.exclusionPaths.map(p => {
      return normalizeDirLower(p)
    })
    const allowFiles = new Set(conf.allowlistFiles.map(p => normalizeLowerPath(p)).filter(Boolean))

    let list = []
    try { list = winapi.getProcessImageSnapshot(conf.maxPids) } catch { list = [] }
    const arr = Array.isArray(list) ? list : []

    const hasDeviceResolver = typeof winapi.devicePathToDosPath === 'function'
    const targets = []

    for (let i = 0; i < arr.length; i++) {
      const it = arr[i] && typeof arr[i] === 'object' ? arr[i] : null
      const pid = Number.isFinite(it && it.pid) ? it.pid : parseInt(String(it && it.pid), 10)
      if (!Number.isFinite(pid) || pid <= 0) continue
      if (pid === process.pid) continue
      let imagePath = typeof it.imagePath === 'string' ? it.imagePath : ''
      if (!imagePath) continue

      if (hasDeviceResolver && imagePath.startsWith('\\') && !imagePath.startsWith('\\\\')) {
        try {
          const dos = winapi.devicePathToDosPath(imagePath)
          if (dos) imagePath = dos
        } catch {}
      }

      const lowerImage = normalizeLowerPath(imagePath)
      if (isAllowlisted(lowerImage, allowFiles)) continue
      if (shouldSkipInterception(lowerImage, systemRootLower, appDirLower, exclusions)) continue
      targets.push({ pid, imagePath, lowerImage, suspended: false })
      if (i % 200 === 0) await sleepImmediate()
    }

    for (let i = 0; i < targets.length; i++) {
      const t = targets[i]
      try { t.suspended = winapi.suspendProcessByPid(t.pid) === true } catch { t.suspended = false }
      if (i % 50 === 0) await sleepImmediate()
    }

    for (let i = 0; i < targets.length; i++) {
      const t = targets[i]
      const pid = t.pid
      const imagePath = t.imagePath
      const lowerImage = t.lowerImage
      let processSigned = false
      let unsignedDlls = []
      let moduleScanFailed = false
      let scanType = 'process'
      try {
        if (scanCache.get(lowerImage) === true) {
          processSigned = true
        } else {
          try { processSigned = winapi.verifyTrust(imagePath) === true } catch {}
          if (processSigned) scanCache.set(lowerImage, true)
        }

        let modules = []
        try { modules = winapi.getProcessModules(pid, conf.modulesBufferBytes) } catch { modules = null }
        if (!modules) moduleScanFailed = true
        const modArr = Array.isArray(modules) ? modules : []
        unsignedDlls = []
        for (let j = 0; j < modArr.length; j++) {
          const p = typeof modArr[j] === 'string' ? modArr[j] : ''
          if (!p) continue
          const lower = normalizeLowerPath(p)
          if (!lower.endsWith('.dll')) continue
          if (conf.skipSystemDll && lower.startsWith(normalizeDirLower(systemRootLower))) continue
          if (isAllowlisted(lower, allowFiles)) continue
          if (shouldSkipInterception(lower, systemRootLower, appDirLower, exclusions)) continue
          if (scanCache.get(lower) === true) continue
          let ok = false
          try { ok = winapi.verifyTrust(p) === true } catch { ok = false }
          if (ok) scanCache.set(lower, true)
          else {
            unsignedDlls.push(p)
            if (unsignedDlls.length >= conf.maxUnsignedDllsPerProcess) break
          }
        }
      } catch {}

      const hasProcIssue = processSigned !== true
      const hasDllIssue = moduleScanFailed || unsignedDlls.length > 0
      if (hasProcIssue && hasDllIssue) scanType = 'joint'
      else if (hasDllIssue) scanType = 'dll'
      else if (hasProcIssue) scanType = 'process'

      if (!(hasProcIssue || hasDllIssue)) {
        if (t.suspended) {
          try { winapi.resumeProcessByPid(pid) } catch {}
        }
      } else {
        postMessage({ type: 'paused', pid, imagePath, paused: t.suspended === true, unsignedDlls, processSigned, scanType, moduleScanFailed })
      }
      if (i % 30 === 0) await sleepImmediate()
    }
  } finally {
    scanInFlight = false
    postMessage({ type: 'scan_done' })
  }
}

/**
 * - 函数: `resumeMany`
 * - Function: `resumeMany`
 * - 作用: 批量恢复被挂起的进程，并把恢复结果按请求 ID 回传主线程。
 * - Purpose: Resumes suspended processes in batches and sends the aggregated result back to the main thread with the request ID.
 * - 调用方: 主线程通过 `type: 'resume_many'` 消息触发，通常用于处理完 `paused` 事件后的恢复链路。
 * - Callers: Triggered by the main thread through the `type: 'resume_many'` message, usually after handling `paused` events.
 * - 被调方: `postMessage`、`sleepImmediate`、`Array.isArray`、`Array.prototype.map`、`Array.prototype.filter`、`Number.isFinite`、`parseInt`、`winapi.resumeProcessByPid`。
 * - Callees: `postMessage`, `sleepImmediate`, `Array.isArray`, `Array.prototype.map`, `Array.prototype.filter`, `Number.isFinite`, `parseInt`, and `winapi.resumeProcessByPid`.
 * - 变量说明: `requestId` 为主线程请求标识；`pids` 为待恢复 PID 列表；`rid` 为规范化请求 ID；`ids` 为过滤后的有效 PID 数组；`resumed` 为实际恢复成功的数量。
 * - Variables: `requestId` is the main-thread request identifier; `pids` is the PID list to resume; `rid` is the normalized request ID; `ids` is the filtered valid PID array; `resumed` is the number of successful resumes.
 * - 接入方式: 主线程发送 `resume_many` 消息并等待 `resume_many_done` 回执，用于批量释放先前挂起的进程。
 * - Integration: Send a `resume_many` message from the main thread and wait for the `resume_many_done` acknowledgment when releasing previously suspended processes in bulk.
 * - 错误处理: 缺少 `requestId` 时直接忽略；无 `winapi` 能力时回传 `NO_WINAPI`；单个 PID 恢复失败仅影响该项，不阻断批次。
 * - Error Handling: Ignores requests without `requestId`, reports `NO_WINAPI` when resume capability is missing, and isolates failures to individual PIDs without breaking the batch.
 * - 关键词: 批量恢复进程 | batch process resume | 挂起解除 | suspension release | 请求ID回执 | request id acknowledgment | Worker恢复链路 | worker resume flow | 部分失败容忍 | partial failure tolerance
 */
async function resumeMany(requestId, pids) {
  const rid = typeof requestId === 'string' ? requestId : ''
  const list = Array.isArray(pids) ? pids : []
  const ids = list.map(x => (Number.isFinite(x) ? x : parseInt(String(x), 10))).filter(x => Number.isFinite(x) && x > 0)
  if (!rid) return
  if (!winapi || typeof winapi.resumeProcessByPid !== 'function') {
    postMessage({ type: 'resume_many_done', requestId: rid, ok: false, error: 'NO_WINAPI' })
    return
  }
  let resumed = 0
  for (let i = 0; i < ids.length; i++) {
    const pid = ids[i]
    try {
      const ok = winapi.resumeProcessByPid(pid) === true
      if (ok) resumed++
    } catch {}
    if (i % 50 === 0) await sleepImmediate()
  }
  postMessage({ type: 'resume_many_done', requestId: rid, ok: true, total: ids.length, resumed })
}

/**
 * - 函数: `pidSnapshot`
 * - Function: `pidSnapshot`
 * - 作用: 获取一次轻量级 PID 映像快照，并以请求-响应形式回传给主线程用于 ETW 缓存预热。
 * - Purpose: Captures one lightweight PID image snapshot and returns it to the main thread in request-response form so the ETW cache can be warmed.
 * - 调用方: 主线程通过 `type: 'pid_snapshot'` 消息触发，调用点位于 `main.js` 的 ETW 快照补种链路。
 * - Callers: Triggered by the main thread through the `type: 'pid_snapshot'` message in the ETW snapshot-seeding flow inside `main.js`.
 * - 被调方: `postMessage`、`asInt`、`winapi.getProcessImageSnapshot`、`Array.isArray`。
 * - Callees: `postMessage`, `asInt`, `winapi.getProcessImageSnapshot`, and `Array.isArray`.
 * - 变量说明: `requestId` 为主线程请求标识；`maxPids` 为主线程建议的最大采样数；`rid` 为规范化请求 ID；`max` 为限幅后的快照上限；`arr` 为返回给主线程的快照数组。
 * - Variables: `requestId` is the main-thread request identifier; `maxPids` is the suggested maximum sample size; `rid` is the normalized request ID; `max` is the clamped snapshot limit; `arr` is the snapshot array returned to the main thread.
 * - 接入方式: 主线程发送 `pid_snapshot` 消息并监听 `pid_snapshot_done`，随后可将返回数组批量灌入 `etw_pid_cache`。
 * - Integration: Send a `pid_snapshot` message from the main thread, listen for `pid_snapshot_done`, and then bulk-feed the returned array into `etw_pid_cache`.
 * - 错误处理: 缺少 `requestId` 时直接忽略；缺失 `winapi` 快照能力时回传 `NO_WINAPI`；底层快照异常时回退为空数组但保持成功回执结构。
 * - Error Handling: Ignores requests without `requestId`, returns `NO_WINAPI` when snapshot capability is missing, and falls back to an empty array on snapshot failure while keeping the success-response shape.
 * - 关键词: PID快照采集 | PID snapshot capture | ETW缓存预热 | ETW cache warmup | 主线程请求响应 | main thread request-response | 轻量进程枚举 | lightweight process enumeration | 批量补种 | batch seeding
 */
async function pidSnapshot(requestId, maxPids) {
  const rid = typeof requestId === 'string' ? requestId : ''
  if (!rid) return
  if (!winapi || typeof winapi.getProcessImageSnapshot !== 'function') {
    postMessage({ type: 'pid_snapshot_done', requestId: rid, ok: false, error: 'NO_WINAPI' })
    return
  }
  const max = asInt(maxPids, 8192, 256, 65536)
  let list = []
  try { list = winapi.getProcessImageSnapshot(max) } catch { list = [] }
  const arr = Array.isArray(list) ? list : []
  postMessage({ type: 'pid_snapshot_done', requestId: rid, ok: true, list: arr })
}

if (parentPort) {
  parentPort.on('message', (msg) => {
    const m = msg && typeof msg === 'object' ? msg : null
    const typ = m && typeof m.type === 'string' ? m.type : ''
    if (typ === 'scan') {
      scanSnapshot(m.config).catch(() => {})
      return
    }
    if (typ === 'resume_many') {
      resumeMany(m.requestId, m.pids).catch(() => postMessage({ type: 'resume_many_done', requestId: m && m.requestId ? String(m.requestId) : '', ok: false }))
      return
    }
    if (typ === 'pid_snapshot') {
      pidSnapshot(m.requestId, m.maxPids).catch(() => postMessage({ type: 'pid_snapshot_done', requestId: m && m.requestId ? String(m.requestId) : '', ok: false }))
      return
    }
    if (typ === 'allow_dlls') {
      const list = Array.isArray(m.paths) ? m.paths : []
      for (const p of list) {
        if (typeof p === 'string' && p) {
          scanCache.set(p.toLowerCase(), true)
        }
      }
    }
  })
}
