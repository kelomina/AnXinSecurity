const fs = require('fs')
const { sanitizeText, isCleanText } = require('./utils')

/**
 * - 函数: `asPid`
 * - Function: `asPid`
 * - 作用: 梳理并返回asPid负责的pid局部处理结果。
 * - Purpose: Coordinates and returns the pid processing result handled by asPid.
 * - 调用方: `模块顶层流程`、`setBaselineTrustedPids`、`addTrustedPid`、`seedFromSnapshot`、`onProcessStart`、`onProcessStop`。
 * - Callers: `模块顶层流程`, `setBaselineTrustedPids`, `addTrustedPid`, `seedFromSnapshot`, `onProcessStart`, `onProcessStop`.
 * - 被调方: `Number.isFinite`。
 * - Callees: `Number.isFinite`.
 * - 变量说明: `v` 为当前流程传入的v；`n` 为函数内部派生的中间状态。
 * - Variables: `v` is the incoming v for this flow; `n` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `asPid`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `asPid` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: as | pid | as | pid | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function asPid(v) {
  const n = typeof v === 'number' ? v : parseInt(String(v), 10)
  if (!Number.isFinite(n) || n < 0) return null
  return n
}

/**
 * - 函数: `createEtwTrustedPidFilter`
 * - Function: `createEtwTrustedPidFilter`
 * - 作用: 创建etw受信任状态pid过滤实例或结构，并初始化后续流程依赖的基础状态。
 * - Purpose: Creates the etw trusted state pid filter instance or structure and initializes the baseline state required by later steps.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `deps` 为当前流程传入的deps。
 * - Variables: `deps` is the incoming deps for this flow.
 * - 接入方式: 可通过 `require('./etw_trusted_pid_filter').createEtwTrustedPidFilter` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./etw_trusted_pid_filter').createEtwTrustedPidFilter`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 创建 | etw | 受信任状态 | pid | 过滤 | create | etw | trusted state | pid | filter
 */
function createEtwTrustedPidFilter(deps = {}) {
  const verifyTrust = typeof deps.verifyTrust === 'function' ? deps.verifyTrust : null
  const devicePathToDosPath = typeof deps.devicePathToDosPath === 'function' ? deps.devicePathToDosPath : null

  const trusted = new Set()
  const baselineTrustedPids = new Set()
  const userTrustedExactPaths = new Set()
  const userTrustedDirPrefixes = new Set()
  let enabled = true
  let applyToSnapshot = true
  let applyToNewProcesses = true
  let maxVerifyPids = 0
  let trustedSkipProviders = null

  /**
 * - 函数: `normalizeProviderName`
 * - Function: `normalizeProviderName`
 * - 作用: 标准化provider名称输入，统一为当前模块后续逻辑可直接消费的结构。
 * - Purpose: Normalizes the provider name input into a structure that downstream logic can consume directly.
 * - 调用方: `模块顶层流程`、`setTrustedSkipProviders`、`shouldSkipEvent`。
 * - Callers: `模块顶层流程`, `setTrustedSkipProviders`, `shouldSkipEvent`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `p` 为当前流程传入的p。
 * - Variables: `p` is the incoming p for this flow.
 * - 接入方式: 在当前模块内部直接调用 `normalizeProviderName(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `normalizeProviderName(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 标准化 | provider | 名称 | normalize | provider | name | call chain | 错误处理 | error handling | 复用
 */
  function normalizeProviderName(p) {
    if (typeof p !== 'string' || !p) return ''
    return p.trim().toLowerCase()
  }

  /**
 * - 函数: `setTrustedSkipProviders`
 * - Function: `setTrustedSkipProviders`
 * - 作用: 设置受信任状态skipproviders状态，并同步影响当前模块内的后续判断。
 * - Purpose: Sets the trusted state skip providers state and synchronizes the downstream decisions made inside this module.
 * - 调用方: `模块顶层流程`、`configure`。
 * - Callers: `模块顶层流程`, `configure`.
 * - 被调方: `normalizeProviderName`、`Array.isArray`。
 * - Callees: `normalizeProviderName`, `Array.isArray`.
 * - 变量说明: `list` 为当前流程传入的列出；`set`, `it` 为函数内部派生的中间状态。
 * - Variables: `list` is the incoming list for this flow; `set`, `it` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `setTrustedSkipProviders(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `setTrustedSkipProviders(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 设置 | 受信任状态 | skip | providers | set | trusted state | skip | providers | error handling | 复用
 */
  function setTrustedSkipProviders(list) {
    if (!Array.isArray(list)) {
      trustedSkipProviders = null
      return
    }
    const set = new Set()
    for (const it of list) {
      const n = normalizeProviderName(String(it))
      if (n) set.add(n)
    }
    trustedSkipProviders = set
  }

  /**
 * - 函数: `setBaselineTrustedPids`
 * - Function: `setBaselineTrustedPids`
 * - 作用: 设置baseline受信任状态pids状态，并同步影响当前模块内的后续判断。
 * - Purpose: Sets the baseline trusted state pids state and synchronizes the downstream decisions made inside this module.
 * - 调用方: `模块顶层流程`、`configure`。
 * - Callers: `模块顶层流程`, `configure`.
 * - 被调方: `asPid`、`Array.isArray`。
 * - Callees: `asPid`, `Array.isArray`.
 * - 变量说明: `list` 为当前流程传入的列出；`arr`, `it` 为函数内部派生的中间状态。
 * - Variables: `list` is the incoming list for this flow; `arr`, `it` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `setBaselineTrustedPids(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `setBaselineTrustedPids(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 设置 | baseline | 受信任状态 | pids | set | baseline | trusted state | pids | error handling | 复用
 */
  function setBaselineTrustedPids(list) {
    baselineTrustedPids.clear()
    const arr = Array.isArray(list) ? list : []
    for (const it of arr) {
      const p = asPid(it)
      if (p == null) continue
      baselineTrustedPids.add(p)
    }
  }

  /**
 * - 函数: `configure`
 * - Function: `configure`
 * - 作用: 梳理并返回configure负责的configure局部处理结果。
 * - Purpose: Coordinates and returns the configure processing result handled by configure.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `setBaselineTrustedPids`、`setTrustedSkipProviders`、`Number.isFinite`、`Math.max`、`Math.floor`、`Array.isArray`。
 * - Callees: `setBaselineTrustedPids`, `setTrustedSkipProviders`, `Number.isFinite`, `Math.max`, `Math.floor`, `Array.isArray`.
 * - 变量说明: `cfg` 为当前流程传入的cfg；`c` 为函数内部派生的中间状态。
 * - Variables: `cfg` is the incoming cfg for this flow; `c` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `configure`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `configure` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: configure | configure | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function configure(cfg) {
    const c = cfg && typeof cfg === 'object' ? cfg : {}
    enabled = c.enabled !== false
    applyToSnapshot = c.applyToSnapshot !== false
    applyToNewProcesses = c.applyToNewProcesses !== false
    maxVerifyPids = Number.isFinite(c.maxVerifyPids) ? Math.max(0, Math.floor(c.maxVerifyPids)) : 0
    if (Array.isArray(c.baseTrustedPids)) setBaselineTrustedPids(c.baseTrustedPids)
    setTrustedSkipProviders(c.skipProviders)
  }

  /**
 * - 函数: `normalizePathForTrust`
 * - Function: `normalizePathForTrust`
 * - 作用: 标准化路径for信任输入，统一为当前模块后续逻辑可直接消费的结构。
 * - Purpose: Normalizes the path for trust input into a structure that downstream logic can consume directly.
 * - 调用方: `模块顶层流程`、`isTrustedImage`、`addUserTrustedPath`。
 * - Callers: `模块顶层流程`, `isTrustedImage`, `addUserTrustedPath`.
 * - 被调方: `sanitizeText`、`isCleanText`。
 * - Callees: `sanitizeText`, `isCleanText`.
 * - 变量说明: `p` 为当前流程传入的p；`s` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `s` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `normalizePathForTrust(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `normalizePathForTrust(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 标准化 | 路径 | for | 信任 | normalize | path | for | trust | error handling | 复用
 */
  function normalizePathForTrust(p) {
    if (typeof p !== 'string' || !p) return ''
    let s = sanitizeText(p)
    if (!s) return ''
    if (!isCleanText(s)) return ''
    if (devicePathToDosPath) {
      try { s = devicePathToDosPath(s) || s } catch {}
    }
    return s.replace(/\//g, '\\').toLowerCase()
  }

  /**
 * - 函数: `isTrustedImage`
 * - Function: `isTrustedImage`
 * - 作用: 判断受信任状态image条件是否成立，并返回布尔化结果供上游守卫分支使用。
 * - Purpose: Checks whether the trusted state image condition is satisfied and returns a boolean-style result for upstream guards.
 * - 调用方: `模块顶层流程`、`seedFromSnapshot`、`onProcessStart`。
 * - Callers: `模块顶层流程`, `seedFromSnapshot`, `onProcessStart`.
 * - 被调方: `normalizePathForTrust`。
 * - Callees: `normalizePathForTrust`.
 * - 变量说明: `imagePath` 为当前流程传入的image路径；`p`, `d` 为函数内部派生的中间状态。
 * - Variables: `imagePath` is the incoming image path for this flow; `p`, `d` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `isTrustedImage(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `isTrustedImage(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 判断 | 受信任状态 | image | check | trusted state | image | call chain | 错误处理 | error handling | 复用
 */
  function isTrustedImage(imagePath) {
    if (!enabled) return false
    
    const p = normalizePathForTrust(imagePath)
    if (!p) return false
    
    if (userTrustedExactPaths.has(p)) return true
    for (const d of userTrustedDirPrefixes) {
      if (p === d) return true
      if (p.startsWith(d + '\\')) return true
    }

    if (!verifyTrust) return false
    try { return verifyTrust(p) === true } catch { return false }
  }

  /**
 * - 函数: `addUserTrustedPath`
 * - Function: `addUserTrustedPath`
 * - 作用: 梳理并返回addUserTrustedPath负责的用户受信任状态路径局部处理结果。
 * - Purpose: Coordinates and returns the user trusted state path processing result handled by addUserTrustedPath.
 * - 调用方: `模块顶层流程`、`setUserTrustedPaths`。
 * - Callers: `模块顶层流程`, `setUserTrustedPaths`.
 * - 被调方: `normalizePathForTrust`、`isDirectory`、`fs.statSync`。
 * - Callees: `normalizePathForTrust`, `isDirectory`, `fs.statSync`.
 * - 变量说明: `p` 为当前流程传入的p；`s`, `raw` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `s`, `raw` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `addUserTrustedPath`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `addUserTrustedPath` through the existing returned object.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: add | 用户 | 受信任状态 | 路径 | add | user | trusted state | path | error handling | 复用
 */
  function addUserTrustedPath(p) {
    const s = normalizePathForTrust(p)
    if (!s) return
    const raw = (typeof p === 'string') ? p.trim() : ''
    const hasTrailingSep = /[\\/]+$/.test(raw)
    let isDir = hasTrailingSep
    if (!isDir) {
      try {
        const st = fs.statSync(s)
        if (st && st.isDirectory && st.isDirectory()) isDir = true
      } catch {}
    }
    if (isDir) {
      const dir = s.replace(/[\\]+$/g, '')
      if (dir) userTrustedDirPrefixes.add(dir)
      return
    }
    userTrustedExactPaths.add(s)
  }

  /**
 * - 函数: `setUserTrustedPaths`
 * - Function: `setUserTrustedPaths`
 * - 作用: 设置用户受信任状态路径集合状态，并同步影响当前模块内的后续判断。
 * - Purpose: Sets the user trusted state path list state and synchronizes the downstream decisions made inside this module.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `addUserTrustedPath`、`Array.isArray`。
 * - Callees: `addUserTrustedPath`, `Array.isArray`.
 * - 变量说明: `list` 为当前流程传入的列出；`arr`, `p` 为函数内部派生的中间状态。
 * - Variables: `list` is the incoming list for this flow; `arr`, `p` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `setUserTrustedPaths`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `setUserTrustedPaths` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 设置 | 用户 | 受信任状态 | 路径集合 | set | user | trusted state | path list | error handling | 复用
 */
  function setUserTrustedPaths(list) {
    userTrustedExactPaths.clear()
    userTrustedDirPrefixes.clear()
    const arr = Array.isArray(list) ? list : []
    for (const p of arr) addUserTrustedPath(p)
  }

  /**
 * - 函数: `addTrustedPid`
 * - Function: `addTrustedPid`
 * - 作用: 梳理并返回addTrustedPid负责的受信任状态pid局部处理结果。
 * - Purpose: Coordinates and returns the trusted state pid processing result handled by addTrustedPid.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `asPid`。
 * - Callees: `asPid`.
 * - 变量说明: `pid` 为当前流程传入的pid；`p` 为函数内部派生的中间状态。
 * - Variables: `pid` is the incoming pid for this flow; `p` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `addTrustedPid`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `addTrustedPid` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: add | 受信任状态 | pid | add | trusted state | pid | call chain | 错误处理 | error handling | 复用
 */
  function addTrustedPid(pid) {
    const p = asPid(pid)
    if (p != null) trusted.add(p)
  }

  /**
 * - 函数: `seedFromSnapshot`
 * - Function: `seedFromSnapshot`
 * - 作用: 梳理并返回seedFromSnapshot负责的from快照局部处理结果。
 * - Purpose: Coordinates and returns the from snapshot processing result handled by seedFromSnapshot.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `asPid`、`isTrustedImage`、`Array.isArray`、`Math.min`。
 * - Callees: `asPid`, `isTrustedImage`, `Array.isArray`, `Math.min`.
 * - 变量说明: `list` 为当前流程传入的列出；`arr`, `lim` 为函数内部派生的中间状态。
 * - Variables: `list` is the incoming list for this flow; `arr`, `lim` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `seedFromSnapshot`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `seedFromSnapshot` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: seed | from | 快照 | seed | from | snapshot | call chain | 错误处理 | error handling | 复用
 */
  function seedFromSnapshot(list) {
    if (!enabled || !applyToSnapshot) return
    trusted.clear()
    const arr = Array.isArray(list) ? list : []
    const lim = maxVerifyPids > 0 ? Math.min(arr.length, maxVerifyPids) : arr.length
    for (let i = 0; i < lim; i++) {
      const it = arr[i]
      if (!it || typeof it !== 'object') continue
      const pid = asPid(it.pid)
      if (pid == null) continue
      const img = typeof it.imagePath === 'string' ? it.imagePath : ''
      if (isTrustedImage(img)) trusted.add(pid)
    }
  }

  /**
 * - 函数: `onProcessStart`
 * - Function: `onProcessStart`
 * - 作用: 梳理并返回onProcessStart负责的处理start局部处理结果。
 * - Purpose: Coordinates and returns the process start processing result handled by onProcessStart.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `asPid`、`isTrustedImage`。
 * - Callees: `asPid`, `isTrustedImage`.
 * - 变量说明: `pid` 为当前流程传入的pid；`imagePath` 为当前流程传入的image路径；`p` 为函数内部派生的中间状态。
 * - Variables: `pid` is the incoming pid for this flow; `imagePath` is the incoming image path for this flow; `p` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `onProcessStart`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `onProcessStart` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: on | 处理 | start | on | process | start | call chain | 错误处理 | error handling | 复用
 */
  function onProcessStart(pid, imagePath) {
    if (!enabled || !applyToNewProcesses) return false
    const p = asPid(pid)
    if (p == null) return false
    trusted.delete(p)
    if (baselineTrustedPids.has(p)) return true
    if (!isTrustedImage(imagePath)) return false
    trusted.add(p)
    return true
  }

  /**
 * - 函数: `onProcessStop`
 * - Function: `onProcessStop`
 * - 作用: 梳理并返回onProcessStop负责的处理stop局部处理结果。
 * - Purpose: Coordinates and returns the process stop processing result handled by onProcessStop.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `asPid`。
 * - Callees: `asPid`.
 * - 变量说明: `pid` 为当前流程传入的pid；`p` 为函数内部派生的中间状态。
 * - Variables: `pid` is the incoming pid for this flow; `p` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `onProcessStop`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `onProcessStop` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: on | 处理 | stop | on | process | stop | call chain | 错误处理 | error handling | 复用
 */
  function onProcessStop(pid) {
    const p = asPid(pid)
    if (p == null) return
    if (baselineTrustedPids.has(p)) return
    trusted.delete(p)
  }

  /**
 * - 函数: `getRelevantPidForEvent`
 * - Function: `getRelevantPidForEvent`
 * - 作用: 读取并汇总relevantpidfor事件，返回当前流程消费的快照或配置结果。
 * - Purpose: Reads and aggregates the relevant pid for event into a snapshot or config result for the current flow.
 * - 调用方: `模块顶层流程`、`shouldSkipEvent`。
 * - Callers: `模块顶层流程`, `shouldSkipEvent`.
 * - 被调方: `asPid`。
 * - Callees: `asPid`.
 * - 变量说明: `ev` 为当前流程传入的ev；`e`, `provider` 为函数内部派生的中间状态。
 * - Variables: `ev` is the incoming ev for this flow; `e`, `provider` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `getRelevantPidForEvent(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `getRelevantPidForEvent(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 获取 | relevant | pid | for | 事件 | get | relevant | pid | for | event
 */
  function getRelevantPidForEvent(ev) {
    const e = ev && typeof ev === 'object' ? ev : null
    if (!e) return null
    const provider = typeof e.provider === 'string' ? e.provider : ''
    const data = e.data && typeof e.data === 'object' ? e.data : null
    if (provider === 'Process' && data) {
      const typ = typeof data.type === 'string' ? data.type : ''
      if (typ === 'Start' || typ === 'Stop') {
        const subjectPid = asPid(data.processId)
        if (subjectPid != null) return subjectPid
      }
    }
    return asPid(e.pid)
  }

  /**
 * - 函数: `shouldSkipEvent`
 * - Function: `shouldSkipEvent`
 * - 作用: 判断当前场景是否应该进入skip事件分支，并返回策略判定结果。
 * - Purpose: Determines whether the current scenario should enter the skip event branch and returns the policy decision.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `getRelevantPidForEvent`、`normalizeProviderName`。
 * - Callees: `getRelevantPidForEvent`, `normalizeProviderName`.
 * - 变量说明: `ev` 为当前流程传入的ev；`pid`, `provider` 为函数内部派生的中间状态。
 * - Variables: `ev` is the incoming ev for this flow; `pid`, `provider` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `shouldSkipEvent`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `shouldSkipEvent` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 判断 | skip | 事件 | check | skip | event | call chain | 错误处理 | error handling | 复用
 */
  function shouldSkipEvent(ev) {
    if (!enabled) return false
    const pid = getRelevantPidForEvent(ev)
    if (pid == null) return false
    if (baselineTrustedPids.has(pid)) return true
    if (!trusted.has(pid)) return false
    if (trustedSkipProviders == null) return true
    const provider = normalizeProviderName(ev && ev.provider)
    if (!provider) return true
    return trustedSkipProviders.has(provider)
  }

  return {
    configure,
    seedFromSnapshot,
    onProcessStart,
    onProcessStop,
    shouldSkipEvent,
    addUserTrustedPath,
    setUserTrustedPaths,
    addTrustedPid,
    isTrustedPid: (pid) => {
      const p = asPid(pid)
      if (p == null) return false
      if (baselineTrustedPids.has(p)) return true
      return trusted.has(p)
    },
    size: () => trusted.size + baselineTrustedPids.size
  }
}

module.exports = {
  createEtwTrustedPidFilter
}
