(function (root) {
  /**
 * - 函数: `getScanProgressBarState`
 * - Function: `getScanProgressBarState`
 * - 作用: 读取并汇总扫描进度barstate，返回当前流程消费的快照或配置结果。
 * - Purpose: Reads and aggregates the scan progress bar state into a snapshot or config result for the current flow.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `Math.max`、`Math.min`、`Math.floor`。
 * - Callees: `Math.max`, `Math.min`, `Math.floor`.
 * - 变量说明: `session` 为当前流程传入的session；`scanning` 为当前流程传入的scanning；`s`, `isFull` 为函数内部派生的中间状态。
 * - Variables: `session` is the incoming session for this flow; `scanning` is the incoming scanning for this flow; `s`, `isFull` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./scan_progress').getScanProgressBarState` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./scan_progress').getScanProgressBarState`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 获取 | 扫描 | 进度 | bar | state | get | scan | progress | bar | state
 */
  function getScanProgressBarState(session, scanning) {
    const s = session || {}
    const isFull = s.mode === 'full'
    const isStopping = !!(s.stopRequested || s.aborted)
    const isIndeterminate = !!(scanning && !isStopping && (s.realtime || isFull))
    if (isIndeterminate) {
      return { indeterminate: true, width: '100%', text: '' }
    }
    const scanned = (s.scannedCount || 0)
    const total = (s.totalCount > 0) ? s.totalCount : Math.max(1, scanned)
    const percent = Math.max(0, Math.min(100, Math.floor(((s.scannedCount || 0) / total) * 100)))
    return { indeterminate: false, width: percent + '%', text: percent + '%' }
  }

  /**
 * - 函数: `createScanQueue`
 * - Function: `createScanQueue`
 * - 作用: 创建扫描队列实例或结构，并初始化后续流程依赖的基础状态。
 * - Purpose: Creates the scan queue instance or structure and initializes the baseline state required by later steps.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `push`、`remaining`、`compactIfNeeded`、`next`、`pushMany`、`Number.isFinite`。
 * - Callees: `push`, `remaining`, `compactIfNeeded`, `next`, `pushMany`, `Number.isFinite`.
 * - 变量说明: `initial` 为当前流程传入的initial；`options` 为当前流程传入的options；`opts`, `compactionThreshold` 为函数内部派生的中间状态。
 * - Variables: `initial` is the incoming initial for this flow; `options` is the incoming options for this flow; `opts`, `compactionThreshold` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./scan_progress').createScanQueue` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./scan_progress').createScanQueue`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 创建 | 扫描 | 队列 | create | scan | queue | call chain | 错误处理 | error handling | 复用
 */
  function createScanQueue(initial, options) {
    const opts = options && typeof options === 'object' ? options : {}
    const compactionThreshold = Number.isFinite(opts.compactionThreshold) ? Math.max(1, opts.compactionThreshold) : 5000
    const arr = []
    if (Array.isArray(initial)) {
      for (const v of initial) {
        if (v) arr.push(v)
      }
    }
    let idx = 0

    /**
 * - 函数: `remaining`
 * - Function: `remaining`
 * - 作用: 梳理并返回remaining负责的remaining局部处理结果。
 * - Purpose: Coordinates and returns the remaining processing result handled by remaining.
 * - 调用方: `createScanQueue`。
 * - Callers: `createScanQueue`.
 * - 被调方: `Math.max`。
 * - Callees: `Math.max`.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `remaining`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `remaining` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: remaining | remaining | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
    function remaining() {
      return Math.max(0, arr.length - idx)
    }

    /**
 * - 函数: `compactIfNeeded`
 * - Function: `compactIfNeeded`
 * - 作用: 梳理并返回compactIfNeeded负责的ifneeded局部处理结果。
 * - Purpose: Coordinates and returns the if needed processing result handled by compactIfNeeded.
 * - 调用方: `createScanQueue`、`next`。
 * - Callers: `createScanQueue`, `next`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `compactIfNeeded`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `compactIfNeeded` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: compact | if | needed | compact | if | needed | call chain | 错误处理 | error handling | 复用
 */
    function compactIfNeeded() {
      if (idx <= 0) return
      if (idx < compactionThreshold) return
      arr.splice(0, idx)
      idx = 0
    }

    /**
 * - 函数: `next`
 * - Function: `next`
 * - 作用: 梳理并返回next负责的next局部处理结果。
 * - Purpose: Coordinates and returns the next processing result handled by next.
 * - 调用方: `createScanQueue`。
 * - Callers: `createScanQueue`.
 * - 被调方: `compactIfNeeded`。
 * - Callees: `compactIfNeeded`.
 * - 变量说明: 无显式入参；`v` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `v` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `next`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `next` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: next | next | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
    function next() {
      if (idx >= arr.length) return null
      const v = arr[idx++]
      compactIfNeeded()
      return v
    }

    /**
 * - 函数: `push`
 * - Function: `push`
 * - 作用: 梳理并返回push负责的push局部处理结果。
 * - Purpose: Coordinates and returns the push processing result handled by push.
 * - 调用方: `createScanQueue`、`pushMany`。
 * - Callers: `createScanQueue`, `pushMany`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `v` 为当前流程传入的v。
 * - Variables: `v` is the incoming v for this flow.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `push`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `push` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: push | push | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
    function push(v) {
      if (v) arr.push(v)
    }

    /**
 * - 函数: `pushMany`
 * - Function: `pushMany`
 * - 作用: 梳理并返回pushMany负责的many局部处理结果。
 * - Purpose: Coordinates and returns the many processing result handled by pushMany.
 * - 调用方: `createScanQueue`。
 * - Callers: `createScanQueue`.
 * - 被调方: `push`、`Array.isArray`。
 * - Callees: `push`, `Array.isArray`.
 * - 变量说明: `list` 为当前流程传入的列出；`v` 为函数内部派生的中间状态。
 * - Variables: `list` is the incoming list for this flow; `v` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `pushMany`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `pushMany` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: push | many | push | many | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
    function pushMany(list) {
      if (!Array.isArray(list) || list.length === 0) return
      for (const v of list) {
        if (v) arr.push(v)
      }
    }

    return { next, push, pushMany, remaining }
  }

  /**
 * - 函数: `getFileExtLower`
 * - Function: `getFileExtLower`
 * - 作用: 读取并汇总文件extlower，返回当前流程消费的快照或配置结果。
 * - Purpose: Reads and aggregates the file ext lower into a snapshot or config result for the current flow.
 * - 调用方: `模块顶层流程`、`isCommonExtensionFile`。
 * - Callers: `模块顶层流程`, `isCommonExtensionFile`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `p` 为当前流程传入的p；`s`, `name` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `s`, `name` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `getFileExtLower`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `getFileExtLower` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 获取 | 文件 | ext | lower | get | file | ext | lower | error handling | 复用
 */
  function getFileExtLower(p) {
    const s = (typeof p === 'string') ? p.trim() : ''
    if (!s) return ''
    const name = s.replace(/^.*[\\/]/, '')
    const i = name.lastIndexOf('.')
    if (i <= 0 || i === name.length - 1) return ''
    return name.slice(i + 1).toLowerCase()
  }

  /**
 * - 函数: `isCommonExtensionFile`
 * - Function: `isCommonExtensionFile`
 * - 作用: 判断commonextension文件条件是否成立，并返回布尔化结果供上游守卫分支使用。
 * - Purpose: Checks whether the common extension file condition is satisfied and returns a boolean-style result for upstream guards.
 * - 调用方: `shouldScanFileByConfig`。
 * - Callers: `shouldScanFileByConfig`.
 * - 被调方: `getFileExtLower`。
 * - Callees: `getFileExtLower`.
 * - 变量说明: `p` 为当前流程传入的p；`ext` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `ext` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./scan_progress').isCommonExtensionFile` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./scan_progress').isCommonExtensionFile`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 判断 | common | extension | 文件 | check | common | extension | file | error handling | 复用
 */
  function isCommonExtensionFile(p) {
    const ext = getFileExtLower(p)
    return ext === 'exe' || ext === 'dll'
  }

  /**
 * - 函数: `shouldScanFileByConfig`
 * - Function: `shouldScanFileByConfig`
 * - 作用: 判断当前场景是否应该进入扫描文件by配置分支，并返回策略判定结果。
 * - Purpose: Determines whether the current scenario should enter the scan file by config branch and returns the policy decision.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `isCommonExtensionFile`。
 * - Callees: `isCommonExtensionFile`.
 * - 变量说明: `filePath` 为当前流程传入的文件路径；`cfg` 为当前流程传入的cfg；`onlyCommon` 为函数内部派生的中间状态。
 * - Variables: `filePath` is the incoming file path for this flow; `cfg` is the incoming cfg for this flow; `onlyCommon` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./scan_progress').shouldScanFileByConfig` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./scan_progress').shouldScanFileByConfig`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 判断 | 扫描 | 文件 | by | 配置 | check | scan | file | by | config
 */
  function shouldScanFileByConfig(filePath, cfg) {
    const onlyCommon = !!(cfg && cfg.scan && cfg.scan.commonExtensionsOnly)
    if (!onlyCommon) return true
    return isCommonExtensionFile(filePath)
  }

  root.getScanProgressBarState = getScanProgressBarState
  root.createScanQueue = createScanQueue
  root.isCommonExtensionFile = isCommonExtensionFile
  root.shouldScanFileByConfig = shouldScanFileByConfig
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { getScanProgressBarState, createScanQueue, isCommonExtensionFile, shouldScanFileByConfig }
  }
})(typeof window !== 'undefined' ? window : globalThis)
