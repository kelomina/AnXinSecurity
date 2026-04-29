(function (root) {
  /**
 * - 函数: `defaultYield`
 * - Function: `defaultYield`
 * - 作用: 梳理并返回defaultYield负责的让出调度局部处理结果。
 * - Purpose: Coordinates and returns the yield processing result handled by defaultYield.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `defaultYield(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `defaultYield(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 默认 | 让出调度 | default | yield | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function defaultYield() {
    return new Promise((resolve) => requestAnimationFrame(() => resolve()))
  }

  /**
 * - 函数: `makeYieldFn`
 * - Function: `makeYieldFn`
 * - 作用: 梳理并返回makeYieldFn负责的让出调度fn局部处理结果。
 * - Purpose: Coordinates and returns the yield fn processing result handled by makeYieldFn.
 * - 调用方: `模块顶层流程`、`renderProcessSelectAsync`。
 * - Callers: `模块顶层流程`, `renderProcessSelectAsync`.
 * - 被调方: `Promise.resolve`。
 * - Callees: `Promise.resolve`.
 * - 变量说明: `yieldFn` 为当前流程传入的让出调度fn。
 * - Variables: `yieldFn` is the incoming yield fn for this flow.
 * - 接入方式: 在当前模块内部直接调用 `makeYieldFn(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `makeYieldFn(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: make | 让出调度 | fn | make | yield | fn | call chain | 错误处理 | error handling | 复用
 */
  function makeYieldFn(yieldFn) {
    if (typeof yieldFn === 'function') return yieldFn
    if (typeof requestAnimationFrame === 'function') return defaultYield
    return () => Promise.resolve()
  }

  /**
 * - 函数: `renderProcessSelectAsync`
 * - Function: `renderProcessSelectAsync`
 * - 作用: 梳理并返回renderProcessSelectAsync负责的处理selectasync局部处理结果。
 * - Purpose: Coordinates and returns the process select async processing result handled by renderProcessSelectAsync.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `makeYieldFn`、`t`、`getBaseName`、`Array.isArray`、`Number.isFinite`、`Math.max`。
 * - Callees: `makeYieldFn`, `t`, `getBaseName`, `Array.isArray`, `Number.isFinite`, `Math.max`.
 * - 变量说明: `opts` 为当前流程传入的opts；`o`, `sel` 为函数内部派生的中间状态。
 * - Variables: `opts` is the incoming opts for this flow; `o`, `sel` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./behavior_render').renderProcessSelectAsync` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./behavior_render').renderProcessSelectAsync`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: render | 处理 | select | async | render | process | select | async | error handling | 复用
 */
  async function renderProcessSelectAsync(opts) {
    const o = opts && typeof opts === 'object' ? opts : {}
    const sel = o.sel
    if (!sel) return
    const list = Array.isArray(o.list) ? o.list : []
    const t = typeof o.t === 'function' ? o.t : ((k) => k)
    const getBaseName = typeof o.getBaseName === 'function' ? o.getBaseName : (() => '')
    const batchSize = Number.isFinite(o.batchSize) ? Math.max(50, Math.min(2000, Math.floor(o.batchSize))) : 200
    const yieldFn = makeYieldFn(o.yieldFn)
    const shouldContinue = typeof o.shouldContinue === 'function' ? o.shouldContinue : (() => true)
    const onProgress = typeof o.onProgress === 'function' ? o.onProgress : null
    const onFirstBatch = typeof o.onFirstBatch === 'function' ? o.onFirstBatch : null
    const total = list.length >>> 0

    if (!shouldContinue()) return
    sel.innerHTML = ''
    const optAll = (sel.ownerDocument && sel.ownerDocument.createElement)
      ? sel.ownerDocument.createElement('option')
      : (typeof document !== 'undefined' && document.createElement ? document.createElement('option') : null)
    if (optAll) {
      optAll.value = ''
      optAll.textContent = t('behavior_all_processes')
      sel.appendChild(optAll)
    }

    for (let i = 0; i < list.length; i += batchSize) {
      if (!shouldContinue()) return
      const frag = (sel.ownerDocument && sel.ownerDocument.createDocumentFragment)
        ? sel.ownerDocument.createDocumentFragment()
        : (typeof document !== 'undefined' && document.createDocumentFragment ? document.createDocumentFragment() : null)
      const slice = list.slice(i, i + batchSize)
      for (const p of slice) {
        if (!shouldContinue()) return
        const pid = Number.isFinite(p && p.pid) ? p.pid : null
        if (pid == null) continue
        const image = typeof p.image === 'string' ? p.image : ''
        const name = (typeof p.name === 'string' && p.name) ? p.name : getBaseName(image)
        const opt = (sel.ownerDocument && sel.ownerDocument.createElement)
          ? sel.ownerDocument.createElement('option')
          : (typeof document !== 'undefined' && document.createElement ? document.createElement('option') : null)
        if (!opt) continue
        opt.value = String(pid)
        opt.textContent = name ? `${pid} - ${name}` : String(pid)
        if (frag && frag.appendChild) frag.appendChild(opt)
        else sel.appendChild(opt)
      }
      if (frag && frag.childNodes && frag.childNodes.length > 0) sel.appendChild(frag)
      if (onProgress) {
        const done = Math.min(total, i + slice.length)
        try { onProgress(total, done) } catch {}
      }
      if (i === 0 && onFirstBatch) {
        try { onFirstBatch() } catch {}
      }
      if (i + batchSize < list.length) {
        await yieldFn()
        if (!shouldContinue()) return
      }
    }
  }

  /**
 * - 函数: `asPid`
 * - Function: `asPid`
 * - 作用: 梳理并返回asPid负责的pid局部处理结果。
 * - Purpose: Coordinates and returns the pid processing result handled by asPid.
 * - 调用方: `模块顶层流程`、`processLabel`、`buildPidLifecycleTree`、`buildMitreMatrixModel`。
 * - Callers: `模块顶层流程`, `processLabel`, `buildPidLifecycleTree`, `buildMitreMatrixModel`.
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
 * - 函数: `baseName`
 * - Function: `baseName`
 * - 作用: 梳理并返回baseName负责的名称局部处理结果。
 * - Purpose: Coordinates and returns the name processing result handled by baseName.
 * - 调用方: `模块顶层流程`、`processLabel`。
 * - Callers: `模块顶层流程`, `processLabel`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `p` 为当前流程传入的p；`s`, `parts` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `s`, `parts` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `baseName(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `baseName(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: base | 名称 | base | name | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function baseName(p) {
    const s = typeof p === 'string' ? p.trim() : ''
    if (!s) return ''
    const parts = s.split(/[\\/]+/).filter(Boolean)
    return parts.length ? parts[parts.length - 1] : s
  }

  /**
 * - 函数: `processLabel`
 * - Function: `processLabel`
 * - 作用: 处理label相关任务，推进队列、状态或后续分发流程。
 * - Purpose: Processes the label task and advances the queue, state, or downstream dispatch flow.
 * - 调用方: `模块顶层流程`、`buildPidLifecycleTree`。
 * - Callers: `模块顶层流程`, `buildPidLifecycleTree`.
 * - 被调方: `asPid`、`baseName`。
 * - Callees: `asPid`, `baseName`.
 * - 变量说明: `p` 为当前流程传入的p；`pid`, `name` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `pid`, `name` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `processLabel`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `processLabel` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 处理 | label | process | label | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function processLabel(p) {
    const pid = asPid(p && p.pid)
    if (pid == null) return ''
    const name = (typeof p.name === 'string' && p.name.trim()) ? p.name.trim() : ''
    const image = (typeof p.image === 'string' && p.image.trim()) ? p.image.trim() : ''
    const label = name || (image ? baseName(image) : '')
    return label ? `${pid} - ${label}` : String(pid)
  }

  /**
 * - 函数: `eventTargetText`
 * - Function: `eventTargetText`
 * - 作用: 梳理并返回eventTargetText负责的target文本局部处理结果。
 * - Purpose: Coordinates and returns the target text processing result handled by eventTargetText.
 * - 调用方: `模块顶层流程`、`summarizeEvent`、`matchRule`。
 * - Callers: `模块顶层流程`, `summarizeEvent`, `matchRule`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `ev` 为当前流程传入的ev；`file`, `regKey` 为函数内部派生的中间状态。
 * - Variables: `ev` is the incoming ev for this flow; `file`, `regKey` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `eventTargetText`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `eventTargetText` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 事件 | target | 文本 | event | target | text | call chain | 错误处理 | error handling | 复用
 */
  function eventTargetText(ev) {
    const file = (typeof ev.file_path === 'string' && ev.file_path) ? ev.file_path : ''
    const regKey = (typeof ev.reg_key === 'string' && ev.reg_key) ? ev.reg_key : ''
    const regValue = (typeof ev.reg_value === 'string' && ev.reg_value) ? ev.reg_value : ''
    const base = file || regKey || ''
    if (!base) return ''
    return regValue ? `${base} :: ${regValue}` : base
  }

  /**
 * - 函数: `summarizeEvent`
 * - Function: `summarizeEvent`
 * - 作用: 梳理并返回summarizeEvent负责的事件局部处理结果。
 * - Purpose: Coordinates and returns the event processing result handled by summarizeEvent.
 * - 调用方: `buildOpGroups`、`buildMitreMatrixModel`。
 * - Callers: `buildOpGroups`, `buildMitreMatrixModel`.
 * - 被调方: `eventTargetText`、`push`、`Number.isFinite`。
 * - Callees: `eventTargetText`, `push`, `Number.isFinite`.
 * - 变量说明: `ev` 为当前流程传入的ev；`ts`, `provider` 为函数内部派生的中间状态。
 * - Variables: `ev` is the incoming ev for this flow; `ts`, `provider` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./behavior_render').summarizeEvent` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./behavior_render').summarizeEvent`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: summarize | 事件 | summarize | event | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function summarizeEvent(ev) {
    const ts = (typeof ev.ts === 'string' && ev.ts) ? ev.ts : ''
    const provider = (typeof ev.provider === 'string' && ev.provider) ? ev.provider : ''
    const op = (typeof ev.op === 'string' && ev.op) ? ev.op : ''
    const tid = Number.isFinite(ev && ev.tid) ? ev.tid : null
    const target = eventTargetText(ev)
    const tail = []
    if (tid != null) tail.push(`TID ${tid}`)
    if (target) tail.push(target)
    const hint = tail.length ? tail.join(' · ') : ''
    const left = [ts, provider, op].filter(Boolean).join(' · ')
    return { label: left || 'event', hint }
  }

  /**
 * - 函数: `groupBy`
 * - Function: `groupBy`
 * - 作用: 梳理并返回groupBy负责的by局部处理结果。
 * - Purpose: Coordinates and returns the by processing result handled by groupBy.
 * - 调用方: `模块顶层流程`、`buildOpGroups`、`buildPidLifecycleTree`。
 * - Callers: `模块顶层流程`, `buildOpGroups`, `buildPidLifecycleTree`.
 * - 被调方: `push`、`Array.isArray`。
 * - Callees: `push`, `Array.isArray`.
 * - 变量说明: `arr` 为当前流程传入的arr；`keyFn` 为当前流程传入的键fn；`m`, `v` 为函数内部派生的中间状态。
 * - Variables: `arr` is the incoming arr for this flow; `keyFn` is the incoming key fn for this flow; `m`, `v` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `groupBy`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `groupBy` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: group | by | group | by | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function groupBy(arr, keyFn) {
    const m = new Map()
    for (const v of Array.isArray(arr) ? arr : []) {
      const k = keyFn(v)
      const key = (k == null) ? '' : String(k)
      if (!m.has(key)) m.set(key, [])
      m.get(key).push(v)
    }
    return m
  }

  /**
 * - 函数: `buildPidLifecycleTree`
 * - Function: `buildPidLifecycleTree`
 * - 作用: 构建pidlifecycletree结构或配置，供后续计算、扫描或持久化流程使用。
 * - Purpose: Builds the pid lifecycle tree structure or configuration for later compute, scan, or persistence flows.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `asPid`、`processLabel`、`t`、`makeCategory`、`buildOpGroups`、`groupBy`。
 * - Callees: `asPid`, `processLabel`, `t`, `makeCategory`, `buildOpGroups`, `groupBy`.
 * - 变量说明: `opts` 为当前流程传入的opts；`o`, `pid` 为函数内部派生的中间状态。
 * - Variables: `opts` is the incoming opts for this flow; `o`, `pid` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./behavior_render').buildPidLifecycleTree` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./behavior_render').buildPidLifecycleTree`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 构建 | pid | lifecycle | tree | build | pid | lifecycle | tree | error handling | 复用
 */
  function buildPidLifecycleTree(opts) {
    const o = opts && typeof opts === 'object' ? opts : {}
    const pid = asPid(o.pid)
    const t = typeof o.t === 'function' ? o.t : ((k) => k)
    const process = (o.process && typeof o.process === 'object') ? o.process : null
    const rawEvents = Array.isArray(o.events) ? o.events : []
    const maxLeafPerOp = Number.isFinite(o.maxLeafPerOp) ? Math.max(20, Math.min(2000, Math.floor(o.maxLeafPerOp))) : 200

    const events = rawEvents.slice().sort((a, b) => {
      const ia = Number.isFinite(a && a.id) ? a.id : 0
      const ib = Number.isFinite(b && b.id) ? b.id : 0
      return ia - ib
    })

    const rootLabel = pid != null ? (process ? processLabel(Object.assign({ pid }, process)) : String(pid)) : t('unknown')
    const rootNode = { kind: 'pid', pid: pid != null ? pid : null, label: rootLabel, hint: '', count: events.length, children: [] }
    if (pid == null) return rootNode

    const processEvents = events.filter((ev) => (ev && ev.provider === 'Process' && (asPid(ev.actor_pid) === pid || asPid(ev.subject_pid) === pid)))
    const fileEvents = events.filter((ev) => (ev && ev.provider === 'File' && asPid(ev.actor_pid) === pid))
    const registryEvents = events.filter((ev) => (ev && ev.provider === 'Registry' && asPid(ev.actor_pid) === pid))
    const otherEvents = events.filter((ev) => (ev && ev.provider !== 'Process' && ev.provider !== 'File' && ev.provider !== 'Registry' && (asPid(ev.actor_pid) === pid || asPid(ev.subject_pid) === pid)))

    /**
 * - 函数: `makeCategory`
 * - Function: `makeCategory`
 * - 作用: 梳理并返回makeCategory负责的category局部处理结果。
 * - Purpose: Coordinates and returns the category processing result handled by makeCategory.
 * - 调用方: `buildPidLifecycleTree`。
 * - Callers: `buildPidLifecycleTree`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `label` 为当前流程传入的label；`evs` 为当前流程传入的evs；`childrenBuilder` 为当前流程传入的childrenbuilder；`node` 为函数内部派生的中间状态。
 * - Variables: `label` is the incoming label for this flow; `evs` is the incoming evs for this flow; `childrenBuilder` is the incoming children builder for this flow; `node` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `makeCategory`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `makeCategory` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: make | category | make | category | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
    const makeCategory = (label, evs, childrenBuilder) => {
      const node = { kind: 'category', label, hint: '', count: evs.length, children: [] }
      if (evs.length === 0) return node
      if (typeof childrenBuilder === 'function') {
        node.children = childrenBuilder(evs)
      }
      return node
    }

    /**
 * - 函数: `buildOpGroups`
 * - Function: `buildOpGroups`
 * - 作用: 构建opgroups结构或配置，供后续计算、扫描或持久化流程使用。
 * - Purpose: Builds the op groups structure or configuration for later compute, scan, or persistence flows.
 * - 调用方: `buildPidLifecycleTree`。
 * - Callers: `buildPidLifecycleTree`.
 * - 被调方: `groupBy`、`t`、`summarizeEvent`、`push`。
 * - Callees: `groupBy`, `t`, `summarizeEvent`, `push`.
 * - 变量说明: `evs` 为当前流程传入的evs；`groups`, `out` 为函数内部派生的中间状态。
 * - Variables: `evs` is the incoming evs for this flow; `groups`, `out` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `buildOpGroups`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `buildOpGroups` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 构建 | op | groups | build | op | groups | call chain | 错误处理 | error handling | 复用
 */
    const buildOpGroups = (evs) => {
      const groups = groupBy(evs, (ev) => (typeof ev.op === 'string' && ev.op) ? ev.op : t('unknown'))
      const out = []
      for (const [op, list] of groups.entries()) {
        const node = { kind: 'op', label: op, hint: '', count: list.length, children: [] }
        const head = list.slice(0, maxLeafPerOp)
        const tail = list.length > maxLeafPerOp ? list.slice(maxLeafPerOp) : []
        node.children = head.map((ev) => {
          const s = summarizeEvent(ev)
          return { kind: 'event', label: s.label, hint: s.hint, count: 1, children: [], raw: ev }
        })
        if (tail.length) node.more = tail.map((ev) => {
          const s = summarizeEvent(ev)
          return { kind: 'event', label: s.label, hint: s.hint, count: 1, children: [], raw: ev }
        })
        out.push(node)
      }
      out.sort((a, b) => (b.count || 0) - (a.count || 0))
      return out
    }

    const selfProc = processEvents.filter((ev) => asPid(ev.subject_pid) === pid)
    const childProc = processEvents.filter((ev) => asPid(ev.actor_pid) === pid && asPid(ev.subject_pid) != null && asPid(ev.subject_pid) !== pid)
    const relatedProc = processEvents.filter((ev) => !(asPid(ev.subject_pid) === pid) && !(asPid(ev.actor_pid) === pid && asPid(ev.subject_pid) != null && asPid(ev.subject_pid) !== pid))

    const procNode = makeCategory(t('behavior_lifecycle_category_process'), processEvents, () => {
      const children = []
      const selfNode = { kind: 'subcategory', label: t('behavior_lifecycle_subcategory_self'), hint: '', count: selfProc.length, children: buildOpGroups(selfProc) }
      const childrenNode = { kind: 'subcategory', label: t('behavior_lifecycle_subcategory_children'), hint: '', count: childProc.length, children: [] }
      if (childProc.length) {
        const bySubject = groupBy(childProc, (ev) => asPid(ev.subject_pid))
        for (const [spidStr, list] of bySubject.entries()) {
          const spid = asPid(spidStr)
          const label = spid != null ? String(spid) : t('unknown')
          const node = { kind: 'pid', pid: spid, label, hint: '', count: list.length, children: buildOpGroups(list) }
          childrenNode.children.push(node)
        }
        childrenNode.children.sort((a, b) => (b.count || 0) - (a.count || 0))
      }

      const relatedNode = { kind: 'subcategory', label: t('behavior_lifecycle_subcategory_related'), hint: '', count: relatedProc.length, children: buildOpGroups(relatedProc) }
      if (selfProc.length) children.push(selfNode)
      if (childProc.length) children.push(childrenNode)
      if (relatedProc.length) children.push(relatedNode)
      if (!children.length) children.push({ kind: 'event', label: t('behavior_lifecycle_empty'), hint: '', count: 0, children: [] })
      return children
    })

    const fileNode = makeCategory(t('behavior_lifecycle_category_file'), fileEvents, buildOpGroups)
    const regNode = makeCategory(t('behavior_lifecycle_category_registry'), registryEvents, buildOpGroups)
    const otherNode = makeCategory(t('behavior_lifecycle_category_other'), otherEvents, buildOpGroups)

    rootNode.children = [procNode, fileNode, regNode, otherNode].filter((n) => (n && typeof n === 'object'))
    return rootNode
  }

  /**
 * - 函数: `normalizeText`
 * - Function: `normalizeText`
 * - 作用: 标准化文本输入，统一为当前模块后续逻辑可直接消费的结构。
 * - Purpose: Normalizes the text input into a structure that downstream logic can consume directly.
 * - 调用方: `模块顶层流程`、`matchRule`、`mapEventToMitre`。
 * - Callers: `模块顶层流程`, `matchRule`, `mapEventToMitre`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `v` 为当前流程传入的v。
 * - Variables: `v` is the incoming v for this flow.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `normalizeText`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `normalizeText` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 标准化 | 文本 | normalize | text | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function normalizeText(v) {
    return (typeof v === 'string') ? v.trim() : ''
  }

  /**
 * - 函数: `matchRule`
 * - Function: `matchRule`
 * - 作用: 梳理并返回matchRule负责的rule局部处理结果。
 * - Purpose: Coordinates and returns the rule processing result handled by matchRule.
 * - 调用方: `模块顶层流程`、`mapEventToMitre`。
 * - Callers: `模块顶层流程`, `mapEventToMitre`.
 * - 被调方: `normalizeText`、`eventTargetText`、`Array.isArray`。
 * - Callees: `normalizeText`, `eventTargetText`, `Array.isArray`.
 * - 变量说明: `rule` 为当前流程传入的rule；`ev` 为当前流程传入的ev；`rp`, `ro` 为函数内部派生的中间状态。
 * - Variables: `rule` is the incoming rule for this flow; `ev` is the incoming ev for this flow; `rp`, `ro` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `matchRule`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `matchRule` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: match | rule | match | rule | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function matchRule(rule, ev) {
    if (!rule || typeof rule !== 'object' || !ev || typeof ev !== 'object') return false
    const rp = normalizeText(rule.provider)
    const ro = normalizeText(rule.op)
    const rtp = normalizeText(rule.targetProvider)
    const evProvider = normalizeText(ev.provider)
    const evOp = normalizeText(ev.op)
    if (rp && rp !== evProvider) return false
    if (ro && ro !== evOp) return false

    if (rtp) {
      const file = normalizeText(ev.file_path)
      const reg = normalizeText(ev.reg_key)
      const targetProvider = file ? 'File' : (reg ? 'Registry' : '')
      if (targetProvider !== rtp) return false
    }

    const textContains = Array.isArray(rule.textContains) ? rule.textContains.map(normalizeText).filter(Boolean) : []
    if (textContains.length) {
      const target = eventTargetText(ev)
      const all = `${normalizeText(target)} ${normalizeText(ev.raw_json)}`
      for (const needle of textContains) {
        if (!needle) continue
        if (!all.includes(needle)) return false
      }
    }
    return true
  }

  /**
 * - 函数: `mapEventToMitre`
 * - Function: `mapEventToMitre`
 * - 作用: 梳理并返回mapEventToMitre负责的事件tomitre局部处理结果。
 * - Purpose: Coordinates and returns the event to mitre processing result handled by mapEventToMitre.
 * - 调用方: `buildMitreMatrixModel`。
 * - Callers: `buildMitreMatrixModel`.
 * - 被调方: `matchRule`、`normalizeText`、`push`、`Array.isArray`。
 * - Callees: `matchRule`, `normalizeText`, `push`, `Array.isArray`.
 * - 变量说明: `ev` 为当前流程传入的ev；`cfg` 为当前流程传入的cfg；`c`, `enabled` 为函数内部派生的中间状态。
 * - Variables: `ev` is the incoming ev for this flow; `cfg` is the incoming cfg for this flow; `c`, `enabled` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./behavior_render').mapEventToMitre` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./behavior_render').mapEventToMitre`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: map | 事件 | to | mitre | map | event | to | mitre | error handling | 复用
 */
  function mapEventToMitre(ev, cfg) {
    const c = (cfg && typeof cfg === 'object') ? cfg : {}
    const enabled = c.enabled !== false
    if (!enabled) return []
    const rules = Array.isArray(c.rules) ? c.rules : []
    const matches = []
    for (const r of rules) {
      if (!matchRule(r, ev)) continue
      const tactic = normalizeText(r.tactic)
      const techniqueId = normalizeText(r.techniqueId)
      const techniqueName = normalizeText(r.techniqueName)
      if (!tactic || !techniqueId || !techniqueName) continue
      matches.push({ tactic, techniqueId, techniqueName })
    }
    return matches
  }

  /**
 * - 函数: `buildMitreMatrixModel`
 * - Function: `buildMitreMatrixModel`
 * - 作用: 构建mitrematrixmodel结构或配置，供后续计算、扫描或持久化流程使用。
 * - Purpose: Builds the mitre matrix model structure or configuration for later compute, scan, or persistence flows.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `asPid`、`mapEventToMitre`、`summarizeEvent`、`push`、`t`、`Array.isArray`。
 * - Callees: `asPid`, `mapEventToMitre`, `summarizeEvent`, `push`, `t`, `Array.isArray`.
 * - 变量说明: `opts` 为当前流程传入的opts；`o`, `pid` 为函数内部派生的中间状态。
 * - Variables: `opts` is the incoming opts for this flow; `o`, `pid` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./behavior_render').buildMitreMatrixModel` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./behavior_render').buildMitreMatrixModel`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 构建 | mitre | matrix | model | build | mitre | matrix | model | error handling | 复用
 */
  function buildMitreMatrixModel(opts) {
    const o = opts && typeof opts === 'object' ? opts : {}
    const pid = asPid(o.pid)
    const t = typeof o.t === 'function' ? o.t : ((k) => k)
    const cfg = (o.cfg && typeof o.cfg === 'object') ? o.cfg : {}
    const rawEvents = Array.isArray(o.events) ? o.events : []
    const tactics = Array.isArray(cfg.tactics) && cfg.tactics.length ? cfg.tactics.slice() : []

    if (pid == null) {
      return { pid: null, tactics, columns: [] }
    }

    const events = rawEvents.filter((ev) => {
      const a = asPid(ev && ev.actor_pid)
      const s = asPid(ev && ev.subject_pid)
      return a === pid || s === pid
    })

    const byTactic = new Map()
    for (const tac of tactics) byTactic.set(String(tac), new Map())

    for (const ev of events) {
      const tags = mapEventToMitre(ev, cfg)
      for (const tag of tags) {
        const tactic = tag.tactic
        if (!byTactic.has(tactic)) byTactic.set(tactic, new Map())
        const techKey = `${tag.techniqueId} ${tag.techniqueName}`
        const techMap = byTactic.get(tactic)
        if (!techMap.has(techKey)) {
          techMap.set(techKey, { tactic, techniqueId: tag.techniqueId, techniqueName: tag.techniqueName, count: 0, examples: [] })
        }
        const cell = techMap.get(techKey)
        cell.count += 1
        if (cell.examples.length < 5) {
          const s = summarizeEvent(ev)
          cell.examples.push({ label: s.label, hint: s.hint })
        }
      }
    }

    const columns = tactics.map((tactic) => {
      const techMap = byTactic.get(String(tactic)) || new Map()
      const techniques = Array.from(techMap.values()).sort((a, b) => (b.count || 0) - (a.count || 0))
      return { tactic: String(tactic), techniques }
    })

    const uncovered = Array.from(byTactic.entries())
      .filter(([k]) => !tactics.includes(k))
      .map(([k]) => k)
      .sort((a, b) => a.localeCompare(b))

    for (const tactic of uncovered) {
      const techMap = byTactic.get(tactic) || new Map()
      const techniques = Array.from(techMap.values()).sort((a, b) => (b.count || 0) - (a.count || 0))
      columns.push({ tactic, techniques })
    }

    const matchedCount = columns.reduce((sum, c2) => sum + (Array.isArray(c2.techniques) ? c2.techniques.reduce((s2, it) => s2 + (it.count || 0), 0) : 0), 0)
    const totalEvents = events.length
    const unmatched = Math.max(0, totalEvents - matchedCount)
    return { pid, tactics: columns.map(c3 => c3.tactic), columns, totalEvents, matchedEvents: matchedCount, unmatchedEvents: unmatched, emptyText: t('behavior_mitre_empty') }
  }

  root.behaviorRender = root.behaviorRender || {}
  root.behaviorRender.renderProcessSelectAsync = renderProcessSelectAsync
  root.behaviorRender.buildPidLifecycleTree = buildPidLifecycleTree
  root.behaviorRender.buildMitreMatrixModel = buildMitreMatrixModel
  root.behaviorRender.summarizeEvent = summarizeEvent

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { renderProcessSelectAsync, buildPidLifecycleTree, buildMitreMatrixModel, mapEventToMitre, summarizeEvent }
  }
})(typeof window !== 'undefined' ? window : globalThis)
