(() => {
  /**
 * - 函数: `animationsEnabled`
 * - Function: `animationsEnabled`
 * - 作用: 梳理并返回animationsEnabled负责的enabled局部处理结果。
 * - Purpose: Coordinates and returns the enabled processing result handled by animationsEnabled.
 * - 调用方: `模块顶层流程`、`fadeIn`、`slideIn`。
 * - Callers: `模块顶层流程`, `fadeIn`, `slideIn`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；`body` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `body` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 在当前模块内部直接调用 `animationsEnabled(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `animationsEnabled(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: animations | enabled | animations | enabled | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function animationsEnabled() {
    const body = document.body
    return !body || body.getAttribute('data-animations') !== 'off'
  }

  /**
 * - 函数: `parseCssTimeMs`
 * - Function: `parseCssTimeMs`
 * - 作用: 解析csstimems原始输入，并提取结构化结果供后续逻辑使用。
 * - Purpose: Parses the raw css time ms input and extracts a structured result for downstream logic.
 * - 调用方: `模块顶层流程`、`getMotionVarMs`。
 * - Callers: `模块顶层流程`, `getMotionVarMs`.
 * - 被调方: `Number.isFinite`。
 * - Callees: `Number.isFinite`.
 * - 变量说明: `raw` 为当前流程传入的raw；`s`, `v` 为函数内部派生的中间状态。
 * - Variables: `raw` is the incoming raw for this flow; `s`, `v` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `parseCssTimeMs(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `parseCssTimeMs(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 解析 | css | time | ms | parse | css | time | ms | error handling | 复用
 */
  function parseCssTimeMs(raw) {
    const s = typeof raw === 'string' ? raw.trim() : ''
    if (!s) return null
    if (s.endsWith('ms')) {
      const v = parseFloat(s.slice(0, -2))
      return Number.isFinite(v) ? v : null
    }
    if (s.endsWith('s')) {
      const v = parseFloat(s.slice(0, -1))
      return Number.isFinite(v) ? v * 1000 : null
    }
    const v = parseFloat(s)
    return Number.isFinite(v) ? v : null
  }

  /**
 * - 函数: `getMotionVarMs`
 * - Function: `getMotionVarMs`
 * - 作用: 读取并汇总动效varms，返回当前流程消费的快照或配置结果。
 * - Purpose: Reads and aggregates the motion var ms into a snapshot or config result for the current flow.
 * - 调用方: `模块顶层流程`、`fadeIn`、`slideIn`。
 * - Callers: `模块顶层流程`, `fadeIn`, `slideIn`.
 * - 被调方: `parseCssTimeMs`、`Number.isFinite`。
 * - Callees: `parseCssTimeMs`, `Number.isFinite`.
 * - 变量说明: `name` 为当前流程传入的名称；`fallbackMs` 为当前流程传入的fallbackms；`v`, `ms` 为函数内部派生的中间状态。
 * - Variables: `name` is the incoming name for this flow; `fallbackMs` is the incoming fallback ms for this flow; `v`, `ms` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `getMotionVarMs(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `getMotionVarMs(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 获取 | 动效 | var | ms | get | motion | var | ms | error handling | 复用
 */
  function getMotionVarMs(name, fallbackMs) {
    try {
      const v = getComputedStyle(document.documentElement).getPropertyValue(name)
      const ms = parseCssTimeMs(v)
      return Number.isFinite(ms) ? ms : fallbackMs
    } catch {
      return fallbackMs
    }
  }

  /**
 * - 函数: `numAttr`
 * - Function: `numAttr`
 * - 作用: 梳理并返回numAttr负责的attr局部处理结果。
 * - Purpose: Coordinates and returns the attr processing result handled by numAttr.
 * - 调用方: `模块顶层流程`、`connectedCallback`。
 * - Callers: `模块顶层流程`, `connectedCallback`.
 * - 被调方: `Number.isFinite`。
 * - Callees: `Number.isFinite`.
 * - 变量说明: `el` 为当前流程传入的el；`name` 为当前流程传入的名称；`fallback` 为当前流程传入的fallback；`v`, `n` 为函数内部派生的中间状态。
 * - Variables: `el` is the incoming el for this flow; `name` is the incoming name for this flow; `fallback` is the incoming fallback for this flow; `v`, `n` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `numAttr(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `numAttr(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: num | attr | num | attr | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function numAttr(el, name, fallback) {
    const v = el.getAttribute(name)
    const n = v != null ? parseFloat(v) : NaN
    return Number.isFinite(n) ? n : fallback
  }

  /**
 * - 函数: `strAttr`
 * - Function: `strAttr`
 * - 作用: 梳理并返回strAttr负责的attr局部处理结果。
 * - Purpose: Coordinates and returns the attr processing result handled by strAttr.
 * - 调用方: `模块顶层流程`、`connectedCallback`。
 * - Callers: `模块顶层流程`, `connectedCallback`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `el` 为当前流程传入的el；`name` 为当前流程传入的名称；`fallback` 为当前流程传入的fallback；`v` 为函数内部派生的中间状态。
 * - Variables: `el` is the incoming el for this flow; `name` is the incoming name for this flow; `fallback` is the incoming fallback for this flow; `v` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `strAttr(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `strAttr(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: str | attr | str | attr | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function strAttr(el, name, fallback) {
    const v = el.getAttribute(name)
    return (typeof v === 'string' && v.trim()) ? v.trim() : fallback
  }

  /**
 * - 函数: `gsapRef`
 * - Function: `gsapRef`
 * - 作用: 梳理并返回gsapRef负责的ref局部处理结果。
 * - Purpose: Coordinates and returns the ref processing result handled by gsapRef.
 * - 调用方: `模块顶层流程`、`fadeIn`、`slideIn`。
 * - Callers: `模块顶层流程`, `fadeIn`, `slideIn`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `gsapRef(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `gsapRef(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: gsap | ref | gsap | ref | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function gsapRef() {
    return (typeof window !== 'undefined' && window.gsap) ? window.gsap : null
  }

  /**
 * - 函数: `fadeIn`
 * - Function: `fadeIn`
 * - 作用: 梳理并返回fadeIn负责的in局部处理结果。
 * - Purpose: Coordinates and returns the in processing result handled by fadeIn.
 * - 调用方: `模块顶层流程`、`connectedCallback`。
 * - Callers: `模块顶层流程`, `connectedCallback`.
 * - 被调方: `gsapRef`、`animationsEnabled`、`getMotionVarMs`、`Math.max`、`Promise.resolve`。
 * - Callees: `gsapRef`, `animationsEnabled`, `getMotionVarMs`, `Math.max`, `Promise.resolve`.
 * - 变量说明: `el` 为当前流程传入的el；`opts` 为当前流程传入的opts；`gsap`, `enabled` 为函数内部派生的中间状态。
 * - Variables: `el` is the incoming el for this flow; `opts` is the incoming opts for this flow; `gsap`, `enabled` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `fadeIn(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `fadeIn(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: fade | in | fade | in | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function fadeIn(el, opts) {
    const gsap = gsapRef()
    const enabled = animationsEnabled()
    const durationMs = Math.max(0, opts.durationMs || getMotionVarMs('--motion-dur-enter', 250))
    const delayMs = Math.max(0, opts.delayMs || 0)
    const ease = opts.ease || 'power3.out'
    if (!enabled || !gsap) {
      el.style.opacity = '1'
      el.style.filter = ''
      el.style.transform = ''
      return Promise.resolve()
    }
    gsap.set(el, { opacity: 0 })
    return new Promise(resolve => {
      gsap.to(el, {
        opacity: 1,
        duration: durationMs / 1000,
        delay: delayMs / 1000,
        ease,
        overwrite: true,
        onComplete: () => {
          try { gsap.set(el, { clearProps: 'opacity,filter,transform' }) } catch {}
          resolve()
        }
      })
    })
  }

  /**
 * - 函数: `slideIn`
 * - Function: `slideIn`
 * - 作用: 梳理并返回slideIn负责的in局部处理结果。
 * - Purpose: Coordinates and returns the in processing result handled by slideIn.
 * - 调用方: `模块顶层流程`、`connectedCallback`。
 * - Callers: `模块顶层流程`, `connectedCallback`.
 * - 被调方: `gsapRef`、`animationsEnabled`、`getMotionVarMs`、`Math.max`、`Number.isFinite`、`Promise.resolve`。
 * - Callees: `gsapRef`, `animationsEnabled`, `getMotionVarMs`, `Math.max`, `Number.isFinite`, `Promise.resolve`.
 * - 变量说明: `el` 为当前流程传入的el；`opts` 为当前流程传入的opts；`gsap`, `enabled` 为函数内部派生的中间状态。
 * - Variables: `el` is the incoming el for this flow; `opts` is the incoming opts for this flow; `gsap`, `enabled` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `slideIn(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `slideIn(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: slide | in | slide | in | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function slideIn(el, opts) {
    const gsap = gsapRef()
    const enabled = animationsEnabled()
    const durationMs = Math.max(0, opts.durationMs || getMotionVarMs('--motion-dur-enter', 250))
    const delayMs = Math.max(0, opts.delayMs || 0)
    const dist = Math.max(0, opts.distance || 12)
    const dir = opts.direction || 'up'
    const overshoot = Number.isFinite(opts.overshoot) ? opts.overshoot : 1.5
    const bounce = Number.isFinite(opts.bounce) ? opts.bounce : 1.2
    const ease = opts.ease || `back.out(${overshoot})`
    const elasticEase = `elastic.out(${bounce},0.55)`
    const useElastic = opts.elastic === true
    const actualEase = useElastic ? elasticEase : ease

    if (!enabled || !gsap) {
      el.style.opacity = '1'
      el.style.filter = ''
      el.style.transform = ''
      return Promise.resolve()
    }

    let x = 0
    let y = 0
    if (dir === 'down') y = -dist
    else if (dir === 'left') x = dist
    else if (dir === 'right') x = -dist
    else y = dist

    gsap.set(el, { opacity: 0, x, y })
    return new Promise(resolve => {
      gsap.to(el, {
        opacity: 1,
        x: 0,
        y: 0,
        duration: durationMs / 1000,
        delay: delayMs / 1000,
        ease: actualEase,
        overwrite: true,
        onComplete: () => {
          try { gsap.set(el, { clearProps: 'opacity,filter,transform' }) } catch {}
          resolve()
        }
      })
    })
  }

  class MotionFade extends HTMLElement {
    /**
 * - 函数: `connectedCallback`
 * - Function: `connectedCallback`
 * - 作用: 梳理并返回connectedCallback负责的callback局部处理结果。
 * - Purpose: Coordinates and returns the callback processing result handled by connectedCallback.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `numAttr`、`strAttr`、`fadeIn`。
 * - Callees: `numAttr`, `strAttr`, `fadeIn`.
 * - 变量说明: 无显式入参；`dur`, `delay`, `ease` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `dur`, `delay`, `ease` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 在当前模块内部直接调用 `connectedCallback(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `connectedCallback(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: connected | callback | connected | callback | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
    connectedCallback() {
      const dur = numAttr(this, 'duration', null)
      const delay = numAttr(this, 'delay', 0)
      const ease = strAttr(this, 'ease', 'power3.out')
      requestAnimationFrame(() => {
        fadeIn(this, { durationMs: dur || undefined, delayMs: delay, ease })
      })
    }
  }

  class MotionSlide extends HTMLElement {
    /**
 * - 函数: `connectedCallback`
 * - Function: `connectedCallback`
 * - 作用: 梳理并返回connectedCallback负责的callback局部处理结果。
 * - Purpose: Coordinates and returns the callback processing result handled by connectedCallback.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `numAttr`、`strAttr`、`slideIn`。
 * - Callees: `numAttr`, `strAttr`, `slideIn`.
 * - 变量说明: 无显式入参；`dur`, `delay`, `dir` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `dur`, `delay`, `dir` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 在当前模块内部直接调用 `connectedCallback(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `connectedCallback(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: connected | callback | connected | callback | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
    connectedCallback() {
      const dur = numAttr(this, 'duration', null)
      const delay = numAttr(this, 'delay', 0)
      const dir = strAttr(this, 'direction', 'up')
      const dist = numAttr(this, 'distance', 12)
      const overshoot = numAttr(this, 'overshoot', 1.5)
      const bounce = numAttr(this, 'bounce', 1.2)
      const elastic = strAttr(this, 'elastic', '') === 'true'
      requestAnimationFrame(() => {
        slideIn(this, { durationMs: dur || undefined, delayMs: delay, direction: dir, distance: dist, overshoot, bounce, elastic })
      })
    }
  }

  /**
 * - 函数: `defineSafe`
 * - Function: `defineSafe`
 * - 作用: 梳理并返回defineSafe负责的safe局部处理结果。
 * - Purpose: Coordinates and returns the safe processing result handled by defineSafe.
 * - 调用方: `模块顶层流程`、`init`。
 * - Callers: `模块顶层流程`, `init`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `name` 为当前流程传入的名称；`ctor` 为当前流程传入的ctor。
 * - Variables: `name` is the incoming name for this flow; `ctor` is the incoming ctor for this flow.
 * - 接入方式: 在当前模块内部直接调用 `defineSafe(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `defineSafe(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: define | safe | define | safe | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function defineSafe(name, ctor) {
    try {
      if (!customElements.get(name)) customElements.define(name, ctor)
    } catch {}
  }

  /**
 * - 函数: `init`
 * - Function: `init`
 * - 作用: 梳理并返回init负责的init局部处理结果。
 * - Purpose: Coordinates and returns the init processing result handled by init.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `defineSafe`。
 * - Callees: `defineSafe`.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `init(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `init(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: init | init | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function init() {
    defineSafe('motion-fade', MotionFade)
    defineSafe('motion-slide', MotionSlide)
    window.Motion = {
      fadeIn,
      slideIn
    }
  }

  if (typeof window !== 'undefined') {
    if (document.readyState === 'loading') window.addEventListener('DOMContentLoaded', init)
    else init()
  }
})()
