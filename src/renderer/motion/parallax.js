(() => {
  let rafId = 0
  let lastScrollTop = 0
  let bound = false
  let contentEl = null
  let layers = []

  /**
 * - 函数: `animationsEnabled`
 * - Function: `animationsEnabled`
 * - 作用: 梳理并返回animationsEnabled负责的enabled局部处理结果。
 * - Purpose: Coordinates and returns the enabled processing result handled by animationsEnabled.
 * - 调用方: `模块顶层流程`、`tick`、`observeMotionFlag`。
 * - Callers: `模块顶层流程`, `tick`, `observeMotionFlag`.
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
 * - 函数: `collect`
 * - Function: `collect`
 * - 作用: 梳理并返回collect负责的收集局部处理结果。
 * - Purpose: Coordinates and returns the collect processing result handled by collect.
 * - 调用方: `模块顶层流程`、`refresh`。
 * - Callers: `模块顶层流程`, `refresh`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `collect(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `collect(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 收集 | collect | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function collect() {
    contentEl = document.querySelector('.content')
    layers = contentEl ? Array.from(contentEl.querySelectorAll('[data-parallax-layer]')) : []
  }

  /**
 * - 函数: `apply`
 * - Function: `apply`
 * - 作用: 梳理并返回apply负责的apply局部处理结果。
 * - Purpose: Coordinates and returns the apply processing result handled by apply.
 * - 调用方: `模块顶层流程`、`tick`。
 * - Callers: `模块顶层流程`, `tick`.
 * - 被调方: `Number.isFinite`。
 * - Callees: `Number.isFinite`.
 * - 变量说明: `st` 为当前流程传入的st；`el`, `rate` 为函数内部派生的中间状态。
 * - Variables: `st` is the incoming st for this flow; `el`, `rate` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `apply(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `apply(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: apply | apply | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function apply(st) {
    for (const el of layers) {
      const rate = parseFloat(el.getAttribute('data-rate') || '1')
      const r = Number.isFinite(rate) ? rate : 1
      const ty = st * (1 - r)
      el.style.transform = `translate3d(0, ${ty}px, 0)`
    }
  }

  /**
 * - 函数: `reset`
 * - Function: `reset`
 * - 作用: 重置重置相关状态，使当前流程回到可重复执行的初始条件。
 * - Purpose: Resets the reset state so the current flow can re-enter a repeatable initial condition.
 * - 调用方: `模块顶层流程`、`tick`、`observeMotionFlag`。
 * - Callers: `模块顶层流程`, `tick`, `observeMotionFlag`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；`el` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `el` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 在当前模块内部直接调用 `reset(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `reset(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 重置 | reset | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function reset() {
    for (const el of layers) {
      el.style.transform = ''
    }
  }

  /**
 * - 函数: `tick`
 * - Function: `tick`
 * - 作用: 梳理并返回tick负责的tick局部处理结果。
 * - Purpose: Coordinates and returns the tick processing result handled by tick.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `animationsEnabled`、`reset`、`apply`。
 * - Callees: `animationsEnabled`, `reset`, `apply`.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `tick(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `tick(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: tick | tick | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function tick() {
    rafId = 0
    if (!contentEl || !layers.length) return
    if (!animationsEnabled()) {
      reset()
      return
    }
    apply(lastScrollTop)
  }

  /**
 * - 函数: `onScroll`
 * - Function: `onScroll`
 * - 作用: 梳理并返回onScroll负责的scroll局部处理结果。
 * - Purpose: Coordinates and returns the scroll processing result handled by onScroll.
 * - 调用方: `模块顶层流程`、`refresh`、`observeMotionFlag`。
 * - Callers: `模块顶层流程`, `refresh`, `observeMotionFlag`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `onScroll(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `onScroll(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: on | scroll | on | scroll | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function onScroll() {
    if (!contentEl) return
    lastScrollTop = contentEl.scrollTop || 0
    if (rafId) return
    rafId = requestAnimationFrame(tick)
  }

  /**
 * - 函数: `bind`
 * - Function: `bind`
 * - 作用: 梳理并返回bind负责的bind局部处理结果。
 * - Purpose: Coordinates and returns the bind processing result handled by bind.
 * - 调用方: `模块顶层流程`、`refresh`。
 * - Callers: `模块顶层流程`, `refresh`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `bind(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `bind(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: bind | bind | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function bind() {
    if (!contentEl || bound) return
    contentEl.addEventListener('scroll', onScroll, { passive: true })
    bound = true
  }

  /**
 * - 函数: `unbind`
 * - Function: `unbind`
 * - 作用: 梳理并返回unbind负责的unbind局部处理结果。
 * - Purpose: Coordinates and returns the unbind processing result handled by unbind.
 * - 调用方: `模块顶层流程`、`refresh`。
 * - Callers: `模块顶层流程`, `refresh`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `unbind(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `unbind(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: unbind | unbind | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function unbind() {
    if (!contentEl || !bound) return
    try {
      contentEl.removeEventListener('scroll', onScroll)
    } catch {}
    bound = false
  }

  /**
 * - 函数: `refresh`
 * - Function: `refresh`
 * - 作用: 梳理并返回refresh负责的刷新局部处理结果。
 * - Purpose: Coordinates and returns the refresh processing result handled by refresh.
 * - 调用方: `模块顶层流程`、`init`。
 * - Callers: `模块顶层流程`, `init`.
 * - 被调方: `unbind`、`collect`、`bind`、`onScroll`。
 * - Callees: `unbind`, `collect`, `bind`, `onScroll`.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `refresh(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `refresh(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 刷新 | refresh | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function refresh() {
    if (rafId) cancelAnimationFrame(rafId)
    rafId = 0
    unbind()
    collect()
    if (!contentEl || !layers.length) return
    bind()
    onScroll()
  }

  /**
 * - 函数: `observeMotionFlag`
 * - Function: `observeMotionFlag`
 * - 作用: 梳理并返回observeMotionFlag负责的动效flag局部处理结果。
 * - Purpose: Coordinates and returns the motion flag processing result handled by observeMotionFlag.
 * - 调用方: `模块顶层流程`、`init`。
 * - Callers: `模块顶层流程`, `init`.
 * - 被调方: `animationsEnabled`、`reset`、`onScroll`。
 * - Callees: `animationsEnabled`, `reset`, `onScroll`.
 * - 变量说明: 无显式入参；`body`, `mo` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `body`, `mo` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 在当前模块内部直接调用 `observeMotionFlag(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `observeMotionFlag(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 监听 | 动效 | flag | observe | motion | flag | call chain | 错误处理 | error handling | 复用
 */
  function observeMotionFlag() {
    const body = document.body
    if (!body || typeof MutationObserver === 'undefined') return
    const mo = new MutationObserver(() => {
      if (!animationsEnabled()) reset()
      else onScroll()
    })
    mo.observe(body, { attributes: true, attributeFilter: ['data-animations'] })
  }

  /**
 * - 函数: `init`
 * - Function: `init`
 * - 作用: 梳理并返回init负责的init局部处理结果。
 * - Purpose: Coordinates and returns the init processing result handled by init.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `refresh`、`observeMotionFlag`。
 * - Callees: `refresh`, `observeMotionFlag`.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `init(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `init(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: init | init | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function init() {
    refresh()
    observeMotionFlag()
    window.addEventListener('resize', refresh)
  }

  if (typeof window !== 'undefined') {
    if (document.readyState === 'loading') window.addEventListener('DOMContentLoaded', init)
    else init()
  }
})()
