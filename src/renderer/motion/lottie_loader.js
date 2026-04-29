(() => {
  const LOADER_URL = './assets/lottie/particle_loader.json'

  const FALLBACK_ANIM = {
    v: '5.7.4',
    fr: 60,
    ip: 0,
    op: 120,
    w: 200,
    h: 200,
    nm: 'anxin_particle_loader',
    ddd: 0,
    assets: [],
    layers: [
      {
        ddd: 0,
        ind: 1,
        ty: 4,
        nm: 'Ring',
        sr: 1,
        ks: {
          o: { a: 0, k: 100 },
          r: { a: 0, k: 0 },
          p: { a: 0, k: [100, 100, 0] },
          a: { a: 0, k: [0, 0, 0] },
          s: { a: 0, k: [100, 100, 100] }
        },
        shapes: [
          {
            ty: 'gr',
            it: [
              {
                ty: 'el',
                p: { a: 0, k: [0, 0] },
                s: { a: 0, k: [120, 120] },
                nm: 'Ellipse Path 1',
                mn: 'ADBE Vector Shape - Ellipse',
                hd: false
              },
              {
                ty: 'st',
                c: { a: 0, k: [0.298, 0.635, 1, 1] },
                o: { a: 0, k: 100 },
                w: { a: 0, k: 10 },
                lc: 2,
                lj: 2,
                ml: 4,
                d: [
                  { n: 'd', nm: 'Dash', v: { a: 0, k: 38 } },
                  { n: 'g', nm: 'Gap', v: { a: 0, k: 22 } },
                  { n: 'o', nm: 'Offset', v: { a: 1, k: [{ t: 0, s: [0] }, { t: 120, s: [-260] }] } }
                ],
                nm: 'Stroke 1',
                mn: 'ADBE Vector Graphic - Stroke',
                hd: false
              },
              {
                ty: 'tr',
                p: { a: 0, k: [0, 0] },
                a: { a: 0, k: [0, 0] },
                s: { a: 0, k: [100, 100] },
                r: { a: 1, k: [{ t: 0, s: [0] }, { t: 120, s: [360] }] },
                o: { a: 0, k: 100 },
                sk: { a: 0, k: 0 },
                sa: { a: 0, k: 0 },
                nm: 'Transform'
              }
            ],
            nm: 'Ellipse 1',
            np: 3,
            cix: 2,
            bm: 0,
            ix: 1,
            mn: 'ADBE Vector Group',
            hd: false
          }
        ],
        ip: 0,
        op: 120,
        st: 0,
        bm: 0
      }
    ],
    markers: []
  }

  const instances = new Map()
  let cachedData = null

  /**
 * - 函数: `animationsEnabled`
 * - Function: `animationsEnabled`
 * - 作用: 梳理并返回animationsEnabled负责的enabled局部处理结果。
 * - Purpose: Coordinates and returns the enabled processing result handled by animationsEnabled.
 * - 调用方: `模块顶层流程`、`start`。
 * - Callers: `模块顶层流程`, `start`.
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
 * - 函数: `loadAnimData`
 * - Function: `loadAnimData`
 * - 作用: 加载anim数据资源，并返回后续逻辑可以直接复用的数据或实例。
 * - Purpose: Loads the anim data resource and returns data or instances that downstream logic can reuse.
 * - 调用方: `模块顶层流程`、`start`。
 * - Callers: `模块顶层流程`, `start`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；`res` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `res` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 在当前模块内部直接调用 `loadAnimData(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `loadAnimData(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部通过 `try/catch` 拦截局部异常；无法自行恢复时，会把错误继续抛给上游调用方处理。
 * - Error Handling: Uses `try/catch` to intercept local failures and rethrows or rejects unrecoverable errors back to upstream callers.
 * - 关键词: 加载 | anim | 数据 | load | anim | data | call chain | 错误处理 | error handling | 复用
 */
  async function loadAnimData() {
    if (cachedData) return cachedData
    try {
      const res = await fetch(LOADER_URL, { cache: 'no-cache' })
      if (!res.ok) throw new Error('bad status')
      cachedData = await res.json()
      return cachedData
    } catch {
      cachedData = FALLBACK_ANIM
      return cachedData
    }
  }

  /**
 * - 函数: `ensureInstance`
 * - Function: `ensureInstance`
 * - 作用: 确保instance已初始化且可复用，必要时执行一次性准备逻辑。
 * - Purpose: Ensures the instance is initialized and reusable, performing one-time setup when necessary.
 * - 调用方: `模块顶层流程`、`start`。
 * - Callers: `模块顶层流程`, `start`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `containerEl` 为当前流程传入的containerel；`key`, `existing` 为函数内部派生的中间状态。
 * - Variables: `containerEl` is the incoming container el for this flow; `key`, `existing` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `ensureInstance(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `ensureInstance(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 确保 | instance | ensure | instance | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function ensureInstance(containerEl) {
    const key = containerEl.id || containerEl
    const existing = instances.get(key)
    if (existing) return existing
    if (!(window.lottie && typeof window.lottie.loadAnimation === 'function')) return null
    const inst = { containerEl, anim: null, active: false }
    instances.set(key, inst)
    return inst
  }

  /**
 * - 函数: `start`
 * - Function: `start`
 * - 作用: 梳理并返回start负责的start局部处理结果。
 * - Purpose: Coordinates and returns the start processing result handled by start.
 * - 调用方: `模块顶层流程`、`bindModal`。
 * - Callers: `模块顶层流程`, `bindModal`.
 * - 被调方: `animationsEnabled`、`ensureInstance`、`loadAnimData`。
 * - Callees: `animationsEnabled`, `ensureInstance`, `loadAnimData`.
 * - 变量说明: `containerId` 为当前流程传入的containerid；`spinnerId` 为当前流程传入的spinnerid；`containerEl`, `spinnerEl` 为函数内部派生的中间状态。
 * - Variables: `containerId` is the incoming container id for this flow; `spinnerId` is the incoming spinner id for this flow; `containerEl`, `spinnerEl` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `start(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `start(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: start | start | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  async function start(containerId, spinnerId) {
    const containerEl = document.getElementById(containerId)
    const spinnerEl = spinnerId ? document.getElementById(spinnerId) : null
    if (!containerEl) return

    if (!animationsEnabled()) {
      containerEl.style.display = 'none'
      if (spinnerEl) spinnerEl.style.display = 'inline-block'
      return
    }

    const inst = ensureInstance(containerEl)
    if (!inst) {
      containerEl.style.display = 'none'
      if (spinnerEl) spinnerEl.style.display = 'inline-block'
      return
    }

    containerEl.style.display = 'inline-block'
    if (spinnerEl) spinnerEl.style.display = 'none'

    if (!inst.anim) {
      const data = await loadAnimData()
      inst.anim = window.lottie.loadAnimation({
        container: containerEl,
        renderer: 'svg',
        loop: true,
        autoplay: false,
        animationData: data
      })
      try {
        inst.anim.setSubframe(false)
      } catch {}
    }

    inst.active = true
    try {
      if (!document.hidden) inst.anim.play()
    } catch {}
  }

  /**
 * - 函数: `stop`
 * - Function: `stop`
 * - 作用: 梳理并返回stop负责的stop局部处理结果。
 * - Purpose: Coordinates and returns the stop processing result handled by stop.
 * - 调用方: `模块顶层流程`、`bindModal`。
 * - Callers: `模块顶层流程`, `bindModal`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `containerId` 为当前流程传入的containerid；`spinnerId` 为当前流程传入的spinnerid；`containerEl`, `spinnerEl` 为函数内部派生的中间状态。
 * - Variables: `containerId` is the incoming container id for this flow; `spinnerId` is the incoming spinner id for this flow; `containerEl`, `spinnerEl` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `stop(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `stop(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: stop | stop | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function stop(containerId, spinnerId) {
    const containerEl = document.getElementById(containerId)
    const spinnerEl = spinnerId ? document.getElementById(spinnerId) : null
    if (spinnerEl) spinnerEl.style.display = 'inline-block'
    if (!containerEl) return
    containerEl.style.display = 'none'
    const key = containerEl.id || containerEl
    const inst = instances.get(key)
    if (!inst || !inst.anim) return
    inst.active = false
    try {
      inst.anim.pause()
    } catch {}
  }

  /**
 * - 函数: `bindModal`
 * - Function: `bindModal`
 * - 作用: 梳理并返回bindModal负责的modal局部处理结果。
 * - Purpose: Coordinates and returns the modal processing result handled by bindModal.
 * - 调用方: `模块顶层流程`、`init`。
 * - Callers: `模块顶层流程`, `init`.
 * - 被调方: `start`、`stop`。
 * - Callees: `start`, `stop`.
 * - 变量说明: `modalId` 为当前流程传入的modalid；`containerId` 为当前流程传入的containerid；`spinnerId` 为当前流程传入的spinnerid；`el` 为函数内部派生的中间状态。
 * - Variables: `modalId` is the incoming modal id for this flow; `containerId` is the incoming container id for this flow; `spinnerId` is the incoming spinner id for this flow; `el` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `bindModal(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `bindModal(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: bind | modal | bind | modal | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function bindModal(modalId, containerId, spinnerId) {
    const el = document.getElementById(modalId)
    if (!el) return
    el.addEventListener('shown.bs.modal', () => start(containerId, spinnerId))
    el.addEventListener('hidden.bs.modal', () => stop(containerId, spinnerId))
  }

  /**
 * - 函数: `onVisibilityChange`
 * - Function: `onVisibilityChange`
 * - 作用: 梳理并返回onVisibilityChange负责的visibilitychange局部处理结果。
 * - Purpose: Coordinates and returns the visibility change processing result handled by onVisibilityChange.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；`hidden`, `inst` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `hidden`, `inst` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 在当前模块内部直接调用 `onVisibilityChange(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `onVisibilityChange(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: on | visibility | change | on | visibility | change | call chain | 错误处理 | error handling | 复用
 */
  function onVisibilityChange() {
    const hidden = !!document.hidden
    for (const inst of instances.values()) {
      if (!inst.anim || !inst.active) continue
      try {
        if (hidden) inst.anim.pause()
        else inst.anim.play()
      } catch {}
    }
  }

  /**
 * - 函数: `init`
 * - Function: `init`
 * - 作用: 梳理并返回init负责的init局部处理结果。
 * - Purpose: Coordinates and returns the init processing result handled by init.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `bindModal`。
 * - Callees: `bindModal`.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `init(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `init(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: init | init | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function init() {
    bindModal('engine-wait-modal', 'engine-wait-lottie', 'engine-wait-spinner')
    bindModal('loading-modal', 'loading-lottie', 'loading-spinner')
    bindModal('processing-modal', 'processing-lottie', 'processing-spinner')
    document.addEventListener('visibilitychange', onVisibilityChange)
  }

  if (typeof window !== 'undefined') {
    if (document.readyState === 'loading') window.addEventListener('DOMContentLoaded', init)
    else init()
  }
})()
