function t(key) {
  const fn = window.api && window.api.i18n && window.api.i18n.t
  return fn ? fn(key) : key
}

/**
 * - 函数: `setTheme`
 * - Function: `setTheme`
 * - 作用: 设置主题状态，并同步影响当前模块内的后续判断。
 * - Purpose: Sets the theme state and synchronizes the downstream decisions made inside this module.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；`cfg`, `color` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `cfg`, `color` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `setTheme`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `setTheme` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 设置 | 主题 | set | theme | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function setTheme() {
  const cfg = (window.api && window.api.config) ? window.api.config.get() : { themeColor: '#1677ff' }
  const color = cfg.themeColor || '#1677ff'
  document.documentElement.style.setProperty('--theme-color', color)
}

let themeMedia = null
let themeMediaBound = false

/**
 * - 函数: `resolveThemeMode`
 * - Function: `resolveThemeMode`
 * - 作用: 解析主题mode，并按当前运行环境返回优先可用的结果。
 * - Purpose: Resolves the theme mode and returns the highest-priority usable result for the current runtime.
 * - 调用方: `模块顶层流程`、`applyThemePreferences`、`handler`。
 * - Callers: `模块顶层流程`, `applyThemePreferences`, `handler`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `cfg` 为当前流程传入的cfg；`m` 为函数内部派生的中间状态。
 * - Variables: `cfg` is the incoming cfg for this flow; `m` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `resolveThemeMode(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `resolveThemeMode(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 解析 | 主题 | mode | resolve | theme | mode | call chain | 错误处理 | error handling | 复用
 */
function resolveThemeMode(cfg) {
  const m = cfg && cfg.ui && typeof cfg.ui.themeMode === 'string' ? cfg.ui.themeMode.trim() : ''
  if (m === 'dark' || m === 'light' || m === 'system') return m
  return 'system'
}

/**
 * - 函数: `resolveThemeFromSystem`
 * - Function: `resolveThemeFromSystem`
 * - 作用: 解析主题fromsystem，并按当前运行环境返回优先可用的结果。
 * - Purpose: Resolves the theme from system and returns the highest-priority usable result for the current runtime.
 * - 调用方: `模块顶层流程`、`applyThemePreferences`、`handler`。
 * - Callers: `模块顶层流程`, `applyThemePreferences`, `handler`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；`mm` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `mm` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 在当前模块内部直接调用 `resolveThemeFromSystem(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `resolveThemeFromSystem(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 解析 | 主题 | from | system | resolve | theme | from | system | error handling | 复用
 */
function resolveThemeFromSystem() {
  try {
    const mm = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null
    return mm && mm.matches ? 'dark' : 'light'
  } catch {
    return 'dark'
  }
}

/**
 * - 函数: `applyThemePreferences`
 * - Function: `applyThemePreferences`
 * - 作用: 梳理并返回applyThemePreferences负责的主题preferences局部处理结果。
 * - Purpose: Coordinates and returns the theme preferences processing result handled by applyThemePreferences.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `resolveThemeMode`、`resolveThemeFromSystem`、`handler`。
 * - Callees: `resolveThemeMode`, `resolveThemeFromSystem`, `handler`.
 * - 变量说明: 无显式入参；`cfg`, `mode`, `theme` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `cfg`, `mode`, `theme` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `applyThemePreferences`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `applyThemePreferences` through the existing returned object.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: apply | 主题 | preferences | apply | theme | preferences | call chain | 错误处理 | error handling | 复用
 */
function applyThemePreferences() {
  const cfg = (window.api && window.api.config) ? window.api.config.get() : null
  const mode = resolveThemeMode(cfg)
  const theme = mode === 'system' ? resolveThemeFromSystem() : mode
  document.documentElement.setAttribute('data-bs-theme', theme)
  document.documentElement.setAttribute('data-theme', theme)

  if (!themeMediaBound) {
    try {
      themeMedia = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null
      /**
 * - 函数: `handler`
 * - Function: `handler`
 * - 作用: 梳理并返回handler负责的handler局部处理结果。
 * - Purpose: Coordinates and returns the handler processing result handled by handler.
 * - 调用方: `applyThemePreferences`。
 * - Callers: `applyThemePreferences`.
 * - 被调方: `resolveThemeMode`、`resolveThemeFromSystem`。
 * - Callees: `resolveThemeMode`, `resolveThemeFromSystem`.
 * - 变量说明: 无显式入参；`cfg2`, `mode2`, `theme2` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `cfg2`, `mode2`, `theme2` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 在当前模块内部直接调用 `handler(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `handler(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: handler | handler | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
      const handler = () => {
        const cfg2 = (window.api && window.api.config) ? window.api.config.get() : null
        const mode2 = resolveThemeMode(cfg2)
        if (mode2 !== 'system') return
        const theme2 = resolveThemeFromSystem()
        document.documentElement.setAttribute('data-bs-theme', theme2)
        document.documentElement.setAttribute('data-theme', theme2)
      }
      if (themeMedia) {
        if (typeof themeMedia.addEventListener === 'function') themeMedia.addEventListener('change', handler)
        else if (typeof themeMedia.addListener === 'function') themeMedia.addListener(handler)
        themeMediaBound = true
      }
    } catch {}
  }
}

/**
 * - 函数: `parseQuery`
 * - Function: `parseQuery`
 * - 作用: 解析query原始输入，并提取结构化结果供后续逻辑使用。
 * - Purpose: Parses the raw query input and extracts a structured result for downstream logic.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；`qs`, `requestId`, `defaultKeep` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `qs`, `requestId`, `defaultKeep` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `parseQuery`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `parseQuery` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 解析 | query | parse | query | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function parseQuery() {
  const qs = new URLSearchParams(location.search || '')
  const requestId = qs.get('requestId') || ''
  const defaultKeep = qs.get('defaultKeep') === '1'
  return { requestId, defaultKeep }
}

window.addEventListener('DOMContentLoaded', () => {
  applyThemePreferences()
  setTheme()

  try {
    const locale = window.api && window.api.i18n && window.api.i18n.getLocale ? window.api.i18n.getLocale() : 'zh-CN'
    document.documentElement.lang = locale || 'zh-CN'
  } catch {}

  const { requestId, defaultKeep } = parseQuery()

  const titleEl = document.getElementById('prompt-title')
  const msgEl = document.getElementById('prompt-message')
  const hintEl = document.getElementById('prompt-hint')
  const btnYes = document.getElementById('btn-yes')
  const btnNo = document.getElementById('btn-no')
  const btnClose = document.getElementById('prompt-close')

  if (titleEl) titleEl.textContent = t('tray_exit_keep_service_title')
  if (msgEl) msgEl.textContent = t('tray_exit_keep_service_message')
  if (hintEl) hintEl.textContent = t('tray_exit_keep_service_hint')
  if (btnYes) btnYes.textContent = t('tray_exit_keep_service_yes')
  if (btnNo) btnNo.textContent = t('tray_exit_keep_service_no')

  let submitted = false
  /**
 * - 函数: `submit`
 * - Function: `submit`
 * - 作用: 梳理并返回submit负责的提交局部处理结果。
 * - Purpose: Coordinates and returns the submit processing result handled by submit.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `keep` 为当前流程传入的keep。
 * - Variables: `keep` is the incoming keep for this flow.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `submit`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `submit` through the existing returned object.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 提交 | submit | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  const submit = (keep) => {
    if (submitted) return
    submitted = true
    if (btnYes) btnYes.disabled = true
    if (btnNo) btnNo.disabled = true
    if (btnClose) btnClose.disabled = true
    try {
      if (window.api && window.api.trayExitPrompt && window.api.trayExitPrompt.submit) {
        window.api.trayExitPrompt.submit(requestId, keep)
      }
    } catch {}
  }

  if (btnYes) btnYes.onclick = () => submit(true)
  if (btnNo) btnNo.onclick = () => submit(false)
  if (btnClose) btnClose.onclick = () => { try { window.close() } catch {} }

  window.addEventListener('keydown', (e) => {
    const key = e && e.key ? e.key : ''
    if (key === 'Escape') { try { window.close() } catch {} }
    if (key === 'Enter') submit(defaultKeep)
  })

  if (defaultKeep) {
    try { if (btnYes) btnYes.focus() } catch {}
  } else {
    try { if (btnNo) btnNo.focus() } catch {}
  }
})
