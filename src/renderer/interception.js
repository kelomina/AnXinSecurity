let current = null
let confirmState = null
let detailsInitialized = false
let jsonLines = null
let jsonRendered = 0
let jsonScrollBound = false

/**
 * - 函数: `t`
 * - Function: `t`
 * - 作用: 梳理并返回t负责的t局部处理结果。
 * - Purpose: Coordinates and returns the t processing result handled by t.
 * - 调用方: `模块顶层流程`、`severityLabel`、`severityBadge`、`formatRuleId`、`render`、`ensureDetailsLazy`。
 * - Callers: `模块顶层流程`, `severityLabel`, `severityBadge`, `formatRuleId`, `render`, `ensureDetailsLazy`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `key` 为当前流程传入的键；`fn` 为函数内部派生的中间状态。
 * - Variables: `key` is the incoming key for this flow; `fn` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `t`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `t` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: t | t | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function t(key) {
  const fn = window.api && window.api.i18n && window.api.i18n.t
  return fn ? fn(key) : key
}

/**
 * - 函数: `stopKeys`
 * - Function: `stopKeys`
 * - 作用: 梳理并返回stopKeys负责的keys局部处理结果。
 * - Purpose: Coordinates and returns the keys processing result handled by stopKeys.
 * - 调用方: `模块顶层流程`、`init`。
 * - Callers: `模块顶层流程`, `init`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `stopKeys`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `stopKeys` through the existing returned object.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: stop | keys | stop | keys | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function stopKeys() {
  window.addEventListener('keydown', (e) => {
    try {
      e.preventDefault()
      e.stopPropagation()
    } catch {}
  }, true)
}

/**
 * - 函数: `resolveThemeMode`
 * - Function: `resolveThemeMode`
 * - 作用: 解析主题mode，并按当前运行环境返回优先可用的结果。
 * - Purpose: Resolves the theme mode and returns the highest-priority usable result for the current runtime.
 * - 调用方: `模块顶层流程`、`applyTheme`。
 * - Callers: `模块顶层流程`, `applyTheme`.
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
 * - 调用方: `模块顶层流程`、`applyTheme`。
 * - Callers: `模块顶层流程`, `applyTheme`.
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

let themeMedia = null
let themeMediaBound = false

/**
 * - 函数: `applyTheme`
 * - Function: `applyTheme`
 * - 作用: 梳理并返回applyTheme负责的主题局部处理结果。
 * - Purpose: Coordinates and returns the theme processing result handled by applyTheme.
 * - 调用方: `模块顶层流程`、`init`。
 * - Callers: `模块顶层流程`, `init`.
 * - 被调方: `resolveThemeMode`、`resolveThemeFromSystem`。
 * - Callees: `resolveThemeMode`, `resolveThemeFromSystem`.
 * - 变量说明: 无显式入参；`cfg`, `mode`, `theme` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `cfg`, `mode`, `theme` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `applyTheme`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `applyTheme` through the existing returned object.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: apply | 主题 | apply | theme | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function applyTheme() {
  const cfg = (window.api && window.api.config) ? window.api.config.get() : null
  const mode = resolveThemeMode(cfg)
  const theme = mode === 'system' ? resolveThemeFromSystem() : mode
  document.documentElement.dataset.theme = theme
  document.documentElement.dataset.bsTheme = theme
  if (mode === 'system' && !themeMediaBound) {
    themeMediaBound = true
    try {
      themeMedia = window.matchMedia('(prefers-color-scheme: dark)')
      if (themeMedia && typeof themeMedia.addEventListener === 'function') {
        themeMedia.addEventListener('change', () => applyTheme())
      }
    } catch {}
  }
}

/**
 * - 函数: `setText`
 * - Function: `setText`
 * - 作用: 设置文本状态，并同步影响当前模块内的后续判断。
 * - Purpose: Sets the text state and synchronizes the downstream decisions made inside this module.
 * - 调用方: `模块顶层流程`、`render`、`refreshSigner`、`showConfirm`、`init`。
 * - Callers: `模块顶层流程`, `render`, `refreshSigner`, `showConfirm`, `init`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `id` 为当前流程传入的id；`text` 为当前流程传入的文本；`el` 为函数内部派生的中间状态。
 * - Variables: `id` is the incoming id for this flow; `text` is the incoming text for this flow; `el` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `setText`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `setText` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 设置 | 文本 | set | text | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function setText(id, text) {
  const el = document.getElementById(id)
  if (!el) return
  el.textContent = typeof text === 'string' ? text : String(text || '')
}

/**
 * - 函数: `severityLabel`
 * - Function: `severityLabel`
 * - 作用: 梳理并返回severityLabel负责的label局部处理结果。
 * - Purpose: Coordinates and returns the label processing result handled by severityLabel.
 * - 调用方: `模块顶层流程`、`render`。
 * - Callers: `模块顶层流程`, `render`.
 * - 被调方: `t`、`Number.isFinite`。
 * - Callees: `t`, `Number.isFinite`.
 * - 变量说明: `sev` 为当前流程传入的sev；`n` 为函数内部派生的中间状态。
 * - Variables: `sev` is the incoming sev for this flow; `n` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `severityLabel`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `severityLabel` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: severity | label | severity | label | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function severityLabel(sev) {
  const n = Number.isFinite(sev) ? sev : parseInt(String(sev), 10)
  if (!Number.isFinite(n)) return t('intercept_level_unknown')
  if (n >= 5) return t('intercept_level_critical')
  if (n === 4) return t('intercept_level_high')
  if (n === 3) return t('intercept_level_medium')
  if (n <= 2) return t('intercept_level_low')
  return t('intercept_level_unknown')
}

/**
 * - 函数: `severityBadge`
 * - Function: `severityBadge`
 * - 作用: 梳理并返回severityBadge负责的badge局部处理结果。
 * - Purpose: Coordinates and returns the badge processing result handled by severityBadge.
 * - 调用方: `模块顶层流程`、`render`。
 * - Callers: `模块顶层流程`, `render`.
 * - 被调方: `t`、`Number.isFinite`。
 * - Callees: `t`, `Number.isFinite`.
 * - 变量说明: `sev` 为当前流程传入的sev；`n` 为函数内部派生的中间状态。
 * - Variables: `sev` is the incoming sev for this flow; `n` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `severityBadge`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `severityBadge` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: severity | badge | severity | badge | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function severityBadge(sev) {
  const n = Number.isFinite(sev) ? sev : parseInt(String(sev), 10)
  if (!Number.isFinite(n)) return { text: t('intercept_level_unknown'), cls: 'bg-secondary' }
  if (n >= 5) return { text: t('intercept_level_critical'), cls: 'bg-danger' }
  if (n === 4) return { text: t('intercept_level_high'), cls: 'bg-warning text-dark' }
  if (n === 3) return { text: t('intercept_level_medium'), cls: 'bg-warning-subtle text-warning-emphasis' }
  if (n <= 2) return { text: t('intercept_level_low'), cls: 'bg-secondary' }
  return { text: t('intercept_level_unknown'), cls: 'bg-secondary' }
}

/**
 * - 函数: `formatRuleId`
 * - Function: `formatRuleId`
 * - 作用: 格式化ruleid内容，输出更适合展示、日志或后续传输的结构。
 * - Purpose: Formats the rule id content into a structure that is easier to display, log, or transmit.
 * - 调用方: `模块顶层流程`、`render`。
 * - Callers: `模块顶层流程`, `render`.
 * - 被调方: `t`。
 * - Callees: `t`.
 * - 变量说明: `p` 为当前流程传入的p；`m`, `ruleId` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `m`, `ruleId` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `formatRuleId`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `formatRuleId` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 格式化 | rule | id | format | rule | id | call chain | 错误处理 | error handling | 复用
 */
function formatRuleId(p) {
  const m = p && p.match && typeof p.match === 'object' ? p.match : null
  const ruleId = m && typeof m.ruleId === 'string' ? m.ruleId : ''
  if (!ruleId) return t('unknown')
  const map = {
    unsigned_dll: t('intercept_rule_unsigned_dll'),
    process_signature_invalid: t('intercept_rule_process_signature_invalid'),
    dll_signature_invalid: t('intercept_rule_dll_signature_invalid'),
    process_and_dll_signature_invalid: t('intercept_rule_process_and_dll_signature_invalid')
  }
  return map[ruleId] || ruleId
}

/**
 * - 函数: `render`
 * - Function: `render`
 * - 作用: 梳理并返回render负责的render局部处理结果。
 * - Purpose: Coordinates and returns the render processing result handled by render.
 * - 调用方: `模块顶层流程`、`init`。
 * - Callers: `模块顶层流程`, `init`.
 * - 被调方: `remove`、`formatRuleId`、`setText`、`t`、`severityBadge`、`severityLabel`。
 * - Callees: `remove`, `formatRuleId`, `setText`, `t`, `severityBadge`, `severityLabel`.
 * - 变量说明: `payload` 为当前流程传入的载荷；`el`, `Collapse` 为函数内部派生的中间状态。
 * - Variables: `payload` is the incoming payload for this flow; `el`, `Collapse` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `render`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `render` through the existing returned object.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: render | render | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function render(payload) {
  current = payload && typeof payload === 'object' ? payload : null
  detailsInitialized = false
  jsonLines = null
  jsonRendered = 0
  try {
    const el = document.getElementById('ix-details')
    if (el) {
      try {
        const Collapse = window.bootstrap && window.bootstrap.Collapse ? window.bootstrap.Collapse : null
        if (Collapse && typeof Collapse.getOrCreateInstance === 'function') {
          const inst = Collapse.getOrCreateInstance(el, { toggle: false })
          if (inst && typeof inst.hide === 'function') inst.hide()
        }
      } catch {}
      el.classList.remove('show')
    }
    const btn = document.querySelector('button.accordion-button[data-bs-target="#ix-details"]')
    if (btn) {
      btn.classList.add('collapsed')
      btn.setAttribute('aria-expanded', 'false')
    }
  } catch {}
  const p = current || {}
  const pid = Number.isFinite(p.pid) ? p.pid : null
  const proc = p.process && typeof p.process === 'object' ? p.process : {}
  const procName = typeof proc.name === 'string' ? proc.name : ''
  const procImage = typeof proc.imagePath === 'string' ? proc.imagePath : ''
  const threatType = typeof p.threatType === 'string' && p.threatType ? p.threatType : formatRuleId(p)
  const severity = Number.isFinite(p.severity) ? p.severity : 4
  const recommendAction = typeof p.recommendAction === 'string' ? p.recommendAction : 'block'

  setText('ix-title', t('intercept_title'))
  setText('ix-sub', t('intercept_desc_action_required'))

  const badge = document.getElementById('ix-severity-badge')
  if (badge) {
    const s = severityBadge(severity)
    badge.className = `ix-badge ${s.cls}`
    badge.textContent = s.text
  }

  setText('ix-k-threat', t('intercept_threat_type'))
  setText('ix-v-threat', threatType)
  setText('ix-k-level', t('intercept_danger_level'))
  setText('ix-v-level', severityLabel(severity))
  setText('ix-k-reco', t('intercept_recommend'))
  setText('ix-v-reco', recommendAction === 'allow' ? t('intercept_reco_allow') : t('intercept_reco_block'))

  setText('ix-details-title', t('intercept_details'))
  setText('ix-details-hint', t('intercept_details_hint'))
  setText('ix-k-pid', t('intercept_label_pid'))
  setText('ix-v-pid', pid != null ? String(pid) : t('unknown'))
  setText('ix-k-proc', t('intercept_label_process'))
  setText('ix-v-proc', (procName || procImage) ? `${procName}${procName && procImage ? ' ' : ''}${procImage ? '(' + procImage + ')' : ''}` : t('unknown'))
  setText('ix-k-rule', t('intercept_label_rule'))
  setText('ix-v-rule', formatRuleId(p))
  setText('ix-k-signer', t('intercept_label_signer'))
  setText('ix-v-signer', t('intercept_signer_loading'))

  const pre = document.getElementById('ix-json')
  if (pre) {
    pre.textContent = t('intercept_details_lazy_hint')
  }

  const btnAllow = document.getElementById('ix-btn-allow')
  const btnBlock = document.getElementById('ix-btn-block')
  if (btnAllow) {
    btnAllow.textContent = t('intercept_btn_allow')
    btnAllow.disabled = pid == null
    btnAllow.onclick = async () => {
      if (pid == null) return
      try {
        const ok = await window.api.intercept.action('allow', pid)
        if (!ok) return alert(t('intercept_action_failed'))
      } catch {
        return alert(t('intercept_action_failed'))
      }
    }
  }
  if (btnBlock) {
    btnBlock.textContent = t('intercept_btn_block')
    btnBlock.disabled = pid == null
    btnBlock.onclick = () => {
      if (pid == null) return
      showConfirm(pid)
    }
  }

  refreshSigner(procImage)
}

/**
 * - 函数: `safePreviewObject`
 * - Function: `safePreviewObject`
 * - 作用: 梳理并返回safePreviewObject负责的previewobject局部处理结果。
 * - Purpose: Coordinates and returns the preview object processing result handled by safePreviewObject.
 * - 调用方: `模块顶层流程`、`ensureDetailsLazy`。
 * - Callers: `模块顶层流程`, `ensureDetailsLazy`.
 * - 被调方: `push`、`Array.isArray`。
 * - Callees: `push`, `Array.isArray`.
 * - 变量说明: `value` 为当前流程传入的值；`depth` 为当前流程传入的depth；`s`, `head` 为函数内部派生的中间状态。
 * - Variables: `value` is the incoming value for this flow; `depth` is the incoming depth for this flow; `s`, `head` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `safePreviewObject`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `safePreviewObject` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: safe | preview | object | safe | preview | object | call chain | 错误处理 | error handling | 复用
 */
function safePreviewObject(value, depth = 0) {
  if (depth > 6) return '[Object]'
  if (value == null) return value
  if (typeof value === 'string') {
    const s = value
    if (s.length > 2048) return s.slice(0, 2048) + '…'
    return s
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value
  if (Array.isArray(value)) {
    const head = value.slice(0, 200).map(v => safePreviewObject(v, depth + 1))
    if (value.length > 200) head.push(`…(${value.length - 200} more)`)
    return head
  }
  if (typeof value === 'object') {
    const out = {}
    const keys = Object.keys(value).slice(0, 200)
    for (const k of keys) out[k] = safePreviewObject(value[k], depth + 1)
    if (Object.keys(value).length > 200) out._truncated = true
    return out
  }
  return String(value)
}

/**
 * - 函数: `ensureDetailsLazy`
 * - Function: `ensureDetailsLazy`
 * - 作用: 确保detailslazy已初始化且可复用，必要时执行一次性准备逻辑。
 * - Purpose: Ensures the details lazy is initialized and reusable, performing one-time setup when necessary.
 * - 调用方: `模块顶层流程`、`init`。
 * - Callers: `模块顶层流程`, `init`.
 * - 被调方: `t`、`safePreviewObject`、`appendJsonChunk`、`bindJsonScroll`、`JSON.stringify`。
 * - Callees: `t`, `safePreviewObject`, `appendJsonChunk`, `bindJsonScroll`, `JSON.stringify`.
 * - 变量说明: 无显式入参；`pre`, `p`, `obj` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `pre`, `p`, `obj` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `ensureDetailsLazy`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `ensureDetailsLazy` through the existing returned object.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 确保 | details | lazy | ensure | details | lazy | call chain | 错误处理 | error handling | 复用
 */
function ensureDetailsLazy() {
  if (detailsInitialized) return
  detailsInitialized = true
  const pre = document.getElementById('ix-json')
  if (!pre) return
  const p = current && typeof current === 'object' ? current : null
  const obj = p && p.event && typeof p.event === 'object' ? p.event : null
  if (!obj) { pre.textContent = ''; return }
  pre.textContent = t('intercept_details_loading')
  setTimeout(() => {
    try {
      const preview = safePreviewObject(obj, 0)
      const text = JSON.stringify(preview, null, 2) || ''
      jsonLines = text.split('\n')
      jsonRendered = 0
      pre.textContent = ''
      appendJsonChunk()
      bindJsonScroll(pre)
    } catch {
      pre.textContent = ''
    }
  }, 0)
}

/**
 * - 函数: `appendJsonChunk`
 * - Function: `appendJsonChunk`
 * - 作用: 向JSON 数据chunk追加记录，供后续诊断、追踪或持久化链路复用。
 * - Purpose: Appends records to the JSON payload chunk so diagnostics, tracing, or persistence flows can reuse them.
 * - 调用方: `ensureDetailsLazy`、`模块顶层流程`、`bindJsonScroll`。
 * - Callers: `ensureDetailsLazy`, `模块顶层流程`, `bindJsonScroll`.
 * - 被调方: `t`、`Array.isArray`、`Math.min`。
 * - Callees: `t`, `Array.isArray`, `Math.min`.
 * - 变量说明: 无显式入参；`pre`, `lines`, `end` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `pre`, `lines`, `end` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `appendJsonChunk`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `appendJsonChunk` through the existing returned object.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 追加 | JSON 数据 | chunk | append | JSON payload | chunk | call chain | 错误处理 | error handling | 复用
 */
function appendJsonChunk() {
  const pre = document.getElementById('ix-json')
  if (!pre) return
  const lines = Array.isArray(jsonLines) ? jsonLines : null
  if (!lines || jsonRendered >= lines.length) return
  const end = Math.min(lines.length, jsonRendered + 200)
  const chunk = lines.slice(jsonRendered, end).join('\n')
  pre.textContent = pre.textContent ? (pre.textContent + '\n' + chunk) : chunk
  jsonRendered = end
  if (jsonRendered >= lines.length) {
    if (lines.length >= 200) pre.textContent += `\n${t('intercept_details_loaded_all')}`

    // Add click-to-copy handler
    pre.style.cursor = 'pointer'
    pre.title = t('intercept_details_copy_hint') || 'Click to copy'
    pre.onclick = async () => {
      try {
        await navigator.clipboard.writeText(pre.textContent)
        const originalTitle = pre.title
        pre.title = t('intercept_details_copied') || 'Copied!'
        
        // Visual feedback
        const originalBg = pre.style.backgroundColor
        pre.style.backgroundColor = 'rgba(40, 167, 69, 0.2)' // Light green
        setTimeout(() => {
          pre.style.backgroundColor = originalBg
          pre.title = originalTitle
        }, 1000)
      } catch (err) {
        console.error('Failed to copy: ', err)
      }
    }
  }
}

/**
 * - 函数: `bindJsonScroll`
 * - Function: `bindJsonScroll`
 * - 作用: 梳理并返回bindJsonScroll负责的JSON 数据scroll局部处理结果。
 * - Purpose: Coordinates and returns the JSON payload scroll processing result handled by bindJsonScroll.
 * - 调用方: `ensureDetailsLazy`、`模块顶层流程`。
 * - Callers: `ensureDetailsLazy`, `模块顶层流程`.
 * - 被调方: `appendJsonChunk`。
 * - Callees: `appendJsonChunk`.
 * - 变量说明: `pre` 为当前流程传入的pre；`nearBottom` 为函数内部派生的中间状态。
 * - Variables: `pre` is the incoming pre for this flow; `nearBottom` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `bindJsonScroll`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `bindJsonScroll` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: bind | JSON 数据 | scroll | bind | JSON payload | scroll | call chain | 错误处理 | error handling | 复用
 */
function bindJsonScroll(pre) {
  if (jsonScrollBound) return
  jsonScrollBound = true
  pre.addEventListener('scroll', () => {
    const nearBottom = (pre.scrollTop + pre.clientHeight) >= (pre.scrollHeight - 64)
    if (!nearBottom) return
    appendJsonChunk()
  }, { passive: true })
}

/**
 * - 函数: `refreshSigner`
 * - Function: `refreshSigner`
 * - 作用: 梳理并返回refreshSigner负责的签名者局部处理结果。
 * - Purpose: Coordinates and returns the signer processing result handled by refreshSigner.
 * - 调用方: `render`、`模块顶层流程`。
 * - Callers: `render`, `模块顶层流程`.
 * - 被调方: `setText`、`t`、`push`。
 * - Callees: `setText`, `t`, `push`.
 * - 变量说明: `procImage` 为当前流程传入的procimage；`info`, `subject` 为函数内部派生的中间状态。
 * - Variables: `procImage` is the incoming proc image for this flow; `info`, `subject` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `refreshSigner`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `refreshSigner` through the existing returned object.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 刷新 | 签名者 | refresh | signer | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
async function refreshSigner(procImage) {
  if (!procImage) {
    setText('ix-v-signer', t('unknown'))
    return
  }
  if (!window.api || !window.api.intercept || typeof window.api.intercept.getSignerInfo !== 'function') {
    setText('ix-v-signer', t('unknown'))
    return
  }
  try {
    const info = await window.api.intercept.getSignerInfo(procImage)
    if (!info || typeof info !== 'object') {
      setText('ix-v-signer', t('intercept_signer_none'))
      return
    }
    const subject = typeof info.subject === 'string' ? info.subject : ''
    const issuer = typeof info.issuer === 'string' ? info.issuer : ''
    const thumb = typeof info.thumbprint === 'string' ? info.thumbprint : ''
    const parts = []
    if (subject) parts.push(subject)
    if (issuer) parts.push(issuer)
    if (thumb) parts.push(thumb)
    setText('ix-v-signer', parts.length ? parts.join(' | ') : t('intercept_signer_none'))
  } catch {
    setText('ix-v-signer', t('unknown'))
  }
}

/**
 * - 函数: `showConfirm`
 * - Function: `showConfirm`
 * - 作用: 梳理并返回showConfirm负责的确认框局部处理结果。
 * - Purpose: Coordinates and returns the confirm dialog processing result handled by showConfirm.
 * - 调用方: `render`、`模块顶层流程`。
 * - Callers: `render`, `模块顶层流程`.
 * - 被调方: `setText`、`t`、`remove`、`hideConfirm`、`action`。
 * - Callees: `setText`, `t`, `remove`, `hideConfirm`, `action`.
 * - 变量说明: `pid` 为当前流程传入的pid；`wrap`, `btnCancel` 为函数内部派生的中间状态。
 * - Variables: `pid` is the incoming pid for this flow; `wrap`, `btnCancel` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `showConfirm`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `showConfirm` through the existing returned object.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: show | 确认框 | show | confirm dialog | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function showConfirm(pid) {
  confirmState = { pid }
  setText('ix-confirm-title', t('intercept_confirm_block_title'))
  setText('ix-confirm-text', t('intercept_confirm_block_text'))
  setText('ix-confirm-cancel', t('cancel'))
  setText('ix-confirm-ok', t('intercept_confirm_block_btn'))
  const wrap = document.getElementById('ix-confirm')
  if (wrap) wrap.classList.remove('ix-hidden')
  const btnCancel = document.getElementById('ix-confirm-cancel')
  const btnOk = document.getElementById('ix-confirm-ok')
  if (btnCancel) btnCancel.onclick = () => hideConfirm()
  if (btnOk) btnOk.onclick = async () => {
    const s = confirmState
    hideConfirm()
    if (!s || !s.pid) return
    try {
      const ok = await window.api.intercept.action('block', s.pid)
      if (!ok) return alert(t('intercept_action_failed'))
    } catch {
      return alert(t('intercept_action_failed'))
    }
  }
}

/**
 * - 函数: `hideConfirm`
 * - Function: `hideConfirm`
 * - 作用: 梳理并返回hideConfirm负责的确认框局部处理结果。
 * - Purpose: Coordinates and returns the confirm dialog processing result handled by hideConfirm.
 * - 调用方: `showConfirm`、`模块顶层流程`、`init`。
 * - Callers: `showConfirm`, `模块顶层流程`, `init`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；`wrap` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `wrap` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `hideConfirm`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `hideConfirm` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: hide | 确认框 | hide | confirm dialog | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function hideConfirm() {
  confirmState = null
  const wrap = document.getElementById('ix-confirm')
  if (wrap) wrap.classList.add('ix-hidden')
}

/**
 * - 函数: `init`
 * - Function: `init`
 * - 作用: 梳理并返回init负责的init局部处理结果。
 * - Purpose: Coordinates and returns the init processing result handled by init.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `stopKeys`、`applyTheme`、`setText`、`t`、`ensureDetailsLazy`、`hideConfirm`。
 * - Callees: `stopKeys`, `applyTheme`, `setText`, `t`, `ensureDetailsLazy`, `hideConfirm`.
 * - 变量说明: 无显式入参；`el`, `onShow` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `el`, `onShow` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `init`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `init` through the existing returned object.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: init | init | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function init() {
  stopKeys()
  try { applyTheme() } catch {}
  setText('ix-v-signer', t('unknown'))

  try {
    const el = document.getElementById('ix-details')
    if (el && typeof el.addEventListener === 'function') {
      el.addEventListener('shown.bs.collapse', () => ensureDetailsLazy())
    }
  } catch {}

  const onShow = window.api && window.api.intercept && typeof window.api.intercept.onShow === 'function'
    ? window.api.intercept.onShow
    : null
  if (onShow) {
    onShow((payload) => {
      try { hideConfirm() } catch {}
      render(payload)
    })
  }
}

init()
