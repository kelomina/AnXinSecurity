let current = null
let confirmState = null
let detailsInitialized = false
let jsonLines = null
let jsonRendered = 0
let jsonScrollBound = false

function t(key) {
  const fn = window.api && window.api.i18n && window.api.i18n.t
  return fn ? fn(key) : key
}

function stopKeys() {
  window.addEventListener('keydown', (e) => {
    try {
      e.preventDefault()
      e.stopPropagation()
    } catch {}
  }, true)
}

function resolveThemeMode(cfg) {
  const m = cfg && cfg.ui && typeof cfg.ui.themeMode === 'string' ? cfg.ui.themeMode.trim() : ''
  if (m === 'dark' || m === 'light' || m === 'system') return m
  return 'system'
}

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

function setText(id, text) {
  const el = document.getElementById(id)
  if (!el) return
  el.textContent = typeof text === 'string' ? text : String(text || '')
}

function severityLabel(sev) {
  const n = Number.isFinite(sev) ? sev : parseInt(String(sev), 10)
  if (!Number.isFinite(n)) return t('intercept_level_unknown')
  if (n >= 5) return t('intercept_level_critical')
  if (n === 4) return t('intercept_level_high')
  if (n === 3) return t('intercept_level_medium')
  if (n <= 2) return t('intercept_level_low')
  return t('intercept_level_unknown')
}

function severityBadge(sev) {
  const n = Number.isFinite(sev) ? sev : parseInt(String(sev), 10)
  if (!Number.isFinite(n)) return { text: t('intercept_level_unknown'), cls: 'bg-secondary' }
  if (n >= 5) return { text: t('intercept_level_critical'), cls: 'bg-danger' }
  if (n === 4) return { text: t('intercept_level_high'), cls: 'bg-warning text-dark' }
  if (n === 3) return { text: t('intercept_level_medium'), cls: 'bg-warning-subtle text-warning-emphasis' }
  if (n <= 2) return { text: t('intercept_level_low'), cls: 'bg-secondary' }
  return { text: t('intercept_level_unknown'), cls: 'bg-secondary' }
}

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

function bindJsonScroll(pre) {
  if (jsonScrollBound) return
  jsonScrollBound = true
  pre.addEventListener('scroll', () => {
    const nearBottom = (pre.scrollTop + pre.clientHeight) >= (pre.scrollHeight - 64)
    if (!nearBottom) return
    appendJsonChunk()
  }, { passive: true })
}

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

function hideConfirm() {
  confirmState = null
  const wrap = document.getElementById('ix-confirm')
  if (wrap) wrap.classList.add('ix-hidden')
}

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
