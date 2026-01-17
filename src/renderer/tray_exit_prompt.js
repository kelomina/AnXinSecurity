function t(key) {
  const fn = window.api && window.api.i18n && window.api.i18n.t
  return fn ? fn(key) : key
}

function setTheme() {
  const cfg = (window.api && window.api.config) ? window.api.config.get() : { themeColor: '#1677ff' }
  const color = cfg.themeColor || '#1677ff'
  document.documentElement.style.setProperty('--theme-color', color)
}

let themeMedia = null
let themeMediaBound = false

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

function applyThemePreferences() {
  const cfg = (window.api && window.api.config) ? window.api.config.get() : null
  const mode = resolveThemeMode(cfg)
  const theme = mode === 'system' ? resolveThemeFromSystem() : mode
  document.documentElement.setAttribute('data-bs-theme', theme)
  document.documentElement.setAttribute('data-theme', theme)

  if (!themeMediaBound) {
    try {
      themeMedia = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null
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
