function t(key) {
  const fn = window.api && window.api.i18n && window.api.i18n.t
  return fn ? fn(key) : key
}

function setTheme() {
  const cfg = (window.api && window.api.config) ? window.api.config.get() : { themeColor: '#1677ff' }
  const color = cfg.themeColor || '#1677ff'
  document.documentElement.style.setProperty('--theme-color', color)
}

function parseQuery() {
  const qs = new URLSearchParams(location.search || '')
  const requestId = qs.get('requestId') || ''
  const defaultKeep = qs.get('defaultKeep') === '1'
  return { requestId, defaultKeep }
}

window.addEventListener('DOMContentLoaded', () => {
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
  if (btnClose) btnClose.onclick = () => submit(null)

  window.addEventListener('keydown', (e) => {
    const key = e && e.key ? e.key : ''
    if (key === 'Escape') submit(null)
    if (key === 'Enter') submit(defaultKeep)
  })

  if (defaultKeep) {
    try { if (btnYes) btnYes.focus() } catch {}
  } else {
    try { if (btnNo) btnNo.focus() } catch {}
  }
})
