const state = {
  page: 'overview',
  lastScanAt: null,
  scanning: false,
  scanSession: null,
  pendingAction: null,
  threatItems: [],
  maxThreatRows: 60,
  autoFollowBottom: false,
  tabCache: {},
  quarantineItems: [],
  exclusionsItems: [],
  behavior: {
    pid: null,
    loading: false,
    processSnapshotId: 0,
    processSnapshotActiveId: 0
  },
  behaviorLifecycle: {
    pid: null,
    loading: false,
    process: null,
    events: [],
    view: 'tree'
  },
  engineStatus: 'ok',
  metricsFromCache: false
}

let behaviorDetailModal = null
let interceptModal = null
let interceptLastPayload = null

function setTheme() {
  const cfg = (window.api && window.api.config) ? window.api.config.get() : { themeColor: '#1677ff' }
  const color = cfg.themeColor || '#1677ff'
  document.documentElement.style.setProperty('--theme-color', color)
  console.log('渲染进程: 设置主题色', color)
}

function t(key) {
  const fn = window.api && window.api.i18n && window.api.i18n.t
  return fn ? fn(key) : key
}
if (typeof window !== 'undefined') window.t = t

function escapeHtml(s) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }
  return String(s).replace(/[&<>"']/g, c => map[c] || c)
}

let overviewEtwLogUnsub = null
let lastOverviewEtwFileEventText = ''
let overviewEtwFileEventUpdatePending = false

function formatEtwFileOpLabel(typ) {
  const t2 = typeof typ === 'string' ? typ.trim() : ''
  if (!t2) return ''
  const k = t2.toLowerCase()
  if (k === 'create' || k === 'open') return '打开'
  if (k === 'delete') return '删除'
  if (k === 'rename') return '重命名'
  return t2
}

function formatEtwFileEventText(ev) {
  const e = ev && typeof ev === 'object' ? ev : null
  if (!e) return ''
  if (e.provider !== 'File') return ''
  const d = e.data && typeof e.data === 'object' ? e.data : null
  if (!d) return ''
  const fileName = typeof d.fileName === 'string' ? d.fileName : ''
  const typ = typeof d.type === 'string' ? d.type : ''
  if (!fileName || !typ) return ''
  const op = formatEtwFileOpLabel(typ)
  if (!op) return ''
  return `[${op}]${fileName}`
}

function updateOverviewEtwFileEventUi() {
  const row = document.getElementById('overview-etw-file-event-row')
  const badge = document.getElementById('overview-etw-file-event')
  if (!row || !badge) return
  const text = lastOverviewEtwFileEventText
  if (!text) {
    row.style.display = 'block'
    badge.textContent = '等待 ETW 文件事件...'
    badge.title = ''
    return
  }
  row.style.display = 'block'
  badge.textContent = text
  badge.title = text
}

function initOverviewEtwFileEventTag() {
  if (overviewEtwLogUnsub) return
  const onLog = window.api && window.api.logs && typeof window.api.logs.onLog === 'function' ? window.api.logs.onLog : null
  if (!onLog) return
  overviewEtwLogUnsub = onLog((ev) => {
    const text = formatEtwFileEventText(ev)
    if (!text) return
    lastOverviewEtwFileEventText = text
    if (!overviewEtwFileEventUpdatePending) {
      overviewEtwFileEventUpdatePending = true
      setTimeout(() => {
        overviewEtwFileEventUpdatePending = false
        uiThread(() => updateOverviewEtwFileEventUi())
      }, 1000)
    }
  })
}

function ensureInterceptModal() {
  const el = document.getElementById('intercept-modal')
  if (!el) return null
  if (!interceptModal) {
    interceptModal = new bootstrap.Modal(el, { backdrop: 'static', keyboard: false })
  }
  return interceptModal
}

function formatInterceptRule(payload) {
  const p = payload && typeof payload === 'object' ? payload : null
  const m = p && p.match && typeof p.match === 'object' ? p.match : null
  if (!m) return ''
  const ruleId = typeof m.ruleId === 'string' ? m.ruleId : ''
  if (ruleId === 'unsigned_dll') return t('intercept_rule_unsigned_dll')
  const provider = typeof m.provider === 'string' ? m.provider : ''
  const op = typeof m.op === 'string' ? m.op : ''
  if (ruleId) return ruleId
  return provider && op ? `${provider}:${op}` : ''
}

function showInterceptModal(payload) {
  interceptLastPayload = payload
  const m = ensureInterceptModal()
  if (!m) return

  const titleEl = document.getElementById('intercept-title')
  const descEl = document.getElementById('intercept-desc')
  const labelPid = document.getElementById('intercept-label-pid')
  const pidEl = document.getElementById('intercept-pid')
  const labelProc = document.getElementById('intercept-label-process')
  const procEl = document.getElementById('intercept-process')
  const labelRule = document.getElementById('intercept-label-rule')
  const ruleEl = document.getElementById('intercept-rule')
  const pre = document.getElementById('intercept-event-json')
  const btnResume = document.getElementById('intercept-btn-resume')
  const btnTerminate = document.getElementById('intercept-btn-terminate')

  const p = payload && typeof payload === 'object' ? payload : {}
  const pid = Number.isFinite(p.pid) ? p.pid : null
  const proc = p.process && typeof p.process === 'object' ? p.process : {}
  const procName = typeof proc.name === 'string' ? proc.name : ''
  const procImage = typeof proc.imagePath === 'string' ? proc.imagePath : ''
  const ruleText = formatInterceptRule(p)
  const paused = p.paused === true

  if (titleEl) titleEl.textContent = t('intercept_title')
  if (descEl) descEl.textContent = paused ? t('intercept_desc_paused') : t('intercept_desc_detected')
  if (labelPid) labelPid.textContent = t('intercept_label_pid')
  if (pidEl) pidEl.textContent = pid != null ? String(pid) : t('unknown')
  if (labelProc) labelProc.textContent = t('intercept_label_process')
  if (procEl) procEl.textContent = (procName || procImage) ? `${procName}${procName && procImage ? ' ' : ''}${procImage ? '(' + procImage + ')' : ''}` : t('unknown')
  if (labelRule) labelRule.textContent = t('intercept_label_rule')
  if (ruleEl) ruleEl.textContent = ruleText || t('unknown')

  if (pre) {
    let text = ''
    try {
      const obj = p.event && typeof p.event === 'object' ? p.event : null
      text = obj ? JSON.stringify(obj, null, 2) : ''
    } catch {}
    pre.textContent = text || ''
  }

  if (btnResume) {
    btnResume.textContent = t('intercept_btn_resume')
    btnResume.disabled = pid == null
    btnResume.onclick = async () => {
      if (pid == null) return
      try {
        const ok = await window.api.process.resume(pid)
        try { m.hide() } catch {}
      } catch {
        return alert(t('intercept_resume_failed'))
      }
    }
  }

  if (btnTerminate) {
    btnTerminate.textContent = t('intercept_btn_terminate')
    btnTerminate.disabled = pid == null
    btnTerminate.onclick = async () => {
      if (pid == null) return
      const okConfirm = confirm(t('intercept_confirm_terminate'))
      if (!okConfirm) return
      try {
        const ok = await window.api.process.terminate(pid)
        try { m.hide() } catch {}
      } catch {
        return alert(t('intercept_terminate_failed'))
      }
    }
  }

  m.show()
}

function initNav() {
  console.log('渲染进程: 初始化导航')
  const brand = document.getElementById('brand')
  if (brand) brand.textContent = t('brand_name')
  document.getElementById('nav-overview').textContent = t('nav_overview')
  const navScan = document.getElementById('nav-scan')
  if (navScan) {
    navScan.textContent = t('nav_scan')
    navScan.style.display = 'block'
  }
  document.getElementById('nav-quarantine').textContent = t('nav_quarantine')
  const navBehavior = document.getElementById('nav-behavior')
  if (navBehavior) navBehavior.textContent = t('nav_behavior')
  const navExcl = document.getElementById('nav-exclusions')
  if (navExcl) navExcl.textContent = t('nav_exclusions')
  document.getElementById('nav-update').textContent = t('nav_update')
  document.getElementById('nav-settings').textContent = t('nav_settings')
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.onclick = async () => {
      const p = btn.dataset.page
      console.log('渲染进程: 点击导航', p)
      try { if (window.api && window.api.ui && window.api.ui.debug) window.api.ui.debug('nav-click', { page: p }) } catch {}
      const action = () => {
        showPage(p)
      }
      tryInterrupt(action)
    }
  })
}

function showPage(p) {
  state.page = p
  document.querySelectorAll('.page').forEach(sec => {
    sec.style.display = sec.id === 'page-' + p ? 'block' : 'none'
  })
  document.querySelectorAll('.nav-btn').forEach(btn => {
    if (btn.dataset.page === p) {
      btn.classList.add('active')
    } else {
      btn.classList.remove('active')
    }
  })
  if (p === 'scan') {
    initScan()
  }
  if (p === 'quarantine') {
    console.log('渲染进程: 进入隔离区页面，开始加载列表')
    initQuarantine()
  }
  if (p === 'behavior') {
    initBehavior()
  }
  if (p === 'behavior-lifecycle') {
    initBehaviorLifecycle()
  }
  if (p === 'exclusions') {
    initExclusions()
  }
  if (p === 'update') {
    if (window.initUpdate) window.initUpdate()
  }
  updateTexts()
  console.log('渲染进程: 切换页面', p)
}

function initOverview() {
  console.log('渲染进程: 初始化概览页')
  document.getElementById('overview-title').textContent = t('overview_title')
  document.getElementById('overview-desc').textContent = t('overview_desc')
  const btn = document.getElementById('btn-start-quick')
  if (btn) btn.style.display = 'none'
  updateOverviewEtwFileEventUi()
}

function uiThread(fn) {
  requestAnimationFrame(() => {
    try { fn() } catch {}
  })
}

function setDisplayById(id, show, display) {
  const el = document.getElementById(id)
  if (!el) return
  el.style.display = show ? (display || 'block') : 'none'
}

function formatDuration(ms) {
  const total = Math.max(0, Math.floor(ms / 1000))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  if (h > 0) return `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
  return `${m}:${String(s).padStart(2, '0')}`
}

function getVirusFamily(res) {
  if (!res || typeof res !== 'object') return ''
  const cands = ['virus_family', 'family', 'label', 'malware_type', 'category', 'name']
  for (const k of cands) {
    const v = res[k]
    if (typeof v === 'string' && v.trim()) return v.trim()
  }
  return ''
}

function isMalware(res) {
  if (!res || typeof res !== 'object') return false
  if (res.infected === true) return true
  if (res.is_malware === true) return true
  if (res.malicious === true) return true
  return false
}

function getScanCfg() {
  const cfg = window.api && window.api.config ? window.api.config.get() : null
  const scan = cfg && cfg.scan ? cfg.scan : {}
  return {
    traversalTimeoutMs: Number.isFinite(scan.traversalTimeoutMs) ? scan.traversalTimeoutMs : 2000,
    walkerBatchSize: Number.isFinite(scan.walkerBatchSize) ? scan.walkerBatchSize : 256,
    cachePersistIntervalMs: Number.isFinite(scan.cachePersistIntervalMs) ? scan.cachePersistIntervalMs : 1000,
    metricsUpdateIntervalMs: Number.isFinite(scan.metricsUpdateIntervalMs) ? scan.metricsUpdateIntervalMs : 200,
    uiYieldEveryFiles: Number.isFinite(scan.uiYieldEveryFiles) ? scan.uiYieldEveryFiles : 25,
    queueCompactionThreshold: Number.isFinite(scan.queueCompactionThreshold) ? scan.queueCompactionThreshold : 5000
  }
}

let scanUiBound = false
let restoringScanCache = false

function applyScanMetricsVisibility(visible) {
  try {
    const fn = window.setScanMetricsVisible
    if (typeof fn === 'function') fn(document, visible)
  } catch {}
}

function resetScanUi() {
  uiThread(() => {
    const scanActions = document.querySelector('.scan-actions')
    if (scanActions) scanActions.style.display = 'grid'
    const desc = document.getElementById('scan-desc')
    if (desc) desc.textContent = t('overview_desc')

    const bar = document.getElementById('scan-progress-bar')
    if (bar) {
      bar.style.width = '0%'
      bar.classList.remove('scan-indeterminate')
      bar.classList.add('progress-bar-striped', 'progress-bar-animated')
      bar.textContent = ''
    }
    const cur = document.getElementById('scan-current-target')
    if (cur) cur.textContent = ''
    const tt = document.getElementById('scan-total-time')
    if (tt) tt.textContent = '0:00'
    const sp = document.getElementById('scan-speed')
    if (sp) sp.textContent = '0'
    const tc = document.getElementById('scan-threat-count')
    if (tc) tc.textContent = '0'
    const sf = document.getElementById('scan-scanned-files')
    if (sf) sf.textContent = '0'
    const report = document.getElementById('scan-final-report')
    if (report) {
      report.style.display = 'none'
      report.textContent = ''
    }
    const wrap = document.getElementById('scan-threat-count-wrap')
    if (wrap) wrap.style.display = 'block'
    const handleBtn = document.getElementById('scan-handle-threats')
    if (handleBtn) handleBtn.style.display = 'none'
    const stopBack = document.getElementById('scan-stop-back')
    if (stopBack) {
      stopBack.className = 'btn btn-danger'
      stopBack.textContent = t('btn_terminate_scan')
      stopBack.style.display = 'none'
    }
    setDisplayById('scan-threat-card', false)
    const tbody = document.getElementById('scan-threat-tbody')
    if (tbody) tbody.innerHTML = ''
    const selAll = document.getElementById('scan-select-all')
    if (selAll) {
      selAll.checked = false
      selAll.indeterminate = false
    }
  })
}

function updateScanMetricsUi(session) {
  const cur = document.getElementById('scan-current-target')
  if (cur) cur.textContent = session.currentTarget || ''
  const tt = document.getElementById('scan-total-time')
  if (tt) tt.textContent = formatDuration(Date.now() - session.startedAt)
  const sp = document.getElementById('scan-speed')
  if (sp) sp.textContent = String(session.speed || 0)
  const tc = document.getElementById('scan-threat-count')
  if (tc) tc.textContent = String(session.threatCount || 0)
  const sf = document.getElementById('scan-scanned-files')
  if (sf) sf.textContent = String(session.scannedCount || 0)
  const bar = document.getElementById('scan-progress-bar')
  if (bar) {
    let st = null
    try {
      const fn = window.getScanProgressBarState
      if (typeof fn === 'function') st = fn(session, !!state.scanning)
    } catch {}
    if (st && st.indeterminate) {
      bar.classList.add('scan-indeterminate')
      bar.classList.remove('progress-bar-striped')
      bar.classList.remove('progress-bar-animated')
      bar.style.width = st.width || '100%'
      bar.textContent = ''
    } else if (st && !st.indeterminate) {
      bar.classList.remove('scan-indeterminate')
      bar.classList.remove('progress-bar-animated')
      bar.style.width = st.width || '0%'
      bar.textContent = st.text || ''
    } else {
      if (session.realtime) {
        bar.classList.add('scan-indeterminate')
        bar.classList.add('progress-bar-striped', 'progress-bar-animated')
        bar.style.width = '100%'
        bar.textContent = ''
      } else {
        bar.classList.remove('scan-indeterminate')
        bar.classList.remove('progress-bar-animated')
        const total = session.totalCount > 0 ? session.totalCount : 1
        const percent = Math.max(0, Math.min(100, Math.floor((session.scannedCount / total) * 100)))
        bar.style.width = percent + '%'
        bar.textContent = percent + '%'
      }
    }
  }
}

function renderThreats() {
  const tbody = document.getElementById('scan-threat-tbody')
  if (!tbody) return
  tbody.innerHTML = ''
  const items = Array.isArray(state.threatItems) ? state.threatItems : []
  if (items.length === 0) {
    setDisplayById('scan-threat-card', false)
    const selAll = document.getElementById('scan-select-all')
    if (selAll) {
      selAll.checked = false
      selAll.indeterminate = false
    }
    return
  }
  setDisplayById('scan-threat-card', true)
  items.forEach((it, idx) => {
    const tr = document.createElement('tr')
    const tdSel = document.createElement('td')
    tdSel.className = 'select-col'
    const chk = document.createElement('input')
    chk.type = 'checkbox'
    chk.className = 'form-check-input scan-threat-checkbox'
    chk.dataset.index = String(idx)
    chk.checked = !!it.selected
    chk.onchange = () => {
      it.selected = chk.checked
      updateScanSelectionState()
    }
    tdSel.appendChild(chk)
    const tdPath = document.createElement('td')
    tdPath.className = 'path-fade'
    tdPath.textContent = it.path
    tdPath.title = it.path
    const tdFam = document.createElement('td')
    tdFam.textContent = it.family || t('unknown')
    tr.appendChild(tdSel)
    tr.appendChild(tdPath)
    tr.appendChild(tdFam)
    tbody.appendChild(tr)
  })
  updateScanSelectionState()
}

function updateScanSelectionState() {
  const tbody = document.getElementById('scan-threat-tbody')
  const selAll = document.getElementById('scan-select-all')
  if (!tbody || !selAll) return
  const boxes = tbody.querySelectorAll('.scan-threat-checkbox')
  const total = boxes.length
  const checked = Array.from(boxes).filter(b => b.checked).length
  selAll.checked = total > 0 && checked === total
  selAll.indeterminate = checked > 0 && checked < total
}

function showConfirmDialog(title, confirmText) {
  const el = document.getElementById('scan-interrupt-modal')
  if (!el) return Promise.resolve(false)
  const titleEl = document.getElementById('scan-interrupt-title')
  const cancelBtn = document.getElementById('scan-interrupt-cancel')
  const confirmBtn = document.getElementById('scan-interrupt-confirm')
  if (titleEl) titleEl.textContent = title || ''
  if (cancelBtn) cancelBtn.textContent = t('modal_cancel')
  if (confirmBtn) confirmBtn.textContent = confirmText || t('modal_confirm')
  if (!state.scanConfirmModal) {
    state.scanConfirmModal = new bootstrap.Modal(el, { backdrop: 'static', keyboard: false })
  }
  return new Promise((resolve) => {
    const onCancel = () => { try { state.scanConfirmModal.hide() } catch {} cleanup(); resolve(false) }
    const onConfirm = () => { try { state.scanConfirmModal.hide() } catch {} cleanup(); resolve(true) }
    function cleanup() {
      if (cancelBtn) cancelBtn.removeEventListener('click', onCancel)
      if (confirmBtn) confirmBtn.removeEventListener('click', onConfirm)
    }
    if (cancelBtn) cancelBtn.addEventListener('click', onCancel, { once: true })
    if (confirmBtn) confirmBtn.addEventListener('click', onConfirm, { once: true })
    state.scanConfirmModal.show()
  })
}

async function persistScanCache(session, force) {
  if (!window.api || !window.api.scanCache || !window.api.scanCache.saveCurrent) return
  const cfg = getScanCfg()
  const now = Date.now()
  if (!force && session.lastCacheAt && now - session.lastCacheAt < cfg.cachePersistIntervalMs) return
  session.lastCacheAt = now
  const payload = {
    id: session.id,
    mode: session.mode,
    startedAt: session.startedAt,
    endedAt: session.endedAt || null,
    realtime: !!session.realtime,
    currentTarget: session.currentTarget || '',
    scannedCount: session.scannedCount || 0,
    totalCount: session.totalCount || 0,
    threatCount: session.threatCount || 0,
    aborted: !!session.aborted,
    handled: !!session.handled,
    threats: Array.isArray(state.threatItems) ? state.threatItems : []
  }
  try { await window.api.scanCache.saveCurrent(payload) } catch {}
}

async function finalizeScan(session) {
  state.scanning = false
  session.endedAt = Date.now()
  await persistScanCache(session, true)
  uiThread(() => {
    const scanActions = document.querySelector('.scan-actions')
    if (scanActions) scanActions.style.display = 'grid'
    const desc = document.getElementById('scan-desc')
    if (desc) desc.textContent = t('overview_desc')

    const wrap = document.getElementById('scan-threat-count-wrap')
    if (wrap) wrap.style.display = 'none'
    const report = document.getElementById('scan-final-report')
    if (report) {
      report.style.display = 'block'
      const threats = Array.isArray(state.threatItems) ? state.threatItems.length : 0
      report.textContent = t('scan_final_report').replace('{threats}', String(threats)).replace('{scanned}', String(session.scannedCount || 0))
    }
    const bar = document.getElementById('scan-progress-bar')
    if (bar) {
      bar.classList.remove('scan-indeterminate')
      bar.classList.remove('progress-bar-animated')
      bar.style.width = '100%'
      bar.textContent = '100%'
    }
    const stopBack = document.getElementById('scan-stop-back')
    if (stopBack) {
      stopBack.className = 'btn btn-secondary'
      stopBack.textContent = t('btn_back')
      stopBack.style.display = 'inline-block'
    }
    const handleBtn = document.getElementById('scan-handle-threats')
    if (handleBtn) handleBtn.style.display = (Array.isArray(state.threatItems) && state.threatItems.length > 0) ? 'inline-block' : 'none'
  })
}

async function scanOneFile(filePath, session) {
  if (!filePath) return
  try {
    if (window.api && window.api.exclusions && window.api.exclusions.isExcluded) {
      const excluded = window.api.exclusions.isExcluded(filePath)
      if (excluded) return
    }
  } catch {}
  session.currentTarget = filePath
  if (session.stopRequested) return

  const cfg = window.api && window.api.config ? window.api.config.get() : null
  const maxMB = cfg && cfg.scanner && Number.isFinite(cfg.scanner.maxFileSizeMB) ? cfg.scanner.maxFileSizeMB : 300
  try {
    const size = await window.api.fsAsync.fileSize(filePath)
    if (size > maxMB * 1024 * 1024) {
      session.scannedCount++
      return
    }
  } catch {}

  if (session.stopRequested) return

  let res
  const requestId = (crypto && crypto.randomUUID) ? crypto.randomUUID() : (String(Date.now()) + '-' + String(Math.random()))
  session.activeScanRequestId = requestId
  try {
    res = await window.api.scanner.scanFile(filePath, { requestId })
  } catch {
    session.scannedCount++
    if (session.activeScanRequestId === requestId) session.activeScanRequestId = ''
    return
  }
  if (session.activeScanRequestId === requestId) session.activeScanRequestId = ''
  session.scannedCount++
  if (isMalware(res)) {
    const family = getVirusFamily(res) || t('unknown')
    const exists = state.threatItems.some(it => it.path === filePath)
    if (!exists) {
      state.threatItems.push({ path: filePath, family, selected: true })
      session.threatCount = state.threatItems.length
      uiThread(() => renderThreats())
    }
  }
}

async function scanDirsAndFiles(session, dirs, files) {
  const cfg = getScanCfg()
  session.realtime = false
  session.totalCount = 0
  session.scannedCount = session.scannedCount || 0
  session.threatCount = state.threatItems.length

  const makeQueue = window.createScanQueue
  const queue = (typeof makeQueue === 'function')
    ? makeQueue(Array.isArray(files) ? files : [], { compactionThreshold: cfg.queueCompactionThreshold })
    : null
  const fallbackQueue = queue ? null : []
  if (fallbackQueue) {
    ;(Array.isArray(files) ? files : []).forEach(p => { if (p) fallbackQueue.push(p) })
  }
  let fallbackQueueIdx = 0

  const queueRemaining = () => {
    if (queue) return queue.remaining()
    return Math.max(0, fallbackQueue.length - fallbackQueueIdx)
  }
  const queuePushMany = (list) => {
    if (!list || list.length === 0) return
    if (queue) queue.pushMany(list)
    else {
      for (const v of list) {
        if (v) fallbackQueue.push(v)
      }
    }
  }
  const queueNext = () => {
    if (queue) return queue.next()
    if (fallbackQueueIdx >= fallbackQueue.length) return null
    const v = fallbackQueue[fallbackQueueIdx++]
    if (fallbackQueueIdx >= cfg.queueCompactionThreshold) {
      fallbackQueue.splice(0, fallbackQueueIdx)
      fallbackQueueIdx = 0
    }
    return v
  }

  let walkerId = null
  if (Array.isArray(dirs) && dirs.length > 0) {
    try {
      walkerId = window.api.fsAsync.createWalker(dirs)
    } catch {
      walkerId = null
    }
  }
  session.walkerId = walkerId

  const startTraversalAt = Date.now()
  let traversalDone = !walkerId
  const initialFiles = []
  let lastUiAt = 0
  let lastYieldAtCount = session.scannedCount

  while (!traversalDone) {
    const step = await window.api.fsAsync.walkerNext(walkerId, cfg.walkerBatchSize)
    initialFiles.push(...(step.files || []))
    traversalDone = !!step.done
    if (traversalDone) break
    if (Date.now() - startTraversalAt >= cfg.traversalTimeoutMs) break
    const now = Date.now()
    if (now - lastUiAt >= cfg.metricsUpdateIntervalMs) {
      lastUiAt = now
      await waitNextPaint()
      uiThread(() => updateScanMetricsUi(session))
    }
  }

  if (traversalDone) {
    session.realtime = false
    session.totalCount = queueRemaining() + initialFiles.length
    queuePushMany(initialFiles)
    uiThread(() => updateScanMetricsUi(session))
  } else {
    session.realtime = true
    queuePushMany(initialFiles)
    uiThread(() => updateScanMetricsUi(session))
    traversalDone = false
  }

  hideLoading()
  let lastSpeedAt = Date.now()
  let lastSpeedCount = session.scannedCount

  while (!session.stopRequested) {
    while (!session.stopRequested && queueRemaining() > 0) {
      const fp = queueNext()
      if (!fp) break
      await scanOneFile(fp, session)
      const now = Date.now()
      if (now - lastSpeedAt >= 1000) {
        const delta = session.scannedCount - lastSpeedCount
        session.speed = delta
        lastSpeedAt = now
        lastSpeedCount = session.scannedCount
      }
      if (cfg.uiYieldEveryFiles > 0 && (session.scannedCount - lastYieldAtCount) >= cfg.uiYieldEveryFiles) {
        lastYieldAtCount = session.scannedCount
        await waitNextPaint()
      }
      if (now - lastUiAt >= cfg.metricsUpdateIntervalMs) {
        lastUiAt = now
        uiThread(() => updateScanMetricsUi(session))
      }
      await persistScanCache(session, false)
    }
    if (session.stopRequested) break
    if (!traversalDone && walkerId) {
      const step = await window.api.fsAsync.walkerNext(walkerId, cfg.walkerBatchSize)
      if (step && Array.isArray(step.files) && step.files.length > 0) {
        queuePushMany(step.files)
      }
      traversalDone = !!(step && step.done)
      if (traversalDone) {
        session.realtime = false
        session.totalCount = session.scannedCount + queueRemaining()
      }
      const now = Date.now()
      if (now - lastUiAt >= cfg.metricsUpdateIntervalMs) {
        lastUiAt = now
        uiThread(() => updateScanMetricsUi(session))
      }
      await persistScanCache(session, false)
      continue
    }
    break
  }

  if (walkerId) {
    try { window.api.fsAsync.destroyWalker(walkerId) } catch {}
  }
  session.walkerId = null
  session.activeScanRequestId = ''
}

async function startScan(mode, targetLabel, dirs, files, serialRoots, options) {
  if (state.scanning) return
  state.scanning = true
  state.page = 'scan'
  showPage('scan')
  applyScanMetricsVisibility(true)
  state.threatItems = []
  resetScanUi()
  uiThread(() => {
    const scanActions = document.querySelector('.scan-actions')
     if (scanActions) scanActions.style.display = 'none'
     const desc = document.getElementById('scan-desc')
     if (desc) {
       const modeName = (targetLabel || t('nav_scan')).replace('检测', '').replace('扫描', '')
       desc.textContent = t('scan_in_progress').replace('{mode}', modeName)
     }

     const stopBack = document.getElementById('scan-stop-back')
    if (stopBack) {
      stopBack.className = 'btn btn-danger'
      stopBack.textContent = t('btn_terminate_scan')
      stopBack.style.display = 'inline-block'
    }
    const handleBtn = document.getElementById('scan-handle-threats')
    if (handleBtn) handleBtn.style.display = 'none'
  })

  const session = {
    id: (crypto && crypto.randomUUID) ? crypto.randomUUID() : String(Date.now()),
    mode,
    startedAt: Date.now(),
    endedAt: null,
    realtime: false,
    currentTarget: targetLabel || '',
    scannedCount: 0,
    totalCount: 0,
    threatCount: 0,
    speed: 0,
    stopRequested: false,
    aborted: false,
    handled: false,
    lastCacheAt: 0,
    walkerId: null,
    activeScanRequestId: ''
  }
  state.scanSession = session

  uiThread(() => updateScanMetricsUi(session))
  await showLoading(t('scan_initializing'), t('please_wait'))
  let extraFiles = []
  const includeRunning = !!(options && options.includeRunningProcesses)
  if (includeRunning && window.api && window.api.system && window.api.system.getRunningProcesses) {
    try {
      const runPre = window.runScanPreTasks
      if (typeof runPre === 'function') {
        extraFiles = await runPre({
          showLoading: () => Promise.resolve(),
          waitNextPaint,
          includeRunningProcesses: true,
          getRunningProcesses: () => window.api.system.getRunningProcesses()
        })
      } else {
        await waitNextPaint()
        extraFiles = await window.api.system.getRunningProcesses()
      }
    } catch {
      extraFiles = []
    }
  }
  const mergedFiles = [...(Array.isArray(files) ? files : []), ...(Array.isArray(extraFiles) ? extraFiles : [])].filter(Boolean)
  await persistScanCache(session, true)

  if (Array.isArray(serialRoots) && serialRoots.length > 0) {
    for (const root of serialRoots) {
      if (session.stopRequested) break
      session.currentTarget = root
      uiThread(() => updateScanMetricsUi(session))
      await scanDirsAndFiles(session, [root], [])
    }
  } else {
    session.currentTarget = targetLabel || ''
    uiThread(() => updateScanMetricsUi(session))
    await scanDirsAndFiles(session, dirs, mergedFiles)
  }

  if (session.stopRequested) {
    session.aborted = true
  }
  await finalizeScan(session)
}

async function restoreScanResultIfAny() {
  if (restoringScanCache) return
  restoringScanCache = true
  try {
    let cached = null
    try { cached = await window.api.scanCache.restore() } catch {}
    if (!cached) return
    state.threatItems = Array.isArray(cached.threats) ? cached.threats.map(it => ({ path: it.path, family: it.family, selected: it.selected !== false })) : []
    state.scanning = false
    state.scanSession = {
      id: cached.id || '',
      mode: cached.mode || '',
      startedAt: cached.startedAt || Date.now(),
      endedAt: cached.endedAt || Date.now(),
      realtime: false,
      currentTarget: cached.currentTarget || '',
      scannedCount: cached.scannedCount || 0,
      totalCount: cached.totalCount || 0,
      threatCount: state.threatItems.length,
      speed: 0,
      stopRequested: false,
      aborted: !!cached.aborted,
      handled: !!cached.handled,
      lastCacheAt: 0,
      walkerId: null,
      activeScanRequestId: ''
    }
    uiThread(() => {
      applyScanMetricsVisibility(true)
      updateScanMetricsUi(state.scanSession)
      renderThreats()
      const wrap = document.getElementById('scan-threat-count-wrap')
      if (wrap) wrap.style.display = 'none'
      const report = document.getElementById('scan-final-report')
      if (report) {
        report.style.display = 'block'
        report.textContent = t('scan_restore_report').replace('{threats}', String(state.threatItems.length)).replace('{scanned}', String(state.scanSession.scannedCount || 0))
      }
      const stopBack = document.getElementById('scan-stop-back')
      if (stopBack) {
        stopBack.className = 'btn btn-secondary'
        stopBack.textContent = t('btn_back')
        stopBack.style.display = 'inline-block'
      }
      const handleBtn = document.getElementById('scan-handle-threats')
      if (handleBtn) handleBtn.style.display = state.threatItems.length > 0 ? 'inline-block' : 'none'
    })
  } finally {
    restoringScanCache = false
  }
}

function bindScanUi() {
  if (scanUiBound) return
  scanUiBound = true

  const btnQuick = document.getElementById('scan-btn-quick')
  const btnFull = document.getElementById('scan-btn-full')
  const btnDir = document.getElementById('scan-btn-dir')
  const btnFile = document.getElementById('scan-btn-file')
  const selAll = document.getElementById('scan-select-all')
  const stopBack = document.getElementById('scan-stop-back')
  const handleBtn = document.getElementById('scan-handle-threats')

  if (selAll) {
    selAll.onchange = () => {
      const tbody = document.getElementById('scan-threat-tbody')
      if (!tbody) return
      const boxes = tbody.querySelectorAll('.scan-threat-checkbox')
      boxes.forEach(b => {
        b.checked = selAll.checked
        const idx = parseInt(b.dataset.index, 10)
        if (Number.isFinite(idx) && state.threatItems[idx]) state.threatItems[idx].selected = b.checked
      })
      updateScanSelectionState()
    }
  }

  if (stopBack) {
    stopBack.onclick = async () => {
      if (state.scanning && state.scanSession) {
        state.scanSession.stopRequested = true
        try { window.api.fsAsync.destroyWalker(state.scanSession.walkerId) } catch {}
        try {
          const reqId = state.scanSession.activeScanRequestId
          if (reqId && window.api && window.api.scanner && window.api.scanner.abort) {
            await window.api.scanner.abort(reqId)
          }
        } catch {}
        return
      }
      const ok = await showConfirmDialog(t('scan_back_confirm_title'), t('modal_confirm'))
      if (!ok) return
      try { await window.api.scanCache.clearCurrent() } catch {}
      state.threatItems = []
      state.scanSession = null
      showPage('overview')
    }
  }

  if (handleBtn) {
    handleBtn.onclick = async () => {
      if (state.scanning) return
      const selected = state.threatItems.filter(it => it.selected).map(it => it.path)
      if (selected.length === 0) {
        alert(t('scan_no_selected_threats'))
        return
      }
      const ok = await showConfirmDialog(t('scan_quarantine_confirm_title'), t('modal_confirm'))
      if (!ok) return
      showProcessing(t('threat_handling_title'), t('threat_handling_desc'))
      try {
        for (let i = 0; i < selected.length; i++) {
          const fp = selected[i]
          updateProcessing(Math.floor(((i + 1) / selected.length) * 100), fp)
          await window.api.quarantine.isolate(fp)
        }
        hideProcessing()
        try { await window.api.scanCache.markHandled(Date.now()) } catch {}
        try { await window.api.scanCache.clearCurrent() } catch {}
        state.threatItems = []
        renderThreats()
        const report = document.getElementById('scan-final-report')
        if (report) report.textContent = t('threats_handled')
        if (handleBtn) handleBtn.style.display = 'none'
      } catch {
        hideProcessing()
        alert(t('scan_quarantine_failed'))
      }
    }
  }

  if (btnQuick) {
    btnQuick.onclick = async () => {
      if (state.scanning) return
      let rules = null
      try { rules = await window.api.scanRules.load() } catch {}
      const quick = rules && rules.quick ? rules.quick : null
      const dirs = (quick && Array.isArray(quick.directories)) ? quick.directories : []
      const files = (quick && Array.isArray(quick.files)) ? quick.files : []
      const resolvedDirs = dirs.map(p => window.api.resolvePath(p)).filter(Boolean)
      const resolvedFiles = files.map(p => window.api.resolvePath(p)).filter(Boolean)
      startScan('quick', t('quick_title'), resolvedDirs, resolvedFiles, null, { includeRunningProcesses: !!(quick && quick.includeRunningProcesses) })
    }
  }

  if (btnFull) {
    btnFull.onclick = async () => {
      if (state.scanning) return
      let roots = []
      try { roots = await window.api.fsAsync.listDriveRoots() } catch { roots = [] }
      startScan('full', t('full_title'), null, null, roots)
    }
  }

  if (btnDir) {
    btnDir.onclick = async () => {
      if (state.scanning) return
      const p = await window.api.dialog.openDirectory()
      if (!p) return
      startScan('custom_dir', p, [p], [], null)
    }
  }

  if (btnFile) {
    btnFile.onclick = async () => {
      if (state.scanning) return
      const p = await window.api.dialog.openFile()
      if (!p) return
      startScan('custom_file', p, [], [p], null)
    }
  }
}

function initScan() {
  uiThread(() => {
    const title = document.getElementById('scan-title')
    if (title) title.textContent = t('nav_scan')
    const desc = document.getElementById('scan-desc')
    if (desc) desc.textContent = t('overview_desc')
    const btnQuick = document.getElementById('scan-btn-quick')
    if (btnQuick) btnQuick.textContent = t('nav_quick')
    const btnFull = document.getElementById('scan-btn-full')
    if (btnFull) btnFull.textContent = t('nav_full')
    const btnDir = document.getElementById('scan-btn-dir')
    if (btnDir) btnDir.textContent = t('btn_choose_dir')
    const btnFile = document.getElementById('scan-btn-file')
    if (btnFile) btnFile.textContent = t('btn_choose_file')
    const thTitle = document.getElementById('scan-threat-title')
    if (thTitle) thTitle.textContent = t('threats_detected')
    const thPath = document.getElementById('scan-th-path')
    if (thPath) thPath.textContent = t('threat_path')
    const thFam = document.getElementById('scan-th-family')
    if (thFam) thFam.textContent = t('threat_family')

    const curLab = document.getElementById('scan-current-target-label')
    if (curLab) curLab.textContent = t('current_scan_file')
    const timeLab = document.getElementById('scan-total-time-label')
    if (timeLab) timeLab.textContent = t('metric_elapsed')
    const spLab = document.getElementById('scan-speed-label')
    if (spLab) spLab.textContent = t('metric_rate')
    const tcLab = document.getElementById('scan-threat-count-label')
    if (tcLab) tcLab.textContent = t('metric_threats')
    const sfLab = document.getElementById('scan-scanned-files-label')
    if (sfLab) sfLab.textContent = t('metric_scanned')

    const stopBack = document.getElementById('scan-stop-back')
    if (stopBack) stopBack.textContent = state.scanning ? t('btn_terminate_scan') : t('btn_back')
    const handleBtn = document.getElementById('scan-handle-threats')
    if (handleBtn) handleBtn.textContent = t('btn_handle_threats')

    if (state.scanning && state.scanSession) {
       const scanActions = document.querySelector('.scan-actions')
       if (scanActions) scanActions.style.display = 'none'
       const desc = document.getElementById('scan-desc')
       if (desc) {
         const rawMode = state.scanSession.mode === 'quick' ? t('nav_quick') : (state.scanSession.mode === 'full' ? t('nav_full') : (state.scanSession.currentTarget || t('nav_scan')))
         const modeName = rawMode.replace('检测', '').replace('扫描', '')
         desc.textContent = t('scan_in_progress').replace('{mode}', modeName)
       }
     }
  })

  bindScanUi()
  if (!state.scanning) {
    applyScanMetricsVisibility(false)
    resetScanUi()
    restoreScanResultIfAny()
  }
}

let loadingModal = null
 
function updateLoading(percent, statusText) {
  const p = Number.isFinite(percent) ? Math.max(0, Math.min(100, Math.floor(percent))) : 0
  const b = document.getElementById('loading-bar')
  if (b) {
    b.style.width = p + '%'
    b.textContent = p + '%'
  }
  const s = document.getElementById('loading-status')
  if (s) s.textContent = statusText ? String(statusText) : ''
}

function showLoading(title, desc, percent, statusText) {
  const el = document.getElementById('loading-modal')
  if (!el) return Promise.resolve()
  const t = document.getElementById('loading-title')
  if (t) t.textContent = title ? String(title) : ''
  const d = document.getElementById('loading-desc')
  if (d) d.textContent = desc ? String(desc) : ''
  updateLoading(percent, statusText)
  
  if (!loadingModal) {
    loadingModal = new bootstrap.Modal(el, { backdrop: 'static', keyboard: false })
  }
  if (el.classList && el.classList.contains('show')) {
    return Promise.resolve()
  }
  return new Promise((resolve) => {
    el.addEventListener('shown.bs.modal', () => resolve(), { once: true })
    loadingModal.show()
  })
}

function hideLoading() {
  if (loadingModal) {
    loadingModal.hide()
  }
}

let processingModal = null

function waitNextPaint() {
  return new Promise((resolve) => requestAnimationFrame(() => resolve()))
}

function showProcessing(title, desc) {
  const el = document.getElementById('processing-modal')
  if (!el) return
  const t = document.getElementById('processing-title')
  if (t) t.textContent = title
  const d = document.getElementById('processing-desc')
  if (d) d.textContent = desc
  const b = document.getElementById('processing-bar')
  if (b) b.style.width = '0%'
  const s = document.getElementById('processing-status')
  if (s) s.textContent = ''
  
  if (!processingModal) {
    processingModal = new bootstrap.Modal(el, { backdrop: 'static', keyboard: false })
  }
  processingModal.show()
}

function showIndeterminateProcessing(title, desc) {
  showProcessing(title, desc)
  updateProcessing(100, '')
}

function updateProcessing(percent, statusText) {
  const b = document.getElementById('processing-bar')
  if (b) b.style.width = percent + '%'
  const s = document.getElementById('processing-status')
  if (s && statusText) s.textContent = statusText
}

function hideProcessing() {
  if (processingModal) {
    processingModal.hide()
  }
}

let exclDeleteModal = null
let exclAddModal = null

function showExclDeleteConfirm(paths) {
  const el = document.getElementById('excl-delete-modal')
  if (!el) return Promise.resolve(false)
  const titleEl = document.getElementById('excl-delete-title')
  if (titleEl) titleEl.textContent = t('exclusions_confirm_delete')
  const listEl = document.getElementById('excl-delete-list')
  if (listEl) {
    listEl.innerHTML = ''
    paths.forEach(p => {
      const li = document.createElement('li')
      li.textContent = p
      listEl.appendChild(li)
    })
  }
  const cancelBtn = document.getElementById('excl-delete-cancel')
  const confirmBtn = document.getElementById('excl-delete-confirm')
  if (cancelBtn) cancelBtn.textContent = t('modal_cancel')
  if (confirmBtn) confirmBtn.textContent = t('modal_confirm')
  if (!exclDeleteModal) {
    exclDeleteModal = new bootstrap.Modal(el, { backdrop: 'static', keyboard: false })
  }
  return new Promise((resolve) => {
    const onCancel = () => { try { exclDeleteModal.hide() } catch {} cleanup(); resolve(false) }
    const onConfirm = () => { try { exclDeleteModal.hide() } catch {} cleanup(); resolve(true) }
    function cleanup() {
      if (cancelBtn) cancelBtn.removeEventListener('click', onCancel)
      if (confirmBtn) confirmBtn.removeEventListener('click', onConfirm)
    }
    if (cancelBtn) cancelBtn.addEventListener('click', onCancel, { once: true })
    if (confirmBtn) confirmBtn.addEventListener('click', onConfirm, { once: true })
    exclDeleteModal.show()
  })
}

function showExclAddConfirm(type, pathText) {
  const el = document.getElementById('excl-add-modal')
  if (!el) return Promise.resolve(false)
  const titleEl = document.getElementById('excl-add-title')
  if (titleEl) titleEl.textContent = t('exclusions_confirm_add')
  const pathEl = document.getElementById('excl-add-path')
  if (pathEl) {
    pathEl.textContent = pathText || ''
    pathEl.title = pathText || ''
  }
  const cancelBtn = document.getElementById('excl-add-cancel')
  const confirmBtn = document.getElementById('excl-add-confirm')
  if (cancelBtn) cancelBtn.textContent = t('modal_cancel')
  if (confirmBtn) confirmBtn.textContent = t('modal_confirm')
  if (!exclAddModal) {
    exclAddModal = new bootstrap.Modal(el, { backdrop: 'static', keyboard: false })
  }
  return new Promise((resolve) => {
    const onCancel = () => { try { exclAddModal.hide() } catch {} cleanup(); resolve(false) }
    const onConfirm = () => { try { exclAddModal.hide() } catch {} cleanup(); resolve(true) }
    function cleanup() {
      if (cancelBtn) cancelBtn.removeEventListener('click', onCancel)
      if (confirmBtn) confirmBtn.removeEventListener('click', onConfirm)
    }
    if (cancelBtn) cancelBtn.addEventListener('click', onCancel, { once: true })
    if (confirmBtn) confirmBtn.addEventListener('click', onConfirm, { once: true })
    exclAddModal.show()
  })
}

function getBehaviorUiCfg() {
  const cfg = window.api && window.api.config ? window.api.config.get() : null
  const ui = cfg && cfg.behaviorUi ? cfg.behaviorUi : {}
  let processListLimit = 500
  if (ui.processListLimit === 0) processListLimit = Infinity
  else if (Number.isFinite(ui.processListLimit)) processListLimit = Math.max(50, Math.min(5000, Math.floor(ui.processListLimit)))

  let eventListLimit = 1000
  if (ui.pageSize === 0) eventListLimit = Infinity
  else if (Number.isFinite(ui.pageSize)) eventListLimit = Math.max(50, Math.min(10000, Math.floor(ui.pageSize)))

  return { processListLimit, eventListLimit }
}

function setBehaviorError(msg) {
  const el = document.getElementById('behavior-error')
  if (!el) return
  if (typeof msg === 'string' && msg.trim()) {
    el.textContent = msg.trim()
    el.style.display = 'block'
  } else {
    el.textContent = ''
    el.style.display = 'none'
  }
}

function setBehaviorStatus(msg) {
  const el = document.getElementById('behavior-status')
  if (!el) return
  el.textContent = msg || ''
}

function setBehaviorMeta(msg) {
  const el = document.getElementById('behavior-meta')
  if (!el) return
  el.textContent = msg || ''
}

function getBaseName(p) {
  const s = typeof p === 'string' ? p : ''
  if (!s) return ''
  const parts = s.split(/[\\/]+/).filter(Boolean)
  return parts.length ? parts[parts.length - 1] : s
}

function formatPidCell(pid, name, image) {
  const p = Number.isFinite(pid) ? pid : null
  if (p == null) return ''
  const n = (typeof name === 'string' && name.trim()) ? name.trim() : ''
  const img = (typeof image === 'string' && image.trim()) ? image.trim() : ''
  const base = img ? getBaseName(img) : ''
  const label = n || base
  return label ? `${p} - ${label}` : String(p)
}

function parsePidValue(v) {
  if (v == null) return null
  const n = typeof v === 'number' ? v : parseInt(String(v), 10)
  if (!Number.isFinite(n) || n <= 0) return null
  return n
}

function getBehaviorPidFromInput() {
  const input = document.getElementById('behavior-pid-input')
  if (!input) return null
  const pid = parsePidValue(input.value)
  return pid
}

function setBehaviorPidInput(pid) {
  const input = document.getElementById('behavior-pid-input')
  if (input) input.value = pid != null ? String(pid) : ''
}

function setBehaviorProcessSelect(pid) {
  const sel = document.getElementById('behavior-process-select')
  if (!sel) return
  const p = pid != null ? String(pid) : ''
  if (sel.value !== p) sel.value = p
}

function updateBehaviorButtons() {
  const btnApply = document.getElementById('behavior-btn-apply')
  if (btnApply) btnApply.disabled = state.behavior.loading
  const btnClear = document.getElementById('behavior-btn-clear')
  if (btnClear) btnClear.disabled = state.behavior.loading
  const btnLifecycle = document.getElementById('behavior-btn-lifecycle')
  if (btnLifecycle) btnLifecycle.disabled = state.behavior.loading
  const btnClearAll = document.getElementById('behavior-btn-clear-all')
  if (btnClearAll) btnClearAll.disabled = state.behavior.loading
  const btnRefresh = document.getElementById('behavior-btn-refresh-processes')
  if (btnRefresh) btnRefresh.disabled = state.behavior.loading
  const btnRefreshEvents = document.getElementById('behavior-btn-refresh-events')
  if (btnRefreshEvents) btnRefreshEvents.disabled = state.behavior.loading
}

async function renderBehaviorProcessesAsync(list) {
  const sel = document.getElementById('behavior-process-select')
  if (!sel) return

  const renderId = (state.behavior.processSnapshotId || 0) + 1
  state.behavior.processSnapshotId = renderId
  state.behavior.processSnapshotActiveId = renderId
  const shouldContinue = () => state.behavior.processSnapshotActiveId === renderId
  const snapshot = Array.isArray(list) ? list.slice() : []

  const helper = window.behaviorRender && window.behaviorRender.renderProcessSelectAsync
  if (typeof helper === 'function') {
    await helper({
      sel,
      list: snapshot,
      t,
      getBaseName,
      batchSize: 200,
      shouldContinue,
      onProgress: (total, done) => {
        const percent = total > 0 ? Math.floor((done / total) * 100) : 100
        updateLoading(percent, '')
      },
      onFirstBatch: () => {
        hideLoading()
      }
    })
    return
  }

  if (!shouldContinue()) return
  sel.innerHTML = ''
  const optAll = document.createElement('option')
  optAll.value = ''
  optAll.textContent = t('behavior_all_processes')
  sel.appendChild(optAll)

  const arr = snapshot
  let firstAppended = false
  let done = 0
  const total = arr.length
  for (const p of arr) {
    if (!shouldContinue()) return
    const pid = Number.isFinite(p && p.pid) ? p.pid : null
    if (pid == null) continue
    const image = typeof p.image === 'string' ? p.image : ''
    const name = (typeof p.name === 'string' && p.name) ? p.name : getBaseName(image)
    const opt = document.createElement('option')
    opt.value = String(pid)
    opt.textContent = name ? `${pid} - ${name}` : String(pid)
    sel.appendChild(opt)
    done++
    if (!firstAppended) {
      firstAppended = true
      hideLoading()
    }
    const percent = total > 0 ? Math.floor((done / total) * 100) : 100
    updateLoading(percent, '')
  }
}

function renderBehaviorEvents(list, append) {
  const tbody = document.getElementById('behavior-tbody')
  if (!tbody) return

  if (!append) tbody.innerHTML = ''

  const arr = Array.isArray(list) ? list : []
  if (!append && arr.length === 0) {
    const tr = document.createElement('tr')
    const td = document.createElement('td')
    td.colSpan = 7
    td.className = 'text-center text-muted'
    td.textContent = t('behavior_empty')
    tr.appendChild(td)
    tbody.appendChild(tr)
    return
  }

  arr.forEach(ev => {
    const tr = document.createElement('tr')
    tr.style.cursor = 'pointer'
    tr.onclick = () => openBehaviorDetail(ev)

    const ts = typeof ev.ts === 'string' ? ev.ts : ''
    const provider = typeof ev.provider === 'string' ? ev.provider : ''
    const op = typeof ev.op === 'string' ? ev.op : ''
    const actor = formatPidCell(ev.actor_pid, ev.actor_processName, ev.actor_processImage)
    const subject = formatPidCell(ev.subject_pid, ev.subject_processName, ev.subject_processImage)
    const tid = Number.isFinite(ev.tid) ? ev.tid : ''
    const target = (typeof ev.file_path === 'string' && ev.file_path) ? ev.file_path
      : ((typeof ev.reg_key === 'string' && ev.reg_key) ? ev.reg_key : '')
    const value = (typeof ev.reg_value === 'string' && ev.reg_value) ? ev.reg_value : ''
    const targetText = value ? `${target} :: ${value}` : target

    const cols = [ts, provider, op, actor, subject, tid, targetText]
    cols.forEach((c, idx) => {
      const td = document.createElement('td')
      if (idx === 6) td.className = 'path-fade'
      td.textContent = c === null || c === undefined ? '' : String(c)
      if (idx === 6) td.title = td.textContent
      tr.appendChild(td)
    })
    tbody.appendChild(tr)
  })
}

function openBehaviorDetail(ev) {
  const el = document.getElementById('behavior-detail-modal')
  if (!el) return
  const titleEl = document.getElementById('behavior-detail-title')
  const closeEl = document.getElementById('behavior-detail-close')
  if (closeEl) closeEl.textContent = t('btn_close')
  const id = Number.isFinite(ev && ev.id) ? ev.id : null
  if (titleEl) titleEl.textContent = id != null ? `${t('behavior_detail_title')} #${id}` : t('behavior_detail_title')

  const pre = document.getElementById('behavior-detail-json')
  if (pre) {
    const raw = typeof ev.raw_json === 'string' ? ev.raw_json : ''
    let text = raw
    try {
      const obj = raw ? JSON.parse(raw) : null
      if (obj && typeof obj === 'object') text = JSON.stringify(obj, null, 2)
    } catch {}
    pre.textContent = text || ''
  }
  if (!behaviorDetailModal) {
    behaviorDetailModal = new bootstrap.Modal(el, { backdrop: 'static', keyboard: true })
  }
  behaviorDetailModal.show()
}

function updateBehaviorTexts() {
  const title = document.getElementById('behavior-title')
  if (title) title.textContent = t('behavior_title')
  const desc = document.getElementById('behavior-desc')
  if (desc) desc.textContent = t('behavior_desc')

  const btnRefresh = document.getElementById('behavior-btn-refresh-processes')
  if (btnRefresh) btnRefresh.textContent = t('behavior_refresh_processes')
  const btnRefreshEvents = document.getElementById('behavior-btn-refresh-events')
  if (btnRefreshEvents) btnRefreshEvents.textContent = t('behavior_refresh_events')
  const btnClearAll = document.getElementById('behavior-btn-clear-all')
  if (btnClearAll) btnClearAll.textContent = t('behavior_clear_all')

  const labelProc = document.getElementById('behavior-label-processes')
  if (labelProc) labelProc.textContent = t('behavior_label_processes')
  const labelPid = document.getElementById('behavior-label-pid')
  if (labelPid) labelPid.textContent = t('behavior_label_pid')

  const thTs = document.getElementById('behavior-th-ts')
  if (thTs) thTs.textContent = t('behavior_th_ts')
  const thProvider = document.getElementById('behavior-th-provider')
  if (thProvider) thProvider.textContent = t('behavior_th_provider')
  const thOp = document.getElementById('behavior-th-op')
  if (thOp) thOp.textContent = t('behavior_th_op')
  const thActor = document.getElementById('behavior-th-actor')
  if (thActor) thActor.textContent = t('behavior_th_actor')
  const thSubject = document.getElementById('behavior-th-subject')
  if (thSubject) thSubject.textContent = t('behavior_th_subject')
  const thTid = document.getElementById('behavior-th-tid')
  if (thTid) thTid.textContent = t('behavior_th_tid')
  const thTarget = document.getElementById('behavior-th-target')
  if (thTarget) thTarget.textContent = t('behavior_th_target')

  const btnApply = document.getElementById('behavior-btn-apply')
  if (btnApply) btnApply.textContent = t('behavior_apply')
  const btnClear = document.getElementById('behavior-btn-clear')
  if (btnClear) btnClear.textContent = t('behavior_clear')
  const btnLifecycle = document.getElementById('behavior-btn-lifecycle')
  if (btnLifecycle) btnLifecycle.textContent = t('behavior_view_lifecycle')
}

function setBehaviorLifecycleError(msg) {
  const el = document.getElementById('behavior-lifecycle-error')
  if (!el) return
  if (typeof msg === 'string' && msg.trim()) {
    el.textContent = msg.trim()
    el.style.display = 'block'
  } else {
    el.textContent = ''
    el.style.display = 'none'
  }
}

function setBehaviorLifecycleStatus(msg) {
  const el = document.getElementById('behavior-lifecycle-status')
  if (!el) return
  el.textContent = msg || ''
}

function setBehaviorLifecycleMeta(msg) {
  const el = document.getElementById('behavior-lifecycle-meta')
  if (!el) return
  el.textContent = msg || ''
}

function getBehaviorLifecyclePidFromInput() {
  const input = document.getElementById('behavior-lifecycle-pid-input')
  if (!input) return null
  return parsePidValue(input.value)
}

function setBehaviorLifecyclePidInput(pid) {
  const input = document.getElementById('behavior-lifecycle-pid-input')
  if (!input) return
  input.value = pid != null ? String(pid) : ''
}

function updateBehaviorLifecycleButtons() {
  const disabled = !!state.behaviorLifecycle.loading
  const btnBack = document.getElementById('behavior-lifecycle-btn-back')
  if (btnBack) btnBack.disabled = disabled
  const btnRefresh = document.getElementById('behavior-lifecycle-btn-refresh')
  if (btnRefresh) btnRefresh.disabled = disabled
  const btnOpen = document.getElementById('behavior-lifecycle-btn-open')
  if (btnOpen) btnOpen.disabled = disabled
  const btnToggle = document.getElementById('behavior-lifecycle-btn-toggle-mitre')
  if (btnToggle) btnToggle.disabled = disabled
}

function updateBehaviorLifecycleTexts() {
  const title = document.getElementById('behavior-lifecycle-title')
  if (title) title.textContent = t('behavior_lifecycle_title')
  const desc = document.getElementById('behavior-lifecycle-desc')
  if (desc) desc.textContent = t('behavior_lifecycle_desc')

  const labelPid = document.getElementById('behavior-lifecycle-label-pid')
  if (labelPid) labelPid.textContent = t('behavior_label_pid')

  const btnBack = document.getElementById('behavior-lifecycle-btn-back')
  if (btnBack) btnBack.textContent = t('btn_back')
  const btnRefresh = document.getElementById('behavior-lifecycle-btn-refresh')
  if (btnRefresh) btnRefresh.textContent = t('behavior_refresh_events')
  const btnOpen = document.getElementById('behavior-lifecycle-btn-open')
  if (btnOpen) btnOpen.textContent = t('behavior_lifecycle_open')
  const btnToggle = document.getElementById('behavior-lifecycle-btn-toggle-mitre')
  if (btnToggle) btnToggle.textContent = (state.behaviorLifecycle.view === 'mitre') ? t('behavior_mitre_show_tree') : t('behavior_mitre_show_matrix')
}

function getProcessDisplayName(p) {
  if (!p || typeof p !== 'object') return ''
  const name = (typeof p.name === 'string' && p.name.trim()) ? p.name.trim() : ''
  const image = (typeof p.image === 'string' && p.image.trim()) ? p.image.trim() : ''
  return name || (image ? getBaseName(image) : '')
}

function renderBehaviorLifecycleSummary(pid, proc, events) {
  const host = document.getElementById('behavior-lifecycle-summary')
  if (!host) return
  host.innerHTML = ''

  const ppid = proc && Number.isFinite(proc.ppid) ? proc.ppid : ''
  const name = getProcessDisplayName(proc)
  const image = proc && typeof proc.image === 'string' ? proc.image : ''
  const firstSeen = proc && typeof proc.first_seen === 'string' ? proc.first_seen : ''
  const lastSeen = proc && typeof proc.last_seen === 'string' ? proc.last_seen : ''
  const exitedAt = proc && typeof proc.exited_at === 'string' ? proc.exited_at : ''

  const arr = Array.isArray(events) ? events : []
  const total = arr.length
  const sorted = arr.slice().sort((a, b) => {
    const ia = Number.isFinite(a && a.id) ? a.id : 0
    const ib = Number.isFinite(b && b.id) ? b.id : 0
    return ia - ib
  })
  const startedAt = sorted.length && typeof sorted[0].ts === 'string' ? sorted[0].ts : ''
  const endedAt = sorted.length && typeof sorted[sorted.length - 1].ts === 'string' ? sorted[sorted.length - 1].ts : ''

  const grid = document.createElement('div')
  grid.className = 'lifecycle-summary-grid'

  const item = (label, value) => {
    const box = document.createElement('div')
    box.className = 'lifecycle-summary-item'
    const l = document.createElement('div')
    l.className = 'lifecycle-summary-label'
    l.textContent = label
    const v = document.createElement('div')
    v.className = 'lifecycle-summary-value'
    v.textContent = value || t('unknown')
    v.title = v.textContent
    box.appendChild(l)
    box.appendChild(v)
    return box
  }

  grid.appendChild(item('PID', pid != null ? String(pid) : ''))
  grid.appendChild(item('PPID', ppid !== '' ? String(ppid) : ''))
  grid.appendChild(item(t('behavior_lifecycle_field_name'), name))
  grid.appendChild(item(t('behavior_lifecycle_field_image'), image))
  grid.appendChild(item(t('behavior_lifecycle_field_first_seen'), firstSeen))
  grid.appendChild(item(t('behavior_lifecycle_field_last_seen'), lastSeen))
  grid.appendChild(item(t('behavior_lifecycle_field_started_at'), startedAt))
  grid.appendChild(item(t('behavior_lifecycle_field_ended_at'), endedAt))
  grid.appendChild(item(t('behavior_lifecycle_field_exited_at'), exitedAt))
  grid.appendChild(item(t('behavior_lifecycle_field_total_events'), String(total)))

  host.appendChild(grid)
}

function getBehaviorMitreCfg() {
  const cfg = window.api && window.api.config ? window.api.config.get() : null
  const src = cfg && cfg.behaviorMitre && typeof cfg.behaviorMitre === 'object' ? cfg.behaviorMitre : {}
  const enabled = src.enabled !== false
  const tactics = Array.isArray(src.tactics) ? src.tactics.map(String).filter(Boolean) : []
  const rules = Array.isArray(src.rules) ? src.rules : []
  return { enabled, tactics, rules }
}

function setBehaviorLifecycleView(view) {
  const v = view === 'mitre' ? 'mitre' : 'tree'
  state.behaviorLifecycle.view = v

  const tree = document.getElementById('behavior-lifecycle-tree')
  const mitre = document.getElementById('behavior-lifecycle-mitre')
  if (tree) tree.style.display = v === 'tree' ? 'block' : 'none'
  if (mitre) mitre.style.display = v === 'mitre' ? 'block' : 'none'

  updateBehaviorLifecycleTexts()
}

function renderBehaviorLifecycleTree(pid, proc, events) {
  const host = document.getElementById('behavior-lifecycle-tree')
  if (!host) return
  host.innerHTML = ''
  const builder = window.behaviorRender && window.behaviorRender.buildPidLifecycleTree
  const tree = (typeof builder === 'function')
    ? builder({ pid, process: proc || {}, events: Array.isArray(events) ? events : [], t })
    : null

  if (!tree || !tree.label) {
    const empty = document.createElement('div')
    empty.className = 'text-center text-muted'
    empty.textContent = t('behavior_lifecycle_empty')
    host.appendChild(empty)
    return
  }

  const makeNodeEl = (node) => {
    const wrap = document.createElement('div')
    wrap.className = 'tree-node'

    const textWrap = document.createElement('div')
    textWrap.className = 'd-flex flex-column'

    const titleRow = document.createElement('div')
    titleRow.className = 'tree-title'
    titleRow.title = typeof node.label === 'string' ? node.label : ''

    if (node && node.kind === 'pid' && Number.isFinite(node.pid) && node.pid !== pid) {
      const btn = document.createElement('button')
      btn.type = 'button'
      btn.className = 'tree-pid-link'
      btn.textContent = typeof node.label === 'string' ? node.label : String(node.pid)
      btn.onclick = () => openBehaviorLifecycle(node.pid)
      titleRow.appendChild(btn)
    } else {
      titleRow.textContent = typeof node.label === 'string' ? node.label : ''
    }

    textWrap.appendChild(titleRow)

    const hint = typeof node.hint === 'string' ? node.hint : ''
    if (hint) {
      const hintEl = document.createElement('div')
      hintEl.className = 'tree-hint'
      hintEl.textContent = hint
      hintEl.title = hint
      textWrap.appendChild(hintEl)
    }

    wrap.appendChild(textWrap)

    const cnt = Number.isFinite(node && node.count) ? node.count : null
    if (cnt != null && cnt > 1 && node.kind !== 'event') {
      const badge = document.createElement('span')
      badge.className = 'tree-count'
      badge.textContent = String(cnt)
      wrap.appendChild(badge)
    }
    return wrap
  }

  const buildDom = (node) => {
    const li = document.createElement('li')
    li.appendChild(makeNodeEl(node))
    const children = Array.isArray(node && node.children) ? node.children : []
    if (children.length) {
      const ul = document.createElement('ul')
      for (const ch of children) ul.appendChild(buildDom(ch))
      li.appendChild(ul)
    }
    return li
  }

  const ul = document.createElement('ul')
  ul.className = 'tree'
  ul.appendChild(buildDom(tree))
  host.appendChild(ul)
}

function renderBehaviorLifecycleMitre(pid, proc, events) {
  const host = document.getElementById('behavior-lifecycle-mitre')
  if (!host) return
  host.innerHTML = ''

  const cfg = getBehaviorMitreCfg()
  if (!cfg.enabled) {
    const el = document.createElement('div')
    el.className = 'text-center text-muted'
    el.textContent = t('behavior_mitre_disabled')
    host.appendChild(el)
    return
  }

  const builder = window.behaviorRender && window.behaviorRender.buildMitreMatrixModel
  const model = (typeof builder === 'function')
    ? builder({ pid, process: proc || {}, events: Array.isArray(events) ? events : [], cfg, t })
    : null

  if (!model || !Array.isArray(model.columns) || model.columns.length === 0) {
    const el = document.createElement('div')
    el.className = 'text-center text-muted'
    el.textContent = t('behavior_mitre_empty')
    host.appendChild(el)
    return
  }

  const stats = `${t('behavior_mitre_matched')}: ${model.matchedEvents || 0} · ${t('behavior_mitre_unmatched')}: ${model.unmatchedEvents || 0}`
  setBehaviorLifecycleStatus(stats)

  const grid = document.createElement('div')
  grid.className = 'mitre-matrix'

  const makeExample = (ex) => {
    const row = document.createElement('div')
    row.className = 'example'
    const label = (ex && typeof ex.label === 'string') ? ex.label : ''
    const hint = (ex && typeof ex.hint === 'string') ? ex.hint : ''
    row.textContent = hint ? `${label} · ${hint}` : label
    row.title = row.textContent
    return row
  }

  for (const col of model.columns) {
    const colEl = document.createElement('div')
    colEl.className = 'mitre-column'

    const head = document.createElement('div')
    head.className = 'mitre-column-title'
    const nameEl = document.createElement('div')
    nameEl.className = 'name'
    nameEl.textContent = col && typeof col.tactic === 'string' ? col.tactic : ''
    nameEl.title = nameEl.textContent
    const countEl = document.createElement('div')
    countEl.className = 'count'
    const colCount = Array.isArray(col && col.techniques) ? col.techniques.reduce((s, it) => s + (it.count || 0), 0) : 0
    countEl.textContent = String(colCount)
    head.appendChild(nameEl)
    head.appendChild(countEl)
    colEl.appendChild(head)

    const techniques = Array.isArray(col && col.techniques) ? col.techniques : []
    if (!techniques.length) {
      const empty = document.createElement('div')
      empty.className = 'text-muted small'
      empty.textContent = t('behavior_mitre_no_hits')
      colEl.appendChild(empty)
    } else {
      for (const tech of techniques) {
        const card = document.createElement('div')
        card.className = 'mitre-tech'

        const header = document.createElement('div')
        header.className = 'mitre-tech-header'

        const titleWrap = document.createElement('div')
        titleWrap.className = 'mitre-tech-title'

        const idEl = document.createElement('div')
        idEl.className = 'id'
        idEl.textContent = tech && typeof tech.techniqueId === 'string' ? tech.techniqueId : ''

        const nmEl = document.createElement('div')
        nmEl.className = 'name'
        nmEl.textContent = tech && typeof tech.techniqueName === 'string' ? tech.techniqueName : ''
        nmEl.title = nmEl.textContent

        titleWrap.appendChild(idEl)
        titleWrap.appendChild(nmEl)

        const badge = document.createElement('div')
        badge.className = 'mitre-tech-badge'
        badge.textContent = String(tech && tech.count ? tech.count : 0)

        header.appendChild(titleWrap)
        header.appendChild(badge)
        card.appendChild(header)

        const exWrap = document.createElement('div')
        exWrap.className = 'mitre-tech-examples'
        const examples = Array.isArray(tech && tech.examples) ? tech.examples : []
        for (const ex of examples) exWrap.appendChild(makeExample(ex))
        card.appendChild(exWrap)

        header.onclick = () => {
          exWrap.classList.toggle('show')
        }

        colEl.appendChild(card)
      }
    }

    grid.appendChild(colEl)
  }

  host.appendChild(grid)
}

async function loadBehaviorLifecycle(pidOverride) {
  if (!window.api || !window.api.behavior || !window.api.behavior.listEvents) return
  if (state.behaviorLifecycle.loading) return
  const pid = pidOverride != null ? pidOverride : state.behaviorLifecycle.pid
  if (pid == null) return

  state.behaviorLifecycle.loading = true
  setBehaviorLifecycleError('')
  setBehaviorLifecycleStatus('')
  updateBehaviorLifecycleButtons()

  try {
    await showLoading(t('behavior_lifecycle_loading'), t('please_wait'), 0, '')
    let processes = Array.isArray(state.tabCache.behaviorProcesses) ? state.tabCache.behaviorProcesses : []
    if (!processes.length && window.api.behavior.listProcesses) {
      const list = await window.api.behavior.listProcesses({ limit: 5000, offset: 0 })
      processes = Array.isArray(list) ? list : []
      state.tabCache.behaviorProcesses = processes
    }
    const proc = processes.find(p => Number.isFinite(p && p.pid) && p.pid === pid) || null

    const list = await window.api.behavior.listEvents({ pid, limit: Infinity, offset: 0 })
    const rows = Array.isArray(list) ? list : []

    state.behaviorLifecycle.pid = pid
    state.behaviorLifecycle.process = proc
    state.behaviorLifecycle.events = rows

    setBehaviorLifecyclePidInput(pid)
    renderBehaviorLifecycleSummary(pid, proc, rows)
    if (state.behaviorLifecycle.view === 'mitre') {
      renderBehaviorLifecycleMitre(pid, proc, rows)
    } else {
      renderBehaviorLifecycleTree(pid, proc, rows)
    }

    const shown = rows.length
    setBehaviorLifecycleMeta(`${t('behavior_filter_pid')}: ${pid} · ${t('behavior_shown')}: ${shown}`)
  } catch (e) {
    setBehaviorLifecycleError((e && e.message) ? e.message : t('behavior_events_load_failed'))
  } finally {
    hideLoading()
    state.behaviorLifecycle.loading = false
    updateBehaviorLifecycleButtons()
  }
}

function openBehaviorLifecycle(pid) {
  const p = parsePidValue(pid)
  if (p == null) return
  state.behaviorLifecycle.pid = p
  showPage('behavior-lifecycle')
  setBehaviorLifecycleView(state.behaviorLifecycle.view)
  void loadBehaviorLifecycle(p)
}

function initBehaviorLifecycle() {
  updateBehaviorLifecycleTexts()

  if (!state.tabCache.behaviorLifecycleBound) {
    const btnBack = document.getElementById('behavior-lifecycle-btn-back')
    const btnRefresh = document.getElementById('behavior-lifecycle-btn-refresh')
    const btnOpen = document.getElementById('behavior-lifecycle-btn-open')
    const btnToggle = document.getElementById('behavior-lifecycle-btn-toggle-mitre')
    const input = document.getElementById('behavior-lifecycle-pid-input')

    if (btnBack) btnBack.onclick = () => showPage('behavior')
    if (btnRefresh) btnRefresh.onclick = () => void loadBehaviorLifecycle()
    if (btnOpen) btnOpen.onclick = () => {
      const pid = getBehaviorLifecyclePidFromInput()
      if (pid == null) {
        alert(t('behavior_lifecycle_pid_required'))
        return
      }
      openBehaviorLifecycle(pid)
    }
    if (input) {
      input.onkeydown = (e) => {
        if (e && e.key === 'Enter') {
          const pid = getBehaviorLifecyclePidFromInput()
          if (pid == null) {
            alert(t('behavior_lifecycle_pid_required'))
            return
          }
          openBehaviorLifecycle(pid)
        }
      }
    }
    if (btnToggle) {
      btnToggle.onclick = () => {
        const cfg = getBehaviorMitreCfg()
        if (!cfg.enabled) {
          alert(t('behavior_mitre_disabled'))
          return
        }
        const next = state.behaviorLifecycle.view === 'mitre' ? 'tree' : 'mitre'
        setBehaviorLifecycleView(next)
        const pid = state.behaviorLifecycle.pid
        const proc = state.behaviorLifecycle.process
        const events = state.behaviorLifecycle.events
        if (pid != null && Array.isArray(events) && events.length) {
          if (next === 'mitre') renderBehaviorLifecycleMitre(pid, proc, events)
          else renderBehaviorLifecycleTree(pid, proc, events)
        } else if (pid != null) {
          void loadBehaviorLifecycle(pid)
        }
      }
    }
    state.tabCache.behaviorLifecycleBound = true
  }

  setBehaviorLifecyclePidInput(state.behaviorLifecycle.pid)
  setBehaviorLifecycleView(state.behaviorLifecycle.view)
  updateBehaviorLifecycleButtons()
}

async function refreshBehaviorProcesses() {
  if (!window.api || !window.api.behavior || !window.api.behavior.listProcesses) return
  if (state.behavior.loading) return
  state.behavior.loading = true
  setBehaviorError('')
  updateBehaviorButtons()
  const { processListLimit } = getBehaviorUiCfg()
  try {
    await showLoading(t('behavior_loading_processes'), t('please_wait'), 0, '')
    const list = await window.api.behavior.listProcesses({ limit: processListLimit, offset: 0 })
    state.tabCache.behaviorProcesses = Array.isArray(list) ? list : []
    await renderBehaviorProcessesAsync(state.tabCache.behaviorProcesses)
    setBehaviorStatus('')
  } catch {
    setBehaviorStatus(t('behavior_processes_load_failed'))
  } finally {
    hideLoading()
    state.behavior.loading = false
    updateBehaviorButtons()
  }
}

async function renderBehaviorEventsAsync(list, opts) {
  const tbody = document.getElementById('behavior-tbody')
  if (!tbody) return

  tbody.innerHTML = ''
  const arr = Array.isArray(list) ? list : []
  if (arr.length === 0) {
    const tr = document.createElement('tr')
    const td = document.createElement('td')
    td.colSpan = 7
    td.className = 'text-center text-muted'
    td.textContent = t('behavior_empty')
    tr.appendChild(td)
    tbody.appendChild(tr)
    updateLoading(100, '')
    hideLoading()
    return
  }

  const o = opts && typeof opts === 'object' ? opts : {}
  const batchSize = Number.isFinite(o.batchSize) ? Math.max(1, Math.floor(o.batchSize)) : 200
  const total = arr.length
  let done = 0
  let firstBatch = true
  for (let i = 0; i < arr.length; i += batchSize) {
    const frag = document.createDocumentFragment()
    const slice = arr.slice(i, i + batchSize)
    slice.forEach(ev => {
      const tr = document.createElement('tr')
      tr.style.cursor = 'pointer'
      tr.onclick = () => openBehaviorDetail(ev)
      const ts = typeof ev.ts === 'string' ? ev.ts : ''
      const provider = typeof ev.provider === 'string' ? ev.provider : ''
      const op = typeof ev.op === 'string' ? ev.op : ''
      const actor = formatPidCell(ev.actor_pid, ev.actor_processName, ev.actor_processImage)
      const subject = formatPidCell(ev.subject_pid, ev.subject_processName, ev.subject_processImage)
      const tid = Number.isFinite(ev.tid) ? ev.tid : ''
      const target = (typeof ev.file_path === 'string' && ev.file_path) ? ev.file_path
        : ((typeof ev.reg_key === 'string' && ev.reg_key) ? ev.reg_key : '')
      const value = (typeof ev.reg_value === 'string' && ev.reg_value) ? ev.reg_value : ''
      const targetText = value ? `${target} :: ${value}` : target
      const cols = [ts, provider, op, actor, subject, tid, targetText]
      cols.forEach((c, idx) => {
        const td = document.createElement('td')
        if (idx === 6) td.className = 'path-fade'
        td.textContent = c === null || c === undefined ? '' : String(c)
        if (idx === 6) td.title = td.textContent
        tr.appendChild(td)
      })
      frag.appendChild(tr)
    })
    tbody.appendChild(frag)
    done += slice.length
    const percent = total > 0 ? Math.floor((done / total) * 100) : 100
    updateLoading(percent, '')
    if (firstBatch) {
      firstBatch = false
      hideLoading()
      if (o.onFirstBatch) o.onFirstBatch()
    }
    if (o.onProgress) o.onProgress(total, done)
    await waitNextPaint()
  }
}

async function loadBehaviorEvents() {
  if (!window.api || !window.api.behavior || !window.api.behavior.listEvents) return
  if (state.behavior.loading) return

  state.behavior.loading = true
  setBehaviorError('')
  updateBehaviorButtons()
  const pid = state.behavior.pid

  try {
    await showLoading(t('behavior_loading_events'), t('please_wait'), 0, '')
    const { eventListLimit } = getBehaviorUiCfg()
    const query = { limit: eventListLimit, offset: 0 }
    if (pid != null) query.pid = pid
    const list = await window.api.behavior.listEvents(query)
    const rows = Array.isArray(list) ? list : []
    state.tabCache.behaviorEvents = rows

    await renderBehaviorEventsAsync(rows, {
      onProgress: (total, done) => {
        const percent = total > 0 ? Math.floor((done / total) * 100) : 100
        updateLoading(percent, `${done}/${total}`)
      },
      onFirstBatch: () => {}
    })
    const shown = rows.length
    const filterText = pid != null ? `${t('behavior_filter_pid')}: ${pid}` : t('behavior_filter_all')
    setBehaviorMeta(`${filterText} · ${t('behavior_shown')}: ${shown}`)
    setBehaviorStatus('')
  } catch (e) {
    setBehaviorError((e && e.message) ? e.message : t('behavior_events_load_failed'))
  } finally {
    hideLoading()
    state.behavior.loading = false
    updateBehaviorButtons()
  }
}

function initBehavior() {
  updateBehaviorTexts()

  const btnRefresh = document.getElementById('behavior-btn-refresh-processes')
  const btnRefreshEvents = document.getElementById('behavior-btn-refresh-events')
  const btnClearAll = document.getElementById('behavior-btn-clear-all')
  const btnApply = document.getElementById('behavior-btn-apply')
  const btnClear = document.getElementById('behavior-btn-clear')
  const btnLifecycle = document.getElementById('behavior-btn-lifecycle')

  if (!state.tabCache.behaviorBound) {
    const sel = document.getElementById('behavior-process-select')
    if (sel) {
      sel.onchange = () => {
        const pid = parsePidValue(sel.value)
        state.behavior.pid = pid
        setBehaviorPidInput(pid)
        setBehaviorProcessSelect(pid)
        loadBehaviorEvents()
      }
    }

    if (btnRefresh) {
      btnRefresh.onclick = async () => {
        await refreshBehaviorProcesses()
      }
    }
    if (btnRefreshEvents) {
      btnRefreshEvents.onclick = async () => {
        await loadBehaviorEvents()
      }
    }
    if (btnClearAll) {
      btnClearAll.onclick = async () => {
        if (!window.api || !window.api.behavior) return
        if (!window.api.behavior.pauseEtw || !window.api.behavior.clearDb || !window.api.behavior.resumeEtw) return
        if (state.behavior.loading) return
        const ok = confirm(t('behavior_clear_all_confirm'))
        if (!ok) return

        state.behavior.loading = true
        setBehaviorError('')
        updateBehaviorButtons()
        let paused = false
        try {
          await showLoading(t('behavior_clearing'), t('please_wait'), 0, '')
          const pauseOk = await window.api.behavior.pauseEtw()
          paused = pauseOk === true
          if (!paused) {
            alert(t('behavior_clear_all_failed'))
            return
          }

          const cleared = await window.api.behavior.clearDb()
          if (!cleared) {
            alert(t('behavior_clear_all_failed'))
            return
          }

          state.behavior.pid = null
          setBehaviorPidInput(null)
          setBehaviorProcessSelect(null)
          state.tabCache.behaviorProcesses = []
          state.tabCache.behaviorEvents = []

          await renderBehaviorProcessesAsync([])
          renderBehaviorEvents([], false)
          setBehaviorMeta(`${t('behavior_filter_all')} · ${t('behavior_shown')}: 0`)
          setBehaviorStatus('')
        } catch {
          alert(t('behavior_clear_all_failed'))
        } finally {
          if (paused) {
            try {
              const resumed = await window.api.behavior.resumeEtw()
              if (!resumed) alert(t('behavior_clear_all_failed'))
            } catch {
              alert(t('behavior_clear_all_failed'))
            }
          }
          hideLoading()
          state.behavior.loading = false
          updateBehaviorButtons()
        }
      }
    }
    if (btnApply) {
      btnApply.onclick = async () => {
        const pid = getBehaviorPidFromInput()
        state.behavior.pid = pid
        setBehaviorProcessSelect(pid)
        await loadBehaviorEvents()
      }
    }
    if (btnClear) {
      btnClear.onclick = async () => {
        state.behavior.pid = null
        setBehaviorPidInput(null)
        setBehaviorProcessSelect(null)
        await loadBehaviorEvents()
      }
    }
    if (btnLifecycle) {
      btnLifecycle.onclick = () => {
        const pid = state.behavior.pid != null ? state.behavior.pid : getBehaviorPidFromInput()
        if (pid == null) {
          alert(t('behavior_lifecycle_pid_required'))
          return
        }
        openBehaviorLifecycle(pid)
      }
    }
    state.tabCache.behaviorBound = true
  }

  const cachedProcesses = Array.isArray(state.tabCache.behaviorProcesses) ? state.tabCache.behaviorProcesses : []
  void renderBehaviorProcessesAsync(cachedProcesses)
  renderBehaviorEvents([], false)

  setBehaviorPidInput(state.behavior.pid)
  setBehaviorProcessSelect(state.behavior.pid)
  updateBehaviorButtons()
}

async function initQuarantine() {
  console.log('渲染进程: 初始化隔离区')
  const title = document.getElementById('quarantine-title')
  if (title) title.textContent = t('quarantine_title')
  const desc = document.getElementById('quarantine-desc')
  if (desc) desc.textContent = t('quarantine_desc')
  const thFilename = document.getElementById('th-filename')
  if (thFilename) thFilename.textContent = t('quarantine_table_filename')
  const thPath = document.getElementById('th-path')
  if (thPath) thPath.textContent = t('quarantine_table_path')
  const thDate = document.getElementById('th-date')
  if (thDate) thDate.textContent = t('quarantine_table_date')
  const thActions = document.getElementById('th-actions')
  if (thActions) thActions.textContent = t('quarantine_table_actions')
  const tbody = document.getElementById('quarantine-tbody')
  const emptyMsg = document.getElementById('quarantine-empty-msg')
  const actions = document.getElementById('quarantine-actions')
  const selectAll = document.getElementById('quarantine-select-all')
  const btnRestoreSelected = document.getElementById('quarantine-btn-restore-selected')
  if (btnRestoreSelected) btnRestoreSelected.textContent = t('btn_restore')
  const btnDeleteSelected = document.getElementById('quarantine-btn-delete-selected')
  if (btnDeleteSelected) btnDeleteSelected.textContent = t('btn_delete')
  
  if (!tbody) return
  
  tbody.innerHTML = ''
  state.quarantineItems = []
  if (actions) actions.style.display = 'none'
  if (selectAll) {
    selectAll.checked = false
    selectAll.indeterminate = false
  }
  if (btnRestoreSelected) btnRestoreSelected.disabled = true
  if (btnDeleteSelected) btnDeleteSelected.disabled = true
  
  let list = []
  try {
    list = await window.api.quarantine.list()
  } catch (e) {
    console.error('Failed to load quarantine list', e)
  }
  
  if (actions) actions.style.display = 'flex'
  if (emptyMsg) emptyMsg.textContent = t('quarantine_empty')
  if (!list || list.length === 0) {
    if (emptyMsg) emptyMsg.style.display = 'block'
    if (selectAll) selectAll.disabled = true
    return
  }

  if (emptyMsg) emptyMsg.style.display = 'none'
  if (selectAll) selectAll.disabled = false
  state.quarantineItems = list
  
  list.forEach(item => {
    const tr = document.createElement('tr')
    const tdSel = document.createElement('td')
    const chk = document.createElement('input')
    chk.type = 'checkbox'
    chk.className = 'form-check-input quarantine-checkbox'
    chk.dataset.id = item.id
    tdSel.appendChild(chk)
    
    const tdName = document.createElement('td')
    tdName.textContent = item.fileName
    
    const tdPath = document.createElement('td')
    tdPath.className = 'path-fade'
    tdPath.textContent = item.originalPath
    tdPath.title = item.originalPath
    
    const tdDate = document.createElement('td')
    try { tdDate.textContent = new Date(item.date).toLocaleString() } catch { tdDate.textContent = item.date }
    
    const tdActions = document.createElement('td')
    const btnRestore = document.createElement('button')
    btnRestore.className = 'btn btn-sm btn-success me-1'
    btnRestore.textContent = t('btn_restore')
    btnRestore.onclick = async () => {
        await window.api.quarantine.restore(item.id)
        initQuarantine()
    }
    
    const btnDel = document.createElement('button')
    btnDel.className = 'btn btn-sm btn-danger'
    btnDel.textContent = t('btn_delete')
    btnDel.onclick = async () => {
        await window.api.quarantine.delete(item.id)
        initQuarantine()
    }
    
    tdActions.appendChild(btnRestore)
    tdActions.appendChild(btnDel)
    
    tr.appendChild(tdSel)
    tr.appendChild(tdName)
    tr.appendChild(tdPath)
    tr.appendChild(tdDate)
    tr.appendChild(tdActions)
    tbody.appendChild(tr)
  })
  if (selectAll) {
    selectAll.onclick = () => {
      const boxes = tbody.querySelectorAll('.quarantine-checkbox')
      boxes.forEach(chk => { chk.checked = selectAll.checked })
      const anySelected = Array.from(boxes).some(b => b.checked)
      if (btnRestoreSelected) btnRestoreSelected.disabled = !anySelected
      if (btnDeleteSelected) btnDeleteSelected.disabled = !anySelected
    }
  }
  tbody.querySelectorAll('.quarantine-checkbox').forEach(chk => {
    chk.onchange = () => {
      const boxes = tbody.querySelectorAll('.quarantine-checkbox')
      const anySelected = Array.from(boxes).some(b => b.checked)
      if (btnRestoreSelected) btnRestoreSelected.disabled = !anySelected
      if (btnDeleteSelected) btnDeleteSelected.disabled = !anySelected
    }
  })
  if (btnRestoreSelected) {
    btnRestoreSelected.onclick = async () => {
      const boxes = tbody.querySelectorAll('.quarantine-checkbox')
      const ids = Array.from(boxes).filter(b => b.checked).map(b => b.dataset.id)
      if (!ids.length) return
      const ok = confirm(t('confirm_restore'))
      if (!ok) return
      try {
        for (const id of ids) {
          await window.api.quarantine.restore(id)
        }
        initQuarantine()
      } catch {
        alert(t('restore_failed'))
      }
    }
  }
  if (btnDeleteSelected) {
    btnDeleteSelected.onclick = async () => {
      const boxes = tbody.querySelectorAll('.quarantine-checkbox')
      const ids = Array.from(boxes).filter(b => b.checked).map(b => b.dataset.id)
      if (!ids.length) return
      const ok = confirm(t('confirm_delete'))
      if (!ok) return
      try {
        for (const id of ids) {
          await window.api.quarantine.delete(id)
        }
        initQuarantine()
      } catch {
        alert(t('delete_failed'))
      }
    }
  }
}

function tryInterrupt(action) {
    if (state.scanning) {
        alert(t('scan_in_progress_warning'))
        return
    }
    action()
}

let lastHealthResult = null

function updateHealthUi(res) {
  const el = document.getElementById('health-status')
  const overviewEl = document.getElementById('overview-health-status')
  
  const isOnline = res && (res.status === 'ok' || res.ok)
  const statusText = t('engine_status') + ': ' + (isOnline ? t('engine_online') : t('engine_offline'))
  const statusClass = 'status ' + (isOnline ? 'status-ok' : 'status-offline')
  const badgeClass = 'badge ' + (isOnline ? 'bg-success' : 'bg-danger')

  if (el) {
    el.textContent = statusText
    el.className = statusClass
  }

  if (overviewEl) {
    overviewEl.innerHTML = `<span class="${badgeClass}">${statusText}</span>`
  }
}

function updateTexts() {
    initNav()
    if (state.page === 'overview') initOverview()
    if (state.page === 'scan') initScan()
    if (state.page === 'quarantine') initQuarantine()
    if (state.page === 'behavior') updateBehaviorTexts()
    if (state.page === 'behavior-lifecycle') updateBehaviorLifecycleTexts()
    if (state.page === 'exclusions') initExclusions()
    if (state.page === 'settings') initSettings()
    updateHealthUi(lastHealthResult)
}

function restoreTabState(tab) {
    setScanTab(tab || 'quick')
}

function initExclusions() {
    console.log('渲染进程: 初始化排除项页');
    document.getElementById('exclusions-title').textContent = t('exclusions_title');
    document.getElementById('exclusions-desc').textContent = t('exclusions_desc');
    const btnAddFile = document.getElementById('excl-btn-file');
    if (btnAddFile) btnAddFile.textContent = t('exclusions_btn_add_file');
    const btnAddDir = document.getElementById('excl-btn-dir');
    if (btnAddDir) btnAddDir.textContent = t('exclusions_btn_add_dir');
    
    document.getElementById('excl-th-type').textContent = t('exclusions_table_type');
    document.getElementById('excl-th-path').textContent = t('exclusions_table_path');
    document.getElementById('excl-th-actions').textContent = t('exclusions_table_actions');

    const selectAll = document.getElementById('excl-select-all');
    const btnDeleteSelected = document.getElementById('excl-btn-delete-selected');
    if (btnDeleteSelected) btnDeleteSelected.textContent = t('btn_delete');
    const actionsPanel = document.getElementById('excl-actions');

    const render = () => {
        const list = window.api.exclusions.list();
        const tbody = document.getElementById('excl-tbody');
        const emptyMsg = document.getElementById('excl-empty-msg');
        
        if (!tbody) return;
        tbody.innerHTML = '';
        
        if (selectAll) {
            selectAll.checked = false;
            selectAll.indeterminate = false;
        }
        if (btnDeleteSelected) btnDeleteSelected.disabled = true;
        if (actionsPanel) actionsPanel.style.display = 'none';

        if (!list || list.length === 0) {
            if (emptyMsg) {
                emptyMsg.textContent = t('exclusions_empty');
                emptyMsg.style.display = 'block';
            }
            if (selectAll) selectAll.disabled = true;
            return;
        }
        
        if (emptyMsg) emptyMsg.style.display = 'none';
        if (selectAll) selectAll.disabled = false;
        if (actionsPanel) actionsPanel.style.display = 'flex';

        list.forEach(item => {
            const tr = document.createElement('tr');
            
            const tdSel = document.createElement('td'); 
            const chk = document.createElement('input');
            chk.type = 'checkbox';
            chk.className = 'form-check-input excl-checkbox';
            chk.dataset.path = item.path;
            chk.onchange = () => {
                updateSelectionState();
            };
            tdSel.appendChild(chk);
            
            const tdType = document.createElement('td');
            tdType.textContent = item.type === 'file' ? t('exclusions_type_file') : t('exclusions_type_dir');
            
            const tdPath = document.createElement('td');
            tdPath.className = 'path-fade';
            tdPath.textContent = item.path;
            tdPath.title = item.path;
            
            const tdActions = document.createElement('td');
            const btnDel = document.createElement('button');
            btnDel.className = 'btn btn-sm btn-danger';
            btnDel.textContent = t('btn_delete');
            btnDel.onclick = async () => {
                const ok = await showExclDeleteConfirm([item.path]);
                if (!ok) return;
                window.api.exclusions.remove(item.path);
                render();
            };
            tdActions.appendChild(btnDel);
            
            tr.appendChild(tdSel);
            tr.appendChild(tdType);
            tr.appendChild(tdPath);
            tr.appendChild(tdActions);
            tbody.appendChild(tr);
        });
    };

    const updateSelectionState = () => {
        const tbody = document.getElementById('excl-tbody');
        if (!tbody) return;
        const boxes = tbody.querySelectorAll('.excl-checkbox');
        const total = boxes.length;
        const checked = Array.from(boxes).filter(b => b.checked).length;
        
        if (selectAll) {
            selectAll.checked = total > 0 && total === checked;
            selectAll.indeterminate = checked > 0 && checked < total;
        }
        
        if (btnDeleteSelected) {
            btnDeleteSelected.disabled = checked === 0;
        }
    };

    if (selectAll) {
        selectAll.onclick = () => {
            const tbody = document.getElementById('excl-tbody');
            if (!tbody) return;
            const boxes = tbody.querySelectorAll('.excl-checkbox');
            boxes.forEach(b => { b.checked = selectAll.checked; });
            updateSelectionState();
        };
    }

    if (btnDeleteSelected) {
        btnDeleteSelected.onclick = async () => {
            const tbody = document.getElementById('excl-tbody');
            if (!tbody) return;
            const boxes = tbody.querySelectorAll('.excl-checkbox');
            const paths = Array.from(boxes).filter(b => b.checked).map(b => b.dataset.path);
            if (!paths.length) return;
            const ok = await showExclDeleteConfirm(paths);
            if (!ok) return;
            paths.forEach(p => window.api.exclusions.remove(p));
            render();
        };
    }

    if (btnAddFile) {
        btnAddFile.onclick = async () => {
            const p = await window.api.dialog.openFile();
            if (p && typeof p === 'string' && p.length > 0) {
                const ok = await showExclAddConfirm('file', p);
                if (!ok) return;
                window.api.exclusions.addFile(p);
                render();
            }
        };
    }

    if (btnAddDir) {
        btnAddDir.onclick = async () => {
            const p = await window.api.dialog.openDirectory();
            if (p && typeof p === 'string' && p.length > 0) {
                const ok = await showExclAddConfirm('dir', p);
                if (!ok) return;
                window.api.exclusions.addDir(p);
                render();
            }
        };
    }
    
    render();
}

function initSettings() {
    console.log('渲染进程: 初始化设置页');
    document.getElementById('settings-title').textContent = t('settings_title');
    const labelLocale = document.getElementById('label-locale');
    if (labelLocale) labelLocale.textContent = t('settings_language');
    const optZh = document.querySelector('#select-locale option[value="zh-CN"]');
    if (optZh) optZh.textContent = t('locale_zh_CN');
    const optEn = document.querySelector('#select-locale option[value="en-US"]');
    if (optEn) optEn.textContent = t('locale_en_US');

    const labelBehaviorMonitoring = document.getElementById('label-behavior-monitoring');
    if (labelBehaviorMonitoring) labelBehaviorMonitoring.textContent = t('settings_behavior_monitoring');

    const labelAuto = document.getElementById('label-auto-tune');
    if (labelAuto) labelAuto.textContent = t('settings_auto_tune');

    const labelTokens = document.querySelector('label[for="input-max-tokens"]');
    if (labelTokens) labelTokens.textContent = t('settings_tokens_label');

    const labelFileSize = document.getElementById('label-max-file-size');
    if (labelFileSize) labelFileSize.textContent = t('settings_max_file_size_label');
    const cfg = window.api.config.get();
    if (!cfg) return;

    const selLocale = document.getElementById('select-locale');
    if (selLocale) {
        selLocale.value = cfg.locale || 'zh-CN';
        selLocale.onchange = null;
        selLocale.onchange = () => {
            const val = selLocale.value;
            console.log('设置: 切换语言', val);
            window.api.config.setLocale(val);
            updateTexts();
            initSettings();
        };
    }

    const toggleBehaviorMonitoring = document.getElementById('toggle-behavior-monitoring');
    const isBehaviorMonitoringEnabled = !(!cfg.behaviorMonitoring || cfg.behaviorMonitoring.enabled === false);
    if (toggleBehaviorMonitoring) {
        toggleBehaviorMonitoring.checked = isBehaviorMonitoringEnabled;
        toggleBehaviorMonitoring.onchange = () => {
            const val = toggleBehaviorMonitoring.checked;
            window.api.config.setBehaviorMonitoringEnabled(val);
        };
    }

    const toggleAuto = document.getElementById('toggle-auto-tune');
    const manualDiv = document.getElementById('manual-tokens');
    const isAuto = cfg.scanner && cfg.scanner.tuningEnabled;
    if (toggleAuto) {
        toggleAuto.checked = isAuto;
        toggleAuto.onchange = () => {
            const val = toggleAuto.checked;
            window.api.config.setTuningEnabled(val);
            if (manualDiv) manualDiv.style.display = val ? 'none' : 'block';
        };
    }
    if (manualDiv) manualDiv.style.display = isAuto ? 'none' : 'block';

    const inputTokens = document.getElementById('input-max-tokens');
    if (inputTokens) {
        inputTokens.value = (cfg.scanner && cfg.scanner.maxTokens) || 16;
        inputTokens.onchange = () => {
            window.api.config.setMaxTokens(inputTokens.value);
        };
    }

    const inputFileSize = document.getElementById('input-max-file-size');
    if (inputFileSize) {
        inputFileSize.value = (cfg.scanner && cfg.scanner.maxFileSizeMB) || 100;
        inputFileSize.onchange = () => {
            window.api.config.setMaxFileSizeMB(inputFileSize.value);
        };
    }
}




function startHealthPoll() {
  const poll = async () => {
    try {
      lastHealthResult = await window.api.scanner.health()
    } catch (e) {
      lastHealthResult = { status: 'offline' }
    }
    updateHealthUi(lastHealthResult)
  }

  const cfg = window.api.config.get()
  const interval = (cfg && cfg.scanner && cfg.scanner.healthPollIntervalMs) || 5000
  
  poll()
  setInterval(poll, interval)
}

if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', () => {
    setTheme()
    initNav()
    updateTexts()
    showPage('overview')
    initOverviewEtwFileEventTag()
    startHealthPoll()
    try {
      if (window.api && window.api.intercept && typeof window.api.intercept.onShow === 'function') {
        window.api.intercept.onShow((payload) => showInterceptModal(payload))
      }
    } catch {}
  })
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { formatEtwFileEventText, formatEtwFileOpLabel }
}
