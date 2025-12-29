const { app, BrowserWindow, Tray, Menu, nativeImage, dialog, ipcMain } = require('electron')
const { Worker } = require('worker_threads')
const path = require('path')
const fs = require('fs')
const { startIfNeeded, checkEngineHealth } = require('./engine_autostart')
const { createScannerClient } = require('./scanner_client')
const quarantineManager = require('./quarantine_manager')
const processes = require('./processes')
const scanCache = require('./scan_cache')
const { createBehaviorAnalyzer } = require('./behavior_analyzer')
const { resolveMainWindowOptions } = require('./window_options')
const { formatEtwEventForConsole, formatEtwEventForParsedConsole, resolveEtwOpMeaning, createRateLimiter, sanitizeText, isCleanText, isLikelyProcessImageText, resolveFileFromBaseDirs } = require('./utils')
const { createEtwPidCache } = require('./etw_pid_cache')
const { createEtwTrustedPidFilter } = require('./etw_trusted_pid_filter')
const { createInterceptionQueue } = require('./interception_manager')
const { resolveTrayExitMode } = require('./tray_exit_mode')

let winapi = null
try {
  winapi = require('./winapi')
} catch {}

const gotTheLock = app.requestSingleInstanceLock()
if (!gotTheLock) {
  app.quit()
} else {
  app.on('second-instance', () => {
    if (win) {
      if (win.isMinimized()) win.restore()
      win.show()
      win.focus()
    }
  })
}

function loadConfig() {
  const p = path.join(__dirname, '../../config/app.json')
  try {
    const raw = fs.readFileSync(p, 'utf-8')
    return JSON.parse(raw)
  } catch {
    return {
      brand: 'AnXin Security',
      themeColor: '#4CA2FF',
      defaultPage: 'overview',
      minimizeToTray: true,
      tray: { exitKeepScannerServicePrompt: true, exitKeepScannerServiceDefault: true },
      ui: { animations: true, window: { minWidth: 800, minHeight: 600 } },  
      engine: { autoStart: true, exeRelativePath: 'Engine\\Axon_v2\\Axon_ml.exe', processName: 'Axon_ml.exe', args: [] },
      scanner: {
        timeoutMs: 10000,
        healthPollIntervalMs: 30000,
        maxFileSizeMB: 500,
        ipc: { enabled: true, prefer: true, host: '127.0.0.1', port: 8765, connectTimeoutMs: 500, timeoutMs: 10000 }
      },
      behaviorAnalyzer: { enabled: true, flushIntervalMs: 500, sqlite: { mode: 'file', directory: '%TEMP%', fileName: 'anxin_etw_behavior.db' } }
    }
  }
}

let tray
let win
let splash
let config = loadConfig()
const behavior = createBehaviorAnalyzer(config)
const scannerClient = createScannerClient(() => config)
let i18nDict = {}

const trayExitPromptPending = new Map()
ipcMain.on('tray-exit-prompt:submit', (_event, payload) => {
  const p = payload && typeof payload === 'object' ? payload : {}
  const requestId = typeof p.requestId === 'string' ? p.requestId : ''
  if (!requestId) return
  const pending = trayExitPromptPending.get(requestId)
  if (!pending) return
  trayExitPromptPending.delete(requestId)

  const keep = p.keep === true ? true : (p.keep === false ? false : null)
  try { if (pending.win && !pending.win.isDestroyed()) pending.win.close() } catch {}
  try { pending.resolve(keep) } catch {}
})

function loadI18n() {
  try {
    const locale = (config && config.locale) ? config.locale : 'zh-CN'
    const p = path.join(__dirname, `../../config/i18n/${locale}.json`)
    const raw = fs.readFileSync(p, 'utf-8')
    return JSON.parse(raw)
  } catch {
    try {
      const fallback = path.join(__dirname, '../../config/i18n/zh-CN.json')
      const raw = fs.readFileSync(fallback, 'utf-8')
      return JSON.parse(raw)
    } catch {
      return {}
    }
  }
}
function t(key) { return i18nDict[key] || key }

let etwWorker = null
const eventLogs = []
let etwConsoleLimiter = null
let etwConsoleLimiterMax = null
const etwPidCache = createEtwPidCache()
const etwTrustedPidFilter = createEtwTrustedPidFilter({
  verifyTrust: (p) => {
    if (!winapi || typeof winapi.verifyTrust !== 'function') return false
    return winapi.verifyTrust(p) === true
  },
  devicePathToDosPath: (p) => {
    if (!winapi || typeof winapi.devicePathToDosPath !== 'function') return p
    return winapi.devicePathToDosPath(p) || p
  }
})
let interceptionSnapshotWorker = null
let interceptionSnapshotStarted = false
let isSnapshotScanning = false
let scanPromiseResolve = null
const scanPromise = new Promise((resolve) => { scanPromiseResolve = resolve })
let interceptionResumeInFlight = false
const interceptionQueue = createInterceptionQueue({
  showFn: (payload) => {
    if (isSnapshotScanning) return false
    if (splash && !splash.isDestroyed()) return false
    if (!win || win.isDestroyed()) return false
    const wc = win.webContents
    if (!wc) return false
    try {
      if (typeof wc.isLoading === 'function' && wc.isLoading()) return false
      if (typeof wc.getURL === 'function' && !wc.getURL()) return false
    } catch {
      return false
    }
    try {
      if (win.isMinimized()) win.restore()
      win.show()
      win.focus()
    } catch {}
    try {
      console.log('主进程: 发送拦截弹窗', payload.pid)
      win.webContents.send('intercept:show', payload)
      return true
    } catch {
      return false
    }
  }
})
try {
  const etwCfg = (config && config.etw) ? config.etw : {}
  const icfg = (etwCfg && etwCfg.interception && typeof etwCfg.interception === 'object') ? etwCfg.interception : null
  interceptionQueue.configure(icfg)
} catch {}
let etwPidSnapshotAt = 0
let etwPidSnapshotInFlight = false
let etwControlSeq = 1
const etwControlPending = new Map()
let etwStartPending = null
let etwLastStatus = null
let etwLastError = null

function resolveAppIconPath() {
  try {
    return resolveFileFromBaseDirs(getEngineBaseDirs(), 'favicon.ico')
  } catch {
    return ''
  }
}

function getProcessNameFromPath(p) {
  if (typeof p !== 'string' || !p) return ''
  try {
    const n = path.basename(p)
    return sanitizeText(typeof n === 'string' ? n : '')
  } catch { return '' }
}

function refreshEtwPidCacheConfig(etwCfg) {
  const max = Number.isFinite(etwCfg.processNameCacheMax) ? Math.max(0, Math.floor(etwCfg.processNameCacheMax)) : 2048
  const ttlMs = Number.isFinite(etwCfg.processNameCacheTtlMs) ? Math.max(0, Math.floor(etwCfg.processNameCacheTtlMs)) : 300000
  etwPidCache.configure({ max, ttlMs })
}

function pruneEtwPidCache(now) {
  etwPidCache.prune(now)
}

function upsertEtwPid(pid, imagePath, now) {
  etwPidCache.upsert(pid, imagePath, now)
}

function removeEtwPid(pid) {
  etwPidCache.remove(pid)
}

function resolveEtwProcessInfo(pid, now, etwCfg) {
  return etwPidCache.resolve(pid, now)
}

async function takeEtwPidSnapshot() {
  if (etwPidSnapshotInFlight) return
  const etwCfg = (config && config.etw) ? config.etw : {}
  const snapCfg = (etwCfg && etwCfg.pidSnapshot && typeof etwCfg.pidSnapshot === 'object') ? etwCfg.pidSnapshot : {}
  const enabled = snapCfg.enabled !== false
  if (!enabled) return
  const w = ensureInterceptionSnapshotWorker()
  const canSync = !!(winapi && typeof winapi.getProcessImageSnapshot === 'function')
  if (!w && !canSync) return

  const maxPids = Number.isFinite(snapCfg.maxPids) ? Math.max(256, Math.floor(snapCfg.maxPids)) : 8192
  const now = Date.now()
  if (etwPidSnapshotAt && now - etwPidSnapshotAt < 10000) return
  etwPidSnapshotAt = now
  etwPidSnapshotInFlight = true
  try {
    refreshEtwPidCacheConfig(etwCfg)
    let list = []
    if (w) {
      const reqId = String(interceptionControlSeq++)
      const out = await requestInterceptionPidSnapshot(w, reqId, maxPids, 12000)
      list = out && out.ok && Array.isArray(out.list) ? out.list : []
    }
    if ((!list || !list.length) && canSync) {
      list = winapi.getProcessImageSnapshot(maxPids)
    }
    etwPidCache.bulkUpsert(list, now)
    try {
      const fcfg = (etwCfg && etwCfg.signedPidFilter && typeof etwCfg.signedPidFilter === 'object') ? etwCfg.signedPidFilter : null
      etwTrustedPidFilter.configure(fcfg)
      etwTrustedPidFilter.seedFromSnapshot(list)
    } catch {}
    pruneEtwPidCache(now)
  } catch {
  } finally {
    etwPidSnapshotInFlight = false
  }
}

let interceptionControlSeq = 1
const interceptionControlPending = new Map()

function ensureInterceptionSnapshotWorker() {
  if (interceptionSnapshotWorker) return interceptionSnapshotWorker
  try {
    const workerPath = path.join(__dirname, 'workers/interception_snapshot_worker.js')
    if (!fs.existsSync(workerPath)) return null
    interceptionSnapshotWorker = new Worker(workerPath)
    interceptionSnapshotWorker.on('message', (msg) => {
      const m = msg && typeof msg === 'object' ? msg : null
      const typ = m && typeof m.type === 'string' ? m.type : ''
      if (typ === 'paused') {
        const pid = Number.isFinite(m.pid) ? m.pid : parseInt(String(m.pid), 10)
        if (!Number.isFinite(pid) || pid <= 0) return
        const imagePath = typeof m.imagePath === 'string' ? m.imagePath : ''
        const unsignedDlls = Array.isArray(m.unsignedDlls) ? m.unsignedDlls.filter(x => typeof x === 'string' && x) : []
        const payload = {
          pid,
          paused: m.paused === true,
          triggeredAt: Date.now(),
          match: { ruleId: 'unsigned_dll', provider: 'Process', op: 'Snapshot', target: '' },
          process: { name: getProcessNameFromPath(imagePath), imagePath },
          event: { provider: 'Process', data: { type: 'UnsignedDll', unsignedDlls } }
        }
        interceptionQueue.enqueuePausedProcess(payload)
        return
      }
      if (typ === 'pid_snapshot_done') {
        const requestId = typeof m.requestId === 'string' ? m.requestId : ''
        if (!requestId) return
        const pending = interceptionControlPending.get(requestId)
        if (!pending) return
        interceptionControlPending.delete(requestId)
        try { if (pending.timer) clearTimeout(pending.timer) } catch {}
        try { pending.resolve(m) } catch {}
        return
      }
      if (typ === 'scan_done') {
        isSnapshotScanning = false
        handleSnapshotScanDone().finally(() => {
          if (scanPromiseResolve) scanPromiseResolve(true)
        })
        return
      }
      if (typ === 'resume_many_done') {
        const requestId = typeof m.requestId === 'string' ? m.requestId : ''
        if (!requestId) return
        const pending = interceptionControlPending.get(requestId)
        if (!pending) return
        interceptionControlPending.delete(requestId)
        try { if (pending.timer) clearTimeout(pending.timer) } catch {}
        try { pending.resolve(m) } catch {}
      }
    })
    interceptionSnapshotWorker.on('error', () => {
      interceptionSnapshotWorker = null
    })
    interceptionSnapshotWorker.on('exit', () => {
      interceptionSnapshotWorker = null
    })
    return interceptionSnapshotWorker
  } catch {
    interceptionSnapshotWorker = null
    return null
  }
}

function requestInterceptionPidSnapshot(w, requestId, maxPids, timeoutMs) {
  const rid = typeof requestId === 'string' ? requestId : ''
  if (!rid || !w) return Promise.resolve({ ok: false })
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      if (interceptionControlPending.has(rid)) interceptionControlPending.delete(rid)
      resolve({ ok: false, timeout: true })
    }, Math.max(250, timeoutMs || 0))
    try { if (timer.unref) timer.unref() } catch {}
    interceptionControlPending.set(rid, { resolve, timer })
    try { w.postMessage({ type: 'pid_snapshot', requestId: rid, maxPids }) } catch {
      try { clearTimeout(timer) } catch {}
      if (interceptionControlPending.has(rid)) interceptionControlPending.delete(rid)
      resolve({ ok: false })
    }
  })
}

function requestInterceptionResumeMany(pids, timeoutMs = 15000) {
  const ps = Array.isArray(pids) ? pids : []
  const list = ps.map(x => (Number.isFinite(x) ? x : parseInt(String(x), 10))).filter(x => Number.isFinite(x) && x > 0)
  if (list.length === 0) return Promise.resolve({ ok: true, skipped: true, total: 0, resumed: 0 })
  const w = ensureInterceptionSnapshotWorker()
  if (!w) return Promise.resolve({ ok: false, error: 'NO_WORKER' })
  const requestId = String(interceptionControlSeq++)
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      if (interceptionControlPending.has(requestId)) interceptionControlPending.delete(requestId)
      resolve({ ok: false, timeout: true })
    }, Math.max(250, timeoutMs || 0))
    try { if (timer.unref) timer.unref() } catch {}
    interceptionControlPending.set(requestId, { resolve, timer })
    try { w.postMessage({ type: 'resume_many', requestId, pids: list }) } catch {
      try { clearTimeout(timer) } catch {}
      if (interceptionControlPending.has(requestId)) interceptionControlPending.delete(requestId)
      resolve({ ok: false })
    }
  })
}

async function resumeAllInterceptedProcesses() {
  if (interceptionResumeInFlight) return false
  interceptionResumeInFlight = true
  try {
    const pids = interceptionQueue.getPausedPids()
    if (pids.length === 0) return true
    const res = await requestInterceptionResumeMany(pids, 20000)
    interceptionQueue.clearAll()
    return !!(res && res.ok !== false)
  } catch {
    interceptionQueue.clearAll()
    return false
  } finally {light = false
  }
}

async function handleSnapshotScanDone() {
  try {
    const paused = interceptionQueue.getAllPausedPayloads()
    const etwCfg = (config && config.etw) ? config.etw : {}
    const icfg = (etwCfg && etwCfg.interception && typeof etwCfg.interception === 'object') ? etwCfg.interception : {}
    const threshold = Number.isFinite(icfg.snapshotTrustThreshold) ? icfg.snapshotTrustThreshold : 3

    if (paused.length > threshold && win && !win.isDestroyed()) {
      try {
        if (win.isMinimized()) win.restore()
        win.show()
        win.focus()
      } catch {}

      const result = await dialog.showMessageBox(win, {
        type: 'question',
        title: t('scan_trust_title'),
        message: t('scan_trust_message_part1') + paused.length + t('scan_trust_message_part2'),
        detail: t('scan_trust_detail'),
        buttons: [t('scan_trust_yes'), t('scan_trust_no')],
        defaultId: 0,
        cancelId: 1,
        noLink: true
      })

      if (result.response === 0) {
        const allowPaths = new Set()
        for (const p of paused) {
          if (p && p.process && typeof p.process.imagePath === 'string' && p.process.imagePath) {
            allowPaths.add(p.process.imagePath)
            etwTrustedPidFilter.addUserTrustedPath(p.process.imagePath)
            if (p.pid) etwTrustedPidFilter.addTrustedPid(p.pid)
          }
          const dlls = p && p.event && p.event.data && Array.isArray(p.event.data.unsignedDlls) ? p.event.data.unsignedDlls : []
          for (const d of dlls) {
            if (typeof d === 'string' && d) allowPaths.add(d)
          }
        }

        if (allowPaths.size > 0 && interceptionSnapshotWorker) {
          interceptionSnapshotWorker.postMessage({ type: 'allow_dlls', paths: Array.from(allowPaths) })
        }

        await resumeAllInterceptedProcesses()
        return
      }
    }

    interceptionQueue.tryShowNext()
  } catch (e) {
    console.error('Snapshot scan done handler error:', e)
    interceptionQueue.tryShowNext()
  }
}


function startInterceptionSnapshotScan() {
  try {
    const etwCfg = (config && config.etw) ? config.etw : {}
    const icfg = (etwCfg && etwCfg.interception && typeof etwCfg.interception === 'object') ? etwCfg.interception : {}
    interceptionQueue.configure(icfg)
    if (icfg.enabled !== true) { isSnapshotScanning = false; if (scanPromiseResolve) scanPromiseResolve(true); return }
    if (icfg.snapshotVerifyOnEtwStart === false) { isSnapshotScanning = false; if (scanPromiseResolve) scanPromiseResolve(true); return }
    if (interceptionSnapshotStarted) return
    interceptionSnapshotStarted = true
    isSnapshotScanning = true
    const w = ensureInterceptionSnapshotWorker()
    if (!w) { isSnapshotScanning = false; if (scanPromiseResolve) scanPromiseResolve(true); return }
    const maxPids = Number.isFinite(icfg.snapshotMaxPids) ? Math.max(256, Math.floor(icfg.snapshotMaxPids)) : 8192
    const modulesBufferBytes = Number.isFinite(icfg.modulesBufferBytes) ? Math.max(4096, Math.floor(icfg.modulesBufferBytes)) : 65536
    const skipSystemDll = icfg.skipSystemDll !== false
    const maxUnsignedDllsPerProcess = Number.isFinite(icfg.maxUnsignedDllsPerProcess) ? Math.max(1, Math.floor(icfg.maxUnsignedDllsPerProcess)) : 16

    const exclusionPaths = []
    try {
      const sysRoot = process.env.SystemRoot || process.env.WINDIR
      if (sysRoot) exclusionPaths.push(sysRoot)
      exclusionPaths.push(path.dirname(app.getPath('exe')))
      exclusionPaths.push(app.getAppPath())
    } catch {}

    w.postMessage({ type: 'scan', config: { maxPids, modulesBufferBytes, skipSystemDll, maxUnsignedDllsPerProcess, exclusionPaths } })
  } catch {
    isSnapshotScanning = false
    if (scanPromiseResolve) scanPromiseResolve(true)
  }
}

function startEtwWorker() {
  if (etwWorker) return
  try {
    const workerPath = path.join(__dirname, 'workers/etw_worker.js')
    if (!fs.existsSync(workerPath)) {
      console.warn('主进程: ETW Worker 脚本未找到:', workerPath)
      return
    }
    etwWorker = new Worker(workerPath)
    
    etwWorker.on('message', (msg) => {
      if (msg && (msg.type === 'paused' || msg.type === 'resumed')) {
        const reqId = msg.requestId
        const pending = etwControlPending.get(reqId)
        if (pending) {
          etwControlPending.delete(reqId)
          try { if (pending.timer) clearTimeout(pending.timer) } catch {}
          try { pending.resolve(msg) } catch {}
        }
        return
      }
      if (msg.type === 'log') {
        const ev = msg.event && typeof msg.event === 'object' ? msg.event : null
        const p = ev && typeof ev.provider === 'string' ? ev.provider : ''
        const d = ev && ev.data && typeof ev.data === 'object' ? ev.data : null
        const etwCfg = (config && config.etw) ? config.etw : {}
        try {
          const fcfg = (etwCfg && etwCfg.signedPidFilter && typeof etwCfg.signedPidFilter === 'object') ? etwCfg.signedPidFilter : null
          etwTrustedPidFilter.configure(fcfg)
        } catch {}

        try {
          if (p === 'Process' && d) {
            refreshEtwPidCacheConfig(etwCfg)
            const now = Date.now()
            pruneEtwPidCache(now)
            const typ = typeof d.type === 'string' ? d.type : ''
            const subjectPid = Number.isFinite(d.processId) ? d.processId : null
            if (typ === 'Start') {
              const pid = subjectPid
              if (pid != null) {
                let img = null
                if (winapi && typeof winapi.getProcessImagePathByPid === 'function') {
                  try { img = winapi.getProcessImagePathByPid(pid) } catch {}
                }
                if (!img) img = (typeof d.imageName === 'string' && d.imageName) ? d.imageName : null
                if (img) upsertEtwPid(pid, img, now)
                try { if (img) etwTrustedPidFilter.onProcessStart(pid, img) } catch {}
              }
            } else if (typ === 'Stop') {
              if (subjectPid != null) {
                removeEtwPid(subjectPid)
                try { etwTrustedPidFilter.onProcessStop(subjectPid) } catch {}
              }
            }
          }
        } catch {}

        let shouldSkip = false
        try { shouldSkip = etwTrustedPidFilter.shouldSkipEvent(ev) } catch {}
        if (shouldSkip) return

        eventLogs.unshift(msg.event)
        if (eventLogs.length > 500) eventLogs.pop()
        try { behavior.ingest(msg.event) } catch {}

        const isDev = !app.isPackaged
        const logToConsole = isDev && (etwCfg.logToConsole !== false)
        const logParsedToConsole = isDev && (etwCfg.logParsedToConsole === true)
        const resolveProcessName = isDev && (etwCfg.resolveProcessName === true)
        const maxPerSecond = Number.isFinite(etwCfg.consoleMaxPerSecond) ? Math.max(0, Math.floor(etwCfg.consoleMaxPerSecond)) : 200
        
        if (win && !win.isDestroyed()) {
          win.webContents.send('etw-log', msg.event)
        }
      } else if (msg.type === 'error') {
        const code = msg && msg.code ? msg.code : 'ETW_ERROR'
        etwLastError = { at: Date.now(), code, message: msg && msg.message ? msg.message : '', details: msg && msg.details ? msg.details : null }
        if (etwStartPending) {
          const p = etwStartPending
          etwStartPending = null
          try { if (p.timer) clearTimeout(p.timer) } catch {}
          try { p.resolve(false) } catch {}
        }
      } else if (msg.type === 'status') {
        etwLastStatus = { at: Date.now(), message: msg.message }
        if (etwStartPending) {
          const text = msg && msg.message ? String(msg.message) : ''
          const isStarted = text.includes('Monitoring started') || text.includes('ETW disabled by config')
          if (isStarted) {
            const p = etwStartPending
            etwStartPending = null
            try { if (p.timer) clearTimeout(p.timer) } catch {}
            try { p.resolve(true) } catch {}
            try { setImmediate(() => { takeEtwPidSnapshot(); startInterceptionSnapshotScan() }) } catch {}
          }
        }
        try {
          const text2 = msg && msg.message ? String(msg.message) : ''
          if (text2.includes('Monitoring started')) setImmediate(() => { takeEtwPidSnapshot(); startInterceptionSnapshotScan() })
        } catch {}
      }
    })
    
    etwWorker.on('error', (err) => {
      etwLastError = { at: Date.now(), code: 'ETW_WORKER_CRASH', message: err && err.message ? String(err.message) : String(err || ''), details: null }
      if (etwStartPending) {
        const p = etwStartPending
        etwStartPending = null
        try { if (p.timer) clearTimeout(p.timer) } catch {}
        try { p.resolve(false) } catch {}
      }
      etwWorker = null
    })
    
    etwWorker.on('exit', (code) => {
      etwLastStatus = { at: Date.now(), message: `worker exited (${code})` }
      if (etwStartPending) {
        const p = etwStartPending
        etwStartPending = null
        try { if (p.timer) clearTimeout(p.timer) } catch {}
        try { p.resolve(false) } catch {}
      }
      etwWorker = null
    })
    
    void requestEtwStart()
    
  } catch (e) {
    console.error('主进程: 启动 ETW Worker 失败:', e)
  }
}

function requestEtwStart(timeoutMs = 5000) {
  if (!etwWorker) return Promise.resolve(false)
  if (etwStartPending) return etwStartPending.promise
  const cfg = (config && config.etw) ? config.etw : null
  let resolveFn = null
  const promise = new Promise((resolve) => { resolveFn = resolve })
  const timer = setTimeout(() => {
    if (etwStartPending && etwStartPending.resolve === resolveFn) {
      etwStartPending = null
      resolveFn(false)
    }
  }, Math.max(250, timeoutMs || 0))
  try { if (timer.unref) timer.unref() } catch {}
  etwStartPending = { promise, resolve: resolveFn, timer }
  try {
    etwWorker.postMessage({ type: 'start', config: cfg })
  } catch {
    try { clearTimeout(timer) } catch {}
    etwStartPending = null
    resolveFn(false)
  }
  return promise
}

function controlEtwWorker(type) {
  if (!etwWorker) return Promise.resolve({ ok: true, skipped: true })
  const reqId = String(etwControlSeq++)
  return new Promise((resolve) => {
    const pending = { resolve, timer: null }
    etwControlPending.set(reqId, pending)
    const timer = setTimeout(() => {
      if (etwControlPending.has(reqId)) etwControlPending.delete(reqId)
      resolve({ ok: false, timeout: true })
    }, 5000)
    try { if (timer.unref) timer.unref() } catch {}
    pending.timer = timer
    try {
      etwWorker.postMessage({ type, requestId: reqId })
    } catch {
      clearTimeout(timer)
      if (etwControlPending.has(reqId)) etwControlPending.delete(reqId)
      resolve({ ok: false })
    }
  })
}

function createSplash() {
  const iconPath = resolveAppIconPath()
  const iconOpt = iconPath ? { icon: iconPath } : {}
  splash = new BrowserWindow({
    ...iconOpt,
    width: 400,
    height: 300,
    transparent: true,
    frame: false,
    alwaysOnTop: true,
    skipTaskbar: true,
    resizable: false,
    webPreferences: { nodeIntegration: false }
  })
  splash.loadFile(path.join(__dirname, '../renderer/splash.html'))
  console.log('主进程: 创建Splash窗口')
  splash.webContents.on('dom-ready', () => {
    try {
      const locale = (config && config.locale) ? config.locale : 'zh-CN'
      splash.webContents.executeJavaScript(`document.documentElement.lang=${JSON.stringify(locale)}`)
      splash.webContents.executeJavaScript(`(function(){var b=document.getElementById('splash-brand');if(b)b.textContent=${JSON.stringify(t('brand_name'))};var s=document.getElementById('splash-status');if(s)s.textContent=${JSON.stringify(t('splash_starting'))};})()`)
    } catch {}
  })
}

function createWindow() {
  const iconPath = resolveAppIconPath()
  const iconOpt = iconPath ? { icon: iconPath } : {}
  const bounds = resolveMainWindowOptions(config)
  win = new BrowserWindow({
    ...bounds,
    ...iconOpt,
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, './preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  })
  console.log('主进程: 创建主窗口')
  win.loadFile(path.join(__dirname, '../renderer/index.html'))
  try { win.setMenuBarVisibility(false) } catch {}
  try { win.removeMenu() } catch {}
  win.webContents.once('did-finish-load', () => {
    console.log('主进程: 窗口内容加载完成')
  })
  win.on('close', (e) => {
    if (config.minimizeToTray) {
      e.preventDefault()
      win.hide()
    }
  })
}

let trayExitInProgress = false

function quitAppOnlyFromTray() {
  try {
    scanCache.clearAll(config).catch(() => {})
    config.minimizeToTray = false
  } catch {}
  app.quit()
}

function quitAllFromTray() {
  try {
    scanCache.clearAll(config).catch(() => {})
    config.minimizeToTray = false
    const scannerCfg = (config && config.scanner) ? config.scanner : {}
    const ipc = (scannerCfg && scannerCfg.ipc) ? scannerCfg.ipc : {}
    const timeout = (config && config.engine && Number.isFinite(config.engine.exitTimeoutMs))
      ? config.engine.exitTimeoutMs
      : (Number.isFinite(ipc.timeoutMs) ? ipc.timeoutMs : ((scannerCfg && scannerCfg.timeoutMs) ? scannerCfg.timeoutMs : 1000))
    const engineCfg = (config && config.engine) ? config.engine : {}
    const processName = engineCfg.processName || 'Axon_ml.exe'
    const mod = require('./engine_autostart')
    mod.postExitCommand({ ipc }, timeout, null).then((res) => {
      const ok = res && res.ok && res.status === 'shutting_down'
      if (!ok && process.platform === 'win32') return mod.killProcessWin32(processName)
      return null
    }).finally(() => { app.quit() })
  } catch {
    app.quit()
  }
}

function showTrayExitPrompt(defaultKeep) {
  const requestId = `${Date.now()}_${Math.random().toString(16).slice(2)}`
  return new Promise((resolve) => {
    const p = path.join(__dirname, '../renderer/tray_exit_prompt.html')
    const iconPath = resolveAppIconPath()
    const iconOpt = iconPath ? { icon: iconPath } : {}
    const promptWin = new BrowserWindow({
      ...iconOpt,
      width: 420,
      height: 220,
      resizable: false,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      frame: false,
      show: false,
      alwaysOnTop: true,
      skipTaskbar: true,
      backgroundColor: '#0f1115',
      webPreferences: {
        preload: path.join(__dirname, './preload.js'),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: false
      }
    })

    trayExitPromptPending.set(requestId, { resolve, win: promptWin })
    promptWin.on('closed', () => {
      const pending = trayExitPromptPending.get(requestId)
      if (!pending) return
      trayExitPromptPending.delete(requestId)
      try { pending.resolve(null) } catch {}
    })

    promptWin.loadFile(p, { query: { requestId, defaultKeep: defaultKeep ? '1' : '0' } })
    promptWin.once('ready-to-show', () => {
      try { promptWin.show() } catch {}
      try { promptWin.focus() } catch {}
    })
  })
}

async function handleTrayExitClick() {
  if (trayExitInProgress) return
  trayExitInProgress = true

  const trayCfg = (config && config.tray) ? config.tray : {}
  try {
    if (trayCfg.exitKeepScannerServicePrompt === false) {
      try { await resumeAllInterceptedProcesses() } catch {}
      return quitAllFromTray()
    }

    const defaultKeep = trayCfg.exitKeepScannerServiceDefault !== false
    const keep = await showTrayExitPrompt(defaultKeep)
    const mode = resolveTrayExitMode({ keep, defaultKeep })
    try { await resumeAllInterceptedProcesses() } catch {}
    if (mode === 'keep_service') return quitAppOnlyFromTray()
    return quitAllFromTray()
  } finally {
    trayExitInProgress = false
  }
}

function createTray() {
  const iconPath = resolveAppIconPath()
  let image = null
  try {
    if (iconPath) image = nativeImage.createFromPath(iconPath)
  } catch {}
  if (!image || (typeof image.isEmpty === 'function' && image.isEmpty())) {
    const pngBase64 =
      'iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAGElEQVQYlWP8////fwYGBgYGJgYGBgYAAG1uCkqO3W1QAAAAAElFTkSuQmCC'
    image = nativeImage.createFromDataURL('data:image/png;base64,' + pngBase64)
  }
  tray = new Tray(image)
  console.log('主进程: 创建系统托盘')
  const menu = Menu.buildFromTemplate([
    { label: t('tray_show_main'), click: () => { win.show() } },
    { label: t('tray_exit'), click: () => { void handleTrayExitClick() } }
  ])
  tray.setToolTip(t('brand_name') || config.brand || 'AnXin Security')
  tray.setContextMenu(menu)
  tray.on('double-click', () => { win.show() })
}

function getEngineBaseDirs() {
  const out = []
  try { out.push(process.cwd()) } catch {}
  try { out.push(app.getAppPath()) } catch {}
  try { out.push(path.dirname(app.getPath('exe'))) } catch {}
  try { if (process.resourcesPath) out.push(process.resourcesPath) } catch {}
  return [...new Set(out.filter(Boolean))]
}

app.whenReady().then(() => {
  try { Menu.setApplicationMenu(null) } catch {}
  i18nDict = loadI18n()
  createSplash()
  createWindow()
  createTray()
  try { behavior.start() } catch {}
  startEtwWorker()
  try {
    const engineCfg = (config && config.engine) ? config.engine : {}
    const scannerCfg = (config && config.scanner) ? config.scanner : {}
    const ipc = (scannerCfg && scannerCfg.ipc) ? scannerCfg.ipc : {}
    const pollIntervalMs = Number.isFinite(scannerCfg.healthPollIntervalMs) ? scannerCfg.healthPollIntervalMs : 300

    const bootstrap = async () => {
      if (engineCfg.autoStart !== false) {
        const engineArgs = (engineCfg && Array.isArray(engineCfg.args)) ? engineCfg.args : []
        const res = await startIfNeeded({ engine: { ...engineCfg, args: engineArgs }, ipc, baseDirs: getEngineBaseDirs() })
        if (res) {
          if (res.started) console.log('主进程: 已后台启动 Axon_ml.exe', res.path)
          else if (res.reason === 'already_running') console.log('主进程: Axon_ml.exe 已在运行')
          else if (res.reason === 'exe_not_found') console.log('主进程: 未找到 Axon_ml.exe，跳过自动启动')
          else if (res.reason === 'spawn_failed') console.log('主进程: 启动 Axon_ml.exe 失败', res.path)
        }
      }

      let retries = 0
      const check = async () => {
        const ok = await checkEngineHealth({ ipc })
        if (ok || retries > 100) {
          const timeoutPromise = new Promise(resolve => setTimeout(resolve, 5000))
          await Promise.race([scanPromise, timeoutPromise])

          if (splash && !splash.isDestroyed()) splash.destroy()
          if (win && !win.isDestroyed()) {
            win.show()
            win.focus()
            try { setImmediate(() => interceptionQueue.tryShowNext()) } catch {}
          }
        } else {
          retries++
          setTimeout(check, pollIntervalMs)
        }
      }
      check()
    }
    bootstrap()
  } catch {}
  ipcMain.on('config-updated', (_event, nextCfg) => {
    if (!nextCfg || typeof nextCfg !== 'object') return
    config = nextCfg
    try { i18nDict = loadI18n() } catch {}
    etwConsoleLimiter = null
    etwConsoleLimiterMax = null
    try {
      const etwCfg = (config && config.etw) ? config.etw : {}
      const icfg = (etwCfg && etwCfg.interception && typeof etwCfg.interception === 'object') ? etwCfg.interception : null
      interceptionQueue.configure(icfg)
    } catch {}
    try { if (etwWorker) etwWorker.postMessage({ type: 'config', config: (config && config.etw) ? config.etw : null }) } catch {}
  })
  ipcMain.handle('open-file-dialog', async () => {
    const browser = BrowserWindow.getFocusedWindow() || win
    console.log('主进程: 打开文件选择对话框')
    const res = await dialog.showOpenDialog(browser, {
      title: t('dialog_choose_file_title'),
      properties: ['openFile', 'dontAddToRecent']
    })
    if (res.canceled || !res.filePaths || !res.filePaths.length) return null
    console.log('主进程: 选择文件', res.filePaths[0])
    return res.filePaths[0]
  })
  ipcMain.handle('open-directory-dialog', async () => {
    const browser = BrowserWindow.getFocusedWindow() || win
    console.log('主进程: 打开目录选择对话框')
    const res = await dialog.showOpenDialog(browser, {
      title: t('dialog_choose_directory_title'),
      properties: ['openDirectory', 'dontAddToRecent']
    })
    if (res.canceled || !res.filePaths || !res.filePaths.length) return null
    console.log('主进程: 选择目录', res.filePaths[0])
    return res.filePaths[0]
  })

  ipcMain.handle('quarantine-list', () => quarantineManager.getList())
  ipcMain.handle('quarantine-isolate', (event, filePath) => quarantineManager.quarantine(filePath))
  ipcMain.handle('quarantine-restore', (event, id) => quarantineManager.restore(id))
  ipcMain.handle('quarantine-delete', (event, id) => quarantineManager.delete(id))
  ipcMain.handle('process-suspend', async (_event, pid) => {
    const p = Number.isFinite(pid) ? pid : parseInt(String(pid), 10)
    if (!Number.isFinite(p) || p <= 0) return false
    if (!winapi || typeof winapi.suspendProcessByPid !== 'function') return false
    try { return winapi.suspendProcessByPid(p) === true } catch { return false }
  })
  ipcMain.handle('process-resume', async (_event, pid) => {
    const p = Number.isFinite(pid) ? pid : parseInt(String(pid), 10)
    if (!Number.isFinite(p) || p <= 0) return false
    
    let wasPaused = false
    try {
      const pausedPids = interceptionQueue.getPausedPids()
      wasPaused = pausedPids.includes(p)
    } catch {}

    const payload = interceptionQueue.markActionResult(p, true)

    if (wasPaused) {
      try {
        if (payload && payload.pid === p) {
          const evt = payload.event
          if (evt && evt.data && evt.data.type === 'UnsignedDll' && Array.isArray(evt.data.unsignedDlls)) {
            const w = ensureInterceptionSnapshotWorker()
            if (w) w.postMessage({ type: 'allow_dlls', paths: evt.data.unsignedDlls })
          }
        }
      } catch {}

      if (winapi && typeof winapi.resumeProcessByPid === 'function') {
        try { winapi.resumeProcessByPid(p) } catch {}
      }
    }
    
    return true
  })
  ipcMain.handle('process-terminate', async (_event, pid) => {
    const p = Number.isFinite(pid) ? pid : parseInt(String(pid), 10)
    if (!Number.isFinite(p) || p <= 0) return false
    
    try { interceptionQueue.markActionResult(p, true) } catch {}

    if (!winapi || typeof winapi.terminateProcessByPid !== 'function') return false
    try {
      return winapi.terminateProcessByPid(p) === true
    } catch {
      return false
    }
  })
  ipcMain.handle('logs:list', () => eventLogs)
  ipcMain.handle('system-get-running-processes', () => processes.getRunningProcesses())
  ipcMain.handle('behavior-get-db-path', () => behavior.getDbPath())
  ipcMain.handle('behavior-pause-etw', async () => {
    try {
      const res = await controlEtwWorker('pause')
      return !!(res && res.ok)
    } catch {
      return false
    }
  })
  ipcMain.handle('behavior-clear-db', async () => {
    try {
      const ok = await behavior.clearAll()
      return ok === true
    } catch {
      return false
    }
  })
  ipcMain.handle('behavior-clear-all', async () => {
    try {
      const paused = await controlEtwWorker('pause')
      if (!(paused && paused.ok)) return false
      const ok = await behavior.clearAll()
      return ok === true
    } catch {
      return false
    } finally {
      try { await controlEtwWorker('resume') } catch {}
    }
  })
  ipcMain.handle('behavior-resume-etw', async () => {
    try {
      if (!etwWorker) {
        startEtwWorker()
        return await requestEtwStart(6000)
      }
      const res = await controlEtwWorker('resume')
      if (res && res.ok) return true
      try { if (etwWorker) await etwWorker.terminate() } catch {}
      etwWorker = null
      startEtwWorker()
      return await requestEtwStart(6000)
    } catch {
      return false
    }
  })
  ipcMain.handle('behavior-list-processes', async (_event, query) => {
    const list = await behavior.listProcesses(query || {})
    const arr = Array.isArray(list) ? list : []
    const now = Date.now()
    const etwCfg = (config && config.etw) ? config.etw : {}
    const uiCfg = (config && config.behaviorUi) ? config.behaviorUi : {}
    const resolveProcessName = uiCfg.resolveProcessName !== false
    if (!resolveProcessName) return arr
    refreshEtwPidCacheConfig(etwCfg)
    pruneEtwPidCache(now)
    return arr.map((p) => {
      const pid = Number.isFinite(p && p.pid) ? p.pid : null
      const out = Object.assign({}, p)
      if (typeof out.image === 'string' && out.image) out.image = sanitizeText(out.image)
      if (typeof out.name === 'string' && out.name) out.name = sanitizeText(out.name)
      if (pid != null) {
        const info = resolveEtwProcessInfo(pid, now, etwCfg)
        if (info && info.imagePath && !out.image) out.image = info.imagePath
        if (info && info.name) out.name = sanitizeText(info.name)
      }
      if (out.name && !isCleanText(out.name)) out.name = ''
      if (!out.name && out.image) out.name = getProcessNameFromPath(out.image)
      if (out.name && !isCleanText(out.name)) out.name = ''
      return out
    })
  })
  ipcMain.handle('behavior-list-events', async (_event, query) => {
    const list = await behavior.listEvents(query || {})
    const arr = Array.isArray(list) ? list : []
    const now = Date.now()
    const etwCfg = (config && config.etw) ? config.etw : {}
    const uiCfg = (config && config.behaviorUi) ? config.behaviorUi : {}
    const resolveProcessName = uiCfg.resolveProcessName !== false
    if (!resolveProcessName) return arr
    refreshEtwPidCacheConfig(etwCfg)
    pruneEtwPidCache(now)
    const hasDeviceResolver = !!(winapi && typeof winapi.devicePathToDosPath === 'function')
    const normalizePath = (v) => {
      if (typeof v !== 'string' || !v) return v
      let s = sanitizeText(v)
      if (hasDeviceResolver) {
        try { s = winapi.devicePathToDosPath(s) || s } catch {}
      }
      return s
    }
    return arr.map((ev) => {
      const out = Object.assign({}, ev)
      const actorPid = Number.isFinite(out.actor_pid) ? out.actor_pid : null
      const subjectPid = Number.isFinite(out.subject_pid) ? out.subject_pid : null
      const actorImage = (typeof out.actor_image === 'string' && out.actor_image) ? out.actor_image : null
      const subjectImage = (typeof out.subject_image === 'string' && out.subject_image) ? out.subject_image : null
      if (typeof out.actor_processImage === 'string' && out.actor_processImage) out.actor_processImage = sanitizeText(out.actor_processImage)
      if (typeof out.subject_processImage === 'string' && out.subject_processImage) out.subject_processImage = sanitizeText(out.subject_processImage)
      if (typeof out.actor_processName === 'string' && out.actor_processName) out.actor_processName = sanitizeText(out.actor_processName)
      if (typeof out.subject_processName === 'string' && out.subject_processName) out.subject_processName = sanitizeText(out.subject_processName)
      if (!out.actor_processImage && actorImage) out.actor_processImage = actorImage
      if (!out.subject_processImage && subjectImage) out.subject_processImage = subjectImage
      if (typeof out.file_path === 'string' && out.file_path) out.file_path = normalizePath(out.file_path)
      if (typeof out.reg_key === 'string' && out.reg_key) out.reg_key = normalizePath(out.reg_key)
      if (!out.actor_processName && out.actor_processImage) out.actor_processName = getProcessNameFromPath(out.actor_processImage)
      if (!out.subject_processName && out.subject_processImage) out.subject_processName = getProcessNameFromPath(out.subject_processImage)
      if (actorPid != null) {
        const info = resolveEtwProcessInfo(actorPid, now, etwCfg)
        if (info && info.name) out.actor_processName = sanitizeText(info.name)
        if (info && info.imagePath) out.actor_processImage = info.imagePath
      }
      if (subjectPid != null) {
        const info = resolveEtwProcessInfo(subjectPid, now, etwCfg)
        if (info && info.name) out.subject_processName = sanitizeText(info.name)
        if (info && info.imagePath) out.subject_processImage = info.imagePath
      }
      if (typeof out.actor_processImage === 'string' && out.actor_processImage) out.actor_processImage = normalizePath(out.actor_processImage)
      if (typeof out.subject_processImage === 'string' && out.subject_processImage) out.subject_processImage = normalizePath(out.subject_processImage)
      if (typeof out.raw_json === 'string' && out.raw_json) {
        try {
          const obj = JSON.parse(out.raw_json)
          if (obj && typeof obj === 'object') {
            const d = obj.data && typeof obj.data === 'object' ? obj.data : null
            if (d) {
              if (typeof d.keyPath === 'string' && d.keyPath) d.keyPath = normalizePath(d.keyPath)
              if (typeof d.fileName === 'string' && d.fileName) d.fileName = normalizePath(d.fileName)
              if (typeof d.imageName === 'string' && d.imageName) d.imageName = normalizePath(d.imageName)
              out.raw_json = JSON.stringify(obj)
            }
          }
        } catch {}
      }
      if (out.actor_processName && !isCleanText(out.actor_processName)) out.actor_processName = ''
      if (out.subject_processName && !isCleanText(out.subject_processName)) out.subject_processName = ''
      if (!out.actor_processName && out.actor_processImage) out.actor_processName = getProcessNameFromPath(out.actor_processImage)
      if (!out.subject_processName && out.subject_processImage) out.subject_processName = getProcessNameFromPath(out.subject_processImage)
      return out
    })
  })
  ipcMain.handle('scanner:health', async () => scannerClient.health())
  ipcMain.handle('scanner:scanFile', async (_event, payload) => {
    const p = payload && typeof payload === 'object' ? payload : {}
    return scannerClient.scanFile(p.filePath, p.requestId)
  })
  ipcMain.handle('scanner:abort', async (_event, requestId) => scannerClient.abort(requestId))

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
    else win.show()
  })
  ipcMain.on('ui-debug', (_evt, data) => {
    try {
      const tag = data && data.tag
      const payload = data && data.payload
      console.log('渲染进程调试:', tag, payload)
    } catch (e) {
      console.log('渲染进程调试: 解析失败', e && e.message)
    }
  })
})

let isQuitting = false
app.on('before-quit', (e) => {
  if (isQuitting) return
  
  if (etwWorker) {
    e.preventDefault()
    isQuitting = true
    
    const forceQuit = setTimeout(() => {
      console.warn('主进程: ETW Worker 停止超时，将断开连接并退出')
      if (etwWorker) etwWorker.unref()
      Promise.resolve().then(() => behavior.stop()).catch(() => {}).finally(() => app.quit())
    }, 5000)
    
    etwWorker.once('exit', () => {
      clearTimeout(forceQuit)
      Promise.resolve().then(() => behavior.stop()).catch(() => {}).finally(() => app.quit())
    })
    
    etwWorker.postMessage({ type: 'stop' })
  } else {
    e.preventDefault()
    isQuitting = true
    Promise.resolve().then(() => behavior.stop()).catch(() => {}).finally(() => app.quit())
  }
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
