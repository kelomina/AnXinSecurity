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
const { formatEtwEventForConsole, formatEtwEventForParsedConsole, resolveEtwOpMeaning, createRateLimiter, sanitizeText, isCleanText, isLikelyProcessImageText } = require('./utils')
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
const etwPidCache = new Map()
let etwPidCacheMax = null
let etwPidCacheTtlMs = null
let etwPidResolveLimiter = null
let etwPidResolveLimiterMax = null

function getProcessNameFromPath(p) {
  if (typeof p !== 'string' || !p) return ''
  try {
    const n = path.basename(p)
    return sanitizeText(typeof n === 'string' ? n : '')
  } catch { return '' }
}

function refreshEtwPidCacheConfig(etwCfg) {
  const max = Number.isFinite(etwCfg.processNameCacheMax) ? Math.max(64, Math.floor(etwCfg.processNameCacheMax)) : 2048
  const ttlMs = Number.isFinite(etwCfg.processNameCacheTtlMs) ? Math.max(0, Math.floor(etwCfg.processNameCacheTtlMs)) : 300000
  const perSec = Number.isFinite(etwCfg.processNameResolveMaxPerSecond) ? Math.max(0, Math.floor(etwCfg.processNameResolveMaxPerSecond)) : 20
  if (etwPidCacheMax !== max) etwPidCacheMax = max
  if (etwPidCacheTtlMs !== ttlMs) etwPidCacheTtlMs = ttlMs
  if (etwPidResolveLimiterMax !== perSec || !etwPidResolveLimiter) {
    etwPidResolveLimiterMax = perSec
    etwPidResolveLimiter = createRateLimiter(perSec)
  }
}

function pruneEtwPidCache(now) {
  const ttl = Number.isFinite(etwPidCacheTtlMs) ? etwPidCacheTtlMs : 300000
  const max = Number.isFinite(etwPidCacheMax) ? etwPidCacheMax : 2048
  if (ttl > 0) {
    for (const [pid, v] of etwPidCache) {
      if (!v || !Number.isFinite(v.at) || now - v.at > ttl) etwPidCache.delete(pid)
    }
  }
  while (etwPidCache.size > max) {
    const firstKey = etwPidCache.keys().next().value
    if (firstKey == null) break
    etwPidCache.delete(firstKey)
  }
}

function upsertEtwPid(pid, imagePath, now) {
  if (!Number.isFinite(pid) || pid <= 0) return
  const rawImg = (typeof imagePath === 'string' && imagePath) ? imagePath : null
  const img = rawImg ? sanitizeText(rawImg) : null
  if (img && !isLikelyProcessImageText(img)) return
  const name = img ? getProcessNameFromPath(img) : ''
  etwPidCache.delete(pid)
  etwPidCache.set(pid, { imagePath: img, name, at: now })
}

function resolveEtwProcessInfo(pid, now, etwCfg) {
  if (!Number.isFinite(pid) || pid <= 0) return null
  const existed = etwPidCache.get(pid)
  if (existed && (!etwPidCacheTtlMs || (now - existed.at <= etwPidCacheTtlMs))) {
    const cachedImage = (typeof existed.imagePath === 'string' && existed.imagePath) ? existed.imagePath : ''
    const cachedName = (typeof existed.name === 'string' && existed.name) ? existed.name : ''
    const ok = (cachedImage && isLikelyProcessImageText(cachedImage)) || (cachedName && isLikelyProcessImageText(cachedName))
    if (ok) {
      etwPidCache.delete(pid)
      etwPidCache.set(pid, { imagePath: existed.imagePath, name: existed.name, at: now })
      return existed
    }
    etwPidCache.delete(pid)
  }

  if (!winapi || typeof winapi.getProcessImagePathByPid !== 'function') return null
  if (!etwPidResolveLimiter || !etwPidResolveLimiter()) return null
  const img = winapi.getProcessImagePathByPid(pid)
  if (!img || !isCleanText(img)) return null
  upsertEtwPid(pid, img, now)
  return etwPidCache.get(pid) || null
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
      if (msg.type === 'log') {
        eventLogs.unshift(msg.event)
        if (eventLogs.length > 500) eventLogs.pop()
        try { behavior.ingest(msg.event) } catch {}

        const isDev = !app.isPackaged
        const etwCfg = (config && config.etw) ? config.etw : {}
        const logToConsole = isDev && (etwCfg.logToConsole !== false)
        const logParsedToConsole = isDev && (etwCfg.logParsedToConsole === true)
        const resolveProcessName = isDev && (etwCfg.resolveProcessName === true)
        const maxPerSecond = Number.isFinite(etwCfg.consoleMaxPerSecond) ? Math.max(0, Math.floor(etwCfg.consoleMaxPerSecond)) : 200
        if (logToConsole) {
          if (etwConsoleLimiterMax !== maxPerSecond || !etwConsoleLimiter) {
            etwConsoleLimiterMax = maxPerSecond
            etwConsoleLimiter = createRateLimiter(maxPerSecond)
          }
          if (etwConsoleLimiter && etwConsoleLimiter()) {
            const now = Date.now()
            if (resolveProcessName || logParsedToConsole) {
              refreshEtwPidCacheConfig(etwCfg)
              pruneEtwPidCache(now)
              const p = msg.event && msg.event.provider
              const d = msg.event && msg.event.data
              if (p === 'Process' && d && typeof d === 'object') {
                const subjectPid = Number.isFinite(d.processId) ? d.processId : null
                const imageName = typeof d.imageName === 'string' ? d.imageName : null
                if (subjectPid != null && imageName) upsertEtwPid(subjectPid, imageName, now)
              }
            }
            const line = formatEtwEventForConsole(msg.event)
            if (line) process.stdout.write(Buffer.from('ETW: ' + line + '\n', 'utf8'))
            else process.stdout.write(Buffer.from('ETW: ' + JSON.stringify(msg.event) + '\n', 'utf8'))
            if (logParsedToConsole) {
              const parsedEvent = Object.assign({}, msg.event)
              parsedEvent.opMeaning = resolveEtwOpMeaning(msg.event)
              if (resolveProcessName && parsedEvent && Number.isFinite(parsedEvent.pid)) {
                const info = resolveEtwProcessInfo(parsedEvent.pid, now, etwCfg)
                if (info && info.name) parsedEvent.processName = info.name
                if (info && info.imagePath) parsedEvent.processImage = info.imagePath
              }
              const parsedLine = formatEtwEventForParsedConsole(parsedEvent)
              if (parsedLine) process.stdout.write(Buffer.from('ETW_PARSED: ' + parsedLine + '\n', 'utf8'))
            }
          }
        }
        
        if (win && !win.isDestroyed()) {
          win.webContents.send('etw-log', msg.event)
        }
      } else if (msg.type === 'error') {
        const code = msg && msg.code ? msg.code : 'ETW_ERROR'
        console.error('主进程: ETW Worker 错误:', code, msg && msg.message ? msg.message : msg)
        if (msg && msg.details) console.error('主进程: ETW Worker 详情:', msg.details)
      } else if (msg.type === 'status') {
        console.log('主进程: ETW Worker 状态:', msg.message)
      }
    })
    
    etwWorker.on('error', (err) => {
      console.error('主进程: ETW Worker 崩溃:', err)
      etwWorker = null
    })
    
    etwWorker.on('exit', (code) => {
      console.log('主进程: ETW Worker 退出，代码', code)
      etwWorker = null
    })
    
    etwWorker.postMessage({ type: 'start', config: (config && config.etw) ? config.etw : null })
    
  } catch (e) {
    console.error('主进程: 启动 ETW Worker 失败:', e)
  }
}

function createSplash() {
  splash = new BrowserWindow({
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
  const bounds = resolveMainWindowOptions(config)
  win = new BrowserWindow({
    ...bounds,
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

async function handleTrayExitClick() {
  if (trayExitInProgress) return
  trayExitInProgress = true

  const trayCfg = (config && config.tray) ? config.tray : {}
  if (trayCfg.exitKeepScannerServicePrompt === false) return quitAllFromTray()

  const defaultKeep = trayCfg.exitKeepScannerServiceDefault !== false
  const defaultId = defaultKeep ? 0 : 1

  let response = null
  try {
    const browser = BrowserWindow.getFocusedWindow() || win
    const res = await dialog.showMessageBox(browser, {
      type: 'question',
      buttons: [t('tray_exit_keep_service_yes'), t('tray_exit_keep_service_no')],
      defaultId,
      cancelId: defaultId,
      noLink: true,
      title: t('tray_exit_keep_service_title'),
      message: t('tray_exit_keep_service_message')
    })
    response = res && Number.isFinite(res.response) ? res.response : null
  } catch {}

  const mode = resolveTrayExitMode({ response, defaultKeep })
  if (mode === 'keep_service') return quitAppOnlyFromTray()
  return quitAllFromTray()
}

function createTray() {
  const pngBase64 =
    'iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAGElEQVQYlWP8////fwYGBgYGJgYGBgYAAG1uCkqO3W1QAAAAAElFTkSuQmCC'
  const image = nativeImage.createFromDataURL('data:image/png;base64,' + pngBase64)
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
          if (splash && !splash.isDestroyed()) splash.destroy()
          if (win && !win.isDestroyed()) {
            win.show()
            win.focus()
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
  ipcMain.handle('logs:list', () => eventLogs)
  ipcMain.handle('system-get-running-processes', () => processes.getRunningProcesses())
  ipcMain.handle('behavior-get-db-path', () => behavior.getDbPath())
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
    console.log('主进程: 正在停止 ETW Worker...')
    
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
