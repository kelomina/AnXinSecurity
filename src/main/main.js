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
      ui: { animations: true, window: { minWidth: 600, minHeight: 800 } },
      engine: { autoStart: true, exeRelativePath: 'Engine\\Axon_v2\\Axon_ml.exe', processName: 'Axon_ml.exe', args: [] },
      scanner: {
        baseUrl: 'http://127.0.0.1:8000',
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
        
        if (win && !win.isDestroyed()) {
          win.webContents.send('etw-log', msg.event)
        }
      } else if (msg.type === 'error') {
        console.error('主进程: ETW Worker 错误:', msg.message)
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
    
    etwWorker.postMessage('start')
    
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

function createTray() {
  const pngBase64 =
    'iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAGElEQVQYlWP8////fwYGBgYGJgYGBgYAAG1uCkqO3W1QAAAAAElFTkSuQmCC'
  const image = nativeImage.createFromDataURL('data:image/png;base64,' + pngBase64)
  tray = new Tray(image)
  console.log('主进程: 创建系统托盘')
  const menu = Menu.buildFromTemplate([
    { label: t('tray_show_main'), click: () => { win.show() } },
    { label: t('tray_exit'), click: () => {
      try {
        scanCache.clearAll(config).catch(() => {})
        config.minimizeToTray = false
        const base = (config && config.scanner && config.scanner.baseUrl) ? config.scanner.baseUrl : 'http://127.0.0.1:8000'
        const url = base.replace(/\/$/, '') + '/control/command'
        const timeout = (config && config.engine && Number.isFinite(config.engine.exitTimeoutMs)) ? config.engine.exitTimeoutMs : ((config && config.scanner && config.scanner.timeoutMs) ? config.scanner.timeoutMs : 1000)
        const engineCfg = (config && config.engine) ? config.engine : {}
        const processName = engineCfg.processName || 'Axon_ml.exe'
        const mod = require('./engine_autostart')
        mod.postExitCommand(url, timeout, null).then((res) => {
          const ok = res && res.ok && res.status === 'shutting_down'
          if (!ok && process.platform === 'win32') return mod.killProcessWin32(processName)
          return null
        }).finally(() => { app.quit() })
      } catch {
        app.quit()
      }
    } }
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
    const baseUrl = scannerCfg.baseUrl || 'http://127.0.0.1:8000'
    const pollIntervalMs = Number.isFinite(scannerCfg.healthPollIntervalMs) ? scannerCfg.healthPollIntervalMs : 300

    const bootstrap = async () => {
      if (engineCfg.autoStart !== false) {
        const engineArgs = (engineCfg && Array.isArray(engineCfg.args)) ? engineCfg.args : []
        const res = await startIfNeeded({ engine: { ...engineCfg, args: engineArgs }, baseUrl, baseDirs: getEngineBaseDirs() })
        if (res) {
          if (res.started) console.log('主进程: 已后台启动 Axon_ml.exe', res.path)
          else if (res.reason === 'already_running') console.log('主进程: Axon_ml.exe (HTTP) 已在运行')
          else if (res.reason === 'exe_not_found') console.log('主进程: 未找到 Axon_ml.exe，跳过自动启动')
          else if (res.reason === 'spawn_failed') console.log('主进程: 启动 Axon_ml.exe 失败', res.path)
        }
      }

      let retries = 0
      const check = async () => {
        const ok = await checkEngineHealth(baseUrl)
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
  ipcMain.handle('behavior-list-processes', async (_event, query) => behavior.listProcesses(query || {}))
  ipcMain.handle('behavior-list-events', async (_event, query) => behavior.listEvents(query || {}))
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
    
    etwWorker.postMessage('stop')
  } else {
    e.preventDefault()
    isQuitting = true
    Promise.resolve().then(() => behavior.stop()).catch(() => {}).finally(() => app.quit())
  }
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
