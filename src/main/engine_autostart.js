const fs = require('fs')
const path = require('path')
const childProcess = require('child_process')
const net = require('net')

function normalizeProcessName(name) {
  if (typeof name !== 'string') return ''
  const trimmed = name.trim()
  return trimmed.toLowerCase().endsWith('.exe') ? trimmed : (trimmed ? (trimmed + '.exe') : '')
}

function isAbsolutePath(p) {
  return typeof p === 'string' && p.length > 0 && path.isAbsolute(p)
}

function resolveExePath(exePathOrRelative, baseDirs, deps = {}) {
  const fsMod = deps.fs || fs
  const pathMod = deps.path || path
  const raw = typeof exePathOrRelative === 'string' ? exePathOrRelative.trim() : ''
  if (!raw) return null

  if (isAbsolutePath(raw)) {
    return fsMod.existsSync(raw) ? raw : null
  }

  const bases = Array.isArray(baseDirs) ? baseDirs.filter(Boolean) : []
  for (const base of bases) {
    const full = pathMod.resolve(base, raw)
    if (fsMod.existsSync(full)) return full
  }
  return null
}

function spawnDetachedHidden(exePath, args, spawnOptions = {}, deps = {}) {
  const cp = deps.childProcess || childProcess
  const opts = spawnOptions && typeof spawnOptions === 'object' ? spawnOptions : {}
  const child = cp.spawn(exePath, Array.isArray(args) ? args : [], {
    detached: true,
    windowsHide: true,
    stdio: 'ignore',
    env: opts.env || process.env
  })
  child.unref()
  return child
}

function resolveIpcOptions(options) {
  const ipc = options && options.ipc ? options.ipc : {}
  const envHost = process.env.SCANNER_SERVICE_IPC_HOST
  const envPort = process.env.SCANNER_SERVICE_IPC_PORT
  const host = (typeof (envHost || ipc.host) === 'string' && (envHost || ipc.host).trim()) ? (envHost || ipc.host).trim() : '127.0.0.1'
  const parsedPort = parseInt(envPort || ipc.port, 10)
  const port = Number.isFinite(parsedPort) && parsedPort > 0 && parsedPort < 65536 ? parsedPort : 8765
  const connectTimeoutMs = Number.isFinite(ipc.connectTimeoutMs) ? ipc.connectTimeoutMs : 300
  const timeoutMs = Number.isFinite(ipc.timeoutMs) ? ipc.timeoutMs : 800
  return { host, port, connectTimeoutMs, timeoutMs }
}

function ipcRoundTrip(host, port, msg, connectTimeoutMs, timeoutMs, deps = {}) {
  const netMod = deps.net || net
  const json = Buffer.from(JSON.stringify(msg), 'utf-8')
  const frame = Buffer.allocUnsafe(4)
  frame.writeUInt32BE(json.length, 0)
  const out = Buffer.concat([frame, json])

  return new Promise((resolve, reject) => {
    let done = false
    let buf = Buffer.alloc(0)
    let expectedLen = null

    const socket = netMod.createConnection({ host, port })
    socket.setNoDelay(true)

    const connectTimer = setTimeout(() => {
      try { socket.destroy(new Error('CONNECT_TIMEOUT')) } catch {}
    }, Math.max(1, connectTimeoutMs))

    const timer = setTimeout(() => {
      try { socket.destroy(new Error('TIMEOUT')) } catch {}
    }, Math.max(1, timeoutMs + connectTimeoutMs))

    function cleanup() {
      clearTimeout(connectTimer)
      clearTimeout(timer)
      try { socket.removeAllListeners() } catch {}
      try { socket.on('error', () => {}) } catch {}
    }

    function finish(err, res) {
      if (done) return
      done = true
      cleanup()
      if (err) return reject(err)
      resolve(res)
    }

    socket.once('connect', () => {
      clearTimeout(connectTimer)
      try {
        socket.write(out)
      } catch (e) {
        finish(e)
      }
    })

    socket.on('data', (chunk) => {
      try {
        const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
        buf = buf.length ? Buffer.concat([buf, b]) : b
        if (expectedLen == null) {
          if (buf.length < 4) return
          expectedLen = buf.readUInt32BE(0)
          if (!Number.isFinite(expectedLen) || expectedLen < 0 || expectedLen > 64 * 1024 * 1024) return finish(new Error('IPC_PROTOCOL'))
        }
        if (buf.length < 4 + expectedLen) return
        const body = buf.subarray(4, 4 + expectedLen)
        const parsed = JSON.parse(body.toString('utf-8'))
        try { socket.end() } catch {}
        finish(null, parsed)
      } catch (e) {
        finish(e)
      }
    })

    socket.once('error', (err) => finish(err))
    socket.once('close', () => {
      if (done) return
      finish(new Error('IPC_CLOSED'))
    })
  })
}

function checkEngineHealth(hostOrOptions, portOrDeps, maybeDeps) {
  let host = '127.0.0.1'
  let port = 8765
  let deps = {}

  if (hostOrOptions && typeof hostOrOptions === 'object') {
    const opt = resolveIpcOptions(hostOrOptions)
    host = opt.host
    port = opt.port
    deps = portOrDeps || {}
    const msg = { version: 1, type: 'health', payload: {}, timeout_ms: opt.timeoutMs }
    return ipcRoundTrip(host, port, msg, opt.connectTimeoutMs, opt.timeoutMs, deps)
      .then((res) => !!(res && res.ok))
      .catch(() => false)
  }

  host = typeof hostOrOptions === 'string' && hostOrOptions.trim() ? hostOrOptions.trim() : '127.0.0.1'
  const p = parseInt(portOrDeps, 10)
  port = Number.isFinite(p) && p > 0 && p < 65536 ? p : 8765
  deps = maybeDeps || {}
  const msg = { version: 1, type: 'health', payload: {}, timeout_ms: 800 }
  return ipcRoundTrip(host, port, msg, 300, 800, deps)
    .then((res) => !!(res && res.ok))
    .catch(() => false)
}

async function startIfNeeded(options, deps = {}) {
  const platform = (options && options.platform) || process.platform
  if (platform !== 'win32') return { started: false, reason: 'unsupported_platform' }

  const engine = options && options.engine ? options.engine : {}
  const baseDirs = options && options.baseDirs ? options.baseDirs : []
  const exeCandidate = engine.exePath || engine.exeRelativePath || ''
  const ipcOpt = resolveIpcOptions(options || {})

  const exePath = resolveExePath(exeCandidate, baseDirs, deps)
  if (!exePath) return { started: false, reason: 'exe_not_found' }

  const running = await checkEngineHealth({ ipc: { host: ipcOpt.host, port: ipcOpt.port, connectTimeoutMs: ipcOpt.connectTimeoutMs, timeoutMs: ipcOpt.timeoutMs } }, deps)
  if (running) return { started: false, reason: 'already_running', path: exePath }

  try {
    const mergedEnv = { ...process.env, SCANNER_SERVICE_IPC_HOST: ipcOpt.host, SCANNER_SERVICE_IPC_PORT: String(ipcOpt.port) }
    spawnDetachedHidden(exePath, engine.args || [], { env: mergedEnv }, deps)
    return { started: true, reason: 'started', path: exePath }
  } catch {
    return { started: false, reason: 'spawn_failed', path: exePath }
  }
}

function postExitCommand(options, timeoutMs, token, deps = {}) {
  const opt = resolveIpcOptions(options || {})
  const to = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : opt.timeoutMs
  const msg = { version: 1, type: 'control', payload: token ? { command: 'exit', token } : { command: 'exit' }, timeout_ms: to }

  return ipcRoundTrip(opt.host, opt.port, msg, opt.connectTimeoutMs, to, deps)
    .then((res) => {
      if (!res || res.ok !== true) return { ok: false, status: null }
      const status = res && res.payload && res.payload.status ? res.payload.status : null
      return { ok: true, status }
    })
    .catch(() => ({ ok: false, status: null }))
}

function killProcessWin32(processName, deps = {}) {
  const cp = deps.childProcess || childProcess
  const pn = normalizeProcessName(processName)
  if (!pn) return Promise.resolve(false)
  return new Promise((resolve) => {
    const cmd = `taskkill /F /IM ${pn} /T`
    cp.exec(cmd, { windowsHide: true }, (err) => {
      if (err) return resolve(false)
      resolve(true)
    })
  })
}

module.exports = {
  normalizeProcessName,
  resolveExePath,
  spawnDetachedHidden,
  startIfNeeded,
  postExitCommand,
  killProcessWin32,
  checkEngineHealth
}
