const net = require('net')

function createScannerClient(getConfig, deps = {}) {
  const active = new Map()

  function getScannerCfg() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const ipc = scanner && scanner.ipc ? scanner.ipc : {}
    const timeoutMs = Number.isFinite(scanner.timeoutMs) ? scanner.timeoutMs : 5000
    const envHost = process.env.SCANNER_SERVICE_IPC_HOST
    const envPort = process.env.SCANNER_SERVICE_IPC_PORT
    const ipcEnabled = ipc && ipc.enabled === false ? false : true
    const ipcPrefer = ipc && ipc.prefer === false ? false : true
    const ipcHost = (typeof (envHost || ipc.host) === 'string' && (envHost || ipc.host).trim()) ? (envHost || ipc.host).trim() : '127.0.0.1'
    const parsedPort = parseInt(envPort || ipc.port, 10)
    const ipcPort = Number.isFinite(parsedPort) && parsedPort > 0 && parsedPort < 65536 ? parsedPort : 8765
    const ipcConnectTimeoutMs = Number.isFinite(ipc.connectTimeoutMs) ? ipc.connectTimeoutMs : 500
    const ipcTimeoutMs = Number.isFinite(ipc.timeoutMs) ? ipc.timeoutMs : timeoutMs
    return { timeoutMs, ipcEnabled, ipcPrefer, ipcHost, ipcPort, ipcConnectTimeoutMs, ipcTimeoutMs }
  }

  function setActive(id, abortFn) {
    if (!id || typeof abortFn !== 'function') return
    active.set(String(id), abortFn)
  }

  function clearActive(id) {
    if (!id) return
    active.delete(String(id))
  }

  function abort(id) {
    const key = id ? String(id) : ''
    if (!key) return false
    const fn = active.get(key)
    if (!fn) return false
    try { fn() } catch {}
    active.delete(key)
    return true
  }

  function ipcRequest(type, payload, requestId) {
    const { ipcHost, ipcPort, ipcConnectTimeoutMs, ipcTimeoutMs } = getScannerCfg()
    const reqId = requestId ? String(requestId) : ''
    const msg = {
      version: 1,
      type: String(type || ''),
      payload: payload && typeof payload === 'object' ? payload : {},
      timeout_ms: ipcTimeoutMs
    }
    if (reqId) msg.id = reqId

    const json = Buffer.from(JSON.stringify(msg), 'utf-8')
    const frame = Buffer.allocUnsafe(4)
    frame.writeUInt32BE(json.length, 0)
    const out = Buffer.concat([frame, json])

    return new Promise((resolve, reject) => {
      let done = false
      let buf = Buffer.alloc(0)
      let expectedLen = null

      const socket = net.createConnection({ host: ipcHost, port: ipcPort })
      socket.setNoDelay(true)

      const connectTimer = setTimeout(() => {
        try {
          const e = new Error('CONNECT_TIMEOUT')
          e.isIpcTransport = true
          socket.destroy(e)
        } catch {}
      }, Math.max(1, ipcConnectTimeoutMs))

      const overallTimer = setTimeout(() => {
        try {
          const e = new Error('TIMEOUT')
          e.isIpcTransport = true
          socket.destroy(e)
        } catch {}
      }, Math.max(1, ipcTimeoutMs + ipcConnectTimeoutMs))

      if (reqId) {
        setActive(reqId, () => {
          try {
            const e = new Error('ABORTED')
            e.isIpcTransport = true
            socket.destroy(e)
          } catch {}
        })
      }

      function cleanup() {
        clearTimeout(connectTimer)
        clearTimeout(overallTimer)
        try { socket.removeAllListeners() } catch {}
        if (reqId) clearActive(reqId)
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
          e.isIpcTransport = true
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
            if (!Number.isFinite(expectedLen) || expectedLen < 0 || expectedLen > 64 * 1024 * 1024) {
              const e = new Error('IPC_PROTOCOL')
              e.isIpcTransport = true
              return finish(e)
            }
          }
          if (buf.length < 4 + expectedLen) return
          const body = buf.subarray(4, 4 + expectedLen)
          let parsed
          try {
            parsed = JSON.parse(body.toString('utf-8'))
          } catch (e) {
            e.isIpcTransport = true
            return finish(e)
          }
          try { socket.end() } catch {}
          return finish(null, parsed)
        } catch (e) {
          e.isIpcTransport = true
          finish(e)
        }
      })

      socket.once('error', (err) => {
        if (err && err.message === 'ABORTED') err.isIpcTransport = true
        if (err && err.message === 'TIMEOUT') err.isIpcTransport = true
        if (err && err.message === 'CONNECT_TIMEOUT') err.isIpcTransport = true
        finish(err)
      })

      socket.once('close', () => {
        if (done) return
        const e = new Error('IPC_CLOSED')
        e.isIpcTransport = true
        finish(e)
      })
    })
  }

  async function ipcHealth(requestId) {
    const res = await ipcRequest('health', {}, requestId)
    if (res && res.ok === false) {
      const e = new Error((res.error && res.error.message) ? String(res.error.message) : 'IPC_ERROR')
      if (res.error && res.error.code) e.code = String(res.error.code)
      e.isIpcTransport = false
      throw e
    }
    return (res && res.payload) ? res.payload : res
  }

  async function ipcScanFile(filePath, requestId) {
    const fp = typeof filePath === 'string' ? filePath : ''
    if (!fp) throw new Error('INVALID_FILE_PATH')
    const res = await ipcRequest('scan_file', { file_path: fp }, requestId)
    if (res && res.ok === false) {
      const e = new Error((res.error && res.error.message) ? String(res.error.message) : 'IPC_ERROR')
      if (res.error && res.error.code) e.code = String(res.error.code)
      e.isIpcTransport = false
      throw e
    }
    return (res && res.payload) ? res.payload : res
  }

  async function ipcScanBatch(filePaths, requestId) {
    const fps = Array.isArray(filePaths) ? filePaths.filter(p => typeof p === 'string' && p) : []
    if (fps.length === 0) throw new Error('INVALID_FILE_PATHS')
    const res = await ipcRequest('scan_batch', { file_paths: fps }, requestId)
    if (res && res.ok === false) {
      const e = new Error((res.error && res.error.message) ? String(res.error.message) : 'IPC_ERROR')
      if (res.error && res.error.code) e.code = String(res.error.code)
      e.isIpcTransport = false
      throw e
    }
    return (res && res.payload) ? res.payload : res
  }

  async function health(requestId) {
    const { ipcEnabled, ipcPrefer } = getScannerCfg()
    if (!ipcEnabled) throw new Error('IPC_DISABLED')
    if (!ipcPrefer) throw new Error('IPC_NOT_PREFERRED')
    return ipcHealth(requestId)
  }

  async function scanFile(filePath, requestId) {
    const fp = typeof filePath === 'string' ? filePath : ''
    if (!fp) throw new Error('INVALID_FILE_PATH')

    const { ipcEnabled, ipcPrefer } = getScannerCfg()
    if (!ipcEnabled) throw new Error('IPC_DISABLED')
    if (!ipcPrefer) throw new Error('IPC_NOT_PREFERRED')
    return ipcScanFile(fp, requestId)
  }

  async function scanBatch(filePaths, requestId) {
    const fps = Array.isArray(filePaths) ? filePaths.filter(p => typeof p === 'string' && p) : []
    if (fps.length === 0) throw new Error('INVALID_FILE_PATHS')

    const { ipcEnabled, ipcPrefer } = getScannerCfg()
    if (!ipcEnabled) throw new Error('IPC_DISABLED')
    if (!ipcPrefer) throw new Error('IPC_NOT_PREFERRED')
    return ipcScanBatch(fps, requestId)
  }

  async function control(command, token, requestId) {
    const cmd = typeof command === 'string' ? command : ''
    if (!cmd) throw new Error('INVALID_COMMAND')
    const { ipcEnabled, ipcPrefer } = getScannerCfg()
    if (!ipcEnabled) throw new Error('IPC_DISABLED')
    if (!ipcPrefer) throw new Error('IPC_NOT_PREFERRED')
    const payload = token ? { command: cmd, token: String(token) } : { command: cmd }
    const res = await ipcRequest('control', payload, requestId)
    if (res && res.ok === false) {
      const e = new Error((res.error && res.error.message) ? String(res.error.message) : 'IPC_ERROR')
      if (res.error && res.error.code) e.code = String(res.error.code)
      e.isIpcTransport = false
      throw e
    }
    return (res && res.payload) ? res.payload : res
  }

  return { health, scanFile, scanBatch, control, abort }
}

module.exports = { createScannerClient }
