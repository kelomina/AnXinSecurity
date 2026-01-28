const net = require('net')
const path = require('path')
const fs = require('fs')
const os = require('os')
const { Worker, isMainThread } = require('worker_threads')
let koffi = null

function createScannerClient(getConfig, deps = {}) {
  const active = new Map()
  let workerPool = null
  let workerSeq = 0

  function getScannerCfg() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const nativeDll = scanner && scanner.nativeDll ? scanner.nativeDll : {}
    const ipc = scanner && scanner.ipc ? scanner.ipc : {}
    const timeoutMs = Number.isFinite(scanner.timeoutMs) ? scanner.timeoutMs : 5000
    const envHost = process.env.SCANNER_SERVICE_IPC_HOST
    const envPort = process.env.SCANNER_SERVICE_IPC_PORT
    const ipcEnabled = ipc && ipc.enabled === false ? false : true
    const ipcPrefer = ipc && ipc.prefer === false ? false : true
    const nativeEnabled = nativeDll && nativeDll.enabled === false ? false : true
    const nativePrefer = nativeDll && nativeDll.prefer === true ? true : false
    const ipcHost = (typeof (envHost || ipc.host) === 'string' && (envHost || ipc.host).trim()) ? (envHost || ipc.host).trim() : '127.0.0.1'
    const parsedPort = parseInt(envPort || ipc.port, 10)
    const ipcPort = Number.isFinite(parsedPort) && parsedPort > 0 && parsedPort < 65536 ? parsedPort : 8765
    const ipcConnectTimeoutMs = Number.isFinite(ipc.connectTimeoutMs) ? ipc.connectTimeoutMs : 500
    const ipcTimeoutMs = Number.isFinite(ipc.timeoutMs) ? ipc.timeoutMs : timeoutMs
    return { timeoutMs, ipcEnabled, ipcPrefer, nativeEnabled, nativePrefer, ipcHost, ipcPort, ipcConnectTimeoutMs, ipcTimeoutMs }
  }

  function resolveWorkerPoolSize() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const tuning = scanner && scanner.tuning ? scanner.tuning : {}
    const cpuCount = (os && typeof os.cpus === 'function' && Array.isArray(os.cpus())) ? os.cpus().length : 4
    const maxTokens = Number.isFinite(scanner.maxTokens) ? Math.floor(scanner.maxTokens) : cpuCount
    const minPool = Number.isFinite(tuning.minPoolSize) ? Math.floor(tuning.minPoolSize) : 1
    const maxPool = Number.isFinite(tuning.maxPoolSize) ? Math.floor(tuning.maxPoolSize) : Math.max(minPool, maxTokens)
    const base = Math.max(minPool, maxTokens)
    const size = Math.min(Math.max(maxPool, minPool), base)
    return Math.max(1, size)
  }

  function getWorkerConfigSnapshot() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    return {
      scanner: cfg && cfg.scanner ? cfg.scanner : {},
      scan: cfg && cfg.scan ? cfg.scan : {}
    }
  }

  function createWorkerPool(size) {
    const pool = { size, workers: [], queue: [] }
    for (let i = 0; i < size; i++) {
      createWorker(pool, i)
    }
    return pool
  }

  function createWorker(pool, id) {
    const workerPath = path.join(__dirname, 'workers', 'scan_worker.js')
    const worker = new Worker(workerPath)
    const wObj = { worker, busy: false, id, currentTask: null }

    worker.on('message', (msg) => {
      const m = msg && typeof msg === 'object' ? msg : {}
      if (m.type !== 'scan_batch_done') return
      const task = wObj.currentTask
      wObj.busy = false
      wObj.currentTask = null
      if (task && !task.done) {
        task.done = true
        if (task.requestId && task.clearActiveOnDone) clearActive(task.requestId)
        if (task.canceled) {
          task.resolve([])
        } else if (m.ok === false) {
          const e = new Error((m.error && typeof m.error === 'string') ? m.error : 'SCAN_FAILED')
          task.reject(e)
        } else {
          task.resolve(Array.isArray(m.results) ? m.results : [])
        }
      }
      processNext(pool)
    })

    worker.on('error', (err) => {
      const task = wObj.currentTask
      wObj.busy = false
      wObj.currentTask = null
      if (task && !task.done) {
        task.done = true
        if (task.requestId && task.clearActiveOnDone) clearActive(task.requestId)
        task.reject(err || new Error('WORKER_ERROR'))
      }
      try { worker.terminate() } catch {}
      pool.workers = pool.workers.filter(w => w.id !== id)
      createWorker(pool, id)
      processNext(pool)
    })

    pool.workers.push(wObj)
  }

  function processNext(pool) {
    if (!pool || pool.queue.length === 0) return
    const availableWorker = pool.workers.find(w => !w.busy)
    if (!availableWorker) return
    const task = pool.queue.shift()
    if (!task) return
    if (task.canceled || task.done) {
      if (!task.done) {
        task.done = true
        if (task.requestId && task.clearActiveOnDone) clearActive(task.requestId)
        task.resolve([])
      }
      return processNext(pool)
    }
    availableWorker.busy = true
    availableWorker.currentTask = task
    task.started = true
    try {
      availableWorker.worker.postMessage({
        type: 'scan_batch',
        taskId: task.id,
        requestId: task.requestId,
        filePaths: task.filePaths,
        config: task.config
      })
    } catch (e) {
      availableWorker.busy = false
      availableWorker.currentTask = null
      task.done = true
      if (task.requestId) clearActive(task.requestId)
      task.reject(e)
      processNext(pool)
    }
  }

  function ensureWorkerPool() {
    if (!isMainThread || deps.disableWorkerPool) return null
    if (workerPool) return workerPool
    const size = resolveWorkerPoolSize()
    workerPool = createWorkerPool(size)
    return workerPool
  }

  let kvd = {
    lib: null,
    create: null,
    destroy: null,
    scanPath: null,
    scanBytes: null,
    free: null,
    validateModels: null,
    configType: null,
    cfgPtr: null,
    handle: null,
    inited: false
  }

  function fileExists(p) {
    try {
      return !!(p && fs.existsSync(p))
    } catch {
      return false
    }
  }

  function resolveKvdDllPath() {
    const candidates = []
    try {
      if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
        candidates.push(path.join(process.resourcesPath, 'Engine', 'C++', 'build', 'src', 'Release', 'kvd.dll'))
      }
    } catch {}
    try {
      candidates.push(path.join(__dirname, '../../Engine/C++/build/src/Release/kvd.dll'))
    } catch {}
    try {
      candidates.push(path.join(process.cwd(), 'Engine', 'C++', 'build', 'src', 'Release', 'kvd.dll'))
    } catch {}
    try {
      candidates.push(path.join(__dirname, '../../Engine/C++/build/src/Debug/kvd.dll'))
    } catch {}
    for (const p of candidates) {
      if (fileExists(p)) return p
    }
    return null
  }

  function resolveModelPath(rel) {
    const cands = []
    try {
      if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
        cands.push(path.join(process.resourcesPath, 'Engine', 'Axon_v2', '_internal', 'saved_models', rel))
      }
    } catch {}
    try {
      cands.push(path.join(__dirname, '../../Engine/Axon_v2/_internal/saved_models', rel))
    } catch {}
    try {
      cands.push(path.join(process.cwd(), 'Engine', 'Axon_v2', '_internal', 'saved_models', rel))
    } catch {}
    for (const p of cands) {
      if (fileExists(p)) return p
    }
    return ''
  }

  function resolveFamilyJsonPath() {
    const cands = []
    try {
      if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
        cands.push(path.join(process.resourcesPath, 'Engine', 'Axon_v2', '_internal', 'hdbscan_cluster_results', 'file_cluster_mapping.json'))
        cands.push(path.join(process.resourcesPath, 'Engine', 'Axon_v2', '_internal', 'hdbscan_cluster_results', 'family_names_mapping.json'))
        cands.push(path.join(process.resourcesPath, 'Engine', 'Axon_v2', '_internal', 'hdbscan_cluster_results', 'family_classifier.json'))
      }
    } catch {}
    try {
      cands.push(path.join(__dirname, '../../Engine/Axon_v2/_internal/hdbscan_cluster_results/family_classifier.json'))
    } catch {}
    try {
      cands.push(path.join(process.cwd(), 'Engine', 'Axon_v2', '_internal', 'hdbscan_cluster_results', 'family_classifier.json'))
    } catch {}
    for (const p of cands) {
      if (fileExists(p)) return p
    }
    return ''
  }

  function ensureKvdEnv() {
    const main = resolveModelPath('lightgbm_model.txt')
    const normal = resolveModelPath('lightgbm_model_normal.txt')
    const packed = resolveModelPath('lightgbm_model_packed.txt')
    const family = resolveFamilyJsonPath()
    if (main && !process.env.SCANNER_LIGHTGBM_MODEL_PATH) process.env.SCANNER_LIGHTGBM_MODEL_PATH = main
    if (normal && !process.env.SCANNER_LIGHTGBM_MODEL_NORMAL_PATH) process.env.SCANNER_LIGHTGBM_MODEL_NORMAL_PATH = normal
    if (packed && !process.env.SCANNER_LIGHTGBM_MODEL_PACKED_PATH) process.env.SCANNER_LIGHTGBM_MODEL_PACKED_PATH = packed
    if (family && !process.env.SCANNER_FAMILY_CLASSIFIER_PATH) process.env.SCANNER_FAMILY_CLASSIFIER_PATH = family
  }

  function buildKvdConfigValues() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const maxMB = Number.isFinite(scanner.maxFileSizeMB) ? Math.max(1, Math.floor(scanner.maxFileSizeMB)) : 0
    const threshold = Number.isFinite(scanner.predictionThreshold) ? scanner.predictionThreshold : 0
    const allowedRoot = typeof scanner.allowedScanRoot === 'string' ? scanner.allowedScanRoot : ''
    return {
      model_path: process.env.SCANNER_LIGHTGBM_MODEL_PATH || '',
      model_normal_path: process.env.SCANNER_LIGHTGBM_MODEL_NORMAL_PATH || '',
      model_packed_path: process.env.SCANNER_LIGHTGBM_MODEL_PACKED_PATH || '',
      family_classifier_json_path: process.env.SCANNER_FAMILY_CLASSIFIER_PATH || '',
      allowed_scan_root: allowedRoot,
      max_file_size: maxMB > 0 ? Math.min(0xFFFFFFFF, maxMB * 1024 * 1024) : 0,
      prediction_threshold: (threshold > 0 && threshold <= 1) ? threshold : 0
    }
  }

  function buildKvdConfigPtr() {
    const cfgObj = buildKvdConfigValues()
    const ptr = koffi.alloc(kvd.configType, 1)
    koffi.encode(ptr, kvd.configType, cfgObj)
    return ptr
  }

  function ensureKvdLoaded() {
    if (kvd.inited) return !!kvd.handle
    if (!koffi) {
      try { koffi = require('koffi') } catch { koffi = null }
    }
    if (!koffi) return false
    const dll = resolveKvdDllPath()
    if (!dll) return false
    try {
      kvd.lib = koffi.load(dll)
      kvd.configType = koffi.struct('kvd_config', {
        model_path: 'string',
        model_normal_path: 'string',
        model_packed_path: 'string',
        family_classifier_json_path: 'string',
        allowed_scan_root: 'string',
        max_file_size: 'uint32_t',
        prediction_threshold: 'float'
      })
      kvd.create = kvd.lib.func('__cdecl', 'kvd_create', koffi.pointer('void *'), [koffi.pointer(kvd.configType)])
      kvd.destroy = kvd.lib.func('__cdecl', 'kvd_destroy', 'void', [koffi.pointer('void *')])
      kvd.scanPath = kvd.lib.func('__cdecl', 'kvd_scan_path', 'int', [koffi.pointer('void *'), 'string', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvd.scanBytes = kvd.lib.func('__cdecl', 'kvd_scan_bytes', 'int', [koffi.pointer('void *'), koffi.pointer('uint8_t'), 'size_t', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvd.free = kvd.lib.func('__cdecl', 'kvd_free', 'void', ['void *'])
      kvd.validateModels = kvd.lib.func('__cdecl', 'kvd_validate_models', 'int', [koffi.pointer(kvd.configType), koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
    } catch {
      kvd.lib = null
      kvd.inited = true
      return false
    }
    ensureKvdEnv()
    try {
      kvd.cfgPtr = buildKvdConfigPtr()
      kvd.handle = kvd.create(kvd.cfgPtr)
    } catch {
      kvd.handle = null
    }
    kvd.inited = true
    return !!kvd.handle
  }

  function canUseNative() {
    const { nativeEnabled } = getScannerCfg()
    if (!nativeEnabled) return false
    return ensureKvdLoaded()
  }

  function resolveBackend() {
    const { ipcEnabled, ipcPrefer, nativeEnabled, nativePrefer } = getScannerCfg()
    if (nativeEnabled && nativePrefer && canUseNative()) return 'native'
    if (ipcEnabled && ipcPrefer) return 'ipc'
    if (nativeEnabled && canUseNative()) return 'native'
    if (ipcEnabled) return 'ipc'
    throw new Error('NO_BACKEND')
  }

  function kvdHealth() {
    if (!canUseNative()) throw new Error('KVD_LOAD_FAILED')
    if (!kvd.cfgPtr) kvd.cfgPtr = buildKvdConfigPtr()
    const outCfg = kvd.cfgPtr
    const outStr = [null]
    const outLen = [0]
    const rc = kvd.validateModels(outCfg, outStr, outLen)
    if (rc !== 0) {
      let msg = 'INVALID'
      try {
        const ptr = outStr[0]
        const len = outLen[0] | 0
        if (ptr && len > 0) {
          const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
          msg = Buffer.from(bytes).toString('utf8') || msg
          try { kvd.free(ptr) } catch {}
        }
      } catch {}
      const e = new Error(msg)
      e.code = String(rc)
      throw e
    }
    return { ok: true }
  }

  async function kvdScanFile(filePath) {
    if (!canUseNative()) throw new Error('KVD_LOAD_FAILED')
    const outStr = [null]
    const outLen = [0]
    const rc = kvd.scanPath(kvd.handle, filePath, outStr, outLen)
    if (rc < 0) throw new Error('KVD_SCAN_FAILED')
    let json = '{}'
    try {
      const ptr = outStr[0]
      const len = outLen[0] | 0
      if (ptr && len > 0) {
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
        json = Buffer.from(bytes).toString('utf8') || '{}'
        try { kvd.free(ptr) } catch {}
      }
    } catch {}
    try {
      return JSON.parse(json)
    } catch {
      return {}
    }
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
        try { socket.on('error', () => {}) } catch {}
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
    const backend = resolveBackend()
    if (backend === 'native') return kvdHealth()
    return ipcHealth(requestId)
  }

  async function scanFile(filePath, requestId) {
    const fp = typeof filePath === 'string' ? filePath : ''
    if (!fp) throw new Error('INVALID_FILE_PATH')

    const backend = resolveBackend()
    if (backend === 'native') {
      const res = await scanBatch([fp], requestId)
      return (Array.isArray(res) && res[0]) ? res[0] : {}
    }
    return ipcScanFile(fp, requestId)
  }

  async function scanBatch(filePaths, requestId) {
    const fps = Array.isArray(filePaths) ? filePaths.filter(p => typeof p === 'string' && p) : []
    if (fps.length === 0) throw new Error('INVALID_FILE_PATHS')

    const backend = resolveBackend()
    if (backend === 'ipc') return ipcScanBatch(fps, requestId)
    const pool = ensureWorkerPool()
    if (!pool) {
      const out = []
      for (const p of fps) {
        try {
          const r = await kvdScanFile(p)
          out.push(r)
        } catch {
          out.push({})
        }
      }
      return out
    }
    const rid = requestId ? String(requestId) : ''
    const poolSize = Math.max(1, pool.size || 1)
    if (fps.length <= 1 || poolSize <= 1) {
      return new Promise((resolve, reject) => {
        const task = {
          id: String(Date.now()) + '-' + String(workerSeq++),
          filePaths: fps,
          requestId: rid,
          resolve,
          reject,
          started: false,
          done: false,
          canceled: false,
          clearActiveOnDone: true,
          config: getWorkerConfigSnapshot()
        }
        if (rid) {
          setActive(rid, () => {
            if (task.done) return
            task.canceled = true
            task.done = true
            const idx = pool.queue.indexOf(task)
            if (idx >= 0) pool.queue.splice(idx, 1)
            try { resolve([]) } catch {}
            clearActive(rid)
          })
        }
        pool.queue.push(task)
        processNext(pool)
      })
    }
    const maxTasks = Math.min(poolSize, fps.length)
    const chunkSize = Math.max(1, Math.ceil(fps.length / maxTasks))
    const chunks = []
    for (let i = 0; i < fps.length; i += chunkSize) {
      chunks.push({ offset: i, list: fps.slice(i, i + chunkSize) })
    }
    const results = new Array(fps.length)
    const tasks = []
    const configSnapshot = getWorkerConfigSnapshot()
    const taskPromises = chunks.map(({ offset, list }) => {
      return new Promise((resolve, reject) => {
        const task = {
          id: String(Date.now()) + '-' + String(workerSeq++),
          filePaths: list,
          requestId: rid,
          resolve,
          reject,
          started: false,
          done: false,
          canceled: false,
          clearActiveOnDone: false,
          offset,
          config: configSnapshot
        }
        tasks.push(task)
        pool.queue.push(task)
      }).then((arr) => {
        const out = Array.isArray(arr) ? arr : []
        for (let i = 0; i < list.length; i++) {
          results[offset + i] = out[i] || {}
        }
        return true
      }).catch(() => {
        for (let i = 0; i < list.length; i++) {
          results[offset + i] = {}
        }
        return false
      })
    })
    if (rid) {
      setActive(rid, () => {
        for (const task of tasks) {
          if (task.done) continue
          task.canceled = true
          task.done = true
          const idx = pool.queue.indexOf(task)
          if (idx >= 0) pool.queue.splice(idx, 1)
          try { task.resolve([]) } catch {}
        }
        clearActive(rid)
      })
    }
    processNext(pool)
    return Promise.all(taskPromises).then(() => {
      if (rid) clearActive(rid)
      for (let i = 0; i < results.length; i++) {
        if (!results[i]) results[i] = {}
      }
      return results
    })
  }

  async function control(command, token, requestId) {
    const cmd = typeof command === 'string' ? command : ''
    if (!cmd) throw new Error('INVALID_COMMAND')
    const backend = resolveBackend()
    if (backend === 'native') return { ok: true }
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
