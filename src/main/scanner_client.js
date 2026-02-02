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
    const timeoutMs = Number.isFinite(scanner.timeoutMs) ? scanner.timeoutMs : 5000
    const nativeEnabled = nativeDll && nativeDll.enabled === false ? false : true
    const nativePrefer = nativeDll && nativeDll.prefer === true ? true : false
    return { timeoutMs, nativeEnabled, nativePrefer }
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
    if (!pool) return
    while (pool.queue.length > 0) {
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
        continue
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
        continue
      }
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
    scanPaths: null,
    scanBytes: null,
    free: null,
    validateModels: null,
    configType: null,
    cfgPtr: null,
    handle: null,
    inited: false,
    loadError: ''
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
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Axon', 'kvd.dll'))
      }
    } catch {}
    try {
      candidates.push(path.join(__dirname, '../../Engine/Axon/kvd.dll'))
    } catch {}
    try {
      candidates.push(path.join(process.cwd(), 'Engine', 'Axon', 'kvd.dll'))
    } catch {}
    for (const p of candidates) {
      if (fileExists(p)) return p
    }
    return null
  }

  function resolveEngineRoots() {
    const roots = []
    try {
      if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
        const p = path.join(process.resourcesPath, 'Engine')
        if (fileExists(p)) roots.push(p)
      }
    } catch {}
    try {
      const p = path.join(__dirname, '../../Engine')
      if (fileExists(p)) roots.push(p)
    } catch {}
    try {
      const p = path.join(process.cwd(), 'Engine')
      if (fileExists(p)) roots.push(p)
    } catch {}
    return roots
  }

  function isDirectory(p) {
    try {
      const st = fs.statSync(p)
      return !!(st && st.isDirectory())
    } catch {
      return false
    }
  }

  function findFileInEngineRoots(fileName, targetDirs) {
    const roots = resolveEngineRoots()
    const dirSet = new Set(Array.isArray(targetDirs) ? targetDirs.map(s => String(s).toLowerCase()) : [])
    const skip = new Set(['node_modules', 'dist', 'dist2', 'build', 'vcpkg', '.git', '.storybook', 'docs'])
    const maxDepth = 6
    for (const root of roots) {
      if (!isDirectory(root)) continue
      const queue = [{ dir: root, depth: 0 }]
      while (queue.length) {
        const { dir, depth } = queue.shift()
        if (depth > maxDepth) continue
        let entries = []
        try {
          entries = fs.readdirSync(dir, { withFileTypes: true })
        } catch {
          entries = []
        }
        for (const ent of entries) {
          if (!ent) continue
          const name = ent.name || ''
          const lower = name.toLowerCase()
          const full = path.join(dir, name)
          if (ent.isDirectory()) {
            if (skip.has(lower)) continue
            if (dirSet.has(lower)) {
              const fp = path.join(full, fileName)
              if (fileExists(fp)) return fp
            }
            if (depth + 1 <= maxDepth) queue.push({ dir: full, depth: depth + 1 })
          }
        }
      }
    }
    return ''
  }

  function resolveModelPath(rel) {
    const cands = []
    try {
      if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
        cands.push(path.join(process.resourcesPath, 'Engine', 'Axon', 'saved_models', rel))
      }
    } catch {}
    try {
      cands.push(path.join(__dirname, '../../Engine/Axon/saved_models', rel))
    } catch {}
    try {
      cands.push(path.join(process.cwd(), 'Engine', 'Axon', 'saved_models', rel))
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
        cands.push(path.join(process.resourcesPath, 'Engine', 'Axon', 'hdbscan_cluster_results', 'family_classifier.json'))
      }
    } catch {}
    try {
      cands.push(path.join(__dirname, '../../Engine/Axon/hdbscan_cluster_results/family_classifier.json'))
    } catch {}
    try {
      cands.push(path.join(process.cwd(), 'Engine', 'Axon', 'hdbscan_cluster_results', 'family_classifier.json'))
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
    const setEnvPath = (key, candidate) => {
      const cur = process.env[key]
      if (cur && fileExists(cur)) return
      if (candidate && fileExists(candidate)) {
        process.env[key] = candidate
        return
      }
      if (cur && !fileExists(cur)) process.env[key] = ''
    }
    setEnvPath('SCANNER_LIGHTGBM_MODEL_PATH', main)
    setEnvPath('SCANNER_LIGHTGBM_MODEL_NORMAL_PATH', normal)
    setEnvPath('SCANNER_LIGHTGBM_MODEL_PACKED_PATH', packed)
    setEnvPath('SCANNER_FAMILY_CLASSIFIER_PATH', family)
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

  function ensureKvdLibraryLoaded() {
    if (kvd.lib) return true
    if (!koffi) {
      try { koffi = require('koffi') } catch { koffi = null }
    }
    if (!koffi) {
      kvd.loadError = 'KVD_KOFFI_MISSING'
      return false
    }
    const dll = resolveKvdDllPath()
    if (!dll) {
      kvd.loadError = 'KVD_DLL_NOT_FOUND'
      return false
    }
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
      kvd.scanPaths = kvd.lib.func('__cdecl', 'kvd_scan_paths', 'int', [koffi.pointer('void *'), 'void *', 'size_t', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvd.scanBytes = kvd.lib.func('__cdecl', 'kvd_scan_bytes', 'int', [koffi.pointer('void *'), koffi.pointer('uint8_t'), 'size_t', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvd.free = kvd.lib.func('__cdecl', 'kvd_free', 'void', ['void *'])
      kvd.validateModels = kvd.lib.func('__cdecl', 'kvd_validate_models', 'int', [koffi.pointer(kvd.configType), koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
    } catch {
      kvd.lib = null
      kvd.loadError = 'KVD_BIND_FAILED'
      return false
    }
    ensureKvdEnv()
    kvd.loadError = ''
    return true
  }

  function ensureKvdHandle() {
    if (kvd.handle) return true
    if (!ensureKvdLibraryLoaded()) return false
    try {
      if (!kvd.cfgPtr) kvd.cfgPtr = buildKvdConfigPtr()
      kvd.handle = kvd.create(kvd.cfgPtr)
    } catch {
      kvd.handle = null
    }
    if (!kvd.handle) kvd.loadError = 'KVD_CREATE_FAILED'
    return !!kvd.handle
  }

  function canUseNative() {
    const { nativeEnabled } = getScannerCfg()
    if (!nativeEnabled) return false
    return ensureKvdHandle()
  }

  function kvdHealth() {
    if (!ensureKvdLibraryLoaded()) throw new Error(kvd.loadError || 'KVD_LOAD_FAILED')
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

  async function kvdScanPaths(filePaths) {
    if (!canUseNative()) throw new Error('KVD_LOAD_FAILED')
    const list = Array.isArray(filePaths) ? filePaths.filter(p => typeof p === 'string' && p) : []
    if (!list.length) return []
    if (!kvd.scanPaths) throw new Error('KVD_SCAN_FAILED')
    let arrPtr = null
    try {
      const arrType = koffi.array('string', list.length)
      arrPtr = koffi.alloc(arrType, list.length)
      koffi.encode(arrPtr, arrType, list)
    } catch {
      arrPtr = null
    }
    const outStr = [null]
    const outLen = [0]
    const rc = kvd.scanPaths(kvd.handle, arrPtr, list.length, outStr, outLen)
    if (rc < 0) throw new Error('KVD_SCAN_FAILED')
    let json = '[]'
    try {
      const ptr = outStr[0]
      const len = outLen[0] | 0
      if (ptr && len > 0) {
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
        json = Buffer.from(bytes).toString('utf8') || '[]'
        try { kvd.free(ptr) } catch {}
      }
    } catch {}
    try {
      const parsed = JSON.parse(json)
      return Array.isArray(parsed) ? parsed : []
    } catch {
      return []
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

  async function health(requestId) {
    return kvdHealth(requestId)
  }

  async function scanFile(filePath, requestId) {
    const fp = typeof filePath === 'string' ? filePath : ''
    if (!fp) throw new Error('INVALID_FILE_PATH')

    const res = await scanBatch([fp], requestId)
    return (Array.isArray(res) && res[0]) ? res[0] : {}
  }

  async function scanBatch(filePaths, requestId) {
    const fps = Array.isArray(filePaths) ? filePaths.filter(p => typeof p === 'string' && p) : []
    if (fps.length === 0) throw new Error('INVALID_FILE_PATHS')
    if (!canUseNative()) throw new Error('KVD_LOAD_FAILED')
    const pool = ensureWorkerPool()
    if (!pool) {
      try {
        const arr = await kvdScanPaths(fps)
        const out = new Array(fps.length)
        for (let i = 0; i < fps.length; i++) out[i] = arr[i] || {}
        return out
      } catch {
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
    return { ok: true }
  }

  return { health, scanFile, scanBatch, control, abort }
}

module.exports = { createScannerClient }
