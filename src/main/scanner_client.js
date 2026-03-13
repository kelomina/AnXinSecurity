const path = require('path')
const fs = require('fs')
const os = require('os')
const { Worker, isMainThread } = require('worker_threads')
const crypto = require('crypto')
let koffi = null
let winapi = null
try { winapi = require('./winapi') } catch { winapi = null }

function createScannerClient(getConfig, deps = {}) {
  const active = new Map()
  let workerPool = null
  let workerSeq = 0

  function getScannerCfg() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const nativeDll = scanner && scanner.nativeDll ? scanner.nativeDll : {}
    const timeoutMs = Number.isFinite(scanner.timeoutMs) ? scanner.timeoutMs : 5000
    const nativeEnabled = false
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

  function resolveErrorLogDir() {
    const base = path.join(__dirname, '../../')
    const dir = path.join(base, 'data', 'logs', 'crash')
    try { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }) } catch {}
    return dir
  }

  function normalizeErrorPayload(err) {
    if (!err) return { message: 'UnknownError', stack: '' }
    if (typeof err === 'string') return { message: err, stack: '' }
    return {
      message: err.message ? String(err.message) : String(err),
      stack: err.stack ? String(err.stack) : ''
    }
  }

  function appendScannerTrace(payload) {
    try {
      const dir = resolveErrorLogDir()
      const isError = payload && (
        /error|fail|exception/i.test(String(payload.stage || '')) ||
        /error|fail|exception/i.test(String(payload.source || '')) ||
        payload.stack || payload.message
      )
      const fileName = isError ? 'error.log' : 'trace.log'
      const filePath = path.join(dir, fileName)
      const line = JSON.stringify(payload)
      fs.appendFileSync(filePath, line + '\n')
    } catch {}
  }

  function trace(stage, data) {
    const base = { ts: Date.now(), source: 'scanner_native', stage }
    const payload = (data && typeof data === 'object') ? Object.assign(base, data) : base
    appendScannerTrace(payload)
  }

  const signatureEngineName = '渡鸦'
  const signatureEngineKey = 'raven'

  function traceSig(stage, data) {
    const extra = { engine: signatureEngineName, engine_key: signatureEngineKey }
    const payload = (data && typeof data === 'object') ? Object.assign(extra, data) : extra
    trace(stage, payload)
  }

  function isLikelyPeFile(filePath) {
    if (typeof filePath !== 'string' || !filePath) return false
    let fd = null
    try {
      const st = fs.statSync(filePath)
      if (!st || !st.isFile() || st.size < 64) return false
      fd = fs.openSync(filePath, 'r')
      const head = Buffer.alloc(64)
      const read = fs.readSync(fd, head, 0, 64, 0)
      if (read < 64) return false
      if (head[0] !== 0x4d || head[1] !== 0x5a) return false
      const peOffset = head.readUInt32LE(0x3c)
      if (!Number.isFinite(peOffset) || peOffset < 0 || peOffset > st.size - 4) return false
      const sig = Buffer.alloc(4)
      const sigRead = fs.readSync(fd, sig, 0, 4, peOffset)
      if (sigRead < 4) return false
      return sig[0] === 0x50 && sig[1] === 0x45 && sig[2] === 0x00 && sig[3] === 0x00
    } catch {
      return false
    } finally {
      if (fd != null) {
        try { fs.closeSync(fd) } catch {}
      }
    }
  }

  function verifyTrusted(filePath) {
    if (!winapi || typeof winapi.verifyTrust !== 'function') return false
    try { return winapi.verifyTrust(filePath) === true } catch { return false }
  }

  let kvd = {
    lib: null,
    create: null,
    destroy: null,
    scanPath: null,
    scanPaths: null,
    scanBytes: null,
    trainFromPath: null,
    free: null,
    validateModels: null,
    configType: null,
    cfgPtr: null,
    handle: null,
    inited: false,
    loadError: '',
    scanPathsMissingLogged: false
  }
  let kvdSig = {
    lib: null,
    create: null,
    destroy: null,
    scanPath: null,
    scanPaths: null,
    scanBytes: null,
    trainFromPath: null,
    free: null,
    validateModels: null,
    configType: null,
    cfgPtr: null,
    handle: null,
    inited: false,
    loadError: '',
    scanPathsMissingLogged: false,
    scanPathsFailedLogged: false,
    scanPathsBroken: false
  }
  const traceState = { createSeq: 0, scanPathSeq: 0, scanPathsSeq: 0 }

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
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Axon', 'Release', 'axon_engine.dll'))
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Axon', 'axon_engine.dll'))
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Axon', 'kvd.dll'))
      }
    } catch {}
    try {
      candidates.push(path.join(__dirname, '../../Engine/Axon/Release/axon_engine.dll'))
      candidates.push(path.join(__dirname, '../../Engine/Axon/axon_engine.dll'))
      candidates.push(path.join(__dirname, '../../Engine/Axon/kvd.dll'))
    } catch {}
    try {
      candidates.push(path.join(process.cwd(), 'Engine', 'Axon', 'Release', 'axon_engine.dll'))
      candidates.push(path.join(process.cwd(), 'Engine', 'Axon', 'axon_engine.dll'))
      candidates.push(path.join(process.cwd(), 'Engine', 'Axon', 'kvd.dll'))
    } catch {}
    for (const p of candidates) {
      if (fileExists(p)) return p
    }
    return null
  }

  function resolveSignatureDllPath() {
    const candidates = []
    try {
      if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Raven', 'signature_engine.dll'))
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Signature', 'Release', 'signature_engine.dll'))
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Signature', 'signature_engine.dll'))
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Raven', 'raven_engine.dll'))
      }
    } catch {}
    try {
      candidates.push(path.join(__dirname, '../../Engine/Raven/signature_engine.dll'))
      candidates.push(path.join(__dirname, '../../Engine/Signature/Release/signature_engine.dll'))
      candidates.push(path.join(__dirname, '../../Engine/Signature/signature_engine.dll'))
      candidates.push(path.join(__dirname, '../../Engine/Raven/raven_engine.dll'))
    } catch {}
    try {
      candidates.push(path.join(process.cwd(), 'Engine', 'Raven', 'signature_engine.dll'))
      candidates.push(path.join(process.cwd(), 'Engine', 'Signature', 'Release', 'signature_engine.dll'))
      candidates.push(path.join(process.cwd(), 'Engine', 'Signature', 'signature_engine.dll'))
      candidates.push(path.join(process.cwd(), 'Engine', 'Raven', 'raven_engine.dll'))
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

  function ensureDir(p) {
    try {
      if (!p) return false
      fs.mkdirSync(p, { recursive: true })
      return true
    } catch {
      return false
    }
  }

  function resolveSignatureStorePath(scannerCfg) {
    const cfgPath = scannerCfg && typeof scannerCfg.signatureStorePath === 'string' ? scannerCfg.signatureStorePath : ''
    if (cfgPath) {
      const dir = path.dirname(cfgPath)
      if (ensureDir(dir)) return cfgPath
    }
    const root = (() => {
      try {
        const cwd = process.cwd()
        if (cwd) return cwd
      } catch {}
      return ''
    })()
    if (!root) return ''
    const p = path.join(root, 'data', 'raven_signature.db')
    const dir = path.dirname(p)
    if (!ensureDir(dir)) return ''
    return p
  }

  function resolveSignatureNativeModelPath(scannerCfg) {
    const cfgPath = scannerCfg && typeof scannerCfg.signatureDbPath === 'string' ? scannerCfg.signatureDbPath : ''
    if (cfgPath) {
      const dir = path.dirname(cfgPath)
      if (ensureDir(dir)) return cfgPath
    }
    const root = (() => {
      try {
        const cwd = process.cwd()
        if (cwd) return cwd
      } catch {}
      return ''
    })()
    if (!root) return ''
    const p = path.join(root, 'data', 'anxin_signature_db.bin')
    const dir = path.dirname(p)
    if (!ensureDir(dir)) return ''
    return p
  }

  function stableStringify(value) {
    if (value == null) return 'null'
    if (typeof value !== 'object') return JSON.stringify(value)
    if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']'
    const keys = Object.keys(value).sort()
    const parts = []
    for (const k of keys) {
      parts.push(JSON.stringify(k) + ':' + stableStringify(value[k]))
    }
    return '{' + parts.join(',') + '}'
  }

  const scriptExtSet = new Set(['.bat', '.cmd', '.ps1', '.js', '.vbs', '.wsf', '.hta', '.jse', '.vbe'])

  function getMaxFileSizeBytes() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const maxMB = Number.isFinite(scanner.maxFileSizeMB) ? Math.max(1, Math.floor(scanner.maxFileSizeMB)) : 0
    return maxMB > 0 ? Math.min(0x7FFFFFFF, maxMB * 1024 * 1024) : 0
  }

  function readFileSlice(fd, offset, length) {
    const buf = Buffer.alloc(length)
    const bytes = fs.readSync(fd, buf, 0, length, offset)
    return bytes > 0 ? buf.slice(0, bytes) : Buffer.alloc(0)
  }

  function readStringAt(fd, offset, maxLen) {
    const buf = readFileSlice(fd, offset, maxLen)
    if (!buf.length) return ''
    const idx = buf.indexOf(0)
    return buf.slice(0, idx >= 0 ? idx : buf.length).toString('utf8')
  }

  function computeEntropy(buf) {
    if (!buf || !buf.length) return 0
    const freq = new Array(256).fill(0)
    for (let i = 0; i < buf.length; i++) freq[buf[i]]++
    let ent = 0
    for (let i = 0; i < 256; i++) {
      const p = freq[i] / buf.length
      if (p > 0) ent -= p * Math.log2(p)
    }
    return ent
  }

  function computeFuzzyHashesFromBuffer(buf) {
    if (!buf || !buf.length) return []
    const chunkSize = 4096
    const maxChunks = 64
    const hashes = []
    for (let i = 0; i < buf.length && hashes.length < maxChunks; i += chunkSize) {
      const slice = buf.slice(i, Math.min(buf.length, i + chunkSize))
      const h = crypto.createHash('sha1').update(slice).digest('hex').slice(0, 16)
      hashes.push(h)
    }
    return hashes
  }

  function fuzzySimilarity(a, b) {
    if (!Array.isArray(a) || !Array.isArray(b) || !a.length || !b.length) return 0
    const setA = new Set(a)
    let hit = 0
    for (const x of b) if (setA.has(x)) hit++
    const denom = Math.max(1, setA.size + b.length - hit)
    return hit / denom
  }

  function normalizeTokenList(list, limit) {
    const out = []
    const seen = new Set()
    for (const item of list) {
      const t = typeof item === 'string' ? item.trim().toLowerCase() : ''
      if (!t || seen.has(t)) continue
      seen.add(t)
      out.push(t)
      if (limit > 0 && out.length >= limit) break
    }
    return out
  }

  function splitScriptSegments(text) {
    if (!text) return []
    const segs = text.split(/(\r\n|\n|\r|&&|\|\||[&|;])/g)
    const out = []
    for (const s of segs) {
      const v = typeof s === 'string' ? s.trim() : ''
      if (v) out.push(v)
    }
    return out
  }

  function extractScriptFeatures(text) {
    const segments = splitScriptSegments(text)
    const tokens = []
    const suspicious = ['powershell', 'cmd', 'reg', 'schtasks', 'certutil', 'bitsadmin', 'mshta', 'rundll32', 'wscript', 'cscript', 'invoke-webrequest', 'iex', 'download', 'base64', 'frombase64string', 'new-object', 'http', 'https']
    let hit = 0
    for (const seg of segments) {
      const parts = seg.toLowerCase().split(/[^a-z0-9_\-\.]+/g).filter(Boolean)
      for (const p of parts) {
        tokens.push(p)
        if (suspicious.includes(p)) hit++
      }
    }
    return { tokens: normalizeTokenList(tokens, 128), segments: segments.length, suspicious: hit }
  }

  function rvaToOffset(rva, sections) {
    for (const s of sections) {
      const start = s.virtualAddress
      const end = start + Math.max(s.virtualSize, s.rawSize)
      if (rva >= start && rva < end) return rva - start + s.rawPtr
    }
    return 0
  }

  function parsePeImports(filePath) {
    let fd = null
    try {
      fd = fs.openSync(filePath, 'r')
      const dos = readFileSlice(fd, 0, 64)
      if (dos.length < 64) return { apis: [], dlls: [] }
      const eMagic = dos.readUInt16LE(0)
      if (eMagic !== 0x5a4d) return { apis: [], dlls: [] }
      const eLfanew = dos.readUInt32LE(60)
      const ntHeader = readFileSlice(fd, eLfanew, 256)
      if (ntHeader.length < 256) return { apis: [], dlls: [] }
      const sig = ntHeader.readUInt32LE(0)
      if (sig !== 0x4550) return { apis: [], dlls: [] }
      const numSections = ntHeader.readUInt16LE(6)
      const sizeOpt = ntHeader.readUInt16LE(20)
      const optOffset = 24
      const magic = ntHeader.readUInt16LE(optOffset)
      const is64 = magic === 0x20b
      const dataDirOffset = optOffset + (is64 ? 112 : 96)
      const importRva = ntHeader.readUInt32LE(dataDirOffset + 8)
      const secOffset = eLfanew + 24 + sizeOpt
      const secBuf = readFileSlice(fd, secOffset, numSections * 40)
      const sections = []
      for (let i = 0; i < numSections; i++) {
        const base = i * 40
        if (base + 40 > secBuf.length) break
        const virtualSize = secBuf.readUInt32LE(base + 8)
        const virtualAddress = secBuf.readUInt32LE(base + 12)
        const rawSize = secBuf.readUInt32LE(base + 16)
        const rawPtr = secBuf.readUInt32LE(base + 20)
        sections.push({ virtualAddress, virtualSize, rawPtr, rawSize })
      }
      const importOffset = rvaToOffset(importRva, sections)
      if (!importOffset) return { apis: [], dlls: [] }
      const apis = []
      const dlls = []
      let cursor = importOffset
      const maxDesc = 256
      for (let i = 0; i < maxDesc; i++) {
        const desc = readFileSlice(fd, cursor, 20)
        if (desc.length < 20) break
        const origThunk = desc.readUInt32LE(0)
        const nameRva = desc.readUInt32LE(12)
        const firstThunk = desc.readUInt32LE(16)
        if (origThunk === 0 && nameRva === 0 && firstThunk === 0) break
        const nameOffset = rvaToOffset(nameRva, sections)
        const dll = nameOffset ? readStringAt(fd, nameOffset, 260) : ''
        if (dll) dlls.push(dll.toLowerCase())
        const thunkRva = origThunk || firstThunk
        const thunkOffset = rvaToOffset(thunkRva, sections)
        if (thunkOffset) {
          let tcur = thunkOffset
          const maxThunk = 2048
          for (let j = 0; j < maxThunk; j++) {
            const entry = readFileSlice(fd, tcur, is64 ? 8 : 4)
            if (entry.length < (is64 ? 8 : 4)) break
            const val = is64 ? Number(entry.readBigUInt64LE(0)) : entry.readUInt32LE(0)
            if (!val) break
            const isOrdinal = is64 ? (val & 0x8000000000000000) !== 0 : (val & 0x80000000) !== 0
            if (!isOrdinal) {
              const hintNameRva = is64 ? (val & 0x7FFFFFFFFFFFFFFF) : (val & 0x7FFFFFFF)
              const nameOff = rvaToOffset(hintNameRva, sections)
              if (nameOff) {
                const n = readStringAt(fd, nameOff + 2, 260)
                if (n) apis.push(n.toLowerCase())
              }
            }
            tcur += is64 ? 8 : 4
          }
        }
        cursor += 20
      }
      return { apis: normalizeTokenList(apis, 512), dlls: normalizeTokenList(dlls, 128) }
    } catch {
      return { apis: [], dlls: [] }
    } finally {
      if (fd) {
        try { fs.closeSync(fd) } catch {}
      }
    }
  }

  function extractRavenFeatures(filePath) {
    const sp = typeof filePath === 'string' ? filePath : ''
    if (!sp) return { features: {}, meta: { ok: false } }
    const ext = path.extname(sp).toLowerCase()
    const isScript = scriptExtSet.has(ext)
    let buf = Buffer.alloc(0)
    let size = 0
    try {
      const stat = fs.statSync(sp)
      size = stat && stat.size ? stat.size : 0
    } catch {}
    const maxBytes = getMaxFileSizeBytes()
    const readLimit = maxBytes > 0 ? Math.min(maxBytes, 8 * 1024 * 1024) : 2 * 1024 * 1024
    try {
      const fd = fs.openSync(sp, 'r')
      const len = size > 0 ? Math.min(size, readLimit) : readLimit
      buf = readFileSlice(fd, 0, len)
      try { fs.closeSync(fd) } catch {}
    } catch {
      buf = Buffer.alloc(0)
    }
    const entropy = computeEntropy(buf)
    const fuzzy = computeFuzzyHashesFromBuffer(buf)
    const features = { fuzzy, entropy }
    if (isScript) {
      const text = buf.toString('utf8')
      const script = extractScriptFeatures(text)
      features.script_tokens = script.tokens
      features.script_segments = script.segments
      features.script_suspicious = script.suspicious
      return { features, meta: { ok: true, type: 'script' } }
    }
    if (isLikelyPeFile(sp)) {
      const pe = parsePeImports(sp)
      features.apis = pe.apis
      features.dlls = pe.dlls
      features.api_seq = pe.apis.slice(0, 64)
      return { features, meta: { ok: true, type: 'pe' } }
    }
    return { features, meta: { ok: true, type: 'binary' } }
  }

  function makeFeatureCode(features) {
    try {
      const raw = stableStringify(features)
      return crypto.createHash('sha256').update(raw).digest('hex')
    } catch {
      return ''
    }
  }

  function buildSignatureFeaturePayload(result, features, meta) {
    const obj = (result && typeof result === 'object') ? result : {}
    const baseMeta = {
      ok: obj.ok === true,
      total: Number.isFinite(obj.total) ? obj.total : 0,
      trained: Number.isFinite(obj.trained) ? obj.trained : 0,
      failed: Number.isFinite(obj.failed) ? obj.failed : 0
    }
    const mergedMeta = Object.assign({}, baseMeta, meta && typeof meta === 'object' ? meta : {})
    const outFeatures = features && typeof features === 'object' ? features : {}
    return { features: outFeatures, meta: mergedMeta }
  }

  function ensureSignatureStoreShape(store) {
    if (!store || typeof store !== 'object') {
      return {
        version: 4,
        version_id: '',
        parent_version_id: '',
        updated_at: Date.now(),
        signatures: [],
        api_stats: {},
        api_sequences: {},
        fuzzy_stats: {},
        meta: {}
      }
    }
    if (!Array.isArray(store.signatures)) store.signatures = []
    if (!store.api_stats || typeof store.api_stats !== 'object') store.api_stats = {}
    if (!store.api_sequences || typeof store.api_sequences !== 'object') store.api_sequences = {}
    if (!store.fuzzy_stats || typeof store.fuzzy_stats !== 'object') store.fuzzy_stats = {}
    if (typeof store.version_id !== 'string') store.version_id = ''
    if (typeof store.parent_version_id !== 'string') store.parent_version_id = ''
    if (!store.meta || typeof store.meta !== 'object') store.meta = {}
    store.version = 4
    return store
  }

  function ensureSignatureIndexShape(index) {
    if (!index || typeof index !== 'object') {
      return { current_version_id: '', last_snapshot_version_id: '', delta_since_snapshot: 0, versions: [] }
    }
    if (typeof index.current_version_id !== 'string') index.current_version_id = ''
    if (typeof index.last_snapshot_version_id !== 'string') index.last_snapshot_version_id = ''
    if (!Number.isFinite(index.delta_since_snapshot)) index.delta_since_snapshot = 0
    if (!Array.isArray(index.versions)) index.versions = []
    return index
  }

  function resolveSignatureIndexPath(scannerCfg) {
    const storePath = resolveSignatureStorePath(scannerCfg)
    if (!storePath) return ''
    return storePath + '.index.json'
  }

  function readSignatureIndex(indexPath) {
    try {
      if (!indexPath || !fs.existsSync(indexPath)) return null
      const raw = fs.readFileSync(indexPath, 'utf8')
      const parsed = raw ? JSON.parse(raw) : null
      return ensureSignatureIndexShape(parsed)
    } catch {
      return null
    }
  }

  function writeSignatureIndex(indexPath, index) {
    try {
      if (!indexPath) return false
      fs.writeFileSync(indexPath, JSON.stringify(index), 'utf8')
      return true
    } catch {
      return false
    }
  }

  function hashLineId(line) {
    try {
      return crypto.createHash('sha256').update(line).digest('hex')
    } catch {
      return ''
    }
  }

  function normalizeStoreEntry(entry) {
    if (!entry || typeof entry !== 'object') return null
    if (entry.entry_type === 'snapshot' || entry.entry_type === 'delta') return entry
    if (entry.signatures || entry.api_stats || entry.api_sequences || entry.fuzzy_stats) {
      const clone = Object.assign({}, entry)
      clone.entry_type = 'snapshot'
      return clone
    }
    return entry
  }

  function rebuildSignatureIndex(storePath, indexPath) {
    try {
      if (!storePath || !fs.existsSync(storePath)) return null
      const buf = fs.readFileSync(storePath)
      const text = buf ? buf.toString('utf8') : ''
      if (!text) return null
      const index = ensureSignatureIndexShape(null)
      let offset = 0
      let lastId = ''
      let lastSnapshotId = ''
      let deltaSinceSnapshot = 0
      const lines = text.split(/\n/)
      for (let i = 0; i < lines.length; i++) {
        const lineRaw = lines[i]
        const line = lineRaw.trim()
        const length = Buffer.byteLength(lineRaw + '\n')
        if (!line) {
          offset += length
          continue
        }
        let parsed = null
        try { parsed = JSON.parse(line) } catch { parsed = null }
        const normalized = normalizeStoreEntry(parsed)
        const entryType = normalized && normalized.entry_type ? normalized.entry_type : 'snapshot'
        const entryId = normalized && typeof normalized.version_id === 'string' && normalized.version_id
          ? normalized.version_id
          : hashLineId(line)
        const parentId = normalized && typeof normalized.parent_version_id === 'string'
          ? normalized.parent_version_id
          : lastId
        index.versions.push({
          id: entryId,
          parent_id: parentId,
          ts: normalized && Number.isFinite(normalized.updated_at) ? normalized.updated_at : Date.now(),
          offset,
          length,
          entry_type: entryType
        })
        lastId = entryId
        if (entryType === 'snapshot') {
          lastSnapshotId = entryId
          deltaSinceSnapshot = 0
        } else {
          deltaSinceSnapshot += 1
        }
        offset += length
      }
      index.current_version_id = lastId
      index.last_snapshot_version_id = lastSnapshotId
      index.delta_since_snapshot = deltaSinceSnapshot
      writeSignatureIndex(indexPath, index)
      return index
    } catch {
      return null
    }
  }

  function readStoreEntryByOffset(storePath, offset, length) {
    try {
      if (!storePath || !Number.isFinite(offset) || !Number.isFinite(length)) return null
      const fd = fs.openSync(storePath, 'r')
      const buf = Buffer.alloc(length)
      const readBytes = fs.readSync(fd, buf, 0, length, offset)
      try { fs.closeSync(fd) } catch {}
      if (!readBytes) return null
      const line = buf.toString('utf8').trim()
      if (!line) return null
      const parsed = JSON.parse(line)
      return normalizeStoreEntry(parsed)
    } catch {
      return null
    }
  }

  function mergeSignatureMeta(a, b) {
    const ma = a && typeof a === 'object' ? a : {}
    const mb = b && typeof b === 'object' ? b : {}
    const out = {}
    const ok = (ma.ok === true) || (mb.ok === true)
    out.ok = ok
    const total = (Number.isFinite(ma.total) ? ma.total : 0) + (Number.isFinite(mb.total) ? mb.total : 0)
    const trained = (Number.isFinite(ma.trained) ? ma.trained : 0) + (Number.isFinite(mb.trained) ? mb.trained : 0)
    const failed = (Number.isFinite(ma.failed) ? ma.failed : 0) + (Number.isFinite(mb.failed) ? mb.failed : 0)
    out.total = total
    out.trained = trained
    out.failed = failed
    if (typeof ma.type === 'string' && ma.type) out.type = ma.type
    else if (typeof mb.type === 'string' && mb.type) out.type = mb.type
    return out
  }

  function applyDeltaStats(storeStats, deltaStats) {
    if (!deltaStats || typeof deltaStats !== 'object') return
    const keys = Object.keys(deltaStats)
    for (const key of keys) {
      const cur = storeStats[key] || { mal: 0, white: 0 }
      const inc = deltaStats[key] || {}
      const mal = Number.isFinite(inc.mal) ? inc.mal : 0
      const white = Number.isFinite(inc.white) ? inc.white : 0
      cur.mal = (Number.isFinite(cur.mal) ? cur.mal : 0) + mal
      cur.white = (Number.isFinite(cur.white) ? cur.white : 0) + white
      storeStats[key] = cur
    }
  }

  function applySignatureDelta(store, delta) {
    if (!store || !delta || typeof delta !== 'object') return
    if (delta.api_stats) applyDeltaStats(store.api_stats, delta.api_stats)
    if (delta.api_sequences) applyDeltaStats(store.api_sequences, delta.api_sequences)
    if (delta.fuzzy_stats) applyDeltaStats(store.fuzzy_stats, delta.fuzzy_stats)
    const sigs = Array.isArray(delta.signatures) ? delta.signatures : []
    for (const item of sigs) {
      if (!item || typeof item !== 'object') continue
      const code = typeof item.code === 'string' ? item.code : ''
      if (!code) continue
      const existing = store.signatures.find(s => s && s.code === code)
      if (!existing) {
        store.signatures.push({
          code,
          features: item.features || {},
          meta: item.meta || {},
          ts: Number.isFinite(item.ts) ? item.ts : Date.now(),
          count: Number.isFinite(item.count) ? item.count : 1,
          first_ts: Number.isFinite(item.first_ts) ? item.first_ts : Date.now(),
          last_ts: Number.isFinite(item.last_ts) ? item.last_ts : Date.now()
        })
      } else {
        existing.meta = mergeSignatureMeta(existing.meta, item.meta)
        existing.ts = Number.isFinite(item.ts) ? item.ts : Date.now()
        existing.count = (Number.isFinite(existing.count) ? existing.count : 0) + (Number.isFinite(item.count) ? item.count : 1)
        if (!Number.isFinite(existing.first_ts)) existing.first_ts = Number.isFinite(item.first_ts) ? item.first_ts : Date.now()
        existing.last_ts = Number.isFinite(item.last_ts) ? item.last_ts : Date.now()
      }
    }
  }

  function updateApiStats(store, apis, isWhite, delta) {
    if (!Array.isArray(apis) || !apis.length) return
    for (const api of apis) {
      const key = typeof api === 'string' ? api.toLowerCase() : ''
      if (!key) continue
      const cur = store.api_stats[key] || { mal: 0, white: 0 }
      if (isWhite) cur.white += 1
      else cur.mal += 1
      store.api_stats[key] = cur
      if (delta) {
        const d = delta.api_stats || (delta.api_stats = {})
        const cd = d[key] || { mal: 0, white: 0 }
        if (isWhite) cd.white += 1
        else cd.mal += 1
        d[key] = cd
      }
    }
  }

  function updateSequenceStats(store, seq, isWhite, delta) {
    if (!Array.isArray(seq) || seq.length < 3) return
    const key = seq.join('>')
    if (!key) return
    const cur = store.api_sequences[key] || { mal: 0, white: 0 }
    if (isWhite) cur.white += 1
    else cur.mal += 1
    store.api_sequences[key] = cur
    if (delta) {
      const d = delta.api_sequences || (delta.api_sequences = {})
      const cd = d[key] || { mal: 0, white: 0 }
      if (isWhite) cd.white += 1
      else cd.mal += 1
      d[key] = cd
    }
  }

  function updateFuzzyStats(store, hashes, isWhite, delta) {
    if (!Array.isArray(hashes) || !hashes.length) return
    const key = hashes.join('.')
    if (!key) return
    const cur = store.fuzzy_stats[key] || { mal: 0, white: 0 }
    if (isWhite) cur.white += 1
    else cur.mal += 1
    store.fuzzy_stats[key] = cur
    if (delta) {
      const d = delta.fuzzy_stats || (delta.fuzzy_stats = {})
      const cd = d[key] || { mal: 0, white: 0 }
      if (isWhite) cd.white += 1
      else cd.mal += 1
      d[key] = cd
    }
  }

  function sleepSync(ms) {
    try {
      const sab = new SharedArrayBuffer(4)
      const i32 = new Int32Array(sab)
      Atomics.wait(i32, 0, 0, ms)
    } catch {}
  }

  function buildStoreFromSnapshotEntry(entry, versionIdOverride) {
    if (!entry || typeof entry !== 'object') return ensureSignatureStoreShape(null)
    const store = ensureSignatureStoreShape({
      version: entry.version,
      version_id: entry.version_id || versionIdOverride || '',
      parent_version_id: entry.parent_version_id || '',
      updated_at: Number.isFinite(entry.updated_at) ? entry.updated_at : Date.now(),
      signatures: entry.signatures,
      api_stats: entry.api_stats,
      api_sequences: entry.api_sequences,
      fuzzy_stats: entry.fuzzy_stats,
      meta: entry.meta
    })
    return store
  }

  function readSignatureStoreFromFile(storePath, indexPath) {
    try {
      if (!storePath || !fs.existsSync(storePath)) return { store: ensureSignatureStoreShape(null), index: null }
      let index = readSignatureIndex(indexPath)
      if (!index) index = rebuildSignatureIndex(storePath, indexPath)
      if (!index || !Array.isArray(index.versions) || !index.versions.length) {
        const raw = fs.readFileSync(storePath, 'utf8')
        const text = raw ? String(raw).trim() : ''
        if (!text) return { store: ensureSignatureStoreShape(null), index: null }
        const lines = text.split(/\r?\n/)
        for (let i = lines.length - 1; i >= 0; i--) {
          const line = lines[i].trim()
          if (!line) continue
          try {
            const parsed = JSON.parse(line)
            const normalized = normalizeStoreEntry(parsed)
            if (normalized && normalized.entry_type === 'snapshot') {
              return { store: buildStoreFromSnapshotEntry(normalized), index: null }
            }
          } catch {}
        }
        return { store: ensureSignatureStoreShape(null), index: null }
      }
      const currentId = index.current_version_id || index.versions[index.versions.length - 1].id
      const currentIdx = index.versions.findIndex(v => v && v.id === currentId)
      const endIdx = currentIdx >= 0 ? currentIdx : (index.versions.length - 1)
      let startIdx = -1
      for (let i = endIdx; i >= 0; i--) {
        const v = index.versions[i]
        if (v && v.entry_type === 'snapshot') {
          startIdx = i
          break
        }
      }
      if (startIdx < 0) startIdx = 0
      const baseEntryInfo = index.versions[startIdx]
      let store = ensureSignatureStoreShape(null)
      let applyStart = startIdx
      if (baseEntryInfo && baseEntryInfo.entry_type === 'snapshot') {
        const baseEntry = readStoreEntryByOffset(storePath, baseEntryInfo.offset, baseEntryInfo.length)
        store = buildStoreFromSnapshotEntry(baseEntry, baseEntryInfo.id)
        applyStart = startIdx + 1
      }
      for (let i = applyStart; i <= endIdx; i++) {
        const info = index.versions[i]
        const entry = readStoreEntryByOffset(storePath, info.offset, info.length)
        if (!entry) continue
        if (entry.entry_type === 'snapshot') {
          store = buildStoreFromSnapshotEntry(entry, info.id)
        } else if (entry.entry_type === 'delta') {
          applySignatureDelta(store, entry.delta || {})
          store.updated_at = Number.isFinite(entry.updated_at) ? entry.updated_at : Date.now()
        }
      }
      store.version_id = currentId
      const curInfo = index.versions[endIdx]
      store.parent_version_id = curInfo && typeof curInfo.parent_id === 'string' ? curInfo.parent_id : store.parent_version_id
      return { store: ensureSignatureStoreShape(store), index }
    } catch {
      return { store: ensureSignatureStoreShape(null), index: null }
    }
  }

  function withSignatureStoreLock(storePath, fn) {
    const lockPath = storePath + '.lock'
    let fd = null
    for (let i = 0; i < 200; i++) {
      try {
        fd = fs.openSync(lockPath, 'wx')
        break
      } catch {
        sleepSync(10)
      }
    }
    try {
      if (!fd) return false
      return fn()
    } finally {
      if (fd) {
        try { fs.closeSync(fd) } catch {}
        try { fs.unlinkSync(lockPath) } catch {}
      }
    }
  }

  function buildSignatureStoreMeta(store) {
    const meta = store && store.meta && typeof store.meta === 'object' ? store.meta : {}
    meta.total_signatures = Array.isArray(store.signatures) ? store.signatures.length : 0
    meta.updated_at = store.updated_at
    store.meta = meta
  }

  function createVersionId() {
    const ts = Date.now()
    const rand = crypto.randomBytes(8).toString('hex')
    return `${ts}-${rand}`
  }

  function persistSignatureStore(result, features, meta, isWhite) {
    try {
      const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
      const scanner = cfg && cfg.scanner ? cfg.scanner : {}
      const storePath = resolveSignatureStorePath(scanner)
      if (!storePath) return { ok: false, versionId: '' }
      const indexPath = resolveSignatureIndexPath(scanner)
      return withSignatureStoreLock(storePath, () => {
        const state = readSignatureStoreFromFile(storePath, indexPath)
        const store = state && state.store ? state.store : ensureSignatureStoreShape(null)
        const index = state && state.index ? state.index : ensureSignatureIndexShape(null)
        const payload = buildSignatureFeaturePayload(result, features, meta)
        const code = makeFeatureCode(payload.features)
        if (!code) return { ok: false, versionId: '' }
        const delta = { signatures: [] }
        updateApiStats(store, payload.features.apis, isWhite, delta)
        updateSequenceStats(store, payload.features.api_seq, isWhite, delta)
        updateFuzzyStats(store, payload.features.fuzzy, isWhite, delta)
        if (!isWhite) {
          const now = Date.now()
          const existing = store.signatures.find(s => s && s.code === code)
          if (!existing) {
            const entry = { code, features: payload.features, meta: payload.meta, ts: now, count: 1, first_ts: now, last_ts: now }
            store.signatures.push(entry)
            delta.signatures.push(Object.assign({ action: 'add' }, entry))
          } else {
            existing.meta = mergeSignatureMeta(existing.meta, payload.meta)
            existing.ts = now
            existing.count = (Number.isFinite(existing.count) ? existing.count : 0) + 1
            if (!Number.isFinite(existing.first_ts)) existing.first_ts = now
            existing.last_ts = now
            delta.signatures.push({
              action: 'update',
              code,
              meta: existing.meta,
              ts: existing.ts,
              count: 1,
              first_ts: existing.first_ts,
              last_ts: existing.last_ts
            })
          }
        }
        const parentId = store.version_id || index.current_version_id || ''
        const versionId = createVersionId()
        store.parent_version_id = parentId
        store.version_id = versionId
        store.updated_at = Date.now()
        buildSignatureStoreMeta(store)
        const snapshotEvery = Number.isFinite(scanner.signatureSnapshotEvery)
          ? Math.max(1, Math.floor(scanner.signatureSnapshotEvery))
          : 50
        const needSnapshot = index.delta_since_snapshot >= snapshotEvery || !index.last_snapshot_version_id
        const entry = needSnapshot
          ? {
              entry_type: 'snapshot',
              version: store.version,
              version_id: store.version_id,
              parent_version_id: store.parent_version_id,
              updated_at: store.updated_at,
              signatures: store.signatures,
              api_stats: store.api_stats,
              api_sequences: store.api_sequences,
              fuzzy_stats: store.fuzzy_stats,
              meta: store.meta
            }
          : {
              entry_type: 'delta',
              version: store.version,
              version_id: store.version_id,
              parent_version_id: store.parent_version_id,
              updated_at: store.updated_at,
              delta: delta,
              meta: store.meta
            }
        const line = JSON.stringify(entry) + '\n'
        const offset = fs.existsSync(storePath) ? fs.statSync(storePath).size : 0
        const length = Buffer.byteLength(line, 'utf8')
        fs.appendFileSync(storePath, line)
        index.versions.push({
          id: versionId,
          parent_id: parentId,
          ts: store.updated_at,
          offset,
          length,
          entry_type: entry.entry_type
        })
        index.current_version_id = versionId
        if (entry.entry_type === 'snapshot') {
          index.last_snapshot_version_id = versionId
          index.delta_since_snapshot = 0
        } else {
          index.delta_since_snapshot = (Number.isFinite(index.delta_since_snapshot) ? index.delta_since_snapshot : 0) + 1
        }
        writeSignatureIndex(indexPath, index)
        return { ok: true, versionId }
      })
    } catch {
      return { ok: false, versionId: '' }
    }
  }

  function loadSignatureStore() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const storePath = resolveSignatureStorePath(scanner)
    const indexPath = resolveSignatureIndexPath(scanner)
    if (!storePath) return null
    const state = readSignatureStoreFromFile(storePath, indexPath)
    return state && state.store ? state.store : ensureSignatureStoreShape(null)
  }

  function computeApiWeightScore(apis, store) {
    if (!Array.isArray(apis) || !apis.length || !store || !store.api_stats) return 0
    let sum = 0
    for (const api of apis) {
      const key = typeof api === 'string' ? api.toLowerCase() : ''
      if (!key) continue
      const cur = store.api_stats[key]
      if (!cur) continue
      const mal = Number.isFinite(cur.mal) ? cur.mal : 0
      const white = Number.isFinite(cur.white) ? cur.white : 0
      const w = Math.log((mal + 1) / (white + 1))
      sum += w
    }
    const avg = sum / Math.max(1, apis.length)
    if (avg <= 0.5) return 0
    return Math.min(1, avg / 4)
  }

  function hasSequenceHit(apis, store) {
    if (!Array.isArray(apis) || apis.length < 3 || !store || !store.api_sequences) return false
    const joined = apis.join('>')
    const keys = Object.keys(store.api_sequences)
    for (const key of keys) {
      const cur = store.api_sequences[key]
      if (!cur || cur.mal <= cur.white) continue
      if (joined.includes(key)) return true
    }
    return false
  }

  function findFuzzySimilarity(hashes, store) {
    if (!Array.isArray(hashes) || !hashes.length || !store || !store.signatures) return 0
    let best = 0
    for (const sig of store.signatures) {
      const fz = sig && sig.features ? sig.features.fuzzy : null
      if (!Array.isArray(fz) || !fz.length) continue
      const sim = fuzzySimilarity(hashes, fz)
      if (sim > best) best = sim
    }
    return best
  }

  function scanRavenByStore(filePath, storeOverride) {
    const sp = typeof filePath === 'string' ? filePath : ''
    if (!sp) return {}
    if (verifyTrusted(sp)) {
      return { signature_verified: true, signature_hit: false, signature_score: 0, is_malware: false, confidence: 0, signature_reason: 'signature_trusted' }
    }
    const store = storeOverride || loadSignatureStore()
    const info = extractRavenFeatures(sp)
    if (!info || !info.features) return {}
    const code = makeFeatureCode(info.features)
    let score = 0
    const reasons = []
    if (store && Array.isArray(store.signatures) && code) {
      const hit = store.signatures.find(s => s && s.code === code)
      if (hit) {
        score = 1
        reasons.push('feature_match')
      }
    }
    const fuzzyScore = findFuzzySimilarity(info.features.fuzzy, store)
    if (fuzzyScore >= 0.6) {
      score = Math.max(score, fuzzyScore)
      reasons.push('fuzzy_match')
    }
    const apiScore = computeApiWeightScore(info.features.apis, store)
    if (apiScore > 0) {
      score = Math.max(score, apiScore)
      reasons.push('api_weight')
    }
    if (hasSequenceHit(info.features.api_seq, store)) {
      score = Math.max(score, 0.9)
      reasons.push('api_sequence')
    }
    if (Number.isFinite(info.features.script_suspicious) && info.features.script_suspicious >= 3) {
      score = Math.max(score, 0.7)
      reasons.push('script_suspicious')
    }
    const signature_hit = score >= 0.6
    return {
      signature_hit,
      signature_score: score,
      signature_reason: reasons.join('|'),
      is_malware: signature_hit,
      confidence: signature_hit ? score : 0
    }
  }

  function mergeSignatureResult(nativeRes, jsRes) {
    const n = nativeRes && typeof nativeRes === 'object' ? nativeRes : {}
    const j = jsRes && typeof jsRes === 'object' ? jsRes : {}
    const out = Object.assign({}, n)
    if (j.signature_verified !== undefined) out.signature_verified = j.signature_verified
    if (j.signature_hit !== undefined) {
      if (n.signature_hit === true) {
        const nScore = Number.isFinite(n.signature_score) ? n.signature_score : 0
        const jScore = Number.isFinite(j.signature_score) ? j.signature_score : 0
        if (jScore > nScore) {
          out.signature_hit = j.signature_hit
          out.signature_score = j.signature_score
          if (j.signature_reason) out.signature_reason = j.signature_reason
        }
      } else {
        out.signature_hit = j.signature_hit
        out.signature_score = j.signature_score
        if (j.signature_reason) out.signature_reason = j.signature_reason
      }
    }
    if (j.is_malware === true) out.is_malware = true
    if (j.confidence !== undefined) {
      const nConf = Number.isFinite(out.confidence) ? out.confidence : 0
      const jConf = Number.isFinite(j.confidence) ? j.confidence : 0
      out.confidence = Math.max(nConf, jConf)
    }
    return out
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
    const threshold = Number.isFinite(scanner.predictionThreshold) ? scanner.predictionThreshold : 0.98
    const allowedRoot = typeof scanner.allowedScanRoot === 'string' ? scanner.allowedScanRoot : ''
    return {
      model_path: process.env.SCANNER_LIGHTGBM_MODEL_PATH || '',
      model_normal_path: process.env.SCANNER_LIGHTGBM_MODEL_NORMAL_PATH || '',
      model_packed_path: process.env.SCANNER_LIGHTGBM_MODEL_PACKED_PATH || '',
      family_classifier_json_path: process.env.SCANNER_FAMILY_CLASSIFIER_PATH || '',
      allowed_scan_root: allowedRoot,
      max_file_size: maxMB > 0 ? Math.min(0xFFFFFFFF, maxMB * 1024 * 1024) : 0,
      prediction_threshold: (threshold > 0 && threshold <= 1) ? threshold : 0.98
    }
  }

  function validateKvdConfigValues(cfgObj) {
    const missing = []
    if (!cfgObj || typeof cfgObj !== 'object') return { ok: false, missing: ['config'] }
    if (!cfgObj.model_path || !fileExists(cfgObj.model_path)) missing.push('model_path')
    if (!cfgObj.model_normal_path || !fileExists(cfgObj.model_normal_path)) missing.push('model_normal_path')
    if (!cfgObj.model_packed_path || !fileExists(cfgObj.model_packed_path)) missing.push('model_packed_path')
    if (!cfgObj.family_classifier_json_path || !fileExists(cfgObj.family_classifier_json_path)) missing.push('family_classifier_json_path')
    return { ok: missing.length === 0, missing }
  }

  function buildSignatureConfigValues() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const maxMB = Number.isFinite(scanner.maxFileSizeMB) ? Math.max(1, Math.floor(scanner.maxFileSizeMB)) : 0
    const allowedRoot = typeof scanner.allowedScanRoot === 'string' ? scanner.allowedScanRoot : ''
    const storePath = resolveSignatureNativeModelPath(scanner)
    return {
      model_path: storePath,
      model_normal_path: '',
      model_packed_path: '',
      family_classifier_json_path: '',
      allowed_scan_root: allowedRoot,
      max_file_size: maxMB > 0 ? Math.min(0xFFFFFFFF, maxMB * 1024 * 1024) : 0,
      prediction_threshold: 0
    }
  }

  function validateSignatureConfigValues() {
    return { ok: true, missing: [] }
  }

  function buildKvdConfigPtr(cfgObj) {
    const obj = cfgObj || buildKvdConfigValues()
    const ptr = koffi.alloc(kvd.configType, 1)
    koffi.encode(ptr, kvd.configType, obj)
    return ptr
  }

  function ensureKvdLibraryLoaded() {
    if (kvd.lib) return true
    if (!koffi) {
      try { koffi = require('koffi') } catch { koffi = null }
    }
    if (!koffi) {
      kvd.loadError = 'KVD_KOFFI_MISSING'
      trace('kvd_koffi_missing')
      return false
    }
    const dll = resolveKvdDllPath()
    if (!dll) {
      kvd.loadError = 'KVD_DLL_NOT_FOUND'
      trace('kvd_dll_not_found')
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
      const bind = (name, ret, args) => {
        try { return kvd.lib.func('__cdecl', name, ret, args) } catch { return null }
      }
      kvd.create = bind('kvd_create', koffi.pointer('void *'), [koffi.pointer(kvd.configType)])
      kvd.destroy = bind('kvd_destroy', 'void', [koffi.pointer('void *')])
      kvd.scanPath = bind('kvd_scan_path', 'int', [koffi.pointer('void *'), 'string', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvd.scanPaths = bind('kvd_scan_paths', 'int', [koffi.pointer('void *'), 'void *', 'size_t', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvd.scanBytes = bind('kvd_scan_bytes', 'int', [koffi.pointer('void *'), koffi.pointer('uint8_t'), 'size_t', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvd.trainFromPath = bind('kvd_train_from_path', 'int', [koffi.pointer('void *'), 'string', 'int', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      if (!kvd.trainFromPath) {
        kvd.trainFromPath = bind('kvd_train_path', 'int', [koffi.pointer('void *'), 'string', 'int', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      }
      kvd.free = bind('kvd_free', 'void', ['void *'])
      kvd.validateModels = bind('kvd_validate_models', 'int', [koffi.pointer(kvd.configType), koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      if (!kvd.create || !kvd.destroy || !kvd.scanPath || !kvd.free || !kvd.validateModels) {
        kvd.lib = null
        kvd.loadError = 'KVD_BIND_FAILED'
        const missing = []
        if (!kvd.create) missing.push('kvd_create')
        if (!kvd.destroy) missing.push('kvd_destroy')
        if (!kvd.scanPath) missing.push('kvd_scan_path')
        if (!kvd.free) missing.push('kvd_free')
        if (!kvd.validateModels) missing.push('kvd_validate_models')
        trace('kvd_bind_failed', { dll, hasScanPaths: !!kvd.scanPaths, hasScanBytes: !!kvd.scanBytes, missing })
        return false
      }
    } catch (e) {
      kvd.lib = null
      kvd.loadError = 'KVD_BIND_FAILED'
      trace('kvd_load_failed', { dll, ...normalizeErrorPayload(e) })
      return false
    }
    ensureKvdEnv()
    kvd.loadError = ''
    return true
  }

  function ensureSignatureLibraryLoaded() {
    if (kvdSig.lib) return true
    if (!koffi) {
      try { koffi = require('koffi') } catch { koffi = null }
    }
    if (!koffi) {
      kvdSig.loadError = 'KVD_KOFFI_MISSING'
      traceSig('raven_koffi_missing')
      return false
    }
    const dll = resolveSignatureDllPath()
    if (!dll) {
      kvdSig.loadError = 'KVD_DLL_NOT_FOUND'
      traceSig('raven_dll_not_found')
      return false
    }
    try {
      kvdSig.lib = koffi.load(dll)
      kvdSig.configType = koffi.struct('kvd_config_sig', {
        model_path: 'string',
        model_normal_path: 'string',
        model_packed_path: 'string',
        family_classifier_json_path: 'string',
        allowed_scan_root: 'string',
        max_file_size: 'uint32_t',
        prediction_threshold: 'float'
      })
      const bind = (name, ret, args) => {
        try { return kvdSig.lib.func('__cdecl', name, ret, args) } catch { return null }
      }
      kvdSig.create = bind('kvd_create', koffi.pointer('void *'), [koffi.pointer(kvdSig.configType)])
      kvdSig.destroy = bind('kvd_destroy', 'void', [koffi.pointer('void *')])
      kvdSig.scanPath = bind('kvd_scan_path', 'int', [koffi.pointer('void *'), 'string', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvdSig.scanPaths = bind('kvd_scan_paths', 'int', [koffi.pointer('void *'), 'void *', 'size_t', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvdSig.scanBytes = bind('kvd_scan_bytes', 'int', [koffi.pointer('void *'), koffi.pointer('uint8_t'), 'size_t', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvdSig.trainFromPath = bind('kvd_train_from_path', 'int', [koffi.pointer('void *'), 'string', 'int', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvdSig.trainPaths = bind('kvd_train_paths', 'int', [koffi.pointer('void *'), 'void *', 'size_t', 'int', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvdSig.flush = bind('kvd_signature_flush', 'void', [koffi.pointer('void *')])
      if (!kvdSig.trainFromPath) {
        kvdSig.trainFromPath = bind('kvd_train_path', 'int', [koffi.pointer('void *'), 'string', 'int', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      }
      kvdSig.free = bind('kvd_free', 'void', ['void *'])
      kvdSig.validateModels = bind('kvd_validate_models', 'int', [koffi.pointer(kvdSig.configType), koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      if (!kvdSig.create || !kvdSig.destroy || !kvdSig.scanPath || !kvdSig.free || !kvdSig.validateModels) {
        kvdSig.lib = null
        kvdSig.loadError = 'KVD_BIND_FAILED'
        const missing = []
        if (!kvdSig.create) missing.push('kvd_create')
        if (!kvdSig.destroy) missing.push('kvd_destroy')
        if (!kvdSig.scanPath) missing.push('kvd_scan_path')
        if (!kvdSig.free) missing.push('kvd_free')
        if (!kvdSig.validateModels) missing.push('kvd_validate_models')
        traceSig('raven_bind_failed', { dll, hasScanPaths: !!kvdSig.scanPaths, hasScanBytes: !!kvdSig.scanBytes, missing })
        return false
      }
    } catch (e) {
      kvdSig.lib = null
      kvdSig.loadError = 'KVD_BIND_FAILED'
      traceSig('raven_load_failed', { dll, ...normalizeErrorPayload(e) })
      return false
    }
    kvdSig.loadError = ''
    return true
  }

  function ensureKvdHandle() {
    if (kvd.handle) return true
    if (!ensureKvdLibraryLoaded()) return false
    try {
      const cfgObj = buildKvdConfigValues()
      const valid = validateKvdConfigValues(cfgObj)
      if (!valid.ok) {
        kvd.loadError = 'KVD_MODEL_MISSING'
        trace('kvd_config_invalid', { missing: valid.missing })
        return false
      }
      if (!kvd.cfgPtr) kvd.cfgPtr = buildKvdConfigPtr(cfgObj)
      const createSeq = ++traceState.createSeq
      trace('kvd_create_begin', { id: createSeq })
      kvd.handle = kvd.create(kvd.cfgPtr)
      trace('kvd_create_ok', { id: createSeq })
    } catch (e) {
      kvd.handle = null
      trace('kvd_create_failed', { ...normalizeErrorPayload(e) })
    }
    if (!kvd.handle) kvd.loadError = 'KVD_CREATE_FAILED'
    return !!kvd.handle
  }

  function ensureSignatureHandle() {
    if (kvdSig.handle) return true
    if (!ensureSignatureLibraryLoaded()) return false
    try {
      const cfgObj = buildSignatureConfigValues()
      const valid = validateSignatureConfigValues(cfgObj)
      if (!valid.ok) {
        kvdSig.loadError = 'KVD_MODEL_MISSING'
        traceSig('raven_config_invalid', { missing: valid.missing })
        return false
      }
      if (!kvdSig.cfgPtr) {
        kvdSig.cfgPtr = koffi.alloc(kvdSig.configType, 1)
        koffi.encode(kvdSig.cfgPtr, kvdSig.configType, cfgObj)
      }
      const createSeq = ++traceState.createSeq
      traceSig('raven_create_begin', { id: createSeq })
      kvdSig.handle = kvdSig.create(kvdSig.cfgPtr)
      traceSig('raven_create_ok', { id: createSeq })
    } catch (e) {
      kvdSig.handle = null
      traceSig('raven_create_failed', { ...normalizeErrorPayload(e) })
    }
    if (!kvdSig.handle) kvdSig.loadError = 'KVD_CREATE_FAILED'
    return !!kvdSig.handle
  }

  function canUseNative() {
    const { nativeEnabled } = getScannerCfg()
    if (!nativeEnabled) return false
    return ensureKvdHandle() || ensureSignatureHandle()
  }

  function kvdHealth() {
    const axonReady = ensureKvdLibraryLoaded()
    const sigReady = ensureSignatureLibraryLoaded()
    if (!axonReady && !sigReady) throw new Error(kvd.loadError || kvdSig.loadError || 'KVD_LOAD_FAILED')
    if (axonReady) {
      const cfgObj = buildKvdConfigValues()
      const valid = validateKvdConfigValues(cfgObj)
      if (!valid.ok) {
        trace('kvd_config_invalid', { missing: valid.missing })
        throw new Error('KVD_MODEL_MISSING')
      }
      if (!kvd.cfgPtr) kvd.cfgPtr = buildKvdConfigPtr(cfgObj)
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
        trace('kvd_validate_failed', { code: String(rc), message: msg })
        throw e
      }
      return { ok: true }
    }
    return { ok: true }
  }

  async function kvdScanFile(filePath) {
    if (!ensureKvdHandle()) throw new Error('KVD_LOAD_FAILED')
    const outStr = [null]
    const outLen = [0]
    const scanSeq = ++traceState.scanPathSeq
    if (scanSeq <= 30) {
      const name = typeof filePath === 'string' ? path.basename(filePath) : ''
      trace('kvd_scan_path_begin', { id: scanSeq, name })
    }
    const rc = kvd.scanPath(kvd.handle, filePath, outStr, outLen)
    if (rc < 0) {
      trace('kvd_scan_path_failed', { code: String(rc) })
      throw new Error('KVD_SCAN_FAILED')
    }
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
    if (!ensureKvdHandle()) throw new Error('KVD_LOAD_FAILED')
    const list = Array.isArray(filePaths) ? filePaths.filter(p => typeof p === 'string' && p) : []
    if (!list.length) return []
    if (!kvd.scanPaths) {
      if (!kvd.scanPathsMissingLogged) {
        kvd.scanPathsMissingLogged = true
        trace('kvd_scan_paths_missing')
      }
      return null
    }
    const scanSeq = ++traceState.scanPathsSeq
    if (scanSeq <= 10) trace('kvd_scan_paths_begin', { id: scanSeq, count: list.length })
    let arrPtr = null
    try {
      const arrType = koffi.array('string', list.length)
      arrPtr = koffi.alloc(arrType, list.length)
      koffi.encode(arrPtr, arrType, list)
    } catch (e) {
      arrPtr = null
      trace('kvd_scan_paths_alloc_failed', { ...normalizeErrorPayload(e) })
      throw new Error('KVD_SCAN_FAILED')
    }
    const outStr = [null]
    const outLen = [0]
    const rc = kvd.scanPaths(kvd.handle, arrPtr, list.length, outStr, outLen)
    if (rc < 0) {
      trace('kvd_scan_paths_failed', { code: String(rc) })
      throw new Error('KVD_SCAN_FAILED')
    }
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

  async function kvdScanFileSig(filePath) {
    if (!ensureSignatureHandle()) throw new Error('KVD_LOAD_FAILED')
    const sp = typeof filePath === 'string' ? filePath : ''
    if (sp && verifyTrusted(sp)) {
      return { signature_verified: true, signature_hit: false, signature_score: 0, is_malware: false, confidence: 0, signature_reason: 'signature_trusted' }
    }
    const outStr = [null]
    const outLen = [0]
    const scanSeq = ++traceState.scanPathSeq
    if (scanSeq <= 30) {
      const name = typeof filePath === 'string' ? path.basename(filePath) : ''
      traceSig('raven_scan_path_begin', { id: scanSeq, name })
    }
    const rc = kvdSig.scanPath(kvdSig.handle, filePath, outStr, outLen)
    if (rc < 0) {
      traceSig('raven_scan_path_failed', { code: String(rc) })
      throw new Error('KVD_SCAN_FAILED')
    }
    let json = '{}'
    try {
      const ptr = outStr[0]
      const len = outLen[0] | 0
      if (ptr && len > 0) {
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
        json = Buffer.from(bytes).toString('utf8') || '{}'
        try { kvdSig.free(ptr) } catch {}
      }
    } catch {}
    let nativeRes = {}
    try {
      nativeRes = JSON.parse(json)
    } catch {
      nativeRes = {}
    }
    return nativeRes && typeof nativeRes === 'object' ? nativeRes : {}
  }

  async function kvdScanPathsSig(filePaths) {
    if (!ensureSignatureHandle()) throw new Error('KVD_LOAD_FAILED')
    const list = Array.isArray(filePaths) ? filePaths.filter(p => typeof p === 'string' && p) : []
    if (!list.length) return []
    if (kvdSig.scanPathsBroken) return null
    if (!kvdSig.scanPaths) {
      if (!kvdSig.scanPathsMissingLogged) {
        kvdSig.scanPathsMissingLogged = true
        traceSig('raven_scan_paths_missing')
      }
      return null
    }
    const scanSeq = ++traceState.scanPathsSeq
    if (scanSeq <= 10) traceSig('raven_scan_paths_begin', { id: scanSeq, count: list.length })
    let arrPtr = null
    try {
      const arrType = koffi.array('string', list.length)
      arrPtr = koffi.alloc(arrType, list.length)
      koffi.encode(arrPtr, arrType, list)
    } catch (e) {
      arrPtr = null
      traceSig('raven_scan_paths_alloc_failed', { ...normalizeErrorPayload(e) })
      kvdSig.scanPathsBroken = true
      return null
    }
    const outStr = [null]
    const outLen = [0]
    const rc = kvdSig.scanPaths(kvdSig.handle, arrPtr, list.length, outStr, outLen)
    if (rc < 0) {
      if (!kvdSig.scanPathsFailedLogged) {
        kvdSig.scanPathsFailedLogged = true
        traceSig('raven_scan_paths_failed', { code: String(rc) })
      }
      kvdSig.scanPathsBroken = true
      return null
    }
    let json = '[]'
    try {
      const ptr = outStr[0]
      const len = outLen[0] | 0
      if (ptr && len > 0) {
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
        json = Buffer.from(bytes).toString('utf8') || '[]'
        try { kvdSig.free(ptr) } catch {}
      }
    } catch {}
    let parsed = []
    try {
      const obj = JSON.parse(json)
      parsed = Array.isArray(obj) ? obj : []
    } catch {
      parsed = []
    }
    const out = new Array(list.length)
    for (let i = 0; i < list.length; i++) {
      const sp = list[i]
      if (sp && verifyTrusted(sp)) {
        out[i] = { signature_verified: true, signature_hit: false, signature_score: 0, is_malware: false, confidence: 0, signature_reason: 'signature_trusted' }
      } else {
        const nativeRes = parsed[i] || {}
        out[i] = (nativeRes && typeof nativeRes === 'object') ? nativeRes : {}
      }
    }
    return out
  }

  function mergeScanResult(axonRes, sigRes) {
    const a = axonRes && typeof axonRes === 'object' ? axonRes : {}
    const s = sigRes && typeof sigRes === 'object' ? sigRes : {}
    const out = Object.assign({}, a)
    if (s.signature_hit !== undefined) out.signature_hit = s.signature_hit
    if (s.signature_score !== undefined) out.signature_score = s.signature_score
    if (s.signature_reason) out.signature_reason = s.signature_reason
    const aMal = a.is_malware === true
    const sMal = s.is_malware === true
    out.is_malware = aMal || sMal
    const aConf = Number.isFinite(a.confidence) ? a.confidence : 0
    const sConf = Number.isFinite(s.confidence) ? s.confidence : 0
    if (aMal || sMal) out.confidence = Math.max(aConf, sConf)
    if ((s.signature_hit === true || (Number.isFinite(s.signature_score) && s.signature_score > 0)) && out.error === 'signature_disabled') {
      delete out.error
    }
    return out
  }

  async function kvdTrainFromPath(samplePath, isWhite) {
    if (!ensureKvdHandle()) {
      const code = kvd.loadError || 'KVD_LOAD_FAILED'
      trace('kvd_train_failed', { code })
      throw new Error(code)
    }
    if (!kvd.trainFromPath) {
      trace('kvd_train_unsupported')
      throw new Error('KVD_TRAIN_UNSUPPORTED')
    }
    const sp = typeof samplePath === 'string' ? samplePath : ''
    if (!sp) {
      trace('kvd_train_invalid_path')
      throw new Error('INVALID_SAMPLE_PATH')
    }
    const name = path.basename(sp)
    if (!isLikelyPeFile(sp)) {
      trace('kvd_train_error_invalid_pe', { name })
      throw new Error('KVD_TRAIN_INVALID_PE')
    }
    trace('kvd_train_begin', { name, isWhite: isWhite === true })
    const outStr = [null]
    const outLen = [0]
    const flag = isWhite ? 0 : 1
    const rc = kvd.trainFromPath(kvd.handle, sp, flag, outStr, outLen)
    if (rc < 0) {
      trace('kvd_train_failed', { code: String(rc), name })
      throw new Error('KVD_TRAIN_FAILED')
    }
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
    let obj = {}
    try {
      obj = JSON.parse(json)
    } catch {
      obj = {}
    }
    const ok = obj && typeof obj === 'object' ? obj.ok === true : false
    trace('kvd_train_ok', { name, ok: ok === true, total: obj.total || 0, trained: obj.trained || 0, failed: obj.failed || 0 })
    return obj
  }

  async function kvdTrainFromPathSig(samplePath, isWhite, options) {
    if (!ensureSignatureHandle()) {
      const code = kvdSig.loadError || 'KVD_LOAD_FAILED'
      traceSig('raven_train_failed', { code })
      throw new Error(code)
    }
    if (!kvdSig.trainFromPath) {
      traceSig('raven_train_unsupported')
      throw new Error('KVD_TRAIN_UNSUPPORTED')
    }
    const sp = typeof samplePath === 'string' ? samplePath : ''
    if (!sp) {
      traceSig('raven_train_invalid_path')
      throw new Error('INVALID_SAMPLE_PATH')
    }
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const nativeTrainDisabled = scanner && scanner.signatureNativeTrainDisabled === true
    const name = path.basename(sp)
    const isPe = isLikelyPeFile(sp)
    if (!isPe) traceSig('raven_train_non_pe', { name })
    traceSig('raven_train_begin', { name, isWhite: isWhite === true })
    const outStr = [null]
    const outLen = [0]
    const flag = isWhite ? 0 : 1
    let obj = {}
    if (nativeTrainDisabled) {
      traceSig('raven_train_failed', { code: 'NATIVE_TRAIN_DISABLED', name })
      throw new Error('NATIVE_TRAIN_DISABLED')
    }
    const rc = kvdSig.trainFromPath(kvdSig.handle, sp, flag, outStr, outLen)
    if (rc < 0) {
      traceSig('raven_train_failed', { code: String(rc), name })
      throw new Error('KVD_TRAIN_FAILED')
    }
    let json = '{}'
    try {
      const ptr = outStr[0]
      const len = outLen[0] | 0
      if (ptr && len > 0) {
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
        json = Buffer.from(bytes).toString('utf8') || '{}'
        try { kvdSig.free(ptr) } catch {}
      }
    } catch {}
    try {
      obj = JSON.parse(json)
    } catch {
      obj = {}
    }
    const ok = obj && typeof obj === 'object' ? obj.ok === true : false
    traceSig('raven_train_ok', { name, ok: ok === true, total: obj.total || 0, trained: obj.trained || 0, failed: obj.failed || 0 })
    if (!ok) throw new Error('KVD_TRAIN_FAILED')
    return obj
  }

  async function kvdTrainPathsSig(filePaths, isWhite) {
    if (!ensureSignatureHandle()) throw new Error('KVD_LOAD_FAILED')
    const list = Array.isArray(filePaths) ? filePaths.filter(p => typeof p === 'string' && p) : []
    if (!list.length) return { ok: false, total: 0, trained: 0, failed: 0 }
    if (!kvdSig.trainPaths) {
      const out = { ok: false, total: 0, trained: 0, failed: 0 }
      for (const p of list) {
        try {
          const r = await kvdTrainFromPathSig(p, isWhite)
          if (r && r.ok) {
            out.total += 1
            out.trained += 1
          } else {
            out.total += 1
            out.failed += 1
          }
        } catch {
          out.total += 1
          out.failed += 1
        }
      }
      out.ok = out.trained > 0
      return out
    }
    let arrPtr = null
    try {
      const arrType = koffi.array('string', list.length)
      arrPtr = koffi.alloc(arrType, list.length)
      koffi.encode(arrPtr, arrType, list)
    } catch {
      throw new Error('KVD_TRAIN_FAILED')
    }
    const outStr = [null]
    const outLen = [0]
    const flag = isWhite ? 0 : 1
    const rc = kvdSig.trainPaths(kvdSig.handle, arrPtr, list.length, flag, outStr, outLen)
    if (rc < 0) throw new Error('KVD_TRAIN_FAILED')
    let json = '{}'
    try {
      const ptr = outStr[0]
      const len = outLen[0] | 0
      if (ptr && len > 0) {
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
        json = Buffer.from(bytes).toString('utf8') || '{}'
        try { kvdSig.free(ptr) } catch {}
      }
    } catch {}
    let obj = {}
    try { obj = JSON.parse(json) } catch { obj = {} }
    try { if (kvdSig.flush) kvdSig.flush(kvdSig.handle) } catch {}
    const ok = obj && typeof obj === 'object' ? obj.ok === true : false
    if (!ok) throw new Error('KVD_TRAIN_FAILED')
    return obj
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
    try {
      return kvdHealth(requestId)
    } catch (e) {
      const code = e && e.code ? String(e.code) : (kvd && kvd.loadError ? String(kvd.loadError) : '')
      const message = e && e.message ? String(e.message) : 'OFFLINE'
      return { ok: false, status: 'offline', code, message }
    }
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
      const out = new Array(fps.length)
      let axonArr = null
      let sigArr = null
      try { sigArr = await kvdScanPathsSig(fps) } catch { sigArr = null }
      const sigOk = Array.isArray(sigArr) && sigArr.length === fps.length
      if (sigOk) {
        for (let i = 0; i < fps.length; i++) {
          const s = sigArr[i] || {}
          const sigReason = (s && typeof s.signature_reason === 'string') ? String(s.signature_reason) : ''
          const weightReason = sigReason.includes('api_weight') || sigReason.includes('script_weight')
          if (s && (s.is_malware === true || s.signature_hit === true || (!weightReason && Number.isFinite(s.signature_score) && s.signature_score >= 0.92))) {
            out[i] = mergeScanResult({}, s)
          } else {
            out[i] = null
          }
        }
      }
      const needAxonIdx = []
      for (let i = 0; i < fps.length; i++) {
        if (out[i] == null) needAxonIdx.push(i)
      }
      if (needAxonIdx.length === 0) return out
      const needAxonPaths = needAxonIdx.map(i => fps[i])
      try { axonArr = await kvdScanPaths(needAxonPaths) } catch { axonArr = null }
      const axonOk = Array.isArray(axonArr) && axonArr.length === needAxonPaths.length
      if (axonOk && sigOk) {
        for (let j = 0; j < needAxonIdx.length; j++) {
          const i = needAxonIdx[j]
          const a = axonArr[j] || {}
          const s = sigArr[i] || {}
          out[i] = mergeScanResult(a, s)
        }
        return out
      }
      if (sigOk && !axonOk) {
        for (let j = 0; j < needAxonIdx.length; j++) {
          const i = needAxonIdx[j]
          let a = {}
          try { a = await kvdScanFile(needAxonPaths[j]) } catch {}
          const s = sigArr[i] || {}
          out[i] = mergeScanResult(a, s)
        }
        return out
      }
      if (!sigOk && axonOk) {
        for (let j = 0; j < needAxonIdx.length; j++) {
          const i = needAxonIdx[j]
          const a = axonArr[j] || {}
          let s = {}
          try { s = await kvdScanFileSig(fps[i]) } catch { s = {} }
          out[i] = mergeScanResult(a, s)
        }
        return out
      }
      for (let i = 0; i < fps.length; i++) {
        if (out[i] != null) continue
        let a = {}
        let s = {}
        try { s = await kvdScanFileSig(fps[i]) } catch {}
        const sigReason = (s && typeof s.signature_reason === 'string') ? String(s.signature_reason) : ''
        const weightReason = sigReason.includes('api_weight') || sigReason.includes('script_weight')
        if (s && (s.is_malware === true || s.signature_hit === true || (!weightReason && Number.isFinite(s.signature_score) && s.signature_score >= 0.92))) {
          out[i] = mergeScanResult({}, s)
          continue
        }
        try { a = await kvdScanFile(fps[i]) } catch {}
        out[i] = mergeScanResult(a, s)
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
    return { ok: true }
  }

  async function trainFromPath(samplePath, isWhite, options) {
    try {
      return await kvdTrainFromPathSig(samplePath, isWhite, options)
    } catch (e) {
      const msg = e && e.message ? String(e.message) : ''
      trace('kvd_sig_train_failed', { error: msg, stack: e.stack || '' })
      throw e
    }
  }

  async function trainPaths(filePaths, isWhite) {
    try {
      return await kvdTrainPathsSig(filePaths, isWhite)
    } catch (e) {
      const msg = e && e.message ? String(e.message) : ''
      trace('kvd_sig_train_failed', { error: msg, stack: e.stack || '' })
      throw e
    }
  }

  const signatureWriteQueue = []
  let signatureWriteBusy = false

  function processSignatureWriteQueue() {
    if (signatureWriteBusy) return
    signatureWriteBusy = true
    while (signatureWriteQueue.length) {
      const task = signatureWriteQueue.shift()
      const res = persistSignatureStore(task.result, task.features, task.meta, task.isWhite)
      try { task.resolve(res) } catch {}
    }
    signatureWriteBusy = false
  }

  function queueSignatureStoreWrite(result, features, meta, isWhite) {
    return new Promise((resolve) => {
      signatureWriteQueue.push({ result, features, meta, isWhite, resolve })
      processSignatureWriteQueue()
    })
  }

  function listSignatureStoreVersions() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const indexPath = resolveSignatureIndexPath(scanner)
    let index = readSignatureIndex(indexPath)
    if (!index) {
      const storePath = resolveSignatureStorePath(scanner)
      if (!storePath) return []
      index = rebuildSignatureIndex(storePath, indexPath)
    }
    return index && Array.isArray(index.versions) ? index.versions : []
  }

  function getSignatureStoreCurrentVersion() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const indexPath = resolveSignatureIndexPath(scanner)
    let index = readSignatureIndex(indexPath)
    if (!index) {
      const storePath = resolveSignatureStorePath(scanner)
      if (!storePath) return ''
      index = rebuildSignatureIndex(storePath, indexPath)
    }
    return index && typeof index.current_version_id === 'string' ? index.current_version_id : ''
  }

  function rollbackSignatureStore(versionId) {
    const id = typeof versionId === 'string' ? versionId : ''
    if (!id) return false
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const storePath = resolveSignatureStorePath(scanner)
    const indexPath = resolveSignatureIndexPath(scanner)
    if (!storePath) return false
    let index = readSignatureIndex(indexPath)
    if (!index) index = rebuildSignatureIndex(storePath, indexPath)
    if (!index || !Array.isArray(index.versions)) return false
    const exists = index.versions.find(v => v && v.id === id)
    if (!exists) return false
    index.current_version_id = id
    return writeSignatureIndex(indexPath, index)
  }

  return {
    health,
    scanFile,
    scanBatch,
    control,
    abort,
    trainFromPath,
    trainPaths,
    signatureStore: {
      append: persistSignatureStore,
      queueAppend: queueSignatureStoreWrite,
      listVersions: listSignatureStoreVersions,
      getCurrentVersion: getSignatureStoreCurrentVersion,
      rollback: rollbackSignatureStore,
      loadCurrent: loadSignatureStore
    }
  }
}

module.exports = { createScannerClient }
