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
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Axon', 'axon_engine.dll'))
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Axon', 'kvd.dll'))
      }
    } catch {}
    try {
      candidates.push(path.join(__dirname, '../../Engine/Axon/axon_engine.dll'))
      candidates.push(path.join(__dirname, '../../Engine/Axon/kvd.dll'))
    } catch {}
    try {
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
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Raven', 'raven_engine.dll'))
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Signature', 'signature_engine.dll'))
      }
    } catch {}
    try {
      candidates.push(path.join(__dirname, '../../Engine/Raven/raven_engine.dll'))
      candidates.push(path.join(__dirname, '../../Engine/Signature/signature_engine.dll'))
    } catch {}
    try {
      candidates.push(path.join(process.cwd(), 'Engine', 'Raven', 'raven_engine.dll'))
      candidates.push(path.join(process.cwd(), 'Engine', 'Signature', 'signature_engine.dll'))
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
      return { version: 3, updated_at: Date.now(), signatures: [], api_stats: {}, api_sequences: {}, fuzzy_stats: {} }
    }
    if (!Array.isArray(store.signatures)) store.signatures = []
    if (!store.api_stats || typeof store.api_stats !== 'object') store.api_stats = {}
    if (!store.api_sequences || typeof store.api_sequences !== 'object') store.api_sequences = {}
    if (!store.fuzzy_stats || typeof store.fuzzy_stats !== 'object') store.fuzzy_stats = {}
    store.version = 3
    return store
  }

  function updateApiStats(store, apis, isWhite) {
    if (!Array.isArray(apis) || !apis.length) return
    for (const api of apis) {
      const key = typeof api === 'string' ? api.toLowerCase() : ''
      if (!key) continue
      const cur = store.api_stats[key] || { mal: 0, white: 0 }
      if (isWhite) cur.white += 1
      else cur.mal += 1
      store.api_stats[key] = cur
    }
  }

  function updateSequenceStats(store, seq, isWhite) {
    if (!Array.isArray(seq) || seq.length < 3) return
    const key = seq.join('>')
    if (!key) return
    const cur = store.api_sequences[key] || { mal: 0, white: 0 }
    if (isWhite) cur.white += 1
    else cur.mal += 1
    store.api_sequences[key] = cur
  }

  function updateFuzzyStats(store, hashes, isWhite) {
    if (!Array.isArray(hashes) || !hashes.length) return
    const key = hashes.join('.')
    if (!key) return
    const cur = store.fuzzy_stats[key] || { mal: 0, white: 0 }
    if (isWhite) cur.white += 1
    else cur.mal += 1
    store.fuzzy_stats[key] = cur
  }

  function sleepSync(ms) {
    try {
      const sab = new SharedArrayBuffer(4)
      const i32 = new Int32Array(sab)
      Atomics.wait(i32, 0, 0, ms)
    } catch {}
  }

  function readSignatureStoreFromFile(storePath) {
    try {
      const raw = fs.readFileSync(storePath, 'utf8')
      const text = raw ? String(raw).trim() : ''
      if (!text) return ensureSignatureStoreShape(null)
      if (text[0] === '{') {
        try {
          const parsed = JSON.parse(text)
          return ensureSignatureStoreShape(parsed)
        } catch {}
      }
      const lines = text.split(/\r?\n/)
      for (let i = lines.length - 1; i >= 0; i--) {
        const line = lines[i].trim()
        if (!line) continue
        try {
          const parsed = JSON.parse(line)
          return ensureSignatureStoreShape(parsed)
        } catch {}
      }
      return ensureSignatureStoreShape(null)
    } catch {
      return ensureSignatureStoreShape(null)
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

  function persistSignatureStore(result, features, meta, isWhite) {
    try {
      const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
      const scanner = cfg && cfg.scanner ? cfg.scanner : {}
      const storePath = resolveSignatureStorePath(scanner)
      if (!storePath) return false
      return withSignatureStoreLock(storePath, () => {
        const store = readSignatureStoreFromFile(storePath)
        const payload = buildSignatureFeaturePayload(result, features, meta)
        const code = makeFeatureCode(payload.features)
        if (!code) return false
        updateApiStats(store, payload.features.apis, isWhite)
        updateSequenceStats(store, payload.features.api_seq, isWhite)
        updateFuzzyStats(store, payload.features.fuzzy, isWhite)
        if (!isWhite) {
          const existing = store.signatures.find(s => s && s.code === code)
          if (!existing) {
            store.signatures.push({ code, features: payload.features, meta: payload.meta, ts: Date.now() })
          } else {
            existing.features = payload.features
            existing.meta = payload.meta
            existing.ts = Date.now()
          }
        }
        store.updated_at = Date.now()
        fs.appendFileSync(storePath, JSON.stringify(store) + '\n')
        return true
      })
    } catch {
      return false
    }
  }

  function loadSignatureStore() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const storePath = resolveSignatureStorePath(scanner)
    if (!storePath) return null
    return readSignatureStoreFromFile(storePath)
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
    const storePath = resolveSignatureStorePath(scanner)
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
    const preRes = scanRavenByStore(filePath)
    if (preRes.signature_verified === true) return preRes
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
    const jsRes = scanRavenByStore(filePath)
    return mergeSignatureResult(nativeRes, jsRes)
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
    const store = loadSignatureStore()
    const out = new Array(list.length)
    for (let i = 0; i < list.length; i++) {
      const nativeRes = parsed[i] || {}
      const jsRes = scanRavenByStore(list[i], store)
      out[i] = jsRes.signature_verified === true ? jsRes : mergeSignatureResult(nativeRes, jsRes)
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
    const flag = isWhite ? 1 : 0
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

  async function kvdTrainFromPathSig(samplePath, isWhite) {
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
    const name = path.basename(sp)
    if (!isLikelyPeFile(sp)) {
      traceSig('raven_train_non_pe', { name })
    }
    traceSig('raven_train_begin', { name, isWhite: isWhite === true })
    const outStr = [null]
    const outLen = [0]
    const flag = isWhite ? 1 : 0
    let nativeOk = false
    let nativeError = ''
    let obj = {}
    const rc = kvdSig.trainFromPath(kvdSig.handle, sp, flag, outStr, outLen)
    if (rc < 0) {
      nativeError = String(rc)
      traceSig('raven_train_failed', { code: nativeError, name })
    } else {
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
      nativeOk = obj && typeof obj === 'object' ? obj.ok === true : false
    }
    const extracted = extractRavenFeatures(sp)
    const persisted = persistSignatureStore(obj, extracted.features, extracted.meta, isWhite === true)
    if (!nativeOk && persisted) {
      obj = { ok: true, total: 1, trained: 1, failed: 0, raven_fallback: true, raven_error: nativeError }
    }
    const ok = obj && typeof obj === 'object' ? obj.ok === true : false
    traceSig('raven_train_ok', { name, ok: ok === true, total: obj.total || 0, trained: obj.trained || 0, failed: obj.failed || 0 })
    if (!ok && !persisted) throw new Error('KVD_TRAIN_FAILED')
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
      try { axonArr = await kvdScanPaths(fps) } catch { axonArr = null }
      try { sigArr = await kvdScanPathsSig(fps) } catch { sigArr = null }
      if (Array.isArray(axonArr) || Array.isArray(sigArr)) {
        const store = loadSignatureStore()
        for (let i = 0; i < fps.length; i++) {
          const a = Array.isArray(axonArr) ? (axonArr[i] || {}) : {}
          let s = Array.isArray(sigArr) ? (sigArr[i] || {}) : {}
          if (!s || s.signature_hit !== true) {
            const jsRes = scanRavenByStore(fps[i], store)
            if (jsRes && jsRes.signature_hit !== undefined) {
              s = jsRes.signature_verified === true ? jsRes : mergeSignatureResult(s, jsRes)
            }
          }
          out[i] = mergeScanResult(a, s)
        }
        return out
      }
      for (let i = 0; i < fps.length; i++) {
        let a = {}
        let s = {}
        try { a = await kvdScanFile(fps[i]) } catch {}
        try { s = await kvdScanFileSig(fps[i]) } catch {}
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

  async function trainFromPath(samplePath, isWhite) {
    try {
      return await kvdTrainFromPathSig(samplePath, isWhite)
    } catch (e) {
      const msg = e && e.message ? String(e.message) : ''
      trace('kvd_sig_train_failed', { error: msg, stack: e.stack || '' })
      throw e
    }
  }

  return { health, scanFile, scanBatch, control, abort, trainFromPath }
}

module.exports = { createScannerClient }
