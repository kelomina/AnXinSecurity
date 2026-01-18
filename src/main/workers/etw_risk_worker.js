const { parentPort } = require('worker_threads')
const path = require('path')
const fs = require('fs')
const { createScannerClient } = require('../scanner_client')

let winapi = null
try { winapi = require('../winapi') } catch { winapi = null }

let cfg = {
  appDirLower: '',
  systemRootDirLower: ((process.env.SystemRoot || 'C:\\Windows') + '\\').toLowerCase().replace(/\//g, '\\'),
  scanner: null,
  scan: null
}

function postMessage(msg) {
  if (!parentPort) return
  parentPort.postMessage(msg)
}

function normalizeLowerPath(p) {
  if (typeof p !== 'string') return ''
  return p.trim().toLowerCase().replace(/\//g, '\\')
}

function normalizeLowerDir(p) {
  let s = normalizeLowerPath(p)
  if (s && !s.endsWith('\\')) s += '\\'
  return s
}

function isUnderDir(lowerPath, lowerDir) {
  if (!lowerPath || !lowerDir) return false
  return lowerPath.startsWith(lowerDir)
}

function shouldSkipAppDir(p) {
  const lower = normalizeLowerPath(p || '')
  return !!(lower && cfg.appDirLower && isUnderDir(lower, cfg.appDirLower))
}

const scannerClient = createScannerClient(() => ({ scanner: cfg.scanner || {}, scan: cfg.scan || {} }))

function isMalware(res) {
  if (!res || typeof res !== 'object') return false
  if (res.infected === true) return true
  if (res.is_malware === true) return true
  if (res.malicious === true) return true
  return false
}

async function scanFileWithHashCache(filePath, requestIdPrefix) {
  const p = typeof filePath === 'string' ? filePath : ''
  if (!p) return { ok: false, skipped: true }
  if (!scannerClient || typeof scannerClient.scanFile !== 'function') return { ok: false, skipped: true }
  if (!winapi || typeof winapi.scanCacheLookupByFile !== 'function' || typeof winapi.scanCacheStore !== 'function') return { ok: false, skipped: true }

  const scanCfg = cfg.scan && typeof cfg.scan === 'object' ? cfg.scan : {}
  const onlyCommonExt = scanCfg.commonExtensionsOnly === true
  const ext = path.extname(p).toLowerCase()
  if (onlyCommonExt && ext !== '.exe' && ext !== '.dll') return { ok: false, skipped: true }

  const sc = cfg.scanner && typeof cfg.scanner === 'object' ? cfg.scanner : {}
  const maxMB = Number.isFinite(sc.maxFileSizeMB) ? Math.max(1, Math.floor(sc.maxFileSizeMB)) : 500
  try {
    const st = fs.statSync(p)
    if (st && st.size > maxMB * 1024 * 1024) return { ok: false, skipped: true, tooLarge: true }
  } catch {}

  let lookup = null
  try { lookup = winapi.scanCacheLookupByFile(p) } catch { lookup = null }
  if (lookup && lookup.hit === true) {
    return { ok: true, cached: true, verdict: lookup.verdict, hash: lookup.hash, malware: lookup.verdict === 2 }
  }

  const rid = `${requestIdPrefix || 'etw_scan'}_${Date.now()}_${Math.random().toString(16).slice(2)}`
  const res = await scannerClient.scanFile(p, rid)
  const malware = isMalware(res)
  const verdict = malware ? 2 : 1
  const hash = lookup && typeof lookup.hash === 'string' ? lookup.hash : null
  if (hash) {
    try { winapi.scanCacheStore(hash, verdict) } catch {}
  }
  return { ok: true, cached: false, verdict, hash, malware, res }
}

async function handleProcessStart(job) {
  const pid = Number.isFinite(job && job.pid) ? job.pid : parseInt(String(job && job.pid), 10)
  const imagePath = typeof (job && job.imagePath) === 'string' ? job.imagePath : ''
  if (!Number.isFinite(pid) || pid <= 0) return
  if (!imagePath) return
  if (!winapi || typeof winapi.verifyTrust !== 'function') return
  if (shouldSkipAppDir(imagePath)) return

  const lowerImg = normalizeLowerPath(imagePath)
  let procSigned = false
  try { procSigned = winapi.verifyTrust(imagePath) === true } catch { procSigned = false }
  if (procSigned && isUnderDir(lowerImg, cfg.systemRootDirLower)) return

  const unsignedTargets = []
  if (!procSigned) unsignedTargets.push(imagePath)

  await new Promise((r) => setTimeout(r, 350))
  const bufBytes = Number.isFinite(job && job.modulesBufferBytes) ? Math.max(4096, Math.min(1024 * 1024, Math.floor(job.modulesBufferBytes))) : 262144
  let mods = []
  try { mods = winapi.getProcessModules(pid, bufBytes) } catch { mods = [] }
  const arr = Array.isArray(mods) ? mods : []
  for (const mp0 of arr) {
    const mp = typeof mp0 === 'string' ? mp0 : ''
    if (!mp) continue
    const lower = normalizeLowerPath(mp)
    if (!lower.endsWith('.dll')) continue
    if (shouldSkipAppDir(lower)) continue
    let ok = false
    try { ok = winapi.verifyTrust(mp) === true } catch { ok = false }
    if (ok) continue
    unsignedTargets.push(mp)
    if (unsignedTargets.length >= 16) break
  }

  if (!unsignedTargets.length) return
  let malwareHit = null
  for (const target of unsignedTargets) {
    const r = await scanFileWithHashCache(target, 'etw_procstart')
    if (r && r.ok && r.malware) {
      malwareHit = { path: target, verdict: r.verdict, hash: r.hash || null, res: r.res || null }
      break
    }
  }
  if (!malwareHit) return

  let paused = false
  if (winapi && typeof winapi.suspendProcessByPid === 'function') {
    try { paused = winapi.suspendProcessByPid(pid) === true } catch { paused = false }
  }
  postMessage({
    type: 'risk_payload',
    payload: {
      pid,
      paused,
      triggeredAt: Date.now(),
      threatType: '进程启动签名异常',
      severity: 5,
      recommendAction: 'block',
      match: { ruleId: 'process_start_signature_scan', provider: 'Process', op: 'Start', target: imagePath },
      process: { name: typeof job.processName === 'string' ? job.processName : '', imagePath },
      event: { provider: 'Process', data: { type: 'ProcessStartSignature', processSigned: procSigned, unsignedTargets, malwareHit } }
    }
  })
}

async function handleFileEvent(job) {
  const pid = Number.isFinite(job && job.pid) ? job.pid : parseInt(String(job && job.pid), 10)
  const filePath = typeof (job && job.filePath) === 'string' ? job.filePath : ''
  const op = typeof (job && job.op) === 'string' ? job.op : ''
  const actorImage = typeof (job && job.actorImage) === 'string' ? job.actorImage : ''
  if (!Number.isFinite(pid) || pid <= 0) return
  if (!filePath) return
  if (!winapi || typeof winapi.verifyTrust !== 'function') return
  if (shouldSkipAppDir(filePath)) return
  if (actorImage && shouldSkipAppDir(actorImage)) return

  const actorLower = normalizeLowerPath(actorImage)
  if (actorLower && isUnderDir(actorLower, cfg.systemRootDirLower)) {
    let ok = false
    try { ok = winapi.verifyTrust(actorImage) === true } catch { ok = false }
    if (ok) return
  }

  let fileSigned = false
  try { fileSigned = winapi.verifyTrust(filePath) === true } catch { fileSigned = false }
  if (fileSigned) return

  const scan = await scanFileWithHashCache(filePath, 'etw_file')
  if (!(scan && scan.ok && scan.malware)) return

  let paused = false
  if (winapi && typeof winapi.suspendProcessByPid === 'function') {
    try { paused = winapi.suspendProcessByPid(pid) === true } catch { paused = false }
  }
  postMessage({
    type: 'risk_payload',
    payload: {
      pid,
      paused,
      triggeredAt: Date.now(),
      threatType: '文件操作签名异常',
      severity: 5,
      recommendAction: 'block',
      match: { ruleId: 'file_event_signature_scan', provider: 'File', op, target: filePath },
      process: { name: typeof job.processName === 'string' ? job.processName : '', imagePath: actorImage },
      event: { provider: 'File', data: { type: 'FileSignature', op, filePath, malwareHit: { verdict: scan.verdict, hash: scan.hash || null, res: scan.res || null } } }
    }
  })
}

async function handleRuleMatch(job) {
  const pid = Number.isFinite(job && job.pid) ? job.pid : parseInt(String(job && job.pid), 10)
  const imagePath = typeof (job && job.imagePath) === 'string' ? job.imagePath : ''
  const scanPath = typeof (job && job.scanPath) === 'string' ? job.scanPath : ''
  const provider = typeof (job && job.provider) === 'string' ? job.provider : ''
  const op = typeof (job && job.op) === 'string' ? job.op : ''
  const ruleId = typeof (job && job.ruleId) === 'string' ? job.ruleId : ''
  const threatType = typeof (job && job.threatType) === 'string' ? job.threatType : ''
  const severity = Number.isFinite(job && job.severity) ? job.severity : parseInt(String(job && job.severity), 10)
  const recommendAction = typeof (job && job.recommendAction) === 'string' ? job.recommendAction : 'block'
  if (!Number.isFinite(pid) || pid <= 0) return
  if (!scanPath) return
  if (!winapi || typeof winapi.verifyTrust !== 'function') return
  if (imagePath && shouldSkipAppDir(imagePath)) return
  if (shouldSkipAppDir(scanPath)) return

  const actorLower = normalizeLowerPath(imagePath)
  if (actorLower && isUnderDir(actorLower, cfg.systemRootDirLower)) {
    let ok = false
    try { ok = winapi.verifyTrust(imagePath) === true } catch { ok = false }
    if (ok) return
  }

  let signed = false
  try { signed = winapi.verifyTrust(scanPath) === true } catch { signed = false }
  if (signed) return

  const scan = await scanFileWithHashCache(scanPath, 'etw_match')
  if (!(scan && scan.ok && scan.malware)) return

  let paused = false
  if (recommendAction !== 'allow' && winapi && typeof winapi.suspendProcessByPid === 'function') {
    try { paused = winapi.suspendProcessByPid(pid) === true } catch { paused = false }
  }
  postMessage({
    type: 'risk_payload',
    payload: {
      pid,
      paused,
      triggeredAt: Date.now(),
      threatType: threatType || ruleId || 'ETW_MATCH',
      severity: Number.isFinite(severity) ? severity : 4,
      recommendAction,
      match: { ruleId: ruleId || 'ETW_MATCH', provider, op, target: scanPath },
      process: { name: typeof job.processName === 'string' ? job.processName : '', imagePath },
      event: { provider, data: { type: 'RuleMatchScan', match: job.match || null, scanPath, malwareHit: { verdict: scan.verdict, hash: scan.hash || null, res: scan.res || null } } },
      context: Array.isArray(job.context) ? job.context : []
    }
  })
}

const queue = []
let busy = false
const keys = new Set()

function enqueue(key, fn) {
  const k = typeof key === 'string' ? key : ''
  if (!k) return
  if (keys.has(k)) return
  keys.add(k)
  queue.push(async () => {
    try { await fn() } catch {}
    keys.delete(k)
  })
  setImmediate(pump)
}

async function pump() {
  if (busy) return
  busy = true
  try {
    while (queue.length) {
      const job = queue.shift()
      if (job) await job()
    }
  } finally {
    busy = false
  }
}

if (parentPort) {
  parentPort.on('message', (msg) => {
    const m = msg && typeof msg === 'object' ? msg : {}
    if (m.type === 'config') {
      const appDir = typeof m.appDir === 'string' ? m.appDir : ''
      cfg.appDirLower = normalizeLowerDir(appDir)
      const sr = typeof m.systemRoot === 'string' ? m.systemRoot : (process.env.SystemRoot || 'C:\\Windows')
      cfg.systemRootDirLower = normalizeLowerDir(sr)
      cfg.scanner = m.scanner && typeof m.scanner === 'object' ? m.scanner : null
      cfg.scan = m.scan && typeof m.scan === 'object' ? m.scan : null
      return
    }
    if (m.type === 'process_start') {
      const pid = Number.isFinite(m.pid) ? m.pid : parseInt(String(m.pid), 10)
      enqueue(`procstart:${pid}`, () => handleProcessStart(m))
      return
    }
    if (m.type === 'file_event') {
      const pid = Number.isFinite(m.pid) ? m.pid : parseInt(String(m.pid), 10)
      const fp = typeof m.filePath === 'string' ? m.filePath : ''
      enqueue(`file:${pid}:${m.op}:${fp}`, () => handleFileEvent(m))
      return
    }
    if (m.type === 'rule_match') {
      const pid = Number.isFinite(m.pid) ? m.pid : parseInt(String(m.pid), 10)
      const sp = typeof m.scanPath === 'string' ? m.scanPath : ''
      enqueue(`match:${pid}:${m.ruleId}:${sp}`, () => handleRuleMatch(m))
    }
  })
}
