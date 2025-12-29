const { parentPort } = require('worker_threads')

const scanCache = new Map()

let winapi = null
try {
  winapi = require('../winapi')
} catch {}

let scanInFlight = false

function postMessage(payload) {
  if (!parentPort) return
  try { parentPort.postMessage(payload) } catch {}
}

function sleepImmediate() {
  return new Promise((resolve) => {
    try { setImmediate(resolve) } catch { resolve() }
  })
}

function asBool(v, def) {
  if (v === true) return true
  if (v === false) return false
  return def === true
}

function asInt(v, def, min, max) {
  const n = Number.isFinite(v) ? v : parseInt(String(v), 10)
  if (!Number.isFinite(n)) return def
  const x = Math.floor(n)
  if (Number.isFinite(min)) return Math.min(Number.isFinite(max) ? max : x, Math.max(min, x))
  if (Number.isFinite(max)) return Math.min(max, x)
  return x
}

function resolveConfig(cfg) {
  const c = cfg && typeof cfg === 'object' ? cfg : {}
  return {
    maxPids: asInt(c.maxPids, 8192, 256, 65536),
    modulesBufferBytes: asInt(c.modulesBufferBytes, 65536, 4096, 1024 * 1024),
    skipSystemDll: asBool(c.skipSystemDll, true),
    maxUnsignedDllsPerProcess: asInt(c.maxUnsignedDllsPerProcess, 16, 1, 256),
    exclusionPaths: Array.isArray(c.exclusionPaths) ? c.exclusionPaths.filter(x => typeof x === 'string' && x) : []
  }
}

async function scanSnapshot(cfg) {
  if (scanInFlight) return
  scanInFlight = true
  try {
    if (!winapi) return
    if (typeof winapi.getProcessImageSnapshot !== 'function') return
    if (typeof winapi.getProcessModules !== 'function') return
    if (typeof winapi.verifyTrust !== 'function') return
    if (typeof winapi.suspendProcessByPid !== 'function') return

    const conf = resolveConfig(cfg)
    const systemRootLower = String(process.env.SystemRoot || 'C:\\Windows').toLowerCase()
    const exclusions = conf.exclusionPaths.map(p => {
      let s = p.toLowerCase()
      s = s.replace(/\//g, '\\')
      if (!s.endsWith('\\')) s += '\\'
      return s
    })

    let list = []
    try { list = winapi.getProcessImageSnapshot(conf.maxPids) } catch { list = [] }
    const arr = Array.isArray(list) ? list : []

    const hasDeviceResolver = typeof winapi.devicePathToDosPath === 'function'

    for (let i = 0; i < arr.length; i++) {
      const it = arr[i] && typeof arr[i] === 'object' ? arr[i] : null
      const pid = Number.isFinite(it && it.pid) ? it.pid : parseInt(String(it && it.pid), 10)
      if (!Number.isFinite(pid) || pid <= 0) continue
      let imagePath = typeof it.imagePath === 'string' ? it.imagePath : ''
      if (!imagePath) continue

      if (hasDeviceResolver && imagePath.startsWith('\\') && !imagePath.startsWith('\\\\')) {
        try {
          const dos = winapi.devicePathToDosPath(imagePath)
          if (dos) imagePath = dos
        } catch {}
      }

      const lowerImage = imagePath.toLowerCase().replace(/\//g, '\\')
      let isExcluded = false
      for (const ex of exclusions) {
        if (lowerImage.startsWith(ex)) {
          isExcluded = true
          break
        }
      }
      if (isExcluded) continue

      try {
        const modules = winapi.getProcessModules(pid, conf.modulesBufferBytes)
        const modArr = Array.isArray(modules) ? modules : []
        const unsignedDlls = []
        for (let j = 0; j < modArr.length; j++) {
          const p = typeof modArr[j] === 'string' ? modArr[j] : ''
          if (!p) continue
          const lower = p.toLowerCase()
          if (!lower.endsWith('.dll')) continue
          if (conf.skipSystemDll && lower.startsWith(systemRootLower)) continue
          
          if (scanCache.get(lower) === true) continue
          
          let ok = false
          try { ok = winapi.verifyTrust(p) === true } catch { ok = false }
          
          if (ok) {
            scanCache.set(lower, true)
          } else {
            unsignedDlls.push(p)
            if (unsignedDlls.length >= conf.maxUnsignedDllsPerProcess) break
          }
        }
        if (unsignedDlls.length) {
        const paused = false
        postMessage({ type: 'paused', pid, imagePath, paused, unsignedDlls })
      } else {
        let processSigned = false
        try { processSigned = winapi.verifyTrust(imagePath) === true } catch {}
        if (processSigned) {
             scanCache.set(lowerImage, true)
        }
      }
      } catch {}
      if (i % 30 === 0) await sleepImmediate()
    }
  } finally {
    scanInFlight = false
    postMessage({ type: 'scan_done' })
  }
}

async function resumeMany(requestId, pids) {
  const rid = typeof requestId === 'string' ? requestId : ''
  const list = Array.isArray(pids) ? pids : []
  const ids = list.map(x => (Number.isFinite(x) ? x : parseInt(String(x), 10))).filter(x => Number.isFinite(x) && x > 0)
  if (!rid) return
  if (!winapi || typeof winapi.resumeProcessByPid !== 'function') {
    postMessage({ type: 'resume_many_done', requestId: rid, ok: false, error: 'NO_WINAPI' })
    return
  }
  let resumed = 0
  for (let i = 0; i < ids.length; i++) {
    const pid = ids[i]
    try {
      const ok = winapi.resumeProcessByPid(pid) === true
      if (ok) resumed++
    } catch {}
    if (i % 50 === 0) await sleepImmediate()
  }
  postMessage({ type: 'resume_many_done', requestId: rid, ok: true, total: ids.length, resumed })
}

async function pidSnapshot(requestId, maxPids) {
  const rid = typeof requestId === 'string' ? requestId : ''
  if (!rid) return
  if (!winapi || typeof winapi.getProcessImageSnapshot !== 'function') {
    postMessage({ type: 'pid_snapshot_done', requestId: rid, ok: false, error: 'NO_WINAPI' })
    return
  }
  const max = asInt(maxPids, 8192, 256, 65536)
  let list = []
  try { list = winapi.getProcessImageSnapshot(max) } catch { list = [] }
  const arr = Array.isArray(list) ? list : []
  postMessage({ type: 'pid_snapshot_done', requestId: rid, ok: true, list: arr })
}

if (parentPort) {
  parentPort.on('message', (msg) => {
    const m = msg && typeof msg === 'object' ? msg : null
    const typ = m && typeof m.type === 'string' ? m.type : ''
    if (typ === 'scan') {
      scanSnapshot(m.config).catch(() => {})
      return
    }
    if (typ === 'resume_many') {
      resumeMany(m.requestId, m.pids).catch(() => postMessage({ type: 'resume_many_done', requestId: m && m.requestId ? String(m.requestId) : '', ok: false }))
      return
    }
    if (typ === 'pid_snapshot') {
      pidSnapshot(m.requestId, m.maxPids).catch(() => postMessage({ type: 'pid_snapshot_done', requestId: m && m.requestId ? String(m.requestId) : '', ok: false }))
      return
    }
    if (typ === 'allow_dlls') {
      const list = Array.isArray(m.paths) ? m.paths : []
      for (const p of list) {
        if (typeof p === 'string' && p) {
          scanCache.set(p.toLowerCase(), true)
        }
      }
    }
  })
}
