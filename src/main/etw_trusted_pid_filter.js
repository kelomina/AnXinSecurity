const fs = require('fs')
const { sanitizeText, isCleanText } = require('./utils')

function asPid(v) {
  const n = typeof v === 'number' ? v : parseInt(String(v), 10)
  if (!Number.isFinite(n) || n < 0) return null
  return n
}

function createEtwTrustedPidFilter(deps = {}) {
  const verifyTrust = typeof deps.verifyTrust === 'function' ? deps.verifyTrust : null
  const devicePathToDosPath = typeof deps.devicePathToDosPath === 'function' ? deps.devicePathToDosPath : null

  const trusted = new Set()
  const baselineTrustedPids = new Set()
  const userTrustedExactPaths = new Set()
  const userTrustedDirPrefixes = new Set()
  let enabled = true
  let applyToSnapshot = true
  let applyToNewProcesses = true
  let maxVerifyPids = 0
  let trustedSkipProviders = null

  function normalizeProviderName(p) {
    if (typeof p !== 'string' || !p) return ''
    return p.trim().toLowerCase()
  }

  function setTrustedSkipProviders(list) {
    if (!Array.isArray(list)) {
      trustedSkipProviders = null
      return
    }
    const set = new Set()
    for (const it of list) {
      const n = normalizeProviderName(String(it))
      if (n) set.add(n)
    }
    trustedSkipProviders = set
  }

  function setBaselineTrustedPids(list) {
    baselineTrustedPids.clear()
    const arr = Array.isArray(list) ? list : []
    for (const it of arr) {
      const p = asPid(it)
      if (p == null) continue
      baselineTrustedPids.add(p)
    }
  }

  function configure(cfg) {
    const c = cfg && typeof cfg === 'object' ? cfg : {}
    enabled = c.enabled !== false
    applyToSnapshot = c.applyToSnapshot !== false
    applyToNewProcesses = c.applyToNewProcesses !== false
    maxVerifyPids = Number.isFinite(c.maxVerifyPids) ? Math.max(0, Math.floor(c.maxVerifyPids)) : 0
    if (Array.isArray(c.baseTrustedPids)) setBaselineTrustedPids(c.baseTrustedPids)
    setTrustedSkipProviders(c.skipProviders)
  }

  function normalizePathForTrust(p) {
    if (typeof p !== 'string' || !p) return ''
    let s = sanitizeText(p)
    if (!s) return ''
    if (!isCleanText(s)) return ''
    if (devicePathToDosPath) {
      try { s = devicePathToDosPath(s) || s } catch {}
    }
    return s.replace(/\//g, '\\').toLowerCase()
  }

  function isTrustedImage(imagePath) {
    if (!enabled) return false
    
    const p = normalizePathForTrust(imagePath)
    if (!p) return false
    
    if (userTrustedExactPaths.has(p)) return true
    for (const d of userTrustedDirPrefixes) {
      if (p === d) return true
      if (p.startsWith(d + '\\')) return true
    }

    if (!verifyTrust) return false
    try { return verifyTrust(p) === true } catch { return false }
  }

  function addUserTrustedPath(p) {
    const s = normalizePathForTrust(p)
    if (!s) return
    const raw = (typeof p === 'string') ? p.trim() : ''
    const hasTrailingSep = /[\\/]+$/.test(raw)
    let isDir = hasTrailingSep
    if (!isDir) {
      try {
        const st = fs.statSync(s)
        if (st && st.isDirectory && st.isDirectory()) isDir = true
      } catch {}
    }
    if (isDir) {
      const dir = s.replace(/[\\]+$/g, '')
      if (dir) userTrustedDirPrefixes.add(dir)
      return
    }
    userTrustedExactPaths.add(s)
  }

  function setUserTrustedPaths(list) {
    userTrustedExactPaths.clear()
    userTrustedDirPrefixes.clear()
    const arr = Array.isArray(list) ? list : []
    for (const p of arr) addUserTrustedPath(p)
  }

  function addTrustedPid(pid) {
    const p = asPid(pid)
    if (p != null) trusted.add(p)
  }

  function seedFromSnapshot(list) {
    if (!enabled || !applyToSnapshot) return
    trusted.clear()
    const arr = Array.isArray(list) ? list : []
    const lim = maxVerifyPids > 0 ? Math.min(arr.length, maxVerifyPids) : arr.length
    for (let i = 0; i < lim; i++) {
      const it = arr[i]
      if (!it || typeof it !== 'object') continue
      const pid = asPid(it.pid)
      if (pid == null) continue
      const img = typeof it.imagePath === 'string' ? it.imagePath : ''
      if (isTrustedImage(img)) trusted.add(pid)
    }
  }

  function onProcessStart(pid, imagePath) {
    if (!enabled || !applyToNewProcesses) return false
    const p = asPid(pid)
    if (p == null) return false
    trusted.delete(p)
    if (baselineTrustedPids.has(p)) return true
    if (!isTrustedImage(imagePath)) return false
    trusted.add(p)
    return true
  }

  function onProcessStop(pid) {
    const p = asPid(pid)
    if (p == null) return
    if (baselineTrustedPids.has(p)) return
    trusted.delete(p)
  }

  function getRelevantPidForEvent(ev) {
    const e = ev && typeof ev === 'object' ? ev : null
    if (!e) return null
    const provider = typeof e.provider === 'string' ? e.provider : ''
    const data = e.data && typeof e.data === 'object' ? e.data : null
    if (provider === 'Process' && data) {
      const typ = typeof data.type === 'string' ? data.type : ''
      if (typ === 'Start' || typ === 'Stop') {
        const subjectPid = asPid(data.processId)
        if (subjectPid != null) return subjectPid
      }
    }
    return asPid(e.pid)
  }

  function shouldSkipEvent(ev) {
    if (!enabled) return false
    const pid = getRelevantPidForEvent(ev)
    if (pid == null) return false
    if (baselineTrustedPids.has(pid)) return true
    if (!trusted.has(pid)) return false
    if (trustedSkipProviders == null) return true
    const provider = normalizeProviderName(ev && ev.provider)
    if (!provider) return true
    return trustedSkipProviders.has(provider)
  }

  return {
    configure,
    seedFromSnapshot,
    onProcessStart,
    onProcessStop,
    shouldSkipEvent,
    addUserTrustedPath,
    setUserTrustedPaths,
    addTrustedPid,
    isTrustedPid: (pid) => {
      const p = asPid(pid)
      if (p == null) return false
      if (baselineTrustedPids.has(p)) return true
      return trusted.has(p)
    },
    size: () => trusted.size + baselineTrustedPids.size
  }
}

module.exports = {
  createEtwTrustedPidFilter
}
