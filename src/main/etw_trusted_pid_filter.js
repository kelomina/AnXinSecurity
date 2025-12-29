const { sanitizeText, isCleanText } = require('./utils')

function asPid(v) {
  const n = typeof v === 'number' ? v : parseInt(String(v), 10)
  if (!Number.isFinite(n) || n <= 0) return null
  return n
}

function createEtwTrustedPidFilter(deps = {}) {
  const verifyTrust = typeof deps.verifyTrust === 'function' ? deps.verifyTrust : null
  const devicePathToDosPath = typeof deps.devicePathToDosPath === 'function' ? deps.devicePathToDosPath : null

  const trusted = new Set([4])
  const userTrustedPaths = new Set()
  let enabled = true
  let applyToSnapshot = true
  let applyToNewProcesses = true
  let maxVerifyPids = 0

  function configure(cfg) {
    const c = cfg && typeof cfg === 'object' ? cfg : {}
    enabled = c.enabled !== false
    applyToSnapshot = c.applyToSnapshot !== false
    applyToNewProcesses = c.applyToNewProcesses !== false
    maxVerifyPids = Number.isFinite(c.maxVerifyPids) ? Math.max(0, Math.floor(c.maxVerifyPids)) : 0
  }

  function normalizePathForTrust(p) {
    if (typeof p !== 'string' || !p) return ''
    let s = sanitizeText(p)
    if (!s) return ''
    if (!isCleanText(s)) return ''
    if (devicePathToDosPath) {
      try { s = devicePathToDosPath(s) || s } catch {}
    }
    return s
  }

  function isTrustedImage(imagePath) {
    if (!enabled) return false
    
    const p = normalizePathForTrust(imagePath)
    if (!p) return false
    
    if (userTrustedPaths.has(p)) return true

    if (!verifyTrust) return false
    try { return verifyTrust(p) === true } catch { return false }
  }

  function addUserTrustedPath(p) {
    const s = normalizePathForTrust(p)
    if (s) userTrustedPaths.add(s)
  }

  function addTrustedPid(pid) {
    const p = asPid(pid)
    if (p) trusted.add(p)
  }

  function seedFromSnapshot(list) {
    if (!enabled || !applyToSnapshot) return
    trusted.clear()
    trusted.add(4) // PID 4 is always trusted (System)
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
    if (!isTrustedImage(imagePath)) return false
    trusted.add(p)
    return true
  }

  function onProcessStop(pid) {
    const p = asPid(pid)
    if (p == null) return
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
    return trusted.has(pid)
  }

  return {
    configure,
    seedFromSnapshot,
    onProcessStart,
    onProcessStop,
    shouldSkipEvent,
    addUserTrustedPath,
    addTrustedPid,
    isTrustedPid: (pid) => {
      const p = asPid(pid)
      if (p == null) return false
      return trusted.has(p)
    },
    size: () => trusted.size
  }
}

module.exports = {
  createEtwTrustedPidFilter
}
