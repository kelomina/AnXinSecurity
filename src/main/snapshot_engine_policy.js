function normalizePathKey(p) {
  if (typeof p !== 'string') return ''
  const s = p.trim()
  if (!s) return ''
  return s.toLowerCase().replace(/\//g, '\\')
}

function isMalware(res) {
  if (!res || typeof res !== 'object') return false
  if (res.infected === true) return true
  if (res.is_malware === true) return true
  if (res.malicious === true) return true
  return false
}

function getPayloadPaths(payload) {
  const p = payload && typeof payload === 'object' ? payload : null
  const out = []
  const imagePath = p && p.process && typeof p.process.imagePath === 'string' ? p.process.imagePath : ''
  if (imagePath) out.push(imagePath)
  const dlls = p && p.event && p.event.data && Array.isArray(p.event.data.unsignedDlls) ? p.event.data.unsignedDlls : []
  for (const d of dlls) {
    if (typeof d === 'string' && d) out.push(d)
  }
  const seen = new Set()
  const uniq = []
  for (const x of out) {
    const k = normalizePathKey(x)
    if (!k || seen.has(k)) continue
    seen.add(k)
    uniq.push(x)
  }
  return uniq
}

function decideSnapshotActions(payloads, scanByPath) {
  const arr = Array.isArray(payloads) ? payloads : []
  const map = (scanByPath && typeof scanByPath.get === 'function') ? scanByPath : new Map()

  const allowPaths = new Set()
  const clearPids = []
  const resumePids = []

  for (const p of arr) {
    const pid = p && Number.isFinite(p.pid) ? p.pid : parseInt(String(p && p.pid), 10)
    if (!Number.isFinite(pid) || pid <= 0) continue
    const paths = getPayloadPaths(p)
    if (!paths.length) continue

    let anyMalware = false
    for (const x of paths) {
      const k = normalizePathKey(x)
      const res = k ? map.get(k) : undefined
      if (isMalware(res)) {
        anyMalware = true
        break
      }
    }

    if (!anyMalware) {
      for (const x of paths) allowPaths.add(x)
      clearPids.push(pid)
      if (p.paused === true) resumePids.push(pid)
    }
  }

  return { allowPaths: Array.from(allowPaths), clearPids, resumePids }
}

module.exports = { normalizePathKey, isMalware, getPayloadPaths, decideSnapshotActions }
