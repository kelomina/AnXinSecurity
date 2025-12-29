const path = require('path')
const { sanitizeText, isLikelyProcessImageText } = require('./utils')

function asPid(v) {
  const n = typeof v === 'number' ? v : parseInt(String(v), 10)
  if (!Number.isFinite(n) || n <= 0) return null
  return n
}

function getProcessNameFromPath(p) {
  if (typeof p !== 'string' || !p) return ''
  try {
    const n = path.basename(p)
    return sanitizeText(typeof n === 'string' ? n : '')
  } catch {
    return ''
  }
}

function createEtwPidCache() {
  const map = new Map()
  let max = 2048
  let ttlMs = 300000

  function configure(cfg = {}) {
    const c = cfg && typeof cfg === 'object' ? cfg : {}
    max = Number.isFinite(c.max) ? Math.max(0, Math.floor(c.max)) : 2048
    ttlMs = Number.isFinite(c.ttlMs) ? Math.max(0, Math.floor(c.ttlMs)) : 300000
  }

  function prune(now) {
    const t = Number.isFinite(ttlMs) ? ttlMs : 300000
    const m = Number.isFinite(max) ? max : 2048
    if (t > 0) {
      for (const [pid, v] of map) {
        if (!v || !Number.isFinite(v.at) || now - v.at > t) map.delete(pid)
      }
    }
    while (map.size > m) {
      const firstKey = map.keys().next().value
      if (firstKey == null) break
      map.delete(firstKey)
    }
  }

  function upsert(pid, imagePath, now) {
    const p = asPid(pid)
    if (p == null) return
    const rawImg = (typeof imagePath === 'string' && imagePath) ? imagePath : null
    const img = rawImg ? sanitizeText(rawImg) : null
    if (img && !isLikelyProcessImageText(img)) return
    const name = img ? getProcessNameFromPath(img) : ''
    map.delete(p)
    map.set(p, { imagePath: img, name, at: now })
  }

  function remove(pid) {
    const p = asPid(pid)
    if (p == null) return
    map.delete(p)
  }

  function resolve(pid, now) {
    const p = asPid(pid)
    if (p == null) return null
    const existed = map.get(p)
    if (!existed) return null
    if (Number.isFinite(ttlMs) && ttlMs > 0 && Number.isFinite(existed.at) && (now - existed.at > ttlMs)) {
      map.delete(p)
      return null
    }
    const cachedImage = (typeof existed.imagePath === 'string' && existed.imagePath) ? existed.imagePath : ''
    const cachedName = (typeof existed.name === 'string' && existed.name) ? existed.name : ''
    const ok = (cachedImage && isLikelyProcessImageText(cachedImage)) || (cachedName && isLikelyProcessImageText(cachedName))
    if (!ok) {
      map.delete(p)
      return null
    }
    map.delete(p)
    map.set(p, { imagePath: existed.imagePath, name: existed.name, at: now })
    return map.get(p) || null
  }

  function bulkUpsert(list, now) {
    const arr = Array.isArray(list) ? list : []
    for (const it of arr) {
      if (!it || typeof it !== 'object') continue
      const pid = it.pid
      const imagePath = it.imagePath
      upsert(pid, imagePath, now)
    }
  }

  return {
    configure,
    prune,
    upsert,
    bulkUpsert,
    remove,
    resolve,
    size: () => map.size
  }
}

module.exports = {
  createEtwPidCache
}
