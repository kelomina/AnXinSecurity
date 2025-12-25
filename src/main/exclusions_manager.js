const fs = require('fs')
const path = require('path')
const CryptoManager = require('./crypto_manager')

class ExclusionsManager {
  constructor(configPath, immutableDirs = []) {
    this.configPath = configPath
    this.crypto = new CryptoManager(configPath, 'exclusions')
    this.storagePath = this.resolveStoragePath()
    this.immutableDirs = this.loadImmutableDirs(immutableDirs)
  }

  resolveStoragePath() {
    let p = null
    try {
      const raw = fs.readFileSync(this.configPath, 'utf-8')
      const cfg = JSON.parse(raw)
      const rel = cfg && cfg.exclusions && cfg.exclusions.file ? cfg.exclusions.file : 'config/exclusions.enc'
      p = path.isAbsolute(rel) ? rel : path.join(path.dirname(this.configPath), '..', rel)
    } catch {
      p = path.join(path.dirname(this.configPath), '..', 'config', 'exclusions.enc')
    }
    const dir = path.dirname(p)
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    return p
  }

  normalize(p) {
    if (!p || typeof p !== 'string') return ''
    return path.normalize(p).toLowerCase()
  }

  loadImmutableDirs(immutableDirs) {
    let staticPaths = []
    try {
      const raw = fs.readFileSync(this.configPath, 'utf-8')
      const cfg = JSON.parse(raw)
      staticPaths = (cfg && cfg.exclusions && Array.isArray(cfg.exclusions.protectedPaths)) ? cfg.exclusions.protectedPaths : []
    } catch {}
    const out = []
    for (const p of staticPaths) {
      if (typeof p === 'string' && p) out.push(p)
    }
    for (const d of Array.isArray(immutableDirs) ? immutableDirs : []) {
      if (typeof d === 'string' && d) out.push(d)
    }
    const uniq = []
    const seen = new Set()
    for (const p of out) {
      const n = this.normalize(p)
      if (!n) continue
      if (seen.has(n)) continue
      seen.add(n)
      uniq.push({ original: p, normalized: n })
    }
    return uniq
  }

  getImmutableDirs() {
    return this.immutableDirs.map(it => it.original)
  }

  loadRaw() {
    try {
      if (!fs.existsSync(this.storagePath)) return null
      const raw = fs.readFileSync(this.storagePath, 'utf-8')
      const payload = JSON.parse(raw)
      const text = this.crypto.decryptText(payload)
      return JSON.parse(text)
    } catch {
      return null
    }
  }

  saveRaw(list) {
    const payload = this.crypto.encryptText(JSON.stringify(Array.isArray(list) ? list : []))
    fs.writeFileSync(this.storagePath, JSON.stringify(payload, null, 2), 'utf-8')
  }

  getImmutableList() {
    return this.immutableDirs.map(it => ({ type: 'dir', path: it.original }))
  }

  getList() {
    const data = this.loadRaw()
    if (!Array.isArray(data)) return []
    const list = data.map(it => ({
      type: it && it.type === 'dir' ? 'dir' : 'file',
      path: it && it.path ? it.path : ''
    })).filter(it => it.path)
    
    return list.filter(it => {
      const n = this.normalize(it.path)
      for (const d of this.immutableDirs) {
        if (it.type === 'file') {
          if (n.startsWith(d.normalized)) return false
        } else {
          if (n.startsWith(d.normalized)) return false
        }
      }
      return true
    })
  }

  setList(list) {
    const dedup = []
    const seen = new Set()
    for (const it of Array.isArray(list) ? list : []) {
      const type = it && it.type === 'dir' ? 'dir' : 'file'
      const p = it && it.path ? it.path : ''
      if (!p) continue
      const key = type + '|' + this.normalize(p)
      if (seen.has(key)) continue
      seen.add(key)
      dedup.push({ type, path: p })
    }
    this.saveRaw(dedup)
    return dedup
  }

  addFile(p) {
    const list = this.getList()
    const key = 'file|' + this.normalize(p)
    const exists = list.some(it => ('file|' + this.normalize(it.path)) === key)
    if (exists) return list
    list.push({ type: 'file', path: p })
    this.saveRaw(list)
    return list
  }

  addDir(p) {
    const list = this.getList()
    const key = 'dir|' + this.normalize(p)
    const exists = list.some(it => ('dir|' + this.normalize(it.path)) === key)
    if (exists) return list
    list.push({ type: 'dir', path: p })
    this.saveRaw(list)
    return list
  }

  remove(p) {
    const target = this.normalize(p)
    for (const d of this.immutableDirs) {
      if (target === d.normalized) {
        return this.getList()
      }
    }
    const list = this.getList()
    const out = list.filter(it => this.normalize(it.path) !== target)
    this.saveRaw(out)
    return out
  }

  isExcluded(p) {
    const target = this.normalize(p)
    for (const d of this.immutableDirs) {
      if (target.startsWith(d.normalized)) return true
    }
    const list = this.getList()
    for (const it of list) {
      const np = this.normalize(it.path)
      if (it.type === 'file') {
        if (target === np) return true
      } else {
        if (target.startsWith(np)) return true
      }
    }
    return false
  }
}

module.exports = ExclusionsManager
