const fs = require('fs')
const path = require('path')
const CryptoManager = require('./crypto_manager')

class StartupAllowlistManager {
  constructor(configPath) {
    this.configPath = configPath
    this.crypto = new CryptoManager(configPath, 'startup_allowlist')
    this.storagePath = this.resolveStoragePath()
  }

  resolveStoragePath() {
    let p = null
    try {
      const raw = fs.readFileSync(this.configPath, 'utf-8')
      const cfg = JSON.parse(raw)
      const rel = cfg && cfg.etw && cfg.etw.interception && cfg.etw.interception.startupAllowlistFile
        ? cfg.etw.interception.startupAllowlistFile
        : 'config/startup_allowlist.enc'
      p = path.isAbsolute(rel) ? rel : path.join(path.dirname(this.configPath), '..', rel)
    } catch {
      p = path.join(path.dirname(this.configPath), '..', 'config', 'startup_allowlist.enc')
    }
    const dir = path.dirname(p)
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    return p
  }

  normalize(p) {
    if (!p || typeof p !== 'string') return ''
    return path.normalize(p).toLowerCase()
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

  getList() {
    const data = this.loadRaw()
    if (!Array.isArray(data)) return []
    return data.map(it => ({
      type: it && it.type === 'dir' ? 'dir' : 'file',
      path: it && it.path ? it.path : ''
    })).filter(it => it.path)
  }

  getFiles() {
    return this.getList().filter(it => it.type === 'file').map(it => it.path)
  }

  addFiles(paths) {
    const list = this.getList()
    const seen = new Set(list.map(it => it.type + '|' + this.normalize(it.path)))
    let changed = false
    for (const p of Array.isArray(paths) ? paths : []) {
      if (typeof p !== 'string' || !p) continue
      const key = 'file|' + this.normalize(p)
      if (!key || seen.has(key)) continue
      seen.add(key)
      list.push({ type: 'file', path: p })
      changed = true
    }
    if (changed) this.saveRaw(list)
    return list
  }
}

module.exports = StartupAllowlistManager
