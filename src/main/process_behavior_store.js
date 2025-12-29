const fs = require('fs')
const path = require('path')
const os = require('os')

function normalizeSqlitePath(cfg = {}) {
  const mode = cfg.mode === 'file' ? 'file' : 'memory'
  const fileName = typeof cfg.fileName === 'string' && cfg.fileName.trim() ? cfg.fileName.trim() : 'anxin_etw_behavior.db'
  const dir = typeof cfg.directory === 'string' && cfg.directory.trim() ? cfg.directory.trim() : '%TEMP%'

  const resolvedDir = String(dir).replace(/%([^%]+)%/g, (_m, n) => process.env[n] || '')
  const baseDir = resolvedDir && resolvedDir !== dir ? resolvedDir : (mode === 'file' ? os.tmpdir() : '')

  const filePath = mode === 'file' ? path.join(baseDir, fileName) : null
  return { mode, filePath }
}

async function initSqlJsOnce() {
  const initSqlJs = require('sql.js')
  const wasmPath = require.resolve('sql.js/dist/sql-wasm.wasm')
  return initSqlJs({
    locateFile: () => wasmPath
  })
}

function nowIso() {
  return new Date().toISOString()
}

class ProcessBehaviorStore {
  constructor(SQL, db, options = {}) {
    this.SQL = SQL
    this.db = db
    this.mode = options.mode || 'memory'
    this.filePath = options.filePath || null
    this.filters = options.filters || {}

    this.db.run('PRAGMA journal_mode=MEMORY')
    this.db.run('PRAGMA synchronous=OFF')

    this.db.run(`
      CREATE TABLE IF NOT EXISTS process (
        pid INTEGER PRIMARY KEY,
        ppid INTEGER,
        image TEXT,
        first_seen TEXT,
        last_seen TEXT,
        exited_at TEXT
      )
    `)

    this.db.run(`
      CREATE TABLE IF NOT EXISTS event (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        provider TEXT NOT NULL,
        op TEXT,
        actor_pid INTEGER,
        subject_pid INTEGER,
        tid INTEGER,
        file_path TEXT,
        reg_key TEXT,
        reg_value TEXT,
        raw_json TEXT,
        raw_hex TEXT
      )
    `)

    this.db.run('CREATE INDEX IF NOT EXISTS idx_event_actor_pid ON event(actor_pid)')
    this.db.run('CREATE INDEX IF NOT EXISTS idx_event_subject_pid ON event(subject_pid)')
    this.db.run('CREATE INDEX IF NOT EXISTS idx_event_ts ON event(ts)')
  }

  getDbPath() {
    return this.filePath
  }

  ingest(event) {
    if (!event || typeof event !== 'object') return

    const provider = typeof event.provider === 'string' ? event.provider : 'Unknown'
    const ts = typeof event.timestamp === 'string' && event.timestamp ? event.timestamp : nowIso()
    let actorPid = Number.isFinite(event.pid) ? event.pid : null
    const tid = Number.isFinite(event.tid) ? event.tid : null
    const data = event.data && typeof event.data === 'object' ? event.data : {}

    let op = typeof data.type === 'string' ? data.type : null
    let subjectPid = null
    let filePath = null
    let regKey = null
    let regValue = null
    let rawHex = null

    if (this._shouldSkipEvent(provider, op)) return

    if (provider === 'Process') {
      subjectPid = Number.isFinite(data.processId) ? data.processId : null
      const ppid = Number.isFinite(data.parentProcessId) ? data.parentProcessId : null
      const image = typeof data.imageName === 'string' ? data.imageName : null
      if (op === 'Start') {
        actorPid = Number.isFinite(ppid) ? ppid : (subjectPid != null ? subjectPid : actorPid)
      } else {
        actorPid = subjectPid != null ? subjectPid : actorPid
      }

      if (subjectPid != null) {
        this._upsertProcess(subjectPid, { ppid, image, seenAt: ts, exitedAt: op === 'Stop' ? ts : null })
      }
    } else if (provider === 'File') {
      filePath = typeof data.fileName === 'string' ? data.fileName : null
      if (actorPid != null) {
        this._upsertProcess(actorPid, { seenAt: ts })
      }
    } else if (provider === 'Registry') {
      regKey = typeof data.keyPath === 'string' ? data.keyPath : null
      regValue = typeof data.valueName === 'string' ? data.valueName : null
      rawHex = typeof data.rawHex === 'string' ? data.rawHex : null
      if (actorPid != null) {
        this._upsertProcess(actorPid, { seenAt: ts })
      }
    } else if (provider === 'Network') {
      const target = typeof data.target === 'string' ? data.target : null
      const remoteIp = typeof data.remoteIp === 'string' ? data.remoteIp : null
      const remotePort = Number.isFinite(data.remotePort) ? data.remotePort : null
      const protocol = typeof data.protocol === 'string' ? data.protocol : null
      filePath = target || (remoteIp && remotePort != null ? `${protocol || ''} ${remoteIp}:${remotePort}`.trim() : null)
      if (actorPid != null) {
        this._upsertProcess(actorPid, { seenAt: ts })
      }
    } else {
      if (actorPid != null) {
        this._upsertProcess(actorPid, { seenAt: ts })
      }
    }

    const rawJson = JSON.stringify(event)
    this.db.run(
      `INSERT INTO event (ts, provider, op, actor_pid, subject_pid, tid, file_path, reg_key, reg_value, raw_json, raw_hex)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [ts, provider, op, actorPid, subjectPid, tid, filePath, regKey, regValue, rawJson, rawHex]
    )
  }

  listProcesses({ limit = 200, offset = 0 } = {}) {
    const lim = Number.isFinite(limit) ? Math.max(1, Math.min(5000, limit)) : 200
    const off = Number.isFinite(offset) ? Math.max(0, offset) : 0
    return this._all(
      'SELECT pid, ppid, image, first_seen, last_seen, exited_at FROM process ORDER BY last_seen DESC LIMIT ? OFFSET ?',
      [lim, off]
    )
  }

  listEvents({ pid = null, limit = 500, offset = 0 } = {}) {
    const lim = Number.isFinite(limit) ? Math.max(1, Math.min(10000, limit)) : 500
    const off = Number.isFinite(offset) ? Math.max(0, offset) : 0
    const p = Number.isFinite(pid) ? pid : null
    if (p == null) {
      return this._all(
        `SELECT e.id, e.ts, e.provider, e.op, e.actor_pid, e.subject_pid, e.tid, e.file_path, e.reg_key, e.reg_value, e.raw_json,
                a.image AS actor_image,
                s.image AS subject_image
         FROM event e
         LEFT JOIN process a ON a.pid = e.actor_pid
         LEFT JOIN process s ON s.pid = e.subject_pid
         ORDER BY e.id DESC
         LIMIT ? OFFSET ?`,
        [lim, off]
      )
    }
    return this._all(
      `SELECT e.id, e.ts, e.provider, e.op, e.actor_pid, e.subject_pid, e.tid, e.file_path, e.reg_key, e.reg_value, e.raw_json,
              a.image AS actor_image,
              s.image AS subject_image
       FROM event e
       LEFT JOIN process a ON a.pid = e.actor_pid
       LEFT JOIN process s ON s.pid = e.subject_pid
       WHERE e.actor_pid = ? OR e.subject_pid = ?
       ORDER BY e.id DESC
       LIMIT ? OFFSET ?`,
      [p, p, lim, off]
    )
  }

  listAllProcesses({ pageSize = 5000 } = {}) {
    const size = Number.isFinite(pageSize) ? Math.max(1, Math.min(5000, Math.floor(pageSize))) : 5000
    const out = []
    let offset = 0
    for (;;) {
      const rows = this.listProcesses({ limit: size, offset })
      const arr = Array.isArray(rows) ? rows : []
      out.push(...arr)
      if (arr.length < size) break
      offset += size
    }
    return out
  }

  listAllEvents({ pid = null, pageSize = 10000 } = {}) {
    const size = Number.isFinite(pageSize) ? Math.max(1, Math.min(10000, Math.floor(pageSize))) : 10000
    const out = []
    let offset = 0
    for (;;) {
      const rows = this.listEvents({ pid, limit: size, offset })
      const arr = Array.isArray(rows) ? rows : []
      out.push(...arr)
      if (arr.length < size) break
      offset += size
    }
    return out
  }

  exportToFileIfNeeded() {
    if (this.mode !== 'file' || !this.filePath) return null
    try {
      const dir = path.dirname(this.filePath)
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
      const data = this.db.export()
      fs.writeFileSync(this.filePath, Buffer.from(data))
      return this.filePath
    } catch {
      return null
    }
  }

  close() {
    try {
      this.exportToFileIfNeeded()
    } catch {}
    try {
      this.db.close()
    } catch {}
  }

  clearAll() {
    try {
      this.db.run('DELETE FROM event')
    } catch {}
    try {
      this.db.run('DELETE FROM process')
    } catch {}
    try {
      this.db.run(`DELETE FROM sqlite_sequence WHERE name = 'event'`)
    } catch {}
  }

  _shouldSkipEvent(provider, op) {
    const p = typeof provider === 'string' ? provider : ''
    const o = typeof op === 'string' ? op : ''
    if (!p || !o) return false
    const cfg = this.filters && typeof this.filters === 'object' ? this.filters : {}
    const rule = cfg[p] && typeof cfg[p] === 'object' ? cfg[p] : {}
    const skipOps = Array.isArray(rule.skipOps) ? rule.skipOps.map(String) : []
    return skipOps.includes(o)
  }

  _upsertProcess(pid, { ppid = null, image = null, seenAt = null, exitedAt = null } = {}) {
    const existed = this._get('SELECT pid, ppid, image, first_seen, last_seen, exited_at FROM process WHERE pid = ?', [pid])
    if (!existed) {
      const first = seenAt || nowIso()
      this.db.run(
        'INSERT INTO process (pid, ppid, image, first_seen, last_seen, exited_at) VALUES (?, ?, ?, ?, ?, ?)',
        [pid, ppid, image, first, first, exitedAt]
      )
      return
    }
    const nextPpid = ppid != null ? ppid : existed.ppid
    const nextImage = image != null ? image : existed.image
    const nextLast = seenAt || existed.last_seen || existed.first_seen || nowIso()
    const nextExit = exitedAt != null ? exitedAt : existed.exited_at
    this.db.run(
      'UPDATE process SET ppid = ?, image = ?, last_seen = ?, exited_at = ? WHERE pid = ?',
      [nextPpid, nextImage, nextLast, nextExit, pid]
    )
  }

  _get(sql, params) {
    const stmt = this.db.prepare(sql)
    try {
      stmt.bind(params || [])
      if (!stmt.step()) return null
      return stmt.getAsObject()
    } finally {
      stmt.free()
    }
  }

  _all(sql, params) {
    const stmt = this.db.prepare(sql)
    try {
      stmt.bind(params || [])
      const out = []
      while (stmt.step()) out.push(stmt.getAsObject())
      return out
    } finally {
      stmt.free()
    }
  }
}

async function createProcessBehaviorStore(sqliteCfg = {}, filters = {}) {
  const { mode, filePath } = normalizeSqlitePath(sqliteCfg)
  const SQL = await initSqlJsOnce()
  let db = null

  if (mode === 'file' && filePath) {
    try {
      if (fs.existsSync(filePath)) {
        const buf = fs.readFileSync(filePath)
        db = new SQL.Database(new Uint8Array(buf))
      }
    } catch {}
  }
  if (!db) db = new SQL.Database()

  return new ProcessBehaviorStore(SQL, db, { mode, filePath, filters })
}

module.exports = {
  createProcessBehaviorStore,
  normalizeSqlitePath,
  ProcessBehaviorStore
}
