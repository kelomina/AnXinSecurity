const fs = require('fs')
const path = require('path')

function normalizeLogPath(cfg = {}) {
  const dir = typeof cfg.directory === 'string' && cfg.directory.trim() ? cfg.directory.trim() : 'data/behavior'
  const resolvedDir = String(dir).replace(/%([^%]+)%/g, (_m, n) => process.env[n] || '')
  
  // If the path was absolute or relative without env vars, resolvedDir === dir.
  // We should use resolvedDir unless it's empty.
  const baseDir = resolvedDir ? resolvedDir : path.join(__dirname, '../..', 'data', 'behavior')
  
  const logDir = path.isAbsolute(baseDir) ? path.join(baseDir, 'processes') : path.join(path.join(__dirname, '../..'), baseDir, 'processes')
  if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true })
  return { logDir }
}

function nowIso() {
  return new Date().toISOString()
}

function safeJsonParse(s) {
  try {
    return JSON.parse(s)
  } catch {
    return null
  }
}

function normalizeEventToRow(event) {
  const ev = event && typeof event === 'object' ? event : {}
  const provider = typeof ev.provider === 'string' ? ev.provider : (typeof ev._provider === 'string' ? ev._provider : 'Unknown')
  const ts = typeof ev.ts === 'string' && ev.ts ? ev.ts : (typeof ev.timestamp === 'string' && ev.timestamp ? ev.timestamp : (typeof ev._ts === 'string' && ev._ts ? ev._ts : nowIso()))
  const tid = Number.isFinite(ev.tid) ? ev.tid : null
  const data = ev.data && typeof ev.data === 'object' ? ev.data : {}

  let op = typeof ev.op === 'string' ? ev.op : (typeof data.type === 'string' ? data.type : (typeof ev._op === 'string' ? ev._op : null))
  let actorPid = Number.isFinite(ev.actor_pid) ? ev.actor_pid : (Number.isFinite(ev.pid) ? ev.pid : null)
  let subjectPid = Number.isFinite(ev.subject_pid) ? ev.subject_pid : null

  let filePath = typeof ev.file_path === 'string' ? ev.file_path : null
  let regKey = typeof ev.reg_key === 'string' ? ev.reg_key : null
  let regValue = typeof ev.reg_value === 'string' ? ev.reg_value : null
  let rawHex = typeof ev.raw_hex === 'string' ? ev.raw_hex : null

  if (provider === 'Process') {
    subjectPid = Number.isFinite(subjectPid) ? subjectPid : (Number.isFinite(data.processId) ? data.processId : null)
    const ppid = Number.isFinite(data.parentProcessId) ? data.parentProcessId : null
    if (op === 'Start') {
      actorPid = Number.isFinite(ppid) ? ppid : (subjectPid != null ? subjectPid : actorPid)
    } else {
      actorPid = subjectPid != null ? subjectPid : actorPid
    }
  } else if (provider === 'File') {
    filePath = typeof filePath === 'string' && filePath ? filePath : (typeof data.fileName === 'string' ? data.fileName : null)
  } else if (provider === 'Registry') {
    regKey = typeof regKey === 'string' && regKey ? regKey : (typeof data.keyPath === 'string' ? data.keyPath : null)
    regValue = typeof regValue === 'string' && regValue ? regValue : (typeof data.valueName === 'string' ? data.valueName : null)
    rawHex = typeof rawHex === 'string' && rawHex ? rawHex : (typeof data.rawHex === 'string' ? data.rawHex : null)
  } else if (provider === 'Network') {
    const target = typeof data.target === 'string' ? data.target : null
    const remoteIp = typeof data.remoteIp === 'string' ? data.remoteIp : null
    const remotePort = Number.isFinite(data.remotePort) ? data.remotePort : null
    const protocol = typeof data.protocol === 'string' ? data.protocol : null
    filePath = typeof filePath === 'string' && filePath ? filePath : (target || (remoteIp && remotePort != null ? `${protocol || ''} ${remoteIp}:${remotePort}`.trim() : null))
  }

  const rawObj = Object.assign({}, ev)
  delete rawObj._ts
  delete rawObj._provider
  delete rawObj._op
  if (!rawObj.timestamp) rawObj.timestamp = ts
  if (!rawObj.provider) rawObj.provider = provider
  const rawJson = typeof ev.raw_json === 'string' && ev.raw_json ? ev.raw_json : JSON.stringify(rawObj)

  return {
    ts,
    provider,
    op,
    actor_pid: Number.isFinite(actorPid) ? actorPid : null,
    subject_pid: Number.isFinite(subjectPid) ? subjectPid : null,
    tid,
    file_path: typeof filePath === 'string' ? filePath : null,
    reg_key: typeof regKey === 'string' ? regKey : null,
    reg_value: typeof regValue === 'string' ? regValue : null,
    raw_json: rawJson,
    raw_hex: typeof rawHex === 'string' ? rawHex : null
  }
}

function getPidKeyFromRow(row) {
  if (row && Number.isFinite(row.subject_pid)) return row.subject_pid
  if (row && Number.isFinite(row.actor_pid)) return row.actor_pid
  return 'global'
}

function readTailLines(filePath, wantLines, maxBytes = 8 * 1024 * 1024) {
  const n = Number.isFinite(wantLines) ? Math.max(0, Math.floor(wantLines)) : 0
  if (n <= 0) return []

  let fd = null
  try {
    const st = fs.statSync(filePath)
    if (!st || !(st.size > 0)) return []

    fd = fs.openSync(filePath, 'r')
    const chunkSize = 64 * 1024
    let pos = st.size
    let readBytes = 0
    let text = ''

    while (pos > 0 && readBytes < maxBytes) {
      const size = Math.min(chunkSize, pos)
      pos -= size
      const buf = Buffer.allocUnsafe(size)
      const got = fs.readSync(fd, buf, 0, size, pos)
      if (!(got > 0)) break
      readBytes += got
      text = buf.toString('utf8', 0, got) + text
      const lineCount = (text.match(/\n/g) || []).length
      if (lineCount >= n + 1) break
    }

    const lines = text.split('\n').map(s => s.trim()).filter(Boolean)
    if (lines.length <= n) return lines
    return lines.slice(lines.length - n)
  } catch {
    return []
  } finally {
    if (fd != null) {
      try { fs.closeSync(fd) } catch {}
    }
  }
}

class ProcessBehaviorStore {
  constructor(options = {}) {
    const defaultBase = path.join(__dirname, '../..', 'data', 'behavior')
    this.logDir = options.logDir || path.join(defaultBase, 'processes')
    if (!fs.existsSync(this.logDir)) fs.mkdirSync(this.logDir, { recursive: true })

    this.buffer = new Map()
    this.totalBufferSize = 0
    this.flushThreshold = 100 * 1024 * 1024

    this.processInfoPath = path.join(this.logDir, 'process_info.json')
    this.processInfo = new Map()
    this.processInfoDirty = false
    this.loadProcessInfo()
  }

  getDbPath() {
    return this.logDir
  }

  loadProcessInfo() {
    try {
      if (fs.existsSync(this.processInfoPath)) {
        const raw = fs.readFileSync(this.processInfoPath, 'utf8')
        const data = JSON.parse(raw)
        if (data && typeof data === 'object') {
          for (const [pid, info] of Object.entries(data)) {
            this.processInfo.set(Number(pid), info)
          }
        }
      }
    } catch (e) {
      console.error('Failed to load process info:', e)
    }
  }

  saveProcessInfo() {
    if (!this.processInfoDirty) return
    try {
      const obj = {}
      for (const [pid, info] of this.processInfo) {
        obj[pid] = info
      }
      fs.writeFileSync(this.processInfoPath, JSON.stringify(obj, null, 2))
      this.processInfoDirty = false
    } catch (e) {
      console.error('Failed to save process info:', e)
    }
  }

  updateProcessInfo(pid, imageName) {
    if (!pid || !imageName) return
    const p = Number(pid)
    if (!p) return

    const existing = this.processInfo.get(p)
    if (!existing || existing.name !== imageName) {
      this.processInfo.set(p, {
        name: imageName,
        lastSeen: Date.now()
      })
      this.processInfoDirty = true
      // Debounce save or save on next flush
    } else {
      // Just update timestamp occasionally?
      // For now, let's keep it simple.
    }
  }

  ingest(event) {
    if (!event || typeof event !== 'object') return

    if (event.provider === 'Process' && event.data && event.data.processId && event.data.imageName) {
       this.updateProcessInfo(event.data.processId, event.data.imageName)
    }

    const row = normalizeEventToRow(event)
    const pidKey = getPidKeyFromRow(row)
    const logLine = JSON.stringify(row) + '\n'
    const lineSize = Buffer.byteLength(logLine)

    if (!this.buffer.has(pidKey)) {
      this.buffer.set(pidKey, [])
    }
    this.buffer.get(pidKey).push(logLine)
    this.totalBufferSize += lineSize

    if (this.totalBufferSize >= this.flushThreshold) {
      this.flush()
    }
  }

  flush() {
    this.saveProcessInfo()
    if (this.totalBufferSize === 0) return

    for (const [pid, lines] of this.buffer) {
      if (lines.length === 0) continue
      const filePath = path.join(this.logDir, `${pid}.log`)
      try {
        fs.appendFileSync(filePath, lines.join(''))
      } catch (e) {
        console.error(`Failed to flush logs for PID ${pid}:`, e)
      }
    }

    this.buffer.clear()
    this.totalBufferSize = 0
  }

  listProcesses({ limit = 200, offset = 0 } = {}) {
    try {
      const lim = Number.isFinite(limit) ? Math.max(1, Math.min(5000, Math.floor(limit))) : 200
      const off = Number.isFinite(offset) ? Math.max(0, Math.floor(offset)) : 0
      const files = fs.readdirSync(this.logDir)
        .filter(f => f.endsWith('.log') && f !== 'global.log')
        .map(f => parseInt(f.replace('.log', ''), 10))
        .filter(pid => !isNaN(pid))
        
      // Sort or just slice? Let's just slice for now as before, though sorting by recent activity would be better.
      const sliced = files.slice(off, off + lim)

      return sliced.map(pid => {
        const info = this.processInfo.get(pid)
        return {
          pid,
          image: info ? info.name : 'Unknown (Log Only)',
          first_seen: info ? new Date(info.lastSeen).toISOString() : null, // We only store lastSeen currently
          last_seen: info ? new Date(info.lastSeen).toISOString() : null
        }
      })
    } catch {
      return []
    }
  }

  listEvents({ pid = null, limit = 500, offset = 0 } = {}) {
    const lim = Number.isFinite(limit) ? Math.max(1, Math.min(10000, Math.floor(limit))) : 500
    const off = Number.isFinite(offset) ? Math.max(0, Math.floor(offset)) : 0
    const p = Number.isFinite(pid) ? pid : null
    if (p == null) return []

    const need = off + lim
    const filePath = path.join(this.logDir, `${p}.log`)
    const fileLines = fs.existsSync(filePath) ? readTailLines(filePath, need) : []

    let memLines = []
    if (this.buffer.has(p)) {
      memLines = this.buffer.get(p).map(l => String(l || '').trim()).filter(Boolean)
    }

    const allLines = fileLines.concat(memLines)
    allLines.reverse()
    const sliced = allLines.slice(off, off + lim)

    const out = []
    for (let i = 0; i < sliced.length; i++) {
      const line = sliced[i]
      const obj = safeJsonParse(line)
      if (!obj || typeof obj !== 'object') continue
      const row = normalizeEventToRow(obj)
      row.id = off + i + 1
      out.push(row)
    }
    return out
  }

  listAllProcesses({ pageSize = 5000 } = {}) {
    return this.listProcesses({ limit: pageSize })
  }

  listAllEvents({ pid = null, pageSize = 10000 } = {}) {
     return this.listEvents({ pid, limit: pageSize })
  }

  exportToFileIfNeeded() {
    this.flush()
    return this.logDir
  }

  close() {
    this.flush()
  }

  clearAll() {
    this.buffer.clear()
    this.totalBufferSize = 0
    this.processInfo.clear()
    this.processInfoDirty = false
    try {
        fs.rmSync(this.logDir, { recursive: true, force: true })
        fs.mkdirSync(this.logDir, { recursive: true })
    } catch {}
  }
}

async function createProcessBehaviorStore(cfg = {}) {
  const { logDir } = normalizeLogPath(cfg)
  return new ProcessBehaviorStore({ logDir })
}

module.exports = {
  createProcessBehaviorStore,
  ProcessBehaviorStore
}
