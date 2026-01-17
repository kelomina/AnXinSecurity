const fs = require('fs')
const path = require('path')
const os = require('os')
const readline = require('readline')

function normalizeLogPath(cfg = {}) {
  const dir = typeof cfg.directory === 'string' && cfg.directory.trim() ? cfg.directory.trim() : '%TEMP%'
  const resolvedDir = String(dir).replace(/%([^%]+)%/g, (_m, n) => process.env[n] || '')
  const baseDir = resolvedDir && resolvedDir !== dir ? resolvedDir : os.tmpdir()
  const logDir = path.join(baseDir, 'anxin_logs', 'processes')
  if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true })
  return { logDir }
}

function nowIso() {
  return new Date().toISOString()
}

class ProcessBehaviorStore {
  constructor(options = {}) {
    this.logDir = options.logDir || path.join(os.tmpdir(), 'anxin_logs', 'processes')
    if (!fs.existsSync(this.logDir)) fs.mkdirSync(this.logDir, { recursive: true })

    this.buffer = new Map() // Map<pid, string[]>
    this.totalBufferSize = 0
    this.flushThreshold = 100 * 1024 * 1024 // 100MB
  }

  getDbPath() {
    return this.logDir
  }

  ingest(event) {
    if (!event || typeof event !== 'object') return

    const ts = typeof event.timestamp === 'string' && event.timestamp ? event.timestamp : nowIso()
    const provider = typeof event.provider === 'string' ? event.provider : 'Unknown'
    const data = event.data && typeof event.data === 'object' ? event.data : {}
    let op = typeof data.type === 'string' ? data.type : null

    // Determine target PID for indexing
    let targetPid = null
    
    // Logic to determine which PID this event belongs to
    // Priority: subjectPid (process being acted on) > actorPid (process doing the action)
    let actorPid = Number.isFinite(event.pid) ? event.pid : null
    let subjectPid = null

    if (provider === 'Process') {
      subjectPid = Number.isFinite(data.processId) ? data.processId : null
      const ppid = Number.isFinite(data.parentProcessId) ? data.parentProcessId : null
      if (op === 'Start') {
        actorPid = Number.isFinite(ppid) ? ppid : (subjectPid != null ? subjectPid : actorPid)
      } else {
        actorPid = subjectPid != null ? subjectPid : actorPid
      }
    }

    // Default to actorPid if no subjectPid (for File, Network, Registry events initiated by a process)
    targetPid = subjectPid != null ? subjectPid : actorPid

    if (targetPid == null) {
        // Fallback for system-wide events or unknown PID
        targetPid = 'global' 
    }

    const logLine = JSON.stringify({ ...event, _ts: ts, _provider: provider, _op: op }) + '\n'
    const lineSize = Buffer.byteLength(logLine)

    if (!this.buffer.has(targetPid)) {
      this.buffer.set(targetPid, [])
    }
    this.buffer.get(targetPid).push(logLine)
    this.totalBufferSize += lineSize

    if (this.totalBufferSize >= this.flushThreshold) {
      this.flush()
    }
  }

  flush() {
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

  // listProcesses is now limited or stubbed since we don't have a relational DB of all processes
  // We could scan the log directory for PIDs, but that might be slow.
  // For now, returning empty or implementing a simple directory scan.
  listProcesses({ limit = 200, offset = 0 } = {}) {
    try {
        const files = fs.readdirSync(this.logDir)
            .filter(f => f.endsWith('.log') && f !== 'global.log')
            .map(f => parseInt(f.replace('.log', ''), 10))
            .filter(pid => !isNaN(pid))
            .slice(offset, offset + limit)
        
        // We don't have metadata (image name, start time) readily available without opening files
        // Returning bare PIDs for now
        return files.map(pid => ({ pid, image: 'Unknown (Log Only)', first_seen: null, last_seen: null }))
    } catch {
        return []
    }
  }

  // Optimized to read from file + memory buffer
  listEvents({ pid = null, limit = 500, offset = 0 } = {}) {
    if (pid == null) return [] // Global listing not supported efficiently without DB

    const targetPid = pid
    const out = []
    
    // 1. Read from memory buffer first (most recent)
    // Note: This logic assumes we want recent events. If we want historic, file first.
    // Usually UI wants latest. But `offset` implies pagination.
    // Let's implement a simple strategy: Read file, then append memory, then slice.
    // CAUTION: Reading full file into memory is bad.
    // But since we split by PID, a single PID's log might be manageable or we use readline.
    
    // Strategy: Use readline to read file lines efficiently
    // Since we need reverse order (latest first) usually, reading from end is better but hard with text files.
    // For simplicity in this "high performance write" context, we'll read forward and slice.
    // If files are huge, this `listEvents` will be slow, but user asked for "write performance".
    
    let fileLines = []
    const filePath = path.join(this.logDir, `${targetPid}.log`)
    
    if (fs.existsSync(filePath)) {
        try {
            // Read file synchronously for simplicity in this context, or use async if acceptable.
            // Given the requirement, we'll load the file content. 
            // Warning: If single PID log > 100MB, this might be heavy.
            // But we can't do random access on JSON lines easily.
            const content = fs.readFileSync(filePath, 'utf-8')
            fileLines = content.split('\n').filter(l => l.trim())
        } catch {}
    }

    let memLines = []
    if (this.buffer.has(targetPid)) {
        // buffer stores strings with \n at end
        memLines = this.buffer.get(targetPid).map(l => l.trim()).filter(l => l)
    }

    const allLines = fileLines.concat(memLines)
    
    // Reverse to show newest first
    allLines.reverse()

    const sliced = allLines.slice(offset, offset + limit)
    
    return sliced.map((line, idx) => {
        try {
            const parsed = JSON.parse(line)
            return {
                id: offset + idx, // Fake ID
                ts: parsed._ts,
                provider: parsed._provider,
                op: parsed._op,
                actor_pid: parsed.pid,
                // Map other fields to match previous DB structure if needed by UI
                // raw_json: line
                ...parsed
            }
        } catch {
            return null
        }
    }).filter(x => x)
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
