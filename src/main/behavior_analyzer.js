const path = require('path')
const { Worker } = require('worker_threads')

function getBehaviorCfg(appConfig = {}) {
  const cfg = appConfig && appConfig.behaviorAnalyzer ? appConfig.behaviorAnalyzer : {}
  const enabled = cfg.enabled !== false
  const flushIntervalMs = Number.isFinite(cfg.flushIntervalMs) ? cfg.flushIntervalMs : 500
  const sqlite = cfg && cfg.sqlite ? cfg.sqlite : {}
  const filters = cfg && cfg.filters ? cfg.filters : {}
  const sqliteCfg = {
    mode: sqlite.mode === 'file' ? 'file' : 'memory',
    directory: typeof sqlite.directory === 'string' ? sqlite.directory : '%TEMP%',
    fileName: typeof sqlite.fileName === 'string' ? sqlite.fileName : 'anxin_etw_behavior.db'
  }
  return { enabled, flushIntervalMs, sqlite: sqliteCfg, filters }
}

function createBehaviorAnalyzer(appConfig = {}) {
  const cfg = getBehaviorCfg(appConfig)
  let worker = null
  let dbPath = null
  let requestSeq = 1
  const pending = new Map()

  function start() {
    if (!cfg.enabled) return
    if (worker) return
    const workerPath = path.join(__dirname, 'workers/behavior_db_worker.js')
    worker = new Worker(workerPath)

    worker.on('message', (msg) => {
      if (msg && msg.type === 'ready') {
        dbPath = msg.dbPath || null
      } else if (msg && msg.type === 'result') {
        const reqId = msg.requestId
        const p = pending.get(reqId)
        if (p) {
          pending.delete(reqId)
          p.resolve(msg.data)
        }
      } else if (msg && msg.type === 'closed') {
        const reqId = msg.requestId
        const p = pending.get(reqId)
        if (p) {
          pending.delete(reqId)
          p.resolve(null)
        }
      } else if (msg && msg.type === 'error') {
        const err = new Error(msg.message || 'behavior_db_worker error')
        for (const [reqId, p] of pending.entries()) {
          pending.delete(reqId)
          p.reject(err)
        }
      }
    })

    worker.on('error', (err) => {
      for (const [reqId, p] of pending.entries()) {
        pending.delete(reqId)
        p.reject(err)
      }
      worker = null
    })

    worker.on('exit', () => {
      for (const [reqId, p] of pending.entries()) {
        pending.delete(reqId)
        p.reject(new Error('behavior_db_worker exited'))
      }
      worker = null
    })

    worker.postMessage({ type: 'init', config: cfg })
  }

  function ingest(event) {
    if (!worker) return
    try {
      worker.postMessage({ type: 'ingest', event })
    } catch {}
  }

  function call(type, query) {
    if (!worker) {
      if (type === 'getDbPath') return Promise.resolve(dbPath)
      if (type === 'clearAll') return Promise.resolve(false)
      return Promise.resolve([])
    }
    const requestId = String(requestSeq++)
    return new Promise((resolve, reject) => {
      pending.set(requestId, { resolve, reject })
      try {
        worker.postMessage({ type, requestId, query })
      } catch (e) {
        pending.delete(requestId)
        reject(e)
      }
    })
  }

  async function stop() {
    if (!worker) return
    const w = worker
    const requestId = String(requestSeq++)
    worker = null
    await new Promise((resolve) => {
      pending.set(requestId, { resolve, reject: resolve })
      try {
        w.postMessage({ type: 'close', requestId })
      } catch {
        pending.delete(requestId)
        resolve()
      }
      setTimeout(() => {
        pending.delete(requestId)
        resolve()
      }, 1500)
    })
    try { w.terminate() } catch {}
  }

  return {
    start,
    stop,
    ingest,
    getDbPath: () => dbPath,
    listProcesses: (q) => call('listProcesses', q),
    listEvents: (q) => call('listEvents', q),
    clearAll: () => call('clearAll', {})
  }
}

module.exports = {
  createBehaviorAnalyzer,
  getBehaviorCfg
}
