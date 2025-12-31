const { parentPort } = require('worker_threads')
const { createProcessBehaviorStore } = require('../process_behavior_store')

let store = null
let flushTimer = null
let flushIntervalMs = 500
let writeEnabled = true

function postMessage(msg) {
  if (!parentPort) return
  parentPort.postMessage(msg)
}

function clearFlushTimer() {
  if (!flushTimer) return
  clearInterval(flushTimer)
  flushTimer = null
}

function resetFlushTimer() {
  clearFlushTimer()
  if (!store) return
  if (!writeEnabled) return
  if (!(flushIntervalMs > 0)) return
  flushTimer = setInterval(() => {
    if (!store) return
    if (!writeEnabled) return
    try { store.exportToFileIfNeeded() } catch {}
  }, flushIntervalMs)
  if (flushTimer.unref) flushTimer.unref()
}

async function init(payload) {
  const cfg = payload && payload.config ? payload.config : {}
  const sqliteCfg = cfg && cfg.sqlite ? cfg.sqlite : {}
  store = await createProcessBehaviorStore(sqliteCfg)

  flushIntervalMs = Number.isFinite(cfg.flushIntervalMs) ? cfg.flushIntervalMs : 500
  resetFlushTimer()

  postMessage({ type: 'ready', dbPath: store.getDbPath() })
}

function ingest(payload) {
  if (!store) return
  if (!writeEnabled) return
  try {
    store.ingest(payload && payload.event)
  } catch {}
}

function setWriteEnabled(payload) {
  writeEnabled = !!(payload && payload.enabled)
  resetFlushTimer()
}

function handleListProcesses(payload) {
  if (!store) return postMessage({ type: 'result', requestId: payload.requestId, data: [] })
  try {
    const q = payload && payload.query ? payload.query : {}
    const data = q && q.limit === Infinity ? store.listAllProcesses({}) : store.listProcesses(q)
    postMessage({ type: 'result', requestId: payload.requestId, data })
  } catch {
    postMessage({ type: 'result', requestId: payload.requestId, data: [] })
  }
}

function handleListEvents(payload) {
  if (!store) return postMessage({ type: 'result', requestId: payload.requestId, data: [] })
  try {
    const q = payload && payload.query ? payload.query : {}
    const data = q && q.limit === Infinity ? store.listAllEvents({ pid: q.pid }) : store.listEvents(q)
    postMessage({ type: 'result', requestId: payload.requestId, data })
  } catch {
    postMessage({ type: 'result', requestId: payload.requestId, data: [] })
  }
}

function handleGetDbPath(payload) {
  postMessage({ type: 'result', requestId: payload.requestId, data: store ? store.getDbPath() : null })
}

function handleClearAll(payload) {
  if (!store) return postMessage({ type: 'result', requestId: payload.requestId, data: false })
  try {
    store.clearAll()
    postMessage({ type: 'result', requestId: payload.requestId, data: true })
  } catch {
    postMessage({ type: 'result', requestId: payload.requestId, data: false })
  }
}

async function close(payload) {
  clearFlushTimer()
  try {
    if (store) store.close()
  } catch {}
  store = null
  postMessage({ type: 'closed', requestId: payload && payload.requestId ? payload.requestId : null })
  process.exit(0)
}

if (parentPort) {
  parentPort.on('message', (msg) => {
    const type = msg && msg.type
    if (type === 'init') {
      init(msg).catch((e) => postMessage({ type: 'error', message: e && e.message ? e.message : String(e) }))
    } else if (type === 'write_enabled') {
      setWriteEnabled(msg)
    } else if (type === 'ingest') {
      ingest(msg)
    } else if (type === 'listProcesses') {
      handleListProcesses(msg)
    } else if (type === 'listEvents') {
      handleListEvents(msg)
    } else if (type === 'getDbPath') {
      handleGetDbPath(msg)
    } else if (type === 'clearAll') {
      handleClearAll(msg)
    } else if (type === 'close') {
      close(msg).catch(() => process.exit(0))
    }
  })
}
