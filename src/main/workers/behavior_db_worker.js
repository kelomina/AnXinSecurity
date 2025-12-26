const { parentPort } = require('worker_threads')
const { createProcessBehaviorStore } = require('../process_behavior_store')

let store = null
let flushTimer = null

function postMessage(msg) {
  if (!parentPort) return
  parentPort.postMessage(msg)
}

function clearFlushTimer() {
  if (!flushTimer) return
  clearInterval(flushTimer)
  flushTimer = null
}

async function init(payload) {
  const cfg = payload && payload.config ? payload.config : {}
  const sqliteCfg = cfg && cfg.sqlite ? cfg.sqlite : {}
  store = await createProcessBehaviorStore(sqliteCfg)

  const flushIntervalMs = Number.isFinite(cfg.flushIntervalMs) ? cfg.flushIntervalMs : 500
  clearFlushTimer()
  if (flushIntervalMs > 0) {
    flushTimer = setInterval(() => {
      try { store.exportToFileIfNeeded() } catch {}
    }, flushIntervalMs)
    if (flushTimer.unref) flushTimer.unref()
  }

  postMessage({ type: 'ready', dbPath: store.getDbPath() })
}

function ingest(payload) {
  if (!store) return
  try {
    store.ingest(payload && payload.event)
  } catch {}
}

function handleListProcesses(payload) {
  if (!store) return postMessage({ type: 'result', requestId: payload.requestId, data: [] })
  try {
    const data = store.listProcesses(payload && payload.query ? payload.query : {})
    postMessage({ type: 'result', requestId: payload.requestId, data })
  } catch {
    postMessage({ type: 'result', requestId: payload.requestId, data: [] })
  }
}

function handleListEvents(payload) {
  if (!store) return postMessage({ type: 'result', requestId: payload.requestId, data: [] })
  try {
    const data = store.listEvents(payload && payload.query ? payload.query : {})
    postMessage({ type: 'result', requestId: payload.requestId, data })
  } catch {
    postMessage({ type: 'result', requestId: payload.requestId, data: [] })
  }
}

function handleGetDbPath(payload) {
  postMessage({ type: 'result', requestId: payload.requestId, data: store ? store.getDbPath() : null })
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
    } else if (type === 'ingest') {
      ingest(msg)
    } else if (type === 'listProcesses') {
      handleListProcesses(msg)
    } else if (type === 'listEvents') {
      handleListEvents(msg)
    } else if (type === 'getDbPath') {
      handleGetDbPath(msg)
    } else if (type === 'close') {
      close(msg).catch(() => process.exit(0))
    }
  })
}

