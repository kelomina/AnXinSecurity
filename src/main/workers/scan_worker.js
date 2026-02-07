const { parentPort } = require('worker_threads')
const path = require('path')
const fs = require('fs')
const { createScannerClient } = require('../scanner_client')

let cfg = { scanner: {}, scan: {} }

const scannerClient = createScannerClient(() => cfg, { disableWorkerPool: true })

function resolveErrorLogDir() {
  const base = path.join(__dirname, '../../../')
  const dir = path.join(base, 'data', 'logs', 'crash')
  try { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }) } catch {}
  return dir
}

function normalizeErrorPayload(err) {
  if (!err) return { message: 'UnknownError', stack: '' }
  if (typeof err === 'string') return { message: err, stack: '' }
  return {
    message: err.message ? String(err.message) : String(err),
    stack: err.stack ? String(err.stack) : ''
  }
}

function appendWorkerTrace(payload) {
  try {
    const dir = resolveErrorLogDir()
    const isError = payload && (
      /error|fail|exception/i.test(String(payload.stage || '')) ||
      /error|fail|exception/i.test(String(payload.source || '')) ||
      payload.stack || payload.message
    )
    const fileName = isError ? 'error.log' : 'trace.log'
    const filePath = path.join(dir, fileName)
    const line = JSON.stringify(payload)
    fs.appendFileSync(filePath, line + '\n')
  } catch {}
}

process.on('uncaughtException', (err) => {
  appendWorkerTrace({ ts: Date.now(), source: 'scan_worker_uncaught', ...normalizeErrorPayload(err) })
})

process.on('unhandledRejection', (reason) => {
  appendWorkerTrace({ ts: Date.now(), source: 'scan_worker_unhandled', ...normalizeErrorPayload(reason) })
})

function postMessage(payload) {
  if (!parentPort) return
  try { parentPort.postMessage(payload) } catch {}
}

async function handleScanBatch(m) {
  const taskId = typeof m.taskId === 'string' ? m.taskId : ''
  const requestId = typeof m.requestId === 'string' ? m.requestId : ''
  const filePaths = Array.isArray(m.filePaths) ? m.filePaths : []
  if (m && m.config && typeof m.config === 'object') {
    cfg = {
      scanner: m.config.scanner && typeof m.config.scanner === 'object' ? m.config.scanner : {},
      scan: m.config.scan && typeof m.config.scan === 'object' ? m.config.scan : {}
    }
  }
  try {
    const res = await scannerClient.scanBatch(filePaths, requestId)
    postMessage({ type: 'scan_batch_done', taskId, ok: true, results: Array.isArray(res) ? res : [] })
  } catch (e) {
    appendWorkerTrace({ ts: Date.now(), source: 'scan_worker_scan_failed', requestId, ...normalizeErrorPayload(e) })
    postMessage({ type: 'scan_batch_done', taskId, ok: false, error: e && e.message ? e.message : 'SCAN_FAILED', results: [] })
  }
}

if (parentPort) {
  parentPort.on('message', (msg) => {
    const m = msg && typeof msg === 'object' ? msg : {}
    if (m.type === 'scan_batch') {
      handleScanBatch(m).catch(() => postMessage({ type: 'scan_batch_done', taskId: m && m.taskId ? String(m.taskId) : '', ok: false, error: 'SCAN_FAILED', results: [] }))
    }
  })
}
