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
  appendWorkerTrace({ ts: Date.now(), source: 'training_worker_uncaught', ...normalizeErrorPayload(err) })
})

process.on('unhandledRejection', (reason) => {
  appendWorkerTrace({ ts: Date.now(), source: 'training_worker_unhandled', ...normalizeErrorPayload(reason) })
})

function postMessage(payload) {
  if (!parentPort) return
  try { parentPort.postMessage(payload) } catch {}
}

async function handleTrainMessage(m) {
  const files = Array.isArray(m.files) ? m.files.filter(Boolean) : []
  const isWhite = m.isWhite === true
  const config = m && m.config && typeof m.config === 'object' ? m.config : {}
  cfg = {
    scanner: config.scanner && typeof config.scanner === 'object' ? config.scanner : {},
    scan: config.scan && typeof config.scan === 'object' ? config.scan : {}
  }
  postMessage({ type: 'count', total: files.length })
  let done = 0
  let trained = 0
  for (const f of files) {
    try {
      const r = await scannerClient.trainFromPath(f, isWhite)
      if (r && r.ok) trained++
      done++
      postMessage({ type: 'progress', total: files.length, done, current: f })
    } catch (e) {
      appendWorkerTrace({ ts: Date.now(), source: 'training_worker_train_failed', file: f, ...normalizeErrorPayload(e) })
      done++
      postMessage({ type: 'progress', total: files.length, done, current: f })
    }
  }
  postMessage({ type: 'done', result: { ok: trained > 0, total: files.length, trained, failed: files.length >= trained ? (files.length - trained) : 0 } })
}

async function handleTrainOne(m) {
  const file = typeof m.file === 'string' ? m.file : ''
  const isWhite = m.isWhite === true
  const config = m && m.config && typeof m.config === 'object' ? m.config : {}
  cfg = {
    scanner: config.scanner && typeof config.scanner === 'object' ? config.scanner : {},
    scan: config.scan && typeof config.scan === 'object' ? config.scan : {}
  }
  if (!file) {
    postMessage({ type: 'train_one_done', ok: false, file: '' })
    return
  }
  try {
    const r = await scannerClient.trainFromPath(file, isWhite)
    const ok = r && r.ok === true
    postMessage({ type: 'train_one_done', ok, file })
  } catch (e) {
    appendWorkerTrace({ ts: Date.now(), source: 'training_worker_train_failed', file, ...normalizeErrorPayload(e) })
    postMessage({ type: 'train_one_done', ok: false, file })
  }
}

if (parentPort) {
  parentPort.on('message', (msg) => {
    const m = msg && typeof msg === 'object' ? msg : {}
    if (m.type === 'train') {
      handleTrainMessage(m).catch(() => postMessage({ type: 'done', result: { ok: false, total: 0, trained: 0, failed: 0 } }))
      return
    }
    if (m.type === 'train_one') {
      handleTrainOne(m).catch(() => postMessage({ type: 'train_one_done', ok: false, file: m && typeof m.file === 'string' ? m.file : '' }))
    }
  })
}
