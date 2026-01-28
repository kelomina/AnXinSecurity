const { parentPort } = require('worker_threads')
const { createScannerClient } = require('../scanner_client')

let cfg = { scanner: {}, scan: {} }

const scannerClient = createScannerClient(() => cfg, { disableWorkerPool: true })

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
