const { parentPort } = require('worker_threads')
const path = require('path')
const fs = require('fs')
const { createScannerClient } = require('../scanner_client')

let cfg = { scanner: {}, scan: {} }

const scannerClient = createScannerClient(() => cfg, { disableWorkerPool: true })

/**
 * - 函数: `resolveErrorLogDir`
 * - Function: `resolveErrorLogDir`
 * - 作用: 解析错误日志目录，并按当前运行环境返回优先可用的结果。
 * - Purpose: Resolves the error log directory and returns the highest-priority usable result for the current runtime.
 * - 调用方: `模块顶层流程`、`appendWorkerTrace`。
 * - Callers: `模块顶层流程`, `appendWorkerTrace`.
 * - 被调方: `path.join`、`fs.existsSync`、`fs.mkdirSync`。
 * - Callees: `path.join`, `fs.existsSync`, `fs.mkdirSync`.
 * - 变量说明: 无显式入参；`base`, `dir` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `base`, `dir` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `resolveErrorLogDir`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `resolveErrorLogDir` through the existing returned object.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 解析 | 错误 | 日志 | 目录 | resolve | error | log | directory | error handling | 复用
 */
function resolveErrorLogDir() {
  const base = path.join(__dirname, '../../../')
  const dir = path.join(base, 'data', 'logs', 'crash')
  try { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }) } catch {}
  return dir
}

/**
 * - 函数: `normalizeErrorPayload`
 * - Function: `normalizeErrorPayload`
 * - 作用: 标准化错误载荷输入，统一为当前模块后续逻辑可直接消费的结构。
 * - Purpose: Normalizes the error payload input into a structure that downstream logic can consume directly.
 * - 调用方: `模块顶层流程`、`handleScanBatch`。
 * - Callers: `模块顶层流程`, `handleScanBatch`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `err` 为当前流程传入的err。
 * - Variables: `err` is the incoming err for this flow.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `normalizeErrorPayload`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `normalizeErrorPayload` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 标准化 | 错误 | 载荷 | normalize | error | payload | call chain | 错误处理 | error handling | 复用
 */
function normalizeErrorPayload(err) {
  if (!err) return { message: 'UnknownError', stack: '' }
  if (typeof err === 'string') return { message: err, stack: '' }
  return {
    message: err.message ? String(err.message) : String(err),
    stack: err.stack ? String(err.stack) : ''
  }
}

/**
 * - 函数: `appendWorkerTrace`
 * - Function: `appendWorkerTrace`
 * - 作用: 向工作线程跟踪追加记录，供后续诊断、追踪或持久化链路复用。
 * - Purpose: Appends records to the worker trace so diagnostics, tracing, or persistence flows can reuse them.
 * - 调用方: `模块顶层流程`、`handleScanBatch`。
 * - Callers: `模块顶层流程`, `handleScanBatch`.
 * - 被调方: `resolveErrorLogDir`、`path.join`、`JSON.stringify`、`fs.appendFileSync`。
 * - Callees: `resolveErrorLogDir`, `path.join`, `JSON.stringify`, `fs.appendFileSync`.
 * - 变量说明: `payload` 为当前流程传入的载荷；`dir`, `isError` 为函数内部派生的中间状态。
 * - Variables: `payload` is the incoming payload for this flow; `dir`, `isError` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `appendWorkerTrace`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `appendWorkerTrace` through the existing returned object.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 追加 | 工作线程 | 跟踪 | append | worker | trace | call chain | 错误处理 | error handling | 复用
 */
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

/**
 * - 函数: `postMessage`
 * - Function: `postMessage`
 * - 作用: 向主线程回传扫描 worker 的结果、进度或失败消息，屏蔽 `parentPort` 不可用与投递异常的细节，是本 worker 唯一的回包出口。
 * - Purpose: Sends scan-worker results, progress, or failures back to the main thread, hiding `parentPort` availability checks and post failures, and acts as the sole outbound reply channel for this worker.
 * - 调用方: `handleScanBatch` 以及 `parentPort.on('message')` 中的兜底失败回包逻辑。
 * - Callers: Called by `handleScanBatch` and by the fallback failure-reply path inside `parentPort.on('message')`.
 * - 被调方: `parentPort.postMessage`。
 * - Callees: `parentPort.postMessage`.
 * - 变量说明: `payload` 为发送给主线程的标准化消息体，通常包含 `type`、`taskId`、`ok`、`results` 或 `error`。
 * - Variables: `payload` is the normalized message sent to the main thread, usually carrying `type`, `taskId`, `ok`, `results`, or `error`.
 * - 接入方式: 仅在 `scan_worker` 内部使用；新增消息类型时应继续通过本函数回包，避免各处直接访问 `parentPort`。
 * - Integration: Use only inside `scan_worker`; new reply message types should still go through this helper instead of touching `parentPort` directly.
 * - 错误处理: `parentPort` 缺失时直接返回；投递异常被局部吞掉，避免 worker 在上报失败时再次触发未处理异常。
 * - Error Handling: Returns immediately when `parentPort` is missing; post failures are swallowed locally so the worker does not throw again while reporting an error.
 * - 关键词: worker回包 | worker reply | 主线程通信 | main-thread bridge | scan_batch_done | parentPort | 错误回传 | error reply | 安全投递 | safe post
 */
function postMessage(payload) {
  if (!parentPort) return
  try { parentPort.postMessage(payload) } catch {}
}

/**
 * - 函数: `handleScanBatch`
 * - Function: `handleScanBatch`
 * - 作用: 执行主线程下发的批量扫描任务，刷新本 worker 的配置快照、调用禁用池化的 `scannerClient.scanBatch()`，并把结果统一封装成 `scan_batch_done` 回传给主线程。
 * - Purpose: Executes a batch-scan job sent by the main thread, refreshes this worker’s config snapshot, invokes the non-pooled `scannerClient.scanBatch()`, and wraps the outcome into a `scan_batch_done` reply for the main thread.
 * - 调用方: `parentPort.on('message')` 在收到 `type === 'scan_batch'` 的消息时调用。
 * - Callers: Called by `parentPort.on('message')` when a message with `type === 'scan_batch'` arrives.
 * - 被调方: `scanBatch`、`postMessage`、`appendWorkerTrace`、`normalizeErrorPayload`、`Array.isArray`、`Date.now`。
 * - Callees: `scanBatch`, `postMessage`, `appendWorkerTrace`, `normalizeErrorPayload`, `Array.isArray`, `Date.now`.
 * - 变量说明: `m` 为主线程下发的批量扫描消息；`taskId` 用于匹配 worker 池中的任务；`requestId` 用于底层扫描请求关联；`filePaths` 为待扫描文件列表。
 * - Variables: `m` is the batch-scan message from the main thread; `taskId` matches the task inside the worker pool; `requestId` associates the lower-level scan request; `filePaths` is the list of files to scan.
 * - 接入方式: 通过主线程向当前 worker 发送 `scan_batch` 消息接入；若新增批量扫描变体，应优先沿用本函数而不是复制一份扫描和回包逻辑。
 * - Integration: Integrate by sending a `scan_batch` message from the main thread to this worker; new batch-scan variants should reuse this function instead of copying the scan-and-reply flow.
 * - 错误处理: 批量扫描异常会先写入 worker trace，再回传 `ok: false` 的 `scan_batch_done`；这样主线程既能拿到失败状态，也能保留排障日志。
 * - Error Handling: Batch-scan failures are first written to the worker trace and then returned as `scan_batch_done` with `ok: false`, so the main thread gets the failure state while diagnostic logs are preserved.
 * - 关键词: 批量扫描 | batch scan | scan_batch | 配置快照 | config snapshot | 主线程回包 | main-thread reply | trace日志 | diagnostic trace | scannerClient
 */
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
