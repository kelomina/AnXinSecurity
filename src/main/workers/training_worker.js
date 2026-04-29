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
 * - 调用方: `模块顶层流程`、`handleTrainMessage`、`handleTrainOne`。
 * - Callers: `模块顶层流程`, `handleTrainMessage`, `handleTrainOne`.
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
 * - 调用方: `模块顶层流程`、`handleTrainMessage`、`handleTrainOne`。
 * - Callers: `模块顶层流程`, `handleTrainMessage`, `handleTrainOne`.
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
  appendWorkerTrace({ ts: Date.now(), source: 'training_worker_uncaught', ...normalizeErrorPayload(err) })
})

process.on('unhandledRejection', (reason) => {
  appendWorkerTrace({ ts: Date.now(), source: 'training_worker_unhandled', ...normalizeErrorPayload(reason) })
})

/**
 * - 函数: `postMessage`
 * - Function: `postMessage`
 * - 作用: 向主线程回传训练 worker 的计数、进度和最终结果消息，是本 worker 与主线程之间的统一出站通道。
 * - Purpose: Sends count, progress, and final-result messages from the training worker back to the main thread and acts as the unified outbound channel for this worker.
 * - 调用方: `handleTrainMessage`、`handleTrainOne` 以及 `parentPort.on('message')` 中的兜底失败回包逻辑。
 * - Callers: Called by `handleTrainMessage`, `handleTrainOne`, and the fallback failure-reply paths inside `parentPort.on('message')`.
 * - 被调方: `parentPort.postMessage`。
 * - Callees: `parentPort.postMessage`.
 * - 变量说明: `payload` 为发送给主线程的训练消息体，通常包含 `type`、`total`、`done`、`current`、`result`、`ok` 与 `file`。
 * - Variables: `payload` is the training message body sent to the main thread, usually carrying `type`, `total`, `done`, `current`, `result`, `ok`, and `file`.
 * - 接入方式: 仅在 `training_worker` 内部使用；新增训练消息类型时应优先通过本函数回包，而不是分散直接调用 `parentPort.postMessage`。
 * - Integration: Use only inside `training_worker`; new training message types should still flow through this helper instead of scattered direct `parentPort.postMessage` calls.
 * - 错误处理: `parentPort` 缺失时直接返回；投递异常被局部吞掉，避免训练失败时因二次上报再次抛错。
 * - Error Handling: Returns immediately when `parentPort` is missing; post failures are swallowed locally so training does not throw again while reporting an error.
 * - 关键词: 训练回包 | training reply | 进度上报 | progress reporting | 主线程通信 | main-thread bridge | parentPort | done消息 | progress消息 | safe post
 */
function postMessage(payload) {
  if (!parentPort) return
  try { parentPort.postMessage(payload) } catch {}
}

/**
 * - 函数: `handleTrainMessage`
 * - Function: `handleTrainMessage`
 * - 作用: 执行批量样本训练任务，按分块策略把文件列表交给扫描客户端训练，并持续向主线程回传总数、进度和训练统计，是训练 worker 的主入口。
 * - Purpose: Executes batch sample-training jobs, feeds file chunks into the scanner client for training, and continuously reports totals, progress, and training stats back to the main thread, serving as the primary entry of the training worker.
 * - 调用方: `parentPort.on('message')` 在收到 `type === 'train'` 的消息时调用。
 * - Callers: Called by `parentPort.on('message')` when a message with `type === 'train'` arrives.
 * - 被调方: `postMessage`、`trainPaths`、`trainFromPath`、`appendWorkerTrace`、`normalizeErrorPayload`、`Array.isArray`。
 * - Callees: `postMessage`, `trainPaths`, `trainFromPath`, `appendWorkerTrace`, `normalizeErrorPayload`, `Array.isArray`.
 * - 变量说明: `m` 为主线程下发的训练消息；`files` 为待训练样本列表；`isWhite` 表示白样本/黑样本标签；`done/trained/failed` 分别累计进度与训练结果。
 * - Variables: `m` is the training message from the main thread; `files` is the sample list; `isWhite` marks white-vs-black labels; `done/trained/failed` accumulate progress and training outcomes.
 * - 接入方式: 通过主线程发送 `train` 消息接入；若新增批量训练模式，应优先扩展本函数中的分块与上报逻辑，而不是新增另一条平行训练链路。
 * - Integration: Integrate by sending a `train` message from the main thread; new batch-training modes should extend the chunking/reporting logic here rather than creating a parallel training flow.
 * - 错误处理: 每个样本或整个分块失败都会累计到 `failed` 并写入训练 trace，最终仍保证回传 `done` 结果，避免主线程等待不到终态消息。
 * - Error Handling: Per-file or per-chunk failures are counted in `failed` and written to the training trace, while a final `done` reply is still guaranteed so the main thread never waits forever for terminal state.
 * - 关键词: 批量训练 | batch training | trainPaths | 进度汇报 | progress report | 分块训练 | chunked training | 样本标签 | sample label | done结果 | terminal reply
 */
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
  let failed = 0
  const chunkSize = 2048
  for (let i = 0; i < files.length; i += chunkSize) {
    const chunk = files.slice(i, i + chunkSize)
    try {
      if (scannerClient && typeof scannerClient.trainPaths === 'function') {
        const r = await scannerClient.trainPaths(chunk, isWhite)
        const t = r && Number.isFinite(r.trained) ? r.trained : 0
        const f = r && Number.isFinite(r.failed) ? r.failed : 0
        trained += t
        failed += f
        done += chunk.length
        postMessage({ type: 'progress', total: files.length, done, current: chunk[chunk.length - 1] || '' })
        continue
      }
      for (const fp of chunk) {
        try {
          const r = await scannerClient.trainFromPath(fp, isWhite)
          if (r && r.ok) trained++
          else failed++
        } catch (e) {
          failed++
          appendWorkerTrace({ ts: Date.now(), source: 'training_worker_train_failed', file: fp, ...normalizeErrorPayload(e) })
        }
        done++
        postMessage({ type: 'progress', total: files.length, done, current: fp })
      }
    } catch (e) {
      failed += chunk.length
      done += chunk.length
      appendWorkerTrace({ ts: Date.now(), source: 'training_worker_train_failed', file: chunk[0] || '', ...normalizeErrorPayload(e) })
      postMessage({ type: 'progress', total: files.length, done, current: chunk[chunk.length - 1] || '' })
    }
  }
  postMessage({ type: 'done', result: { ok: trained > 0, total: files.length, trained, failed } })
}

/**
 * - 函数: `handleTrainOne`
 * - Function: `handleTrainOne`
 * - 作用: 执行单文件训练请求，适用于实时补充样本或手动训练单个目标，并把单文件训练结果以 `train_one_done` 回传主线程。
 * - Purpose: Executes a single-file training request for real-time sample supplementation or manual one-off training and reports the outcome back as `train_one_done`.
 * - 调用方: `parentPort.on('message')` 在收到 `type === 'train_one'` 的消息时调用。
 * - Callers: Called by `parentPort.on('message')` when a message with `type === 'train_one'` arrives.
 * - 被调方: `postMessage`、`trainFromPath`、`appendWorkerTrace`、`normalizeErrorPayload`、`Date.now`。
 * - Callees: `postMessage`, `trainFromPath`, `appendWorkerTrace`, `normalizeErrorPayload`, `Date.now`.
 * - 变量说明: `m` 为主线程下发的单文件训练消息；`file` 为目标样本路径；`isWhite` 表示训练标签；`cfg` 快照控制本次训练的扫描与训练参数。
 * - Variables: `m` is the single-file training message from the main thread; `file` is the target sample path; `isWhite` is the training label; the `cfg` snapshot controls scan and training parameters for this run.
 * - 接入方式: 通过主线程发送 `train_one` 消息接入；适合 UI 中的手动训练、快速修复或单样本增量训练场景。
 * - Integration: Integrate by sending a `train_one` message from the main thread; it fits manual training from the UI, quick fixes, or incremental single-sample training scenarios.
 * - 错误处理: 空路径会立即回传失败；训练异常会写入 trace 并返回 `ok: false`，保证主线程能得到明确单文件失败结果。
 * - Error Handling: Empty paths fail fast with an immediate reply; training exceptions are traced and returned as `ok: false`, guaranteeing an explicit single-file failure result to the main thread.
 * - 关键词: 单文件训练 | single-file training | train_one | 增量样本 | incremental sample | 手动训练 | manual training | 失败回包 | failure reply | trace logging
 */
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
