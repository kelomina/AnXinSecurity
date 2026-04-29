const path = require('path')
const fs = require('fs')
const os = require('os')
const { Worker, isMainThread } = require('worker_threads')
const crypto = require('crypto')
let koffi = null
let winapi = null
try { winapi = require('./winapi') } catch { winapi = null }

/**
 * - 函数: `createScannerClient`
 * - Function: `createScannerClient`
 * - 作用: 创建扫描客户端聚合对象，统一封装单文件扫描、批量扫描、训练、健康检查、任务中止、签名库版本管理以及可选 worker 池调度，是主进程与多个 worker 共享的扫描能力入口。
 * - Purpose: Creates the scanner client aggregate that centralizes file scanning, batch scanning, training, health checks, task aborting, signature-store versioning, and optional worker-pool scheduling for both the main process and worker consumers.
 * - 调用方: `main.js` 中的主进程扫描能力初始化，`workers/scan_worker.js`、`workers/training_worker.js`、`workers/etw_risk_worker.js` 中的轻量扫描实例创建。
 * - Callers: The main-process scanner bootstrap in `main.js`, plus the lightweight scanner instances created in `workers/scan_worker.js`, `workers/training_worker.js`, and `workers/etw_risk_worker.js`.
 * - 被调方: `getScannerCfg`、`resolveWorkerPoolSize`、`ensureWorkerPool`、`scanFile`、`scanBatch`、`health`、`control`、`abort`、`trainFromPath`、`persistSignatureStore` 等内部能力函数。
 * - Callees: Internal capabilities such as `getScannerCfg`, `resolveWorkerPoolSize`, `ensureWorkerPool`, `scanFile`, `scanBatch`, `health`, `control`, `abort`, `trainFromPath`, and `persistSignatureStore`.
 * - 变量说明: `getConfig` 为配置提供器，按需返回最新 `scanner/scan` 配置；`deps` 为依赖注入对象，可关闭 worker 池或替换底层能力；`active` 保存进行中的请求；`workerPool` 为批量扫描并发执行池；`workerSeq` 用于生成 worker 标识。
 * - Variables: `getConfig` is the config provider that returns the latest `scanner/scan` settings on demand; `deps` is the dependency-injection object used to disable the worker pool or swap lower-level capabilities; `active` tracks in-flight requests; `workerPool` manages concurrent batch workers; `workerSeq` generates worker identifiers.
 * - 接入方式: 通过 `const { createScannerClient } = require('./scanner_client')` 接入，并传入返回最新配置的函数；若在新 worker 中接入，建议复用 `disableWorkerPool: true` 模式，避免 worker 再次创建嵌套 worker 池。
 * - Integration: Import it with `const { createScannerClient } = require('./scanner_client')` and pass a function that returns the latest config; for new worker-side integrations, prefer `disableWorkerPool: true` to avoid spawning nested worker pools from inside workers.
 * - 错误处理: 采用工厂内局部兜底和子函数分散处理策略；工厂自身尽量保持可构造，具体扫描、训练、签名库读写错误延后到返回的接口方法中按请求粒度报告。
 * - Error Handling: Uses defensive guards in the factory and delegates detailed failure handling to the returned methods, keeping construction resilient while reporting scan, training, and signature-store errors per request.
 * - 关键词: 扫描客户端 | scanner client | 聚合根 | aggregate | 批量扫描 | batch scan | 训练 | training | 签名库 | signature store
 */
function createScannerClient(getConfig, deps = {}) {
  const active = new Map()
  let workerPool = null
  let workerSeq = 0

  /**
 * - 函数: `getScannerCfg`
 * - Function: `getScannerCfg`
 * - 作用: 从全局配置提供器读取扫描相关开关，并提炼出扫描客户端真正关心的运行时快照，例如超时、native 启用状态和优先级策略。
 * - Purpose: Reads scan-related switches from the global config provider and distills the runtime snapshot that the scanner client actually cares about, such as timeout, native enablement, and preference policy.
 * - 调用方: `canUseNative`、`canUseSignatureEngine` 以及其他需要快速判断扫描能力门禁的内部入口会调用本函数。
 * - Callers: Called by `canUseNative`, `canUseSignatureEngine`, and other internal gates that need a quick scanner-capability snapshot.
 * - 被调方: `Number.isFinite`。
 * - Callees: `Number.isFinite`.
 * - 变量说明: 无显式入参；`cfg` 为完整配置对象；`scanner` 为扫描配置分支；`nativeDll` 为 native DLL 子配置。
 * - Variables: No explicit parameters; `cfg` is the full config object; `scanner` is the scan-config branch; `nativeDll` is the native-DLL sub-config.
 * - 接入方式: 应作为扫描开关快照的统一读取入口；新能力不要自行从 `getConfig()` 重复抽取这些字段。
 * - Integration: It should remain the single read entry for scanner-toggle snapshots; new features should not re-extract the same fields from `getConfig()` on their own.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 扫描配置快照 | scanner config snapshot | timeout policy | native enabled | native prefer | runtime toggles | shared config view | gate input
 */
  function getScannerCfg() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const nativeDll = scanner && scanner.nativeDll ? scanner.nativeDll : {}
    const timeoutMs = Number.isFinite(scanner.timeoutMs) ? scanner.timeoutMs : 5000
    const nativeEnabled = nativeDll && nativeDll.enabled === false ? false : true
    const signatureEnabled = false
    const nativePrefer = nativeDll && nativeDll.prefer === true ? true : false
    return { timeoutMs, nativeEnabled, nativePrefer, signatureEnabled }
  }

  /**
 * - 函数: `resolveWorkerPoolSize`
 * - Function: `resolveWorkerPoolSize`
 * - 作用: 根据 CPU 数量、扫描 token 上限和调优配置计算主线程 worker 池的目标大小，避免批量扫描并发过高或过低。
 * - Purpose: Computes the target size of the main-thread worker pool from CPU count, scan-token limits, and tuning config so batch scanning does not run with overly high or low concurrency.
 * - 调用方: `ensureWorkerPool` 在准备初始化并发扫描池时调用。
 * - Callers: Called by `ensureWorkerPool` when it is about to initialize the concurrent scan pool.
 * - 被调方: `Array.isArray`、`Number.isFinite`、`Math.floor`、`Math.max`、`Math.min`。
 * - Callees: `Array.isArray`, `Number.isFinite`, `Math.floor`, `Math.max`, `Math.min`.
 * - 变量说明: 无显式入参；`scanner` 为扫描配置；`tuning` 为并发调优分支；`cpuCount` 为本机 CPU 核数；`size` 为最终池大小。
 * - Variables: No explicit parameters; `scanner` is the scan config; `tuning` is the concurrency-tuning branch; `cpuCount` is the local CPU core count; `size` is the final pool size.
 * - 接入方式: 应作为 worker 池大小决策的唯一入口；并发相关策略变更优先集中在这里。
 * - Integration: It should be the single decision point for worker-pool sizing; concurrency policy changes should be centralized here first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: worker池大小 | worker pool size | concurrency tuning | CPU-aware sizing | token limit | pool bounds | main-thread batch scan | dispatch parallelism
 */
  function resolveWorkerPoolSize() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const tuning = scanner && scanner.tuning ? scanner.tuning : {}
    const cpuCount = (os && typeof os.cpus === 'function' && Array.isArray(os.cpus())) ? os.cpus().length : 4
    const maxTokens = Number.isFinite(scanner.maxTokens) ? Math.floor(scanner.maxTokens) : cpuCount
    const minPool = Number.isFinite(tuning.minPoolSize) ? Math.floor(tuning.minPoolSize) : 1
    const maxPool = Number.isFinite(tuning.maxPoolSize) ? Math.floor(tuning.maxPoolSize) : Math.max(minPool, maxTokens)
    const base = Math.max(minPool, maxTokens)
    const size = Math.min(Math.max(maxPool, minPool), base)
    return Math.max(1, size)
  }

  /**
 * - 函数: `getWorkerConfigSnapshot`
 * - Function: `getWorkerConfigSnapshot`
 * - 作用: 提取适合传给扫描 worker 的轻量配置快照，只保留 `scanner` 与 `scan` 两个分支，避免把整个配置对象跨线程复制。
 * - Purpose: Extracts the lightweight config snapshot suitable for scan workers, keeping only the `scanner` and `scan` branches so the entire config object does not need to be copied across threads.
 * - 调用方: `scanBatch` 在向 worker 下发批量扫描任务前调用。
 * - Callers: Called by `scanBatch` before dispatching batch-scan work to a worker.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；`cfg` 为完整配置对象，函数只裁剪出 worker 扫描实际需要的两段配置。
 * - Variables: No explicit parameters; `cfg` is the full config object, and the function trims it down to the two branches the worker scan path actually needs.
 * - 接入方式: 应作为跨线程扫描配置裁剪的统一入口；新的 worker 消费字段应在这里显式加入。
 * - Integration: It should be the single trim point for cross-thread scan config; if workers need new config fields, add them here explicitly.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: worker配置快照 | worker config snapshot | cross-thread config | scan task payload | trimmed config | scanner branch | scan branch | worker handoff
 */
  function getWorkerConfigSnapshot() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    return {
      scanner: cfg && cfg.scanner ? cfg.scanner : {},
      scan: cfg && cfg.scan ? cfg.scan : {}
    }
  }

  /**
 * - 函数: `createWorkerPool`
 * - Function: `createWorkerPool`
 * - 作用: 创建扫描 worker 池的内存结构，并立即拉起指定数量的 worker 实例，为后续批量扫描任务分发准备可复用执行器。
 * - Purpose: Creates the in-memory structure of the scan worker pool and immediately spawns the requested number of workers so later batch scans have reusable executors ready.
 * - 调用方: `ensureWorkerPool` 在首次需要并发扫描时调用。
 * - Callers: Called by `ensureWorkerPool` the first time concurrent scanning is needed.
 * - 被调方: `createWorker`。
 * - Callees: `createWorker`.
 * - 变量说明: `size` 为目标 worker 数量；`pool` 保存 worker 列表和待执行队列；`i` 为启动 worker 时的序号。
 * - Variables: `size` is the target worker count; `pool` stores the worker list and pending queue; `i` is the ordinal used while spawning workers.
 * - 接入方式: 仅作为 worker 池初始化步骤使用；外部不要直接手工构造 `pool` 结构。
 * - Integration: Use it only for worker-pool initialization; outer layers should not handcraft the `pool` structure directly.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 创建worker池 | create worker pool | reusable executors | batch dispatch pool | queue bootstrap | spawn workers | scan concurrency | pool initialization
 */
  function createWorkerPool(size) {
    const pool = { size, workers: [], queue: [] }
    for (let i = 0; i < size; i++) {
      createWorker(pool, i)
    }
    return pool
  }

  /**
 * - 函数: `createWorker`
 * - Function: `createWorker`
 * - 作用: 创建单个扫描 worker，并把“完成消息处理、异常重建、任务回收”这一整套生命周期绑定到池中，是 worker 池自愈的最小单元。
 * - Purpose: Creates one scan worker and wires in the full lifecycle of completion handling, crash recovery, and task cleanup, serving as the smallest self-healing unit of the worker pool.
 * - 调用方: `createWorkerPool` 在池初始化时调用，worker 崩溃后的重建路径也会再次调用本函数。
 * - Callers: Called by `createWorkerPool` during pool bootstrap and also reused when a crashed worker needs to be recreated.
 * - 被调方: `clearActive`、`processNext`、`push`、`path.join`、`Array.isArray`。
 * - Callees: `clearActive`, `processNext`, `push`, `path.join`, `Array.isArray`.
 * - 变量说明: `pool` 为所属 worker 池；`id` 为 worker 编号；`workerPath` 为 `scan_worker.js` 路径；`wObj` 为池内维护的 worker 状态对象。
 * - Variables: `pool` is the owning worker pool; `id` is the worker id; `workerPath` points to `scan_worker.js`; `wObj` is the per-worker state object stored in the pool.
 * - 接入方式: 仅用于 worker 池内部管理；新的 worker 类型不要复用本函数直接创建，除非它遵守相同的消息协议。
 * - Integration: Use it only for internal worker-pool management; new worker types should not call this helper unless they follow the same message protocol.
 * - 错误处理: 内部通过 `try/catch` 拦截局部异常；无法自行恢复时，会把错误继续抛给上游调用方处理。
 * - Error Handling: Uses `try/catch` to intercept local failures and rethrows or rejects unrecoverable errors back to upstream callers.
 * - 关键词: 单worker生命周期 | single worker lifecycle | crash recovery | task cleanup | scan_worker binding | pool self-healing | message handler | worker restart
 */
  function createWorker(pool, id) {
    const workerPath = path.join(__dirname, 'workers', 'scan_worker.js')
    const worker = new Worker(workerPath)
    const wObj = { worker, busy: false, id, currentTask: null }

    worker.on('message', (msg) => {
      const m = msg && typeof msg === 'object' ? msg : {}
      if (m.type !== 'scan_batch_done') return
      const task = wObj.currentTask
      wObj.busy = false
      wObj.currentTask = null
      if (task && !task.done) {
        task.done = true
        if (task.requestId && task.clearActiveOnDone) clearActive(task.requestId)
        if (task.canceled) {
          task.resolve([])
        } else if (m.ok === false) {
          const e = new Error((m.error && typeof m.error === 'string') ? m.error : 'SCAN_FAILED')
          task.reject(e)
        } else {
          task.resolve(Array.isArray(m.results) ? m.results : [])
        }
      }
      processNext(pool)
    })

    worker.on('error', (err) => {
      const task = wObj.currentTask
      wObj.busy = false
      wObj.currentTask = null
      if (task && !task.done) {
        task.done = true
        if (task.requestId && task.clearActiveOnDone) clearActive(task.requestId)
        task.reject(err || new Error('WORKER_ERROR'))
      }
      try { worker.terminate() } catch {}
      pool.workers = pool.workers.filter(w => w.id !== id)
      createWorker(pool, id)
      processNext(pool)
    })

    pool.workers.push(wObj)
  }

  /**
 * - 函数: `processNext`
 * - Function: `processNext`
 * - 作用: 从 worker 池队列中取出下一个待执行批次，并派发给空闲 worker；同时负责跳过已取消任务和维护请求完成态。
 * - Purpose: Pulls the next pending batch from the worker-pool queue and dispatches it to an idle worker while also skipping cancelled work and maintaining request completion state.
 * - 调用方: `createWorker` 在 worker 释放后调用，`scanBatch` 在新任务入队后也会调用。
 * - Callers: Called by `createWorker` after a worker becomes free and by `scanBatch` after new work is enqueued.
 * - 被调方: `clearActive`、`postMessage`。
 * - Callees: `clearActive`, `postMessage`.
 * - 变量说明: `pool` 为 worker 池；`availableWorker` 为当前找到的空闲执行器；`task` 为即将派发的批次任务。
 * - Variables: `pool` is the worker pool; `availableWorker` is the idle executor found for dispatch; `task` is the batch task about to be scheduled.
 * - 接入方式: 仅作为 worker 池调度器使用；任何批量扫描入队后都应通过本函数触发继续调度。
 * - Integration: Use it only as the worker-pool scheduler; every enqueued batch-scan task should rely on it to continue dispatching.
 * - 错误处理: 内部通过 `try/catch` 拦截局部异常；无法自行恢复时，会把错误继续抛给上游调用方处理。
 * - Error Handling: Uses `try/catch` to intercept local failures and rethrows or rejects unrecoverable errors back to upstream callers.
 * - 关键词: 队列调度 | queue dispatch | idle worker pickup | batch task handoff | cancel skip | request completion | worker scheduler | postMessage dispatch
 */
  function processNext(pool) {
    if (!pool) return
    while (pool.queue.length > 0) {
      const availableWorker = pool.workers.find(w => !w.busy)
      if (!availableWorker) return
      const task = pool.queue.shift()
      if (!task) return
      if (task.canceled || task.done) {
        if (!task.done) {
          task.done = true
          if (task.requestId && task.clearActiveOnDone) clearActive(task.requestId)
          task.resolve([])
        }
        continue
      }
      availableWorker.busy = true
      availableWorker.currentTask = task
      task.started = true
      try {
        availableWorker.worker.postMessage({
          type: 'scan_batch',
          taskId: task.id,
          requestId: task.requestId,
          filePaths: task.filePaths,
          config: task.config
        })
      } catch (e) {
        availableWorker.busy = false
        availableWorker.currentTask = null
        task.done = true
        if (task.requestId) clearActive(task.requestId)
        task.reject(e)
        continue
      }
    }
  }

  /**
   * - 函数: `ensureWorkerPool`
   * - Function: `ensureWorkerPool`
   * - 作用: 为批量扫描能力按需初始化并复用主线程 worker 池，让 `scanBatch` 在主进程中能够并发分发任务，同时避免在 worker 内再嵌套创建子 worker 池。
   * - Purpose: Lazily initializes and reuses the main-thread worker pool for batch scanning so `scanBatch` can fan out work in parallel while avoiding nested worker pools inside worker contexts.
   * - 调用方: `scanBatch` 在准备进入并行扫描分支时调用。
   * - Callers: Called by `scanBatch` when it is about to enter the parallel batch-scan path.
   * - 被调方: `resolveWorkerPoolSize`、`createWorkerPool`。
   * - Callees: `resolveWorkerPoolSize`, `createWorkerPool`.
   * - 变量说明: 无显式入参；闭包变量 `workerPool` 缓存已创建的池实例；`size` 为根据当前配置计算出的并发 worker 数量；`deps.disableWorkerPool` 表示显式禁用并行池。
   * - Variables: No explicit parameters; the closure variable `workerPool` caches the pool instance, `size` is the configured worker count, and `deps.disableWorkerPool` explicitly disables pool usage.
   * - 接入方式: 仅作为 `createScannerClient` 内部基础设施使用；若新增批量扫描变体，应先调用本函数判断是否能走并行分支，而不是直接访问 `workerPool` 闭包状态。
   * - Integration: Use it only as internal infrastructure inside `createScannerClient`; new batch-scan variants should call this function first to decide whether parallel execution is available instead of touching the `workerPool` closure directly.
   * - 错误处理: 通过守卫条件直接返回 `null` 表示当前环境不适合创建 worker 池，例如处于非主线程或显式关闭池化；底层创建异常不在此处吞掉，而是继续向上传递给批量扫描流程处理。
   * - Error Handling: It returns `null` through guard clauses when the environment should not create a worker pool, such as non-main-thread usage or explicit pool disablement; creation failures are not swallowed here and bubble up to the batch-scan flow.
   * - 关键词: 工作池复用 | worker pool reuse | 主线程并发 | main-thread concurrency | 批量调度 | batch dispatch | 禁用池化 | disable pooling | 嵌套worker | nested workers
   */
  function ensureWorkerPool() {
    if (!isMainThread || deps.disableWorkerPool) return null
    if (workerPool) return workerPool
    const size = resolveWorkerPoolSize()
    workerPool = createWorkerPool(size)
    return workerPool
  }

  /**
 * - 函数: `resolveErrorLogDir`
 * - Function: `resolveErrorLogDir`
 * - 作用: 解析扫描链路 trace/error 日志目录，并在缺失时自动创建 `data/logs/crash`，保证本地诊断日志有稳定落点。
 * - Purpose: Resolves the directory for scan trace/error logs and auto-creates `data/logs/crash` when missing so local diagnostic logs always have a stable destination.
 * - 调用方: `appendScannerTrace` 在落盘 trace 或 error 日志前调用。
 * - Callers: Called by `appendScannerTrace` before persisting trace or error logs.
 * - 被调方: `path.join`、`fs.existsSync`、`fs.mkdirSync`。
 * - Callees: `path.join`, `fs.existsSync`, `fs.mkdirSync`.
 * - 变量说明: 无显式入参；`base` 为项目根附近的上层目录；`dir` 为实际日志目录路径。
 * - Variables: No explicit parameters; `base` is the upper project-relative base directory; `dir` is the actual log directory path.
 * - 接入方式: 应作为扫描诊断日志目录的统一解析入口；新增本地 trace 文件不要自行散落到其他路径。
 * - Integration: It should be the single path resolver for scanner diagnostic logs; new local trace files should not scatter into unrelated paths.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 诊断日志目录 | diagnostic log dir | crash trace path | local error logs | ensure log folder | scanner trace sink | stable log destination | data logs crash
 */
  function resolveErrorLogDir() {
    const base = path.join(__dirname, '../../')
    const dir = path.join(base, 'data', 'logs', 'crash')
    try { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }) } catch {}
    return dir
  }

  /**
 * - 函数: `normalizeErrorPayload`
 * - Function: `normalizeErrorPayload`
 * - 作用: 把字符串、异常对象或空值统一折叠成 `{ message, stack }` 结构，便于 trace 与错误上报在不同来源下保持同一协议。
 * - Purpose: Folds strings, exception objects, or empty values into a shared `{ message, stack }` structure so trace logging and error reporting keep one protocol across different sources.
 * - 调用方: `ensureKvdLibraryLoaded`、`ensureSignatureLibraryLoaded`、`ensureKvdHandle`、`ensureSignatureHandle`、`kvdScanPaths` 等需要记录异常摘要的入口会调用本函数。
 * - Callers: Called by `ensureKvdLibraryLoaded`, `ensureSignatureLibraryLoaded`, `ensureKvdHandle`, `ensureSignatureHandle`, `kvdScanPaths`, and other entries that need a summarized error payload.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `err` 为原始错误来源，可能是 `Error`、字符串或空值。
 * - Variables: `err` is the raw error source and may be an `Error`, a string, or an empty value.
 * - 接入方式: 应作为扫描客户端错误摘要格式化的统一入口；新的 trace 上报路径优先复用本函数。
 * - Integration: It should be the single formatter for scanner-client error summaries; new trace-reporting paths should reuse it first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 错误摘要标准化 | error payload normalization | message stack pair | trace-ready error | exception folding | shared error schema | logging input | diagnostic payload
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
 * - 函数: `appendScannerTrace`
 * - Function: `appendScannerTrace`
 * - 作用: 以 JSON 行格式把扫描 trace 或 error 事件追加到本地日志文件，作为 native 装载、句柄创建、扫描失败和训练失败的离线诊断底座。
 * - Purpose: Appends scan trace or error events to local log files in JSON-lines format, providing the offline diagnostic foundation for native loading, handle creation, scan failures, and training failures.
 * - 调用方: `trace` 统一封装后调用本函数落盘。
 * - Callers: Called by `trace` after trace payloads are standardized.
 * - 被调方: `resolveErrorLogDir`、`path.join`、`JSON.stringify`、`fs.appendFileSync`。
 * - Callees: `resolveErrorLogDir`, `path.join`, `JSON.stringify`, `fs.appendFileSync`.
 * - 变量说明: `payload` 为待写入的 trace 事件；`dir` 为日志目录；`isError` 表示事件是否应进入 `error.log` 而不是 `trace.log`。
 * - Variables: `payload` is the trace event to persist; `dir` is the log directory; `isError` decides whether the event goes to `error.log` instead of `trace.log`.
 * - 接入方式: 应作为扫描链本地 trace 落盘的唯一出口；新的诊断事件不要直接写文件。
 * - Integration: It should be the single file-writing exit for local scanner traces; new diagnostic events should not write files directly.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: JSON行trace | JSONL trace | local scanner logs | error.log trace.log | offline diagnostics | append-only logging | native failure trail | persistent trace sink
 */
  function appendScannerTrace(payload) {
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

  /**
 * - 函数: `trace`
 * - Function: `trace`
 * - 作用: 为扫描事件补上统一时间戳、来源和阶段名，再交给底层日志链路，形成主扫描引擎的标准 trace 事件。
 * - Purpose: Adds a shared timestamp, source tag, and stage name to scan events before handing them to the logging path, forming the standard trace event shape of the main scan engine.
 * - 调用方: `ensureKvdLibraryLoaded`、`ensureKvdHandle`、`kvdHealth`、`kvdScanFile` 等主扫描链路节点会调用本函数。
 * - Callers: Called by main scan-chain nodes such as `ensureKvdLibraryLoaded`, `ensureKvdHandle`, `kvdHealth`, and `kvdScanFile`.
 * - 被调方: `appendScannerTrace`、`Date.now`、`Object.assign`。
 * - Callees: `appendScannerTrace`, `Date.now`, `Object.assign`.
 * - 变量说明: `stage` 为阶段名；`data` 为附加上下文；`base` 为标准公共字段；`payload` 为最终写入日志的事件对象。
 * - Variables: `stage` is the stage name; `data` carries extra context; `base` is the standard shared field set; `payload` is the final event object written to logs.
 * - 接入方式: 应作为主扫描 trace 事件的统一入口；新增 trace 事件优先从这里进入。
 * - Integration: It should be the single entry for main scanner trace events; new trace events should flow through it first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 主扫描trace | main scan trace | stage logging | timestamped event | scanner_native source | structured trace | common event schema | trace entrypoint
 */
  function trace(stage, data) {
    const base = { ts: Date.now(), source: 'scanner_native', stage }
    const payload = (data && typeof data === 'object') ? Object.assign(base, data) : base
    appendScannerTrace(payload)
  }

  const signatureEngineName = '渡鸦'
  const signatureEngineKey = 'raven'

  /**
 * - 函数: `traceSig`
 * - Function: `traceSig`
 * - 作用: 在主 trace 事件上补充签名引擎名称与 engine key，把 Raven 相关扫描和训练事件统一打到同一条诊断轨迹中。
 * - Purpose: Adds the signature-engine name and engine key on top of the main trace event so Raven-related scans and training events land in one coherent diagnostic stream.
 * - 调用方: `ensureSignatureLibraryLoaded`、`ensureSignatureHandle`、`kvdScanFileSig`、`kvdScanPathsSig`、`kvdTrainFromPathSig` 等签名链入口会调用本函数。
 * - Callers: Called by signature-chain entries such as `ensureSignatureLibraryLoaded`, `ensureSignatureHandle`, `kvdScanFileSig`, `kvdScanPathsSig`, and `kvdTrainFromPathSig`.
 * - 被调方: `trace`、`Object.assign`。
 * - Callees: `trace`, `Object.assign`.
 * - 变量说明: `stage` 为签名阶段名；`data` 为附加上下文；`extra` 为统一注入的引擎标识；`payload` 为最终转给 `trace` 的对象。
 * - Variables: `stage` is the signature-stage name; `data` is extra context; `extra` is the injected engine identity; `payload` is the final object forwarded to `trace`.
 * - 接入方式: 应作为 Raven 相关 trace 的统一入口；新增签名诊断事件优先使用本函数。
 * - Integration: It should be the single entry for Raven-related trace events; new signature diagnostics should prefer this helper.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 签名trace | signature trace | Raven diagnostics | engine identity tag | shared logging stream | signature scan trace | training trace | trace wrapper
 */
  function traceSig(stage, data) {
    const extra = { engine: signatureEngineName, engine_key: signatureEngineKey }
    const payload = (data && typeof data === 'object') ? Object.assign(extra, data) : extra
    trace(stage, payload)
  }

  /**
 * - 函数: `isLikelyPeFile`
 * - Function: `isLikelyPeFile`
 * - 作用: 判断可能性PE 文件文件条件是否成立，并返回布尔化结果供上游守卫分支使用。
 * - Purpose: Checks whether the likelihood PE file file condition is satisfied and returns a boolean-style result for upstream guards.
 * - 调用方: `extractRavenFeatures` 在区分 PE 与脚本/普通二进制样本时调用；`kvdTrainFromPath` 与 `kvdTrainFromPathSig` 在 native 训练前用它过滤非 PE 样本。
 * - Callers: Called by `extractRavenFeatures` when distinguishing PE from script/plain binary samples, and by `kvdTrainFromPath` plus `kvdTrainFromPathSig` to filter non-PE samples before native training.
 * - 被调方: `fs.statSync`、`fs.openSync`、`Buffer.alloc`、`fs.readSync`、`Number.isFinite`。
 * - Callees: `fs.statSync`, `fs.openSync`, `Buffer.alloc`, `fs.readSync`, `Number.isFinite`.
 * - 变量说明: `filePath` 为当前流程传入的文件路径；`fd`, `st` 为函数内部派生的中间状态。
 * - Variables: `filePath` is the incoming file path for this flow; `fd`, `st` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `isLikelyPeFile`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `isLikelyPeFile` through the existing returned object.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 判断 | 可能性 | PE 文件 | 文件 | check | likelihood | PE file | file | error handling | 复用
 */
  function isLikelyPeFile(filePath) {
    if (typeof filePath !== 'string' || !filePath) return false
    let fd = null
    try {
      const st = fs.statSync(filePath)
      if (!st || !st.isFile() || st.size < 64) return false
      fd = fs.openSync(filePath, 'r')
      const head = Buffer.alloc(64)
      const read = fs.readSync(fd, head, 0, 64, 0)
      if (read < 64) return false
      if (head[0] !== 0x4d || head[1] !== 0x5a) return false
      const peOffset = head.readUInt32LE(0x3c)
      if (!Number.isFinite(peOffset) || peOffset < 0 || peOffset > st.size - 4) return false
      const sig = Buffer.alloc(4)
      const sigRead = fs.readSync(fd, sig, 0, 4, peOffset)
      if (sigRead < 4) return false
      return sig[0] === 0x50 && sig[1] === 0x45 && sig[2] === 0x00 && sig[3] === 0x00
    } catch {
      return false
    } finally {
      if (fd != null) {
        try { fs.closeSync(fd) } catch {}
      }
    }
  }

  /**
 * - 函数: `verifyTrusted`
 * - Function: `verifyTrusted`
 * - 作用: 验证受信任状态状态是否满足当前策略要求，并返回可信判断结果。
 * - Purpose: Verifies whether the trusted state state satisfies the current policy and returns a trust decision.
 * - 调用方: `scanRavenByStore` 在 JS 特征库判定前调用；`kvdScanFileSig` 与 `kvdScanPathsSig` 在 native 签名扫描前先用它短路可信文件。
 * - Callers: Called by `scanRavenByStore` before JS-store matching, and by `kvdScanFileSig` plus `kvdScanPathsSig` to short-circuit trusted files ahead of native signature scanning.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `filePath` 为当前流程传入的文件路径。
 * - Variables: `filePath` is the incoming file path for this flow.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `verifyTrusted`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `verifyTrusted` through the existing returned object.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 验证 | 受信任状态 | verify | trusted state | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function verifyTrusted(filePath) {
    if (!winapi || typeof winapi.verifyTrust !== 'function') return false
    try { return winapi.verifyTrust(filePath) === true } catch { return false }
  }

  let kvd = {
    lib: null,
    create: null,
    destroy: null,
    scanPath: null,
    scanPaths: null,
    scanBytes: null,
    trainFromPath: null,
    free: null,
    validateModels: null,
    configType: null,
    cfgPtr: null,
    handle: null,
    inited: false,
    loadError: '',
    scanPathsMissingLogged: false
  }
  let kvdSig = {
    lib: null,
    create: null,
    destroy: null,
    scanPath: null,
    scanPaths: null,
    scanBytes: null,
    trainFromPath: null,
    free: null,
    validateModels: null,
    configType: null,
    cfgPtr: null,
    handle: null,
    inited: false,
    loadError: '',
    scanPathsMissingLogged: false,
    scanPathsFailedLogged: false,
    scanPathsBroken: false
  }
  const traceState = { createSeq: 0, scanPathSeq: 0, scanPathsSeq: 0 }

  /**
 * - 函数: `fileExists`
 * - Function: `fileExists`
 * - 作用: 以安全布尔值方式判断路径是否存在，统一包住 `fs.existsSync` 的异常边界，供 DLL、模型和引擎目录查找链复用。
 * - Purpose: Safely checks whether a path exists as a boolean, wrapping the exception boundary of `fs.existsSync` for reuse by DLL, model, and engine-root lookup chains.
 * - 调用方: `resolveKvdDllPath`、`resolveSignatureDllPath`、`resolveEngineRoots`、`findFileInEngineRoots`、`resolveModelPath`、`resolveFamilyJsonPath` 等路径探测 helper 会调用本函数。
 * - Callers: Called by lookup helpers such as `resolveKvdDllPath`, `resolveSignatureDllPath`, `resolveEngineRoots`, `findFileInEngineRoots`, `resolveModelPath`, and `resolveFamilyJsonPath`.
 * - 被调方: `fs.existsSync`。
 * - Callees: `fs.existsSync`.
 * - 变量说明: `p` 为待检测路径。
 * - Variables: `p` is the path being tested.
 * - 接入方式: 应作为本文件内部存在性检测的统一 helper；新路径探测逻辑优先复用本函数。
 * - Integration: It should remain the shared existence-check helper inside this file; new path-probing logic should reuse it.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 安全存在性检测 | safe exists check | fs.existsSync wrapper | path probe | no throw helper | DLL lookup | model lookup | boolean existence
 */
  function fileExists(p) {
    try {
      return !!(p && fs.existsSync(p))
    } catch {
      return false
    }
  }

  /**
 * - 函数: `resolveKvdDllPath`
 * - Function: `resolveKvdDllPath`
 * - 作用: 按“安装资源目录 -> 源码目录 -> 当前工作目录”的优先级查找 Axon/KVD 主扫描 DLL，兼容打包态与开发态路径差异。
 * - Purpose: Locates the Axon/KVD primary scan DLL in the priority order of “packaged resources -> source tree -> current working directory,” covering both packaged and development layouts.
 * - 调用方: `ensureKvdLibraryLoaded` 在尝试加载主扫描引擎前调用。
 * - Callers: Called by `ensureKvdLibraryLoaded` before it attempts to load the primary scan engine.
 * - 被调方: `push`、`fileExists`、`path.join`。
 * - Callees: `push`, `fileExists`, `path.join`.
 * - 变量说明: 无显式入参；`candidates` 为按优先级收集的候选 DLL 路径列表；`p` 为当前正在尝试的候选路径。
 * - Variables: No explicit parameters; `candidates` is the priority-ordered list of candidate DLL paths; `p` is the path currently being tested.
 * - 接入方式: 应作为 Axon/KVD DLL 的统一定位入口；主扫描引擎装载前不要自行遍历路径。
 * - Integration: It should be the single locator for the Axon/KVD DLL; scan-engine loaders should not perform independent path searches beforehand.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: Axon DLL 定位 | Axon DLL resolution | KVD loader path | packaged vs dev path | native scan engine DLL | candidate search | engine bootstrap | DLL fallback order
 */
  function resolveKvdDllPath() {
    const candidates = []
    try {
      if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Axon', 'Release', 'axon_engine.dll'))
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Axon', 'axon_engine.dll'))
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Axon', 'kvd.dll'))
      }
    } catch {}
    try {
      candidates.push(path.join(__dirname, '../../Engine/Axon/Release/axon_engine.dll'))
      candidates.push(path.join(__dirname, '../../Engine/Axon/axon_engine.dll'))
      candidates.push(path.join(__dirname, '../../Engine/Axon/kvd.dll'))
    } catch {}
    try {
      candidates.push(path.join(process.cwd(), 'Engine', 'Axon', 'Release', 'axon_engine.dll'))
      candidates.push(path.join(process.cwd(), 'Engine', 'Axon', 'axon_engine.dll'))
      candidates.push(path.join(process.cwd(), 'Engine', 'Axon', 'kvd.dll'))
    } catch {}
    for (const p of candidates) {
      if (fileExists(p)) return p
    }
    return null
  }

  /**
 * - 函数: `resolveSignatureDllPath`
 * - Function: `resolveSignatureDllPath`
 * - 作用: 按打包目录、源码目录和工作目录的顺序查找 Raven/Signature DLL，兼容多套目录命名与历史文件名。
 * - Purpose: Resolves the Raven/Signature DLL by searching packaged, source-tree, and working-directory locations in order, while remaining compatible with multiple directory names and legacy filenames.
 * - 调用方: `ensureSignatureLibraryLoaded` 在加载签名引擎前调用。
 * - Callers: Called by `ensureSignatureLibraryLoaded` before loading the signature engine.
 * - 被调方: `push`、`fileExists`、`path.join`。
 * - Callees: `push`, `fileExists`, `path.join`.
 * - 变量说明: 无显式入参；`candidates` 为签名引擎 DLL 候选路径列表；`p` 为当前尝试的候选路径。
 * - Variables: No explicit parameters; `candidates` is the candidate path list for the signature-engine DLL; `p` is the candidate currently being tested.
 * - 接入方式: 应作为签名 DLL 的统一定位入口；签名引擎加载链不要自行拼路径。
 * - Integration: It should be the single locator for the signature DLL; signature-engine loading paths should not rebuild candidate paths on their own.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: Raven DLL 定位 | Raven DLL resolution | signature engine DLL | packaged dev fallback | legacy filename support | candidate search | native signature bootstrap | DLL path chooser
 */
  function resolveSignatureDllPath() {
    const candidates = []
    try {
      if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Raven', 'signature_engine.dll'))
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Signature', 'Release', 'signature_engine.dll'))
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Signature', 'signature_engine.dll'))
        candidates.push(path.join(process.resourcesPath, 'Engine', 'Raven', 'raven_engine.dll'))
      }
    } catch {}
    try {
      candidates.push(path.join(__dirname, '../../Engine/Raven/signature_engine.dll'))
      candidates.push(path.join(__dirname, '../../Engine/Signature/Release/signature_engine.dll'))
      candidates.push(path.join(__dirname, '../../Engine/Signature/signature_engine.dll'))
      candidates.push(path.join(__dirname, '../../Engine/Raven/raven_engine.dll'))
    } catch {}
    try {
      candidates.push(path.join(process.cwd(), 'Engine', 'Raven', 'signature_engine.dll'))
      candidates.push(path.join(process.cwd(), 'Engine', 'Signature', 'Release', 'signature_engine.dll'))
      candidates.push(path.join(process.cwd(), 'Engine', 'Signature', 'signature_engine.dll'))
      candidates.push(path.join(process.cwd(), 'Engine', 'Raven', 'raven_engine.dll'))
    } catch {}
    for (const p of candidates) {
      if (fileExists(p)) return p
    }
    return null
  }

  /**
 * - 函数: `resolveEngineRoots`
 * - Function: `resolveEngineRoots`
 * - 作用: 收集所有可能的 `Engine/` 根目录候选，为后续递归查找模型、DLL 或附属资源文件提供统一搜索起点。
 * - Purpose: Collects all possible `Engine/` root-directory candidates so later recursive searches for models, DLLs, or ancillary resources share one common starting set.
 * - 调用方: `findFileInEngineRoots` 在做深度查找前调用。
 * - Callers: Called by `findFileInEngineRoots` before it performs recursive search.
 * - 被调方: `fileExists`、`push`、`path.join`。
 * - Callees: `fileExists`, `push`, `path.join`.
 * - 变量说明: 无显式入参；`roots` 为可用引擎根目录集合；`p` 为当前尝试加入集合的候选目录。
 * - Variables: No explicit parameters; `roots` is the set of usable engine roots; `p` is the candidate directory currently being tested for inclusion.
 * - 接入方式: 应作为引擎目录搜索的统一入口；递归文件搜索不要各自重新推导根目录。
 * - Integration: It should be the single entry for engine-directory discovery; recursive file searchers should not infer roots independently.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: Engine根目录集合 | Engine root set | packaged source cwd roots | recursive search roots | resource discovery | shared search base | engine assets | root candidates
 */
  function resolveEngineRoots() {
    const roots = []
    try {
      if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
        const p = path.join(process.resourcesPath, 'Engine')
        if (fileExists(p)) roots.push(p)
      }
    } catch {}
    try {
      const p = path.join(__dirname, '../../Engine')
      if (fileExists(p)) roots.push(p)
    } catch {}
    try {
      const p = path.join(process.cwd(), 'Engine')
      if (fileExists(p)) roots.push(p)
    } catch {}
    return roots
  }

  /**
 * - 函数: `isDirectory`
 * - Function: `isDirectory`
 * - 作用: 判断目录条件是否成立，并返回布尔化结果供上游守卫分支使用。
 * - Purpose: Checks whether the directory condition is satisfied and returns a boolean-style result for upstream guards.
 * - 调用方: `findFileInEngineRoots` 在广度优先遍历 `Engine/` 目录树时调用，用它过滤掉非目录节点。
 * - Callers: Called by `findFileInEngineRoots` while traversing the `Engine/` directory tree breadth-first to filter out non-directory nodes.
 * - 被调方: `fs.statSync`。
 * - Callees: `fs.statSync`.
 * - 变量说明: `p` 为当前流程传入的p；`st` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `st` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `isDirectory`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `isDirectory` through the existing returned object.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 判断 | 目录 | check | directory | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function isDirectory(p) {
    try {
      const st = fs.statSync(p)
      return !!(st && st.isDirectory())
    } catch {
      return false
    }
  }

  /**
 * - 函数: `findFileInEngineRoots`
 * - Function: `findFileInEngineRoots`
 * - 作用: 在 `Engine/` 根目录集合下按受限深度递归搜索目标文件，并只在指定子目录命中时返回结果，用于兼容打包后目录漂移。
 * - Purpose: Recursively searches for a target file under the `Engine/` root set with bounded depth and returns a hit only when it appears inside selected subdirectories, helping tolerate directory drift after packaging.
 * - 调用方: 动态定位附属模型或资源文件的内部查找链会调用本函数。
 * - Callers: Called by internal lookup chains that need to locate auxiliary models or resource files dynamically.
 * - 被调方: `resolveEngineRoots`、`isDirectory`、`fileExists`、`push`、`Array.isArray`、`fs.readdirSync`。
 * - Callees: `resolveEngineRoots`, `isDirectory`, `fileExists`, `push`, `Array.isArray`, `fs.readdirSync`.
 * - 变量说明: `fileName` 为目标文件名；`targetDirs` 为优先命中的目录名集合；`roots` 为可搜索引擎根目录；`dirSet` 为小写化后的目标目录集合。
 * - Variables: `fileName` is the target filename; `targetDirs` is the preferred directory-name set; `roots` is the set of searchable engine roots; `dirSet` is the lowercased target-directory set.
 * - 接入方式: 应作为“已知文件名但未知具体层级”的统一查找器使用；新增资源探测逻辑可优先复用本函数。
 * - Integration: It should be used as the shared finder when the filename is known but the exact directory depth is not; new asset-probing logic can reuse it first.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 引擎目录递归查找 | recursive Engine search | bounded depth lookup | target subdir filter | packaged path drift | asset finder | model discovery | directory walk
 */
  function findFileInEngineRoots(fileName, targetDirs) {
    const roots = resolveEngineRoots()
    const dirSet = new Set(Array.isArray(targetDirs) ? targetDirs.map(s => String(s).toLowerCase()) : [])
    const skip = new Set(['node_modules', 'dist', 'dist2', 'build', 'vcpkg', '.git', '.storybook', 'docs'])
    const maxDepth = 6
    for (const root of roots) {
      if (!isDirectory(root)) continue
      const queue = [{ dir: root, depth: 0 }]
      while (queue.length) {
        const { dir, depth } = queue.shift()
        if (depth > maxDepth) continue
        let entries = []
        try {
          entries = fs.readdirSync(dir, { withFileTypes: true })
        } catch {
          entries = []
        }
        for (const ent of entries) {
          if (!ent) continue
          const name = ent.name || ''
          const lower = name.toLowerCase()
          const full = path.join(dir, name)
          if (ent.isDirectory()) {
            if (skip.has(lower)) continue
            if (dirSet.has(lower)) {
              const fp = path.join(full, fileName)
              if (fileExists(fp)) return fp
            }
            if (depth + 1 <= maxDepth) queue.push({ dir: full, depth: depth + 1 })
          }
        }
      }
    }
    return ''
  }

  /**
 * - 函数: `resolveModelPath`
 * - Function: `resolveModelPath`
 * - 作用: 按多环境候选路径定位 Axon 主模型文件，供主扫描引擎环境变量和配置构造链复用。
 * - Purpose: Resolves Axon model files from multi-environment candidate paths so the main scan engine can reuse them in env-variable setup and config construction.
 * - 调用方: `ensureKvdEnv` 在准备模型路径环境变量时调用。
 * - Callers: Called by `ensureKvdEnv` when preparing model-path environment variables.
 * - 被调方: `push`、`fileExists`、`path.join`。
 * - Callees: `push`, `fileExists`, `path.join`.
 * - 变量说明: `rel` 为模型相对路径；`cands` 为候选绝对路径列表；`p` 为当前测试的候选路径。
 * - Variables: `rel` is the relative model path; `cands` is the list of candidate absolute paths; `p` is the candidate currently under test.
 * - 接入方式: 应作为 Axon 模型文件定位的统一入口；不同模型不要分散复制路径回退逻辑。
 * - Integration: It should be the shared locator for Axon model files; different models should not duplicate fallback path logic separately.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: Axon模型路径 | Axon model path | saved_models lookup | packaged dev fallback | model resolver | env bootstrap input | candidate path search | native model file
 */
  function resolveModelPath(rel) {
    const cands = []
    try {
      if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
        cands.push(path.join(process.resourcesPath, 'Engine', 'Axon', 'saved_models', rel))
      }
    } catch {}
    try {
      cands.push(path.join(__dirname, '../../Engine/Axon/saved_models', rel))
    } catch {}
    try {
      cands.push(path.join(process.cwd(), 'Engine', 'Axon', 'saved_models', rel))
    } catch {}
    for (const p of cands) {
      if (fileExists(p)) return p
    }
    return ''
  }

  /**
 * - 函数: `resolveFamilyJsonPath`
 * - Function: `resolveFamilyJsonPath`
 * - 作用: 定位家族分类器 `family_classifier.json`，供主扫描引擎在 native 侧补充家族识别或标签推断能力。
 * - Purpose: Resolves `family_classifier.json` so the primary scan engine can provide family classification or label inference on the native side.
 * - 调用方: `ensureKvdEnv` 在设置主扫描引擎环境变量时调用。
 * - Callers: Called by `ensureKvdEnv` while setting main-engine environment variables.
 * - 被调方: `push`、`fileExists`、`path.join`。
 * - Callees: `push`, `fileExists`, `path.join`.
 * - 变量说明: 无显式入参；`cands` 为家族分类器 JSON 候选路径；`p` 为当前测试路径。
 * - Variables: No explicit parameters; `cands` is the candidate-path list for the family-classifier JSON; `p` is the path currently being tested.
 * - 接入方式: 应作为家族分类器文件定位的统一入口；不要在别处重复拼接相同目录结构。
 * - Integration: It should be the shared locator for the family-classifier file; other code paths should not rebuild the same directory pattern independently.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: family分类器路径 | family classifier path | family_classifier.json | auxiliary model lookup | label inference asset | packaged dev fallback | shared resolver | engine env input
 */
  function resolveFamilyJsonPath() {
    const cands = []
    try {
      if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
        cands.push(path.join(process.resourcesPath, 'Engine', 'Axon', 'hdbscan_cluster_results', 'family_classifier.json'))
      }
    } catch {}
    try {
      cands.push(path.join(__dirname, '../../Engine/Axon/hdbscan_cluster_results/family_classifier.json'))
    } catch {}
    try {
      cands.push(path.join(process.cwd(), 'Engine', 'Axon', 'hdbscan_cluster_results', 'family_classifier.json'))
    } catch {}
    for (const p of cands) {
      if (fileExists(p)) return p
    }
    return ''
  }

  /**
 * - 函数: `ensureDir`
 * - Function: `ensureDir`
 * - 作用: 确保目标目录存在并可用于后续落盘，是签名库、native 模型文件和日志目录写入链上的基础准备步骤。
 * - Purpose: Ensures that a target directory exists and is writable for later persistence, serving as the basic preparation step for signature-store, native-model, and log-directory write paths.
 * - 调用方: `resolveSignatureStorePath`、`resolveSignatureNativeModelPath`、以及其他需要先保证目录存在的本地落盘链路会调用本函数。
 * - Callers: Called by `resolveSignatureStorePath`, `resolveSignatureNativeModelPath`, and other local persistence paths that must guarantee directory existence first.
 * - 被调方: `fs.mkdirSync`。
 * - Callees: `fs.mkdirSync`.
 * - 变量说明: `p` 为目标目录路径。
 * - Variables: `p` is the target directory path.
 * - 接入方式: 应作为本文件内部目录创建的统一 helper 使用；新的落盘链优先复用它。
 * - Integration: It should be the shared directory-creation helper inside this file; new persistence paths should reuse it first.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 目录确保存在 | ensure directory exists | mkdir recursive | persistence prerequisite | storage setup | safe dir creation | write path bootstrap | reusable helper
 */
  function ensureDir(p) {
    try {
      if (!p) return false
      fs.mkdirSync(p, { recursive: true })
      return true
    } catch {
      return false
    }
  }

  /**
 * - 函数: `resolveSignatureStorePath`
 * - Function: `resolveSignatureStorePath`
 * - 作用: 解析日志式 JS 签名库主文件路径，优先采用用户配置路径，缺省时回落到项目 `data/raven_signature.db`，作为版本追加、读取回放与索引构建的统一根文件。
 * - Purpose: Resolves the main file path of the append-only JS signature store, preferring a user-configured path and falling back to `data/raven_signature.db`, and acts as the shared root file for version appends, replay reads, and index construction.
 * - 调用方: `resolveSignatureIndexPath`、`persistSignatureStore`、`loadSignatureStore`、`listSignatureStoreVersions`、`getSignatureStoreCurrentVersion`、`rollbackSignatureStore`。
 * - Callers: Called by `resolveSignatureIndexPath`, `persistSignatureStore`, `loadSignatureStore`, `listSignatureStoreVersions`, `getSignatureStoreCurrentVersion`, and `rollbackSignatureStore`.
 * - 被调方: `ensureDir`、`root`、`path.dirname`、`path.join`。
 * - Callees: `ensureDir`, `root`, `path.dirname`, `path.join`.
 * - 变量说明: `scannerCfg` 为扫描配置；`cfgPath` 为用户显式指定的签名库存储路径；`dir` 为目标文件所在目录。
 * - Variables: `scannerCfg` is the scanner config; `cfgPath` is the explicitly configured signature-store path; `dir` is the directory containing the target file.
 * - 接入方式: 应作为 JS 签名库主文件路径的唯一解析入口；不要在其他读取/写入函数中重复拼接默认路径。
 * - Integration: It should remain the single path resolver for the JS signature-store file; other read/write helpers should not rebuild the default path independently.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 签名库主文件路径 | signature store file path | append-only DB | configured path fallback | data raven_signature.db | shared resolver | version root | store location
 */
  function resolveSignatureStorePath(scannerCfg) {
    const cfgPath = scannerCfg && typeof scannerCfg.signatureStorePath === 'string' ? scannerCfg.signatureStorePath : ''
    if (cfgPath) {
      const dir = path.dirname(cfgPath)
      if (ensureDir(dir)) return cfgPath
    }
    /**
 * - 函数: `root`
 * - Function: `root`
 * - 作用: 在未显式配置签名库路径时，把当前工作目录当作项目根目录候选，供默认 `data/*` 路径拼接使用。
 * - Purpose: Treats the current working directory as the project-root candidate when no explicit signature-store path is configured, so default `data/*` paths can be derived from it.
 * - 调用方: `resolveSignatureStorePath`、`resolveSignatureNativeModelPath`。
 * - Callers: `resolveSignatureStorePath`, `resolveSignatureNativeModelPath`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；`cwd` 为通过 `process.cwd()` 获取到的当前工作目录。
 * - Variables: No explicit parameters; `cwd` is the current working directory returned by `process.cwd()`.
 * - 接入方式: 仅作为路径回退逻辑中的内联 helper 使用；新的默认路径推导优先复用相同模式，而不是硬编码绝对路径。
 * - Integration: Use it only as an inline helper for path fallbacks; new default-path derivations should reuse the same pattern rather than hardcoding absolute paths.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 项目根目录候选 | project root candidate | cwd fallback | default data path | inline path helper | process.cwd | path derivation | storage fallback
 */
    const root = (() => {
      try {
        const cwd = process.cwd()
        if (cwd) return cwd
      } catch {}
      return ''
    })()
    if (!root) return ''
    const p = path.join(root, 'data', 'raven_signature.db')
    const dir = path.dirname(p)
    if (!ensureDir(dir)) return ''
    return p
  }

  /**
 * - 函数: `resolveSignatureNativeModelPath`
 * - Function: `resolveSignatureNativeModelPath`
 * - 作用: 解析 Raven/native 签名引擎使用的二进制模型路径，优先取用户配置 `signatureDbPath`，否则回退到项目 `data/anxin_signature_db.bin`。
 * - Purpose: Resolves the binary-model path used by the Raven/native signature engine, preferring the configured `signatureDbPath` and otherwise falling back to `data/anxin_signature_db.bin`.
 * - 调用方: `buildSignatureConfigValues` 在构造签名引擎配置时调用。
 * - Callers: Called by `buildSignatureConfigValues` while assembling the signature-engine config.
 * - 被调方: `ensureDir`、`root`、`path.dirname`、`path.join`。
 * - Callees: `ensureDir`, `root`, `path.dirname`, `path.join`.
 * - 变量说明: `scannerCfg` 为扫描配置；`cfgPath` 为用户指定的 native 模型路径；`dir` 为目标二进制模型所在目录。
 * - Variables: `scannerCfg` is the scanner config; `cfgPath` is the user-specified native model path; `dir` is the directory holding that binary model.
 * - 接入方式: 应作为签名 native 模型路径的统一解析入口；签名配置构造与健康检查不要自行拼路径。
 * - Integration: It should be the single resolver for the native signature-model path; signature config builders and health checks should not reconstruct the path independently.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 签名 native 模型路径 | signature native model path | anxin_signature_db.bin | configured binary model | path fallback | Raven model resolver | storage location | native engine input
 */
  function resolveSignatureNativeModelPath(scannerCfg) {
    const cfgPath = scannerCfg && typeof scannerCfg.signatureDbPath === 'string' ? scannerCfg.signatureDbPath : ''
    if (cfgPath) {
      const dir = path.dirname(cfgPath)
      if (ensureDir(dir)) return cfgPath
    }
    /**
 * - 函数: `root`
 * - Function: `root`
 * - 作用: 在未设置 `signatureDbPath` 时，从当前工作目录推导签名 native 模型的默认存放根目录。
 * - Purpose: Derives the default root directory for the native signature model from the current working directory when `signatureDbPath` is not configured.
 * - 调用方: `resolveSignatureStorePath`、`resolveSignatureNativeModelPath`。
 * - Callers: `resolveSignatureStorePath`, `resolveSignatureNativeModelPath`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；`cwd` 为当前工作目录，用作回退路径推导基础。
 * - Variables: No explicit parameters; `cwd` is the current working directory used as the fallback base for path derivation.
 * - 接入方式: 仅作为路径回退逻辑中的局部 helper 使用；其职责不是返回“仓库真实根目录”，而是提供默认落盘基准。
 * - Integration: Use it only as a local helper in fallback path logic; its job is not to discover the canonical repo root but to provide a default persistence base.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: native 模型默认根目录 | native model default root | cwd-derived path | fallback base | inline helper | default persistence base | project data dir | path assembly
 */
    const root = (() => {
      try {
        const cwd = process.cwd()
        if (cwd) return cwd
      } catch {}
      return ''
    })()
    if (!root) return ''
    const p = path.join(root, 'data', 'anxin_signature_db.bin')
    const dir = path.dirname(p)
    if (!ensureDir(dir)) return ''
    return p
  }

  /**
 * - 函数: `stableStringify`
 * - Function: `stableStringify`
 * - 作用: 以稳定键顺序递归序列化对象，消除普通 `JSON.stringify` 在对象键顺序上的不确定性，为特征码计算提供可重复的原始文本。
 * - Purpose: Recursively serializes objects with a stable key order, removing the non-determinism of ordinary `JSON.stringify` on object-key ordering and producing repeatable raw text for feature-code hashing.
 * - 调用方: `makeFeatureCode` 在生成特征 SHA-256 前调用。
 * - Callers: Called by `makeFeatureCode` before computing the feature SHA-256 hash.
 * - 被调方: `push`、`JSON.stringify`、`Array.isArray`。
 * - Callees: `push`, `JSON.stringify`, `Array.isArray`.
 * - 变量说明: `value` 为待序列化值；`keys` 为排序后的对象键列表；`parts` 为逐项拼装的稳定字段片段。
 * - Variables: `value` is the value being serialized; `keys` is the sorted object-key list; `parts` is the list of stable field fragments being concatenated.
 * - 接入方式: 应作为需要“稳定文本表示”的内部通用 helper 使用；不要在特征哈希链外随意替换成普通 `JSON.stringify`。
 * - Integration: It should serve as the shared internal helper wherever a stable textual representation is required; do not casually replace it with plain `JSON.stringify` in feature-hash paths.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 稳定序列化 | stable stringify | deterministic object text | sorted keys | feature hash input | repeatable serialization | canonical JSON | SHA source
 */
  function stableStringify(value) {
    if (value == null) return 'null'
    if (typeof value !== 'object') return JSON.stringify(value)
    if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']'
    const keys = Object.keys(value).sort()
    const parts = []
    for (const k of keys) {
      parts.push(JSON.stringify(k) + ':' + stableStringify(value[k]))
    }
    return '{' + parts.join(',') + '}'
  }

  const scriptExtSet = new Set(['.bat', '.cmd', '.ps1', '.js', '.vbs', '.wsf', '.hta', '.jse', '.vbe'])

  /**
 * - 函数: `getMaxFileSizeBytes`
 * - Function: `getMaxFileSizeBytes`
 * - 作用: 把配置中的 `maxFileSizeMB` 归一化成字节上限，供特征提取链在读大文件前快速决定是否需要截断或跳过。
 * - Purpose: Normalizes `maxFileSizeMB` from config into a byte limit so feature-extraction paths can quickly decide whether large files should be truncated or skipped.
 * - 调用方: `extractRavenFeatures` 在读取样本内容前调用。
 * - Callers: Called by `extractRavenFeatures` before sample content is read.
 * - 被调方: `Number.isFinite`、`Math.max`、`Math.floor`、`Math.min`。
 * - Callees: `Number.isFinite`, `Math.max`, `Math.floor`, `Math.min`.
 * - 变量说明: 无显式入参；`scanner` 为扫描配置；`maxMB` 为归一化后的 MB 上限。
 * - Variables: No explicit parameters; `scanner` is the scan config; `maxMB` is the normalized limit in MB.
 * - 接入方式: 应作为“最大样本大小”字节化的统一入口；读取样本前不要在其他函数重复做同样换算。
 * - Integration: It should be the shared byte-conversion entry for the maximum sample size; sample readers should not repeat the same conversion elsewhere.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 最大文件字节上限 | max file bytes | MB to bytes | feature read limit | sample size guard | scanner config normalization | large file cap | extraction threshold
 */
  function getMaxFileSizeBytes() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const maxMB = Number.isFinite(scanner.maxFileSizeMB) ? Math.max(1, Math.floor(scanner.maxFileSizeMB)) : 0
    return maxMB > 0 ? Math.min(0x7FFFFFFF, maxMB * 1024 * 1024) : 0
  }

  /**
 * - 函数: `readFileSlice`
 * - Function: `readFileSlice`
 * - 作用: 读取文件slice并将原始数据解析为当前模块需要的值。
 * - Purpose: Reads the file slice and parses raw data into the value required by this module.
 * - 调用方: `readStringAt` 用它读取以 `\0` 结尾的字符串；`parsePeImports` 用它读取 DOS/NT/section/import 原始字节；`extractRavenFeatures` 也会直接读取样本头部与片段。
 * - Callers: Called by `readStringAt` for null-terminated strings, by `parsePeImports` for DOS/NT/section/import raw bytes, and directly by `extractRavenFeatures` for file headers and sample slices.
 * - 被调方: `Buffer.alloc`、`fs.readSync`。
 * - Callees: `Buffer.alloc`, `fs.readSync`.
 * - 变量说明: `fd` 为当前流程传入的fd；`offset` 为当前流程传入的offset；`length` 为当前流程传入的length；`buf`, `bytes` 为函数内部派生的中间状态。
 * - Variables: `fd` is the incoming fd for this flow; `offset` is the incoming offset for this flow; `length` is the incoming length for this flow; `buf`, `bytes` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `readFileSlice`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `readFileSlice` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 读取 | 文件 | slice | read | file | slice | call chain | 错误处理 | error handling | 复用
 */
  function readFileSlice(fd, offset, length) {
    const buf = Buffer.alloc(length)
    const bytes = fs.readSync(fd, buf, 0, length, offset)
    return bytes > 0 ? buf.slice(0, bytes) : Buffer.alloc(0)
  }

  /**
 * - 函数: `readStringAt`
 * - Function: `readStringAt`
 * - 作用: 读取stringat并将原始数据解析为当前模块需要的值。
 * - Purpose: Reads the string at and parses raw data into the value required by this module.
 * - 调用方: `parsePeImports` 在根据名称 RVA 读取 DLL 名和导入 API 名时调用。
 * - Callers: Called by `parsePeImports` when reading DLL names and imported API names from name RVAs.
 * - 被调方: `readFileSlice`。
 * - Callees: `readFileSlice`.
 * - 变量说明: `fd` 为当前流程传入的fd；`offset` 为当前流程传入的offset；`maxLen` 为当前流程传入的maxlen；`buf`, `idx` 为函数内部派生的中间状态。
 * - Variables: `fd` is the incoming fd for this flow; `offset` is the incoming offset for this flow; `maxLen` is the incoming max len for this flow; `buf`, `idx` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `readStringAt`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `readStringAt` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 读取 | string | at | read | string | at | call chain | 错误处理 | error handling | 复用
 */
  function readStringAt(fd, offset, maxLen) {
    const buf = readFileSlice(fd, offset, maxLen)
    if (!buf.length) return ''
    const idx = buf.indexOf(0)
    return buf.slice(0, idx >= 0 ? idx : buf.length).toString('utf8')
  }

  /**
 * - 函数: `computeEntropy`
 * - Function: `computeEntropy`
 * - 作用: 计算entropy相关分值或结果，为后续决策提供依据。
 * - Purpose: Computes the entropy score or result to support later decisions.
 * - 调用方: `extractRavenFeatures` 在分析样本头部与局部缓冲区时调用，用熵值刻画壳化或高混淆倾向。
 * - Callers: Called by `extractRavenFeatures` while analyzing file headers and local buffers to characterize packing or high-obfuscation tendencies through entropy.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `buf` 为当前流程传入的buf；`freq`, `i` 为函数内部派生的中间状态。
 * - Variables: `buf` is the incoming buf for this flow; `freq`, `i` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `computeEntropy`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `computeEntropy` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 计算 | entropy | compute | entropy | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function computeEntropy(buf) {
    if (!buf || !buf.length) return 0
    const freq = new Array(256).fill(0)
    for (let i = 0; i < buf.length; i++) freq[buf[i]]++
    let ent = 0
    for (let i = 0; i < 256; i++) {
      const p = freq[i] / buf.length
      if (p > 0) ent -= p * Math.log2(p)
    }
    return ent
  }

  /**
 * - 函数: `computeFuzzyHashesFromBuffer`
 * - Function: `computeFuzzyHashesFromBuffer`
 * - 作用: 计算fuzzyhashesfrombuffer相关分值或结果，为后续决策提供依据。
 * - Purpose: Computes the fuzzy hashes from buffer score or result to support later decisions.
 * - 调用方: `extractRavenFeatures` 在构造 fuzzy 特征时调用，把样本内容切块后生成粗粒度相似指纹。
 * - Callers: Called by `extractRavenFeatures` when building fuzzy features, chunking the sample content into coarse-grained similarity fingerprints.
 * - 被调方: `push`、`Math.min`。
 * - Callees: `push`, `Math.min`.
 * - 变量说明: `buf` 为当前流程传入的buf；`chunkSize`, `maxChunks` 为函数内部派生的中间状态。
 * - Variables: `buf` is the incoming buf for this flow; `chunkSize`, `maxChunks` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `computeFuzzyHashesFromBuffer`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `computeFuzzyHashesFromBuffer` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 计算 | fuzzy | hashes | from | buffer | compute | fuzzy | hashes | from | buffer
 */
  function computeFuzzyHashesFromBuffer(buf) {
    if (!buf || !buf.length) return []
    const chunkSize = 4096
    const maxChunks = 64
    const hashes = []
    for (let i = 0; i < buf.length && hashes.length < maxChunks; i += chunkSize) {
      const slice = buf.slice(i, Math.min(buf.length, i + chunkSize))
      const h = crypto.createHash('sha1').update(slice).digest('hex').slice(0, 16)
      hashes.push(h)
    }
    return hashes
  }

  /**
 * - 函数: `fuzzySimilarity`
 * - Function: `fuzzySimilarity`
 * - 作用: 计算两组 fuzzy hash 分片的近似交集比例，用于估计样本与已有特征之间的粗粒度相似度。
 * - Purpose: Computes the approximate overlap ratio between two fuzzy-hash fragment sets, helping estimate coarse-grained similarity between a sample and existing features.
 * - 调用方: `findFuzzySimilarity` 在比较 fuzzy hash 集合时调用。
 * - Callers: Called by `findFuzzySimilarity` while comparing fuzzy-hash sets.
 * - 被调方: `Array.isArray`、`Math.max`。
 * - Callees: `Array.isArray`, `Math.max`.
 * - 变量说明: `a`、`b` 为两组 fuzzy hash 片段；`setA` 为第一组去重集合；`hit` 为命中数。
 * - Variables: `a` and `b` are the two fuzzy-hash fragment lists; `setA` is the deduplicated set of the first list; `hit` counts the overlaps.
 * - 接入方式: 仅作为 fuzzy 特征比对 helper 使用；相似度公式若需调整，应优先在此统一修改。
 * - Integration: Use it only as a fuzzy-feature comparison helper; if the similarity formula changes, it should be updated here centrally.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: fuzzy相似度 | fuzzy similarity | overlap ratio | fragment intersection | coarse match score | feature comparison | set-based similarity | sample similarity
 */
  function fuzzySimilarity(a, b) {
    if (!Array.isArray(a) || !Array.isArray(b) || !a.length || !b.length) return 0
    const setA = new Set(a)
    let hit = 0
    for (const x of b) if (setA.has(x)) hit++
    const denom = Math.max(1, setA.size + b.length - hit)
    return hit / denom
  }

  /**
 * - 函数: `normalizeTokenList`
 * - Function: `normalizeTokenList`
 * - 作用: 标准化token列出输入，统一为当前模块后续逻辑可直接消费的结构。
 * - Purpose: Normalizes the token list input into a structure that downstream logic can consume directly.
 * - 调用方: `extractScriptFeatures` 用它去重并裁剪脚本 token；`parsePeImports` 用它规范化 DLL/API 名列表。
 * - Callers: Called by `extractScriptFeatures` to deduplicate and cap script tokens, and by `parsePeImports` to normalize DLL/API name lists.
 * - 被调方: `push`。
 * - Callees: `push`.
 * - 变量说明: `list` 为当前流程传入的列出；`limit` 为当前流程传入的limit；`out`, `seen` 为函数内部派生的中间状态。
 * - Variables: `list` is the incoming list for this flow; `limit` is the incoming limit for this flow; `out`, `seen` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `normalizeTokenList`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `normalizeTokenList` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 标准化 | token | 列出 | normalize | token | list | call chain | 错误处理 | error handling | 复用
 */
  function normalizeTokenList(list, limit) {
    const out = []
    const seen = new Set()
    for (const item of list) {
      const t = typeof item === 'string' ? item.trim().toLowerCase() : ''
      if (!t || seen.has(t)) continue
      seen.add(t)
      out.push(t)
      if (limit > 0 && out.length >= limit) break
    }
    return out
  }

  /**
 * - 函数: `splitScriptSegments`
 * - Function: `splitScriptSegments`
 * - 作用: 按换行与常见命令连接符切分脚本文本，生成适合做 token 提取和可疑片段统计的脚本段列表。
 * - Purpose: Splits script text on newlines and common command separators to produce script segments suitable for token extraction and suspicious-snippet counting.
 * - 调用方: `extractScriptFeatures` 在抽取脚本行为特征前调用。
 * - Callers: Called by `extractScriptFeatures` before it extracts script-behavior features.
 * - 被调方: `push`。
 * - Callees: `push`.
 * - 变量说明: `text` 为原始脚本文本；`segs` 为粗切分结果；`out` 为去空白后的最终段列表。
 * - Variables: `text` is the raw script text; `segs` is the coarse split result; `out` is the final segment list after trimming empties.
 * - 接入方式: 应作为脚本分段的统一 helper 使用；脚本特征链中的切分规则不要分散复制。
 * - Integration: It should be the shared script-segmentation helper; splitting rules in the script-feature path should not be duplicated elsewhere.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 脚本分段 | script segmentation | command separators | newline split | suspicious snippet prep | token extraction helper | segment list | script preprocessing
 */
  function splitScriptSegments(text) {
    if (!text) return []
    const segs = text.split(/(\r\n|\n|\r|&&|\|\||[&|;])/g)
    const out = []
    for (const s of segs) {
      const v = typeof s === 'string' ? s.trim() : ''
      if (v) out.push(v)
    }
    return out
  }

  /**
 * - 函数: `extractScriptFeatures`
 * - Function: `extractScriptFeatures`
 * - 作用: 从脚本文本中提取 token 列表、段数和可疑命令命中次数，为非 PE 样本建立轻量脚本行为特征。
 * - Purpose: Extracts token lists, segment counts, and suspicious-command hit counts from script text, building lightweight script-behavior features for non-PE samples.
 * - 调用方: `extractRavenFeatures` 在识别到脚本类样本时调用。
 * - Callers: Called by `extractRavenFeatures` when the sample is recognized as script-like content.
 * - 被调方: `splitScriptSegments`、`push`、`normalizeTokenList`。
 * - Callees: `splitScriptSegments`, `push`, `normalizeTokenList`.
 * - 变量说明: `text` 为脚本文本；`segments` 为切分后的脚本片段；`tokens` 为归一化前的原始 token 累积列表；`hit` 为可疑命令命中次数。
 * - Variables: `text` is the script text; `segments` is the split segment list; `tokens` is the raw token accumulator before normalization; `hit` counts suspicious-command matches.
 * - 接入方式: 应作为脚本样本特征提取的统一入口；新脚本规则字段优先在这里扩展。
 * - Integration: It should be the shared entry for script-sample feature extraction; new script-rule fields should be extended here first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 脚本特征提取 | script feature extraction | suspicious commands | token normalization | segment count | non-PE features | lightweight behavior features | script heuristics
 */
  function extractScriptFeatures(text) {
    const segments = splitScriptSegments(text)
    const tokens = []
    const suspicious = ['powershell', 'cmd', 'reg', 'schtasks', 'certutil', 'bitsadmin', 'mshta', 'rundll32', 'wscript', 'cscript', 'invoke-webrequest', 'iex', 'download', 'base64', 'frombase64string', 'new-object', 'http', 'https']
    let hit = 0
    for (const seg of segments) {
      const parts = seg.toLowerCase().split(/[^a-z0-9_\-\.]+/g).filter(Boolean)
      for (const p of parts) {
        tokens.push(p)
        if (suspicious.includes(p)) hit++
      }
    }
    return { tokens: normalizeTokenList(tokens, 128), segments: segments.length, suspicious: hit }
  }

  /**
 * - 函数: `rvaToOffset`
 * - Function: `rvaToOffset`
 * - 作用: 根据 PE section 表把 RVA 转换成文件偏移，供 import 表和字符串表解析时定位原始字节位置。
 * - Purpose: Converts an RVA into a file offset using the PE section table so import-table and string-table parsing can locate raw bytes in the file.
 * - 调用方: `parsePeImports` 在解析 PE import 描述符时调用。
 * - Callers: Called by `parsePeImports` while decoding PE import descriptors.
 * - 被调方: `Math.max`。
 * - Callees: `Math.max`.
 * - 变量说明: `rva` 为目标相对虚拟地址；`sections` 为 section 元数据列表；`s` 为当前匹配 section；`start` 为该 section 的起始 RVA。
 * - Variables: `rva` is the target relative virtual address; `sections` is the section-metadata list; `s` is the section currently being matched; `start` is that section’s starting RVA.
 * - 接入方式: 应作为 PE 地址换算的统一 helper 使用；PE 解析链不要自己重复写 section 映射逻辑。
 * - Integration: It should be the shared helper for PE address conversion; PE parsing paths should not duplicate section-mapping logic on their own.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: RVA转文件偏移 | RVA to file offset | PE section mapping | import parser helper | raw byte location | virtual address conversion | PE metadata | address translation
 */
  function rvaToOffset(rva, sections) {
    for (const s of sections) {
      const start = s.virtualAddress
      const end = start + Math.max(s.virtualSize, s.rawSize)
      if (rva >= start && rva < end) return rva - start + s.rawPtr
    }
    return 0
  }

  /**
 * - 函数: `parsePeImports`
 * - Function: `parsePeImports`
 * - 作用: 解析PE 文件imports原始输入，并提取结构化结果供后续逻辑使用。
 * - Purpose: Parses the raw PE file imports input and extracts a structured result for downstream logic.
 * - 调用方: `extractRavenFeatures` 在识别 PE 样本后调用，用导入表特征补充 API 序列与 DLL 画像。
 * - Callers: Called by `extractRavenFeatures` after recognizing a PE sample so import-table features can enrich API sequences and DLL fingerprints.
 * - 被调方: `readFileSlice`、`push`、`rvaToOffset`、`readStringAt`、`normalizeTokenList`、`fs.openSync`。
 * - Callees: `readFileSlice`, `push`, `rvaToOffset`, `readStringAt`, `normalizeTokenList`, `fs.openSync`.
 * - 变量说明: `filePath` 为当前流程传入的文件路径；`fd`, `dos` 为函数内部派生的中间状态。
 * - Variables: `filePath` is the incoming file path for this flow; `fd`, `dos` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `parsePeImports`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `parsePeImports` through the existing returned object.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 解析 | PE 文件 | imports | parse | PE file | imports | call chain | 错误处理 | error handling | 复用
 */
  function parsePeImports(filePath) {
    let fd = null
    try {
      fd = fs.openSync(filePath, 'r')
      const dos = readFileSlice(fd, 0, 64)
      if (dos.length < 64) return { apis: [], dlls: [] }
      const eMagic = dos.readUInt16LE(0)
      if (eMagic !== 0x5a4d) return { apis: [], dlls: [] }
      const eLfanew = dos.readUInt32LE(60)
      const ntHeader = readFileSlice(fd, eLfanew, 256)
      if (ntHeader.length < 256) return { apis: [], dlls: [] }
      const sig = ntHeader.readUInt32LE(0)
      if (sig !== 0x4550) return { apis: [], dlls: [] }
      const numSections = ntHeader.readUInt16LE(6)
      const sizeOpt = ntHeader.readUInt16LE(20)
      const optOffset = 24
      const magic = ntHeader.readUInt16LE(optOffset)
      const is64 = magic === 0x20b
      const dataDirOffset = optOffset + (is64 ? 112 : 96)
      const importRva = ntHeader.readUInt32LE(dataDirOffset + 8)
      const secOffset = eLfanew + 24 + sizeOpt
      const secBuf = readFileSlice(fd, secOffset, numSections * 40)
      const sections = []
      for (let i = 0; i < numSections; i++) {
        const base = i * 40
        if (base + 40 > secBuf.length) break
        const virtualSize = secBuf.readUInt32LE(base + 8)
        const virtualAddress = secBuf.readUInt32LE(base + 12)
        const rawSize = secBuf.readUInt32LE(base + 16)
        const rawPtr = secBuf.readUInt32LE(base + 20)
        sections.push({ virtualAddress, virtualSize, rawPtr, rawSize })
      }
      const importOffset = rvaToOffset(importRva, sections)
      if (!importOffset) return { apis: [], dlls: [] }
      const apis = []
      const dlls = []
      let cursor = importOffset
      const maxDesc = 256
      for (let i = 0; i < maxDesc; i++) {
        const desc = readFileSlice(fd, cursor, 20)
        if (desc.length < 20) break
        const origThunk = desc.readUInt32LE(0)
        const nameRva = desc.readUInt32LE(12)
        const firstThunk = desc.readUInt32LE(16)
        if (origThunk === 0 && nameRva === 0 && firstThunk === 0) break
        const nameOffset = rvaToOffset(nameRva, sections)
        const dll = nameOffset ? readStringAt(fd, nameOffset, 260) : ''
        if (dll) dlls.push(dll.toLowerCase())
        const thunkRva = origThunk || firstThunk
        const thunkOffset = rvaToOffset(thunkRva, sections)
        if (thunkOffset) {
          let tcur = thunkOffset
          const maxThunk = 2048
          for (let j = 0; j < maxThunk; j++) {
            const entry = readFileSlice(fd, tcur, is64 ? 8 : 4)
            if (entry.length < (is64 ? 8 : 4)) break
            const val = is64 ? Number(entry.readBigUInt64LE(0)) : entry.readUInt32LE(0)
            if (!val) break
            const isOrdinal = is64 ? (val & 0x8000000000000000) !== 0 : (val & 0x80000000) !== 0
            if (!isOrdinal) {
              const hintNameRva = is64 ? (val & 0x7FFFFFFFFFFFFFFF) : (val & 0x7FFFFFFF)
              const nameOff = rvaToOffset(hintNameRva, sections)
              if (nameOff) {
                const n = readStringAt(fd, nameOff + 2, 260)
                if (n) apis.push(n.toLowerCase())
              }
            }
            tcur += is64 ? 8 : 4
          }
        }
        cursor += 20
      }
      return { apis: normalizeTokenList(apis, 512), dlls: normalizeTokenList(dlls, 128) }
    } catch {
      return { apis: [], dlls: [] }
    } finally {
      if (fd) {
        try { fs.closeSync(fd) } catch {}
      }
    }
  }

  /**
 * - 函数: `extractRavenFeatures`
 * - Function: `extractRavenFeatures`
 * - 作用: 从样本文件中提取 Raven 特征，按脚本、PE 与普通二进制三类路径生成模糊哈希、熵值、API 序列或脚本文本特征，是 JS 签名库训练与命中的共同前处理入口。
 * - Purpose: Extracts Raven features from a sample file, producing fuzzy hashes, entropy, API sequences, or script-text features across script, PE, and generic binary paths, and serves as the shared preprocessing entry for JS signature training and detection.
 * - 调用方: `scanRavenByStore` 在做 JS 签名命中时调用；训练链路写入签名库前也会依赖其产出的特征结构。
 * - Callers: Called by `scanRavenByStore` during JS signature matching, and also relied upon by training flows before appending entries into the signature store.
 * - 被调方: `getMaxFileSizeBytes`、`readFileSlice`、`computeEntropy`、`computeFuzzyHashesFromBuffer`、`extractScriptFeatures`、`isLikelyPeFile`。
 * - Callees: `getMaxFileSizeBytes`, `readFileSlice`, `computeEntropy`, `computeFuzzyHashesFromBuffer`, `extractScriptFeatures`, `isLikelyPeFile`.
 * - 变量说明: `filePath` 为目标样本路径；`sp` 为安全字符串路径；`ext` 用于区分脚本扩展名；`buf` 为截断读取的文件内容；`features` 为最终进入训练/命中的特征对象。
 * - Variables: `filePath` is the target sample path; `sp` is the safe normalized path string; `ext` distinguishes script extensions; `buf` is the truncated file content; `features` is the final feature object used for training and matching.
 * - 接入方式: 仅作为 `scanner_client` 内部的特征抽取入口使用；新增 JS 特征维度时应优先扩展本函数，而不是在训练和扫描两端分别复制提取逻辑。
 * - Integration: Use it only as the internal feature-extraction entry of `scanner_client`; new JS feature dimensions should extend this helper rather than duplicating extraction logic in both training and scanning.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: Raven特征提取 | Raven feature extraction | fuzzy hash | entropy | script features | PE imports | feature preprocessing | JS signature pipeline
 */
  function extractRavenFeatures(filePath) {
    const sp = typeof filePath === 'string' ? filePath : ''
    if (!sp) return { features: {}, meta: { ok: false } }
    const ext = path.extname(sp).toLowerCase()
    const isScript = scriptExtSet.has(ext)
    let buf = Buffer.alloc(0)
    let size = 0
    try {
      const stat = fs.statSync(sp)
      size = stat && stat.size ? stat.size : 0
    } catch {}
    const maxBytes = getMaxFileSizeBytes()
    const readLimit = maxBytes > 0 ? Math.min(maxBytes, 8 * 1024 * 1024) : 2 * 1024 * 1024
    try {
      const fd = fs.openSync(sp, 'r')
      const len = size > 0 ? Math.min(size, readLimit) : readLimit
      buf = readFileSlice(fd, 0, len)
      try { fs.closeSync(fd) } catch {}
    } catch {
      buf = Buffer.alloc(0)
    }
    const entropy = computeEntropy(buf)
    const fuzzy = computeFuzzyHashesFromBuffer(buf)
    const features = { fuzzy, entropy }
    if (isScript) {
      const text = buf.toString('utf8')
      const script = extractScriptFeatures(text)
      features.script_tokens = script.tokens
      features.script_segments = script.segments
      features.script_suspicious = script.suspicious
      return { features, meta: { ok: true, type: 'script' } }
    }
    if (isLikelyPeFile(sp)) {
      const pe = parsePeImports(sp)
      features.apis = pe.apis
      features.dlls = pe.dlls
      features.api_seq = pe.apis.slice(0, 64)
      return { features, meta: { ok: true, type: 'pe' } }
    }
    return { features, meta: { ok: true, type: 'binary' } }
  }

  /**
 * - 函数: `makeFeatureCode`
 * - Function: `makeFeatureCode`
 * - 作用: 对规范化特征对象做稳定序列化并计算 SHA-256 指纹，用作 JS 签名库中“同一特征样本”的主键与精确命中键。
 * - Purpose: Performs stable serialization on a normalized feature object and computes its SHA-256 fingerprint, using it as both the primary key and exact-match key inside the JS signature store.
 * - 调用方: `persistSignatureStore` 在写入签名库前生成唯一特征码；`scanRavenByStore` 在检测时也用同一规则计算命中键。
 * - Callers: Called by `persistSignatureStore` before appending to the signature store, and by `scanRavenByStore` during detection to compute the same matching key.
 * - 被调方: `stableStringify`。
 * - Callees: `stableStringify`.
 * - 变量说明: `features` 为规范化后的样本特征对象；`raw` 为稳定序列化后的文本表示，随后被哈希为固定长度指纹。
 * - Variables: `features` is the normalized sample feature object; `raw` is the stably serialized text that is hashed into a fixed-length fingerprint.
 * - 接入方式: 仅在 JS 签名训练和命中链路内部复用；若新增新的特征码生成策略，应统一在本函数调整。
 * - Integration: Reuse it only inside the JS signature training and matching flow; any new feature-code strategy should be centralized here.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 特征码 | feature code | stable stringify | SHA-256 fingerprint | exact match key | signature identity | deterministic hash | JS signature store
 */
  function makeFeatureCode(features) {
    try {
      const raw = stableStringify(features)
      return crypto.createHash('sha256').update(raw).digest('hex')
    } catch {
      return ''
    }
  }

  /**
 * - 函数: `buildSignatureFeaturePayload`
 * - Function: `buildSignatureFeaturePayload`
 * - 作用: 构建签名feature载荷结构或配置，供后续计算、扫描或持久化流程使用。
 * - Purpose: Builds the signature feature payload structure or configuration for later compute, scan, or persistence flows.
 * - 调用方: `persistSignatureStore` 在把训练结果写成 snapshot 或 delta 前调用，用于构造单条签名记录的特征与元数据载荷。
 * - Callers: Called by `persistSignatureStore` before writing snapshot or delta entries so one signature record can be assembled with features and metadata.
 * - 被调方: `Number.isFinite`、`Object.assign`。
 * - Callees: `Number.isFinite`, `Object.assign`.
 * - 变量说明: `result` 为当前流程传入的result；`features` 为当前流程传入的features；`meta` 为当前流程传入的元数据；`obj`, `baseMeta` 为函数内部派生的中间状态。
 * - Variables: `result` is the incoming result for this flow; `features` is the incoming features for this flow; `meta` is the incoming metadata for this flow; `obj`, `baseMeta` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `buildSignatureFeaturePayload`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `buildSignatureFeaturePayload` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 构建 | 签名 | feature | 载荷 | build | signature | feature | payload | error handling | 复用
 */
  function buildSignatureFeaturePayload(result, features, meta) {
    const obj = (result && typeof result === 'object') ? result : {}
    const baseMeta = {
      ok: obj.ok === true,
      total: Number.isFinite(obj.total) ? obj.total : 0,
      trained: Number.isFinite(obj.trained) ? obj.trained : 0,
      failed: Number.isFinite(obj.failed) ? obj.failed : 0
    }
    const mergedMeta = Object.assign({}, baseMeta, meta && typeof meta === 'object' ? meta : {})
    const outFeatures = features && typeof features === 'object' ? features : {}
    return { features: outFeatures, meta: mergedMeta }
  }

  /**
 * - 函数: `ensureSignatureStoreShape`
 * - Function: `ensureSignatureStoreShape`
 * - 作用: 确保签名特征库shape已初始化且可复用，必要时执行一次性准备逻辑。
 * - Purpose: Ensures the signature signature store shape is initialized and reusable, performing one-time setup when necessary.
 * - 调用方: `buildStoreFromSnapshotEntry` 在恢复 snapshot 后调用；`readSignatureStoreFromFile` 与 `loadSignatureStore` 在读取当前版本时调用；`persistSignatureStore` 在提交前后也会用它修正库结构。
 * - Callers: Called by `buildStoreFromSnapshotEntry` after snapshot recovery, by `readSignatureStoreFromFile` and `loadSignatureStore` when reading the active version, and by `persistSignatureStore` before and after commits to normalize store shape.
 * - 被调方: `Date.now`、`Array.isArray`。
 * - Callees: `Date.now`, `Array.isArray`.
 * - 变量说明: `store` 为当前流程传入的特征库。
 * - Variables: `store` is the incoming signature store for this flow.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `ensureSignatureStoreShape`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `ensureSignatureStoreShape` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 确保 | 签名 | 特征库 | shape | ensure | signature | signature store | shape | error handling | 复用
 */
  function ensureSignatureStoreShape(store) {
    if (!store || typeof store !== 'object') {
      return {
        version: 4,
        version_id: '',
        parent_version_id: '',
        updated_at: Date.now(),
        signatures: [],
        api_stats: {},
        api_sequences: {},
        fuzzy_stats: {},
        meta: {}
      }
    }
    if (!Array.isArray(store.signatures)) store.signatures = []
    if (!store.api_stats || typeof store.api_stats !== 'object') store.api_stats = {}
    if (!store.api_sequences || typeof store.api_sequences !== 'object') store.api_sequences = {}
    if (!store.fuzzy_stats || typeof store.fuzzy_stats !== 'object') store.fuzzy_stats = {}
    if (typeof store.version_id !== 'string') store.version_id = ''
    if (typeof store.parent_version_id !== 'string') store.parent_version_id = ''
    if (!store.meta || typeof store.meta !== 'object') store.meta = {}
    store.version = 4
    return store
  }

  /**
 * - 函数: `ensureSignatureIndexShape`
 * - Function: `ensureSignatureIndexShape`
 * - 作用: 确保签名indexshape已初始化且可复用，必要时执行一次性准备逻辑。
 * - Purpose: Ensures the signature index shape is initialized and reusable, performing one-time setup when necessary.
 * - 调用方: `readSignatureIndex` 在解析索引文件后调用；`rebuildSignatureIndex` 在重扫全库时调用；`persistSignatureStore` 在写入版本元数据前也会用它保证结构完整。
 * - Callers: Called by `readSignatureIndex` after parsing the index file, by `rebuildSignatureIndex` during full-store rescans, and by `persistSignatureStore` before writing version metadata to ensure a complete shape.
 * - 被调方: `Number.isFinite`、`Array.isArray`。
 * - Callees: `Number.isFinite`, `Array.isArray`.
 * - 变量说明: `index` 为当前流程传入的index。
 * - Variables: `index` is the incoming index for this flow.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `ensureSignatureIndexShape`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `ensureSignatureIndexShape` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 确保 | 签名 | index | shape | ensure | signature | index | shape | error handling | 复用
 */
  function ensureSignatureIndexShape(index) {
    if (!index || typeof index !== 'object') {
      return { current_version_id: '', last_snapshot_version_id: '', delta_since_snapshot: 0, versions: [] }
    }
    if (typeof index.current_version_id !== 'string') index.current_version_id = ''
    if (typeof index.last_snapshot_version_id !== 'string') index.last_snapshot_version_id = ''
    if (!Number.isFinite(index.delta_since_snapshot)) index.delta_since_snapshot = 0
    if (!Array.isArray(index.versions)) index.versions = []
    return index
  }

  /**
 * - 函数: `resolveSignatureIndexPath`
 * - Function: `resolveSignatureIndexPath`
 * - 作用: 基于签名库主文件路径推导版本索引文件路径，约定把索引持久化到同目录下的 `*.index.json`，供版本读取、回滚和重建流程共享。
 * - Purpose: Derives the version-index file path from the signature-store main file and standardizes index persistence as a sibling `*.index.json`, shared by version reads, rollback, and rebuild flows.
 * - 调用方: `persistSignatureStore`、`loadSignatureStore`、`listSignatureStoreVersions`、`getSignatureStoreCurrentVersion`、`rollbackSignatureStore`。
 * - Callers: Called by `persistSignatureStore`, `loadSignatureStore`, `listSignatureStoreVersions`, `getSignatureStoreCurrentVersion`, and `rollbackSignatureStore`.
 * - 被调方: `resolveSignatureStorePath`。
 * - Callees: `resolveSignatureStorePath`.
 * - 变量说明: `scannerCfg` 为扫描配置；`storePath` 为签名库主文件路径，索引路径由其后缀派生。
 * - Variables: `scannerCfg` is the scanner config; `storePath` is the main signature-store path from which the index path is derived.
 * - 接入方式: 应作为签名版本索引路径的统一解析入口；所有索引读写逻辑都应复用本函数。
 * - Integration: It should be the single resolver for the signature-version index path; all index read/write flows should reuse it.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 签名索引路径 | signature index path | sibling index file | index.json derivation | version metadata path | shared resolver | rollback support | replay metadata
 */
  function resolveSignatureIndexPath(scannerCfg) {
    const storePath = resolveSignatureStorePath(scannerCfg)
    if (!storePath) return ''
    return storePath + '.index.json'
  }

  /**
 * - 函数: `readSignatureIndex`
 * - Function: `readSignatureIndex`
 * - 作用: 读取签名库版本索引文件并规范化成内部可用结构，作为“当前版本在哪、各版本偏移与父子关系如何”的快速元数据入口。
 * - Purpose: Reads the signature-store version index file and normalizes it into the internal shape used to answer “which version is current” and “what are the offsets and parent links of each version.”
 * - 调用方: `readSignatureStoreFromFile`、`listSignatureStoreVersions`、`getSignatureStoreCurrentVersion`、`rollbackSignatureStore`。
 * - Callers: Called by `readSignatureStoreFromFile`, `listSignatureStoreVersions`, `getSignatureStoreCurrentVersion`, and `rollbackSignatureStore`.
 * - 被调方: `ensureSignatureIndexShape`、`fs.existsSync`、`fs.readFileSync`、`JSON.parse`。
 * - Callees: `ensureSignatureIndexShape`, `fs.existsSync`, `fs.readFileSync`, `JSON.parse`.
 * - 变量说明: `indexPath` 为索引文件路径；`raw` 为原始 JSON 文本；`parsed` 为解析后的对象；返回值会再经 `ensureSignatureIndexShape` 规范化。
 * - Variables: `indexPath` is the index file path; `raw` is the raw JSON text; `parsed` is the parsed object, which is then normalized through `ensureSignatureIndexShape`.
 * - 接入方式: 应作为签名版本索引的统一读取入口；上层不要直接 `JSON.parse` 索引文件，以免绕过形状修复逻辑。
 * - Integration: It should be the single read entry for the signature-version index; upper layers should not `JSON.parse` the file directly and bypass shape normalization.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 读取签名索引 | read signature index | version metadata load | current version lookup | ensure index shape | resilient parse | replay metadata | index entrypoint
 */
  function readSignatureIndex(indexPath) {
    try {
      if (!indexPath || !fs.existsSync(indexPath)) return null
      const raw = fs.readFileSync(indexPath, 'utf8')
      const parsed = raw ? JSON.parse(raw) : null
      return ensureSignatureIndexShape(parsed)
    } catch {
      return null
    }
  }

  /**
 * - 函数: `writeSignatureIndex`
 * - Function: `writeSignatureIndex`
 * - 作用: 把当前签名版本索引完整写回磁盘，使版本链、当前版本指针和偏移元数据在 snapshot/delta 提交、回滚或重建后持久化生效。
 * - Purpose: Writes the current signature-version index back to disk so version lineage, the active-version pointer, and offset metadata persist after snapshot/delta commits, rollbacks, or rebuilds.
 * - 调用方: `rebuildSignatureIndex`、`persistSignatureStore`、`rollbackSignatureStore`。
 * - Callers: Called by `rebuildSignatureIndex`, `persistSignatureStore`, and `rollbackSignatureStore`.
 * - 被调方: `fs.writeFileSync`、`JSON.stringify`。
 * - Callees: `fs.writeFileSync`, `JSON.stringify`.
 * - 变量说明: `indexPath` 为索引文件路径；`index` 为待持久化的完整索引对象。
 * - Variables: `indexPath` is the index file path; `index` is the full index object to persist.
 * - 接入方式: 应作为签名索引持久化的统一出口；索引修改后不要在别处自行写文件。
 * - Integration: It should be the single persistence exit for the signature index; callers should not write the file independently elsewhere after mutating index state.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 写签名索引 | write signature index | version metadata persist | current_version_id update | rebuild commit | rollback commit | index flush | metadata save
 */
  function writeSignatureIndex(indexPath, index) {
    try {
      if (!indexPath) return false
      fs.writeFileSync(indexPath, JSON.stringify(index), 'utf8')
      return true
    } catch {
      return false
    }
  }

  /**
 * - 函数: `hashLineId`
 * - Function: `hashLineId`
 * - 作用: 为签名库中的单行原始记录生成稳定哈希 ID，供索引重建时标识版本行、去重或辅助比对偏移记录。
 * - Purpose: Generates a stable hash id for one raw line in the signature store so index rebuilding can identify version rows, assist deduplication, and compare offset records.
 * - 调用方: `rebuildSignatureIndex` 在逐行重扫签名库时调用。
 * - Callers: Called by `rebuildSignatureIndex` while rescanning the signature store line by line.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `line` 为签名库中的原始一行文本。
 * - Variables: `line` is the raw single-line text from the signature store.
 * - 接入方式: 仅作为签名库逐行分析和索引重建辅助函数使用；外部版本标识不要拿它替代真正的 `versionId`。
 * - Integration: Use it only as a helper for line-wise signature-store analysis and index rebuilding; external version identity should still rely on the real `versionId`.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 行哈希 ID | line hash id | raw line fingerprint | rebuild helper | SHA-256 line hash | index scan aid | dedupe hint | offset comparison
 */
  function hashLineId(line) {
    try {
      return crypto.createHash('sha256').update(line).digest('hex')
    } catch {
      return ''
    }
  }

  /**
 * - 函数: `normalizeStoreEntry`
 * - Function: `normalizeStoreEntry`
 * - 作用: 兼容历史签名库存储格式，把没有显式 `entry_type` 的旧记录补正为 snapshot/delta 语义，确保后续索引重建和版本回放都能按统一协议解析。
 * - Purpose: Normalizes legacy signature-store records by backfilling missing `entry_type` semantics into snapshot/delta entries so later index rebuilding and version replay can parse everything through one protocol.
 * - 调用方: `rebuildSignatureIndex` 在重扫整库文件时调用；`readStoreEntryByOffset` 与 `readSignatureStoreFromFile` 在按索引回放版本链时也会复用。
 * - Callers: Called by `rebuildSignatureIndex` while rescanning the whole store file, and reused by `readStoreEntryByOffset` and `readSignatureStoreFromFile` during indexed version replay.
 * - 被调方: `Object.assign`。
 * - Callees: `Object.assign`.
 * - 变量说明: `entry` 为从签名库文件读出的原始 JSON 记录；`clone` 为向旧格式补写 `entry_type` 时创建的兼容副本。
 * - Variables: `entry` is the raw JSON record read from the signature store; `clone` is the compatibility copy created when backfilling `entry_type` for old formats.
 * - 接入方式: 仅供签名库读取链内部使用；如果未来调整磁盘格式，应优先在这里集中兼容，而不是在多个读取点分散判断。
 * - Integration: Use it only inside the signature-store read path; if disk format changes again, compatibility rules should be centralized here instead of scattered across readers.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 历史格式兼容 | legacy format compatibility | entry_type normalization | snapshot entry | delta entry | replay protocol | index rebuild | backward compatibility
 */
  function normalizeStoreEntry(entry) {
    if (!entry || typeof entry !== 'object') return null
    if (entry.entry_type === 'snapshot' || entry.entry_type === 'delta') return entry
    if (entry.signatures || entry.api_stats || entry.api_sequences || entry.fuzzy_stats) {
      const clone = Object.assign({}, entry)
      clone.entry_type = 'snapshot'
      return clone
    }
    return entry
  }

  /**
 * - 函数: `rebuildSignatureIndex`
 * - Function: `rebuildSignatureIndex`
 * - 作用: 在索引文件缺失或损坏时，重新扫描日志式签名库文件，按每行记录恢复版本链、父子关系、偏移量和 snapshot/delta 边界，重建可供快速回放的版本索引。
 * - Purpose: Rebuilds the fast replay index by rescanning the append-only signature-store file when the index is missing or corrupted, restoring version lineage, parent links, byte offsets, and snapshot/delta boundaries line by line.
 * - 调用方: `readSignatureStoreFromFile` 在找不到有效索引时调用；版本查询、当前版本读取和回滚功能也会通过本函数修复索引后继续工作。
 * - Callers: Called by `readSignatureStoreFromFile` when a valid index is unavailable; version listing, current-version reads, and rollback also depend on it to recover the index before continuing.
 * - 被调方: `ensureSignatureIndexShape`、`normalizeStoreEntry`、`hashLineId`、`push`、`writeSignatureIndex`、`fs.existsSync`。
 * - Callees: `ensureSignatureIndexShape`, `normalizeStoreEntry`, `hashLineId`, `push`, `writeSignatureIndex`, `fs.existsSync`.
 * - 变量说明: `storePath` 为签名库主文件；`indexPath` 为待重建的索引文件；`offset/length` 共同标记每条记录在文件中的字节范围；`lastId/lastSnapshotId/deltaSinceSnapshot` 用于恢复版本链状态。
 * - Variables: `storePath` is the main store file; `indexPath` is the index file being rebuilt; `offset` and `length` mark each record’s byte span; `lastId`, `lastSnapshotId`, and `deltaSinceSnapshot` reconstruct version-chain state.
 * - 接入方式: 只应作为索引恢复手段由读取链内部调用；外部不要把它当作常规读路径，以免频繁全量扫描大文件。
 * - Integration: It should be used internally as an index-recovery mechanism only; external callers should not treat it as the normal read path because it rescans the whole file.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 索引重建 | index rebuild | append-only store | byte offsets | version lineage | snapshot boundary | delta chain | corruption recovery
 */
  function rebuildSignatureIndex(storePath, indexPath) {
    try {
      if (!storePath || !fs.existsSync(storePath)) return null
      const buf = fs.readFileSync(storePath)
      const text = buf ? buf.toString('utf8') : ''
      if (!text) return null
      const index = ensureSignatureIndexShape(null)
      let offset = 0
      let lastId = ''
      let lastSnapshotId = ''
      let deltaSinceSnapshot = 0
      const lines = text.split(/\n/)
      for (let i = 0; i < lines.length; i++) {
        const lineRaw = lines[i]
        const line = lineRaw.trim()
        const length = Buffer.byteLength(lineRaw + '\n')
        if (!line) {
          offset += length
          continue
        }
        let parsed = null
        try { parsed = JSON.parse(line) } catch { parsed = null }
        const normalized = normalizeStoreEntry(parsed)
        const entryType = normalized && normalized.entry_type ? normalized.entry_type : 'snapshot'
        const entryId = normalized && typeof normalized.version_id === 'string' && normalized.version_id
          ? normalized.version_id
          : hashLineId(line)
        const parentId = normalized && typeof normalized.parent_version_id === 'string'
          ? normalized.parent_version_id
          : lastId
        index.versions.push({
          id: entryId,
          parent_id: parentId,
          ts: normalized && Number.isFinite(normalized.updated_at) ? normalized.updated_at : Date.now(),
          offset,
          length,
          entry_type: entryType
        })
        lastId = entryId
        if (entryType === 'snapshot') {
          lastSnapshotId = entryId
          deltaSinceSnapshot = 0
        } else {
          deltaSinceSnapshot += 1
        }
        offset += length
      }
      index.current_version_id = lastId
      index.last_snapshot_version_id = lastSnapshotId
      index.delta_since_snapshot = deltaSinceSnapshot
      writeSignatureIndex(indexPath, index)
      return index
    } catch {
      return null
    }
  }

  /**
 * - 函数: `readStoreEntryByOffset`
 * - Function: `readStoreEntryByOffset`
 * - 作用: 按索引记录保存的偏移量与长度直接定位并读取单条签名库记录，避免回放当前版本时反复全量扫描整个特征库文件。
 * - Purpose: Reads a single signature-store entry directly from byte offset and length recorded in the index, avoiding repeated full-file scans while replaying the active version.
 * - 调用方: `readSignatureStoreFromFile` 在按版本链回放 snapshot 和 delta 时调用。
 * - Callers: Called by `readSignatureStoreFromFile` while replaying snapshot and delta entries along the version chain.
 * - 被调方: `normalizeStoreEntry`、`Number.isFinite`、`fs.openSync`、`Buffer.alloc`、`fs.readSync`、`fs.closeSync`。
 * - Callees: `normalizeStoreEntry`, `Number.isFinite`, `fs.openSync`, `Buffer.alloc`, `fs.readSync`, `fs.closeSync`.
 * - 变量说明: `storePath` 为签名库文件路径；`offset/length` 为索引给出的字节范围；`fd` 为临时文件句柄；`buf` 为读取出的原始行缓冲区。
 * - Variables: `storePath` is the signature-store file path; `offset` and `length` are the byte span from the index; `fd` is the temporary file descriptor; `buf` is the raw line buffer being read.
 * - 接入方式: 仅供索引驱动的读取链使用；新增版本回放逻辑时应优先复用本函数，而不是重新拼装低层随机读代码。
 * - Integration: Use it only in index-driven read paths; new replay logic should reuse this helper instead of rewriting random-read file access.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 按偏移读取 | read by offset | random access | store entry | indexed replay | byte-range read | snapshot fetch | delta fetch
 */
  function readStoreEntryByOffset(storePath, offset, length) {
    try {
      if (!storePath || !Number.isFinite(offset) || !Number.isFinite(length)) return null
      const fd = fs.openSync(storePath, 'r')
      const buf = Buffer.alloc(length)
      const readBytes = fs.readSync(fd, buf, 0, length, offset)
      try { fs.closeSync(fd) } catch {}
      if (!readBytes) return null
      const line = buf.toString('utf8').trim()
      if (!line) return null
      const parsed = JSON.parse(line)
      return normalizeStoreEntry(parsed)
    } catch {
      return null
    }
  }

  /**
 * - 函数: `mergeSignatureMeta`
 * - Function: `mergeSignatureMeta`
 * - 作用: 合并签名元数据相关结果，输出统一结构给上游调用方。
 * - Purpose: Merges the signature metadata results and produces a unified structure for upstream callers.
 * - 调用方: `applySignatureDelta` 在回放已有 delta 时调用；`persistSignatureStore` 在生成新 delta 或更新已有签名项元数据时调用。
 * - Callers: Called by `applySignatureDelta` while replaying stored deltas, and by `persistSignatureStore` while creating a new delta or updating metadata on existing signatures.
 * - 被调方: `Number.isFinite`。
 * - Callees: `Number.isFinite`.
 * - 变量说明: `a` 为当前流程传入的a；`b` 为当前流程传入的b；`ma`, `mb` 为函数内部派生的中间状态。
 * - Variables: `a` is the incoming a for this flow; `b` is the incoming b for this flow; `ma`, `mb` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `mergeSignatureMeta`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `mergeSignatureMeta` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 合并 | 签名 | 元数据 | merge | signature | metadata | call chain | 错误处理 | error handling | 复用
 */
  function mergeSignatureMeta(a, b) {
    const ma = a && typeof a === 'object' ? a : {}
    const mb = b && typeof b === 'object' ? b : {}
    const out = {}
    const ok = (ma.ok === true) || (mb.ok === true)
    out.ok = ok
    const total = (Number.isFinite(ma.total) ? ma.total : 0) + (Number.isFinite(mb.total) ? mb.total : 0)
    const trained = (Number.isFinite(ma.trained) ? ma.trained : 0) + (Number.isFinite(mb.trained) ? mb.trained : 0)
    const failed = (Number.isFinite(ma.failed) ? ma.failed : 0) + (Number.isFinite(mb.failed) ? mb.failed : 0)
    out.total = total
    out.trained = trained
    out.failed = failed
    if (typeof ma.type === 'string' && ma.type) out.type = ma.type
    else if (typeof mb.type === 'string' && mb.type) out.type = mb.type
    return out
  }

  /**
 * - 函数: `applyDeltaStats`
 * - Function: `applyDeltaStats`
 * - 作用: 把单个 delta 中记录的统计增量累加回当前内存特征库，用于在 snapshot 基础上恢复 API、序列和模糊哈希统计面板。
 * - Purpose: Folds statistic increments from one delta back into the current in-memory store, rebuilding API, sequence, and fuzzy-hash statistics on top of a snapshot.
 * - 调用方: `applySignatureDelta` 在回放单个 delta 记录时调用。
 * - Callers: Called by `applySignatureDelta` while replaying one delta record.
 * - 被调方: `Number.isFinite`。
 * - Callees: `Number.isFinite`.
 * - 变量说明: `storeStats` 为当前内存中的统计表；`deltaStats` 为本次 delta 带来的增量；`keys` 为需要合并的统计键集合。
 * - Variables: `storeStats` is the current in-memory stats table; `deltaStats` is the increment carried by the delta; `keys` lists the stat keys that need merging.
 * - 接入方式: 仅作为 delta 回放辅助函数使用；统计结构演进时应在这里统一调整增量合并规则。
 * - Integration: Use it only as a delta-replay helper; if stat structures evolve, merge semantics should be updated here centrally.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 增量统计回放 | delta stats replay | counter merge | api_stats | sequence_stats | fuzzy_stats | snapshot continuation | in-memory rebuild
 */
  function applyDeltaStats(storeStats, deltaStats) {
    if (!deltaStats || typeof deltaStats !== 'object') return
    const keys = Object.keys(deltaStats)
    for (const key of keys) {
      const cur = storeStats[key] || { mal: 0, white: 0 }
      const inc = deltaStats[key] || {}
      const mal = Number.isFinite(inc.mal) ? inc.mal : 0
      const white = Number.isFinite(inc.white) ? inc.white : 0
      cur.mal = (Number.isFinite(cur.mal) ? cur.mal : 0) + mal
      cur.white = (Number.isFinite(cur.white) ? cur.white : 0) + white
      storeStats[key] = cur
    }
  }

  /**
 * - 函数: `applySignatureDelta`
 * - Function: `applySignatureDelta`
 * - 作用: 将单条 delta 记录应用到当前内存特征库，把新增/更新的签名项和统计增量恢复到最新版本状态，是版本回放链中的核心补丁步骤。
 * - Purpose: Applies one delta record to the current in-memory store, restoring newly added or updated signatures together with stat increments as the core patch step in version replay.
 * - 调用方: `readSignatureStoreFromFile` 在从最近 snapshot 向当前版本逐条回放 delta 时调用。
 * - Callers: Called by `readSignatureStoreFromFile` while replaying deltas one by one from the nearest snapshot toward the active version.
 * - 被调方: `applyDeltaStats`、`push`、`mergeSignatureMeta`、`Array.isArray`、`Number.isFinite`、`Date.now`。
 * - Callees: `applyDeltaStats`, `push`, `mergeSignatureMeta`, `Array.isArray`, `Number.isFinite`, `Date.now`.
 * - 变量说明: `store` 为正在恢复的内存特征库；`delta` 为当前版本记录中的增量内容；`sigs` 为需要合并的签名列表；`item` 为当前处理的单个签名增量。
 * - Variables: `store` is the in-memory store being reconstructed; `delta` is the incremental payload from the current version record; `sigs` is the signature list to merge; `item` is the signature delta currently being applied.
 * - 接入方式: 仅应作为 snapshot 回放后的补丁步骤使用；新增 delta 字段时要优先扩展本函数，否则读取链无法正确还原当前版本。
 * - Integration: It should only be used as the post-snapshot patch step; any new delta fields must be added here first or the read path will fail to reconstruct the active version correctly.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 版本补丁回放 | version patch replay | delta apply | signature merge | metadata merge | active version rebuild | snapshot plus delta | store reconstruction
 */
  function applySignatureDelta(store, delta) {
    if (!store || !delta || typeof delta !== 'object') return
    if (delta.api_stats) applyDeltaStats(store.api_stats, delta.api_stats)
    if (delta.api_sequences) applyDeltaStats(store.api_sequences, delta.api_sequences)
    if (delta.fuzzy_stats) applyDeltaStats(store.fuzzy_stats, delta.fuzzy_stats)
    const sigs = Array.isArray(delta.signatures) ? delta.signatures : []
    for (const item of sigs) {
      if (!item || typeof item !== 'object') continue
      const code = typeof item.code === 'string' ? item.code : ''
      if (!code) continue
      const existing = store.signatures.find(s => s && s.code === code)
      if (!existing) {
        store.signatures.push({
          code,
          features: item.features || {},
          meta: item.meta || {},
          ts: Number.isFinite(item.ts) ? item.ts : Date.now(),
          count: Number.isFinite(item.count) ? item.count : 1,
          first_ts: Number.isFinite(item.first_ts) ? item.first_ts : Date.now(),
          last_ts: Number.isFinite(item.last_ts) ? item.last_ts : Date.now()
        })
      } else {
        existing.meta = mergeSignatureMeta(existing.meta, item.meta)
        existing.ts = Number.isFinite(item.ts) ? item.ts : Date.now()
        existing.count = (Number.isFinite(existing.count) ? existing.count : 0) + (Number.isFinite(item.count) ? item.count : 1)
        if (!Number.isFinite(existing.first_ts)) existing.first_ts = Number.isFinite(item.first_ts) ? item.first_ts : Date.now()
        existing.last_ts = Number.isFinite(item.last_ts) ? item.last_ts : Date.now()
      }
    }
  }

  /**
 * - 函数: `updateApiStats`
 * - Function: `updateApiStats`
 * - 作用: 更新apistats上的统计或状态字段，保持上下游数据一致。
 * - Purpose: Updates the stats or state fields on the api stats and keeps upstream and downstream data aligned.
 * - 调用方: `persistSignatureStore` 在把 API 列表写入内存库和 delta 统计时调用。
 * - Callers: Called by `persistSignatureStore` while folding API lists into the in-memory store and delta statistics.
 * - 被调方: `Array.isArray`。
 * - Callees: `Array.isArray`.
 * - 变量说明: `store` 为当前流程传入的特征库；`apis` 为当前流程传入的apis；`isWhite` 为当前流程传入的判断white；`api`, `key` 为函数内部派生的中间状态。
 * - Variables: `store` is the incoming signature store for this flow; `apis` is the incoming apis for this flow; `isWhite` is the incoming check white for this flow; `api`, `key` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `updateApiStats`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `updateApiStats` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 更新 | api | stats | update | api | stats | call chain | 错误处理 | error handling | 复用
 */
  function updateApiStats(store, apis, isWhite, delta) {
    if (!Array.isArray(apis) || !apis.length) return
    for (const api of apis) {
      const key = typeof api === 'string' ? api.toLowerCase() : ''
      if (!key) continue
      const cur = store.api_stats[key] || { mal: 0, white: 0 }
      if (isWhite) cur.white += 1
      else cur.mal += 1
      store.api_stats[key] = cur
      if (delta) {
        const d = delta.api_stats || (delta.api_stats = {})
        const cd = d[key] || { mal: 0, white: 0 }
        if (isWhite) cd.white += 1
        else cd.mal += 1
        d[key] = cd
      }
    }
  }

  /**
 * - 函数: `updateSequenceStats`
 * - Function: `updateSequenceStats`
 * - 作用: 更新sequencestats上的统计或状态字段，保持上下游数据一致。
 * - Purpose: Updates the stats or state fields on the sequence stats and keeps upstream and downstream data aligned.
 * - 调用方: `persistSignatureStore` 在写入 API 序列特征及其增量统计时调用。
 * - Callers: Called by `persistSignatureStore` while recording API-sequence features and their incremental statistics.
 * - 被调方: `Array.isArray`。
 * - Callees: `Array.isArray`.
 * - 变量说明: `store` 为当前流程传入的特征库；`seq` 为当前流程传入的seq；`isWhite` 为当前流程传入的判断white；`key`, `cur` 为函数内部派生的中间状态。
 * - Variables: `store` is the incoming signature store for this flow; `seq` is the incoming seq for this flow; `isWhite` is the incoming check white for this flow; `key`, `cur` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `updateSequenceStats`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `updateSequenceStats` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 更新 | sequence | stats | update | sequence | stats | call chain | 错误处理 | error handling | 复用
 */
  function updateSequenceStats(store, seq, isWhite, delta) {
    if (!Array.isArray(seq) || seq.length < 3) return
    const key = seq.join('>')
    if (!key) return
    const cur = store.api_sequences[key] || { mal: 0, white: 0 }
    if (isWhite) cur.white += 1
    else cur.mal += 1
    store.api_sequences[key] = cur
    if (delta) {
      const d = delta.api_sequences || (delta.api_sequences = {})
      const cd = d[key] || { mal: 0, white: 0 }
      if (isWhite) cd.white += 1
      else cd.mal += 1
      d[key] = cd
    }
  }

  /**
 * - 函数: `updateFuzzyStats`
 * - Function: `updateFuzzyStats`
 * - 作用: 更新fuzzystats上的统计或状态字段，保持上下游数据一致。
 * - Purpose: Updates the stats or state fields on the fuzzy stats and keeps upstream and downstream data aligned.
 * - 调用方: `persistSignatureStore` 在写入 fuzzy 哈希特征及其增量统计时调用。
 * - Callers: Called by `persistSignatureStore` while recording fuzzy-hash features and their incremental statistics.
 * - 被调方: `Array.isArray`。
 * - Callees: `Array.isArray`.
 * - 变量说明: `store` 为当前流程传入的特征库；`hashes` 为当前流程传入的hashes；`isWhite` 为当前流程传入的判断white；`key`, `cur` 为函数内部派生的中间状态。
 * - Variables: `store` is the incoming signature store for this flow; `hashes` is the incoming hashes for this flow; `isWhite` is the incoming check white for this flow; `key`, `cur` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `updateFuzzyStats`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `updateFuzzyStats` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 更新 | fuzzy | stats | update | fuzzy | stats | call chain | 错误处理 | error handling | 复用
 */
  function updateFuzzyStats(store, hashes, isWhite, delta) {
    if (!Array.isArray(hashes) || !hashes.length) return
    const key = hashes.join('.')
    if (!key) return
    const cur = store.fuzzy_stats[key] || { mal: 0, white: 0 }
    if (isWhite) cur.white += 1
    else cur.mal += 1
    store.fuzzy_stats[key] = cur
    if (delta) {
      const d = delta.fuzzy_stats || (delta.fuzzy_stats = {})
      const cd = d[key] || { mal: 0, white: 0 }
      if (isWhite) cd.white += 1
      else cd.mal += 1
      d[key] = cd
    }
  }

  /**
 * - 函数: `sleepSync`
 * - Function: `sleepSync`
 * - 作用: 在签名库文件锁竞争时执行短暂同步等待，给其他写入方释放 `.lock` 文件的时间，避免自旋重试过于激进。
 * - Purpose: Performs a short synchronous wait during signature-store lock contention, giving other writers time to release the `.lock` file so retry loops are not overly aggressive.
 * - 调用方: `withSignatureStoreLock` 在获取文件锁失败后重试前调用。
 * - Callers: Called by `withSignatureStoreLock` between retries after failing to acquire the file lock.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `ms` 为阻塞等待毫秒数；`sab/i32` 是通过 `Atomics.wait` 实现同步 sleep 的最小共享内存载体。
 * - Variables: `ms` is the blocking wait duration in milliseconds; `sab/i32` is the minimal shared-memory carrier used to implement sync sleep through `Atomics.wait`.
 * - 接入方式: 仅供锁竞争控制逻辑使用；不要把它扩散到普通扫描或训练路径中。
 * - Integration: Use it only for lock-contention control; it should not spread into ordinary scan or training paths.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 同步退避 | synchronous backoff | lock retry delay | Atomics.wait | contention control | signature store lock | spin reduction | blocking sleep
 */
  function sleepSync(ms) {
    try {
      const sab = new SharedArrayBuffer(4)
      const i32 = new Int32Array(sab)
      Atomics.wait(i32, 0, 0, ms)
    } catch {}
  }

  /**
 * - 函数: `buildStoreFromSnapshotEntry`
 * - Function: `buildStoreFromSnapshotEntry`
 * - 作用: 将磁盘中的 snapshot 记录恢复成可直接使用的内存特征库对象，作为后续 delta 回放的基准状态。
 * - Purpose: Reconstructs a directly usable in-memory signature store from a snapshot record on disk, providing the baseline state for subsequent delta replay.
 * - 调用方: `readSignatureStoreFromFile` 在找到最近 snapshot 后调用。
 * - Callers: Called by `readSignatureStoreFromFile` after locating the nearest snapshot in the version chain.
 * - 被调方: `ensureSignatureStoreShape`、`Number.isFinite`、`Date.now`。
 * - Callees: `ensureSignatureStoreShape`, `Number.isFinite`, `Date.now`.
 * - 变量说明: `entry` 为 snapshot 原始记录；`versionIdOverride` 用于在缺失版本号时回填索引中的版本 ID；`store` 为恢复后的内存库对象。
 * - Variables: `entry` is the raw snapshot record; `versionIdOverride` backfills the version id from index metadata when the entry lacks one; `store` is the reconstructed in-memory store.
 * - 接入方式: 仅供签名库回放链复用；外部不要直接用 snapshot JSON 当作最终对象，应先经过本函数补齐结构。
 * - Integration: Use it only in the store replay path; external code should not treat raw snapshot JSON as the final object before it passes through this normalizer.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 快照恢复 | snapshot restore | in-memory store | version baseline | replay base | store normalization | snapshot entry | current state seed
 */
  function buildStoreFromSnapshotEntry(entry, versionIdOverride) {
    if (!entry || typeof entry !== 'object') return ensureSignatureStoreShape(null)
    const store = ensureSignatureStoreShape({
      version: entry.version,
      version_id: entry.version_id || versionIdOverride || '',
      parent_version_id: entry.parent_version_id || '',
      updated_at: Number.isFinite(entry.updated_at) ? entry.updated_at : Date.now(),
      signatures: entry.signatures,
      api_stats: entry.api_stats,
      api_sequences: entry.api_sequences,
      fuzzy_stats: entry.fuzzy_stats,
      meta: entry.meta
    })
    return store
  }

  /**
 * - 函数: `readSignatureStoreFromFile`
 * - Function: `readSignatureStoreFromFile`
 * - 作用: 读取日志式签名库的当前生效版本，优先借助索引定位最近 snapshot，再顺序回放后续 delta，最终恢复出供命中与训练复用的完整内存视图。
 * - Purpose: Loads the active version of the append-only signature store by locating the nearest snapshot through the index and replaying subsequent deltas in order, producing the full in-memory view reused by matching and training.
 * - 调用方: `persistSignatureStore` 在追加前读取当前库状态；`loadSignatureStore` 在扫描命中前加载当前生效版本。
 * - Callers: Called by `persistSignatureStore` before appending new data and by `loadSignatureStore` before signature matching loads the current active version.
 * - 被调方: `ensureSignatureStoreShape`、`readSignatureIndex`、`rebuildSignatureIndex`、`normalizeStoreEntry`、`buildStoreFromSnapshotEntry`、`readStoreEntryByOffset`。
 * - Callees: `ensureSignatureStoreShape`, `readSignatureIndex`, `rebuildSignatureIndex`, `normalizeStoreEntry`, `buildStoreFromSnapshotEntry`, `readStoreEntryByOffset`.
 * - 变量说明: `storePath` 为签名库文件；`indexPath` 为版本索引文件；`index` 保存版本链元数据；`currentId/endIdx/startIdx` 用于确定当前版本回放窗口；`store` 为最终恢复出的内存库对象。
 * - Variables: `storePath` is the signature-store file; `indexPath` is the version index file; `index` holds version-chain metadata; `currentId/endIdx/startIdx` define the replay window; `store` is the reconstructed in-memory store.
 * - 接入方式: 应作为所有签名库读取的统一入口；新增“读当前版本”类能力应复用本函数，不要自行拆解 snapshot/delta 文件格式。
 * - Integration: It should remain the unified read entry for the signature store; any new “read active version” feature should reuse this function instead of parsing snapshot/delta formats independently.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 当前版本回放 | active version replay | snapshot plus delta | index-assisted load | store reconstruction | current_version_id | resilient read | fallback rebuild
 */
  function readSignatureStoreFromFile(storePath, indexPath) {
    try {
      if (!storePath || !fs.existsSync(storePath)) return { store: ensureSignatureStoreShape(null), index: null }
      let index = readSignatureIndex(indexPath)
      if (!index) index = rebuildSignatureIndex(storePath, indexPath)
      if (!index || !Array.isArray(index.versions) || !index.versions.length) {
        const raw = fs.readFileSync(storePath, 'utf8')
        const text = raw ? String(raw).trim() : ''
        if (!text) return { store: ensureSignatureStoreShape(null), index: null }
        const lines = text.split(/\r?\n/)
        for (let i = lines.length - 1; i >= 0; i--) {
          const line = lines[i].trim()
          if (!line) continue
          try {
            const parsed = JSON.parse(line)
            const normalized = normalizeStoreEntry(parsed)
            if (normalized && normalized.entry_type === 'snapshot') {
              return { store: buildStoreFromSnapshotEntry(normalized), index: null }
            }
          } catch {}
        }
        return { store: ensureSignatureStoreShape(null), index: null }
      }
      const currentId = index.current_version_id || index.versions[index.versions.length - 1].id
      const currentIdx = index.versions.findIndex(v => v && v.id === currentId)
      const endIdx = currentIdx >= 0 ? currentIdx : (index.versions.length - 1)
      let startIdx = -1
      for (let i = endIdx; i >= 0; i--) {
        const v = index.versions[i]
        if (v && v.entry_type === 'snapshot') {
          startIdx = i
          break
        }
      }
      if (startIdx < 0) startIdx = 0
      const baseEntryInfo = index.versions[startIdx]
      let store = ensureSignatureStoreShape(null)
      let applyStart = startIdx
      if (baseEntryInfo && baseEntryInfo.entry_type === 'snapshot') {
        const baseEntry = readStoreEntryByOffset(storePath, baseEntryInfo.offset, baseEntryInfo.length)
        store = buildStoreFromSnapshotEntry(baseEntry, baseEntryInfo.id)
        applyStart = startIdx + 1
      }
      for (let i = applyStart; i <= endIdx; i++) {
        const info = index.versions[i]
        const entry = readStoreEntryByOffset(storePath, info.offset, info.length)
        if (!entry) continue
        if (entry.entry_type === 'snapshot') {
          store = buildStoreFromSnapshotEntry(entry, info.id)
        } else if (entry.entry_type === 'delta') {
          applySignatureDelta(store, entry.delta || {})
          store.updated_at = Number.isFinite(entry.updated_at) ? entry.updated_at : Date.now()
        }
      }
      store.version_id = currentId
      const curInfo = index.versions[endIdx]
      store.parent_version_id = curInfo && typeof curInfo.parent_id === 'string' ? curInfo.parent_id : store.parent_version_id
      return { store: ensureSignatureStoreShape(store), index }
    } catch {
      return { store: ensureSignatureStoreShape(null), index: null }
    }
  }

  /**
 * - 函数: `withSignatureStoreLock`
 * - Function: `withSignatureStoreLock`
 * - 作用: 为签名库写入操作加上进程级文件锁，保证 snapshot/delta 追加与索引更新在单写者上下文中完成，避免并发训练把版本链写乱。
 * - Purpose: Wraps signature-store writes in a process-level file lock so snapshot/delta appends and index updates complete under a single-writer context, preventing concurrent training from corrupting version lineage.
 * - 调用方: `persistSignatureStore` 在真正写入签名库与索引前调用。
 * - Callers: Called by `persistSignatureStore` before performing the actual store and index writes.
 * - 被调方: `sleepSync`、`fs.openSync`、`fs.closeSync`。
 * - Callees: `sleepSync`, `fs.openSync`, `fs.closeSync`.
 * - 变量说明: `storePath` 为待保护的签名库主文件；`fn` 为持锁期间真正执行的写入逻辑；`lockPath` 为 `.lock` 文件路径；`fd` 表示当前是否成功持有文件锁。
 * - Variables: `storePath` is the protected signature-store file; `fn` is the write logic executed while holding the lock; `lockPath` is the `.lock` file path; `fd` indicates whether the lock is currently held.
 * - 接入方式: 仅供签名库写链内部调用；任何需要改写版本链的逻辑都应经过本函数，不要绕过文件锁直接写盘。
 * - Integration: Use it only inside the signature-store write path; any logic that mutates version lineage should go through this lock instead of writing directly.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 文件锁 | file lock | single writer | version lineage safety | lock file | concurrent training guard | append serialization | safe commit
 */
  function withSignatureStoreLock(storePath, fn) {
    const lockPath = storePath + '.lock'
    let fd = null
    for (let i = 0; i < 200; i++) {
      try {
        fd = fs.openSync(lockPath, 'wx')
        break
      } catch {
        sleepSync(10)
      }
    }
    try {
      if (!fd) return false
      return fn()
    } finally {
      if (fd) {
        try { fs.closeSync(fd) } catch {}
        try { fs.unlinkSync(lockPath) } catch {}
      }
    }
  }

  /**
 * - 函数: `buildSignatureStoreMeta`
 * - Function: `buildSignatureStoreMeta`
 * - 作用: 构建签名特征库元数据结构或配置，供后续计算、扫描或持久化流程使用。
 * - Purpose: Builds the signature signature store metadata structure or configuration for later compute, scan, or persistence flows.
 * - 调用方: `persistSignatureStore` 在准备落盘 snapshot 或 delta 之前调用，用于刷新总签名数和更新时间等库级元数据。
 * - Callers: Called by `persistSignatureStore` before flushing snapshot or delta commits so store-level metadata such as total signatures and updated time can be refreshed.
 * - 被调方: `Array.isArray`。
 * - Callees: `Array.isArray`.
 * - 变量说明: `store` 为当前流程传入的特征库；`meta` 为函数内部派生的中间状态。
 * - Variables: `store` is the incoming signature store for this flow; `meta` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `buildSignatureStoreMeta`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `buildSignatureStoreMeta` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 构建 | 签名 | 特征库 | 元数据 | build | signature | signature store | metadata | error handling | 复用
 */
  function buildSignatureStoreMeta(store) {
    const meta = store && store.meta && typeof store.meta === 'object' ? store.meta : {}
    meta.total_signatures = Array.isArray(store.signatures) ? store.signatures.length : 0
    meta.updated_at = store.updated_at
    store.meta = meta
  }

  /**
 * - 函数: `createVersionId`
 * - Function: `createVersionId`
 * - 作用: 为每次签名库提交生成唯一版本号，作为 snapshot/delta、索引记录和回滚指针之间的稳定关联键。
 * - Purpose: Generates a unique version id for each signature-store commit, serving as the stable linkage key across snapshot/delta records, index entries, and rollback pointers.
 * - 调用方: `persistSignatureStore` 在提交新版本前调用。
 * - Callers: Called by `persistSignatureStore` before committing a new version.
 * - 被调方: `Date.now`。
 * - Callees: `Date.now`.
 * - 变量说明: 无显式入参；`ts` 提供按时间排序的前缀；`rand` 提供同毫秒内的冲突隔离。
 * - Variables: No explicit parameters; `ts` provides the time-ordered prefix and `rand` provides collision isolation within the same millisecond.
 * - 接入方式: 仅供版本化写库链路使用；不要用它替代普通请求 ID 或扫描任务 ID。
 * - Integration: Use it only in the versioned persistence path; it should not replace ordinary request ids or scan task ids.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 版本号生成 | version id generation | commit id | rollback pointer | unique lineage key | timestamp plus random | store versioning | snapshot delta id
 */
  function createVersionId() {
    const ts = Date.now()
    const rand = crypto.randomBytes(8).toString('hex')
    return `${ts}-${rand}`
  }

  /**
 * - 函数: `persistSignatureStore`
 * - Function: `persistSignatureStore`
 * - 作用: 将训练产出的特征与统计增量追加到 JS 签名库文件，必要时写入快照、维护版本索引，并返回本次提交生成的版本 ID。
 * - Purpose: Appends training-generated features and statistical deltas into the JS signature-store file, writes a snapshot when needed, maintains the version index, and returns the version id created for this commit.
 * - 调用方: `processSignatureWriteQueue` 串行消费训练写队列时调用；也可被上层直接用作即时写入入口。
 * - Callers: Called by `processSignatureWriteQueue` while serially draining the training write queue, and can also serve as the direct immediate write entry.
 * - 被调方: `resolveSignatureStorePath`、`resolveSignatureIndexPath`、`withSignatureStoreLock`、`readSignatureStoreFromFile`、`ensureSignatureStoreShape`、`ensureSignatureIndexShape`。
 * - Callees: `resolveSignatureStorePath`, `resolveSignatureIndexPath`, `withSignatureStoreLock`, `readSignatureStoreFromFile`, `ensureSignatureStoreShape`, `ensureSignatureIndexShape`.
 * - 变量说明: `result` 保存训练统计；`features` 为待写入的 Raven 特征；`meta` 为样本元数据；`delta` 记录本次增量变化；`versionId` 为本次写入后的可回滚版本号。
 * - Variables: `result` carries training stats; `features` holds the Raven features to store; `meta` is sample metadata; `delta` captures this write’s incremental changes; `versionId` is the rollback-capable version created for the write.
 * - 接入方式: 通过 `signatureStore.append(...)` 或训练队列间接接入；所有签名库写入都应复用本函数，避免绕过版本链与索引维护逻辑。
 * - Integration: Use it through `signatureStore.append(...)` or indirectly through the training queue; all signature-store writes should reuse this helper to avoid bypassing version-chain and index maintenance.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 签名库存盘 | signature store persistence | versioned append | snapshot or delta | store lock | index maintenance | rollback chain | training commit
 */
  function persistSignatureStore(result, features, meta, isWhite) {
    try {
      const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
      const scanner = cfg && cfg.scanner ? cfg.scanner : {}
      const storePath = resolveSignatureStorePath(scanner)
      if (!storePath) return { ok: false, versionId: '' }
      const indexPath = resolveSignatureIndexPath(scanner)
      return withSignatureStoreLock(storePath, () => {
        const state = readSignatureStoreFromFile(storePath, indexPath)
        const store = state && state.store ? state.store : ensureSignatureStoreShape(null)
        const index = state && state.index ? state.index : ensureSignatureIndexShape(null)
        const payload = buildSignatureFeaturePayload(result, features, meta)
        const code = makeFeatureCode(payload.features)
        if (!code) return { ok: false, versionId: '' }
        const delta = { signatures: [] }
        updateApiStats(store, payload.features.apis, isWhite, delta)
        updateSequenceStats(store, payload.features.api_seq, isWhite, delta)
        updateFuzzyStats(store, payload.features.fuzzy, isWhite, delta)
        if (!isWhite) {
          const now = Date.now()
          const existing = store.signatures.find(s => s && s.code === code)
          if (!existing) {
            const entry = { code, features: payload.features, meta: payload.meta, ts: now, count: 1, first_ts: now, last_ts: now }
            store.signatures.push(entry)
            delta.signatures.push(Object.assign({ action: 'add' }, entry))
          } else {
            existing.meta = mergeSignatureMeta(existing.meta, payload.meta)
            existing.ts = now
            existing.count = (Number.isFinite(existing.count) ? existing.count : 0) + 1
            if (!Number.isFinite(existing.first_ts)) existing.first_ts = now
            existing.last_ts = now
            delta.signatures.push({
              action: 'update',
              code,
              meta: existing.meta,
              ts: existing.ts,
              count: 1,
              first_ts: existing.first_ts,
              last_ts: existing.last_ts
            })
          }
        }
        const parentId = store.version_id || index.current_version_id || ''
        const versionId = createVersionId()
        store.parent_version_id = parentId
        store.version_id = versionId
        store.updated_at = Date.now()
        buildSignatureStoreMeta(store)
        const snapshotEvery = Number.isFinite(scanner.signatureSnapshotEvery)
          ? Math.max(1, Math.floor(scanner.signatureSnapshotEvery))
          : 50
        const needSnapshot = index.delta_since_snapshot >= snapshotEvery || !index.last_snapshot_version_id
        const entry = needSnapshot
          ? {
              entry_type: 'snapshot',
              version: store.version,
              version_id: store.version_id,
              parent_version_id: store.parent_version_id,
              updated_at: store.updated_at,
              signatures: store.signatures,
              api_stats: store.api_stats,
              api_sequences: store.api_sequences,
              fuzzy_stats: store.fuzzy_stats,
              meta: store.meta
            }
          : {
              entry_type: 'delta',
              version: store.version,
              version_id: store.version_id,
              parent_version_id: store.parent_version_id,
              updated_at: store.updated_at,
              delta: delta,
              meta: store.meta
            }
        const line = JSON.stringify(entry) + '\n'
        const offset = fs.existsSync(storePath) ? fs.statSync(storePath).size : 0
        const length = Buffer.byteLength(line, 'utf8')
        fs.appendFileSync(storePath, line)
        index.versions.push({
          id: versionId,
          parent_id: parentId,
          ts: store.updated_at,
          offset,
          length,
          entry_type: entry.entry_type
        })
        index.current_version_id = versionId
        if (entry.entry_type === 'snapshot') {
          index.last_snapshot_version_id = versionId
          index.delta_since_snapshot = 0
        } else {
          index.delta_since_snapshot = (Number.isFinite(index.delta_since_snapshot) ? index.delta_since_snapshot : 0) + 1
        }
        writeSignatureIndex(indexPath, index)
        return { ok: true, versionId }
      })
    } catch {
      return { ok: false, versionId: '' }
    }
  }

  /**
 * - 函数: `loadSignatureStore`
 * - Function: `loadSignatureStore`
 * - 作用: 读取当前生效的 JS 签名库版本，必要时通过索引回放快照与增量恢复完整内存视图，为特征命中和版本管理提供统一加载入口。
 * - Purpose: Loads the currently active JS signature-store version, rebuilding a full in-memory view from snapshots and deltas when needed, and serves as the unified load entry for feature matching and version management.
 * - 调用方: `scanRavenByStore` 在无外部覆盖库时调用；版本查询与回滚链路也会依赖同一套读取结果。
 * - Callers: Called by `scanRavenByStore` when no override store is supplied, and also relied upon by version-query and rollback flows.
 * - 被调方: `resolveSignatureStorePath`、`resolveSignatureIndexPath`、`readSignatureStoreFromFile`、`ensureSignatureStoreShape`。
 * - Callees: `resolveSignatureStorePath`, `resolveSignatureIndexPath`, `readSignatureStoreFromFile`, `ensureSignatureStoreShape`.
 * - 变量说明: 无显式入参；`scanner` 为当前扫描配置；`storePath`/`indexPath` 分别指向日志式特征库文件和版本索引文件；返回值为归一化后的完整库对象。
 * - Variables: No explicit parameters; `scanner` is the current scanner config; `storePath` and `indexPath` point to the append-only store file and version index; the return value is the normalized full store object.
 * - 接入方式: 通过 `signatureStore.loadCurrent()` 或内部命中链路接入；外部不要直接解析 `.db`/`.index.json` 文件。
 * - Integration: Use it through `signatureStore.loadCurrent()` or internal matching flows; external code should not parse the store and index files directly.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 当前签名库加载 | load current store | snapshot replay | delta replay | in-memory store | active version | version chain | read path
 */
  function loadSignatureStore() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const storePath = resolveSignatureStorePath(scanner)
    const indexPath = resolveSignatureIndexPath(scanner)
    if (!storePath) return null
    const state = readSignatureStoreFromFile(storePath, indexPath)
    return state && state.store ? state.store : ensureSignatureStoreShape(null)
  }

  /**
 * - 函数: `computeApiWeightScore`
 * - Function: `computeApiWeightScore`
 * - 作用: 计算apiweightscore相关分值或结果，为后续决策提供依据。
 * - Purpose: Computes the api weight score score or result to support later decisions.
 * - 调用方: `scanRavenByStore` 在基于 API 统计给样本打分时调用。
 * - Callers: Called by `scanRavenByStore` while scoring samples from API statistics.
 * - 被调方: `Array.isArray`、`Number.isFinite`、`Math.max`、`Math.min`。
 * - Callees: `Array.isArray`, `Number.isFinite`, `Math.max`, `Math.min`.
 * - 变量说明: `apis` 为当前流程传入的apis；`store` 为当前流程传入的特征库；`sum`, `api` 为函数内部派生的中间状态。
 * - Variables: `apis` is the incoming apis for this flow; `store` is the incoming signature store for this flow; `sum`, `api` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `computeApiWeightScore`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `computeApiWeightScore` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 计算 | api | weight | score | compute | api | weight | score | error handling | 复用
 */
  function computeApiWeightScore(apis, store) {
    if (!Array.isArray(apis) || !apis.length || !store || !store.api_stats) return 0
    let sum = 0
    for (const api of apis) {
      const key = typeof api === 'string' ? api.toLowerCase() : ''
      if (!key) continue
      const cur = store.api_stats[key]
      if (!cur) continue
      const mal = Number.isFinite(cur.mal) ? cur.mal : 0
      const white = Number.isFinite(cur.white) ? cur.white : 0
      const w = Math.log((mal + 1) / (white + 1))
      sum += w
    }
    const avg = sum / Math.max(1, apis.length)
    if (avg <= 0.5) return 0
    return Math.min(1, avg / 4)
  }

  /**
 * - 函数: `hasSequenceHit`
 * - Function: `hasSequenceHit`
 * - 作用: 判断当前上下文是否具备sequencehit特征，并返回布尔化结果。
 * - Purpose: Checks whether the current context has the sequence hit characteristic and returns a boolean-style result.
 * - 调用方: `scanRavenByStore` 在检查恶意 API 序列片段是否命中已知模式时调用。
 * - Callers: Called by `scanRavenByStore` when checking whether malicious API-sequence fragments match known patterns.
 * - 被调方: `Array.isArray`。
 * - Callees: `Array.isArray`.
 * - 变量说明: `apis` 为当前流程传入的apis；`store` 为当前流程传入的特征库；`joined`, `keys` 为函数内部派生的中间状态。
 * - Variables: `apis` is the incoming apis for this flow; `store` is the incoming signature store for this flow; `joined`, `keys` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `hasSequenceHit`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `hasSequenceHit` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 判断 | sequence | hit | check | sequence | hit | call chain | 错误处理 | error handling | 复用
 */
  function hasSequenceHit(apis, store) {
    if (!Array.isArray(apis) || apis.length < 3 || !store || !store.api_sequences) return false
    const joined = apis.join('>')
    const keys = Object.keys(store.api_sequences)
    for (const key of keys) {
      const cur = store.api_sequences[key]
      if (!cur || cur.mal <= cur.white) continue
      if (joined.includes(key)) return true
    }
    return false
  }

  /**
 * - 函数: `findFuzzySimilarity`
 * - Function: `findFuzzySimilarity`
 * - 作用: 在当前搜索范围内查找fuzzysimilarity，并返回首个可用结果。
 * - Purpose: Finds the fuzzy similarity within the current search scope and returns the first usable result.
 * - 调用方: `scanRavenByStore` 在遍历历史签名的 fuzzy 哈希特征时调用，用于找出最佳相似度。
 * - Callers: Called by `scanRavenByStore` while iterating over stored fuzzy-hash features to find the best similarity score.
 * - 被调方: `fuzzySimilarity`、`Array.isArray`。
 * - Callees: `fuzzySimilarity`, `Array.isArray`.
 * - 变量说明: `hashes` 为当前流程传入的hashes；`store` 为当前流程传入的特征库；`best`, `sig` 为函数内部派生的中间状态。
 * - Variables: `hashes` is the incoming hashes for this flow; `store` is the incoming signature store for this flow; `best`, `sig` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `findFuzzySimilarity`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `findFuzzySimilarity` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 查找 | fuzzy | similarity | find | fuzzy | similarity | call chain | 错误处理 | error handling | 复用
 */
  function findFuzzySimilarity(hashes, store) {
    if (!Array.isArray(hashes) || !hashes.length || !store || !store.signatures) return 0
    let best = 0
    for (const sig of store.signatures) {
      const fz = sig && sig.features ? sig.features.fuzzy : null
      if (!Array.isArray(fz) || !fz.length) continue
      const sim = fuzzySimilarity(hashes, fz)
      if (sim > best) best = sim
    }
    return best
  }

  /**
 * - 函数: `scanRavenByStore`
 * - Function: `scanRavenByStore`
 * - 作用: 用 JS 签名库对单个样本执行特征命中，综合精确特征码、模糊哈希、API 权重、API 序列和脚本可疑度生成签名分数，是 native 签名结果之外的补充判定层。
 * - Purpose: Runs JS signature matching for a single sample, combining exact feature codes, fuzzy hashes, API weights, API sequences, and script suspiciousness into a signature score as the supplemental verdict layer beyond native signature results.
 * - 调用方: 扫描链路在需要用 Raven 特征库补充 native 签名判断时调用，包括 `kvdScanFileSig` 与 `kvdScanPathsSig` 的内部流程。
 * - Callers: Called when the scan pipeline needs Raven-store matching to supplement native signature checks, including internal flows under `kvdScanFileSig` and `kvdScanPathsSig`.
 * - 被调方: `verifyTrusted`、`loadSignatureStore`、`extractRavenFeatures`、`makeFeatureCode`、`push`、`findFuzzySimilarity`。
 * - Callees: `verifyTrusted`, `loadSignatureStore`, `extractRavenFeatures`, `makeFeatureCode`, `push`, `findFuzzySimilarity`.
 * - 变量说明: `filePath` 为待判断样本；`storeOverride` 允许测试或特定链路传入定制库；`info.features` 为提取出的 Raven 特征；`score`/`reasons` 为最终命中强度与命中原因集合。
 * - Variables: `filePath` is the sample under evaluation; `storeOverride` allows tests or special flows to inject a custom store; `info.features` are the extracted Raven features; `score` and `reasons` hold the final hit strength and reason set.
 * - 接入方式: 仅作为 JS 签名判定层内部入口使用；新增基于特征库的命中策略应集中扩展本函数，而不是在不同扫描函数里重复打分逻辑。
 * - Integration: Use it only as the internal JS-signature verdict entry; new store-based scoring strategies should be centralized here instead of being reimplemented across different scan functions.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: Raven命中 | Raven matching | JS signature verdict | fuzzy match | API weight | sequence hit | script suspicious | secondary detection
 */
  function scanRavenByStore(filePath, storeOverride) {
    const sp = typeof filePath === 'string' ? filePath : ''
    if (!sp) return {}
    if (verifyTrusted(sp)) {
      return { signature_verified: true, signature_hit: false, signature_score: 0, is_malware: false, confidence: 0, signature_reason: 'signature_trusted' }
    }
    const store = storeOverride || loadSignatureStore()
    const info = extractRavenFeatures(sp)
    if (!info || !info.features) return {}
    const code = makeFeatureCode(info.features)
    let score = 0
    const reasons = []
    if (store && Array.isArray(store.signatures) && code) {
      const hit = store.signatures.find(s => s && s.code === code)
      if (hit) {
        score = 1
        reasons.push('feature_match')
      }
    }
    const fuzzyScore = findFuzzySimilarity(info.features.fuzzy, store)
    if (fuzzyScore >= 0.6) {
      score = Math.max(score, fuzzyScore)
      reasons.push('fuzzy_match')
    }
    const apiScore = computeApiWeightScore(info.features.apis, store)
    if (apiScore > 0) {
      score = Math.max(score, apiScore)
      reasons.push('api_weight')
    }
    if (hasSequenceHit(info.features.api_seq, store)) {
      score = Math.max(score, 0.9)
      reasons.push('api_sequence')
    }
    if (Number.isFinite(info.features.script_suspicious) && info.features.script_suspicious >= 3) {
      score = Math.max(score, 0.7)
      reasons.push('script_suspicious')
    }
    const signature_hit = score >= 0.6
    return {
      signature_hit,
      signature_score: score,
      signature_reason: reasons.join('|'),
      is_malware: signature_hit,
      confidence: signature_hit ? score : 0
    }
  }

  /**
 * - 函数: `mergeSignatureResult`
 * - Function: `mergeSignatureResult`
 * - 作用: 把 native 签名引擎结果与 JS Raven 特征库结果折叠成单一签名 verdict，并按命中强度选择更可信的 `signature_score` 与 `signature_reason`。
 * - Purpose: Folds the native signature-engine result and the JS Raven store result into one signature verdict, selecting the more trustworthy `signature_score` and `signature_reason` based on hit strength.
 * - 调用方: 扫描链在拿到 native 与 JS 双路签名结果后调用，用于给上层返回统一签名判断。
 * - Callers: Called by scan flows after both native and JS signature verdicts are available so upper layers receive one unified signature result.
 * - 被调方: `Object.assign`、`Number.isFinite`、`Math.max`。
 * - Callees: `Object.assign`, `Number.isFinite`, `Math.max`.
 * - 变量说明: `nativeRes` 为 native 签名结果；`jsRes` 为 JS 特征库结果；`n/j` 为归一化后的对象视图；`out` 为最终统一签名 verdict。
 * - Variables: `nativeRes` is the native signature verdict; `jsRes` is the JS-store verdict; `n/j` are their normalized object views; `out` is the final unified signature verdict.
 * - 接入方式: 仅作为双路签名结果折叠器使用；新增签名来源时应先把优先级规则扩展到这里。
 * - Integration: Use it only as the reducer for dual-path signature results; if another signature source is added later, its precedence rules should be extended here first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 签名 verdict 合并 | signature verdict merge | native plus JS | score arbitration | reason selection | confidence merge | Raven fallback | unified signature result
 */
  function mergeSignatureResult(nativeRes, jsRes) {
    const n = nativeRes && typeof nativeRes === 'object' ? nativeRes : {}
    const j = jsRes && typeof jsRes === 'object' ? jsRes : {}
    const out = Object.assign({}, n)
    if (j.signature_verified !== undefined) out.signature_verified = j.signature_verified
    if (j.signature_hit !== undefined) {
      if (n.signature_hit === true) {
        const nScore = Number.isFinite(n.signature_score) ? n.signature_score : 0
        const jScore = Number.isFinite(j.signature_score) ? j.signature_score : 0
        if (jScore > nScore) {
          out.signature_hit = j.signature_hit
          out.signature_score = j.signature_score
          if (j.signature_reason) out.signature_reason = j.signature_reason
        }
      } else {
        out.signature_hit = j.signature_hit
        out.signature_score = j.signature_score
        if (j.signature_reason) out.signature_reason = j.signature_reason
      }
    }
    if (j.is_malware === true) out.is_malware = true
    if (j.confidence !== undefined) {
      const nConf = Number.isFinite(out.confidence) ? out.confidence : 0
      const jConf = Number.isFinite(j.confidence) ? j.confidence : 0
      out.confidence = Math.max(nConf, jConf)
    }
    return out
  }

  /**
 * - 函数: `ensureKvdEnv`
 * - Function: `ensureKvdEnv`
 * - 作用: 为主扫描引擎准备模型相关环境变量，把解析出的模型文件与 family 分类器路径写入进程环境，确保 DLL 在初始化后能按固定键读取到模型位置。
 * - Purpose: Prepares model-related environment variables for the primary scan engine by writing resolved model and family-classifier paths into the process environment so the DLL can read model locations from stable keys after initialization.
 * - 调用方: `ensureKvdLibraryLoaded` 在 DLL 成功绑定后调用，用于补齐 native 侧依赖的模型路径环境。
 * - Callers: Called by `ensureKvdLibraryLoaded` after DLL binding succeeds, filling the model-path environment expected by the native side.
 * - 被调方: `resolveModelPath`、`resolveFamilyJsonPath`、`setEnvPath`、`fileExists`。
 * - Callees: `resolveModelPath`, `resolveFamilyJsonPath`, `setEnvPath`, `fileExists`.
 * - 变量说明: 无显式入参；`main`、`normal`、`packed` 分别是三套 LightGBM 模型路径；`family` 为家族分类器 JSON 路径。
 * - Variables: No explicit parameters; `main`, `normal`, and `packed` are the three LightGBM model paths, and `family` is the family-classifier JSON path.
 * - 接入方式: 仅作为主 KVD 引擎装载链的环境补齐步骤使用；若未来新增依赖相同环境变量的 native 能力，应优先复用本函数。
 * - Integration: Use it only as the environment-setup step of the primary KVD load chain; future native features depending on the same env vars should reuse this helper.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 模型环境变量 | model environment vars | KVD env bootstrap | family classifier path | LightGBM paths | native model discovery | process.env setup | DLL prerequisites
 */
  function ensureKvdEnv() {
    const main = resolveModelPath('lightgbm_model.txt')
    const normal = resolveModelPath('lightgbm_model_normal.txt')
    const packed = resolveModelPath('lightgbm_model_packed.txt')
    const family = resolveFamilyJsonPath()
    /**
 * - 函数: `setEnvPath`
 * - Function: `setEnvPath`
 * - 作用: 以“已有有效值优先、候选路径可用时覆盖、失效旧值清空”的策略维护单个 native 环境变量，避免 DLL 继续读取到已不存在的模型路径。
 * - Purpose: Maintains one native environment variable with the policy of “keep existing valid value, overwrite with a usable candidate, clear stale invalid value” so the DLL does not keep reading removed model paths.
 * - 调用方: `ensureKvdEnv`。
 * - Callers: `ensureKvdEnv`.
 * - 被调方: `fileExists`。
 * - Callees: `fileExists`.
 * - 变量说明: `key` 为目标环境变量名；`candidate` 为最新解析出的候选路径；`cur` 为进程中当前已存在的值。
 * - Variables: `key` is the target environment-variable name; `candidate` is the newly resolved candidate path; `cur` is the value currently present in the process environment.
 * - 接入方式: 仅作为 `ensureKvdEnv` 的内部辅助函数使用；新的环境变量修正规则应优先在这里集中维护。
 * - Integration: Use it only as an internal helper of `ensureKvdEnv`; new env-fixup rules should be centralized here.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 环境变量修正 | env var fixup | stale path cleanup | candidate override | fileExists guard | native model path | safe env mutation | setup helper
 */
    const setEnvPath = (key, candidate) => {
      const cur = process.env[key]
      if (cur && fileExists(cur)) return
      if (candidate && fileExists(candidate)) {
        process.env[key] = candidate
        return
      }
      if (cur && !fileExists(cur)) process.env[key] = ''
    }
    setEnvPath('SCANNER_LIGHTGBM_MODEL_PATH', main)
    setEnvPath('SCANNER_LIGHTGBM_MODEL_NORMAL_PATH', normal)
    setEnvPath('SCANNER_LIGHTGBM_MODEL_PACKED_PATH', packed)
    setEnvPath('SCANNER_FAMILY_CLASSIFIER_PATH', family)
  }

  /**
 * - 函数: `buildKvdConfigValues`
 * - Function: `buildKvdConfigValues`
 * - 作用: 从运行时扫描配置与环境变量组装主 KVD 引擎需要的完整配置对象，包括模型路径、允许扫描根目录、最大文件大小和预测阈值。
 * - Purpose: Assembles the full config object required by the primary KVD engine from runtime scanner settings and environment variables, including model paths, allowed scan root, max file size, and prediction threshold.
 * - 调用方: `buildKvdConfigPtr`、`ensureKvdHandle`、`kvdHealth` 在创建句柄或做健康探针前调用。
 * - Callers: Called by `buildKvdConfigPtr`, `ensureKvdHandle`, and `kvdHealth` before handle creation or health probing.
 * - 被调方: `Number.isFinite`、`Math.max`、`Math.floor`、`Math.min`。
 * - Callees: `Number.isFinite`, `Math.max`, `Math.floor`, `Math.min`.
 * - 变量说明: 无显式入参；`scanner` 为当前扫描配置；`maxMB` 为归一化后的文件大小上限；`threshold` 为 native 判定阈值；`allowedRoot` 为扫描白名单根目录。
 * - Variables: No explicit parameters; `scanner` is the current scanner config; `maxMB` is the normalized max file size; `threshold` is the native decision threshold; `allowedRoot` is the scan allowlist root.
 * - 接入方式: 应作为主 KVD 配置对象的唯一构造入口；新增主引擎配置字段时应优先在这里汇总，而不是在多个句柄入口分别拼装。
 * - Integration: It should remain the single construction entry for primary KVD config objects; new engine config fields should be aggregated here instead of being assembled in multiple handle paths.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: KVD配置构造 | KVD config build | model paths | threshold normalization | max file size | allowed scan root | runtime scanner config | native settings object
 */
  function buildKvdConfigValues() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const maxMB = Number.isFinite(scanner.maxFileSizeMB) ? Math.max(1, Math.floor(scanner.maxFileSizeMB)) : 0
    const threshold = Number.isFinite(scanner.predictionThreshold) ? scanner.predictionThreshold : 0.98
    const allowedRoot = typeof scanner.allowedScanRoot === 'string' ? scanner.allowedScanRoot : ''
    return {
      model_path: process.env.SCANNER_LIGHTGBM_MODEL_PATH || '',
      model_normal_path: process.env.SCANNER_LIGHTGBM_MODEL_NORMAL_PATH || '',
      model_packed_path: process.env.SCANNER_LIGHTGBM_MODEL_PACKED_PATH || '',
      family_classifier_json_path: process.env.SCANNER_FAMILY_CLASSIFIER_PATH || '',
      allowed_scan_root: allowedRoot,
      max_file_size: maxMB > 0 ? Math.min(0xFFFFFFFF, maxMB * 1024 * 1024) : 0,
      prediction_threshold: (threshold > 0 && threshold <= 1) ? threshold : 0.98
    }
  }

  /**
 * - 函数: `validateKvdConfigValues`
 * - Function: `validateKvdConfigValues`
 * - 作用: 校验主 KVD 引擎配置中的关键模型文件是否真实存在，并把缺失项整理成明确的字段列表，供句柄创建与健康检查统一判断失败原因。
 * - Purpose: Validates that the critical model files referenced by the primary KVD config actually exist and returns a clear list of missing fields so handle creation and health checks can share the same failure reason.
 * - 调用方: `ensureKvdHandle` 在创建句柄前调用；`kvdHealth` 在探测引擎可用性时也会复用。
 * - Callers: Called by `ensureKvdHandle` before handle creation and reused by `kvdHealth` when probing engine readiness.
 * - 被调方: `fileExists`、`push`。
 * - Callees: `fileExists`, `push`.
 * - 变量说明: `cfgObj` 为待验证的主引擎配置对象；`missing` 为最终收集出的缺失配置字段名列表。
 * - Variables: `cfgObj` is the primary-engine config object being validated; `missing` is the collected list of missing config field names.
 * - 接入方式: 应作为主 KVD 配置有效性的统一校验入口；上层不要自己零散检查文件存在性，以免错误语义不一致。
 * - Integration: It should be the single validation entry for primary KVD config validity; upper layers should not perform scattered file-existence checks on their own.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: KVD配置校验 | KVD config validation | missing model files | readiness check | health failure reason | fileExists validation | model prerequisites | shared validator
 */
  function validateKvdConfigValues(cfgObj) {
    const missing = []
    if (!cfgObj || typeof cfgObj !== 'object') return { ok: false, missing: ['config'] }
    if (!cfgObj.model_path || !fileExists(cfgObj.model_path)) missing.push('model_path')
    if (!cfgObj.model_normal_path || !fileExists(cfgObj.model_normal_path)) missing.push('model_normal_path')
    if (!cfgObj.model_packed_path || !fileExists(cfgObj.model_packed_path)) missing.push('model_packed_path')
    if (!cfgObj.family_classifier_json_path || !fileExists(cfgObj.family_classifier_json_path)) missing.push('family_classifier_json_path')
    return { ok: missing.length === 0, missing }
  }

  /**
 * - 函数: `buildSignatureConfigValues`
 * - Function: `buildSignatureConfigValues`
 * - 作用: 组装 Raven/native 签名引擎所需的配置对象，把签名 native 模型路径、扫描根目录和大小上限统一映射到与主 KVD 引擎兼容的配置结构。
 * - Purpose: Assembles the config object required by the Raven/native signature engine by mapping the signature native-model path, scan root, and size cap into the config shape compatible with the primary KVD engine.
 * - 调用方: `ensureSignatureHandle` 在创建签名句柄前调用。
 * - Callers: Called by `ensureSignatureHandle` before the signature handle is created.
 * - 被调方: `resolveSignatureNativeModelPath`、`Number.isFinite`、`Math.max`、`Math.floor`、`Math.min`。
 * - Callees: `resolveSignatureNativeModelPath`, `Number.isFinite`, `Math.max`, `Math.floor`, `Math.min`.
 * - 变量说明: 无显式入参；`scanner` 为扫描配置；`storePath` 为签名 native 模型文件路径；`maxMB` 为归一化后的文件大小上限；`allowedRoot` 为允许扫描根目录。
 * - Variables: No explicit parameters; `scanner` is the scan config; `storePath` is the signature native-model file path; `maxMB` is the normalized max file size; `allowedRoot` is the allowed scan root.
 * - 接入方式: 应作为签名引擎配置的统一构造入口；若签名引擎未来扩展更多 native 配置字段，应优先在此集中维护。
 * - Integration: It should be the single construction entry for signature-engine config; if more native signature settings are added later, they should be centralized here.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 签名配置构造 | signature config build | native signature model | allowed scan root | file size cap | Raven settings | compatible config shape | handle bootstrap
 */
  function buildSignatureConfigValues() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const maxMB = Number.isFinite(scanner.maxFileSizeMB) ? Math.max(1, Math.floor(scanner.maxFileSizeMB)) : 0
    const allowedRoot = typeof scanner.allowedScanRoot === 'string' ? scanner.allowedScanRoot : ''
    const storePath = resolveSignatureNativeModelPath(scanner)
    return {
      model_path: storePath,
      model_normal_path: '',
      model_packed_path: '',
      family_classifier_json_path: '',
      allowed_scan_root: allowedRoot,
      max_file_size: maxMB > 0 ? Math.min(0xFFFFFFFF, maxMB * 1024 * 1024) : 0,
      prediction_threshold: 0
    }
  }

  /**
 * - 函数: `validateSignatureConfigValues`
 * - Function: `validateSignatureConfigValues`
 * - 作用: 为签名引擎提供与主 KVD 校验链一致的验证出口；当前实现默认放行，表示签名 native 模型路径由引擎自身在创建或扫描阶段继续兜底校验。
 * - Purpose: Provides a validation exit aligned with the primary KVD validation chain for the signature engine; the current implementation defaults to pass-through, meaning final native-model checks are deferred to handle creation or scan execution.
 * - 调用方: `ensureSignatureHandle` 在创建签名句柄前调用。
 * - Callers: Called by `ensureSignatureHandle` before signature handle creation.
 * - 被调方: 当前函数主要依赖字面返回值完成签名配置占位校验。
 * - Callees: Primarily relies on a literal return value to provide placeholder validation for signature config.
 * - 变量说明: 无显式入参；返回值中的 `ok/missing` 与主 KVD 校验链保持相同协议，便于上层统一处理。
 * - Variables: No explicit parameters; the returned `ok/missing` pair follows the same protocol as the primary KVD validator so upper layers can handle both uniformly.
 * - 接入方式: 应保留为签名引擎校验链的统一出口；如果后续需要对签名 native 模型文件做显式存在性校验，应优先扩展本函数。
 * - Integration: It should remain the single exit of the signature-engine validation chain; if explicit file-existence checks are later needed for the signature native model, they should be added here first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 签名配置校验出口 | signature validation exit | placeholder validator | shared ok missing protocol | future extensibility | handle precheck | Raven config gate | consistent diagnostics
 */
  function validateSignatureConfigValues() {
    return { ok: true, missing: [] }
  }

  /**
 * - 函数: `buildKvdConfigPtr`
 * - Function: `buildKvdConfigPtr`
 * - 作用: 将 JS 侧主引擎配置对象编码成 `koffi` 可传递给 DLL 的原生结构体指针，是 `kvd_create` 与 `kvd_validate_models` 之前的最后一步桥接。
 * - Purpose: Encodes the JS-side primary-engine config object into a native struct pointer that `koffi` can pass into the DLL, acting as the last bridge before `kvd_create` and `kvd_validate_models`.
 * - 调用方: `ensureKvdHandle` 与 `kvdHealth` 在需要把配置交给 native 侧时调用。
 * - Callers: Called by `ensureKvdHandle` and `kvdHealth` whenever config must be handed to the native side.
 * - 被调方: `buildKvdConfigValues`。
 * - Callees: `buildKvdConfigValues`.
 * - 变量说明: `cfgObj` 为可选的待编码配置；`obj` 为最终参与编码的配置对象；`ptr` 为返回给上游保存或复用的原生内存指针。
 * - Variables: `cfgObj` is the optional config to encode; `obj` is the final config object actually encoded; `ptr` is the native memory pointer returned for reuse upstream.
 * - 接入方式: 应作为主 KVD 配置到 native 指针的唯一编码入口；外层不要自行分配 `koffi` 结构体，以免与统一配置协议脱节。
 * - Integration: It should be the single encoding entry from primary KVD config into a native pointer; outer layers should not allocate their own `koffi` structs and drift from the shared config protocol.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 原生配置指针 | native config pointer | koffi encoding | DLL bridge | kvd_create input | validate_models input | struct allocation | config handoff
 */
  function buildKvdConfigPtr(cfgObj) {
    const obj = cfgObj || buildKvdConfigValues()
    const ptr = koffi.alloc(kvd.configType, 1)
    koffi.encode(ptr, kvd.configType, obj)
    return ptr
  }

  /**
   * - 函数: `ensureKvdLibraryLoaded`
   * - Function: `ensureKvdLibraryLoaded`
   * - 作用: 按需加载主扫描引擎 KVD DLL，完成 `koffi` 绑定、结构体定义和关键导出函数绑定，为后续句柄创建、健康检查和原生扫描提供底层动态库能力。
   * - Purpose: Lazily loads the primary KVD scanning DLL, sets up `koffi` bindings, defines native structs, and binds required exports so handle creation, health checks, and native scans can run on top of the loaded library.
   * - 调用方: `ensureKvdHandle` 在创建引擎句柄前调用，`kvdHealth` 在做底层可用性探测时调用。
   * - Callers: Called by `ensureKvdHandle` before creating the engine handle and by `kvdHealth` when probing low-level availability.
   * - 被调方: `trace`、`resolveKvdDllPath`、内部 `bind`、`normalizeErrorPayload`、`ensureKvdEnv`、`koffi.load`、`koffi.struct`、`lib.func`。
   * - Callees: `trace`, `resolveKvdDllPath`, the local `bind` helper, `normalizeErrorPayload`, `ensureKvdEnv`, `koffi.load`, `koffi.struct`, and `lib.func`.
   * - 变量说明: 无显式入参；闭包对象 `kvd` 保存 `lib/configType/create/destroy/scanPath/...` 等原生句柄与函数指针；`dll` 为解析出的 DLL 路径；`missing` 收集绑定失败的导出函数名。
   * - Variables: No explicit parameters; the closure object `kvd` stores native handles and function pointers such as `lib/configType/create/destroy/scanPath/...`, `dll` is the resolved DLL path, and `missing` collects failed export bindings.
   * - 接入方式: 仅供扫描客户端内部的 native 初始化链路复用；如果后续新增依赖 KVD DLL 的能力，应优先以“先 ensure、后用句柄”的模式接入，而不是直接重复绑定逻辑。
   * - Integration: Use it only from the scanner client's internal native-initialization chain; if new features start depending on the KVD DLL, integrate them with the “ensure first, then use the handle” pattern instead of duplicating binding logic.
   * - 错误处理: 缺失 `koffi`、找不到 DLL、导出绑定失败或动态加载异常时，都会写入 `kvd.loadError` 并返回 `false`；函数自身尽量不抛异常，让上层基于布尔结果决定是否回退或报错。
   * - Error Handling: Missing `koffi`, an unresolved DLL path, export-binding failures, or dynamic-load exceptions all set `kvd.loadError` and return `false`; the function avoids throwing so upper layers can decide whether to fall back or fail.
   * - 关键词: 原生DLL装载 | native DLL loading | KVD绑定 | KVD binding | koffi桥接 | koffi bridge | 导出函数绑定 | export binding | 引擎预热 | engine bootstrap
   */
  function ensureKvdLibraryLoaded() {
    if (kvd.lib) return true
    if (!koffi) {
      try { koffi = require('koffi') } catch { koffi = null }
    }
    if (!koffi) {
      kvd.loadError = 'KVD_KOFFI_MISSING'
      trace('kvd_koffi_missing')
      return false
    }
    const dll = resolveKvdDllPath()
    if (!dll) {
      kvd.loadError = 'KVD_DLL_NOT_FOUND'
      trace('kvd_dll_not_found')
      return false
    }
    try {
      kvd.lib = koffi.load(dll)
      kvd.configType = koffi.struct('kvd_config', {
        model_path: 'string',
        model_normal_path: 'string',
        model_packed_path: 'string',
        family_classifier_json_path: 'string',
        allowed_scan_root: 'string',
        max_file_size: 'uint32_t',
        prediction_threshold: 'float'
      })
      /**
 * - 函数: `bind`
 * - Function: `bind`
 * - 作用: 尝试从已加载的 native DLL 中绑定单个导出函数，并在导出缺失或签名不匹配时返回 `null`，让上层按能力缺失继续汇总诊断。
 * - Purpose: Attempts to bind one exported function from the loaded native DLL and returns `null` when the export is missing or its signature cannot be matched, allowing upper layers to continue aggregating missing-capability diagnostics.
 * - 调用方: `ensureKvdLibraryLoaded`、`ensureSignatureLibraryLoaded`。
 * - Callers: `ensureKvdLibraryLoaded`, `ensureSignatureLibraryLoaded`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `name` 为目标导出函数名；`ret` 为返回值类型定义；`args` 为参数类型列表。
 * - Variables: `name` is the target export name; `ret` is the declared return type; `args` is the argument-type list.
 * - 接入方式: 仅作为 DLL 装载链中的局部 helper 使用；新增原生导出绑定应先通过本函数完成，保持“失败返回 null”的统一协议。
 * - Integration: Use it only as a local helper inside DLL load chains; new native export bindings should go through it first so the shared “return null on failure” protocol remains consistent.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 导出绑定 helper | export binding helper | DLL symbol lookup | null on bind failure | function signature match | koffi func bind | capability probing | native bootstrap
 */
      const bind = (name, ret, args) => {
        try { return kvd.lib.func('__cdecl', name, ret, args) } catch { return null }
      }
      kvd.create = bind('kvd_create', koffi.pointer('void *'), [koffi.pointer(kvd.configType)])
      kvd.destroy = bind('kvd_destroy', 'void', [koffi.pointer('void *')])
      kvd.scanPath = bind('kvd_scan_path', 'int', [koffi.pointer('void *'), 'string', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvd.scanPaths = bind('kvd_scan_paths', 'int', [koffi.pointer('void *'), 'void *', 'size_t', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvd.scanBytes = bind('kvd_scan_bytes', 'int', [koffi.pointer('void *'), koffi.pointer('uint8_t'), 'size_t', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvd.trainFromPath = bind('kvd_train_from_path', 'int', [koffi.pointer('void *'), 'string', 'int', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      if (!kvd.trainFromPath) {
        kvd.trainFromPath = bind('kvd_train_path', 'int', [koffi.pointer('void *'), 'string', 'int', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      }
      kvd.free = bind('kvd_free', 'void', ['void *'])
      kvd.validateModels = bind('kvd_validate_models', 'int', [koffi.pointer(kvd.configType), koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      if (!kvd.create || !kvd.destroy || !kvd.scanPath || !kvd.free || !kvd.validateModels) {
        kvd.lib = null
        kvd.loadError = 'KVD_BIND_FAILED'
        const missing = []
        if (!kvd.create) missing.push('kvd_create')
        if (!kvd.destroy) missing.push('kvd_destroy')
        if (!kvd.scanPath) missing.push('kvd_scan_path')
        if (!kvd.free) missing.push('kvd_free')
        if (!kvd.validateModels) missing.push('kvd_validate_models')
        trace('kvd_bind_failed', { dll, hasScanPaths: !!kvd.scanPaths, hasScanBytes: !!kvd.scanBytes, missing })
        return false
      }
    } catch (e) {
      kvd.lib = null
      kvd.loadError = 'KVD_BIND_FAILED'
      trace('kvd_load_failed', { dll, ...normalizeErrorPayload(e) })
      return false
    }
    ensureKvdEnv()
    kvd.loadError = ''
    return true
  }

  /**
   * - 函数: `ensureSignatureLibraryLoaded`
   * - Function: `ensureSignatureLibraryLoaded`
   * - 作用: 按需加载签名/规则引擎 DLL，建立 Raven 签名扫描、批量训练和刷盘能力所需的原生函数绑定，是签名引擎句柄创建前的底层准备步骤。
   * - Purpose: Lazily loads the signature/rule-engine DLL and binds the native functions required for Raven signature scanning, batch training, and flushing, serving as the low-level prerequisite for signature-engine handle creation.
   * - 调用方: `ensureSignatureHandle` 在创建签名引擎句柄前调用，`kvdHealth` 在检测签名引擎可用性时调用。
   * - Callers: Called by `ensureSignatureHandle` before creating the signature-engine handle and by `kvdHealth` when checking signature-engine availability.
   * - 被调方: `traceSig`、`resolveSignatureDllPath`、内部 `bind`、`normalizeErrorPayload`、`koffi.load`、`koffi.struct`、`koffi.pointer`、`lib.func`。
   * - Callees: `traceSig`, `resolveSignatureDllPath`, the local `bind` helper, `normalizeErrorPayload`, `koffi.load`, `koffi.struct`, `koffi.pointer`, and `lib.func`.
   * - 变量说明: 无显式入参；闭包对象 `kvdSig` 保存签名引擎的 `lib/configType/create/scanPath/trainPaths/flush/...` 等能力；`dll` 为签名 DLL 路径；`missing` 记录必要导出缺失列表。
   * - Variables: No explicit parameters; the closure object `kvdSig` stores signature-engine capabilities such as `lib/configType/create/scanPath/trainPaths/flush/...`, `dll` is the signature DLL path, and `missing` tracks missing required exports.
   * - 接入方式: 仅在扫描客户端内部由签名引擎相关能力调用；若新增基于签名库的诊断或维护命令，应复用本函数统一加载 DLL，而不是重新定义一套绑定。
   * - Integration: Use it only from signature-engine features inside the scanner client; if new diagnostics or maintenance commands depend on the signature library, reuse this function to load the DLL instead of redefining another binding layer.
   * - 错误处理: 与主 KVD 引擎一致，遇到缺少 `koffi`、DLL 不存在、导出缺失或加载异常时设置 `kvdSig.loadError` 并返回 `false`，将失败语义统一交给上游句柄创建与扫描入口处理。
   * - Error Handling: Like the primary KVD loader, it sets `kvdSig.loadError` and returns `false` when `koffi` is missing, the DLL cannot be found, exports are absent, or loading fails, leaving upper-layer handle creation and scan entry points to interpret the failure.
   * - 关键词: 签名引擎装载 | signature engine loading | Raven绑定 | Raven binding | 批量训练接口 | batch training API | 刷盘能力 | flush capability | 原生桥接 | native bridge
   */
  function ensureSignatureLibraryLoaded() {
    if (kvdSig.lib) return true
    if (!koffi) {
      try { koffi = require('koffi') } catch { koffi = null }
    }
    if (!koffi) {
      kvdSig.loadError = 'KVD_KOFFI_MISSING'
      traceSig('raven_koffi_missing')
      return false
    }
    const dll = resolveSignatureDllPath()
    if (!dll) {
      kvdSig.loadError = 'KVD_DLL_NOT_FOUND'
      traceSig('raven_dll_not_found')
      return false
    }
    try {
      kvdSig.lib = koffi.load(dll)
      kvdSig.configType = koffi.struct('kvd_config_sig', {
        model_path: 'string',
        model_normal_path: 'string',
        model_packed_path: 'string',
        family_classifier_json_path: 'string',
        allowed_scan_root: 'string',
        max_file_size: 'uint32_t',
        prediction_threshold: 'float'
      })
      /**
 * - 函数: `bind`
 * - Function: `bind`
 * - 作用: 尝试绑定签名引擎 DLL 的单个导出函数，并把导出缺失视为能力不可用而非立即抛错，方便后续统一判断哪些接口可以启用。
 * - Purpose: Attempts to bind one export from the signature-engine DLL and treats missing exports as unavailable capability instead of throwing immediately, making it easier to decide later which interfaces can be enabled.
 * - 调用方: `ensureKvdLibraryLoaded`、`ensureSignatureLibraryLoaded`。
 * - Callers: `ensureKvdLibraryLoaded`, `ensureSignatureLibraryLoaded`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `name` 为目标导出名；`ret` 为返回值类型；`args` 为参数签名。
 * - Variables: `name` is the target export name; `ret` is the return type; `args` is the argument signature.
 * - 接入方式: 仅作为签名 DLL 装载链中的局部 helper 使用；新增签名导出能力应沿用本函数的“失败返回 null”约定。
 * - Integration: Use it only as a local helper in the signature-DLL load chain; new signature exports should keep the same “return null on failure” convention through this helper.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 签名导出绑定 | signature export binding | capability optionality | null on missing export | Raven DLL symbol | koffi binding helper | feature gating | native load chain
 */
      const bind = (name, ret, args) => {
        try { return kvdSig.lib.func('__cdecl', name, ret, args) } catch { return null }
      }
      kvdSig.create = bind('kvd_create', koffi.pointer('void *'), [koffi.pointer(kvdSig.configType)])
      kvdSig.destroy = bind('kvd_destroy', 'void', [koffi.pointer('void *')])
      kvdSig.scanPath = bind('kvd_scan_path', 'int', [koffi.pointer('void *'), 'string', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvdSig.scanPaths = bind('kvd_scan_paths', 'int', [koffi.pointer('void *'), 'void *', 'size_t', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvdSig.scanBytes = bind('kvd_scan_bytes', 'int', [koffi.pointer('void *'), koffi.pointer('uint8_t'), 'size_t', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvdSig.trainFromPath = bind('kvd_train_from_path', 'int', [koffi.pointer('void *'), 'string', 'int', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvdSig.trainPaths = bind('kvd_train_paths', 'int', [koffi.pointer('void *'), 'void *', 'size_t', 'int', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      kvdSig.flush = bind('kvd_signature_flush', 'void', [koffi.pointer('void *')])
      if (!kvdSig.trainFromPath) {
        kvdSig.trainFromPath = bind('kvd_train_path', 'int', [koffi.pointer('void *'), 'string', 'int', koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      }
      kvdSig.free = bind('kvd_free', 'void', ['void *'])
      kvdSig.validateModels = bind('kvd_validate_models', 'int', [koffi.pointer(kvdSig.configType), koffi.out(koffi.pointer('void *', 2)), koffi.out('size_t *')])
      if (!kvdSig.create || !kvdSig.destroy || !kvdSig.scanPath || !kvdSig.free || !kvdSig.validateModels) {
        kvdSig.lib = null
        kvdSig.loadError = 'KVD_BIND_FAILED'
        const missing = []
        if (!kvdSig.create) missing.push('kvd_create')
        if (!kvdSig.destroy) missing.push('kvd_destroy')
        if (!kvdSig.scanPath) missing.push('kvd_scan_path')
        if (!kvdSig.free) missing.push('kvd_free')
        if (!kvdSig.validateModels) missing.push('kvd_validate_models')
        traceSig('raven_bind_failed', { dll, hasScanPaths: !!kvdSig.scanPaths, hasScanBytes: !!kvdSig.scanBytes, missing })
        return false
      }
    } catch (e) {
      kvdSig.lib = null
      kvdSig.loadError = 'KVD_BIND_FAILED'
      traceSig('raven_load_failed', { dll, ...normalizeErrorPayload(e) })
      return false
    }
    kvdSig.loadError = ''
    return true
  }

  /**
   * - 函数: `ensureKvdHandle`
   * - Function: `ensureKvdHandle`
   * - 作用: 确保主扫描引擎句柄已创建并可复用，负责衔接 DLL 已装载状态、模型配置校验、原生配置指针构建和 `kvd_create` 实际建链。
   * - Purpose: Ensures the primary scan-engine handle is created and reusable by bridging loaded-DLL state, model-config validation, native config-pointer construction, and the actual `kvd_create` call.
   * - 调用方: `canUseNative`、`kvdScanFile`、`kvdScanPaths`、`kvdTrainFromPath` 等需要主引擎句柄的原生调用入口。
   * - Callers: Used by native entry points that require the primary engine handle, including `canUseNative`, `kvdScanFile`, `kvdScanPaths`, and `kvdTrainFromPath`.
   * - 被调方: `ensureKvdLibraryLoaded`、`buildKvdConfigValues`、`validateKvdConfigValues`、`trace`、`buildKvdConfigPtr`、`normalizeErrorPayload`、`kvd.create`。
   * - Callees: `ensureKvdLibraryLoaded`, `buildKvdConfigValues`, `validateKvdConfigValues`, `trace`, `buildKvdConfigPtr`, `normalizeErrorPayload`, and `kvd.create`.
   * - 变量说明: 无显式入参；闭包对象 `kvd.handle` 保存最终引擎句柄；`cfgObj` 为构造好的模型配置；`valid` 表示配置校验结果；`createSeq` 用于追踪单次创建日志序号。
   * - Variables: No explicit parameters; the closure field `kvd.handle` stores the final engine handle, `cfgObj` is the assembled model config, `valid` is the config-validation result, and `createSeq` tags the creation attempt in trace logs.
   * - 接入方式: 所有需要访问主 KVD 引擎句柄的代码都应先通过本函数守卫；如果以后增加新的 native 调用入口，应避免直接读取 `kvd.handle`，而是复用本函数统一完成初始化。
   * - Integration: Any code that needs the primary KVD handle should guard through this function first; if new native entry points are added later, avoid reading `kvd.handle` directly and reuse this initializer instead.
   * - 错误处理: DLL 不可用、模型文件缺失、指针构建异常或 `kvd_create` 失败时返回 `false`，并通过 `kvd.loadError` 与 `trace` 记录失败上下文，不把底层异常直接抛给扫描调用方。
   * - Error Handling: When the DLL is unavailable, model files are missing, pointer construction fails, or `kvd_create` fails, it returns `false` and records the failure context through `kvd.loadError` and `trace` instead of surfacing raw native exceptions to scan callers.
   * - 关键词: 引擎句柄创建 | engine handle creation | 模型校验 | model validation | 原生配置指针 | native config pointer | KVD建链 | KVD bootstrap | 句柄复用 | handle reuse
   */
  function ensureKvdHandle() {
    if (kvd.handle) return true
    if (!ensureKvdLibraryLoaded()) return false
    try {
      const cfgObj = buildKvdConfigValues()
      const valid = validateKvdConfigValues(cfgObj)
      if (!valid.ok) {
        kvd.loadError = 'KVD_MODEL_MISSING'
        trace('kvd_config_invalid', { missing: valid.missing })
        return false
      }
      if (!kvd.cfgPtr) kvd.cfgPtr = buildKvdConfigPtr(cfgObj)
      const createSeq = ++traceState.createSeq
      trace('kvd_create_begin', { id: createSeq })
      kvd.handle = kvd.create(kvd.cfgPtr)
      trace('kvd_create_ok', { id: createSeq })
    } catch (e) {
      kvd.handle = null
      trace('kvd_create_failed', { ...normalizeErrorPayload(e) })
    }
    if (!kvd.handle) kvd.loadError = 'KVD_CREATE_FAILED'
    return !!kvd.handle
  }

  /**
   * - 函数: `ensureSignatureHandle`
   * - Function: `ensureSignatureHandle`
   * - 作用: 确保签名/规则引擎句柄已就绪，负责验证签名模型配置、分配并编码 `koffi` 配置内存，然后执行 `kvd_create` 创建 `kvdSig.handle`。
   * - Purpose: Ensures the signature/rule-engine handle is ready by validating signature-model config, allocating and encoding the `koffi` config memory, and then calling `kvd_create` to build `kvdSig.handle`.
   * - 调用方: `canUseNative`、`canUseSignatureEngine`、`kvdTrainFromPathSig`、`kvdTrainPathsSig` 等依赖签名引擎句柄的调用路径。
   * - Callers: Used by call paths that depend on the signature-engine handle, including `canUseNative`, `canUseSignatureEngine`, `kvdTrainFromPathSig`, and `kvdTrainPathsSig`.
   * - 被调方: `ensureSignatureLibraryLoaded`、`buildSignatureConfigValues`、`validateSignatureConfigValues`、`traceSig`、`normalizeErrorPayload`、`koffi.alloc`、`koffi.encode`、`kvdSig.create`。
   * - Callees: `ensureSignatureLibraryLoaded`, `buildSignatureConfigValues`, `validateSignatureConfigValues`, `traceSig`, `normalizeErrorPayload`, `koffi.alloc`, `koffi.encode`, and `kvdSig.create`.
   * - 变量说明: 无显式入参；`kvdSig.handle` 为最终签名引擎句柄；`cfgObj` 为编码前配置对象；`valid` 为配置校验结果；`kvdSig.cfgPtr` 为原生配置内存指针；`createSeq` 为日志中的建链序号。
   * - Variables: No explicit parameters; `kvdSig.handle` is the final signature-engine handle, `cfgObj` is the pre-encoding config object, `valid` is the validation result, `kvdSig.cfgPtr` is the native config pointer, and `createSeq` tags the creation attempt in logs.
   * - 接入方式: 任何想直接使用签名引擎扫描或训练能力的入口都应先调用本函数；不要在外层自行分配 `cfgPtr` 或直接调用 `kvdSig.create`，否则容易绕过统一的错误状态维护。
   * - Integration: Any entry point that wants direct access to signature-engine scan or training capabilities should call this function first; do not allocate `cfgPtr` or call `kvdSig.create` manually outside, or you may bypass shared error-state management.
   * - 错误处理: 配置非法、原生编码失败或句柄创建失败时返回 `false`，并将失败细节写入 `traceSig` 与 `kvdSig.loadError`，让上层能力按需降级到仅主引擎或完全报错。
   * - Error Handling: Invalid config, native encoding failures, or handle-creation failures return `false` and emit details through `traceSig` and `kvdSig.loadError`, allowing upper layers to fall back to the primary engine only or fail completely.
   * - 关键词: 签名句柄创建 | signature handle creation | 配置编码 | config encoding | koffi内存 | koffi memory | Raven引擎 | Raven engine | 训练入口守卫 | training guard
   */
  function ensureSignatureHandle() {
    if (kvdSig.handle) return true
    if (!ensureSignatureLibraryLoaded()) return false
    try {
      const cfgObj = buildSignatureConfigValues()
      const valid = validateSignatureConfigValues(cfgObj)
      if (!valid.ok) {
        kvdSig.loadError = 'KVD_MODEL_MISSING'
        traceSig('raven_config_invalid', { missing: valid.missing })
        return false
      }
      if (!kvdSig.cfgPtr) {
        kvdSig.cfgPtr = koffi.alloc(kvdSig.configType, 1)
        koffi.encode(kvdSig.cfgPtr, kvdSig.configType, cfgObj)
      }
      const createSeq = ++traceState.createSeq
      traceSig('raven_create_begin', { id: createSeq })
      kvdSig.handle = kvdSig.create(kvdSig.cfgPtr)
      traceSig('raven_create_ok', { id: createSeq })
    } catch (e) {
      kvdSig.handle = null
      traceSig('raven_create_failed', { ...normalizeErrorPayload(e) })
    }
    if (!kvdSig.handle) kvdSig.loadError = 'KVD_CREATE_FAILED'
    return !!kvdSig.handle
  }

  /**
   * - 函数: `canUseNative`
   * - Function: `canUseNative`
   * - 作用: 统一判定当前扫描请求是否具备原生引擎执行条件，综合 `scanner` 配置开关、主 KVD 句柄状态以及可选签名引擎状态，为 `scanBatch` 选择 native 分支提供前置守卫。
   * - Purpose: Centralizes the decision of whether the current scan request can run on native engines by combining scanner config flags, primary KVD handle readiness, and optional signature-engine availability, serving as the guard for the native branch in `scanBatch`.
   * - 调用方: `scanBatch` 在进入批量扫描主流程之前调用。
   * - Callers: Called by `scanBatch` before entering the main batch-scan pipeline.
   * - 被调方: `getScannerCfg`、`ensureKvdHandle`、`ensureSignatureHandle`。
   * - Callees: `getScannerCfg`, `ensureKvdHandle`, `ensureSignatureHandle`.
   * - 变量说明: 无显式入参；`nativeEnabled` 表示是否允许主引擎扫描；`signatureEnabled` 表示是否要求启用签名引擎辅助；返回值用于决定批量扫描是否直接抛出 `KVD_LOAD_FAILED`。
   * - Variables: No explicit parameters; `nativeEnabled` indicates whether primary-engine scanning is allowed, `signatureEnabled` indicates whether signature assistance is expected, and the boolean return decides whether batch scans should throw `KVD_LOAD_FAILED`.
   * - 接入方式: 应作为原生扫描入口统一守卫函数使用；新增依赖 KVD/Raven 的扫描能力时，优先复用本函数表达“当前环境可不可用”，避免把配置判断散落到多个调用点。
   * - Integration: Use it as the shared guard for native-scan entry points; if new features begin depending on KVD/Raven, reuse this function to express environment readiness instead of scattering config checks across many call sites.
   * - 错误处理: 本函数本身不抛异常，主要通过布尔返回值表达可用性；底层句柄创建失败的细节由 `ensureKvdHandle`/`ensureSignatureHandle` 记录，调用方再统一决定报错或回退。
   * - Error Handling: The function itself does not throw and communicates readiness through a boolean result; detailed failures from handle creation are recorded by `ensureKvdHandle` and `ensureSignatureHandle`, and callers then decide whether to throw or downgrade.
   * - 关键词: 原生可用性 | native readiness | 扫描前置守卫 | scan guard | 配置开关 | config toggle | KVD句柄 | KVD handle | 签名辅助 | signature assist
   */
  function canUseNative() {
    const { nativeEnabled, signatureEnabled } = getScannerCfg()
    if (!nativeEnabled) return false
    if (signatureEnabled) return ensureKvdHandle() || ensureSignatureHandle()
    return ensureKvdHandle()
  }

  /**
 * - 函数: `canUseSignatureEngine`
 * - Function: `canUseSignatureEngine`
 * - 作用: 统一判定当前是否允许走 native 签名引擎链路，只有配置启用且 Raven/native 签名句柄可用时才放行后续签名扫描或训练。
 * - Purpose: Serves as the unified gate for the native signature-engine path, allowing downstream signature scanning or training only when configuration enables it and the Raven/native signature handle is available.
 * - 调用方: `kvdScanFileSig`、`kvdScanPathsSig` 等签名扫描入口会先调用本函数；未来的签名训练前置检查也应复用同一判定。
 * - Callers: Called by signature-scan entries such as `kvdScanFileSig` and `kvdScanPathsSig`, and future signature-training prechecks should reuse the same gate.
 * - 被调方: `getScannerCfg`、`ensureSignatureHandle`。
 * - Callees: `getScannerCfg`, `ensureSignatureHandle`.
 * - 变量说明: 无显式入参；`signatureEnabled` 来自扫描配置，表示业务层是否允许启用签名引擎。
 * - Variables: No explicit parameters; `signatureEnabled` comes from scanner config and represents whether the business layer allows the signature engine.
 * - 接入方式: 仅作为签名引擎相关入口的前置门禁使用；新增签名能力时应先复用本函数，而不是各处自行判断配置和句柄状态。
 * - Integration: Use it only as the preflight gate for signature-engine entry points; new signature features should reuse this helper instead of rechecking config and handles ad hoc.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 签名引擎门禁 | signature engine gate | config enabled | handle ready | Raven native | preflight check | scan eligibility | training eligibility
 */
  function canUseSignatureEngine() {
    const { signatureEnabled } = getScannerCfg()
    if (!signatureEnabled) return false
    return ensureSignatureHandle()
  }

  /**
 * - 函数: `kvdHealth`
 * - Function: `kvdHealth`
 * - 作用: 检查 Axon 原生扫描库与签名库是否成功加载、模型路径是否完整、模型是否可被 native 侧验证，是扫描客户端对外的底层健康探针。
 * - Purpose: Verifies that the Axon native scan library and signature library are loaded, model paths are complete, and models pass native validation, serving as the low-level health probe exposed by the scanner client.
 * - 调用方: `health` 对外包装接口会调用本函数；初始化时的自检或故障诊断流程也适合直接复用。
 * - Callers: Called by the public `health` wrapper, and also suitable for initialization self-checks or fault-diagnosis flows.
 * - 被调方: `ensureKvdLibraryLoaded`、`ensureSignatureLibraryLoaded`、`buildKvdConfigValues`、`validateKvdConfigValues`、`trace`、`buildKvdConfigPtr`。
 * - Callees: `ensureKvdLibraryLoaded`, `ensureSignatureLibraryLoaded`, `buildKvdConfigValues`, `validateKvdConfigValues`, `trace`, `buildKvdConfigPtr`.
 * - 变量说明: 无显式入参；`axonReady`/`sigReady` 分别表示扫描库与签名库是否可用；`cfgObj` 为发给 native 校验器的模型配置快照。
 * - Variables: No explicit parameters; `axonReady` and `sigReady` indicate scan-library and signature-library readiness, while `cfgObj` is the model-config snapshot passed into native validation.
 * - 接入方式: 通过 `createScannerClient(...).health()` 间接接入；若要判断 native 端是否真正可扫描，优先依赖本函数而不是只看 DLL 是否加载。
 * - Integration: Reach it indirectly via `createScannerClient(...).health()`; if callers need to know whether native scanning is truly runnable, they should rely on this function rather than only checking DLL load state.
 * - 错误处理: 内部通过 `try/catch` 拦截局部异常；无法自行恢复时，会把错误继续抛给上游调用方处理。
 * - Error Handling: Uses `try/catch` to intercept local failures and rethrows or rejects unrecoverable errors back to upstream callers.
 * - 关键词: native健康检查 | native health check | model validation | DLL readiness | config validation | scanner probe | signature library | offline diagnosis
 */
  function kvdHealth() {
    const axonReady = ensureKvdLibraryLoaded()
    const sigReady = ensureSignatureLibraryLoaded()
    if (!axonReady && !sigReady) throw new Error(kvd.loadError || kvdSig.loadError || 'KVD_LOAD_FAILED')
    if (axonReady) {
      const cfgObj = buildKvdConfigValues()
      const valid = validateKvdConfigValues(cfgObj)
      if (!valid.ok) {
        trace('kvd_config_invalid', { missing: valid.missing })
        throw new Error('KVD_MODEL_MISSING')
      }
      if (!kvd.cfgPtr) kvd.cfgPtr = buildKvdConfigPtr(cfgObj)
      const outCfg = kvd.cfgPtr
      const outStr = [null]
      const outLen = [0]
      const rc = kvd.validateModels(outCfg, outStr, outLen)
      if (rc !== 0) {
        let msg = 'INVALID'
        try {
          const ptr = outStr[0]
          const len = outLen[0] | 0
          if (ptr && len > 0) {
            const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
            msg = Buffer.from(bytes).toString('utf8') || msg
            try { kvd.free(ptr) } catch {}
          }
        } catch {}
        const e = new Error(msg)
        e.code = String(rc)
        trace('kvd_validate_failed', { code: String(rc), message: msg })
        throw e
      }
      return { ok: true }
    }
    return { ok: true }
  }

  /**
 * - 函数: `kvdScanFile`
 * - Function: `kvdScanFile`
 * - 作用: 调用 Axon native DLL 对单个文件执行原生恶意扫描，并把 native 返回的 JSON 结果转换为 JS 对象，作为行为规则之外的主检测结果来源。
 * - Purpose: Invokes the Axon native DLL to scan a single file for malware and converts the native JSON payload into a JS object, serving as the main detection result source outside behavior rules.
 * - 调用方: `scanBatch` 在串行回退或补扫单文件时调用；其他单文件原生检测链路也应复用本函数。
 * - Callers: Called by `scanBatch` during serial fallback or targeted single-file rescans, and reusable from other native single-file detection flows.
 * - 被调方: `ensureKvdHandle`、`trace`、`path.basename`、`JSON.parse`。
 * - Callees: `ensureKvdHandle`, `trace`, `path.basename`, `JSON.parse`.
 * - 变量说明: `filePath` 为待扫描样本路径；`outStr/outLen` 用于承接 native DLL 回传的 JSON 缓冲区；`scanSeq` 用于 trace 链路上的前若干次文件扫描打点。
 * - Variables: `filePath` is the sample path to scan; `outStr/outLen` receive the JSON buffer returned by the native DLL; `scanSeq` provides trace sampling for the first few file scans.
 * - 接入方式: 仅作为原生单文件扫描底座使用；新增检测入口应优先复用本函数，而不是直接调用 `kvd.scanPath` 自己处理内存和 JSON 解析。
 * - Integration: Use it as the base native single-file scan primitive; new detection entries should reuse this helper instead of calling `kvd.scanPath` directly and manually decoding memory/JSON.
 * - 错误处理: 内部通过 `try/catch` 拦截局部异常；无法自行恢复时，会把错误继续抛给上游调用方处理。
 * - Error Handling: Uses `try/catch` to intercept local failures and rethrows or rejects unrecoverable errors back to upstream callers.
 * - 关键词: Axon单文件扫描 | Axon single-file scan | native DLL | JSON decode | malware verdict | scanPath | trace sampling | result parsing
 */
  async function kvdScanFile(filePath) {
    if (!ensureKvdHandle()) throw new Error('KVD_LOAD_FAILED')
    const outStr = [null]
    const outLen = [0]
    const scanSeq = ++traceState.scanPathSeq
    if (scanSeq <= 30) {
      const name = typeof filePath === 'string' ? path.basename(filePath) : ''
      trace('kvd_scan_path_begin', { id: scanSeq, name })
    }
    const rc = kvd.scanPath(kvd.handle, filePath, outStr, outLen)
    if (rc < 0) {
      trace('kvd_scan_path_failed', { code: String(rc) })
      throw new Error('KVD_SCAN_FAILED')
    }
    let json = '{}'
    try {
      const ptr = outStr[0]
      const len = outLen[0] | 0
      if (ptr && len > 0) {
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
        json = Buffer.from(bytes).toString('utf8') || '{}'
        try { kvd.free(ptr) } catch {}
      }
    } catch {}
    try {
      return JSON.parse(json)
    } catch {
      return {}
    }
  }

  /**
 * - 函数: `kvdScanPaths`
 * - Function: `kvdScanPaths`
 * - 作用: 调用 Axon native DLL 的批量扫描接口，对一组路径一次性完成原生检测，并在接口缺失时显式返回 `null` 让上层回退到逐文件扫描。
 * - Purpose: Invokes the Axon native DLL batch-scan API to scan a path list in one call and explicitly returns `null` when the batch API is unavailable so upper layers can fall back to per-file scans.
 * - 调用方: `scanBatch` 会优先调用本函数尝试批量原生扫描。
 * - Callers: Called first by `scanBatch` when attempting native batch scanning.
 * - 被调方: `ensureKvdHandle`、`trace`、`normalizeErrorPayload`、`Array.isArray`、`JSON.parse`。
 * - Callees: `ensureKvdHandle`, `trace`, `normalizeErrorPayload`, `Array.isArray`, `JSON.parse`.
 * - 变量说明: `filePaths` 为输入路径集合；`list` 为过滤后的有效路径数组；`arrPtr` 为传给 native 批量接口的字符串数组指针；`scanSeq` 用于批次 trace 采样。
 * - Variables: `filePaths` is the incoming path list; `list` is the filtered valid-path array; `arrPtr` is the native string-array pointer passed into the batch API; `scanSeq` is used for batch trace sampling.
 * - 接入方式: 仅作为原生批量扫描底座使用；外部新增批量扫描路径时应复用本函数，并尊重它用 `null` 表达“批量接口不可用、请上层回退”的语义。
 * - Integration: Use it only as the base native batch-scan primitive; new batch scan entries should reuse it and preserve its `null` meaning of “batch API unavailable, let upper layers fall back.”
 * - 错误处理: 内部通过 `try/catch` 拦截局部异常；无法自行恢复时，会把错误继续抛给上游调用方处理。
 * - Error Handling: Uses `try/catch` to intercept local failures and rethrows or rejects unrecoverable errors back to upstream callers.
 * - 关键词: Axon批量扫描 | Axon batch scan | scanPaths | native array pointer | batch fallback | null means unsupported | trace batch | result list
 */
  async function kvdScanPaths(filePaths) {
    if (!ensureKvdHandle()) throw new Error('KVD_LOAD_FAILED')
    const list = Array.isArray(filePaths) ? filePaths.filter(p => typeof p === 'string' && p) : []
    if (!list.length) return []
    if (!kvd.scanPaths) {
      if (!kvd.scanPathsMissingLogged) {
        kvd.scanPathsMissingLogged = true
        trace('kvd_scan_paths_missing')
      }
      return null
    }
    const scanSeq = ++traceState.scanPathsSeq
    if (scanSeq <= 10) trace('kvd_scan_paths_begin', { id: scanSeq, count: list.length })
    let arrPtr = null
    try {
      const arrType = koffi.array('string', list.length)
      arrPtr = koffi.alloc(arrType, list.length)
      koffi.encode(arrPtr, arrType, list)
    } catch (e) {
      arrPtr = null
      trace('kvd_scan_paths_alloc_failed', { ...normalizeErrorPayload(e) })
      throw new Error('KVD_SCAN_FAILED')
    }
    const outStr = [null]
    const outLen = [0]
    const rc = kvd.scanPaths(kvd.handle, arrPtr, list.length, outStr, outLen)
    if (rc < 0) {
      trace('kvd_scan_paths_failed', { code: String(rc) })
      throw new Error('KVD_SCAN_FAILED')
    }
    let json = '[]'
    try {
      const ptr = outStr[0]
      const len = outLen[0] | 0
      if (ptr && len > 0) {
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
        json = Buffer.from(bytes).toString('utf8') || '[]'
        try { kvd.free(ptr) } catch {}
      }
    } catch {}
    try {
      const parsed = JSON.parse(json)
      return Array.isArray(parsed) ? parsed : []
    } catch {
      return []
    }
  }

  /**
 * - 函数: `kvdScanFileSig`
 * - Function: `kvdScanFileSig`
 * - 作用: 使用 Raven/native 签名引擎对单个文件做签名命中检测，并在可信签名文件上提前短路放行，作为原生 Axon 结果之前的低成本补充判定层。
 * - Purpose: Runs Raven/native signature matching against a single file and short-circuits trusted signed files early, acting as the low-cost supplemental verdict layer before the heavier Axon result is considered.
 * - 调用方: `scanBatch` 在串行回退或单文件补扫时先调用本函数尝试获取签名层结论。
 * - Callers: Called by `scanBatch` during serial fallback or targeted rescans before native Axon verdicts are merged in.
 * - 被调方: `canUseSignatureEngine`、`verifyTrusted`、`traceSig`、`path.basename`、`JSON.parse`。
 * - Callees: `canUseSignatureEngine`, `verifyTrusted`, `traceSig`, `path.basename`, `JSON.parse`.
 * - 变量说明: `filePath` 为待做签名检测的文件；`sp` 为归一化后的安全路径；`outStr/outLen` 承接签名 DLL 返回的 JSON；`nativeRes` 为解析后的签名检测结果对象。
 * - Variables: `filePath` is the file under signature detection; `sp` is the normalized safe path; `outStr/outLen` receive the JSON returned by the signature DLL; `nativeRes` is the parsed signature verdict object.
 * - 接入方式: 仅作为单文件签名检测底座使用；新增单文件签名链路时应复用本函数，以保持“可信文件提前放行”的统一策略。
 * - Integration: Use it only as the base single-file signature primitive; new single-file signature flows should reuse it to preserve the shared “trusted files short-circuit early” policy.
 * - 错误处理: 内部通过 `try/catch` 拦截局部异常；无法自行恢复时，会把错误继续抛给上游调用方处理。
 * - Error Handling: Uses `try/catch` to intercept local failures and rethrows or rejects unrecoverable errors back to upstream callers.
 * - 关键词: Raven单文件签名 | Raven single-file signature | trusted short-circuit | signature_hit | signature_score | native signature DLL | JSON verdict | pre-Axon layer
 */
  async function kvdScanFileSig(filePath) {
    if (!canUseSignatureEngine()) return {}
    const sp = typeof filePath === 'string' ? filePath : ''
    if (sp && verifyTrusted(sp)) {
      return { signature_verified: true, signature_hit: false, signature_score: 0, is_malware: false, confidence: 0, signature_reason: 'signature_trusted' }
    }
    const outStr = [null]
    const outLen = [0]
    const scanSeq = ++traceState.scanPathSeq
    if (scanSeq <= 30) {
      const name = typeof filePath === 'string' ? path.basename(filePath) : ''
      traceSig('raven_scan_path_begin', { id: scanSeq, name })
    }
    const rc = kvdSig.scanPath(kvdSig.handle, filePath, outStr, outLen)
    if (rc < 0) {
      traceSig('raven_scan_path_failed', { code: String(rc) })
      throw new Error('KVD_SCAN_FAILED')
    }
    let json = '{}'
    try {
      const ptr = outStr[0]
      const len = outLen[0] | 0
      if (ptr && len > 0) {
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
        json = Buffer.from(bytes).toString('utf8') || '{}'
        try { kvdSig.free(ptr) } catch {}
      }
    } catch {}
    let nativeRes = {}
    try {
      nativeRes = JSON.parse(json)
    } catch {
      nativeRes = {}
    }
    return nativeRes && typeof nativeRes === 'object' ? nativeRes : {}
  }

  /**
 * - 函数: `kvdScanPathsSig`
 * - Function: `kvdScanPathsSig`
 * - 作用: 调用 Raven/native 签名引擎的批量接口，对一组文件预先做签名命中检测；当批量接口缺失或损坏时返回 `null`，由上层选择回退策略。
 * - Purpose: Invokes the Raven/native signature batch API to pre-check a file list for signature hits; when the batch API is missing or broken, it returns `null` so upper layers can choose a fallback strategy.
 * - 调用方: `scanBatch` 在批量扫描主流程中优先调用本函数，以便先用轻量签名结果过滤一部分文件。
 * - Callers: Called first by `scanBatch` in the batch-scan main flow so lightweight signature verdicts can filter part of the file set early.
 * - 被调方: `canUseSignatureEngine`、`traceSig`、`normalizeErrorPayload`、`verifyTrusted`、`Array.isArray`、`JSON.parse`。
 * - Callees: `canUseSignatureEngine`, `traceSig`, `normalizeErrorPayload`, `verifyTrusted`, `Array.isArray`, `JSON.parse`.
 * - 变量说明: `filePaths` 为输入路径集合；`list` 为归一化后的有效路径数组；`parsed` 为批量签名接口返回的结果数组；`out` 为最终与输入顺序对齐的签名结果列表。
 * - Variables: `filePaths` is the incoming path list; `list` is the normalized valid-path array; `parsed` is the result array returned by the batch signature API; `out` is the final signature verdict list aligned with input order.
 * - 接入方式: 仅作为批量签名预判层使用；新批量扫描链若需要签名预过滤，应优先复用本函数而不是循环调用 `kvdScanFileSig`。
 * - Integration: Use it only as the batch signature prefilter layer; new batch scan flows that need signature prefiltering should reuse it instead of looping over `kvdScanFileSig`.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: Raven批量签名 | Raven batch signature | signature prefilter | trusted bypass | batch API fallback | null means broken | ordered results | pre-scan layer
 */
  async function kvdScanPathsSig(filePaths) {
    const list = Array.isArray(filePaths) ? filePaths.filter(p => typeof p === 'string' && p) : []
    if (!list.length) return []
    if (!canUseSignatureEngine()) {
      const out = new Array(list.length)
      for (let i = 0; i < list.length; i++) out[i] = {}
      return out
    }
    if (kvdSig.scanPathsBroken) return null
    if (!kvdSig.scanPaths) {
      if (!kvdSig.scanPathsMissingLogged) {
        kvdSig.scanPathsMissingLogged = true
        traceSig('raven_scan_paths_missing')
      }
      return null
    }
    const scanSeq = ++traceState.scanPathsSeq
    if (scanSeq <= 10) traceSig('raven_scan_paths_begin', { id: scanSeq, count: list.length })
    let arrPtr = null
    try {
      const arrType = koffi.array('string', list.length)
      arrPtr = koffi.alloc(arrType, list.length)
      koffi.encode(arrPtr, arrType, list)
    } catch (e) {
      arrPtr = null
      traceSig('raven_scan_paths_alloc_failed', { ...normalizeErrorPayload(e) })
      kvdSig.scanPathsBroken = true
      return null
    }
    const outStr = [null]
    const outLen = [0]
    const rc = kvdSig.scanPaths(kvdSig.handle, arrPtr, list.length, outStr, outLen)
    if (rc < 0) {
      if (!kvdSig.scanPathsFailedLogged) {
        kvdSig.scanPathsFailedLogged = true
        traceSig('raven_scan_paths_failed', { code: String(rc) })
      }
      kvdSig.scanPathsBroken = true
      return null
    }
    let json = '[]'
    try {
      const ptr = outStr[0]
      const len = outLen[0] | 0
      if (ptr && len > 0) {
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
        json = Buffer.from(bytes).toString('utf8') || '[]'
        try { kvdSig.free(ptr) } catch {}
      }
    } catch {}
    let parsed = []
    try {
      const obj = JSON.parse(json)
      parsed = Array.isArray(obj) ? obj : []
    } catch {
      parsed = []
    }
    const out = new Array(list.length)
    for (let i = 0; i < list.length; i++) {
      const sp = list[i]
      if (sp && verifyTrusted(sp)) {
        out[i] = { signature_verified: true, signature_hit: false, signature_score: 0, is_malware: false, confidence: 0, signature_reason: 'signature_trusted' }
      } else {
        const nativeRes = parsed[i] || {}
        out[i] = (nativeRes && typeof nativeRes === 'object') ? nativeRes : {}
      }
    }
    return out
  }

  /**
 * - 函数: `mergeScanResult`
 * - Function: `mergeScanResult`
 * - 作用: 把 Axon 原生扫描结果与 Raven 签名结果折叠成单一 verdict，对 `is_malware`、`confidence`、`signature_*` 字段做统一裁决，是批量扫描主链最终出参的合并节点。
 * - Purpose: Folds the Axon native scan result and the Raven signature result into one verdict, unifying `is_malware`, `confidence`, and `signature_*` fields as the final merge node of the batch-scan pipeline.
 * - 调用方: `scanBatch` 在同时拿到 native 与签名层结果后调用；串行回退和并行 worker 分支最终都会汇总到这里。
 * - Callers: Called by `scanBatch` after both native and signature-layer results are available; both serial fallback and parallel worker branches eventually converge here.
 * - 被调方: `Object.assign`、`Number.isFinite`、`Math.max`。
 * - Callees: `Object.assign`, `Number.isFinite`, `Math.max`.
 * - 变量说明: `axonRes` 为原生引擎结果；`sigRes` 为签名层结果；`a/s` 为归一化后的对象视图；`out` 为最终返回给上层的合并 verdict。
 * - Variables: `axonRes` is the native-engine result; `sigRes` is the signature-layer result; `a/s` are their normalized object views; `out` is the merged verdict returned upstream.
 * - 接入方式: 仅作为扫描主链的结果折叠器使用；新增检测层时应优先扩展本函数，而不是在 `scanBatch` 各分支重复编排字段优先级。
 * - Integration: Use it only as the scan pipeline’s verdict reducer; if a new detection layer is added, its precedence should be integrated here instead of re-implementing merge rules inside each `scanBatch` branch.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: verdict 合并 | verdict merge | Axon plus Raven | confidence arbitration | signature fields | malware union | result reducer | scan pipeline
 */
  function mergeScanResult(axonRes, sigRes) {
    const a = axonRes && typeof axonRes === 'object' ? axonRes : {}
    const s = sigRes && typeof sigRes === 'object' ? sigRes : {}
    const out = Object.assign({}, a)
    if (s.signature_hit !== undefined) out.signature_hit = s.signature_hit
    if (s.signature_score !== undefined) out.signature_score = s.signature_score
    if (s.signature_reason) out.signature_reason = s.signature_reason
    const aMal = a.is_malware === true
    const sMal = s.is_malware === true
    out.is_malware = aMal || sMal
    const aConf = Number.isFinite(a.confidence) ? a.confidence : 0
    const sConf = Number.isFinite(s.confidence) ? s.confidence : 0
    if (aMal || sMal) out.confidence = Math.max(aConf, sConf)
    if ((s.signature_hit === true || (Number.isFinite(s.signature_score) && s.signature_score > 0)) && out.error === 'signature_disabled') {
      delete out.error
    }
    return out
  }

  /**
 * - 函数: `kvdTrainFromPath`
 * - Function: `kvdTrainFromPath`
 * - 作用: 使用 Axon native 训练接口对单个 PE 样本做白/黑样本训练，并把 native 统计结果还原为 JS 对象，是 native 模型训练的最小执行单元。
 * - Purpose: Uses the Axon native training API to train one PE sample as white or black and converts the native training stats back into a JS object, serving as the smallest execution unit for native model training.
 * - 调用方: 上层训练入口在需要训练单个 native 样本时调用；批量训练不支持时也可通过逐个调用本函数退化执行。
 * - Callers: Used by upper-layer training entries when training a single native sample, and also reusable as the fallback path when true batch training is unavailable.
 * - 被调方: `ensureKvdHandle`、`trace`、`isLikelyPeFile`、`trainFromPath`、`path.basename`、`JSON.parse`。
 * - Callees: `ensureKvdHandle`, `trace`, `isLikelyPeFile`, `trainFromPath`, `path.basename`, `JSON.parse`.
 * - 变量说明: `samplePath` 为目标样本路径；`isWhite` 控制白样本/黑样本标记；`sp` 为归一化后的路径；`flag` 为传给 native 的训练标签位；`obj` 为 native 回传的训练统计对象。
 * - Variables: `samplePath` is the target sample path; `isWhite` controls white-vs-black labeling; `sp` is the normalized path; `flag` is the native training label bit; `obj` is the training-stats object returned by native code.
 * - 接入方式: 仅作为 native 单样本训练底座使用；新增训练入口应复用本函数，以保持对非 PE 样本的统一拒绝策略和 trace 语义。
 * - Integration: Use it only as the base native single-sample training primitive; new training entries should reuse it to preserve the shared non-PE rejection policy and trace semantics.
 * - 错误处理: 内部通过 `try/catch` 拦截局部异常；无法自行恢复时，会把错误继续抛给上游调用方处理。
 * - Error Handling: Uses `try/catch` to intercept local failures and rethrows or rejects unrecoverable errors back to upstream callers.
 * - 关键词: Axon单样本训练 | Axon single-sample training | PE only | white black label | native train API | training stats | trace result | model update
 */
  async function kvdTrainFromPath(samplePath, isWhite) {
    if (!ensureKvdHandle()) {
      const code = kvd.loadError || 'KVD_LOAD_FAILED'
      trace('kvd_train_failed', { code })
      throw new Error(code)
    }
    if (!kvd.trainFromPath) {
      trace('kvd_train_unsupported')
      throw new Error('KVD_TRAIN_UNSUPPORTED')
    }
    const sp = typeof samplePath === 'string' ? samplePath : ''
    if (!sp) {
      trace('kvd_train_invalid_path')
      throw new Error('INVALID_SAMPLE_PATH')
    }
    const name = path.basename(sp)
    if (!isLikelyPeFile(sp)) {
      trace('kvd_train_error_invalid_pe', { name })
      throw new Error('KVD_TRAIN_INVALID_PE')
    }
    trace('kvd_train_begin', { name, isWhite: isWhite === true })
    const outStr = [null]
    const outLen = [0]
    const flag = isWhite ? 0 : 1
    const rc = kvd.trainFromPath(kvd.handle, sp, flag, outStr, outLen)
    if (rc < 0) {
      trace('kvd_train_failed', { code: String(rc), name })
      throw new Error('KVD_TRAIN_FAILED')
    }
    let json = '{}'
    try {
      const ptr = outStr[0]
      const len = outLen[0] | 0
      if (ptr && len > 0) {
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
        json = Buffer.from(bytes).toString('utf8') || '{}'
        try { kvd.free(ptr) } catch {}
      }
    } catch {}
    let obj = {}
    try {
      obj = JSON.parse(json)
    } catch {
      obj = {}
    }
    const ok = obj && typeof obj === 'object' ? obj.ok === true : false
    trace('kvd_train_ok', { name, ok: ok === true, total: obj.total || 0, trained: obj.trained || 0, failed: obj.failed || 0 })
    return obj
  }

  /**
 * - 函数: `kvdTrainFromPathSig`
 * - Function: `kvdTrainFromPathSig`
 * - 作用: 使用 Raven/native 签名训练接口对单个样本做签名训练，并在训练前检查 native 训练禁用开关、PE 适配性和句柄可用性，是签名单样本训练的核心执行入口。
 * - Purpose: Uses the Raven/native signature training API to train one sample and checks the native-train disable flag, PE suitability, and handle readiness before execution, making it the core execution entry for single-sample signature training.
 * - 调用方: `trainFromPath` 的单样本训练链会调用本函数；`kvdTrainPathsSig` 在批量接口缺失时也会逐个回退到这里。
 * - Callers: Called by the single-sample training path in `trainFromPath`, and also reused by `kvdTrainPathsSig` as the per-file fallback when the batch API is unavailable.
 * - 被调方: `ensureSignatureHandle`、`traceSig`、`isLikelyPeFile`、`trainFromPath`、`path.basename`、`JSON.parse`。
 * - Callees: `ensureSignatureHandle`, `traceSig`, `isLikelyPeFile`, `trainFromPath`, `path.basename`, `JSON.parse`.
 * - 变量说明: `samplePath` 为目标样本路径；`isWhite` 为标签位；`options` 为扩展训练选项预留位；`nativeTrainDisabled` 表示是否禁止 native 签名训练；`obj` 为训练结果统计。
 * - Variables: `samplePath` is the target sample path; `isWhite` is the label bit; `options` is reserved for extended training options; `nativeTrainDisabled` indicates whether native signature training is disabled; `obj` is the training result stats object.
 * - 接入方式: 仅作为签名单样本训练底座使用；新增签名训练入口应优先复用本函数，以继承“禁用开关优先、非 PE 仅记录 trace、不在此处做 JS 特征库写入”的统一语义。
 * - Integration: Use it only as the base single-sample signature-training primitive; new signature-training entries should reuse it to inherit the shared semantics of “disable flag first, non-PE only traced, no JS store append here.”
 * - 错误处理: 内部通过 `try/catch` 拦截局部异常；无法自行恢复时，会把错误继续抛给上游调用方处理。
 * - Error Handling: Uses `try/catch` to intercept local failures and rethrows or rejects unrecoverable errors back to upstream callers.
 * - 关键词: Raven单样本训练 | Raven single-sample training | native train disable | PE suitability | signature handle | traceSig | training stats | per-file fallback
 */
  async function kvdTrainFromPathSig(samplePath, isWhite, options) {
    if (!ensureSignatureHandle()) {
      const code = kvdSig.loadError || 'KVD_LOAD_FAILED'
      traceSig('raven_train_failed', { code })
      throw new Error(code)
    }
    if (!kvdSig.trainFromPath) {
      traceSig('raven_train_unsupported')
      throw new Error('KVD_TRAIN_UNSUPPORTED')
    }
    const sp = typeof samplePath === 'string' ? samplePath : ''
    if (!sp) {
      traceSig('raven_train_invalid_path')
      throw new Error('INVALID_SAMPLE_PATH')
    }
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const nativeTrainDisabled = scanner && scanner.signatureNativeTrainDisabled === true
    const name = path.basename(sp)
    const isPe = isLikelyPeFile(sp)
    if (!isPe) traceSig('raven_train_non_pe', { name })
    traceSig('raven_train_begin', { name, isWhite: isWhite === true })
    const outStr = [null]
    const outLen = [0]
    const flag = isWhite ? 0 : 1
    let obj = {}
    if (nativeTrainDisabled) {
      traceSig('raven_train_failed', { code: 'NATIVE_TRAIN_DISABLED', name })
      throw new Error('NATIVE_TRAIN_DISABLED')
    }
    const rc = kvdSig.trainFromPath(kvdSig.handle, sp, flag, outStr, outLen)
    if (rc < 0) {
      traceSig('raven_train_failed', { code: String(rc), name })
      throw new Error('KVD_TRAIN_FAILED')
    }
    let json = '{}'
    try {
      const ptr = outStr[0]
      const len = outLen[0] | 0
      if (ptr && len > 0) {
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
        json = Buffer.from(bytes).toString('utf8') || '{}'
        try { kvdSig.free(ptr) } catch {}
      }
    } catch {}
    try {
      obj = JSON.parse(json)
    } catch {
      obj = {}
    }
    const ok = obj && typeof obj === 'object' ? obj.ok === true : false
    traceSig('raven_train_ok', { name, ok: ok === true, total: obj.total || 0, trained: obj.trained || 0, failed: obj.failed || 0 })
    if (!ok) throw new Error('KVD_TRAIN_FAILED')
    return obj
  }

  /**
 * - 函数: `kvdTrainPathsSig`
 * - Function: `kvdTrainPathsSig`
 * - 作用: 使用 Raven/native 的批量训练接口训练一组样本；若批量接口不可用，则退化为逐文件调用 `kvdTrainFromPathSig` 并手工汇总训练统计。
 * - Purpose: Uses Raven/native batch training to train a sample list; if the batch API is unavailable, it degrades to per-file `kvdTrainFromPathSig` calls and aggregates training stats manually.
 * - 调用方: `trainPaths` 的批量训练链会调用本函数，把 worker 或主进程传来的样本集合转交给 native 签名训练层。
 * - Callers: Called by the batch training path in `trainPaths`, forwarding sample lists from workers or the main process into the native signature-training layer.
 * - 被调方: `ensureSignatureHandle`、`kvdTrainFromPathSig`、`trainPaths`、`flush`、`Array.isArray`、`JSON.parse`。
 * - Callees: `ensureSignatureHandle`, `kvdTrainFromPathSig`, `trainPaths`, `flush`, `Array.isArray`, `JSON.parse`.
 * - 变量说明: `filePaths` 为批量训练输入；`list` 为过滤后的有效路径数组；`out` 为批量接口缺失时的手工汇总结果；`flag` 为 native 批量训练标签位。
 * - Variables: `filePaths` is the batch training input; `list` is the filtered valid path array; `out` is the manually aggregated result when the batch API is missing; `flag` is the native label bit for batch training.
 * - 接入方式: 仅作为签名批量训练底座使用；新增批量训练入口应复用本函数，以继承“优先批量接口、失败时逐文件回退、结束后尝试 flush”的完整策略。
 * - Integration: Use it only as the base signature batch-training primitive; new batch training entries should reuse it to inherit the full strategy of “prefer batch API, fall back per file, flush after completion.”
 * - 错误处理: 内部通过 `try/catch` 拦截局部异常；无法自行恢复时，会把错误继续抛给上游调用方处理。
 * - Error Handling: Uses `try/catch` to intercept local failures and rethrows or rejects unrecoverable errors back to upstream callers.
 * - 关键词: Raven批量训练 | Raven batch training | batch API preferred | per-file fallback | training aggregate | signature flush | sample list | native stats
 */
  async function kvdTrainPathsSig(filePaths, isWhite) {
    if (!ensureSignatureHandle()) throw new Error('KVD_LOAD_FAILED')
    const list = Array.isArray(filePaths) ? filePaths.filter(p => typeof p === 'string' && p) : []
    if (!list.length) return { ok: false, total: 0, trained: 0, failed: 0 }
    if (!kvdSig.trainPaths) {
      const out = { ok: false, total: 0, trained: 0, failed: 0 }
      for (const p of list) {
        try {
          const r = await kvdTrainFromPathSig(p, isWhite)
          if (r && r.ok) {
            out.total += 1
            out.trained += 1
          } else {
            out.total += 1
            out.failed += 1
          }
        } catch {
          out.total += 1
          out.failed += 1
        }
      }
      out.ok = out.trained > 0
      return out
    }
    let arrPtr = null
    try {
      const arrType = koffi.array('string', list.length)
      arrPtr = koffi.alloc(arrType, list.length)
      koffi.encode(arrPtr, arrType, list)
    } catch {
      throw new Error('KVD_TRAIN_FAILED')
    }
    const outStr = [null]
    const outLen = [0]
    const flag = isWhite ? 0 : 1
    const rc = kvdSig.trainPaths(kvdSig.handle, arrPtr, list.length, flag, outStr, outLen)
    if (rc < 0) throw new Error('KVD_TRAIN_FAILED')
    let json = '{}'
    try {
      const ptr = outStr[0]
      const len = outLen[0] | 0
      if (ptr && len > 0) {
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len))
        json = Buffer.from(bytes).toString('utf8') || '{}'
        try { kvdSig.free(ptr) } catch {}
      }
    } catch {}
    let obj = {}
    try { obj = JSON.parse(json) } catch { obj = {} }
    try { if (kvdSig.flush) kvdSig.flush(kvdSig.handle) } catch {}
    const ok = obj && typeof obj === 'object' ? obj.ok === true : false
    if (!ok) throw new Error('KVD_TRAIN_FAILED')
    return obj
  }

  /**
 * - 函数: `setActive`
 * - Function: `setActive`
 * - 作用: 把当前请求 ID 与可执行的中止函数注册到 `active` 表中，使批量扫描或训练任务在执行期间可被 `abort()` 按请求级取消。
 * - Purpose: Registers the current request id together with an executable abort function inside the `active` map so running batch scans or training jobs can later be cancelled by `abort()` on a per-request basis.
 * - 调用方: `scanBatch` 在创建 worker 池任务或长链路扫描时调用；其他未来的可取消训练链路也应复用。
 * - Callers: Called by `scanBatch` when creating worker-pool tasks or other long-running scan flows, and reusable by future cancellable training paths.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `id` 为请求标识；`abortFn` 为真正执行取消逻辑的闭包，可能封装 worker 终止、任务标记或 Promise 中断。
 * - Variables: `id` is the request identifier; `abortFn` is the closure that performs real cancellation, potentially terminating workers, flipping task flags, or interrupting promises.
 * - 接入方式: 仅用于注册可取消任务；新增长任务如果需要支持 `abort(requestId)`，应在启动时先调用本函数登记。
 * - Integration: Use it only to register cancellable work; any new long-running task that should support `abort(requestId)` must call this helper when it starts.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 活跃任务注册 | active task registration | request map | abort handle bind | cancellable scan | long-running task | cooperative control | active registry
 */
  function setActive(id, abortFn) {
    if (!id || typeof abortFn !== 'function') return
    active.set(String(id), abortFn)
  }

  /**
 * - 函数: `clearActive`
 * - Function: `clearActive`
 * - 作用: 在请求结束、失败或被取消后，从 `active` 表中移除对应的中止句柄，避免旧请求残留导致误取消或内存泄漏。
 * - Purpose: Removes the abort handle for a request from the `active` map after completion, failure, or cancellation so stale entries do not cause accidental aborts or memory leaks.
 * - 调用方: `scanBatch` 在批次结束时调用；其他注册过 `setActive` 的可取消链路也应在收尾阶段复用。
 * - Callers: Called by `scanBatch` when a batch finishes, and it should also be reused by any other cancellable flow that previously registered through `setActive`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `id` 为待清理请求的标识，函数内部会把它转成 `active` 表使用的字符串键。
 * - Variables: `id` is the identifier of the request being cleaned up, and the function converts it into the string key used by the `active` map.
 * - 接入方式: 仅作为可取消任务的收尾清理步骤使用；凡是调用过 `setActive` 的流程，原则上都应在 `finally` 或终态分支中调用本函数。
 * - Integration: Use it only as the teardown step for cancellable work; any flow that calls `setActive` should normally invoke this helper in `finally` or another terminal branch.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 活跃任务清理 | active task cleanup | abort registry cleanup | request lifecycle | stale handle removal | finally cleanup | memory hygiene | cancel safety
 */
  function clearActive(id) {
    if (!id) return
    active.delete(String(id))
  }

  /**
 * - 函数: `abort`
 * - Function: `abort`
 * - 作用: 根据请求 ID 找到正在执行的批量扫描/训练中止句柄并主动触发取消，是扫描客户端对外暴露的协作式取消入口。
 * - Purpose: Locates the in-flight abort handle by request id and actively triggers cancellation, serving as the cooperative cancellation entry exposed by the scanner client.
 * - 调用方: 主进程或 worker 在用户取消扫描任务、窗口关闭或超时控制时调用。
 * - Callers: Called by the main process or workers when users cancel scans, windows close, or timeout controls trigger.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `id` 为待取消任务的请求标识；`key` 为字符串化后的 map 键；`fn` 为具体执行取消的中止函数。
 * - Variables: `id` is the request identifier of the task to cancel; `key` is the stringified map key; `fn` is the concrete abort function that performs cancellation.
 * - 接入方式: 通过 `createScannerClient(...).abort(requestId)` 接入；新增可取消任务应先调用 `setActive` 注册自己的 abort 句柄。
 * - Integration: Use `createScannerClient(...).abort(requestId)`; new cancellable tasks should register their abort handle through `setActive` first.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 协作式取消 | cooperative cancel | request abort | active map | abort handle | scan cancellation | training cancellation | safe cleanup
 */
  function abort(id) {
    const key = id ? String(id) : ''
    if (!key) return false
    const fn = active.get(key)
    if (!fn) return false
    try { fn() } catch {}
    active.delete(key)
    return true
  }

  /**
 * - 函数: `health`
 * - Function: `health`
 * - 作用: 对外包装 `kvdHealth`，把 native 层抛出的加载失败、模型无效或离线异常统一折叠为稳定的健康状态对象，供 UI 和 worker 做连通性探测。
 * - Purpose: Wraps `kvdHealth` and folds native load failures, invalid-model states, or offline exceptions into a stable health-status object for UI and workers to probe connectivity and readiness.
 * - 调用方: 主进程健康检查、worker 自检和外部诊断接口通过返回对象上的 `health()` 调用。
 * - Callers: Called through the returned `health()` API by main-process health checks, worker self-tests, and external diagnostic endpoints.
 * - 被调方: `kvdHealth`。
 * - Callees: `kvdHealth`.
 * - 变量说明: `requestId` 预留给上层链路追踪；`code` 为 native 错误码；`message` 为对外呈现的离线或失败说明。
 * - Variables: `requestId` is reserved for upper-layer request tracing; `code` is the native error code; `message` is the externally visible offline/failure description.
 * - 接入方式: 通过 `createScannerClient(...).health()` 对外接入；新增探针类能力应优先在此层包装底层异常，而不是把 native 异常直接暴露给 UI。
 * - Integration: Expose it through `createScannerClient(...).health()`; new probe-style capabilities should wrap lower-level exceptions here instead of surfacing raw native errors to the UI.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 对外健康探针 | public health probe | offline status | native error folding | readiness check | UI diagnostics | worker probe | stable status object
 */
  async function health(requestId) {
    try {
      return kvdHealth(requestId)
    } catch (e) {
      const code = e && e.code ? String(e.code) : (kvd && kvd.loadError ? String(kvd.loadError) : '')
      const message = e && e.message ? String(e.message) : 'OFFLINE'
      return { ok: false, status: 'offline', code, message }
    }
  }

  /**
   * - 函数: `scanFile`
   * - Function: `scanFile`
   * - 作用: 对单个文件提供轻量包装扫描接口，将单文件请求统一折叠为单元素批量扫描，再从 `scanBatch` 返回结果中提取首项，保持单文件与批量扫描共用同一套策略。
   * - Purpose: Provides a lightweight single-file scan wrapper by converting the request into a one-element batch scan and extracting the first result from `scanBatch`, keeping single-file and batch scans on the same execution policy.
   * - 调用方: `createScannerClient` 返回对象上的 `scanFile` API 消费方，包括主进程扫描入口和各类扫描 worker 的单文件请求流程。
   * - Callers: Consumers of the `scanFile` API exposed by `createScannerClient`, including main-process scan entry points and single-file flows inside scanner workers.
   * - 被调方: `Error`、`scanBatch`、`Array.isArray`。
   * - Callees: `Error`, `scanBatch`, `Array.isArray`.
   * - 变量说明: `filePath` 为待扫描文件路径；`requestId` 为链路追踪或日志关联使用的请求标识；`fp` 为归一化后的安全字符串路径；`res` 为批量扫描返回数组。
   * - Variables: `filePath` is the target file path, `requestId` is the tracing/request correlation id, `fp` is the normalized safe string path, and `res` is the batch-scan result array.
   * - 接入方式: 通过 `createScannerClient(...).scanFile` 对外接入；若新增单文件扫描入口，优先复用本函数而不是直接复制 `scanBatch([file])` 逻辑，以保持错误码和结果抽取行为一致。
   * - Integration: Expose it through `createScannerClient(...).scanFile`; new single-file scan entry points should reuse this function instead of duplicating `scanBatch([file])` so error codes and result extraction stay consistent.
   * - 错误处理: 传入空路径时立即抛出 `INVALID_FILE_PATH`；底层 `scanBatch` 的 native 加载失败、批量扫描失败或任务中止等异常会原样透传给调用方，由上层决定是否提示、重试或降级。
   * - Error Handling: It throws `INVALID_FILE_PATH` immediately for empty input; failures from `scanBatch`, such as native load errors, batch execution errors, or abort conditions, are propagated unchanged for upper layers to report, retry, or downgrade.
   * - 关键词: 单文件扫描 | single file scan | 批量复用 | batch reuse | 请求追踪 | request tracing | 错误透传 | error propagation | 结果抽取 | result extraction
   */
  async function scanFile(filePath, requestId) {
    const fp = typeof filePath === 'string' ? filePath : ''
    if (!fp) throw new Error('INVALID_FILE_PATH')

    const res = await scanBatch([fp], requestId)
    return (Array.isArray(res) && res[0]) ? res[0] : {}
  }

  /**
   * - 函数: `scanBatch`
   * - Function: `scanBatch`
   * - 作用: 作为扫描客户端的批量文件扫描主通道，负责参数归一化、native 能力校验、签名扫描优先命中、串行回退与 worker 池并行调度，并最终合并每个文件的检测结果。
   * - Purpose: Serves as the primary batch-file scan pipeline for the scanner client by normalizing inputs, validating native availability, prioritizing signature hits, handling serial fallback or worker-pool parallel dispatch, and merging per-file scan results.
   * - 调用方: `scanFile` 的单文件包装路径，以及 `createScannerClient` 返回对象上的 `scanBatch` API 消费方。
   * - Callers: Called by the single-file wrapper `scanFile` and by consumers of the public `scanBatch` API returned from `createScannerClient`.
   * - 被调方: `Error`、`canUseNative`、`ensureWorkerPool`、`kvdScanPathsSig`、`mergeScanResult`、`kvdScanPaths`、`String` 等。
   * - Callees: `Error`, `canUseNative`, `ensureWorkerPool`, `kvdScanPathsSig`, `mergeScanResult`, `kvdScanPaths`, `String`, and related helpers.
   * - 变量说明: `filePaths` 为输入路径集合；`requestId` 用于关联批次请求；`fps` 为过滤后的有效路径数组；`pool` 表示可选 worker 池；`out` 保存最终结果；`sigArr`/`axonArr` 分别表示签名扫描和原生扫描返回；`sigOk`/`nativeOk` 表示对应结果是否可用。
   * - Variables: `filePaths` is the incoming path list, `requestId` correlates the batch request, `fps` is the filtered valid-path array, `pool` is the optional worker pool, `out` stores final results, `sigArr` and `axonArr` hold signature/native scan outputs, and `sigOk`/`nativeOk` indicate whether those outputs are usable.
   * - 接入方式: 通过 `createScannerClient(...).scanBatch` 暴露给主进程或 worker 使用；新增批量检测场景应复用本函数，以继承签名优先、串行回退、并行池化和结果合并的完整策略，而不是分别直连底层 DLL。
   * - Integration: Expose it through `createScannerClient(...).scanBatch` for main-process or worker usage; new batch-detection scenarios should reuse this function to inherit signature-first matching, serial fallback, worker-pool parallelism, and result merging instead of calling the underlying DLLs directly.
   * - 错误处理: 输入数组无有效路径时抛出 `INVALID_FILE_PATHS`，native 能力不可用时抛出 `KVD_LOAD_FAILED`；签名扫描、原生扫描的局部失败会在串行分支内做兜底判空，而并行分支中的任务级异常则交由上层调用方统一决定是否记录、重试或中止。
   * - Error Handling: It throws `INVALID_FILE_PATHS` when no valid input paths remain and `KVD_LOAD_FAILED` when native scanning is unavailable; partial signature/native failures are tolerated as nullable results in the serial path, while task-level failures in the parallel path are left to upper layers to log, retry, or abort.
   * - 关键词: 批量扫描 | batch scan | 签名优先 | signature first | worker并发 | worker parallelism | 串行回退 | serial fallback | 结果合并 | result merging
   */
  async function scanBatch(filePaths, requestId) {
    const fps = Array.isArray(filePaths) ? filePaths.filter(p => typeof p === 'string' && p) : []
    if (fps.length === 0) throw new Error('INVALID_FILE_PATHS')
    if (!canUseNative()) throw new Error('KVD_LOAD_FAILED')
    const pool = ensureWorkerPool()
    if (!pool) {
      const out = new Array(fps.length)
      let axonArr = null
      let sigArr = null
      try { sigArr = await kvdScanPathsSig(fps) } catch { sigArr = null }
      const sigOk = Array.isArray(sigArr) && sigArr.length === fps.length
      if (sigOk) {
        for (let i = 0; i < fps.length; i++) {
          const s = sigArr[i] || {}
          const sigReason = (s && typeof s.signature_reason === 'string') ? String(s.signature_reason) : ''
          const weightReason = sigReason.includes('api_weight') || sigReason.includes('script_weight')
          if (s && (s.is_malware === true || s.signature_hit === true || (!weightReason && Number.isFinite(s.signature_score) && s.signature_score >= 0.92))) {
            out[i] = mergeScanResult({}, s)
          } else {
            out[i] = null
          }
        }
      }
      const needAxonIdx = []
      for (let i = 0; i < fps.length; i++) {
        if (out[i] == null) needAxonIdx.push(i)
      }
      if (needAxonIdx.length === 0) return out
      const needAxonPaths = needAxonIdx.map(i => fps[i])
      try { axonArr = await kvdScanPaths(needAxonPaths) } catch { axonArr = null }
      const axonOk = Array.isArray(axonArr) && axonArr.length === needAxonPaths.length
      if (axonOk && sigOk) {
        for (let j = 0; j < needAxonIdx.length; j++) {
          const i = needAxonIdx[j]
          const a = axonArr[j] || {}
          const s = sigArr[i] || {}
          out[i] = mergeScanResult(a, s)
        }
        return out
      }
      if (sigOk && !axonOk) {
        for (let j = 0; j < needAxonIdx.length; j++) {
          const i = needAxonIdx[j]
          let a = {}
          try { a = await kvdScanFile(needAxonPaths[j]) } catch {}
          const s = sigArr[i] || {}
          out[i] = mergeScanResult(a, s)
        }
        return out
      }
      if (!sigOk && axonOk) {
        for (let j = 0; j < needAxonIdx.length; j++) {
          const i = needAxonIdx[j]
          const a = axonArr[j] || {}
          let s = {}
          try { s = await kvdScanFileSig(fps[i]) } catch { s = {} }
          out[i] = mergeScanResult(a, s)
        }
        return out
      }
      for (let i = 0; i < fps.length; i++) {
        if (out[i] != null) continue
        let a = {}
        let s = {}
        try { s = await kvdScanFileSig(fps[i]) } catch {}
        const sigReason = (s && typeof s.signature_reason === 'string') ? String(s.signature_reason) : ''
        const weightReason = sigReason.includes('api_weight') || sigReason.includes('script_weight')
        if (s && (s.is_malware === true || s.signature_hit === true || (!weightReason && Number.isFinite(s.signature_score) && s.signature_score >= 0.92))) {
          out[i] = mergeScanResult({}, s)
          continue
        }
        try { a = await kvdScanFile(fps[i]) } catch {}
        out[i] = mergeScanResult(a, s)
      }
      return out
    }
    const rid = requestId ? String(requestId) : ''
    const poolSize = Math.max(1, pool.size || 1)
    if (fps.length <= 1 || poolSize <= 1) {
      return new Promise((resolve, reject) => {
        const task = {
          id: String(Date.now()) + '-' + String(workerSeq++),
          filePaths: fps,
          requestId: rid,
          resolve,
          reject,
          started: false,
          done: false,
          canceled: false,
          clearActiveOnDone: true,
          config: getWorkerConfigSnapshot()
        }
        if (rid) {
          setActive(rid, () => {
            if (task.done) return
            task.canceled = true
            task.done = true
            const idx = pool.queue.indexOf(task)
            if (idx >= 0) pool.queue.splice(idx, 1)
            try { resolve([]) } catch {}
            clearActive(rid)
          })
        }
        pool.queue.push(task)
        processNext(pool)
      })
    }
    const maxTasks = Math.min(poolSize, fps.length)
    const chunkSize = Math.max(1, Math.ceil(fps.length / maxTasks))
    const chunks = []
    for (let i = 0; i < fps.length; i += chunkSize) {
      chunks.push({ offset: i, list: fps.slice(i, i + chunkSize) })
    }
    const results = new Array(fps.length)
    const tasks = []
    const configSnapshot = getWorkerConfigSnapshot()
    const taskPromises = chunks.map(({ offset, list }) => {
      return new Promise((resolve, reject) => {
        const task = {
          id: String(Date.now()) + '-' + String(workerSeq++),
          filePaths: list,
          requestId: rid,
          resolve,
          reject,
          started: false,
          done: false,
          canceled: false,
          clearActiveOnDone: false,
          offset,
          config: configSnapshot
        }
        tasks.push(task)
        pool.queue.push(task)
      }).then((arr) => {
        const out = Array.isArray(arr) ? arr : []
        for (let i = 0; i < list.length; i++) {
          results[offset + i] = out[i] || {}
        }
        return true
      }).catch(() => {
        for (let i = 0; i < list.length; i++) {
          results[offset + i] = {}
        }
        return false
      })
    })
    if (rid) {
      setActive(rid, () => {
        for (const task of tasks) {
          if (task.done) continue
          task.canceled = true
          task.done = true
          const idx = pool.queue.indexOf(task)
          if (idx >= 0) pool.queue.splice(idx, 1)
          try { task.resolve([]) } catch {}
        }
        clearActive(rid)
      })
    }
    processNext(pool)
    return Promise.all(taskPromises).then(() => {
      if (rid) clearActive(rid)
      for (let i = 0; i < results.length; i++) {
        if (!results[i]) results[i] = {}
      }
      return results
    })
  }

  /**
 * - 函数: `control`
 * - Function: `control`
 * - 作用: 作为扫描客户端预留的控制命令入口，统一承接未来的 pause/resume/flush/reload 等控制面指令；当前实现只做入参校验并返回成功占位结果。
 * - Purpose: Serves as the reserved control-command entry of the scanner client, intended to centralize future pause/resume/flush/reload style control-plane commands; the current implementation only validates input and returns a placeholder success result.
 * - 调用方: 主进程或上层维护工具在需要向扫描客户端发送控制命令时调用。
 * - Callers: Called by the main process or upper-layer maintenance tools when they need to send control commands to the scanner client.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `command` 为控制命令文本；`token` 预留给鉴权或幂等控制；`requestId` 预留给链路追踪；`cmd` 为归一化后的命令字符串。
 * - Variables: `command` is the control-command text; `token` is reserved for auth or idempotency; `requestId` is reserved for tracing; `cmd` is the normalized command string.
 * - 接入方式: 通过 `createScannerClient(...).control()` 对外接入；新增控制命令应优先在这里扩展，而不是零散暴露新的方法。
 * - Integration: Expose it via `createScannerClient(...).control()`; future control commands should extend this method instead of creating scattered new APIs.
 * - 错误处理: 主要通过返回值与上游异常通道协同处理错误，失败会继续向调用方暴露。
 * - Error Handling: Relies on return values plus the upstream exception channel, so failures stay visible to callers.
 * - 关键词: 控制平面入口 | control-plane entry | reserved command channel | pause resume placeholder | command validation | future extensibility | maintenance API | scanner control
 */
  async function control(command, token, requestId) {
    const cmd = typeof command === 'string' ? command : ''
    if (!cmd) throw new Error('INVALID_COMMAND')
    return { ok: true }
  }

  /**
 * - 函数: `trainFromPath`
 * - Function: `trainFromPath`
 * - 作用: 执行单样本训练请求，并统一把 native/签名训练失败记录到跟踪日志，是 UI 手动训练和 worker 单文件训练的公共入口。
 * - Purpose: Executes a single-sample training request and consistently records native/signature training failures into trace logs, acting as the shared entry for UI manual training and worker-driven single-file training.
 * - 调用方: 主进程和训练 worker 在处理单文件训练需求时调用；内部最终复用 `kvdTrainFromPathSig` 完成实际训练。
 * - Callers: Called by the main process and training workers when handling single-file training requests, ultimately reusing `kvdTrainFromPathSig` for the actual training work.
 * - 被调方: `kvdTrainFromPathSig`、`trace`。
 * - Callees: `kvdTrainFromPathSig`, `trace`.
 * - 变量说明: `samplePath` 为目标样本路径；`isWhite` 区分白样本和黑样本；`options` 控制训练模式；`msg` 为异常摘要，用于 trace 记录。
 * - Variables: `samplePath` is the target sample path; `isWhite` distinguishes white vs black labels; `options` controls training mode; `msg` is the summarized failure text written to trace logs.
 * - 接入方式: 通过 `createScannerClient(...).trainFromPath()` 接入；新增单样本训练入口应优先复用本函数。
 * - Integration: Use `createScannerClient(...).trainFromPath()`; new single-sample training entries should reuse this helper first.
 * - 错误处理: 内部通过 `try/catch` 拦截局部异常；无法自行恢复时，会把错误继续抛给上游调用方处理。
 * - Error Handling: Uses `try/catch` to intercept local failures and rethrows or rejects unrecoverable errors back to upstream callers.
 * - 关键词: 单样本训练 | single-sample training | trainFromPath | trace logging | 标签训练 | labeled training | UI训练入口 | manual training | error rethrow
 */
  async function trainFromPath(samplePath, isWhite, options) {
    try {
      return await kvdTrainFromPathSig(samplePath, isWhite, options)
    } catch (e) {
      const msg = e && e.message ? String(e.message) : ''
      trace('kvd_sig_train_failed', { error: msg, stack: e.stack || '' })
      throw e
    }
  }

  /**
 * - 函数: `trainPaths`
 * - Function: `trainPaths`
 * - 作用: 执行多样本批量训练请求，并在失败时写入统一 trace，作为训练 worker 批量样本训练的主入口。
 * - Purpose: Executes batch training across multiple samples and writes uniform trace records on failure, acting as the main entry for bulk training in the training worker.
 * - 调用方: 训练 worker 的批量训练流程和主进程批量训练入口会调用本方法。
 * - Callers: Called by batch-training flows in the training worker and by main-process bulk training entries.
 * - 被调方: `kvdTrainPathsSig`、`trace`。
 * - Callees: `kvdTrainPathsSig`, `trace`.
 * - 变量说明: `filePaths` 为批量样本路径集合；`isWhite` 表示训练标签；`msg` 为异常摘要，用于统一训练失败 trace。
 * - Variables: `filePaths` is the batch sample path list; `isWhite` is the training label; `msg` is the summarized exception text used in failure trace records.
 * - 接入方式: 通过 `createScannerClient(...).trainPaths()` 接入；批量训练入口不要直接调用底层 DLL 包装函数。
 * - Integration: Use `createScannerClient(...).trainPaths()`; bulk-training callers should not call the low-level DLL wrappers directly.
 * - 错误处理: 内部通过 `try/catch` 拦截局部异常；无法自行恢复时，会把错误继续抛给上游调用方处理。
 * - Error Handling: Uses `try/catch` to intercept local failures and rethrows or rejects unrecoverable errors back to upstream callers.
 * - 关键词: 批量训练 | batch training | trainPaths | worker training | trace logging | 样本集合 | sample list | error rethrow
 */
  async function trainPaths(filePaths, isWhite) {
    try {
      return await kvdTrainPathsSig(filePaths, isWhite)
    } catch (e) {
      const msg = e && e.message ? String(e.message) : ''
      trace('kvd_sig_train_failed', { error: msg, stack: e.stack || '' })
      throw e
    }
  }

  const signatureWriteQueue = []
  let signatureWriteBusy = false

  /**
 * - 函数: `processSignatureWriteQueue`
 * - Function: `processSignatureWriteQueue`
 * - 作用: 串行消费待写入签名库的训练任务，确保特征库追加、版本号生成和索引更新在单线程顺序下完成，避免并发写坏日志式特征库。
 * - Purpose: Serially drains queued signature-store write tasks so store appends, version generation, and index updates happen in a single-threaded order, preventing concurrent corruption of the append-only store.
 * - 调用方: `queueSignatureStoreWrite` 在有新的训练结果等待写库时触发本函数。
 * - Callers: Triggered by `queueSignatureStoreWrite` whenever a new training result is waiting to be persisted.
 * - 被调方: `persistSignatureStore`。
 * - Callees: `persistSignatureStore`.
 * - 变量说明: 无显式入参；`signatureWriteQueue` 存放待落库训练任务；`task` 为当前出队任务；`res` 为本次 `persistSignatureStore` 的写入结果。
 * - Variables: No explicit parameters; `signatureWriteQueue` stores pending persistence tasks; `task` is the task currently dequeued; `res` is the write result returned by `persistSignatureStore`.
 * - 接入方式: 仅作为签名库写入管线内部调度器使用；外部新增异步写入入口时应入队，而不是直接并发调用 `persistSignatureStore`。
 * - Integration: Use it only as the internal scheduler of the signature-store write pipeline; new async write entries should enqueue work instead of calling `persistSignatureStore` concurrently.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 写队列消费 | write queue drain | serialized persistence | append-only store | version ordering | training commit queue | no concurrent writes | signature store
 */
  function processSignatureWriteQueue() {
    if (signatureWriteBusy) return
    signatureWriteBusy = true
    while (signatureWriteQueue.length) {
      const task = signatureWriteQueue.shift()
      const res = persistSignatureStore(task.result, task.features, task.meta, task.isWhite)
      try { task.resolve(res) } catch {}
    }
    signatureWriteBusy = false
  }

  /**
 * - 函数: `queueSignatureStoreWrite`
 * - Function: `queueSignatureStoreWrite`
 * - 作用: 把单次训练结果封装成一个顺序写库任务，并返回 Promise 供上层等待实际写库完成，是异步训练写入签名库的公共入口。
 * - Purpose: Wraps one training result as an ordered persistence task and returns a Promise that resolves when the actual store append finishes, serving as the shared async entry for writing trained samples into the signature store.
 * - 调用方: 主进程训练流程、worker 训练流程或未来的批量导入逻辑都应通过本函数入队写库。
 * - Callers: Main-process training flows, worker training flows, and future bulk-import logic should all enqueue store writes through this helper.
 * - 被调方: `push`、`processSignatureWriteQueue`。
 * - Callees: `push`, `processSignatureWriteQueue`.
 * - 变量说明: `result` 为训练统计；`features` 为待写入特征；`meta` 为样本元数据；`isWhite` 表示白样本/黑样本；`resolve` 用于把最终写入结果回传给调用方。
 * - Variables: `result` is the training summary; `features` are the features to persist; `meta` is sample metadata; `isWhite` marks white vs black samples; `resolve` sends the final write result back to the caller.
 * - 接入方式: 通过 `signatureStore.queueAppend(...)` 接入；所有希望异步、安全地写入签名库的调用方都应优先用本方法。
 * - Integration: Use `signatureStore.queueAppend(...)`; any caller that wants asynchronous and safe signature-store persistence should prefer this helper.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 异步写库入队 | async store enqueue | queueAppend | ordered persistence | training result commit | Promise handoff | no direct write | signature store
 */
  function queueSignatureStoreWrite(result, features, meta, isWhite) {
    return new Promise((resolve) => {
      signatureWriteQueue.push({ result, features, meta, isWhite, resolve })
      processSignatureWriteQueue()
    })
  }

  /**
 * - 函数: `listSignatureStoreVersions`
 * - Function: `listSignatureStoreVersions`
 * - 作用: 返回签名库当前已知的版本链列表，必要时先触发索引重建，供 UI、调试工具或回滚界面展示所有可选版本。
 * - Purpose: Returns the currently known version chain of the signature store and rebuilds the index first when necessary, so the UI, debugging tools, or rollback views can display all available versions.
 * - 调用方: 对外的签名库维护接口、版本列表展示或调试命令会调用本函数。
 * - Callers: Called by public signature-store maintenance APIs, version-list views, or debugging commands.
 * - 被调方: `resolveSignatureIndexPath`、`readSignatureIndex`、`resolveSignatureStorePath`、`rebuildSignatureIndex`、`Array.isArray`。
 * - Callees: `resolveSignatureIndexPath`, `readSignatureIndex`, `resolveSignatureStorePath`, `rebuildSignatureIndex`, `Array.isArray`.
 * - 变量说明: 无显式入参；`scanner` 为扫描配置；`indexPath` 为索引文件路径；`index` 为读取或重建后的索引对象。
 * - Variables: No explicit parameters; `scanner` is the scan config; `indexPath` is the index file path; `index` is the loaded or rebuilt index object.
 * - 接入方式: 通过 `signatureStore.listVersions()` 一类外层接口接入；任何版本列表展示都应复用本函数而不是直接读索引文件。
 * - Integration: Reach it through outer APIs such as `signatureStore.listVersions()`; all version-list displays should reuse this helper instead of reading index files directly.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 版本链列表 | version chain list | list versions | index rebuild fallback | UI version picker | rollback candidates | store metadata | maintenance API
 */
  function listSignatureStoreVersions() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const indexPath = resolveSignatureIndexPath(scanner)
    let index = readSignatureIndex(indexPath)
    if (!index) {
      const storePath = resolveSignatureStorePath(scanner)
      if (!storePath) return []
      index = rebuildSignatureIndex(storePath, indexPath)
    }
    return index && Array.isArray(index.versions) ? index.versions : []
  }

  /**
 * - 函数: `getSignatureStoreCurrentVersion`
 * - Function: `getSignatureStoreCurrentVersion`
 * - 作用: 读取签名库当前生效的版本 ID，必要时自动重建索引，供诊断、展示或回滚前确认当前落点。
 * - Purpose: Reads the currently active version id of the signature store and rebuilds the index automatically when needed, supporting diagnostics, UI display, and rollback confirmation.
 * - 调用方: 对外的签名库状态展示、调试命令和回滚前确认流程会调用本函数。
 * - Callers: Called by public signature-store status views, debugging commands, and rollback-confirmation flows.
 * - 被调方: `resolveSignatureIndexPath`、`readSignatureIndex`、`resolveSignatureStorePath`、`rebuildSignatureIndex`。
 * - Callees: `resolveSignatureIndexPath`, `readSignatureIndex`, `resolveSignatureStorePath`, `rebuildSignatureIndex`.
 * - 变量说明: 无显式入参；`scanner` 为扫描配置；`indexPath` 为索引路径；`index` 为读取或重建后的版本索引对象。
 * - Variables: No explicit parameters; `scanner` is the scan config; `indexPath` is the index path; `index` is the loaded or rebuilt version-index object.
 * - 接入方式: 应作为“当前版本是谁”的统一读取入口；调用方不要直接访问 `current_version_id` 文件字段。
 * - Integration: It should be the shared read entry for “which version is current”; callers should not access the `current_version_id` file field directly.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 当前版本 ID | current version id | active store version | rollback anchor | metadata probe | index fallback rebuild | status display | maintenance helper
 */
  function getSignatureStoreCurrentVersion() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const indexPath = resolveSignatureIndexPath(scanner)
    let index = readSignatureIndex(indexPath)
    if (!index) {
      const storePath = resolveSignatureStorePath(scanner)
      if (!storePath) return ''
      index = rebuildSignatureIndex(storePath, indexPath)
    }
    return index && typeof index.current_version_id === 'string' ? index.current_version_id : ''
  }

  /**
 * - 函数: `rollbackSignatureStore`
 * - Function: `rollbackSignatureStore`
 * - 作用: 通过修改版本索引中的 `current_version_id` 把签名库逻辑回滚到指定版本，而不直接改写主库文件内容，是低成本的版本切换入口。
 * - Purpose: Logically rolls the signature store back to a specified version by changing `current_version_id` in the version index, without rewriting the main store file, making it a low-cost version-switch entry.
 * - 调用方: 对外回滚命令、调试工具或签名库维护界面在选择目标版本后调用。
 * - Callers: Called by public rollback commands, debugging tools, or signature-store maintenance views after a target version is chosen.
 * - 被调方: `resolveSignatureStorePath`、`resolveSignatureIndexPath`、`readSignatureIndex`、`rebuildSignatureIndex`、`writeSignatureIndex`、`Array.isArray`。
 * - Callees: `resolveSignatureStorePath`, `resolveSignatureIndexPath`, `readSignatureIndex`, `rebuildSignatureIndex`, `writeSignatureIndex`, `Array.isArray`.
 * - 变量说明: `versionId` 为目标版本号；`id` 为归一化后的目标 ID；`index` 为当前版本索引；`exists` 表示目标版本是否存在于版本链中。
 * - Variables: `versionId` is the target version id; `id` is the normalized target id; `index` is the current version index; `exists` indicates whether the target version exists in the version chain.
 * - 接入方式: 应作为签名库逻辑回滚的统一入口；外层不要直接编辑索引文件中的 `current_version_id`。
 * - Integration: It should be the single logical rollback entry for the signature store; outer layers should not edit `current_version_id` in the index file directly.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 逻辑回滚 | logical rollback | current_version_id switch | version selector | no main file rewrite | rollback entry | metadata mutation | store maintenance
 */
  function rollbackSignatureStore(versionId) {
    const id = typeof versionId === 'string' ? versionId : ''
    if (!id) return false
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const storePath = resolveSignatureStorePath(scanner)
    const indexPath = resolveSignatureIndexPath(scanner)
    if (!storePath) return false
    let index = readSignatureIndex(indexPath)
    if (!index) index = rebuildSignatureIndex(storePath, indexPath)
    if (!index || !Array.isArray(index.versions)) return false
    const exists = index.versions.find(v => v && v.id === id)
    if (!exists) return false
    index.current_version_id = id
    return writeSignatureIndex(indexPath, index)
  }

  return {
    health,
    scanFile,
    scanBatch,
    control,
    abort,
    trainFromPath,
    trainPaths,
    signatureStore: {
      append: persistSignatureStore,
      queueAppend: queueSignatureStoreWrite,
      listVersions: listSignatureStoreVersions,
      getCurrentVersion: getSignatureStoreCurrentVersion,
      rollback: rollbackSignatureStore,
      loadCurrent: loadSignatureStore
    }
  }
}

module.exports = { createScannerClient }
