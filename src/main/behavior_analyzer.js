const path = require('path')
const { Worker } = require('worker_threads')

/**
 * - 函数: `getBehaviorCfg`
 * - Function: `getBehaviorCfg`
 * - 作用: 从主配置中提取行为分析子配置，并补齐启用状态、刷盘间隔和 SQLite 存储路径默认值，作为行为分析器与落库 worker 共用的统一配置入口。
 * - Purpose: Extracts the behavior-analyzer sub-config from the app config, fills default values for enablement, flush interval, and SQLite storage, and serves as the shared config entry for both the analyzer and the persistence worker.
 * - 调用方: `createBehaviorAnalyzer` 在创建分析器实例时调用；外部也可单独读取规范化后的行为分析配置。
 * - Callers: Called by `createBehaviorAnalyzer` while constructing the analyzer; external consumers may also read the normalized behavior-analyzer config directly.
 * - 被调方: 当前函数主要依赖字段解构、默认值回退和 `Number.isFinite` 完成配置规范化。
 * - Callees: Mainly relies on field extraction, default fallbacks, and `Number.isFinite` to normalize configuration.
 * - 变量说明: `appConfig` 为应用总配置；`cfg` 为 `behaviorAnalyzer` 子配置；`sqliteCfg` 为补齐默认值后的持久化配置快照。
 * - Variables: `appConfig` is the root application config; `cfg` is the `behaviorAnalyzer` sub-config; `sqliteCfg` is the persistence snapshot after defaults are applied.
 * - 接入方式: 可通过 `require('./behavior_analyzer').getBehaviorCfg` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./behavior_analyzer').getBehaviorCfg`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 获取 | behavior | cfg | get | behavior | cfg | call chain | 错误处理 | error handling | 复用
 */
function getBehaviorCfg(appConfig = {}) {
  const cfg = appConfig && appConfig.behaviorAnalyzer ? appConfig.behaviorAnalyzer : {}
  const enabled = cfg.enabled !== false
  const flushIntervalMs = Number.isFinite(cfg.flushIntervalMs) ? cfg.flushIntervalMs : 500
  const sqlite = cfg && cfg.sqlite ? cfg.sqlite : {}
  const sqliteCfg = {
    mode: sqlite.mode === 'file' ? 'file' : 'memory',
    directory: typeof sqlite.directory === 'string' ? sqlite.directory : 'data/behavior',
    fileName: typeof sqlite.fileName === 'string' ? sqlite.fileName : 'anxin_etw_behavior.db'
  }
  return { enabled, flushIntervalMs, sqlite: sqliteCfg }
}

/**
 * - 函数: `createBehaviorAnalyzer`
 * - Function: `createBehaviorAnalyzer`
 * - 作用: 创建主进程侧行为分析聚合对象，统一封装 worker 生命周期、事件写入、查询 RPC、写入开关和优雅关闭能力，是主线程访问行为数据库的唯一门面。
 * - Purpose: Creates the main-process behavior-analysis aggregate that centralizes worker lifecycle management, event ingestion, query RPCs, write toggling, and graceful shutdown, acting as the single facade for behavior-database access from the main thread.
 * - 调用方: 主进程行为监控初始化链路通过导出接口创建实例，后续由返回对象上的 `start`、`ingest`、`listProcesses`、`listEvents`、`stop` 等方法驱动。
 * - Callers: The main-process behavior-monitor bootstrap creates the instance through the exported API, and later drives it through returned methods such as `start`, `ingest`, `listProcesses`, `listEvents`, and `stop`.
 * - 被调方: `getBehaviorCfg`、`start`、`ingest`、`setWriteEnabled`、`call`、`stop` 以及底层 `Worker` 消息协议。
 * - Callees: `getBehaviorCfg`, `start`, `ingest`, `setWriteEnabled`, `call`, `stop`, plus the underlying `Worker` message contract.
 * - 变量说明: `appConfig` 为应用配置源；`deps` 用于注入自定义 `Worker` 或 worker 路径；`pending` 保存尚未返回的请求 Promise；`writeEnabled` 控制是否继续向 worker 投递行为事件。
 * - Variables: `appConfig` is the application config source; `deps` injects a custom `Worker` or worker path; `pending` stores unresolved request promises; `writeEnabled` controls whether behavior events keep being posted to the worker.
 * - 接入方式: 可通过 `require('./behavior_analyzer').createBehaviorAnalyzer` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./behavior_analyzer').createBehaviorAnalyzer`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 创建 | behavior | analyzer | create | behavior | analyzer | call chain | 错误处理 | error handling | 复用
 */
function createBehaviorAnalyzer(appConfig = {}, deps = {}) {
  const cfg = getBehaviorCfg(appConfig)
  const WorkerCtor = deps && deps.Worker ? deps.Worker : Worker
  const behaviorWorkerPath = deps && typeof deps.workerPath === 'string' && deps.workerPath ? deps.workerPath : path.join(__dirname, 'workers/behavior_db_worker.js')
  let worker = null
  let dbPath = null
  let requestSeq = 1
  const pending = new Map()
  let writeEnabled = true

  /**
 * - 函数: `start`
 * - Function: `start`
 * - 作用: 启动行为数据库 worker，建立主线程与 worker 之间的消息回路，并在启动后同步发送 `init` 与 `write_enabled`，使后续写入和查询请求具备可用的执行端。
 * - Purpose: Starts the behavior-database worker, wires the message loop between the main thread and the worker, and sends `init` plus `write_enabled` so later writes and queries have an execution backend.
 * - 调用方: `createBehaviorAnalyzer` 返回对象上的 `start` 导出方法，由主进程在开启行为监控或首次需要行为落库时调用。
 * - Callers: Exposed as the returned `start` method from `createBehaviorAnalyzer`, and invoked by the main process when behavior monitoring starts or behavior persistence is first needed.
 * - 被调方: `WorkerCtor`、worker `message/error/exit` 事件、`worker.postMessage`。
 * - Callees: `WorkerCtor`, the worker `message/error/exit` events, and `worker.postMessage`.
 * - 变量说明: `worker` 保存当前 worker 实例；`dbPath` 保存 worker 回传的数据库路径；`pending` 中的 `reqId/p` 用于把异步 RPC 响应重新关联回主线程 Promise。
 * - Variables: `worker` stores the current worker instance; `dbPath` stores the DB path returned by the worker; `reqId/p` inside `pending` reconnect async RPC responses back to main-thread promises.
 * - 接入方式: 通过 `createBehaviorAnalyzer(...).start()` 调用；必须先启动后再调用 `ingest`、`listProcesses`、`listEvents` 等依赖 worker 的接口。
 * - Integration: Call through `createBehaviorAnalyzer(...).start()`; it should run before invoking worker-dependent APIs such as `ingest`, `listProcesses`, or `listEvents`.
 * - 错误处理: 若配置禁用或 worker 已存在则幂等返回；worker 运行期报错或退出时，会清空 `pending` 并拒绝所有在途请求，避免主线程永久挂起。
 * - Error Handling: Returns idempotently when disabled or already started; if the worker errors or exits, it drains `pending` and rejects all in-flight requests so the main thread does not hang indefinitely.
 * - 关键词: 启动worker | start worker | 行为分析 | behavior analyzer | 消息回路 | message loop | 在途请求 | pending RPC | 数据库路径 | db path
 */
  function start() {
    if (!cfg.enabled) return
    if (worker) return
    worker = new WorkerCtor(behaviorWorkerPath)

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
    try { worker.postMessage({ type: 'write_enabled', enabled: writeEnabled }) } catch {}
  }

  /**
 * - 函数: `ingest`
 * - Function: `ingest`
 * - 作用: 将单条行为事件投递给落库 worker，作为主进程采集链路向行为存储层追加数据的最轻量入口。
 * - Purpose: Posts a single behavior event to the persistence worker and serves as the lightest-weight entry from the main-process collection pipeline into the behavior store.
 * - 调用方: 主进程行为事件采集链路通过返回对象上的 `ingest` 导出方法持续调用。
 * - Callers: Continuously invoked by the main-process behavior-event collection pipeline through the returned `ingest` method.
 * - 被调方: `postMessage`。
 * - Callees: `postMessage`.
 * - 变量说明: `event` 为待持久化的行为事件对象；`writeEnabled` 控制当前是否允许写入；`worker` 表示消息的实际执行端。
 * - Variables: `event` is the behavior event to persist; `writeEnabled` controls whether writes are currently allowed; `worker` is the actual execution endpoint.
 * - 接入方式: 通过 `createBehaviorAnalyzer(...).ingest(event)` 接入；适合在高频行为流中重复调用，不建议外部直接操作 worker 消息格式。
 * - Integration: Use `createBehaviorAnalyzer(...).ingest(event)`; it is intended for repeated high-frequency behavior streams, and external code should avoid touching the raw worker message format directly.
 * - 错误处理: worker 未启动或写入被关闭时直接忽略；发送消息异常会被局部吞掉，避免采集主链路因为单次投递失败而中断。
 * - Error Handling: Silently no-ops when the worker is not started or writes are disabled; message-send failures are locally swallowed so a single post failure does not break the collection pipeline.
 * - 关键词: 行为写入 | behavior ingest | 事件投递 | event dispatch | 高频采集 | high-frequency stream | 写入开关 | write toggle | worker投递 | worker post
 */
  function ingest(event) {
    if (!worker) return
    if (!writeEnabled) return
    try {
      worker.postMessage({ type: 'ingest', event })
    } catch {}
  }

  /**
 * - 函数: `setWriteEnabled`
 * - Function: `setWriteEnabled`
 * - 作用: 在主线程侧切换行为事件是否继续投递到持久化 worker，并把最新开关状态同步下发给 worker，保证采集入口和落库执行端保持一致。
 * - Purpose: Toggles whether behavior events should continue being posted to the persistence worker from the main thread and synchronizes the latest switch state down to the worker so the ingestion entry and persistence backend stay aligned.
 * - 调用方: `createBehaviorAnalyzer` 返回对象上的 `setWriteEnabled` 导出方法由主进程功能开关、隐私模式或调试控制链调用。
 * - Callers: Exposed as the returned `setWriteEnabled` method from `createBehaviorAnalyzer`, and invoked by main-process feature toggles, privacy-mode flows, or debugging controls.
 * - 被调方: `postMessage`。
 * - Callees: `postMessage`.
 * - 变量说明: `enabled` 为外部请求的写入开关；`writeEnabled` 为主线程内存态中的实际开关值；`worker` 为状态同步的目标执行端。
 * - Variables: `enabled` is the requested write toggle from callers; `writeEnabled` is the actual in-memory switch on the main thread; `worker` is the execution endpoint that receives the synchronized state.
 * - 接入方式: 通过 `createBehaviorAnalyzer(...).setWriteEnabled(enabled)` 接入；新的写入控制需求应优先复用本方法，而不是直接向 worker 发送裸消息。
 * - Integration: Use `createBehaviorAnalyzer(...).setWriteEnabled(enabled)`; new write-control needs should reuse this method instead of posting raw worker messages directly.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 写入开关同步 | write toggle sync | behavior worker gate | privacy mode control | ingestion enable flag | main thread state | worker message sync | runtime control
 */
  function setWriteEnabled(enabled) {
    writeEnabled = enabled !== false
    if (!worker) return
    try { worker.postMessage({ type: 'write_enabled', enabled: writeEnabled }) } catch {}
  }

  /**
 * - 函数: `call`
 * - Function: `call`
 * - 作用: 封装主线程到行为数据库 worker 的请求/响应 RPC，把查询类与控制类消息统一映射成 Promise 形式，供上层接口复用。
 * - Purpose: Wraps request/response RPCs from the main thread to the behavior-database worker and normalizes query/control messages into Promise-based calls for upper-layer reuse.
 * - 调用方: 返回对象中的 `listProcesses`、`listEvents`、`getDbPath`、`clearAll` 等查询或控制接口通过本函数复用同一套 RPC 通道。
 * - Callers: Reused by returned query/control methods such as `listProcesses`, `listEvents`, `getDbPath`, and `clearAll` through a shared RPC channel.
 * - 被调方: `postMessage`、`Promise.resolve`。
 * - Callees: `postMessage`, `Promise.resolve`.
 * - 变量说明: `type` 表示目标 worker 指令；`query` 表示请求参数；`requestId` 用于把 worker 回包与 `pending` 中的 Promise 正确关联。
 * - Variables: `type` is the target worker command; `query` is the request payload; `requestId` reconnects the worker response with the matching Promise inside `pending`.
 * - 接入方式: 仅作为 `createBehaviorAnalyzer` 内部基础设施使用；新增查询接口时应基于本函数扩展，而不是重新实现一套 requestId 管理逻辑。
 * - Integration: Use it only as internal infrastructure inside `createBehaviorAnalyzer`; new query APIs should extend this helper instead of re-implementing request-id tracking.
 * - 错误处理: worker 未启动时返回空结果或当前 `dbPath` 的降级值；消息发送失败时会从 `pending` 中回滚请求并显式 `reject` 给调用方。
 * - Error Handling: Falls back to empty results or the cached `dbPath` when the worker is absent; if posting fails, it rolls the request back out of `pending` and explicitly rejects the caller.
 * - 关键词: RPC调用 | RPC call | 请求响应 | request response | requestId | pending map | 查询代理 | query bridge | worker通信 | worker communication
 */
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

  /**
 * - 函数: `stop`
 * - Function: `stop`
 * - 作用: 请求行为数据库 worker 进行关闭和最终刷盘，并在主线程侧释放 worker 引用，使分析器实例回到可再次启动的干净状态。
 * - Purpose: Requests the behavior-database worker to shut down and flush final state, then releases the worker reference on the main thread so the analyzer returns to a clean restartable state.
 * - 调用方: 主进程退出、功能关闭或重建分析器实例前，通过返回对象上的 `stop` 导出方法调用。
 * - Callers: Invoked through the returned `stop` method before process shutdown, feature disablement, or analyzer recreation.
 * - 被调方: `postMessage`。
 * - Callees: `postMessage`.
 * - 变量说明: `w` 保存待关闭的旧 worker 引用；`requestId` 用于等待 worker 返回 `closed` 响应；`pending` 会在关闭过程中承接这次收尾请求。
 * - Variables: `w` stores the worker reference being shut down; `requestId` waits for the worker’s `closed` response; `pending` temporarily carries this final shutdown request.
 * - 接入方式: 通过 `createBehaviorAnalyzer(...).stop()` 接入；建议在应用退出或切换存储模式前显式等待本函数完成。
 * - Integration: Call via `createBehaviorAnalyzer(...).stop()`; callers should explicitly await it before app shutdown or storage-mode switches.
 * - 错误处理: 若 worker 不存在则直接返回；关闭消息发送失败时会立即清理挂起请求并完成当前 Promise，避免关闭流程卡死。
 * - Error Handling: Returns immediately when no worker exists; if the shutdown message cannot be posted, it clears the pending request and resolves promptly so shutdown does not stall.
 * - 关键词: 优雅关闭 | graceful shutdown | 最终刷盘 | final flush | worker释放 | worker release | close RPC | pending cleanup | restartable state
 */
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
    setWriteEnabled,
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
