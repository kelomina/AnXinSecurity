const { parentPort } = require('worker_threads')
const { createProcessBehaviorStore } = require('../process_behavior_store')

let store = null
let flushTimer = null
let flushIntervalMs = 500
let writeEnabled = true

/**
 * - 函数: `postMessage`
 * - Function: `postMessage`
 * - 作用: 向主线程回传行为数据库 worker 的就绪、查询结果、关闭完成或错误消息，是本 worker 唯一的对外消息出口。
 * - Purpose: Sends ready, query-result, close-complete, or error messages from the behavior-database worker back to the main thread and serves as the worker’s single outbound message gate.
 * - 调用方: `init`、`handleListProcesses`、`handleListEvents`、`handleGetDbPath`、`handleClearAll`、`close` 以及消息分发中的异常处理。
 * - Callers: Called by `init`, `handleListProcesses`, `handleListEvents`, `handleGetDbPath`, `handleClearAll`, `close`, and the error paths in message dispatch.
 * - 被调方: `parentPort.postMessage`。
 * - Callees: `parentPort.postMessage`.
 * - 变量说明: `msg` 为发往主线程的标准消息对象，通常包含 `type`、`requestId`、`data`、`dbPath` 或 `message`。
 * - Variables: `msg` is the normalized outbound message object, usually carrying `type`, `requestId`, `data`, `dbPath`, or `message`.
 * - 接入方式: 仅在 `behavior_db_worker` 内部使用；新增 worker 回包类型时应优先通过本函数统一发送。
 * - Integration: Use only inside `behavior_db_worker`; new worker reply types should be sent through this helper for consistency.
 * - 错误处理: `parentPort` 缺失时直接返回；本函数本身不吞掉 `postMessage` 异常，因此调用方应确保回包结构正确。
 * - Error Handling: Returns immediately when `parentPort` is missing; this helper does not swallow `postMessage` failures, so callers should keep reply payloads valid.
 * - 关键词: 行为库回包 | behavior DB reply | ready消息 | ready reply | 查询结果 | query result | close通知 | close notification | parentPort | worker bridge
 */
function postMessage(msg) {
  if (!parentPort) return
  parentPort.postMessage(msg)
}

/**
 * - 函数: `clearFlushTimer`
 * - Function: `clearFlushTimer`
 * - 作用: 停掉当前自动刷盘定时器并清空 worker 内部计时器引用，避免重复创建周期任务或在关闭阶段继续触发落盘。
 * - Purpose: Stops the current auto-flush timer and clears the worker’s timer reference so duplicate periodic jobs are not created and shutdown does not continue triggering flushes.
 * - 调用方: `resetFlushTimer` 在重建定时器前调用；`close` 在 worker 退出前调用。
 * - Callers: Called by `resetFlushTimer` before rebuilding the timer and by `close` before the worker exits.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；`flushTimer` 为当前自动刷盘 `setInterval` 句柄。
 * - Variables: No explicit parameters; `flushTimer` is the current auto-flush `setInterval` handle.
 * - 接入方式: 仅在 `behavior_db_worker` 内部作为计时器生命周期 helper 使用；新的周期任务不要复用它去管理无关定时器。
 * - Integration: Use it only inside `behavior_db_worker` as the timer-lifecycle helper; unrelated periodic jobs should not be managed through it.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 自动刷盘定时器清理 | auto flush timer cleanup | clearInterval helper | timer lifecycle | shutdown prep | duplicate timer guard | worker timer state | flush scheduler stop
 */
function clearFlushTimer() {
  if (!flushTimer) return
  clearInterval(flushTimer)
  flushTimer = null
}

/**
 * - 函数: `resetFlushTimer`
 * - Function: `resetFlushTimer`
 * - 作用: 按当前 `store`、`writeEnabled` 和 `flushIntervalMs` 状态重建自动刷盘调度器，让行为日志在启用写入时按固定周期落盘。
 * - Purpose: Rebuilds the auto-flush scheduler from the current `store`, `writeEnabled`, and `flushIntervalMs` state so behavior logs are flushed on a fixed cadence whenever writes are enabled.
 * - 调用方: `init` 在 store 就绪后调用；`setWriteEnabled` 在主线程切换写入开关后调用。
 * - Callers: Called by `init` after the store becomes ready and by `setWriteEnabled` after the main thread toggles write enablement.
 * - 被调方: `clearFlushTimer`、`exportToFileIfNeeded`。
 * - Callees: `clearFlushTimer`, `exportToFileIfNeeded`.
 * - 变量说明: 无显式入参；`flushIntervalMs` 为周期刷盘间隔；`store` 为真正执行 `exportToFileIfNeeded()` 的持久化实例；`writeEnabled` 决定是否应当保留定时器。
 * - Variables: No explicit parameters; `flushIntervalMs` is the periodic flush interval; `store` is the persistence instance that executes `exportToFileIfNeeded()`; `writeEnabled` decides whether the timer should exist.
 * - 接入方式: 仅作为 worker 内部自动刷盘调度入口使用；定时刷盘策略变更应优先集中在这里。
 * - Integration: Use it only as the internal auto-flush scheduling entry of the worker; changes to periodic flush policy should be centralized here.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 自动刷盘调度重建 | auto flush scheduler rebuild | setInterval flush | writeEnabled gate | periodic persistence | exportToFileIfNeeded loop | timer refresh | worker scheduler
 */
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

/**
 * - 函数: `init`
 * - Function: `init`
 * - 作用: 初始化行为数据库存储实例，应用刷盘间隔配置并向主线程回传数据库路径，是 `behavior_db_worker` 的启动入口。
 * - Purpose: Initializes the behavior-store instance, applies the flush interval configuration, and reports the database path back to the main thread, serving as the startup entry for `behavior_db_worker`.
 * - 调用方: `parentPort.on('message')` 在收到 `type === 'init'` 的消息时调用。
 * - Callers: Called by `parentPort.on('message')` when it receives a message with `type === 'init'`.
 * - 被调方: `createProcessBehaviorStore`、`resetFlushTimer`、`postMessage`、`getDbPath`、`Number.isFinite`。
 * - Callees: `createProcessBehaviorStore`, `resetFlushTimer`, `postMessage`, `getDbPath`, `Number.isFinite`.
 * - 变量说明: `payload` 为主线程传入的初始化消息；`cfg` 为行为分析配置；`sqliteCfg` 为底层存储配置；`store` 为创建后的持久化实例。
 * - Variables: `payload` is the init message from the main thread; `cfg` is the behavior-analysis config; `sqliteCfg` is the storage config; `store` is the created persistence instance.
 * - 接入方式: 通过主线程向 worker 发送 `init` 消息接入；其他消息处理前通常应先完成本函数，以确保 `store` 已就绪。
 * - Integration: Integrate by sending an `init` message from the main thread; other message handlers usually expect this function to complete first so `store` is ready.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: worker初始化 | worker init | 行为数据库 | behavior store | ready回包 | ready reply | flush interval | SQLite配置 | store bootstrap
 */
async function init(payload) {
  const cfg = payload && payload.config ? payload.config : {}
  const sqliteCfg = cfg && cfg.sqlite ? cfg.sqlite : {}
  store = await createProcessBehaviorStore(sqliteCfg)

  flushIntervalMs = Number.isFinite(cfg.flushIntervalMs) ? cfg.flushIntervalMs : 500
  resetFlushTimer()

  postMessage({ type: 'ready', dbPath: store.getDbPath() })
}

/**
 * - 函数: `ingest`
 * - Function: `ingest`
 * - 作用: 接收主线程投递的单条行为事件，并在写入开关开启时追加到 `ProcessBehaviorStore`，是行为事件落库的高频入口。
 * - Purpose: Accepts a single behavior event posted from the main thread and appends it into `ProcessBehaviorStore` when writes are enabled, serving as the high-frequency ingress for behavior persistence.
 * - 调用方: `parentPort.on('message')` 在收到 `type === 'ingest'` 的消息时调用。
 * - Callers: Called by `parentPort.on('message')` when it receives a message with `type === 'ingest'`.
 * - 被调方: `store.ingest`。
 * - Callees: `store.ingest`.
 * - 变量说明: `payload` 为主线程投递的行为消息；`payload.event` 为真正落库的行为事件；`writeEnabled` 控制当前是否允许写入。
 * - Variables: `payload` is the behavior message from the main thread; `payload.event` is the actual event being persisted; `writeEnabled` controls whether writes are currently allowed.
 * - 接入方式: 通过主线程发送 `ingest` 消息接入；高频调用场景应复用本函数，而不是绕过 worker 直接访问存储实例。
 * - Integration: Integrate by sending an `ingest` message from the main thread; high-frequency flows should reuse this function instead of touching the store directly.
 * - 错误处理: `store` 未就绪或写入被禁用时直接忽略；写入异常被局部吞掉，防止单条坏事件拖垮整条行为采集链路。
 * - Error Handling: Silently no-ops when the store is not ready or writes are disabled; ingestion failures are swallowed locally so a single bad event does not break the whole collection stream.
 * - 关键词: 行为入库 | behavior ingest | 高频写入 | high-frequency write | ProcessBehaviorStore | writeEnabled | worker消息 | worker message | event append
 */
function ingest(payload) {
  if (!store) return
  if (!writeEnabled) return
  try {
    store.ingest(payload && payload.event)
  } catch {}
}

/**
 * - 函数: `setWriteEnabled`
 * - Function: `setWriteEnabled`
 * - 作用: 接收主线程下发的行为写入开关，并立即刷新自动刷盘调度器，使 worker 的采集落盘节奏与主线程控制状态保持一致。
 * - Purpose: Accepts the behavior-write toggle pushed down from the main thread and immediately refreshes the auto-flush scheduler so the worker’s persistence cadence stays aligned with main-thread control state.
 * - 调用方: `parentPort.on('message')` 在收到 `type === 'write_enabled'` 的消息时调用。
 * - Callers: Called by `parentPort.on('message')` when a message with `type === 'write_enabled'` arrives.
 * - 被调方: `resetFlushTimer`。
 * - Callees: `resetFlushTimer`.
 * - 变量说明: `payload` 为主线程消息体；`payload.enabled` 为请求中的目标写入开关；`writeEnabled` 为 worker 当前保存的开关状态。
 * - Variables: `payload` is the message body from the main thread; `payload.enabled` is the requested write toggle; `writeEnabled` is the worker’s current stored state.
 * - 接入方式: 仅通过主线程发送 `write_enabled` 消息接入；外部不要直接改 worker 进程中的 `writeEnabled` 闭包变量。
 * - Integration: Integrate only by sending a `write_enabled` message from the main thread; external code should not mutate the worker’s `writeEnabled` closure state directly.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 写入开关下发 | write toggle dispatch | worker write gate | main-thread sync | flush timer refresh | runtime persistence control | write_enabled message | capture switch
 */
function setWriteEnabled(payload) {
  writeEnabled = !!(payload && payload.enabled)
  resetFlushTimer()
}

/**
 * - 函数: `handleListProcesses`
 * - Function: `handleListProcesses`
 * - 作用: 响应主线程的进程列表查询请求，根据是否传入 `limit === Infinity` 选择分页或全量读取，并把结果通过统一 RPC 回包返回。
 * - Purpose: Handles process-list queries from the main thread, choosing paged vs full reads based on `limit === Infinity`, and returns the result through the shared RPC reply channel.
 * - 调用方: `parentPort.on('message')` 在收到 `type === 'listProcesses'` 的消息时调用。
 * - Callers: Called by `parentPort.on('message')` when a message with `type === 'listProcesses'` arrives.
 * - 被调方: `postMessage`、`listAllProcesses`、`listProcesses`。
 * - Callees: `postMessage`, `listAllProcesses`, `listProcesses`.
 * - 变量说明: `payload` 为查询消息；`q` 为进程查询条件；`data` 为最终回传给主线程的进程列表结果。
 * - Variables: `payload` is the query message; `q` is the process-query filter; `data` is the process list returned to the main thread.
 * - 接入方式: 在当前模块内部直接调用 `handleListProcesses(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `handleListProcesses(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 进程查询 | process listing | listProcesses | 分页读取 | paged query | 全量读取 | full read | RPC结果 | requestId reply | behavior DB
 */
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

/**
 * - 函数: `handleListEvents`
 * - Function: `handleListEvents`
 * - 作用: 响应主线程的事件列表查询请求，可按 PID、分页条件或全量模式读取行为事件，并把查询结果回传给 UI/主进程调用方。
 * - Purpose: Serves event-list queries from the main thread, supporting PID filters, paged access, or full-mode reads, and returns the resulting events to the UI/main-process caller.
 * - 调用方: `parentPort.on('message')` 在收到 `type === 'listEvents'` 的消息时调用。
 * - Callers: Called by `parentPort.on('message')` when a message with `type === 'listEvents'` arrives.
 * - 被调方: `postMessage`、`listAllEvents`、`listEvents`。
 * - Callees: `postMessage`, `listAllEvents`, `listEvents`.
 * - 变量说明: `payload` 为查询消息；`q` 为事件过滤与分页参数；`data` 为最终回传的行为事件列表。
 * - Variables: `payload` is the query message; `q` holds event filters and paging params; `data` is the final behavior-event list returned to the caller.
 * - 接入方式: 在当前模块内部直接调用 `handleListEvents(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `handleListEvents(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 事件查询 | event listing | listEvents | PID过滤 | pid filter | 分页查询 | paged query | 全量事件 | full event scan | RPC reply
 */
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

/**
 * - 函数: `handleGetDbPath`
 * - Function: `handleGetDbPath`
 * - 作用: 向主线程回传当前行为数据库文件路径，供诊断、展示或导出流程确认实际使用的存储位置。
 * - Purpose: Returns the current behavior-database file path to the main thread so diagnostics, UI display, or export flows can know the active storage location.
 * - 调用方: `parentPort.on('message')` 在收到 `type === 'getDbPath'` 的消息时调用。
 * - Callers: Called by `parentPort.on('message')` when a message with `type === 'getDbPath'` arrives.
 * - 被调方: `postMessage`、`getDbPath`。
 * - Callees: `postMessage`, `getDbPath`.
 * - 变量说明: `payload` 为主线程查询消息；`payload.requestId` 用于把数据库路径结果对应回原始 RPC 请求。
 * - Variables: `payload` is the query message from the main thread; `payload.requestId` maps the DB path result back to the original RPC request.
 * - 接入方式: 在当前模块内部直接调用 `handleGetDbPath(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `handleGetDbPath(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 数据库路径 | database path | getDbPath | requestId | 诊断支持 | diagnostics | 存储位置 | storage location | RPC query
 */
function handleGetDbPath(payload) {
  postMessage({ type: 'result', requestId: payload.requestId, data: store ? store.getDbPath() : null })
}

/**
 * - 函数: `handleClearAll`
 * - Function: `handleClearAll`
 * - 作用: 清空行为数据库中的现有进程与事件数据，并把成功/失败结果通过 RPC 回包返回给主线程。
 * - Purpose: Clears existing process and event data from the behavior store and returns the success/failure result to the main thread through RPC.
 * - 调用方: `parentPort.on('message')` 在收到 `type === 'clearAll'` 的消息时调用。
 * - Callers: Called by `parentPort.on('message')` when a message with `type === 'clearAll'` arrives.
 * - 被调方: `postMessage`、`clearAll`。
 * - Callees: `postMessage`, `clearAll`.
 * - 变量说明: `payload` 为清空请求消息；`payload.requestId` 用于把布尔结果回传给对应调用方。
 * - Variables: `payload` is the clear request message; `payload.requestId` routes the boolean result back to the matching caller.
 * - 接入方式: 在当前模块内部直接调用 `handleClearAll(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `handleClearAll(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 清空行为库 | clear behavior DB | clearAll | 数据重置 | data reset | 请求回包 | request reply | 布尔结果 | boolean result | worker RPC
 */
function handleClearAll(payload) {
  if (!store) return postMessage({ type: 'result', requestId: payload.requestId, data: false })
  try {
    store.clearAll()
    postMessage({ type: 'result', requestId: payload.requestId, data: true })
  } catch {
    postMessage({ type: 'result', requestId: payload.requestId, data: false })
  }
}

/**
 * - 函数: `close`
 * - Function: `close`
 * - 作用: 停止自动刷盘定时器、关闭底层存储实例并向主线程回传 `closed`，随后主动结束 worker 进程，是行为数据库 worker 的优雅退出入口。
 * - Purpose: Stops the auto-flush timer, closes the underlying store, sends `closed` back to the main thread, and then exits the worker process, serving as the graceful shutdown entry of the behavior-db worker.
 * - 调用方: `parentPort.on('message')` 在收到 `type === 'close'` 的消息时调用。
 * - Callers: Called by `parentPort.on('message')` when a message with `type === 'close'` arrives.
 * - 被调方: `clearFlushTimer`、`postMessage`。
 * - Callees: `clearFlushTimer`, `postMessage`.
 * - 变量说明: `payload` 为关闭请求消息；`payload.requestId` 用于通知主线程哪一次关闭请求已经完成。
 * - Variables: `payload` is the shutdown request message; `payload.requestId` tells the main thread which close request has completed.
 * - 接入方式: 在当前模块内部直接调用 `close(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `close(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: worker关闭 | worker shutdown | graceful close | 自动刷盘停止 | flush timer stop | closed回包 | closed reply | process exit | store cleanup
 */
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
