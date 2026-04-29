const fs = require('fs')
const path = require('path')

/**
 * - 函数: `normalizeLogPath`
 * - Function: `normalizeLogPath`
 * - 作用: 把行为存储配置中的目录参数解析成真正的行为日志根目录，并强制补出 `processes/` 子目录，作为所有 PID 日志与 `process_info.json` 的统一落盘位置。
 * - Purpose: Resolves the directory setting from behavior-store config into the real behavior-log root and always appends the `processes/` subdirectory so PID logs and `process_info.json` share one persistence location.
 * - 调用方: `createProcessBehaviorStore` 在实例化 `ProcessBehaviorStore` 前调用。
 * - Callers: Called by `createProcessBehaviorStore` before the `ProcessBehaviorStore` instance is created.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `cfg` 为行为存储配置；`dir` 为用户配置的目录文本；`resolvedDir` 为展开环境变量后的结果；`logDir` 为最终行为日志目录。
 * - Variables: `cfg` is the behavior-store config; `dir` is the configured directory text; `resolvedDir` is the env-expanded result; `logDir` is the final behavior-log directory.
 * - 接入方式: 应作为行为日志目录解析的统一入口；新增存储模式不要自行重复拼接 `data/behavior/processes` 路径。
 * - Integration: It should remain the single resolver for behavior-log directories; new storage modes should not rebuild the `data/behavior/processes` path independently.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 行为日志目录 | behavior log directory | processes subdir | env path expansion | storage root | persistence path | process_info location | log path resolver
 */
function normalizeLogPath(cfg = {}) {
  const dir = typeof cfg.directory === 'string' && cfg.directory.trim() ? cfg.directory.trim() : 'data/behavior'
  const resolvedDir = String(dir).replace(/%([^%]+)%/g, (_m, n) => process.env[n] || '')
  
  // If the path was absolute or relative without env vars, resolvedDir === dir.
  // We should use resolvedDir unless it's empty.
  const baseDir = resolvedDir ? resolvedDir : path.join(__dirname, '../..', 'data', 'behavior')
  
  const logDir = path.isAbsolute(baseDir) ? path.join(baseDir, 'processes') : path.join(path.join(__dirname, '../..'), baseDir, 'processes')
  if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true })
  return { logDir }
}

/**
 * - 函数: `nowIso`
 * - Function: `nowIso`
 * - 作用: 为缺失时间戳的行为事件补出统一 ISO 时间，确保实时写入与历史查询都能落到同一种时间格式。
 * - Purpose: Supplies a shared ISO timestamp for behavior events that arrive without one, ensuring live writes and historical queries use the same time format.
 * - 调用方: `normalizeEventToRow` 在原始事件缺少可用时间字段时调用。
 * - Callers: Called by `normalizeEventToRow` when the raw event does not provide a usable timestamp.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；返回值为当前时刻的 ISO 8601 时间字符串。
 * - Variables: No explicit parameters; the return value is the current ISO 8601 timestamp string.
 * - 接入方式: 仅作为事件归一化链的时间回退 helper 使用；不要在外部用不同格式替代它。
 * - Integration: Use it only as the timestamp fallback helper in the event-normalization chain; external callers should not replace it with another time format.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: ISO时间回退 | ISO timestamp fallback | event timestamp | normalizeEventToRow helper | current UTC time | consistent time format | behavior log time | time default
 */
function nowIso() {
  return new Date().toISOString()
}

/**
 * - 函数: `safeJsonParse`
 * - Function: `safeJsonParse`
 * - 作用: 以“解析失败返回 `null`”的方式安全反序列化日志行，避免历史日志中的坏行拖垮事件列表查询。
 * - Purpose: Safely deserializes log lines with a “return `null` on parse failure” policy so malformed historical lines do not break event-list queries.
 * - 调用方: `listEvents` 在把日志行恢复成事件对象时调用。
 * - Callers: Called by `listEvents` when log lines are reconstructed into event objects.
 * - 被调方: `JSON.parse`。
 * - Callees: `JSON.parse`.
 * - 变量说明: `s` 为待解析的单行 JSON 文本。
 * - Variables: `s` is the single-line JSON text being parsed.
 * - 接入方式: 应作为行为日志行解析的统一安全入口；新的历史日志读取链优先复用它。
 * - Integration: It should be the shared safe entry for parsing behavior-log lines; new historical-log readers should reuse it first.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 安全JSON解析 | safe JSON parse | malformed log line | null fallback | event row restore | history query helper | parse guard | resilient deserialization
 */
function safeJsonParse(s) {
  try {
    return JSON.parse(s)
  } catch {
    return null
  }
}

/**
 * - 函数: `normalizeEventToRow`
 * - Function: `normalizeEventToRow`
 * - 作用: 将来自 ETW、行为分析器或历史回放的原始事件统一折叠为日志行结构，补齐时间戳、提供方、操作名以及文件/注册表/网络目标字段，作为落盘与查询的公共数据契约。
 * - Purpose: Collapses raw events from ETW, the behavior analyzer, or replayed history into a unified log-row shape, filling timestamps, provider, operation name, and file/registry/network target fields as the shared contract for persistence and queries.
 * - 调用方: `ingest` 在写入前调用；`listEvents` 在从日志行反序列化对象后也会再次复用，确保历史查询与实时写入走同一套字段归一化规则。
 * - Callers: Called by `ingest` before persistence, and reused by `listEvents` after deserializing log lines so historical queries and live writes share the same normalization rules.
 * - 被调方: `nowIso`、`Number.isFinite`、`Object.assign`、`JSON.stringify`。
 * - Callees: `nowIso`, `Number.isFinite`, `Object.assign`, `JSON.stringify`.
 * - 变量说明: `event` 为原始行为事件；`ev` 为保证可读性的对象化副本；`provider`/`op` 标识事件来源与动作；`data` 为 provider 自带载荷；`rawJson` 为最终保留到日志中的原始上下文快照。
 * - Variables: `event` is the raw behavior event; `ev` is the object-safe copy; `provider` and `op` identify the event source and action; `data` is the provider payload; `rawJson` is the raw context snapshot preserved in the log row.
 * - 接入方式: 仅作为 `ProcessBehaviorStore` 的内部标准化入口使用；新增事件来源时应优先扩展本函数，而不是在写入点各自拼装字段。
 * - Integration: Use it as the internal normalization entry of `ProcessBehaviorStore`; new event providers should extend this helper instead of assembling fields ad hoc at each write site.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 事件归一化 | event normalization | 日志行模型 | log row model | ETW事件 | ETW event | provider映射 | provider mapping | raw_json | persistence contract
 */
function normalizeEventToRow(event) {
  const ev = event && typeof event === 'object' ? event : {}
  const provider = typeof ev.provider === 'string' ? ev.provider : (typeof ev._provider === 'string' ? ev._provider : 'Unknown')
  const ts = typeof ev.ts === 'string' && ev.ts ? ev.ts : (typeof ev.timestamp === 'string' && ev.timestamp ? ev.timestamp : (typeof ev._ts === 'string' && ev._ts ? ev._ts : nowIso()))
  const tid = Number.isFinite(ev.tid) ? ev.tid : null
  const data = ev.data && typeof ev.data === 'object' ? ev.data : {}

  let op = typeof ev.op === 'string' ? ev.op : (typeof data.type === 'string' ? data.type : (typeof ev._op === 'string' ? ev._op : null))
  let actorPid = Number.isFinite(ev.actor_pid) ? ev.actor_pid : (Number.isFinite(ev.pid) ? ev.pid : null)
  let subjectPid = Number.isFinite(ev.subject_pid) ? ev.subject_pid : null

  let filePath = typeof ev.file_path === 'string' ? ev.file_path : null
  let regKey = typeof ev.reg_key === 'string' ? ev.reg_key : null
  let regValue = typeof ev.reg_value === 'string' ? ev.reg_value : null
  let rawHex = typeof ev.raw_hex === 'string' ? ev.raw_hex : null

  if (provider === 'Process') {
    subjectPid = Number.isFinite(subjectPid) ? subjectPid : (Number.isFinite(data.processId) ? data.processId : null)
    const ppid = Number.isFinite(data.parentProcessId) ? data.parentProcessId : null
    if (op === 'Start') {
      actorPid = Number.isFinite(ppid) ? ppid : (subjectPid != null ? subjectPid : actorPid)
    } else {
      actorPid = subjectPid != null ? subjectPid : actorPid
    }
  } else if (provider === 'File') {
    filePath = typeof filePath === 'string' && filePath ? filePath : (typeof data.fileName === 'string' ? data.fileName : null)
  } else if (provider === 'Registry') {
    regKey = typeof regKey === 'string' && regKey ? regKey : (typeof data.keyPath === 'string' ? data.keyPath : null)
    regValue = typeof regValue === 'string' && regValue ? regValue : (typeof data.valueName === 'string' ? data.valueName : null)
    rawHex = typeof rawHex === 'string' && rawHex ? rawHex : (typeof data.rawHex === 'string' ? data.rawHex : null)
  } else if (provider === 'Network') {
    const target = typeof data.target === 'string' ? data.target : null
    const remoteIp = typeof data.remoteIp === 'string' ? data.remoteIp : null
    const remotePort = Number.isFinite(data.remotePort) ? data.remotePort : null
    const protocol = typeof data.protocol === 'string' ? data.protocol : null
    filePath = typeof filePath === 'string' && filePath ? filePath : (target || (remoteIp && remotePort != null ? `${protocol || ''} ${remoteIp}:${remotePort}`.trim() : null))
  }

  const rawObj = Object.assign({}, ev)
  delete rawObj._ts
  delete rawObj._provider
  delete rawObj._op
  if (!rawObj.timestamp) rawObj.timestamp = ts
  if (!rawObj.provider) rawObj.provider = provider
  const rawJson = typeof ev.raw_json === 'string' && ev.raw_json ? ev.raw_json : JSON.stringify(rawObj)

  return {
    ts,
    provider,
    op,
    actor_pid: Number.isFinite(actorPid) ? actorPid : null,
    subject_pid: Number.isFinite(subjectPid) ? subjectPid : null,
    tid,
    file_path: typeof filePath === 'string' ? filePath : null,
    reg_key: typeof regKey === 'string' ? regKey : null,
    reg_value: typeof regValue === 'string' ? regValue : null,
    raw_json: rawJson,
    raw_hex: typeof rawHex === 'string' ? rawHex : null
  }
}

/**
 * - 函数: `getPidKeyFromRow`
 * - Function: `getPidKeyFromRow`
 * - 作用: 从归一化后的事件行中选出应该写入哪个 PID 日志桶，优先落到 `subject_pid`，其次回退 `actor_pid`，都缺失时归入 `global.log`。
 * - Purpose: Selects the PID bucket that should receive a normalized event row, preferring `subject_pid`, then falling back to `actor_pid`, and finally routing to `global.log` when neither exists.
 * - 调用方: `ingest` 在决定事件应写入哪个缓冲桶与 `.log` 文件前调用。
 * - Callers: Called by `ingest` before deciding which buffer bucket and `.log` file should receive the event.
 * - 被调方: `Number.isFinite`。
 * - Callees: `Number.isFinite`.
 * - 变量说明: `row` 为归一化后的行为日志行。
 * - Variables: `row` is the normalized behavior-log row.
 * - 接入方式: 仅作为按 PID 分桶写入的内部 helper 使用；新的分桶规则应优先集中在这里调整。
 * - Integration: Use it only as the internal helper for PID-based bucketing; new bucketing rules should be centralized here first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: PID分桶键 | PID bucket key | subject actor fallback | global log bucket | per-PID routing | ingest helper | log sharding | row bucket chooser
 */
function getPidKeyFromRow(row) {
  if (row && Number.isFinite(row.subject_pid)) return row.subject_pid
  if (row && Number.isFinite(row.actor_pid)) return row.actor_pid
  return 'global'
}

/**
 * - 函数: `readTailLines`
 * - Function: `readTailLines`
 * - 作用: 从大日志文件尾部反向读取最近若干行，避免事件详情查询为拿最新记录而把整个 PID 日志一次性读入内存。
 * - Purpose: Reads the last N lines of a large log file from the tail backward so event-detail queries can fetch recent records without loading the entire PID log into memory.
 * - 调用方: `listEvents` 在读取已刷盘的最近事件时调用。
 * - Callers: Called by `listEvents` when it needs recently persisted events.
 * - 被调方: `Number.isFinite`、`Math.max`、`Math.floor`、`fs.statSync`、`fs.openSync`。
 * - Callees: `Number.isFinite`, `Math.max`, `Math.floor`, `fs.statSync`, `fs.openSync`.
 * - 变量说明: `filePath` 为目标 PID 日志文件；`wantLines` 为需要的尾部行数；`maxBytes` 为最大回溯读取字节数；`fd` 为文件描述符。
 * - Variables: `filePath` is the target PID log file; `wantLines` is the requested tail-line count; `maxBytes` is the maximum number of bytes to read backward; `fd` is the file descriptor.
 * - 接入方式: 应作为按尾部分页读取行为日志的统一 helper 使用；不要在别处重新实现同类反向读取逻辑。
 * - Integration: It should be the shared helper for tail-based paging of behavior logs; other code paths should not reimplement the same reverse-read logic.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 尾部日志读取 | tail log read | reverse file scan | recent event query | large file paging | PID log tail | bounded bytes | history tail helper
 */
function readTailLines(filePath, wantLines, maxBytes = 8 * 1024 * 1024) {
  const n = Number.isFinite(wantLines) ? Math.max(0, Math.floor(wantLines)) : 0
  if (n <= 0) return []

  let fd = null
  try {
    const st = fs.statSync(filePath)
    if (!st || !(st.size > 0)) return []

    fd = fs.openSync(filePath, 'r')
    const chunkSize = 64 * 1024
    let pos = st.size
    let readBytes = 0
    let text = ''

    while (pos > 0 && readBytes < maxBytes) {
      const size = Math.min(chunkSize, pos)
      pos -= size
      const buf = Buffer.allocUnsafe(size)
      const got = fs.readSync(fd, buf, 0, size, pos)
      if (!(got > 0)) break
      readBytes += got
      text = buf.toString('utf8', 0, got) + text
      const lineCount = (text.match(/\n/g) || []).length
      if (lineCount >= n + 1) break
    }

    const lines = text.split('\n').map(s => s.trim()).filter(Boolean)
    if (lines.length <= n) return lines
    return lines.slice(lines.length - n)
  } catch {
    return []
  } finally {
    if (fd != null) {
      try { fs.closeSync(fd) } catch {}
    }
  }
}

class ProcessBehaviorStore {
  /**
   * - 函数: `constructor`
   * - Function: `constructor`
   * - 作用: 初始化 ProcessBehaviorStore 的实例状态，并准备后续方法依赖的数据。
   * - Purpose: Initializes the ProcessBehaviorStore instance state and prepares data required by later methods.
   * - 调用方: 当前类实例、静态入口或外部类使用方。
   * - Callers: Current class instances, static entry points, or external class consumers.
   * - 被调方: 无明显命名函数调用，主要执行内联逻辑或基础语句。
   * - Callees: No obvious named function calls; mainly performs inline logic or basic statements.
   * - 变量说明: 无显式入参；局部变量用于保存当前函数的中间状态。
   * - Variables: No explicit parameters; local variables keep intermediate state for this function.
   * - 接入方式: 通过 `new ProcessBehaviorStore(...)` 创建实例后接入。
   * - Integration: Integrate by creating an instance with `new ProcessBehaviorStore(...)`.
   * - 错误处理: 主要依赖前置守卫与返回值控制流程，未在函数内部集中处理异常。
   * - Error Handling: Relies on guard clauses and return values for control flow and does not centralize exception handling inside the function.
   * - 关键词: ProcessBehaviorStore | class | 函数 | function | 模块 | module | 接入 | integration | 错误处理 | error-handling
   */
  constructor(options = {}) {
    const defaultBase = path.join(__dirname, '../..', 'data', 'behavior')
    this.logDir = options.logDir || path.join(defaultBase, 'processes')
    if (!fs.existsSync(this.logDir)) fs.mkdirSync(this.logDir, { recursive: true })

    this.buffer = new Map()
    this.totalBufferSize = 0
    this.flushThreshold = 100 * 1024 * 1024

    this.processInfoPath = path.join(this.logDir, 'process_info.json')
    this.processInfo = new Map()
    this.processInfoDirty = false
    this.loadProcessInfo()
  }

  /**
 * - 函数: `getDbPath`
 * - Function: `getDbPath`
 * - 作用: 返回当前行为日志目录路径，作为 worker 向主线程报告“行为数据库位置”的统一出口。
 * - Purpose: Returns the current behavior-log directory path as the shared exit through which the worker reports the “behavior database location” back to the main thread.
 * - 调用方: `behavior_db_worker` 初始化 `ready` 消息和 `handleGetDbPath` RPC 处理时都会调用。
 * - Callers: Called by `behavior_db_worker` both when composing the initial `ready` message and when handling the `getDbPath` RPC.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；返回值为实例当前使用的 `this.logDir`。
 * - Variables: No explicit parameters; the return value is the instance’s active `this.logDir`.
 * - 接入方式: 通过 `store.getDbPath()` 接入；外部若只需知道行为日志位置，应复用本方法而不是直接窥探实例字段。
 * - Integration: Use `store.getDbPath()` when callers only need the behavior-log location; external code should not inspect instance fields directly.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 行为库路径 | behavior DB path | logDir accessor | worker ready payload | getDbPath RPC | storage location | behavior log root | path exposure
 */
  getDbPath() {
    return this.logDir
  }

  /**
 * - 函数: `loadProcessInfo`
 * - Function: `loadProcessInfo`
 * - 作用: 加载处理info资源，并返回后续逻辑可以直接复用的数据或实例。
 * - Purpose: Loads the process info resource and returns data or instances that downstream logic can reuse.
 * - 调用方: `constructor` 在实例启动时调用，用磁盘上的 `process_info.json` 预热进程索引。
 * - Callers: Called by the `constructor` at startup to warm the process index from `process_info.json` on disk.
 * - 被调方: `fs.existsSync`、`fs.readFileSync`、`JSON.parse`。
 * - Callees: `fs.existsSync`, `fs.readFileSync`, `JSON.parse`.
 * - 变量说明: 无显式入参；`raw` 为磁盘上的原始 JSON 文本；`data` 为解析后的 PID -> 进程信息映射。
 * - Variables: No explicit parameters; `raw` is the raw JSON text from disk; `data` is the parsed PID-to-process-info mapping.
 * - 接入方式: 仅作为实例初始化阶段的预热步骤使用；若未来需要重载索引，优先复用本方法。
 * - Integration: Use it only as the warm-up step during instance initialization; if index reloads are needed later, reuse this method first.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 进程索引预热 | process index warmup | process_info.json load | startup restore | PID metadata cache | constructor bootstrap | disk to memory map | resilient load
 */
  loadProcessInfo() {
    try {
      if (fs.existsSync(this.processInfoPath)) {
        const raw = fs.readFileSync(this.processInfoPath, 'utf8')
        const data = JSON.parse(raw)
        if (data && typeof data === 'object') {
          for (const [pid, info] of Object.entries(data)) {
            this.processInfo.set(Number(pid), info)
          }
        }
      }
    } catch (e) {
      console.error('Failed to load process info:', e)
    }
  }

  /**
 * - 函数: `saveProcessInfo`
 * - Function: `saveProcessInfo`
 * - 作用: 将内存中的进程元数据索引批量持久化到 `process_info.json`，保证日志文件只保存事件流，而进程名与最近出现时间由独立索引维护。
 * - Purpose: Persists the in-memory process metadata index into `process_info.json`, keeping event streams in log files while process names and last-seen timestamps are maintained in a separate index.
 * - 调用方: `flush` 在正式刷写日志前调用；只有 `processInfoDirty` 为真时才会真正落盘。
 * - Callers: Called by `flush` before event logs are written, and it only persists when `processInfoDirty` is true.
 * - 被调方: `fs.writeFileSync`、`JSON.stringify`。
 * - Callees: `fs.writeFileSync`, `JSON.stringify`.
 * - 变量说明: 无显式入参；`obj` 为从 `this.processInfo` 转换出的可序列化对象快照，用于写入 JSON 文件。
 * - Variables: No explicit parameters; `obj` is the serializable snapshot converted from `this.processInfo` before writing JSON.
 * - 接入方式: 仅供 `ProcessBehaviorStore` 内部刷盘链路复用；外部若需要保证进程索引落盘，应调用 `flush()` 或 `close()`，而不是直接调用本方法。
 * - Integration: Reused only inside the `ProcessBehaviorStore` flush pipeline; external callers that need durable process metadata should invoke `flush()` or `close()` instead of calling this method directly.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 进程索引持久化 | process index persistence | process_info.json | dirty flag | 刷盘前置 | pre-flush save | metadata snapshot | JSON dump | resilient write
 */
  saveProcessInfo() {
    if (!this.processInfoDirty) return
    try {
      const obj = {}
      for (const [pid, info] of this.processInfo) {
        obj[pid] = info
      }
      fs.writeFileSync(this.processInfoPath, JSON.stringify(obj, null, 2))
      this.processInfoDirty = false
    } catch (e) {
      console.error('Failed to save process info:', e)
    }
  }

  /**
 * - 函数: `updateProcessInfo`
 * - Function: `updateProcessInfo`
 * - 作用: 根据进程启动事件刷新 PID 对应的镜像名与最近出现时间，并标记 `processInfoDirty`，让后续 `flush` 知道需要把进程索引同步到磁盘。
 * - Purpose: Refreshes the image name and last-seen time for a PID based on process-start events and marks `processInfoDirty` so the next `flush` knows the process index must be persisted.
 * - 调用方: `ingest` 在接收到 `Process/Start` 类事件且带有 `imageName` 时调用。
 * - Callers: Called by `ingest` when it receives `Process/Start`-style events carrying `imageName`.
 * - 被调方: `Date.now`。
 * - Callees: `Date.now`.
 * - 变量说明: `pid` 为目标进程号；`imageName` 为进程镜像名；`p` 为归一化后的数值 PID；`existing` 为旧的进程索引条目。
 * - Variables: `pid` is the target process id; `imageName` is the process image name; `p` is the normalized numeric PID; `existing` is the previous process-index entry.
 * - 接入方式: 仅作为进程索引维护 helper 使用；新增进程元数据写入规则应优先扩展本方法。
 * - Integration: Use it only as the process-index maintenance helper; new process-metadata write rules should extend this method first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 进程索引刷新 | process index refresh | imageName update | lastSeen update | dirty flag set | PID metadata maintenance | ingest helper | process start sync
 */
  updateProcessInfo(pid, imageName) {
    if (!pid || !imageName) return
    const p = Number(pid)
    if (!p) return

    const existing = this.processInfo.get(p)
    if (!existing || existing.name !== imageName) {
      this.processInfo.set(p, {
        name: imageName,
        lastSeen: Date.now()
      })
      this.processInfoDirty = true
      // Debounce save or save on next flush
    } else {
      // Just update timestamp occasionally?
      // For now, let's keep it simple.
    }
  }

  /**
 * - 函数: `ingest`
 * - Function: `ingest`
 * - 作用: 接收单条行为事件，补齐进程索引、归一化事件结构并按 PID 维度写入内存缓冲区，是行为数据进入 `ProcessBehaviorStore` 的高频入口。
 * - Purpose: Accepts a single behavior event, updates the process index, normalizes the event shape, and appends it into the per-PID in-memory buffer, serving as the high-frequency ingress into `ProcessBehaviorStore`.
 * - 调用方: `behavior_db_worker` 的 `ingest` 消息处理函数会持续调用本方法，把主线程投递的行为事件转入存储层。
 * - Callers: Continuously called by the `ingest` message handler in `behavior_db_worker`, which forwards behavior events from the main thread into the storage layer.
 * - 被调方: `updateProcessInfo`、`normalizeEventToRow`、`getPidKeyFromRow`、`push`、`flush`、`JSON.stringify`。
 * - Callees: `updateProcessInfo`, `normalizeEventToRow`, `getPidKeyFromRow`, `push`, `flush`, `JSON.stringify`.
 * - 变量说明: `event` 为待写入的原始行为事件；`row` 为归一化后的日志行；`pidKey` 决定事件被追加到哪个 `.log` 文件；`lineSize` 用于累计总缓冲体积并触发阈值刷盘。
 * - Variables: `event` is the raw behavior event to persist; `row` is the normalized log row; `pidKey` determines which `.log` file receives the line; `lineSize` accumulates the total buffer size and triggers threshold-based flushing.
 * - 接入方式: 通过 `ProcessBehaviorStore` 实例的 `ingest(event)` 接入；新增实时事件源时应复用本方法，而不是直接写 `.log` 文件。
 * - Integration: Use `ProcessBehaviorStore.ingest(event)` as the ingress; new real-time event sources should reuse this method instead of writing `.log` files directly.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 行为写入 | behavior ingest | PID缓冲区 | per-PID buffer | 事件落盘前缓冲 | pre-flush buffering | 进程索引更新 | process index update | flush threshold
 */
  ingest(event) {
    if (!event || typeof event !== 'object') return

    if (event.provider === 'Process' && event.data && event.data.processId && event.data.imageName) {
       this.updateProcessInfo(event.data.processId, event.data.imageName)
    }

    const row = normalizeEventToRow(event)
    const pidKey = getPidKeyFromRow(row)
    const logLine = JSON.stringify(row) + '\n'
    const lineSize = Buffer.byteLength(logLine)

    if (!this.buffer.has(pidKey)) {
      this.buffer.set(pidKey, [])
    }
    this.buffer.get(pidKey).push(logLine)
    this.totalBufferSize += lineSize

    if (this.totalBufferSize >= this.flushThreshold) {
      this.flush()
    }
  }

  /**
 * - 函数: `flush`
 * - Function: `flush`
 * - 作用: 将当前内存缓冲区中的行为日志按 PID 追加到磁盘文件，并同步落下 `process_info.json`，把实时采集状态转换为可查询的稳定持久化状态。
 * - Purpose: Appends buffered behavior logs to per-PID files on disk and persists `process_info.json`, turning live in-memory capture state into a durable queryable state.
 * - 调用方: `ingest` 在缓冲体积达到阈值时触发；`exportToFileIfNeeded` 与 `close` 也会显式调用，保证查询、导出和关闭前没有残留未写数据。
 * - Callers: Triggered by `ingest` when the buffer crosses its threshold, and also called explicitly by `exportToFileIfNeeded` and `close` so queries, exports, and shutdowns do not leave unwritten data behind.
 * - 被调方: `saveProcessInfo`、`path.join`、`fs.appendFileSync`。
 * - Callees: `saveProcessInfo`, `path.join`, `fs.appendFileSync`.
 * - 变量说明: 无显式入参；`this.buffer` 存放待刷写的按 PID 分组日志行；`filePath` 为每个 PID 对应的目标日志文件路径。
 * - Variables: No explicit parameters; `this.buffer` holds pending log lines grouped by PID, and `filePath` is the destination log file path for each PID.
 * - 接入方式: 通过 `store.flush()` 接入；上层如果需要强制把行为事件落盘，应统一调用本方法，而不是分别操作各个缓冲桶。
 * - Integration: Use `store.flush()` when upper layers need a forced durable write; callers should use this single method instead of touching individual buffers.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 刷盘 | flush to disk | PID日志文件 | per-PID log file | appendFileSync | metadata flush | durable state | buffer drain | graceful persistence
 */
  flush() {
    this.saveProcessInfo()
    if (this.totalBufferSize === 0) return

    for (const [pid, lines] of this.buffer) {
      if (lines.length === 0) continue
      const filePath = path.join(this.logDir, `${pid}.log`)
      try {
        fs.appendFileSync(filePath, lines.join(''))
      } catch (e) {
        console.error(`Failed to flush logs for PID ${pid}:`, e)
      }
    }

    this.buffer.clear()
    this.totalBufferSize = 0
  }

  /**
 * - 函数: `listProcesses`
 * - Function: `listProcesses`
 * - 作用: 从行为日志目录枚举已有 PID 日志文件，并结合进程索引返回进程列表，为主界面的行为生命周期面板提供分页数据源。
 * - Purpose: Enumerates PID log files under the behavior-log directory and combines them with the process index to produce the process list used by the behavior lifecycle panel.
 * - 调用方: `behavior_db_worker` 的 `handleListProcesses` 调用本方法；渲染层的行为生命周期刷新链路最终都会落到这里。
 * - Callers: Called by `handleListProcesses` in `behavior_db_worker`, and ultimately reached by renderer-side lifecycle refresh flows.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `limit`/`offset` 控制分页窗口；`files` 为目录中实际存在的 PID 日志文件列表；`sliced` 为当前页返回的 PID 子集。
 * - Variables: `limit` and `offset` control the paging window; `files` is the list of PID log files found on disk; `sliced` is the current-page subset of PIDs.
 * - 接入方式: 通过 `store.listProcesses({ limit, offset })` 接入；新的行为概览查询应优先走本方法，而不是自行扫描日志目录。
 * - Integration: Use `store.listProcesses({ limit, offset })`; new behavior-overview queries should reuse this method instead of scanning the log directory manually.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 进程列表 | process list | 生命周期面板 | lifecycle panel | 分页查询 | paged query | PID日志枚举 | PID log enumeration | process_info index
 */
  listProcesses({ limit = 200, offset = 0 } = {}) {
    try {
      const lim = Number.isFinite(limit) ? Math.max(1, Math.min(5000, Math.floor(limit))) : 200
      const off = Number.isFinite(offset) ? Math.max(0, Math.floor(offset)) : 0
      const files = fs.readdirSync(this.logDir)
        .filter(f => f.endsWith('.log') && f !== 'global.log')
        .map(f => parseInt(f.replace('.log', ''), 10))
        .filter(pid => !isNaN(pid))
        
      // Sort or just slice? Let's just slice for now as before, though sorting by recent activity would be better.
      const sliced = files.slice(off, off + lim)

      return sliced.map(pid => {
        const info = this.processInfo.get(pid)
        return {
          pid,
          image: info ? info.name : 'Unknown (Log Only)',
          first_seen: info ? new Date(info.lastSeen).toISOString() : null, // We only store lastSeen currently
          last_seen: info ? new Date(info.lastSeen).toISOString() : null
        }
      })
    } catch {
      return []
    }
  }

  /**
 * - 函数: `listEvents`
 * - Function: `listEvents`
 * - 作用: 针对单个 PID 读取最近落盘日志和当前内存缓冲区，合并后按倒序切片返回事件列表，使 UI 在未刷盘前也能看到最新行为。
 * - Purpose: Reads both persisted log lines and the current in-memory buffer for a single PID, merges them, and returns reverse-ordered slices so the UI can see the latest behavior even before the next flush.
 * - 调用方: `behavior_db_worker` 的 `handleListEvents` 调用本方法；行为详情面板的分页加载最终也会落到这里。
 * - Callers: Called by `handleListEvents` in `behavior_db_worker`, and ultimately used by paged loading in the behavior details panel.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `pid` 为目标进程；`need` 为本页实际需要读取的尾部行数；`fileLines` 为已刷盘事件；`memLines` 为尚未刷盘的缓冲事件；`out` 为最终返回的归一化事件数组。
 * - Variables: `pid` is the target process; `need` is the actual tail-line count needed for the page; `fileLines` are persisted events; `memLines` are buffered yet-unflushed events; `out` is the final normalized event array.
 * - 接入方式: 通过 `store.listEvents({ pid, limit, offset })` 接入；新的事件详情查询应复用本方法，以保持“磁盘 + 内存缓冲”一致视图。
 * - Integration: Use `store.listEvents({ pid, limit, offset })`; new event-detail queries should reuse this method to preserve the combined “disk plus buffer” view.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 事件列表 | event list | 内存缓冲可见性 | buffered visibility | 倒序分页 | reverse paging | PID详情 | per-PID detail | readTailLines
 */
  listEvents({ pid = null, limit = 500, offset = 0 } = {}) {
    const lim = Number.isFinite(limit) ? Math.max(1, Math.min(10000, Math.floor(limit))) : 500
    const off = Number.isFinite(offset) ? Math.max(0, Math.floor(offset)) : 0
    const p = Number.isFinite(pid) ? pid : null
    if (p == null) return []

    const need = off + lim
    const filePath = path.join(this.logDir, `${p}.log`)
    const fileLines = fs.existsSync(filePath) ? readTailLines(filePath, need) : []

    let memLines = []
    if (this.buffer.has(p)) {
      memLines = this.buffer.get(p).map(l => String(l || '').trim()).filter(Boolean)
    }

    const allLines = fileLines.concat(memLines)
    allLines.reverse()
    const sliced = allLines.slice(off, off + lim)

    const out = []
    for (let i = 0; i < sliced.length; i++) {
      const line = sliced[i]
      const obj = safeJsonParse(line)
      if (!obj || typeof obj !== 'object') continue
      const row = normalizeEventToRow(obj)
      row.id = off + i + 1
      out.push(row)
    }
    return out
  }

  /**
 * - 函数: `listAllProcesses`
 * - Function: `listAllProcesses`
 * - 作用: 作为“给一个足够大的分页窗口即可拿到全部进程”的便捷包装器，供不关心分页细节的调用方一次性取回全部 PID 视图。
 * - Purpose: Serves as a convenience wrapper that fetches all processes by using a large enough page window, for callers that do not care about pagination details.
 * - 调用方: 需要一次性获取全量进程列表的维护或调试链路可调用；底层实际仍复用 `listProcesses`。
 * - Callers: Called by maintenance or debugging flows that need the full process list at once, while still delegating the actual work to `listProcesses`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `pageSize` 为单次拉取的最大进程数。
 * - Variables: `pageSize` is the maximum number of processes fetched in one call.
 * - 接入方式: 通过 `store.listAllProcesses()` 接入；若调用方确实需要分页控制，仍应直接使用 `listProcesses()`。
 * - Integration: Use `store.listAllProcesses()` for full fetches; callers that truly need paging control should still call `listProcesses()` directly.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 全量进程列表 | full process list | paging wrapper | convenience query | listProcesses delegate | maintenance helper | debug fetch | all PIDs
 */
  listAllProcesses({ pageSize = 5000 } = {}) {
    return this.listProcesses({ limit: pageSize })
  }

  /**
 * - 函数: `listAllEvents`
 * - Function: `listAllEvents`
 * - 作用: 作为事件详情查询的全量包装器，用大分页窗口一次取回某个 PID 的全部可见事件，适合导出、调试或离线分析。
 * - Purpose: Acts as the full-fetch wrapper for event-detail queries, retrieving all visible events of a PID with a large page window, suitable for export, debugging, or offline analysis.
 * - 调用方: 需要导出或调试某个 PID 全量行为历史的调用链可使用；底层实际仍复用 `listEvents`。
 * - Callers: Used by flows that export or debug the full behavior history of one PID, while delegating the actual read path to `listEvents`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `pid` 为目标进程号；`pageSize` 为单次读取的最大事件数。
 * - Variables: `pid` is the target process id; `pageSize` is the maximum event count pulled in one call.
 * - 接入方式: 通过 `store.listAllEvents({ pid })` 接入；若调用方需要严格分页，应直接使用 `listEvents()`。
 * - Integration: Use `store.listAllEvents({ pid })` for full fetches; callers that need strict paging should invoke `listEvents()` directly.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 全量事件列表 | full event list | event export wrapper | large page query | listEvents delegate | offline analysis | PID history fetch | debug helper
 */
  listAllEvents({ pid = null, pageSize = 10000 } = {}) {
     return this.listEvents({ pid, limit: pageSize })
  }

  /**
 * - 函数: `exportToFileIfNeeded`
 * - Function: `exportToFileIfNeeded`
 * - 作用: 作为“导出/读取前确保已落盘”的统一钩子，先强制刷盘再返回行为日志目录路径，供上层做后续归档、读取或调试导出。
 * - Purpose: Acts as the shared “flush before export/read” hook by forcing a flush and then returning the behavior-log directory path for archiving, reading, or debugging exports.
 * - 调用方: 周期性刷盘调度或上层导出链路在需要获取稳定文件视图时调用。
 * - Callers: Called by periodic flush scheduling or export flows when upper layers need a stable on-disk view before reading files.
 * - 被调方: `flush`。
 * - Callees: `flush`.
 * - 变量说明: 无显式入参；返回值 `this.logDir` 是导出方需要消费的行为日志根目录。
 * - Variables: No explicit parameters; the return value `this.logDir` is the behavior-log root directory consumed by export callers.
 * - 接入方式: 通过 `store.exportToFileIfNeeded()` 接入；外部若要读取日志文件，建议先走本方法而不是直接拿目录路径。
 * - Integration: Use `store.exportToFileIfNeeded()`; external readers should prefer this helper over grabbing the directory path directly.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 导出前刷盘 | flush before export | 日志目录 | log directory | stable file view | export hook | read consistency | forced flush
 */
  exportToFileIfNeeded() {
    this.flush()
    return this.logDir
  }

  /**
 * - 函数: `close`
 * - Function: `close`
 * - 作用: 关闭 `ProcessBehaviorStore` 前执行最后一次刷盘，确保进程索引和缓冲事件全部转入磁盘，是存储实例的优雅收尾入口。
 * - Purpose: Performs one final flush before `ProcessBehaviorStore` is torn down, ensuring both process metadata and buffered events reach disk as the store’s graceful shutdown path.
 * - 调用方: `behavior_db_worker` 在接收 `close` 消息时调用；任何结束行为采集的上层流程也应通过本方法收尾。
 * - Callers: Called by `behavior_db_worker` when it receives a `close` message, and it should be used by any upper layer shutting behavior capture down.
 * - 被调方: `flush`。
 * - Callees: `flush`.
 * - 变量说明: 无显式入参；本函数主要操作实例内的缓冲区、进程索引和日志目录状态。
 * - Variables: No explicit parameters; this method mainly acts on the instance buffer, process index, and log-directory state.
 * - 接入方式: 通过 `store.close()` 接入；应用退出或 worker 终止前应显式调用，而不是依赖进程退出时的隐式回收。
 * - Integration: Use `store.close()` explicitly before app exit or worker shutdown instead of relying on implicit process teardown.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 优雅关闭 | graceful close | 最终刷盘 | final flush | store shutdown | persistence tail | buffered events | metadata sync
 */
  close() {
    this.flush()
  }

  /**
 * - 函数: `clearAll`
 * - Function: `clearAll`
 * - 作用: 清空内存缓冲、进程索引和整个行为日志目录，用于重置行为数据库视图，使后续采集从全新基线重新开始。
 * - Purpose: Clears in-memory buffers, the process index, and the entire behavior-log directory so later collection restarts from a clean behavior-database baseline.
 * - 调用方: `behavior_db_worker` 的 `handleClearAll` 调用本方法，通常用于用户主动清空行为历史或调试重置。
 * - Callers: Called by `handleClearAll` in `behavior_db_worker`, typically when the user clears behavior history or triggers a debug reset.
 * - 被调方: `fs.mkdirSync`。
 * - Callees: `fs.mkdirSync`.
 * - 变量说明: 无显式入参；`this.buffer`、`this.processInfo` 和 `this.logDir` 分别对应内存事件、进程索引和磁盘存储根目录。
 * - Variables: No explicit parameters; `this.buffer`, `this.processInfo`, and `this.logDir` represent in-memory events, the process index, and the disk storage root respectively.
 * - 接入方式: 通过 `store.clearAll()` 接入；上层若需要重置行为历史，应统一走本方法，而不是单独删某个 PID 日志。
 * - Integration: Use `store.clearAll()` for history resets; upper layers should not delete individual PID logs manually.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 清空行为历史 | clear behavior history | reset baseline | log directory reset | process index reset | worker clearAll | clean slate | rmSync recreate
 */
  clearAll() {
    this.buffer.clear()
    this.totalBufferSize = 0
    this.processInfo.clear()
    this.processInfoDirty = false
    try {
        fs.rmSync(this.logDir, { recursive: true, force: true })
        fs.mkdirSync(this.logDir, { recursive: true })
    } catch {}
  }
}

/**
 * - 函数: `createProcessBehaviorStore`
 * - Function: `createProcessBehaviorStore`
 * - 作用: 根据外部传入的行为存储配置规范化日志目录，并创建 `ProcessBehaviorStore` 实例，作为主进程与 `behavior_db_worker` 共用的行为持久化工厂入口。
 * - Purpose: Normalizes the log-directory configuration from external behavior-store settings and creates a `ProcessBehaviorStore` instance, serving as the shared persistence-factory entry for both the main process and `behavior_db_worker`.
 * - 调用方: `workers/behavior_db_worker.js` 在初始化行为数据库 worker 时调用；其他主进程存储实验或测试场景也可直接复用。
 * - Callers: Called by `workers/behavior_db_worker.js` while initializing the behavior-database worker; reusable from other main-process storage experiments or tests as well.
 * - 被调方: `normalizeLogPath`、`ProcessBehaviorStore`。
 * - Callees: `normalizeLogPath`, `ProcessBehaviorStore`.
 * - 变量说明: `cfg` 为外部传入的存储配置；`logDir` 为规范化后的行为日志目录；返回值为真正承接进程与事件写入的 `ProcessBehaviorStore` 实例。
 * - Variables: `cfg` is the externally supplied storage config; `logDir` is the normalized behavior-log directory; the return value is the `ProcessBehaviorStore` instance that actually persists processes and events.
 * - 接入方式: 可通过 `require('./process_behavior_store').createProcessBehaviorStore` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./process_behavior_store').createProcessBehaviorStore`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 行为存储工厂 | behavior store factory | ProcessBehaviorStore | normalizeLogPath | worker初始化 | worker bootstrap | logDir | persistence entry | main process
 */
async function createProcessBehaviorStore(cfg = {}) {
  const { logDir } = normalizeLogPath(cfg)
  return new ProcessBehaviorStore({ logDir })
}

module.exports = {
  createProcessBehaviorStore,
  ProcessBehaviorStore
}
