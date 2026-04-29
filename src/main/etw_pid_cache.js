const path = require('path')
const { sanitizeText, isLikelyProcessImageText } = require('./utils')

/**
 * - 函数: `asPid`
 * - Function: `asPid`
 * - 作用: 将 ETW、快照或调用方传入的 PID 值归一化为可缓存的非负整数。
 * - Purpose: Normalizes the PID value coming from ETW, snapshots, or callers into a non-negative integer that can be cached safely.
 * - 调用方: `createEtwPidCache` 返回的 `upsert`、`remove`、`resolve` 方法。
 * - Callers: The `upsert`, `remove`, and `resolve` methods returned by `createEtwPidCache`.
 * - 被调方: `parseInt`、`Number.isFinite`。
 * - Callees: `parseInt` and `Number.isFinite`.
 * - 变量说明: `v` 为待转换的 PID 输入，可能是数字、字符串或其他可转文本值。
 * - Variables: `v` is the PID input to normalize and may be a number, string, or another text-convertible value.
 * - 接入方式: 作为当前模块内部 PID 标准化入口复用，不要在缓存读写方法里重复实现 PID 解析。
 * - Integration: Reuse it as the internal PID normalization entry instead of reimplementing PID parsing inside cache read/write methods.
 * - 错误处理: 无法解析为有限非负整数时返回 `null`，由上层方法决定忽略该条记录。
 * - Error Handling: Returns `null` when the value cannot be parsed into a finite non-negative integer, letting upper methods ignore that record.
 * - 关键词: PID归一化 | PID normalization | 缓存键转换 | cache key conversion | 非负整数校验 | non-negative integer validation | ETW输入兼容 | ETW input compatibility | 进程标识解析 | process id parsing
 */
function asPid(v) {
  const n = typeof v === 'number' ? v : parseInt(String(v), 10)
  if (!Number.isFinite(n) || n < 0) return null
  return n
}

/**
 * - 函数: `getProcessNameFromPath`
 * - Function: `getProcessNameFromPath`
 * - 作用: 从进程映像路径中提取可展示的进程名，并对结果做文本净化后写入缓存。
 * - Purpose: Extracts a displayable process name from an image path and sanitizes it before storing it in the cache.
 * - 调用方: `createEtwPidCache` 返回的 `upsert` 方法。
 * - Callers: The `upsert` method returned by `createEtwPidCache`.
 * - 被调方: `path.basename`、`sanitizeText`。
 * - Callees: `path.basename` and `sanitizeText`.
 * - 变量说明: `p` 为原始进程映像路径；`n` 为截取出的文件名。
 * - Variables: `p` is the raw process image path; `n` is the extracted basename.
 * - 接入方式: 仅作为缓存写入时的派生字段生成助手使用，避免在 ETW 事件处理侧重复截取进程名。
 * - Integration: Use it only as the derived-field helper during cache writes so ETW event handling does not duplicate process-name extraction.
 * - 错误处理: 路径为空或路径解析失败时返回空字符串，避免污染缓存结构。
 * - Error Handling: Returns an empty string when the path is blank or basename extraction fails, preventing cache pollution.
 * - 关键词: 进程名提取 | process name extraction | 映像路径解析 | image path parsing | 文本净化 | text sanitization | 缓存派生字段 | cache derived field | 文件名截取 | basename extraction
 */
function getProcessNameFromPath(p) {
  if (typeof p !== 'string' || !p) return ''
  try {
    const n = path.basename(p)
    return sanitizeText(typeof n === 'string' ? n : '')
  } catch {
    return ''
  }
}

/**
 * - 函数: `createEtwPidCache`
 * - Function: `createEtwPidCache`
 * - 作用: 创建 ETW 进程信息缓存实例，为主进程提供 PID 到映像路径/进程名的短期记忆、过期淘汰和容量控制能力。
 * - Purpose: Creates the ETW process-info cache instance, giving the main process short-term PID-to-image/name memory plus expiration and size control.
 * - 调用方: `main.js` 模块初始化阶段创建全局 `etwPidCache`。
 * - Callers: The `main.js` module initialization stage that creates the global `etwPidCache`.
 * - 被调方: `Map`、`configure`、`prune`、`upsert`、`bulkUpsert`、`remove`、`resolve`、`asPid`、`getProcessNameFromPath`。
 * - Callees: `Map`, `configure`, `prune`, `upsert`, `bulkUpsert`, `remove`, `resolve`, `asPid`, and `getProcessNameFromPath`.
 * - 变量说明: `map` 为 PID 缓存表；`max` 为最大条目数；`ttlMs` 为条目存活时长。
 * - Variables: `map` is the PID cache table; `max` is the maximum entry count; `ttlMs` is the entry time-to-live.
 * - 接入方式: 通过 `const { createEtwPidCache } = require('./etw_pid_cache')` 接入，并在主进程持有单例后复用其返回方法。
 * - Integration: Integrate via `const { createEtwPidCache } = require('./etw_pid_cache')` and keep a singleton in the main process that reuses the returned methods.
 * - 错误处理: 工厂本身不抛异常；具体非法输入由各实例方法在读写时就地过滤和回退。
 * - Error Handling: The factory itself does not throw; invalid inputs are filtered and degraded in place by each instance method.
 * - 关键词: ETW进程缓存 | ETW process cache | PID映射 | PID mapping | 进程名短期记忆 | short-term process memory | TTL淘汰 | TTL eviction | 容量控制 | capacity control
 */
function createEtwPidCache() {
  const map = new Map()
  let max = 2048
  let ttlMs = 300000

  /**
   * - 函数: `configure`
   * - Function: `configure`
   * - 作用: 更新缓存容量上限和 TTL 配置，使主进程可按当前 ETW 配置动态调整缓存策略。
   * - Purpose: Updates the cache capacity and TTL so the main process can adjust cache policy dynamically from the current ETW configuration.
   * - 调用方: `main.js` 中的 `refreshEtwPidCacheConfig`。
   * - Callers: `refreshEtwPidCacheConfig` in `main.js`.
   * - 被调方: `Number.isFinite`、`Math.max`、`Math.floor`。
   * - Callees: `Number.isFinite`, `Math.max`, and `Math.floor`.
   * - 变量说明: `cfg` 为缓存配置对象；`c` 为经过对象守卫后的安全配置视图；`max` 与 `ttlMs` 为闭包内实际生效的缓存参数。
   * - Variables: `cfg` is the cache config object; `c` is the guarded config view; `max` and `ttlMs` are the effective cache parameters captured in the closure.
   * - 接入方式: 通过缓存实例的 `configure()` 方法接入，推荐在快照种子或 ETW 启动前先刷新配置。
   * - Integration: Integrate through the cache instance `configure()` method and refresh it before seeding from snapshots or starting ETW processing.
   * - 错误处理: 非法配置值回退到默认 `2048` 和 `300000ms`，不抛异常。
   * - Error Handling: Invalid config values fall back to the defaults `2048` and `300000ms` without throwing.
   * - 关键词: 缓存配置刷新 | cache config refresh | TTL设置 | TTL setting | 容量上限 | capacity limit | 主进程调参 | main process tuning | 动态策略 | dynamic policy
   */
  function configure(cfg = {}) {
    const c = cfg && typeof cfg === 'object' ? cfg : {}
    max = Number.isFinite(c.max) ? Math.max(0, Math.floor(c.max)) : 2048
    ttlMs = Number.isFinite(c.ttlMs) ? Math.max(0, Math.floor(c.ttlMs)) : 300000
  }

  /**
   * - 函数: `prune`
   * - Function: `prune`
   * - 作用: 按时间和容量双条件淘汰 ETW PID 缓存中的过期或超量条目。
   * - Purpose: Evicts expired or over-capacity entries from the ETW PID cache by both time and size constraints.
   * - 调用方: `main.js` 中的 `pruneEtwPidCache`。
   * - Callers: `pruneEtwPidCache` in `main.js`.
   * - 被调方: `Number.isFinite`、`map.keys().next`、`map.delete`。
   * - Callees: `Number.isFinite`, `map.keys().next`, and `map.delete`.
   * - 变量说明: `now` 为当前时间戳；`t` 为生效 TTL；`m` 为生效容量上限；`firstKey` 为超量清理时最早被移除的键。
   * - Variables: `now` is the current timestamp; `t` is the effective TTL; `m` is the effective capacity limit; `firstKey` is the earliest key removed during overflow cleanup.
   * - 接入方式: 应在批量写入快照种子或 ETW 事件高峰后调用，保持缓存新鲜度与内存上界。
   * - Integration: Call it after bulk snapshot seeding or ETW event bursts to keep cache freshness and memory usage bounded.
   * - 错误处理: 无需集中异常处理；TTL 为 `0` 时跳过时间淘汰，仅保留容量控制。
   * - Error Handling: No centralized exception handling is needed; when TTL is `0`, time-based eviction is skipped and only capacity control remains.
   * - 关键词: 缓存淘汰 | cache pruning | TTL过期删除 | TTL expiration removal | 容量裁剪 | capacity trimming | ETW缓存维护 | ETW cache maintenance | 内存边界控制 | memory bound control
   */
  function prune(now) {
    const t = Number.isFinite(ttlMs) ? ttlMs : 300000
    const m = Number.isFinite(max) ? max : 2048
    if (t > 0) {
      for (const [pid, v] of map) {
        if (!v || !Number.isFinite(v.at) || now - v.at > t) map.delete(pid)
      }
    }
    while (map.size > m) {
      const firstKey = map.keys().next().value
      if (firstKey == null) break
      map.delete(firstKey)
    }
  }

  /**
   * - 函数: `upsert`
   * - Function: `upsert`
   * - 作用: 写入或刷新单个 PID 的映像路径、进程名和访问时间，使 ETW 事件可在缺少完整元数据时回查缓存。
   * - Purpose: Inserts or refreshes one PID's image path, process name, and access time so ETW events can look up cached metadata when they lack full details.
   * - 调用方: `main.js` 中的 `upsertEtwPid`，以及当前缓存实例的 `bulkUpsert`。
   * - Callers: `upsertEtwPid` in `main.js`, plus the current cache instance `bulkUpsert`.
   * - 被调方: `asPid`、`sanitizeText`、`isLikelyProcessImageText`、`getProcessNameFromPath`、`map.delete`、`map.set`。
   * - Callees: `asPid`, `sanitizeText`, `isLikelyProcessImageText`, `getProcessNameFromPath`, `map.delete`, and `map.set`.
   * - 变量说明: `pid` 为目标进程 ID；`imagePath` 为原始映像路径；`now` 为写入时间；`p` 为归一化 PID；`img` 为净化后的映像路径；`name` 为派生的进程名。
   * - Variables: `pid` is the target process ID; `imagePath` is the raw image path; `now` is the write timestamp; `p` is the normalized PID; `img` is the sanitized image path; `name` is the derived process name.
   * - 接入方式: 当 ETW 进程创建事件或 PID 快照拿到新的进程路径时调用本方法更新缓存。
   * - Integration: Call this helper whenever ETW process-create events or PID snapshots provide a new image path that should refresh the cache.
   * - 错误处理: PID 非法或映像路径文本明显异常时直接忽略该写入；不会抛异常影响事件主链路。
   * - Error Handling: Ignores the write when the PID is invalid or the image-path text is obviously malformed, without throwing into the event-processing chain.
   * - 关键词: PID缓存写入 | PID cache upsert | 映像路径刷新 | image path refresh | 进程名派生 | process name derivation | ETW事件补全 | ETW event enrichment | 访问时间更新 | access time update
   */
  function upsert(pid, imagePath, now) {
    const p = asPid(pid)
    if (p == null) return
    const rawImg = (typeof imagePath === 'string' && imagePath) ? imagePath : null
    const img = rawImg ? sanitizeText(rawImg) : null
    if (img && !isLikelyProcessImageText(img)) return
    const name = img ? getProcessNameFromPath(img) : ''
    map.delete(p)
    map.set(p, { imagePath: img, name, at: now })
  }

  /**
   * - 函数: `remove`
   * - Function: `remove`
   * - 作用: 删除指定 PID 的缓存记录，供进程退出或缓存纠正时立即清理陈旧映射。
   * - Purpose: Removes the cache record for a specific PID so process-exit handling or correction flows can clear stale mappings immediately.
   * - 调用方: `main.js` 中的 `removeEtwPid`。
   * - Callers: `removeEtwPid` in `main.js`.
   * - 被调方: `asPid`、`map.delete`。
   * - Callees: `asPid` and `map.delete`.
   * - 变量说明: `pid` 为待删除的进程 ID；`p` 为归一化后的缓存键。
   * - Variables: `pid` is the process ID to remove; `p` is the normalized cache key.
   * - 接入方式: 当收到进程结束事件或确认缓存失真时，通过缓存实例的 `remove()` 调用接入。
   * - Integration: Integrate through the cache instance `remove()` call when a process-exit event arrives or cache corruption is detected.
   * - 错误处理: PID 不合法时直接跳过，不抛异常。
   * - Error Handling: Skips the removal when the PID is invalid and does not throw.
   * - 关键词: 缓存删除 | cache removal | 进程退出清理 | process exit cleanup | 陈旧映射清除 | stale mapping cleanup | PID失效 | PID invalidation | 单条记录移除 | single entry removal
   */
  function remove(pid) {
    const p = asPid(pid)
    if (p == null) return
    map.delete(p)
  }

  /**
   * - 函数: `resolve`
   * - Function: `resolve`
   * - 作用: 解析指定 PID 的缓存进程信息，并在命中时刷新最近访问时间，供 ETW 风险分析回填进程名称和路径。
   * - Purpose: Resolves cached process info for a PID and refreshes its recent-access time on a hit so ETW risk analysis can backfill process names and paths.
   * - 调用方: `main.js` 中的 `resolveEtwProcessInfo`。
   * - Callers: `resolveEtwProcessInfo` in `main.js`.
   * - 被调方: `asPid`、`map.get`、`Number.isFinite`、`isLikelyProcessImageText`、`map.delete`、`map.set`。
   * - Callees: `asPid`, `map.get`, `Number.isFinite`, `isLikelyProcessImageText`, `map.delete`, and `map.set`.
   * - 变量说明: `pid` 为待查询进程 ID；`now` 为当前时间戳；`existed` 为已命中的缓存项；`cachedImage` 与 `cachedName` 为缓存中的映像路径和进程名；`ok` 为缓存内容有效性标记。
   * - Variables: `pid` is the process ID to query; `now` is the current timestamp; `existed` is the matched cache entry; `cachedImage` and `cachedName` are the cached image path and process name; `ok` marks whether the cached content is still valid.
   * - 接入方式: 在 ETW 事件缺少可靠映像路径时，通过缓存实例的 `resolve()` 方法先尝试补全元数据。
   * - Integration: When an ETW event lacks a reliable image path, first try to enrich its metadata through the cache instance `resolve()` method.
   * - 错误处理: PID 非法、缓存未命中、TTL 过期或缓存内容失真时返回 `null` 并同步清理脏项。
   * - Error Handling: Returns `null` and cleans the dirty entry when the PID is invalid, no cache entry exists, the entry has expired, or the cached content is invalid.
   * - 关键词: 缓存命中解析 | cache hit resolution | 访问时间续期 | access time refresh | ETW元数据补全 | ETW metadata enrichment | 过期校验 | expiration validation | 脏项清理 | dirty entry cleanup
   */
  function resolve(pid, now) {
    const p = asPid(pid)
    if (p == null) return null
    const existed = map.get(p)
    if (!existed) return null
    if (Number.isFinite(ttlMs) && ttlMs > 0 && Number.isFinite(existed.at) && (now - existed.at > ttlMs)) {
      map.delete(p)
      return null
    }
    const cachedImage = (typeof existed.imagePath === 'string' && existed.imagePath) ? existed.imagePath : ''
    const cachedName = (typeof existed.name === 'string' && existed.name) ? existed.name : ''
    const ok = (cachedImage && isLikelyProcessImageText(cachedImage)) || (cachedName && isLikelyProcessImageText(cachedName))
    if (!ok) {
      map.delete(p)
      return null
    }
    map.delete(p)
    map.set(p, { imagePath: existed.imagePath, name: existed.name, at: now })
    return map.get(p) || null
  }

  /**
   * - 函数: `bulkUpsert`
   * - Function: `bulkUpsert`
   * - 作用: 批量导入 PID 快照列表到缓存中，常用于启动时或定期快照为 ETW 分析预热元数据。
   * - Purpose: Bulk imports PID snapshot records into the cache, typically to warm ETW metadata during startup or scheduled snapshots.
   * - 调用方: `main.js` 中的 `takeEtwPidSnapshot`。
   * - Callers: `takeEtwPidSnapshot` in `main.js`.
   * - 被调方: `Array.isArray`、`upsert`。
 * - Callees: `Array.isArray` and `upsert`.
   * - 变量说明: `list` 为 PID 快照数组；`now` 为统一写入时间戳；`arr` 为安全化后的批量输入；`it` 为单条快照对象。
   * - Variables: `list` is the PID snapshot array; `now` is the shared write timestamp; `arr` is the guarded batch input; `it` is one snapshot object.
   * - 接入方式: 当从 `interception_snapshot_worker` 或 `winapi.getProcessImageSnapshot()` 拿到批量结果后，直接通过本函数灌入缓存。
   * - Integration: After receiving a batch from `interception_snapshot_worker` or `winapi.getProcessImageSnapshot()`, feed it directly into the cache through this helper.
   * - 错误处理: 非数组输入会退化为空批次；单条脏数据仅跳过该项，不影响其余记录写入。
   * - Error Handling: Non-array inputs degrade to an empty batch, and a dirty record only skips that item without affecting the rest of the import.
   * - 关键词: 批量快照导入 | bulk snapshot import | 缓存预热 | cache warmup | PID种子数据 | PID seed data | 批量写入 | batch upsert | ETW启动补种 | ETW startup seeding
   */
  function bulkUpsert(list, now) {
    const arr = Array.isArray(list) ? list : []
    for (const it of arr) {
      if (!it || typeof it !== 'object') continue
      const pid = it.pid
      const imagePath = it.imagePath
      upsert(pid, imagePath, now)
    }
  }

  return {
    configure,
    prune,
    upsert,
    bulkUpsert,
    remove,
    resolve,
    size: () => map.size
  }
}

module.exports = {
  createEtwPidCache
}
