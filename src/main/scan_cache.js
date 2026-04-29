const fs = require('fs')
const path = require('path')

/**
 * - 函数: `getProjectRoot`
 * - Function: `getProjectRoot`
 * - 作用: 返回主进程源码目录对应的项目根目录，供扫描缓存路径解析统一使用，避免不同调用方各自拼接相对路径。
 * - Purpose: Returns the project root that corresponds to the main-process source directory so scan-cache path resolution stays centralized instead of being rebuilt by each caller.
 * - 调用方: `resolveCachePath` 会先调用本函数，再基于项目根目录解析缓存文件绝对路径。
 * - Callers: `resolveCachePath` invokes this helper first and then resolves the absolute cache-file path from the returned project root.
 * - 被调方: `path.join`。
 * - Callees: `path.join`.
 * - 变量说明: 无显式入参；`__dirname` 为当前模块目录；返回值固定指向项目根目录字符串。
 * - Variables: There are no explicit parameters; `__dirname` is the current module directory, and the return value is the normalized project-root string.
 * - 接入方式: 仅建议在本模块内部作为基础路径锚点使用；如果后续缓存、报告或会话文件需要共享根目录解析，应继续通过本函数复用。
 * - Integration: Keep it as the internal anchor for root-path resolution; if future cache, report, or session files also need the same base directory, reuse this helper.
 * - 错误处理: 本函数不主动捕获异常，直接依赖 `path.join` 的稳定行为；一旦运行环境异常，上层路径解析会在调用处统一回退。
 * - Error Handling: It does not add its own `try/catch` and relies on the stable behavior of `path.join`; if the runtime is malformed, callers handle fallback at their own layer.
 * - 关键词: 项目根目录 | project root | 缓存路径锚点 | cache path anchor | 相对路径归一化 | relative path normalization | 主进程基础路径 | main-process base path | 路径复用 | path reuse
 */
function getProjectRoot() {
  return path.join(__dirname, '../..')
}

/**
 * - 函数: `resolveCachePath`
 * - Function: `resolveCachePath`
 * - 作用: 根据配置中的 `scan_cache.file` 解析扫描会话缓存文件绝对路径，是 `restore`、`saveCurrent`、`clearCurrent`、`markHandled` 和 `clearAll` 共用的定位入口。
 * - Purpose: Resolves the absolute scan-session cache file path from `scan_cache.file` in config, serving as the shared locator used by `restore`, `saveCurrent`, `clearCurrent`, `markHandled`, and `clearAll`.
 * - 调用方: `restore`、`saveCurrent`、`clearCurrent`、`markHandled`、`clearAll`。
 * - Callers: `restore`, `saveCurrent`, `clearCurrent`, `markHandled`, and `clearAll`.
 * - 被调方: `getProjectRoot`、`path.resolve`。
 * - Callees: `getProjectRoot` and `path.resolve`.
 * - 变量说明: `config` 为应用配置对象；`root` 为项目根目录；`rel` 为配置中的相对缓存路径，默认回退到 `config/scan_cache.json`。
 * - Variables: `config` is the application config object, `root` is the project root, and `rel` is the configured relative cache path that falls back to `config/scan_cache.json`.
 * - 接入方式: 所有读写扫描缓存文件的逻辑都应先经过本函数，不要在调用方重复拼接默认文件名或自行解析相对路径。
 * - Integration: Any cache read/write flow should route through this helper first; callers should not duplicate default filenames or resolve relative paths on their own.
 * - 错误处理: 本函数主要通过默认值守卫保证可返回有效路径；即使配置缺失也会稳定回退到默认缓存文件地址。
 * - Error Handling: Guarded defaults keep the function returning a usable path; even when config is incomplete it falls back to the default cache-file location.
 * - 关键词: 扫描缓存路径 | scan cache path | 配置解析 | config resolution | 默认文件回退 | default file fallback | 绝对路径生成 | absolute path generation | 会话存储定位 | session storage location
 */
function resolveCachePath(config) {
  const root = getProjectRoot()
  const rel = config && config.scan_cache && typeof config.scan_cache.file === 'string' ? config.scan_cache.file : 'config/scan_cache.json'
  return path.resolve(root, rel)
}

/**
 * - 函数: `readJsonFile`
 * - Function: `readJsonFile`
 * - 作用: 异步读取并解析指定 JSON 文件，给缓存恢复、清理和已处理标记逻辑提供统一的文件读取入口。
 * - Purpose: Asynchronously reads and parses the target JSON file, providing one shared file-loading entry for restore, cleanup, and handled-mark flows.
 * - 调用方: `restore`、`clearCurrent`、`markHandled`。
 * - Callers: `restore`, `clearCurrent`, and `markHandled`.
 * - 被调方: `fs.promises.readFile`、`JSON.parse`。
 * - Callees: `fs.promises.readFile` and `JSON.parse`.
 * - 变量说明: `p` 为待读取的缓存文件路径；`raw` 为原始 JSON 文本；返回值为解析后的对象或 `null`。
 * - Variables: `p` is the cache-file path to read, `raw` is the raw JSON text, and the return value is either the parsed object or `null`.
 * - 接入方式: 仅建议由本模块内部调用；若后续新增版本迁移或 schema 校验，可继续在本函数上层或内部集中扩展。
 * - Integration: Keep it internal to this module; if version migration or schema validation is added later, extend that behavior around or inside this helper.
 * - 错误处理: 文件不存在、编码异常或 JSON 解析失败时统一返回 `null`，避免把 I/O 异常直接传播到 UI 恢复链路。
 * - Error Handling: Missing files, encoding issues, or JSON parse failures are all normalized to `null` so I/O problems do not bubble directly into UI restore flows.
 * - 关键词: JSON读取 | JSON read | 异步文件解析 | async file parse | 扫描缓存装载 | scan cache load | 恢复前读取 | pre-restore read | 容错回退 | fault-tolerant fallback
 */
async function readJsonFile(p) {
  try {
    const raw = await fs.promises.readFile(p, 'utf-8')
    return JSON.parse(raw)
  } catch {
    return null
  }
}

/**
 * - 函数: `writeJsonFile`
 * - Function: `writeJsonFile`
 * - 作用: 异步创建父目录并写入格式化 JSON 文件，为扫描会话保存、清空和已处理打标提供统一落盘入口。
 * - Purpose: Asynchronously creates the parent directory and writes a formatted JSON document, acting as the shared persistence entry for saving, clearing, and handled-mark updates.
 * - 调用方: `saveCurrent`、`clearCurrent`、`markHandled`。
 * - Callers: `saveCurrent`, `clearCurrent`, and `markHandled`.
 * - 被调方: `path.dirname`、`fs.promises.mkdir`、`JSON.stringify`、`fs.promises.writeFile`。
 * - Callees: `path.dirname`, `fs.promises.mkdir`, `JSON.stringify`, and `fs.promises.writeFile`.
 * - 变量说明: `p` 为目标缓存文件路径；`data` 为待持久化对象；写入内容固定使用 2 空格缩进，便于人工排查。
 * - Variables: `p` is the target cache-file path, `data` is the object being persisted, and output always uses two-space indentation for easier manual inspection.
 * - 接入方式: 所有缓存文件写回都应通过本函数统一处理，避免不同调用方在目录创建、编码或格式化上产生分叉。
 * - Integration: Route all cache-file writes through this helper so directory creation, encoding, and formatting remain consistent across callers.
 * - 错误处理: 目录创建或文件写入失败时返回 `false`，不抛异常，让上层决定是否重试或静默降级。
 * - Error Handling: Directory-creation and file-write failures return `false` instead of throwing, allowing callers to decide whether to retry or degrade silently.
 * - 关键词: JSON写入 | JSON write | 目录自动创建 | parent directory creation | 会话落盘 | session persistence | 统一格式输出 | stable formatting | 异步持久化 | async persistence
 */
async function writeJsonFile(p, data) {
  try {
    await fs.promises.mkdir(path.dirname(p), { recursive: true })
    await fs.promises.writeFile(p, JSON.stringify(data, null, 2), 'utf-8')
    return true
  } catch {
    return false
  }
}

/**
 * - 函数: `clearFile`
 * - Function: `clearFile`
 * - 作用: 异步删除指定缓存文件，作为“当前会话为空”或“整份扫描缓存重置”场景下的统一物理清理入口。
 * - Purpose: Asynchronously deletes the target cache file, serving as the shared physical-cleanup entry when the current session becomes empty or the whole scan cache must be reset.
 * - 调用方: `clearCurrent`、`clearAll`。
 * - Callers: `clearCurrent` and `clearAll`.
 * - 被调方: `fs.promises.unlink`。
 * - Callees: `fs.promises.unlink`.
 * - 变量说明: `p` 为待删除的缓存文件路径；返回值表示删除动作是否成功完成。
 * - Variables: `p` is the cache-file path to remove, and the return value reports whether deletion completed successfully.
 * - 接入方式: 本模块涉及删除缓存文件的逻辑都应通过本函数收口，保证“文件不存在”与“删除失败”统一折叠成布尔返回值。
 * - Integration: Any cache-file deletion in this module should funnel through this helper so missing files and delete failures are uniformly collapsed into a boolean result.
 * - 错误处理: 删除失败或文件不存在时返回 `false`，不抛异常，方便调用方继续做兼容回退。
 * - Error Handling: Delete failures and already-missing files return `false` without throwing, making follow-up fallback handling straightforward for callers.
 * - 关键词: 缓存文件删除 | cache file delete | 物理清理 | physical cleanup | 会话重置 | session reset | unlink封装 | unlink wrapper | 布尔结果回退 | boolean fallback
 */
async function clearFile(p) {
  try {
    await fs.promises.unlink(p)
    return true
  } catch {
    return false
  }
}

/**
 * - 函数: `restore`
 * - Function: `restore`
 * - 作用: 读取上一次保存的扫描会话，并只在当前会话尚未标记为已处理时返回，用于渲染层恢复“未完成扫描”入口。
 * - Purpose: Reads the last persisted scan session and returns it only when that session has not yet been marked as handled, allowing the renderer to restore an unfinished scan flow.
 * - 调用方: `preload.js` 暴露的 `scanCache.restore()` 会被 `renderer.js` 的启动恢复逻辑调用。
 * - Callers: Invoked by the startup-restore logic in `renderer.js` through the `scanCache.restore()` bridge exposed by `preload.js`.
 * - 被调方: `resolveCachePath`、`readJsonFile`。
 * - Callees: `resolveCachePath` and `readJsonFile`.
 * - 变量说明: `config` 提供缓存目录和文件配置；`p` 为最终缓存文件路径；`data` 为完整缓存文件内容；`current` 为当前扫描会话快照。
 * - Variables: `config` provides cache-directory and file settings, `p` is the resolved cache-file path, `data` is the full persisted document, and `current` is the current scan-session snapshot.
 * - 接入方式: 所有“恢复未完成扫描”的入口都应经由本函数读取统一状态；不要在渲染层直接访问缓存文件，以免绕过 `handled` 判定。
 * - Integration: Any unfinished-scan restore flow should use this function as the single state reader; the renderer should not touch the cache file directly or it may bypass the `handled` guard.
 * - 错误处理: 文件不存在、JSON 读取失败、无 `current` 字段或会话已标记 `handled` 时统一返回 `null`，让上层按“无可恢复会话”处理。
 * - Error Handling: Missing files, JSON read failures, absent `current` data, or sessions already marked as `handled` all collapse to `null`, letting callers treat them uniformly as "nothing to restore."
 * - 关键词: 扫描会话恢复 | scan session restore | 未完成扫描 | unfinished scan | handled过滤 | handled guard | preload桥接 | preload bridge | 启动恢复入口 | startup restore entry
 */
async function restore(config) {
  const p = resolveCachePath(config)
  const data = await readJsonFile(p)
  const current = data && data.current ? data.current : null
  if (!current) return null
  if (current.handled) return null
  return current
}

/**
 * - 函数: `saveCurrent`
 * - Function: `saveCurrent`
 * - 作用: 把当前扫描会话整体写入缓存文件，覆盖旧的 `current` 快照，供页面刷新、应用重启或异常中断后继续恢复。
 * - Purpose: Persists the current scan session into the cache file by replacing the previous `current` snapshot, enabling recovery after page reloads, app restarts, or unexpected interruptions.
 * - 调用方: `preload.js` 暴露的 `scanCache.saveCurrent()` 会被 `renderer.js` 在扫描进行中持续调用。
 * - Callers: Called continuously by `renderer.js` during active scans through the `scanCache.saveCurrent()` bridge exposed by `preload.js`.
 * - 被调方: `resolveCachePath`、`writeJsonFile`。
 * - Callees: `resolveCachePath` and `writeJsonFile`.
 * - 变量说明: `config` 提供缓存文件定位信息；`session` 为需要持久化的当前扫描状态；`payload` 固定封装成 `{ current }` 结构，便于后续读取与扩展。
 * - Variables: `config` provides the cache-file location, `session` is the current scan state to persist, and `payload` wraps the data into a stable `{ current }` shape for later reads and future extensions.
 * - 接入方式: 所有扫描进度快照保存都应通过本函数，保证文件结构统一；若以后要新增历史会话或版本字段，应先扩展这里的持久化格式。
 * - Integration: All scan-progress persistence should flow through this function so the file structure stays uniform; if historical sessions or version fields are added later, extend the persistence format here first.
 * - 错误处理: 结果完全依赖 `writeJsonFile`；写入失败返回 `false`，上层可以选择静默继续扫描而不影响当前前台流程。
 * - Error Handling: The outcome is delegated to `writeJsonFile`; write failures return `false`, allowing callers to continue the foreground scan flow without crashing.
 * - 关键词: 扫描快照保存 | scan snapshot save | current会话落盘 | current session persistence | 页面刷新恢复 | reload recovery | 写入统一格式 | stable write format | 持续保存 | incremental persistence
 */
async function saveCurrent(config, session) {
  const p = resolveCachePath(config)
  const payload = { current: session || null }
  return writeJsonFile(p, payload)
}

/**
 * - 函数: `clearCurrent`
 * - Function: `clearCurrent`
 * - 作用: 清空缓存中的当前扫描会话；如果文件本身不存在或只剩空内容，则直接删除缓存文件，避免残留无效状态。
 * - Purpose: Clears the current scan session from the cache; if the file no longer contains meaningful data, it removes the cache file entirely to avoid leaving stale state behind.
 * - 调用方: `preload.js` 暴露的 `scanCache.clearCurrent()` 会被 `renderer.js` 在扫描完成、取消或恢复后清理阶段调用。
 * - Callers: Invoked during completion, cancellation, or post-restore cleanup in `renderer.js` through the `scanCache.clearCurrent()` bridge exposed by `preload.js`.
 * - 被调方: `resolveCachePath`、`readJsonFile`、`clearFile`、`writeJsonFile`。
 * - Callees: `resolveCachePath`, `readJsonFile`, `clearFile`, and `writeJsonFile`.
 * - 变量说明: `config` 提供缓存路径配置；`p` 为缓存文件路径；`data` 为当前已落盘的 JSON 内容，决定是直接删文件还是仅清空 `current` 字段。
 * - Variables: `config` provides cache-path settings, `p` is the cache-file path, and `data` is the persisted JSON content that determines whether the file should be deleted or only have its `current` field cleared.
 * - 接入方式: 任何结束当前扫描会话的逻辑都应调用本函数，而不是直接写 `null` 或删除文件，以保持“有文件但无 current”与“文件不存在”两种情况的兼容处理一致。
 * - Integration: Any flow that ends the current scan session should call this function instead of writing `null` or deleting the file directly, keeping the handling of "file exists but no current" and "file absent" consistent.
 * - 错误处理: 读取不到数据时回退为删文件；写回失败则返回 `false`，由上层决定是否重试，不会抛异常打断 UI 收尾流程。
 * - Error Handling: When existing data cannot be read, it falls back to deleting the file; write failures return `false`, leaving retry decisions to callers without interrupting UI cleanup.
 * - 关键词: 当前会话清空 | clear current session | 缓存文件删除 | cache file removal | 扫描结束收尾 | scan completion cleanup | 空状态归一化 | empty state normalization | 恢复后清理 | post-restore cleanup
 */
async function clearCurrent(config) {
  const p = resolveCachePath(config)
  const data = await readJsonFile(p)
  if (!data) return clearFile(p)
  data.current = null
  return writeJsonFile(p, data)
}

/**
 * - 函数: `markHandled`
 * - Function: `markHandled`
 * - 作用: 把当前扫描会话标记为“已被用户处理”，并记录处理时间，防止同一份缓存会话在下次启动时再次被恢复。
 * - Purpose: Marks the current scan session as already handled and records the handling timestamp so the same cached session will not be restored again on the next startup.
 * - 调用方: `preload.js` 暴露的 `scanCache.markHandled()` 会被 `renderer.js` 在用户完成恢复会话处理后调用。
 * - Callers: Called by `renderer.js` after the user finishes dealing with a restored session through the `scanCache.markHandled()` bridge exposed by `preload.js`.
 * - 被调方: `resolveCachePath`、`readJsonFile`、`writeJsonFile`、`Date.now`。
 * - Callees: `resolveCachePath`, `readJsonFile`, `writeJsonFile`, and `Date.now`.
 * - 变量说明: `config` 提供缓存路径信息；`handledAt` 支持由调用方传入外部时间戳；`data.current.handled` 表示是否已处理；`data.current.handledAt` 记录最终时间。
 * - Variables: `config` provides cache-path settings, `handledAt` optionally allows the caller to inject a timestamp, `data.current.handled` stores the handled flag, and `data.current.handledAt` records the final time.
 * - 接入方式: 所有“恢复过一次后不要再弹”的场景都应通过本函数打标，而不是仅调用 `clearCurrent`，这样仍可保留会话痕迹用于审计或后续扩展。
 * - Integration: Any "restored once, do not show again" flow should mark through this function rather than relying only on `clearCurrent`, preserving a lightweight audit trail and leaving room for future extensions.
 * - 错误处理: 不存在缓存或 `current` 为空时返回 `false`；写入失败也返回 `false`，调用方可继续走清理链路，不会因为打标失败阻断恢复流程。
 * - Error Handling: Returns `false` when no cache exists or when `current` is missing; write failures also return `false`, allowing callers to continue cleanup without blocking the restore flow.
 * - 关键词: 已处理标记 | handled flag | 恢复去重 | restore deduplication | 处理时间戳 | handled timestamp | 启动防重复恢复 | startup no-repeat restore | 会话审计钩子 | session audit hook
 */
async function markHandled(config, handledAt) {
  const p = resolveCachePath(config)
  const data = await readJsonFile(p)
  if (!data || !data.current) return false
  data.current.handled = true
  data.current.handledAt = handledAt || Date.now()
  return writeJsonFile(p, data)
}

/**
 * - 函数: `clearAll`
 * - Function: `clearAll`
 * - 作用: 删除扫描缓存文件整体内容，用于用户主动重置缓存或需要彻底放弃所有恢复上下文的场景。
 * - Purpose: Removes the entire scan-cache file, which is useful when the user explicitly resets cache state or the application must discard all restore context completely.
 * - 调用方: 供 `preload.js` 暴露给渲染层的缓存清理 API 以及其他需要全量重置扫描会话状态的主进程逻辑调用。
 * - Callers: Used by the cache-reset API exposed through `preload.js` and by any main-process flow that needs a full reset of scan-session state.
 * - 被调方: `resolveCachePath`、`clearFile`。
 * - Callees: `resolveCachePath` and `clearFile`.
 * - 变量说明: `config` 提供缓存文件定位配置；`p` 为最终要删除的缓存文件路径。
 * - Variables: `config` provides cache-location settings, and `p` is the final cache-file path to delete.
 * - 接入方式: 任何“清空全部扫描缓存”的需求都应通过本函数，而不是在外部直接 `unlink`，这样可复用统一的路径解析和布尔返回约定。
 * - Integration: Any "clear all scan cache" requirement should call this function instead of unlinking externally so it can reuse the shared path resolution and boolean result contract.
 * - 错误处理: 结果完全依赖 `clearFile`；删除失败返回 `false`，由上层决定是否提示用户或再次重试。
 * - Error Handling: The outcome is delegated entirely to `clearFile`; deletion failures return `false`, leaving the caller to decide whether to notify the user or retry.
 * - 关键词: 全量缓存清空 | full cache clear | 扫描会话重置 | scan session reset | 恢复上下文删除 | restore context removal | 文件级清理 | file-level cleanup | preload重置接口 | preload reset API
 */
async function clearAll(config) {
  const p = resolveCachePath(config)
  return clearFile(p)
}

module.exports = {
  resolveCachePath,
  restore,
  saveCurrent,
  clearCurrent,
  markHandled,
  clearAll
}
