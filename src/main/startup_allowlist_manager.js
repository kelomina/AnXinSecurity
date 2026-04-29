const fs = require('fs')
const path = require('path')
const CryptoManager = require('./crypto_manager')

class StartupAllowlistManager {
  /**
   * - 函数: `constructor`
   * - Function: `constructor`
   * - 作用: 初始化启动放行名单管理器，绑定配置文件路径、加密器实例与持久化存储位置。
   * - Purpose: Initializes the startup allowlist manager by binding the config path, crypto helper, and persistence location.
   * - 调用方: `main.js` 中创建 `startupAllowlist` 实例的初始化流程。
   * - Callers: The initialization flow in `main.js` that creates the `startupAllowlist` instance.
   * - 被调方: `CryptoManager`、`resolveStoragePath`。
   * - Callees: `CryptoManager` and `resolveStoragePath`.
   * - 变量说明: `configPath` 为应用配置文件路径；`this.crypto` 为启动放行名单的加密存储助手；`this.storagePath` 为加密名单文件落盘路径。
   * - Variables: `configPath` is the app-config path; `this.crypto` is the encrypted-storage helper for the startup allowlist; `this.storagePath` is the on-disk path of the encrypted allowlist file.
   * - 接入方式: 通过 `new StartupAllowlistManager(configPath)` 创建单例或共享实例，再调用 `getFiles`、`addFiles` 等方法接入后续策略链。
   * - Integration: Create a shared instance with `new StartupAllowlistManager(configPath)`, then integrate later policy flows through methods such as `getFiles` and `addFiles`.
   * - 错误处理: 构造函数本身不主动捕获异常，具体文件路径解析和读写回退由后续实例方法负责。
   * - Error Handling: The constructor does not actively catch errors; concrete path resolution and file I/O fallback behavior are handled by later instance methods.
   * - 关键词: 启动放行名单 | startup allowlist | 管理器初始化 | manager initialization | 加密存储 | encrypted storage | 配置路径绑定 | config path binding | 持久化入口 | persistence entry
   */
  constructor(configPath) {
    this.configPath = configPath
    this.crypto = new CryptoManager(configPath, 'startup_allowlist')
    this.storagePath = this.resolveStoragePath()
  }

  /**
   * - 函数: `resolveStoragePath`
   * - Function: `resolveStoragePath`
   * - 作用: 从应用配置解析启动放行名单加密文件路径，并确保目标目录存在，作为后续读写的统一落点。
   * - Purpose: Resolves the encrypted startup-allowlist file path from app configuration and ensures the target directory exists as the shared read/write location.
   * - 调用方: `constructor`。
   * - Callers: `constructor`.
   * - 被调方: `fs.readFileSync`、`JSON.parse`、`path.isAbsolute`、`path.join`、`path.dirname`、`fs.existsSync`、`fs.mkdirSync`。
   * - Callees: `fs.readFileSync`, `JSON.parse`, `path.isAbsolute`, `path.join`, `path.dirname`, `fs.existsSync`, and `fs.mkdirSync`.
   * - 变量说明: `p` 为解析后的最终存储路径；`raw` 与 `cfg` 分别保存配置文件文本和解析结果；`rel` 为配置中的相对或绝对路径配置项；`dir` 为目标目录。
   * - Variables: `p` is the final resolved storage path; `raw` and `cfg` store the config text and parsed object; `rel` is the configured relative or absolute path; `dir` is the target directory.
   * - 接入方式: 仅作为实例初始化阶段的内部路径收口点使用；若后续支持新的配置字段，应优先在本函数中扩展解析逻辑。
   * - Integration: Use it only as the internal path-resolution choke point during initialization; if new config fields are supported later, extend the resolution logic here first.
   * - 错误处理: 读取或解析配置失败时回退到默认 `config/startup_allowlist.enc` 路径，并在返回前补建目录。
   * - Error Handling: Falls back to the default `config/startup_allowlist.enc` path when config reading or parsing fails and creates the directory before returning.
   * - 关键词: 存储路径解析 | storage path resolution | 加密名单文件 | encrypted allowlist file | 配置回退 | config fallback | 目录创建 | directory creation | 启动策略持久化 | startup policy persistence
   */
  resolveStoragePath() {
    let p = null
    try {
      const raw = fs.readFileSync(this.configPath, 'utf-8')
      const cfg = JSON.parse(raw)
      const rel = cfg && cfg.etw && cfg.etw.interception && cfg.etw.interception.startupAllowlistFile
        ? cfg.etw.interception.startupAllowlistFile
        : 'config/startup_allowlist.enc'
      p = path.isAbsolute(rel) ? rel : path.join(path.dirname(this.configPath), '..', rel)
    } catch {
      p = path.join(path.dirname(this.configPath), '..', 'config', 'startup_allowlist.enc')
    }
    const dir = path.dirname(p)
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    return p
  }

  /**
   * - 函数: `normalize`
   * - Function: `normalize`
   * - 作用: 统一规范启动放行名单中的路径大小写与分隔符格式，便于去重和比较。
   * - Purpose: Normalizes path case and separator format for startup-allowlist entries so deduplication and comparisons remain stable.
   * - 调用方: `addFiles`。
   * - Callers: `addFiles`.
   * - 被调方: `path.normalize`、`String.prototype.toLowerCase`。
   * - Callees: `path.normalize` and `String.prototype.toLowerCase`.
   * - 变量说明: `p` 为待标准化的原始文件路径字符串。
   * - Variables: `p` is the raw file-path string to normalize.
   * - 接入方式: 供名单写入前的键构造统一复用；若未来要支持目录项比较，也应沿用本函数的归一化规则。
   * - Integration: Reuse it when building keys before allowlist writes; if directory-entry comparison is added later, keep using this normalization rule.
   * - 错误处理: 非字符串或空路径输入时返回空字符串，避免生成脏键值。
   * - Error Handling: Returns an empty string for non-string or blank inputs, preventing dirty comparison keys from being generated.
   * - 关键词: 路径标准化 | path normalization | 大小写归一 | lowercase normalization | 去重键 | dedupe key | 文件名单 | file allowlist | 比较一致性 | comparison consistency
   */
  normalize(p) {
    if (!p || typeof p !== 'string') return ''
    return path.normalize(p).toLowerCase()
  }

  /**
   * - 函数: `loadRaw`
   * - Function: `loadRaw`
   * - 作用: 读取并解密启动放行名单文件，返回原始名单数组供上层再做结构清洗。
   * - Purpose: Reads and decrypts the startup-allowlist file, returning the raw list array for later structural cleanup by upper layers.
   * - 调用方: `getList`。
   * - Callers: `getList`.
   * - 被调方: `fs.existsSync`、`fs.readFileSync`、`JSON.parse`、`this.crypto.decryptText`。
   * - Callees: `fs.existsSync`, `fs.readFileSync`, `JSON.parse`, and `this.crypto.decryptText`.
   * - 变量说明: `raw` 为加密文件文本内容；`payload` 为解密前的 JSON 载荷；`text` 为解密后的纯文本名单数据。
   * - Variables: `raw` is the encrypted file text; `payload` is the JSON envelope before decryption; `text` is the decrypted plain-text allowlist data.
   * - 接入方式: 仅供 `getList` 作为底层数据源复用；若后续增加审计或迁移逻辑，应在本函数附近统一处理解密入口。
   * - Integration: Keep it as the low-level data source for `getList`; if audit or migration logic is added later, handle the decryption entry near this function.
   * - 错误处理: 文件不存在、解密失败或 JSON 解析失败时统一返回 `null`，由上层按空名单处理。
   * - Error Handling: Returns `null` when the file is missing, decryption fails, or JSON parsing fails, allowing upper layers to degrade to an empty allowlist.
   * - 关键词: 名单解密加载 | allowlist decrypt load | 加密文件读取 | encrypted file read | 原始数据恢复 | raw data restore | JSON载荷 | JSON payload | 空名单回退 | empty allowlist fallback
   */
  loadRaw() {
    try {
      if (!fs.existsSync(this.storagePath)) return null
      const raw = fs.readFileSync(this.storagePath, 'utf-8')
      const payload = JSON.parse(raw)
      const text = this.crypto.decryptText(payload)
      return JSON.parse(text)
    } catch {
      return null
    }
  }

  /**
   * - 函数: `saveRaw`
   * - Function: `saveRaw`
   * - 作用: 将启动放行名单数组加密后写回磁盘，作为名单变更后的唯一持久化出口。
   * - Purpose: Encrypts the startup-allowlist array and writes it back to disk as the single persistence exit after list mutations.
   * - 调用方: `addFiles`。
   * - Callers: `addFiles`.
   * - 被调方: `this.crypto.encryptText`、`JSON.stringify`、`fs.writeFileSync`。
   * - Callees: `this.crypto.encryptText`, `JSON.stringify`, and `fs.writeFileSync`.
   * - 变量说明: `list` 为待持久化的名单数组；`payload` 为加密后的 JSON 包装对象。
   * - Variables: `list` is the allowlist array to persist; `payload` is the encrypted JSON envelope.
   * - 接入方式: 所有会修改启动放行名单的实例方法都应通过本函数落盘，避免出现多处写文件规则不一致。
   * - Integration: Any instance method that mutates the startup allowlist should persist through this helper so file-writing rules stay centralized.
   * - 错误处理: 本函数不吞掉写盘异常，由调用方感知失败并决定是否回滚或提示用户。
   * - Error Handling: This function does not swallow disk-write errors; callers can observe failures and decide whether to roll back or notify the user.
   * - 关键词: 名单加密保存 | allowlist encrypted save | 持久化出口 | persistence exit | 文件写回 | file write back | 加密载荷 | encrypted payload | 变更提交 | mutation commit
   */
  saveRaw(list) {
    const payload = this.crypto.encryptText(JSON.stringify(Array.isArray(list) ? list : []))
    fs.writeFileSync(this.storagePath, JSON.stringify(payload, null, 2), 'utf-8')
  }

  /**
   * - 函数: `getList`
   * - Function: `getList`
   * - 作用: 读取启动放行名单并清洗为统一结构 `{ type, path }`，屏蔽底层原始数据缺项或脏数据。
   * - Purpose: Reads the startup allowlist and normalizes it into a consistent `{ type, path }` shape, hiding missing fields or dirty raw entries.
   * - 调用方: `getFiles`、`addFiles`。
   * - Callers: `getFiles` and `addFiles`.
   * - 被调方: `loadRaw`、`Array.isArray`、`Array.prototype.map`、`Array.prototype.filter`。
   * - Callees: `loadRaw`, `Array.isArray`, `Array.prototype.map`, and `Array.prototype.filter`.
   * - 变量说明: `data` 为解密后的原始数组；返回项中的 `type` 仅保留 `file` 或 `dir`，`path` 为有效路径字符串。
   * - Variables: `data` is the decrypted raw array; the returned entry `type` is limited to `file` or `dir`, and `path` is the validated path string.
   * - 接入方式: 上层查询或修改名单前应先通过本函数拿到标准化结构，避免直接操作 `loadRaw()` 的原始结果。
   * - Integration: Query and mutation flows should obtain the normalized structure through this helper instead of operating directly on the raw `loadRaw()` output.
   * - 错误处理: 原始数据不是数组时返回空列表；无效项会在映射与过滤阶段被清理掉。
   * - Error Handling: Returns an empty list when raw data is not an array, and invalid entries are removed during mapping and filtering.
   * - 关键词: 名单结构清洗 | allowlist shape normalization | 条目标准化 | entry normalization | 文件目录类型 | file dir type | 脏数据过滤 | dirty data filtering | 查询入口 | query entry
   */
  getList() {
    const data = this.loadRaw()
    if (!Array.isArray(data)) return []
    return data.map(it => ({
      type: it && it.type === 'dir' ? 'dir' : 'file',
      path: it && it.path ? it.path : ''
    })).filter(it => it.path)
  }

  /**
   * - 函数: `getFiles`
   * - Function: `getFiles`
   * - 作用: 从标准化名单中提取仅文件类型的启动放行路径，供快照扫描与放行策略直接使用。
   * - Purpose: Extracts only file-type startup-allowlist paths from the normalized list so snapshot scan and allow policies can use them directly.
   * - 调用方: `main.js` 中向拦截快照 worker 下发 `allowlistFiles` 的流程。
   * - Callers: The flow in `main.js` that sends `allowlistFiles` to the interception snapshot worker.
   * - 被调方: `getList`、`Array.prototype.filter`、`Array.prototype.map`。
   * - Callees: `getList`, `Array.prototype.filter`, and `Array.prototype.map`.
   * - 变量说明: 无显式入参；过滤后仅保留 `type === 'file'` 的条目，并返回其 `path` 字段。
   * - Variables: There are no explicit parameters; it keeps only entries where `type === 'file'` and returns their `path` fields.
   * - 接入方式: 若下游只需要文件路径数组，应优先调用本函数而不是手动从 `getList()` 结果中过滤。
   * - Integration: If downstream code only needs the file-path array, call this helper instead of filtering the `getList()` result manually.
   * - 错误处理: 继承 `getList` 的空列表回退策略，不额外抛出异常。
   * - Error Handling: Inherits the empty-list fallback behavior from `getList` and does not throw additional exceptions.
   * - 关键词: 文件白名单提取 | file allowlist extraction | 启动放行文件 | startup allowed files | worker配置输入 | worker config input | 文件路径数组 | file path array | 策略下发 | policy dispatch
   */
  getFiles() {
    return this.getList().filter(it => it.type === 'file').map(it => it.path)
  }

  /**
   * - 函数: `addFiles`
   * - Function: `addFiles`
   * - 作用: 向启动放行名单追加新的文件路径，按归一化结果去重，并在有变更时触发加密持久化。
   * - Purpose: Appends new file paths to the startup allowlist, deduplicates them by normalized form, and persists the encrypted list only when changes occur.
   * - 调用方: 主进程中根据快照扫描结果补充启动放行名单的流程。
   * - Callers: Main-process flows that enrich the startup allowlist from snapshot-scan results.
   * - 被调方: `getList`、`Set`、`normalize`、`saveRaw`。
   * - Callees: `getList`, `Set`, `normalize`, and `saveRaw`.
   * - 变量说明: `paths` 为待追加路径数组；`list` 为当前标准化名单；`seen` 为已存在键集合；`changed` 标记本次是否发生新增。
   * - Variables: `paths` is the array of paths to append; `list` is the current normalized allowlist; `seen` stores existing keys; `changed` marks whether this call added anything new.
   * - 接入方式: 将待放行的文件路径数组传入本函数即可；若未来支持目录新增，建议拆分独立方法而不是混入当前文件逻辑。
   * - Integration: Pass the file-path array to allow into this helper; if directory additions are supported later, prefer a separate method instead of mixing that logic here.
   * - 错误处理: 非数组或非法路径项会被跳过；只有实际发生新增时才调用 `saveRaw`，写盘异常继续向上传递。
   * - Error Handling: Non-array inputs or invalid path entries are skipped; `saveRaw` runs only when entries are actually added, and disk-write errors continue to bubble upward.
   * - 关键词: 名单追加 | allowlist append | 路径去重写入 | deduplicated path write | 增量持久化 | incremental persistence | 快照放行同步 | snapshot allow sync | 文件新增 | file addition
   */
  addFiles(paths) {
    const list = this.getList()
    const seen = new Set(list.map(it => it.type + '|' + this.normalize(it.path)))
    let changed = false
    for (const p of Array.isArray(paths) ? paths : []) {
      if (typeof p !== 'string' || !p) continue
      const key = 'file|' + this.normalize(p)
      if (!key || seen.has(key)) continue
      seen.add(key)
      list.push({ type: 'file', path: p })
      changed = true
    }
    if (changed) this.saveRaw(list)
    return list
  }
}

module.exports = StartupAllowlistManager
