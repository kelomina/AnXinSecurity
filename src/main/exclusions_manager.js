const fs = require('fs')
const path = require('path')
const CryptoManager = require('./crypto_manager')

class ExclusionsManager {
  /**
   * - 函数: `constructor`
   * - Function: `constructor`
   * - 作用: 初始化 ExclusionsManager 的实例状态，并准备后续方法依赖的数据。
   * - Purpose: Initializes the ExclusionsManager instance state and prepares data required by later methods.
   * - 调用方: 当前类实例、静态入口或外部类使用方。
   * - Callers: Current class instances, static entry points, or external class consumers.
   * - 被调方: CryptoManager, resolveStoragePath, loadImmutableDirs。
   * - Callees: CryptoManager, resolveStoragePath, loadImmutableDirs.
   * - 变量说明: 无显式入参；局部变量用于保存当前函数的中间状态。
   * - Variables: No explicit parameters; local variables keep intermediate state for this function.
   * - 接入方式: 通过 `new ExclusionsManager(...)` 创建实例后接入。
   * - Integration: Integrate by creating an instance with `new ExclusionsManager(...)`.
   * - 错误处理: 主要依赖前置守卫与返回值控制流程，未在函数内部集中处理异常。
   * - Error Handling: Relies on guard clauses and return values for control flow and does not centralize exception handling inside the function.
   * - 关键词: ExclusionsManager | class | 函数 | function | 模块 | module | 接入 | integration | 错误处理 | error-handling
   */
  constructor(configPath, immutableDirs = []) {
    this.configPath = configPath
    this.crypto = new CryptoManager(configPath, 'exclusions')
    this.storagePath = this.resolveStoragePath()
    this.immutableDirs = this.loadImmutableDirs(immutableDirs)
  }

  /**
 * - 函数: `resolveStoragePath`
 * - Function: `resolveStoragePath`
 * - 作用: 解析storage路径，并按当前运行环境返回优先可用的结果。
 * - Purpose: Resolves the storage path and returns the highest-priority usable result for the current runtime.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `fs.readFileSync`、`JSON.parse`、`path.join`、`path.dirname`、`fs.existsSync`。
 * - Callees: `fs.readFileSync`, `JSON.parse`, `path.join`, `path.dirname`, `fs.existsSync`.
 * - 变量说明: 无显式入参；`p`, `raw`, `cfg` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `p`, `raw`, `cfg` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 在当前模块内部直接调用 `resolveStoragePath(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `resolveStoragePath(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 解析 | storage | 路径 | resolve | storage | path | call chain | 错误处理 | error handling | 复用
 */
  resolveStoragePath() {
    let p = null
    try {
      const raw = fs.readFileSync(this.configPath, 'utf-8')
      const cfg = JSON.parse(raw)
      const rel = cfg && cfg.exclusions && cfg.exclusions.file ? cfg.exclusions.file : 'config/exclusions.enc'
      p = path.isAbsolute(rel) ? rel : path.join(path.dirname(this.configPath), '..', rel)
    } catch {
      p = path.join(path.dirname(this.configPath), '..', 'config', 'exclusions.enc')
    }
    const dir = path.dirname(p)
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    return p
  }

  /**
 * - 函数: `normalize`
 * - Function: `normalize`
 * - 作用: 标准化标准化输入，统一为当前模块后续逻辑可直接消费的结构。
 * - Purpose: Normalizes the normalize input into a structure that downstream logic can consume directly.
 * - 调用方: `模块顶层流程`、`loadImmutableDirs`、`getList`、`setList`、`addFile`、`addDir`。
 * - Callers: `模块顶层流程`, `loadImmutableDirs`, `getList`, `setList`, `addFile`, `addDir`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `p` 为当前流程传入的p。
 * - Variables: `p` is the incoming p for this flow.
 * - 接入方式: 在当前模块内部直接调用 `normalize(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `normalize(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 标准化 | normalize | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  normalize(p) {
    if (!p || typeof p !== 'string') return ''
    return path.normalize(p).toLowerCase()
  }

  /**
 * - 函数: `loadImmutableDirs`
 * - Function: `loadImmutableDirs`
 * - 作用: 加载immutabledirs资源，并返回后续逻辑可以直接复用的数据或实例。
 * - Purpose: Loads the immutable dirs resource and returns data or instances that downstream logic can reuse.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `push`、`normalize`、`fs.readFileSync`、`JSON.parse`、`Array.isArray`。
 * - Callees: `push`, `normalize`, `fs.readFileSync`, `JSON.parse`, `Array.isArray`.
 * - 变量说明: `immutableDirs` 为当前流程传入的immutabledirs；`staticPaths`, `raw` 为函数内部派生的中间状态。
 * - Variables: `immutableDirs` is the incoming immutable dirs for this flow; `staticPaths`, `raw` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `loadImmutableDirs(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `loadImmutableDirs(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 加载 | immutable | dirs | load | immutable | dirs | call chain | 错误处理 | error handling | 复用
 */
  loadImmutableDirs(immutableDirs) {
    let staticPaths = []
    try {
      const raw = fs.readFileSync(this.configPath, 'utf-8')
      const cfg = JSON.parse(raw)
      staticPaths = (cfg && cfg.exclusions && Array.isArray(cfg.exclusions.protectedPaths)) ? cfg.exclusions.protectedPaths : []
    } catch {}
    const out = []
    for (const p of staticPaths) {
      if (typeof p === 'string' && p) out.push(p)
    }
    for (const d of Array.isArray(immutableDirs) ? immutableDirs : []) {
      if (typeof d === 'string' && d) out.push(d)
    }
    const uniq = []
    const seen = new Set()
    for (const p of out) {
      const n = this.normalize(p)
      if (!n) continue
      if (seen.has(n)) continue
      seen.add(n)
      uniq.push({ original: p, normalized: n })
    }
    return uniq
  }

  /**
 * - 函数: `getImmutableDirs`
 * - Function: `getImmutableDirs`
 * - 作用: 读取并汇总immutabledirs，返回当前流程消费的快照或配置结果。
 * - Purpose: Reads and aggregates the immutable dirs into a snapshot or config result for the current flow.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `getImmutableDirs(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `getImmutableDirs(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 获取 | immutable | dirs | get | immutable | dirs | call chain | 错误处理 | error handling | 复用
 */
  getImmutableDirs() {
    return this.immutableDirs.map(it => it.original)
  }

  /**
 * - 函数: `loadRaw`
 * - Function: `loadRaw`
 * - 作用: 加载raw资源，并返回后续逻辑可以直接复用的数据或实例。
 * - Purpose: Loads the raw resource and returns data or instances that downstream logic can reuse.
 * - 调用方: `模块顶层流程`、`getList`。
 * - Callers: `模块顶层流程`, `getList`.
 * - 被调方: `decryptText`、`fs.existsSync`、`fs.readFileSync`、`JSON.parse`。
 * - Callees: `decryptText`, `fs.existsSync`, `fs.readFileSync`, `JSON.parse`.
 * - 变量说明: 无显式入参；`raw`, `payload`, `text` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `raw`, `payload`, `text` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 在当前模块内部直接调用 `loadRaw(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `loadRaw(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 加载 | raw | load | raw | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
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
 * - 作用: 梳理并返回saveRaw负责的raw局部处理结果。
 * - Purpose: Coordinates and returns the raw processing result handled by saveRaw.
 * - 调用方: `模块顶层流程`、`setList`、`addFile`、`addDir`、`remove`。
 * - Callers: `模块顶层流程`, `setList`, `addFile`, `addDir`, `remove`.
 * - 被调方: `encryptText`、`JSON.stringify`、`Array.isArray`、`fs.writeFileSync`。
 * - Callees: `encryptText`, `JSON.stringify`, `Array.isArray`, `fs.writeFileSync`.
 * - 变量说明: `list` 为当前流程传入的列出；`payload` 为函数内部派生的中间状态。
 * - Variables: `list` is the incoming list for this flow; `payload` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `saveRaw(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `saveRaw(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: save | raw | save | raw | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  saveRaw(list) {
    const payload = this.crypto.encryptText(JSON.stringify(Array.isArray(list) ? list : []))
    fs.writeFileSync(this.storagePath, JSON.stringify(payload, null, 2), 'utf-8')
  }

  /**
 * - 函数: `getImmutableList`
 * - Function: `getImmutableList`
 * - 作用: 读取并汇总immutable列出，返回当前流程消费的快照或配置结果。
 * - Purpose: Reads and aggregates the immutable list into a snapshot or config result for the current flow.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `getImmutableList(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `getImmutableList(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 获取 | immutable | 列出 | get | immutable | list | call chain | 错误处理 | error handling | 复用
 */
  getImmutableList() {
    return this.immutableDirs.map(it => ({ type: 'dir', path: it.original }))
  }

  /**
 * - 函数: `getList`
 * - Function: `getList`
 * - 作用: 读取并汇总列出，返回当前流程消费的快照或配置结果。
 * - Purpose: Reads and aggregates the list into a snapshot or config result for the current flow.
 * - 调用方: `模块顶层流程`、`addFile`、`addDir`、`remove`、`isExcluded`。
 * - Callers: `模块顶层流程`, `addFile`, `addDir`, `remove`, `isExcluded`.
 * - 被调方: `loadRaw`、`normalize`、`Array.isArray`。
 * - Callees: `loadRaw`, `normalize`, `Array.isArray`.
 * - 变量说明: 无显式入参；`data`, `list`, `n` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `data`, `list`, `n` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 在当前模块内部直接调用 `getList(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `getList(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 获取 | 列出 | get | list | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  getList() {
    const data = this.loadRaw()
    if (!Array.isArray(data)) return []
    const list = data.map(it => ({
      type: it && it.type === 'dir' ? 'dir' : 'file',
      path: it && it.path ? it.path : ''
    })).filter(it => it.path)
    
    return list.filter(it => {
      const n = this.normalize(it.path)
      for (const d of this.immutableDirs) {
        if (it.type === 'file') {
          if (n.startsWith(d.normalized)) return false
        } else {
          if (n.startsWith(d.normalized)) return false
        }
      }
      return true
    })
  }

  /**
 * - 函数: `setList`
 * - Function: `setList`
 * - 作用: 设置列出状态，并同步影响当前模块内的后续判断。
 * - Purpose: Sets the list state and synchronizes the downstream decisions made inside this module.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `normalize`、`push`、`saveRaw`、`Array.isArray`。
 * - Callees: `normalize`, `push`, `saveRaw`, `Array.isArray`.
 * - 变量说明: `list` 为当前流程传入的列出；`dedup`, `seen` 为函数内部派生的中间状态。
 * - Variables: `list` is the incoming list for this flow; `dedup`, `seen` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `setList(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `setList(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 设置 | 列出 | set | list | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  setList(list) {
    const dedup = []
    const seen = new Set()
    for (const it of Array.isArray(list) ? list : []) {
      const type = it && it.type === 'dir' ? 'dir' : 'file'
      const p = it && it.path ? it.path : ''
      if (!p) continue
      const key = type + '|' + this.normalize(p)
      if (seen.has(key)) continue
      seen.add(key)
      dedup.push({ type, path: p })
    }
    this.saveRaw(dedup)
    return dedup
  }

  /**
 * - 函数: `addFile`
 * - Function: `addFile`
 * - 作用: 梳理并返回addFile负责的文件局部处理结果。
 * - Purpose: Coordinates and returns the file processing result handled by addFile.
 * - 调用方: `模块顶层流程`、`initExclusions`。
 * - Callers: `模块顶层流程`, `initExclusions`.
 * - 被调方: `getList`、`normalize`、`push`、`saveRaw`。
 * - Callees: `getList`, `normalize`, `push`, `saveRaw`.
 * - 变量说明: `p` 为当前流程传入的p；`list`, `key` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `list`, `key` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `addFile(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `addFile(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: add | 文件 | add | file | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  addFile(p) {
    const list = this.getList()
    const key = 'file|' + this.normalize(p)
    const exists = list.some(it => ('file|' + this.normalize(it.path)) === key)
    if (exists) return list
    list.push({ type: 'file', path: p })
    this.saveRaw(list)
    return list
  }

  /**
 * - 函数: `addDir`
 * - Function: `addDir`
 * - 作用: 梳理并返回addDir负责的目录局部处理结果。
 * - Purpose: Coordinates and returns the directory processing result handled by addDir.
 * - 调用方: `模块顶层流程`、`initExclusions`。
 * - Callers: `模块顶层流程`, `initExclusions`.
 * - 被调方: `getList`、`normalize`、`push`、`saveRaw`。
 * - Callees: `getList`, `normalize`, `push`, `saveRaw`.
 * - 变量说明: `p` 为当前流程传入的p；`list`, `key` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `list`, `key` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `addDir(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `addDir(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: add | 目录 | add | directory | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  addDir(p) {
    const list = this.getList()
    const key = 'dir|' + this.normalize(p)
    const exists = list.some(it => ('dir|' + this.normalize(it.path)) === key)
    if (exists) return list
    list.push({ type: 'dir', path: p })
    this.saveRaw(list)
    return list
  }

  /**
 * - 函数: `remove`
 * - Function: `remove`
 * - 作用: 梳理并返回remove负责的remove局部处理结果。
 * - Purpose: Coordinates and returns the remove processing result handled by remove.
 * - 调用方: `模块顶层流程`、`render`、`showConfirm`、`setActiveNav`、`resetScanUi`、`updateScanMetricsUi`。
 * - Callers: `模块顶层流程`, `render`, `showConfirm`, `setActiveNav`, `resetScanUi`, `updateScanMetricsUi`.
 * - 被调方: `normalize`、`getList`、`saveRaw`。
 * - Callees: `normalize`, `getList`, `saveRaw`.
 * - 变量说明: `p` 为当前流程传入的p；`target`, `d` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `target`, `d` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `remove(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `remove(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: remove | remove | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  remove(p) {
    const target = this.normalize(p)
    for (const d of this.immutableDirs) {
      if (target === d.normalized) {
        return this.getList()
      }
    }
    const list = this.getList()
    const out = list.filter(it => this.normalize(it.path) !== target)
    this.saveRaw(out)
    return out
  }

  /**
 * - 函数: `isExcluded`
 * - Function: `isExcluded`
 * - 作用: 判断excluded条件是否成立，并返回布尔化结果供上游守卫分支使用。
 * - Purpose: Checks whether the excluded condition is satisfied and returns a boolean-style result for upstream guards.
 * - 调用方: `模块顶层流程`、`shouldScanFile`。
 * - Callers: `模块顶层流程`, `shouldScanFile`.
 * - 被调方: `normalize`、`getList`。
 * - Callees: `normalize`, `getList`.
 * - 变量说明: `p` 为当前流程传入的p；`target`, `d` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `target`, `d` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `isExcluded(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `isExcluded(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 判断 | excluded | check | excluded | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  isExcluded(p) {
    const target = this.normalize(p)
    for (const d of this.immutableDirs) {
      if (target.startsWith(d.normalized)) return true
    }
    const list = this.getList()
    for (const it of list) {
      const np = this.normalize(it.path)
      if (it.type === 'file') {
        if (target === np) return true
      } else {
        if (target.startsWith(np)) return true
      }
    }
    return false
  }
}

module.exports = ExclusionsManager
