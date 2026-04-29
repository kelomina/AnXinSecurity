const fs = require('fs')
const path = require('path')

/**
 * - 函数: `nextTick`
 * - Function: `nextTick`
 * - 作用: 梳理并返回nextTick负责的tick局部处理结果。
 * - Purpose: Coordinates and returns the tick processing result handled by nextTick.
 * - 调用方: `模块顶层流程`、`listFilesRecursively`、`walkerNext`。
 * - Callers: `模块顶层流程`, `listFilesRecursively`, `walkerNext`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `nextTick`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `nextTick` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: next | tick | next | tick | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function nextTick() {
  return new Promise((resolve) => setImmediate(resolve))
}

/**
 * - 函数: `normalizeForCompare`
 * - Function: `normalizeForCompare`
 * - 作用: 标准化forcompare输入，统一为当前模块后续逻辑可直接消费的结构。
 * - Purpose: Normalizes the for compare input into a structure that downstream logic can consume directly.
 * - 调用方: `模块顶层流程`、`compileExcludeList`、`isExcludedPath`。
 * - Callers: `模块顶层流程`, `compileExcludeList`, `isExcludedPath`.
 * - 被调方: `path.resolve`。
 * - Callees: `path.resolve`.
 * - 变量说明: `p` 为当前流程传入的p；`resolved` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `resolved` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `normalizeForCompare(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `normalizeForCompare(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 标准化 | for | compare | normalize | for | compare | call chain | 错误处理 | error handling | 复用
 */
function normalizeForCompare(p) {
  try {
    const resolved = path.resolve(String(p || ''))
    return resolved.replace(/\//g, '\\').toLowerCase()
  } catch {
    return String(p || '').replace(/\//g, '\\').toLowerCase()
  }
}

/**
 * - 函数: `compileExcludeList`
 * - Function: `compileExcludeList`
 * - 作用: 梳理并返回compileExcludeList负责的exclude列出局部处理结果。
 * - Purpose: Coordinates and returns the exclude list processing result handled by compileExcludeList.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `normalizeForCompare`、`push`、`Array.isArray`。
 * - Callees: `normalizeForCompare`, `push`, `Array.isArray`.
 * - 变量说明: `excludeList` 为当前流程传入的exclude列出；`out`, `src` 为函数内部派生的中间状态。
 * - Variables: `excludeList` is the incoming exclude list for this flow; `out`, `src` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `compileExcludeList(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `compileExcludeList(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: compile | exclude | 列出 | compile | exclude | list | call chain | 错误处理 | error handling | 复用
 */
function compileExcludeList(excludeList) {
  const out = []
  const src = Array.isArray(excludeList) ? excludeList : []
  for (const it of src) {
    if (!it) continue
    if (typeof it === 'string') {
      const n = normalizeForCompare(it)
      if (!n) continue
      const isDir = n.endsWith('\\') || n.endsWith(path.sep)
      out.push({ type: isDir ? 'dir' : 'file', n: isDir ? (n.endsWith('\\') ? n : (n + '\\')) : n })
      continue
    }
    const t = it.type === 'dir' ? 'dir' : (it.type === 'file' ? 'file' : null)
    const p = typeof it.path === 'string' ? it.path : ''
    if (!t || !p) continue
    const n = normalizeForCompare(p)
    if (!n) continue
    if (t === 'dir') {
      out.push({ type: 'dir', n: n.endsWith('\\') ? n : (n + '\\') })
    } else {
      out.push({ type: 'file', n })
    }
  }
  return out
}

/**
 * - 函数: `isExcludedPath`
 * - Function: `isExcludedPath`
 * - 作用: 判断excluded路径条件是否成立，并返回布尔化结果供上游守卫分支使用。
 * - Purpose: Checks whether the excluded path condition is satisfied and returns a boolean-style result for upstream guards.
 * - 调用方: `模块顶层流程`、`walkerNext`。
 * - Callers: `模块顶层流程`, `walkerNext`.
 * - 被调方: `normalizeForCompare`。
 * - Callees: `normalizeForCompare`.
 * - 变量说明: `p` 为当前流程传入的p；`compiledExclude` 为当前流程传入的compiledexclude；`n`, `ex` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `compiledExclude` is the incoming compiled exclude for this flow; `n`, `ex` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `isExcludedPath`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `isExcludedPath` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 判断 | excluded | 路径 | check | excluded | path | call chain | 错误处理 | error handling | 复用
 */
function isExcludedPath(p, compiledExclude) {
  if (!compiledExclude || compiledExclude.length === 0) return false
  const n = normalizeForCompare(p)
  if (!n) return false
  for (const ex of compiledExclude) {
    if (ex.type === 'file') {
      if (n === ex.n) return true
      continue
    }
    if (n === ex.n.slice(0, -1)) return true
    if (n.startsWith(ex.n)) return true
  }
  return false
}

/**
 * - 函数: `isDirectory`
 * - Function: `isDirectory`
 * - 作用: 判断目录条件是否成立，并返回布尔化结果供上游守卫分支使用。
 * - Purpose: Checks whether the directory condition is satisfied and returns a boolean-style result for upstream guards.
 * - 调用方: `listFilesRecursively`、`walkerNext`。
 * - Callers: `listFilesRecursively`, `walkerNext`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `p` 为当前流程传入的p；`st` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `st` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./fs_async').isDirectory` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./fs_async').isDirectory`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 判断 | 目录 | check | directory | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
async function isDirectory(p) {
  try {
    const st = await fs.promises.stat(p)
    return st.isDirectory()
  } catch {
    return false
  }
}

/**
 * - 函数: `fileSize`
 * - Function: `fileSize`
 * - 作用: 梳理并返回fileSize负责的大小局部处理结果。
 * - Purpose: Coordinates and returns the size processing result handled by fileSize.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `p` 为当前流程传入的p；`st` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `st` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./fs_async').fileSize` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./fs_async').fileSize`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 文件 | 大小 | file | size | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
async function fileSize(p) {
  try {
    const st = await fs.promises.stat(p)
    return st.size
  } catch {
    return -1
  }
}

/**
 * - 函数: `listFilesRecursively`
 * - Function: `listFilesRecursively`
 * - 作用: 列出filesrecursively集合，并返回上层展示或控制流程所需的列表结果。
 * - Purpose: Lists the files recursively collection and returns the list needed by upper-layer display or control flows.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `isDirectory`、`push`、`nextTick`、`path.join`。
 * - Callees: `isDirectory`, `push`, `nextTick`, `path.join`.
 * - 变量说明: `dir` 为当前流程传入的目录；`maxCount` 为当前流程传入的maxcount；`out`, `stack` 为函数内部派生的中间状态。
 * - Variables: `dir` is the incoming directory for this flow; `maxCount` is the incoming max count for this flow; `out`, `stack` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./fs_async').listFilesRecursively` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./fs_async').listFilesRecursively`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 列出 | files | recursively | list | files | recursively | call chain | 错误处理 | error handling | 复用
 */
async function listFilesRecursively(dir, maxCount) {
  const out = []
  const stack = [dir]
  let steps = 0

  while (stack.length) {
    const d = stack.pop()
    let entries
    try {
      entries = await fs.promises.readdir(d, { withFileTypes: true })
    } catch {
      continue
    }

    for (const e of entries) {
      const full = path.join(d, e.name)
      if (e.isDirectory()) stack.push(full)
      else out.push(full)
      if (maxCount && out.length >= maxCount) return out
    }

    steps++
    if (steps % 64 === 0) {
      await nextTick()
    }
  }

  return out
}

/**
 * - 函数: `listDriveRoots`
 * - Function: `listDriveRoots`
 * - 作用: 列出drive根目录集合集合，并返回上层展示或控制流程所需的列表结果。
 * - Purpose: Lists the drive root directories collection and returns the list needed by upper-layer display or control flows.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `push`。
 * - Callees: `push`.
 * - 变量说明: 无显式入参；`roots`, `letters`, `i` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `roots`, `letters`, `i` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 可通过 `require('./fs_async').listDriveRoots` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./fs_async').listDriveRoots`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 列出 | drive | 根目录集合 | list | drive | root directories | call chain | 错误处理 | error handling | 复用
 */
async function listDriveRoots() {
  const roots = []
  const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  for (let i = 0; i < letters.length; i++) {
    const root = letters[i] + ':\\'
    try {
      await fs.promises.access(root, fs.constants.F_OK)
      roots.push(root)
    } catch {}
  }
  roots.sort((a, b) => a.localeCompare(b))
  return roots
}

let walkers = {}
let walkerSeq = 1

/**
 * - 函数: `createWalker`
 * - Function: `createWalker`
 * - 作用: 创建walker实例或结构，并初始化后续流程依赖的基础状态。
 * - Purpose: Creates the walker instance or structure and initializes the baseline state required by later steps.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `roots` 为当前流程传入的根目录集合；`options` 为当前流程传入的options。
 * - Variables: `roots` is the incoming root directories for this flow; `options` is the incoming options for this flow.
 * - 接入方式: 可通过 `require('./fs_async').createWalker` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./fs_async').createWalker`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 创建 | walker | create | walker | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function createWalker(roots, options = {}) {
  const id = walkerSeq++
  const r = Array.isArray(roots) ? roots : [roots]
  const stack = r.map(v => String(v || '')).filter(Boolean)
  const excludeCompiled = compileExcludeList(options.excludeList)
  walkers[id] = { stack, excludeCompiled }
  return id
}

/**
 * - 函数: `walkerNext`
 * - Function: `walkerNext`
 * - 作用: 梳理并返回walkerNext负责的next局部处理结果。
 * - Purpose: Coordinates and returns the next processing result handled by walkerNext.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `isExcludedPath`、`isDirectory`、`push`、`nextTick`、`Number.isFinite`、`Math.max`。
 * - Callees: `isExcludedPath`, `isDirectory`, `push`, `nextTick`, `Number.isFinite`, `Math.max`.
 * - 变量说明: `id` 为当前流程传入的id；`limit` 为当前流程传入的limit；`w`, `out` 为函数内部派生的中间状态。
 * - Variables: `id` is the incoming id for this flow; `limit` is the incoming limit for this flow; `w`, `out` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./fs_async').walkerNext` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./fs_async').walkerNext`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: walker | next | walker | next | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
async function walkerNext(id, limit) {
  const w = walkers[id]
  if (!w) return { files: [], done: true }
  const out = []
  const lim = Number.isFinite(limit) ? Math.max(1, limit) : 512
  let steps = 0

  while (out.length < lim && w.stack.length > 0) {
    const d = w.stack.pop()
    if (isExcludedPath(d, w.excludeCompiled)) continue
    let entries
    try {
      entries = await fs.promises.readdir(d, { withFileTypes: true })
    } catch {
      entries = null
    }
    if (!entries) continue
    for (const e of entries) {
      const full = path.join(d, e.name)
      if (isExcludedPath(full, w.excludeCompiled)) continue
      if (e.isDirectory()) {
        w.stack.push(full)
      } else {
        out.push(full)
        if (out.length >= lim) break
      }
    }
    steps++
    if (steps % 32 === 0) {
      await nextTick()
    }
  }

  const done = w.stack.length === 0
  if (done) delete walkers[id]
  return { files: out, done }
}

/**
 * - 函数: `destroyWalker`
 * - Function: `destroyWalker`
 * - 作用: 梳理并返回destroyWalker负责的walker局部处理结果。
 * - Purpose: Coordinates and returns the walker processing result handled by destroyWalker.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `id` 为当前流程传入的id。
 * - Variables: `id` is the incoming id for this flow.
 * - 接入方式: 可通过 `require('./fs_async').destroyWalker` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./fs_async').destroyWalker`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: destroy | walker | destroy | walker | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function destroyWalker(id) {
  if (walkers[id]) delete walkers[id]
}

module.exports = {
  isDirectory,
  fileSize,
  listFilesRecursively,
  listDriveRoots,
  createWalker,
  walkerNext,
  destroyWalker
}
