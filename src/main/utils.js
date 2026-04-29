const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

/**
 * - 函数: `resolveProjectRootDir`
 * - Function: `resolveProjectRootDir`
 * - 作用: 解析project根目录目录，并按当前运行环境返回优先可用的结果。
 * - Purpose: Resolves the project root directory directory and returns the highest-priority usable result for the current runtime.
 * - 调用方: `resolveProjectDataDir`。
 * - Callers: `resolveProjectDataDir`.
 * - 被调方: `path.resolve`。
 * - Callees: `path.resolve`.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 可通过 `require('./utils').resolveProjectRootDir` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').resolveProjectRootDir`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 解析 | project | 根目录 | 目录 | resolve | project | root directory | directory | error handling | 复用
 */
function resolveProjectRootDir() {
  try {
    return path.resolve(__dirname, '../..');
  } catch {
    return process.cwd();
  }
}

/**
 * - 函数: `resolveProjectDataDir`
 * - Function: `resolveProjectDataDir`
 * - 作用: 解析project数据目录，并按当前运行环境返回优先可用的结果。
 * - Purpose: Resolves the project data directory and returns the highest-priority usable result for the current runtime.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `resolveProjectRootDir`、`path.join`、`fs.existsSync`、`fs.mkdirSync`。
 * - Callees: `resolveProjectRootDir`, `path.join`, `fs.existsSync`, `fs.mkdirSync`.
 * - 变量说明: `rel` 为当前流程传入的rel；`root`, `base` 为函数内部派生的中间状态。
 * - Variables: `rel` is the incoming rel for this flow; `root`, `base` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./utils').resolveProjectDataDir` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').resolveProjectDataDir`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 解析 | project | 数据 | 目录 | resolve | project | data | directory | error handling | 复用
 */
function resolveProjectDataDir(rel = '') {
  const root = resolveProjectRootDir();
  const base = path.join(root, 'data');
  try {
    if (!fs.existsSync(base)) fs.mkdirSync(base, { recursive: true });
  } catch {}
  return rel ? path.join(base, rel) : base;
}

/**
 * - 函数: `killRelatedProcess`
 * - Function: `killRelatedProcess`
 * - 作用: 梳理并返回killRelatedProcess负责的related处理局部处理结果。
 * - Purpose: Coordinates and returns the related process processing result handled by killRelatedProcess.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `path.basename`。
 * - Callees: `path.basename`.
 * - 变量说明: `filePath` 为当前流程传入的文件路径；`fileName` 为函数内部派生的中间状态。
 * - Variables: `filePath` is the incoming file path for this flow; `fileName` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./utils').killRelatedProcess` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').killRelatedProcess`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: kill | related | 处理 | kill | related | process | call chain | 错误处理 | error handling | 复用
 */
async function killRelatedProcess(filePath) {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve();
    
    const fileName = path.basename(filePath);
    if (!fileName.toLowerCase().endsWith('.exe')) return resolve();

    exec(`taskkill /F /IM "${fileName}"`, (err, stdout, stderr) => {
      setTimeout(resolve, 500);
    });
  });
}

/**
 * - 函数: `forceDelete`
 * - Function: `forceDelete`
 * - 作用: 梳理并返回forceDelete负责的delete局部处理结果。
 * - Purpose: Coordinates and returns the delete processing result handled by forceDelete.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `fs.existsSync`。
 * - Callees: `fs.existsSync`.
 * - 变量说明: `filePath` 为当前流程传入的文件路径；`i` 为函数内部派生的中间状态。
 * - Variables: `filePath` is the incoming file path for this flow; `i` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./utils').forceDelete` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').forceDelete`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 内部通过 `try/catch` 拦截局部异常；无法自行恢复时，会把错误继续抛给上游调用方处理。
 * - Error Handling: Uses `try/catch` to intercept local failures and rethrows or rejects unrecoverable errors back to upstream callers.
 * - 关键词: force | delete | force | delete | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
async function forceDelete(filePath) {
  for (let i = 0; i < 3; i++) {
    try {
      if (!fs.existsSync(filePath)) return;
      fs.unlinkSync(filePath);
      return;
    } catch (e) {
      try {
          await new Promise((resolve, reject) => {
              exec(`del /f /q "${filePath}"`, (err) => {
                  if (err) reject(err);
                  else resolve();
              });
          });
          if (!fs.existsSync(filePath)) return;
      } catch {}
      
      await new Promise(r => setTimeout(r, 200 * (i + 1)));
    }
  }
  if (fs.existsSync(filePath)) {
      throw new Error('Cannot delete file: ' + filePath);
  }
}

/**
 * - 函数: `resolveFileFromBaseDirs`
 * - Function: `resolveFileFromBaseDirs`
 * - 作用: 解析文件frombasedirs，并按当前运行环境返回优先可用的结果。
 * - Purpose: Resolves the file from base dirs and returns the highest-priority usable result for the current runtime.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `Array.isArray`、`path.join`、`fs.existsSync`。
 * - Callees: `Array.isArray`, `path.join`, `fs.existsSync`.
 * - 变量说明: `baseDirs` 为当前流程传入的basedirs；`relativeFilePath` 为当前流程传入的relative文件路径；`rel`, `dirs` 为函数内部派生的中间状态。
 * - Variables: `baseDirs` is the incoming base dirs for this flow; `relativeFilePath` is the incoming relative file path for this flow; `rel`, `dirs` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./utils').resolveFileFromBaseDirs` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').resolveFileFromBaseDirs`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 解析 | 文件 | from | base | dirs | resolve | file | from | base | dirs
 */
function resolveFileFromBaseDirs(baseDirs, relativeFilePath) {
  const rel = typeof relativeFilePath === 'string' ? relativeFilePath.trim() : ''
  if (!rel) return ''
  const dirs = Array.isArray(baseDirs) ? baseDirs : []
  for (const dir of dirs) {
    if (typeof dir !== 'string' || !dir) continue
    try {
      const p = path.join(dir, rel)
      if (fs.existsSync(p)) return p
    } catch {}
  }
  return ''
}

/**
 * - 函数: `formatEtwEventForConsole`
 * - Function: `formatEtwEventForConsole`
 * - 作用: 格式化etw事件forconsole内容，输出更适合展示、日志或后续传输的结构。
 * - Purpose: Formats the etw event for console content into a structure that is easier to display, log, or transmit.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `clean`、`Number.isFinite`。
 * - Callees: `clean`, `Number.isFinite`.
 * - 变量说明: `event` 为当前流程传入的事件；`clean`, `out` 为函数内部派生的中间状态。
 * - Variables: `event` is the incoming event for this flow; `clean`, `out` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./utils').formatEtwEventForConsole` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').formatEtwEventForConsole`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 格式化 | etw | 事件 | for | console | format | etw | event | for | console
 */
function formatEtwEventForConsole(event) {
  if (!event || typeof event !== 'object') return ''
  /**
 * - 函数: `clean`
 * - Function: `clean`
 * - 作用: 梳理并返回clean负责的clean局部处理结果。
 * - Purpose: Coordinates and returns the clean processing result handled by clean.
 * - 调用方: `formatEtwEventForConsole`。
 * - Callers: `formatEtwEventForConsole`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `s` 为当前流程传入的s；`out` 为函数内部派生的中间状态。
 * - Variables: `s` is the incoming s for this flow; `out` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `clean(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `clean(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: clean | clean | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  const clean = (s) => {
    if (typeof s !== 'string') return ''
    let out = s.replace(/\uFFFD/g, '')
    out = out.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '')
    out = out.replace(/\s+/g, ' ').trim()
    return out
  }
  const ts = typeof event.timestamp === 'string' ? event.timestamp : ''
  const provider = typeof event.provider === 'string' ? event.provider : ''
  const opcode = Number.isFinite(event.opcode) ? event.opcode : ''
  const id = Number.isFinite(event.id) ? event.id : ''
  const pid = Number.isFinite(event.pid) ? event.pid : ''
  const tid = Number.isFinite(event.tid) ? event.tid : ''
  const data = (event.data && typeof event.data === 'object') ? event.data : {}
  const type = clean(typeof data.type === 'string' ? data.type : '')
  const imageName = clean(typeof data.imageName === 'string' ? data.imageName : '')
  const fileName = clean(typeof data.fileName === 'string' ? data.fileName : '')
  const keyPath = clean(typeof data.keyPath === 'string' ? data.keyPath : '')
  const valueName = clean(typeof data.valueName === 'string' ? data.valueName : '')
  const parts = [
    clean(ts),
    clean(provider),
    type || (id !== '' ? ('id=' + id) : ''),
    pid !== '' ? ('pid=' + pid) : '',
    tid !== '' ? ('tid=' + tid) : '',
    opcode !== '' ? ('op=' + opcode) : '',
    imageName ? ('image=' + imageName) : '',
    fileName ? ('file=' + fileName) : '',
    keyPath ? ('key=' + keyPath) : '',
    valueName ? ('value=' + valueName) : ''
  ].filter(Boolean)
  return parts.join(' ')
}

/**
 * - 函数: `formatEtwEventForParsedConsole`
 * - Function: `formatEtwEventForParsedConsole`
 * - 作用: 格式化etw事件forparsedconsole内容，输出更适合展示、日志或后续传输的结构。
 * - Purpose: Formats the etw event for parsed console content into a structure that is easier to display, log, or transmit.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `sanitizeText`、`JSON.parse`、`JSON.stringify`。
 * - Callees: `sanitizeText`, `JSON.parse`, `JSON.stringify`.
 * - 变量说明: `event` 为当前流程传入的事件；`out`, `data` 为函数内部派生的中间状态。
 * - Variables: `event` is the incoming event for this flow; `out`, `data` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./utils').formatEtwEventForParsedConsole` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').formatEtwEventForParsedConsole`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 格式化 | etw | 事件 | for | parsed | format | etw | event | for | parsed
 */
function formatEtwEventForParsedConsole(event) {
  if (!event || typeof event !== 'object') return ''
  try {
    const out = JSON.parse(JSON.stringify(event))
    if (out && typeof out === 'object') {
      if (typeof out.processName === 'string') out.processName = sanitizeText(out.processName)
      if (typeof out.processImage === 'string') out.processImage = sanitizeText(out.processImage)
      const data = (out.data && typeof out.data === 'object') ? out.data : null
      if (data) {
        if (typeof data.type === 'string') data.type = sanitizeText(data.type)
        if (typeof data.imageName === 'string') data.imageName = sanitizeText(data.imageName)
        if (typeof data.fileName === 'string') data.fileName = sanitizeText(data.fileName)
        if (typeof data.keyPath === 'string') data.keyPath = sanitizeText(data.keyPath)
        if (typeof data.valueName === 'string') data.valueName = sanitizeText(data.valueName)
      }
    }
    return JSON.stringify(out)
  } catch {
    return ''
  }
}

/**
 * - 函数: `resolveEtwOpMeaning`
 * - Function: `resolveEtwOpMeaning`
 * - 作用: 解析etwopmeaning，并按当前运行环境返回优先可用的结果。
 * - Purpose: Resolves the etw op meaning and returns the highest-priority usable result for the current runtime.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `Number.isFinite`。
 * - Callees: `Number.isFinite`.
 * - 变量说明: `event` 为当前流程传入的事件；`provider`, `data` 为函数内部派生的中间状态。
 * - Variables: `event` is the incoming event for this flow; `provider`, `data` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./utils').resolveEtwOpMeaning` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').resolveEtwOpMeaning`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 解析 | etw | op | meaning | resolve | etw | op | meaning | error handling | 复用
 */
function resolveEtwOpMeaning(event) {
  if (!event || typeof event !== 'object') return null
  const provider = typeof event.provider === 'string' ? event.provider : ''
  const data = (event.data && typeof event.data === 'object') ? event.data : {}
  const type = typeof data.type === 'string' ? data.type : ''
  const id = Number.isFinite(event.id) ? event.id : null
  const opcode = Number.isFinite(event.opcode) ? event.opcode : null

  const registryIdMap = {
    1: 'CreateKey',
    2: 'OpenKey',
    3: 'DeleteKey',
    4: 'QueryValue',
    5: 'SetValue',
    6: 'DeleteValue',
    7: 'QueryKey',
    8: 'EnumerateKey',
    9: 'EnumerateValue',
    10: 'QueryMultipleValue',
    11: 'SetInformationKey',
    12: 'FlushKey',
    13: 'CloseKey',
    14: 'SetSecurityKey',
    15: 'QuerySecurityKey',
    16: 'RenameKey'
  }

  if (provider === 'Registry') {
    if (type && !/^EventId_\d+$/i.test(type)) return type
    if (id != null && registryIdMap[id]) return registryIdMap[id]
    if (type) return type
    return null
  }

  if (type) return type

  if (provider === 'Process') {
    if (opcode === 1) return 'Start'
    if (opcode === 2) return 'Stop'
    return null
  }
  if (provider === 'File') {
    if (opcode === 32) return 'Create'
    if (opcode === 35) return 'Delete'
    if (opcode === 36) return 'Rename'
    return null
  }
  return null
}

/**
 * - 函数: `parseEtwEventFromConsoleLine`
 * - Function: `parseEtwEventFromConsoleLine`
 * - 作用: 解析etw事件fromconsoleline原始输入，并提取结构化结果供后续逻辑使用。
 * - Purpose: Parses the raw etw event from console line input and extracts a structured result for downstream logic.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `isKeyToken`、`push`、`toInt`、`JSON.parse`、`Number.isFinite`。
 * - Callees: `isKeyToken`, `push`, `toInt`, `JSON.parse`, `Number.isFinite`.
 * - 变量说明: `line` 为当前流程传入的line；`s`, `obj` 为函数内部派生的中间状态。
 * - Variables: `line` is the incoming line for this flow; `s`, `obj` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./utils').parseEtwEventFromConsoleLine` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').parseEtwEventFromConsoleLine`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 解析 | etw | 事件 | from | console | parse | etw | event | from | console
 */
function parseEtwEventFromConsoleLine(line) {
  if (typeof line !== 'string') return null
  let s = line.trim()
  if (!s) return null
  if (s.startsWith('ETW:')) s = s.slice(4).trim()
  if (!s) return null

  if (s[0] === '{' && s.endsWith('}')) {
    try {
      const obj = JSON.parse(s)
      return (obj && typeof obj === 'object') ? obj : null
    } catch {}
  }

  const tokens = s.split(/\s+/).filter(Boolean)
  if (tokens.length < 2) return null

  const timestamp = tokens[0]
  const provider = tokens[1]

  const knownKeys = new Set(['pid', 'tid', 'op', 'id', 'image', 'file', 'key', 'value'])
  /**
 * - 函数: `isKeyToken`
 * - Function: `isKeyToken`
 * - 作用: 判断键token条件是否成立，并返回布尔化结果供上游守卫分支使用。
 * - Purpose: Checks whether the key token condition is satisfied and returns a boolean-style result for upstream guards.
 * - 调用方: `parseEtwEventFromConsoleLine`。
 * - Callers: `parseEtwEventFromConsoleLine`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `t` 为当前流程传入的t；`idx` 为函数内部派生的中间状态。
 * - Variables: `t` is the incoming t for this flow; `idx` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `isKeyToken(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `isKeyToken(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 判断 | 键 | token | check | key | token | call chain | 错误处理 | error handling | 复用
 */
  const isKeyToken = (t) => {
    const idx = t.indexOf('=')
    if (idx <= 0) return false
    return knownKeys.has(t.slice(0, idx))
  }

  let typeParts = []
  const kv = Object.create(null)

  for (let i = 2; i < tokens.length; i++) {
    const t = tokens[i]
    if (!isKeyToken(t)) {
      if (Object.keys(kv).length === 0) typeParts.push(t)
      else {
        const lastKey = kv.__lastKey
        if (lastKey) kv[lastKey] = (kv[lastKey] ? (kv[lastKey] + ' ' + t) : t)
      }
      continue
    }

    const eq = t.indexOf('=')
    const k = t.slice(0, eq)
    let v = t.slice(eq + 1)
    kv[k] = v
    kv.__lastKey = k
  }

  delete kv.__lastKey

  /**
 * - 函数: `toInt`
 * - Function: `toInt`
 * - 作用: 梳理并返回toInt负责的int局部处理结果。
 * - Purpose: Coordinates and returns the int processing result handled by toInt.
 * - 调用方: `parseEtwEventFromConsoleLine`。
 * - Callers: `parseEtwEventFromConsoleLine`.
 * - 被调方: `Number.isFinite`。
 * - Callees: `Number.isFinite`.
 * - 变量说明: `v` 为当前流程传入的v；`n` 为函数内部派生的中间状态。
 * - Variables: `v` is the incoming v for this flow; `n` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `toInt(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `toInt(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: to | int | to | int | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  const toInt = (v) => {
    if (typeof v !== 'string' || !v) return null
    const n = Number(v)
    if (!Number.isFinite(n)) return null
    return Math.trunc(n)
  }

  const data = {}
  const type = typeParts.join(' ').trim()
  if (type) data.type = type
  if (typeof kv.image === 'string' && kv.image) data.imageName = kv.image
  if (typeof kv.file === 'string' && kv.file) data.fileName = kv.file
  if (typeof kv.key === 'string' && kv.key) data.keyPath = kv.key
  if (typeof kv.value === 'string' && kv.value) data.valueName = kv.value

  let id = toInt(kv.id)
  if (id === null && data.type) {
    const m = /^EventId_(\d+)$/i.exec(data.type)
    if (m) id = toInt(m[1])
  }

  const event = {
    timestamp,
    provider,
    data
  }

  const pid = toInt(kv.pid)
  const tid = toInt(kv.tid)
  const opcode = toInt(kv.op)
  if (pid !== null) event.pid = pid
  if (tid !== null) event.tid = tid
  if (opcode !== null) event.opcode = opcode
  if (id !== null) event.id = id

  return event
}

/**
 * - 函数: `createRateLimiter`
 * - Function: `createRateLimiter`
 * - 作用: 创建ratelimiter实例或结构，并初始化后续流程依赖的基础状态。
 * - Purpose: Creates the rate limiter instance or structure and initializes the baseline state required by later steps.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `Number.isFinite`、`Math.max`、`Math.floor`、`Date.now`。
 * - Callees: `Number.isFinite`, `Math.max`, `Math.floor`, `Date.now`.
 * - 变量说明: `maxPerSecond` 为当前流程传入的maxpersecond；`nowFn` 为当前流程传入的nowfn；`limit`, `now` 为函数内部派生的中间状态。
 * - Variables: `maxPerSecond` is the incoming max per second for this flow; `nowFn` is the incoming now fn for this flow; `limit`, `now` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./utils').createRateLimiter` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').createRateLimiter`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 创建 | rate | limiter | create | rate | limiter | call chain | 错误处理 | error handling | 复用
 */
function createRateLimiter(maxPerSecond, nowFn) {
  const limit = Number.isFinite(maxPerSecond) ? Math.max(0, Math.floor(maxPerSecond)) : 0
  const now = typeof nowFn === 'function' ? nowFn : () => Date.now()
  let windowStart = now()
  let count = 0
  return () => {
    if (!limit) return false
    const t = now()
    if (t - windowStart >= 1000) {
      windowStart = t
      count = 0
    }
    if (count >= limit) return false
    count++
    return true
  }
}

/**
 * - 函数: `sanitizeText`
 * - Function: `sanitizeText`
 * - 作用: 梳理并返回sanitizeText负责的文本局部处理结果。
 * - Purpose: Coordinates and returns the text processing result handled by sanitizeText.
 * - 调用方: `formatEtwEventForParsedConsole`、`normalizeWindowsPathText`。
 * - Callers: `formatEtwEventForParsedConsole`, `normalizeWindowsPathText`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `s` 为当前流程传入的s。
 * - Variables: `s` is the incoming s for this flow.
 * - 接入方式: 可通过 `require('./utils').sanitizeText` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').sanitizeText`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: sanitize | 文本 | sanitize | text | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
function sanitizeText(s) {
  if (typeof s !== 'string' || !s) return ''
  return s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFD]/g, '').trim()
}

/**
 * - 函数: `normalizeWindowsPathText`
 * - Function: `normalizeWindowsPathText`
 * - 作用: 标准化windows路径文本输入，统一为当前模块后续逻辑可直接消费的结构。
 * - Purpose: Normalizes the windows path text input into a structure that downstream logic can consume directly.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `sanitizeText`。
 * - Callees: `sanitizeText`.
 * - 变量说明: `v` 为当前流程传入的v；`devicePathToDosPath` 为当前流程传入的device路径todos路径；`s`, `converted` 为函数内部派生的中间状态。
 * - Variables: `v` is the incoming v for this flow; `devicePathToDosPath` is the incoming device path to dos path for this flow; `s`, `converted` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./utils').normalizeWindowsPathText` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').normalizeWindowsPathText`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: 标准化 | windows | 路径 | 文本 | normalize | windows | path | text | error handling | 复用
 */
function normalizeWindowsPathText(v, devicePathToDosPath) {
  if (typeof v !== 'string' || !v) return v
  let s = sanitizeText(v)
  if (!s) return s
  if (typeof devicePathToDosPath === 'function') {
    try {
      const converted = devicePathToDosPath(s)
      if (typeof converted === 'string' && converted) s = converted
    } catch {}
  }
  return sanitizeText(s)
}

/**
 * - 函数: `isBehaviorMonitoringEnabled`
 * - Function: `isBehaviorMonitoringEnabled`
 * - 作用: 判断behaviormonitoringenabled条件是否成立，并返回布尔化结果供上游守卫分支使用。
 * - Purpose: Checks whether the behavior monitoring enabled condition is satisfied and returns a boolean-style result for upstream guards.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `appConfig` 为当前流程传入的app配置；`cfg`, `bm` 为函数内部派生的中间状态。
 * - Variables: `appConfig` is the incoming app config for this flow; `cfg`, `bm` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./utils').isBehaviorMonitoringEnabled` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').isBehaviorMonitoringEnabled`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 判断 | behavior | monitoring | enabled | check | behavior | monitoring | enabled | error handling | 复用
 */
function isBehaviorMonitoringEnabled(appConfig) {
  const cfg = appConfig && typeof appConfig === 'object' ? appConfig : {}
  const bm = cfg && cfg.behaviorMonitoring && typeof cfg.behaviorMonitoring === 'object' ? cfg.behaviorMonitoring : {}
  return bm.enabled !== false
}

/**
 * - 函数: `isCleanText`
 * - Function: `isCleanText`
 * - 作用: 判断clean文本条件是否成立，并返回布尔化结果供上游守卫分支使用。
 * - Purpose: Checks whether the clean text condition is satisfied and returns a boolean-style result for upstream guards.
 * - 调用方: `isLikelyProcessImageText`。
 * - Callers: `isLikelyProcessImageText`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `s` 为当前流程传入的s。
 * - Variables: `s` is the incoming s for this flow.
 * - 接入方式: 可通过 `require('./utils').isCleanText` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').isCleanText`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 判断 | clean | 文本 | check | clean | text | call chain | 错误处理 | error handling | 复用
 */
function isCleanText(s) {
  if (typeof s !== 'string' || !s) return false
  return !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFD]/.test(s)
}

/**
 * - 函数: `isLikelyWindowsPath`
 * - Function: `isLikelyWindowsPath`
 * - 作用: 判断可能性windows路径条件是否成立，并返回布尔化结果供上游守卫分支使用。
 * - Purpose: Checks whether the likelihood windows path condition is satisfied and returns a boolean-style result for upstream guards.
 * - 调用方: `isLikelyProcessImagePath`。
 * - Callers: `isLikelyProcessImagePath`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `p` 为当前流程传入的p；`s` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `s` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./utils').isLikelyWindowsPath` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').isLikelyWindowsPath`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 判断 | 可能性 | windows | 路径 | check | likelihood | windows | path | error handling | 复用
 */
function isLikelyWindowsPath(p) {
  if (typeof p !== 'string') return false
  const s = p.trim()
  if (!s) return false
  if (/^[a-zA-Z]:[\\/]/.test(s)) return true
  if (s.startsWith('\\\\?\\') || s.startsWith('\\\\.\\')) return true
  if (s.startsWith('\\\\')) return true
  if (s.startsWith('\\Device\\')) return true
  if (s.startsWith('\\??\\')) return true
  return false
}

/**
 * - 函数: `isLikelyProcessImagePath`
 * - Function: `isLikelyProcessImagePath`
 * - 作用: 判断可能性处理image路径条件是否成立，并返回布尔化结果供上游守卫分支使用。
 * - Purpose: Checks whether the likelihood process image path condition is satisfied and returns a boolean-style result for upstream guards.
 * - 调用方: `isLikelyProcessImageText`。
 * - Callers: `isLikelyProcessImageText`.
 * - 被调方: `isLikelyWindowsPath`。
 * - Callees: `isLikelyWindowsPath`.
 * - 变量说明: `p` 为当前流程传入的p；`s` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `s` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./utils').isLikelyProcessImagePath` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').isLikelyProcessImagePath`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 判断 | 可能性 | 处理 | image | 路径 | check | likelihood | process | image | path
 */
function isLikelyProcessImagePath(p) {
  if (typeof p !== 'string') return false
  const s = p.trim()
  if (!s) return false
  if (!/[\\/]/.test(s)) return false
  if (!/\.exe$/i.test(s)) return false
  return isLikelyWindowsPath(s)
}

/**
 * - 函数: `isLikelyProcessImageText`
 * - Function: `isLikelyProcessImageText`
 * - 作用: 判断可能性处理image文本条件是否成立，并返回布尔化结果供上游守卫分支使用。
 * - Purpose: Checks whether the likelihood process image text condition is satisfied and returns a boolean-style result for upstream guards.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `isCleanText`、`isLikelyProcessImagePath`。
 * - Callees: `isCleanText`, `isLikelyProcessImagePath`.
 * - 变量说明: `p` 为当前流程传入的p；`s` 为函数内部派生的中间状态。
 * - Variables: `p` is the incoming p for this flow; `s` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./utils').isLikelyProcessImageText` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./utils').isLikelyProcessImageText`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 判断 | 可能性 | 处理 | image | 文本 | check | likelihood | process | image | text
 */
function isLikelyProcessImageText(p) {
  if (typeof p !== 'string') return false
  const s = p.trim()
  if (!s) return false
  if (!isCleanText(s)) return false
  if (isLikelyProcessImagePath(s)) return true
  if (/\.exe$/i.test(s) && !/[\\/]/.test(s) && s.length <= 260) return true
  return false
}

module.exports = {
  resolveProjectRootDir,
  resolveProjectDataDir,
  killRelatedProcess,
  forceDelete,
  formatEtwEventForConsole,
  formatEtwEventForParsedConsole,
  resolveEtwOpMeaning,
  parseEtwEventFromConsoleLine,
  createRateLimiter,
  sanitizeText,
  normalizeWindowsPathText,
  isBehaviorMonitoringEnabled,
  isCleanText,
  isLikelyWindowsPath,
  isLikelyProcessImagePath,
  isLikelyProcessImageText,
  resolveFileFromBaseDirs
};
