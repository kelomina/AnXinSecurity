function uniqPaths(arr) {
  const out = []
  const seen = new Set()
  for (const v of Array.isArray(arr) ? arr : []) {
    const s = (typeof v === 'string') ? v.trim() : ''
    if (!s) continue
    if (seen.has(s)) continue
    seen.add(s)
    out.push(s)
  }
  return out
}

/**
 * - 函数: `parseLines`
 * - Function: `parseLines`
 * - 作用: 将命令输出文本按行拆分并清理空白，供进程路径枚举的 PowerShell 与 WMIC 回退链统一复用。
 * - Purpose: Splits command-output text into trimmed non-empty lines so both the PowerShell and WMIC fallback chain can reuse the same normalization step.
 * - 调用方: `getRunningProcesses`。
 * - Callers: `getRunningProcesses`.
 * - 被调方: `String.prototype.split`、`Array.prototype.map`、`Array.prototype.filter`。
 * - Callees: `String.prototype.split`, `Array.prototype.map`, and `Array.prototype.filter`.
 * - 变量说明: `text` 为待解析的命令输出字符串。
 * - Variables: `text` is the command-output string to parse.
 * - 接入方式: 仅作为当前模块内部文本预处理助手使用；若新增命令源，优先复用本函数保持行清洗规则一致。
 * - Integration: Use it as the internal text-preprocessing helper; if new command sources are added, reuse this function to keep line-cleaning rules consistent.
 * - 错误处理: 输入为空时直接返回空数组，避免后续链路处理 `null` 或空字符串。
 * - Error Handling: Returns an empty array when the input is empty, preventing later stages from handling `null` or blank strings.
 * - 关键词: 命令输出拆行 | command output parsing | 行清洗 | line trimming | 进程路径回退 | process path fallback | PowerShell输出 | PowerShell output | WMIC输出 | WMIC output
 */
function parseLines(text) {
  if (!text) return []
  return text.split(/\r?\n/).map(l => l.trim()).filter(l => l)
}

/**
 * - 函数: `getRunningProcesses`
 * - Function: `getRunningProcesses`
 * - 作用: 以“原生 WinAPI 优先、PowerShell 次级、WMIC 兜底”的顺序枚举当前运行进程路径，并返回去重后的可执行文件列表。
 * - Purpose: Enumerates running process paths in the order of native WinAPI first, PowerShell second, and WMIC as the final fallback, returning a deduplicated executable-path list.
 * - 调用方: 主进程中需要获取当前运行程序路径快照的流程。
 * - Callers: Main-process flows that need a snapshot of currently running executable paths.
 * - 被调方: `winapi.getProcessPaths`、`uniqPaths`、`parseLines`、`child_process.exec`。
 * - Callees: `winapi.getProcessPaths`, `uniqPaths`, `parseLines`, and `child_process.exec`.
 * - 变量说明: `deps` 为可注入依赖对象；`winapi` 提供原生枚举能力；`exec` 为命令执行函数；`opt` 为命令缓冲配置。
 * - Variables: `deps` is the injectable dependency object; `winapi` provides native enumeration; `exec` is the command runner; `opt` stores command-buffer settings.
 * - 接入方式: 通过 `const { getRunningProcesses } = require('./processes')` 接入；测试时可传入自定义 `winapi` 与 `exec` 以模拟不同回退分支。
 * - Integration: Integrate via `const { getRunningProcesses } = require('./processes')`; tests can inject custom `winapi` and `exec` implementations to simulate different fallback branches.
 * - 错误处理: 原生枚举异常会静默回退到命令方案；PowerShell 失败继续尝试 WMIC；所有分支都失败时返回空数组而不抛异常。
 * - Error Handling: Native-enumeration errors silently fall back to command-based discovery, PowerShell failure continues to WMIC, and the function returns an empty array instead of throwing if every branch fails.
 * - 关键词: 运行进程枚举 | running process enumeration | WinAPI优先 | WinAPI first | PowerShell回退 | PowerShell fallback | WMIC兜底 | WMIC fallback | 路径去重 | path deduplication
 */
function getRunningProcesses(deps = {}) {
  const winapi = deps.winapi || null
  const exec = deps.exec || require('child_process').exec
  return new Promise((resolve) => {
    if (winapi && winapi.getProcessPaths) {
      try {
        const paths = winapi.getProcessPaths()
        const unique = uniqPaths(paths)
        if (unique.length > 0) {
          resolve(unique)
          return
        }
      } catch {}
    }

    const opt = { maxBuffer: 1024 * 1024 * 10 }
    exec('powershell "Get-Process | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue"', opt, (err, stdout) => {
      if (!err && stdout) {
        const unique = uniqPaths(parseLines(stdout))
        if (unique.length > 0) {
          resolve(unique)
          return
        }
      }

      exec('wmic process get ExecutablePath', opt, (err2, stdout2) => {
        if (err2) {
          resolve([])
          return
        }
        const lines = parseLines(stdout2).filter(l => l.toLowerCase() !== 'executablepath')
        resolve(uniqPaths(lines))
      })
    })
  })
}

module.exports = {
  getRunningProcesses
}
