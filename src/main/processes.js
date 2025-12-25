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

function parseLines(text) {
  if (!text) return []
  return text.split(/\r?\n/).map(l => l.trim()).filter(l => l)
}

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

