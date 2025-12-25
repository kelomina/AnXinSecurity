const fs = require('fs')
const path = require('path')
const childProcess = require('child_process')
const http = require('http')
const https = require('https')

function normalizeProcessName(name) {
  if (typeof name !== 'string') return ''
  const trimmed = name.trim()
  return trimmed.toLowerCase().endsWith('.exe') ? trimmed : (trimmed ? (trimmed + '.exe') : '')
}

function isAbsolutePath(p) {
  return typeof p === 'string' && p.length > 0 && path.isAbsolute(p)
}

function resolveExePath(exePathOrRelative, baseDirs, deps = {}) {
  const fsMod = deps.fs || fs
  const pathMod = deps.path || path
  const raw = typeof exePathOrRelative === 'string' ? exePathOrRelative.trim() : ''
  if (!raw) return null

  if (isAbsolutePath(raw)) {
    return fsMod.existsSync(raw) ? raw : null
  }

  const bases = Array.isArray(baseDirs) ? baseDirs.filter(Boolean) : []
  for (const base of bases) {
    const full = pathMod.resolve(base, raw)
    if (fsMod.existsSync(full)) return full
  }
  return null
}

function spawnDetachedHidden(exePath, args, deps = {}) {
  const cp = deps.childProcess || childProcess
  const child = cp.spawn(exePath, Array.isArray(args) ? args : [], {
    detached: true,
    windowsHide: true,
    stdio: 'ignore'
  })
  child.unref()
  return child
}

function checkEngineHealth(baseUrl, deps = {}) {
  const base = typeof baseUrl === 'string' ? baseUrl.replace(/\/$/, '') : 'http://127.0.0.1:8000'
  const url = base + '/health'
  const fetchImpl = deps.fetch || (global.fetch ? global.fetch.bind(global) : null)

  if (fetchImpl) {
    const controller = new (deps.AbortController || AbortController)()
    const t = setTimeout(() => controller.abort(), 1000)
    return fetchImpl(url, { method: 'GET', signal: controller.signal })
      .then(res => {
        clearTimeout(t)
        if (!res.ok) return false
        return res.json().then(() => true).catch(() => false)
      })
      .catch(() => {
        clearTimeout(t)
        return false
      })
  }

  return new Promise((resolve) => {
    try {
      const isHttps = url.startsWith('https:')
      const client = isHttps ? (deps.https || https) : (deps.http || http)
      const req = client.get(url, (res) => {
        const chunks = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              JSON.parse(Buffer.concat(chunks).toString())
              resolve(true)
            } catch {
              resolve(false)
            }
          } else {
            resolve(false)
          }
        })
      })
      req.on('error', () => resolve(false))
      req.setTimeout(1000, () => {
        req.destroy()
        resolve(false)
      })
    } catch {
      resolve(false)
    }
  })
}

async function startIfNeeded(options, deps = {}) {
  const platform = (options && options.platform) || process.platform
  if (platform !== 'win32') return { started: false, reason: 'unsupported_platform' }

  const engine = options && options.engine ? options.engine : {}
  const baseDirs = options && options.baseDirs ? options.baseDirs : []
  const exeCandidate = engine.exePath || engine.exeRelativePath || ''
  const baseUrl = options.baseUrl || 'http://127.0.0.1:8000'

  const exePath = resolveExePath(exeCandidate, baseDirs, deps)
  if (!exePath) return { started: false, reason: 'exe_not_found' }

  const running = await checkEngineHealth(baseUrl, deps)
  if (running) return { started: false, reason: 'already_running', path: exePath }

  try {
    spawnDetachedHidden(exePath, engine.args || [], deps)
    return { started: true, reason: 'started', path: exePath }
  } catch {
    return { started: false, reason: 'spawn_failed', path: exePath }
  }
}

function postExitCommand(url, timeoutMs, token, deps = {}) {
  const u = typeof url === 'string' ? url : ''
  const to = (typeof timeoutMs === 'number' && timeoutMs > 0) ? timeoutMs : 1000
  const fetchImpl = deps.fetch || (global.fetch ? global.fetch.bind(global) : null)

  if (fetchImpl) {
    const controller = new (deps.AbortController || AbortController)()
    const t = setTimeout(() => controller.abort(), to)
    const body = token ? { command: 'exit', token } : { command: 'exit' }
    return fetchImpl(u, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal
    }).then(async (res) => {
      clearTimeout(t)
      let status = null
      try {
        const ct = res && res.headers && res.headers.get ? res.headers.get('content-type') : null
        if (ct && ct.indexOf('application/json') !== -1) {
          const data = await res.json()
          status = data && data.status ? data.status : null
        }
      } catch {}
      return { ok: true, status }
    }).catch(() => {
      clearTimeout(t)
      return { ok: false, status: null }
    })
  }

  return new Promise((resolve) => {
    try {
      const data = Buffer.from(JSON.stringify(token ? { command: 'exit', token } : { command: 'exit' }))
      const isHttps = u.startsWith('https:')
      const client = isHttps ? (deps.https || https) : (deps.http || http)
      const req = client.request(u, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': data.length }
      }, (res) => {
        const chunks = []
        res.on('data', (c) => { chunks.push(c) })
        res.on('end', () => {
          clearTimeout(timer)
          try {
            const text = Buffer.concat(chunks).toString('utf-8')
            const parsed = JSON.parse(text)
            resolve({ ok: true, status: parsed && parsed.status ? parsed.status : null })
          } catch {
            resolve({ ok: true, status: null })
          }
        })
      })
      const timer = setTimeout(() => {
        try { req.destroy() } catch {}
        resolve({ ok: false, status: null })
      }, to)
      req.on('error', () => { clearTimeout(timer); resolve({ ok: false, status: null }) })
      req.write(data)
      req.end()
    } catch {
      resolve({ ok: false, status: null })
    }
  })
}

function killProcessWin32(processName, deps = {}) {
  const cp = deps.childProcess || childProcess
  const pn = normalizeProcessName(processName)
  if (!pn) return Promise.resolve(false)
  return new Promise((resolve) => {
    const cmd = `taskkill /F /IM ${pn} /T`
    cp.exec(cmd, { windowsHide: true }, (err) => {
      if (err) return resolve(false)
      resolve(true)
    })
  })
}

module.exports = {
  normalizeProcessName,
  resolveExePath,
  spawnDetachedHidden,
  startIfNeeded,
  postExitCommand,
  killProcessWin32,
  checkEngineHealth
}
