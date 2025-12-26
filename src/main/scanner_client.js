const http = require('http')
const https = require('https')

function normalizeBaseUrl(baseUrl) {
  const raw = typeof baseUrl === 'string' ? baseUrl.trim() : ''
  return (raw ? raw : 'http://127.0.0.1:8000').replace(/\/$/, '')
}

function createScannerClient(getConfig, deps = {}) {
  const fetchImpl = deps.fetch || (global.fetch ? global.fetch.bind(global) : null)
  const AbortControllerImpl = deps.AbortController || (global.AbortController ? global.AbortController : null)
  const active = new Map()

  function getScannerCfg() {
    const cfg = typeof getConfig === 'function' ? (getConfig() || {}) : {}
    const scanner = cfg && cfg.scanner ? cfg.scanner : {}
    const baseUrl = normalizeBaseUrl(scanner.baseUrl)
    const timeoutMs = Number.isFinite(scanner.timeoutMs) ? scanner.timeoutMs : 5000
    return { baseUrl, timeoutMs }
  }

  function setController(id, controller) {
    if (!id || !controller) return
    active.set(String(id), controller)
  }

  function clearController(id) {
    if (!id) return
    active.delete(String(id))
  }

  function abort(id) {
    const key = id ? String(id) : ''
    if (!key) return false
    const c = active.get(key)
    if (!c) return false
    try { c.abort() } catch {}
    active.delete(key)
    return true
  }

  async function health(requestId) {
    const { baseUrl, timeoutMs } = getScannerCfg()
    const url = baseUrl + '/health'

    if (!fetchImpl || !AbortControllerImpl) {
      return new Promise((resolve, reject) => {
        try {
          const isHttps = url.startsWith('https:')
          const client = isHttps ? https : http
          const req = client.get(url, (res) => {
            const chunks = []
            res.on('data', (c) => chunks.push(c))
            res.on('end', () => {
              if (res.statusCode < 200 || res.statusCode >= 300) return reject(new Error('HTTP_' + res.statusCode))
              try {
                resolve(JSON.parse(Buffer.concat(chunks).toString()))
              } catch (e) {
                reject(e)
              }
            })
          })
          req.on('error', reject)
          req.setTimeout(timeoutMs, () => {
            req.destroy(new Error('TIMEOUT'))
          })
        } catch (e) {
          reject(e)
        }
      })
    }

    const controller = new AbortControllerImpl()
    const reqId = requestId ? String(requestId) : ''
    if (reqId) setController(reqId, controller)
    const t = setTimeout(() => controller.abort(), timeoutMs)
    try {
      const res = await fetchImpl(url, { method: 'GET', signal: controller.signal })
      clearTimeout(t)
      if (!res.ok) throw new Error('HTTP_' + res.status)
      return await res.json()
    } finally {
      clearTimeout(t)
      if (reqId) clearController(reqId)
    }
  }

  async function scanFile(filePath, requestId) {
    const fp = typeof filePath === 'string' ? filePath : ''
    if (!fp) throw new Error('INVALID_FILE_PATH')

    const { baseUrl, timeoutMs } = getScannerCfg()
    const url = baseUrl + '/scan/file'

    if (!fetchImpl || !AbortControllerImpl) {
      return new Promise((resolve, reject) => {
        try {
          const body = Buffer.from(JSON.stringify({ file_path: fp }), 'utf-8')
          const isHttps = url.startsWith('https:')
          const client = isHttps ? https : http
          const req = client.request(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': body.length } }, (res) => {
            const chunks = []
            res.on('data', (c) => chunks.push(c))
            res.on('end', () => {
              if (res.statusCode === 400) return resolve({ infected: false, is_malware: false, file_path: fp })
              if (res.statusCode < 200 || res.statusCode >= 300) return reject(new Error('HTTP_' + res.statusCode))
              try {
                resolve(JSON.parse(Buffer.concat(chunks).toString()))
              } catch (e) {
                reject(e)
              }
            })
          })
          req.on('error', reject)
          req.setTimeout(timeoutMs, () => {
            req.destroy(new Error('TIMEOUT'))
          })
          req.write(body)
          req.end()
        } catch (e) {
          reject(e)
        }
      })
    }

    const controller = new AbortControllerImpl()
    const reqId = requestId ? String(requestId) : ''
    if (reqId) setController(reqId, controller)
    const t = setTimeout(() => controller.abort(), timeoutMs)
    try {
      const res = await fetchImpl(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_path: fp }),
        signal: controller.signal
      })
      clearTimeout(t)
      if (res.status === 400) return { infected: false, is_malware: false, file_path: fp }
      if (!res.ok) throw new Error('HTTP_' + res.status)
      return await res.json()
    } finally {
      clearTimeout(t)
      if (reqId) clearController(reqId)
    }
  }

  return { health, scanFile, abort }
}

module.exports = { createScannerClient }

