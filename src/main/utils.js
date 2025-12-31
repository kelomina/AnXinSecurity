const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

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

function formatEtwEventForConsole(event) {
  if (!event || typeof event !== 'object') return ''
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

function sanitizeText(s) {
  if (typeof s !== 'string' || !s) return ''
  return s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFD]/g, '').trim()
}

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

function isBehaviorMonitoringEnabled(appConfig) {
  const cfg = appConfig && typeof appConfig === 'object' ? appConfig : {}
  const bm = cfg && cfg.behaviorMonitoring && typeof cfg.behaviorMonitoring === 'object' ? cfg.behaviorMonitoring : {}
  return bm.enabled !== false
}

function isCleanText(s) {
  if (typeof s !== 'string' || !s) return false
  return !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFD]/.test(s)
}

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

function isLikelyProcessImagePath(p) {
  if (typeof p !== 'string') return false
  const s = p.trim()
  if (!s) return false
  if (!/[\\/]/.test(s)) return false
  if (!/\.exe$/i.test(s)) return false
  return isLikelyWindowsPath(s)
}

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
