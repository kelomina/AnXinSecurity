const fs = require('fs')
const path = require('path')

function getProjectRoot() {
  return path.join(__dirname, '../..')
}

function resolveCachePath(config) {
  const root = getProjectRoot()
  const rel = config && config.scan_cache && typeof config.scan_cache.file === 'string' ? config.scan_cache.file : 'config/scan_cache.json'
  return path.resolve(root, rel)
}

async function readJsonFile(p) {
  try {
    const raw = await fs.promises.readFile(p, 'utf-8')
    return JSON.parse(raw)
  } catch {
    return null
  }
}

async function writeJsonFile(p, data) {
  try {
    await fs.promises.mkdir(path.dirname(p), { recursive: true })
    await fs.promises.writeFile(p, JSON.stringify(data, null, 2), 'utf-8')
    return true
  } catch {
    return false
  }
}

async function clearFile(p) {
  try {
    await fs.promises.unlink(p)
    return true
  } catch {
    return false
  }
}

async function restore(config) {
  const p = resolveCachePath(config)
  const data = await readJsonFile(p)
  const current = data && data.current ? data.current : null
  if (!current) return null
  if (current.handled) return null
  return current
}

async function saveCurrent(config, session) {
  const p = resolveCachePath(config)
  const payload = { current: session || null }
  return writeJsonFile(p, payload)
}

async function clearCurrent(config) {
  const p = resolveCachePath(config)
  const data = await readJsonFile(p)
  if (!data) return clearFile(p)
  data.current = null
  return writeJsonFile(p, data)
}

async function markHandled(config, handledAt) {
  const p = resolveCachePath(config)
  const data = await readJsonFile(p)
  if (!data || !data.current) return false
  data.current.handled = true
  data.current.handledAt = handledAt || Date.now()
  return writeJsonFile(p, data)
}

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

