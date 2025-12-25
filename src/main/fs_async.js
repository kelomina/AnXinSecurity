const fs = require('fs')
const path = require('path')

function nextTick() {
  return new Promise((resolve) => setImmediate(resolve))
}

function normalizeForCompare(p) {
  try {
    const resolved = path.resolve(String(p || ''))
    return resolved.replace(/\//g, '\\').toLowerCase()
  } catch {
    return String(p || '').replace(/\//g, '\\').toLowerCase()
  }
}

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

async function isDirectory(p) {
  try {
    const st = await fs.promises.stat(p)
    return st.isDirectory()
  } catch {
    return false
  }
}

async function fileSize(p) {
  try {
    const st = await fs.promises.stat(p)
    return st.size
  } catch {
    return -1
  }
}

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

function createWalker(roots, options = {}) {
  const id = walkerSeq++
  const r = Array.isArray(roots) ? roots : [roots]
  const stack = r.map(v => String(v || '')).filter(Boolean)
  const excludeCompiled = compileExcludeList(options.excludeList)
  walkers[id] = { stack, excludeCompiled }
  return id
}

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
