const fs = require('fs')
const path = require('path')
const koffi = require('koffi')

let lib = null
let startFn = null
let stopFn = null
let setSignedFn = null
let pollFn = null

function fileExists(p) {
  try { return !!(p && fs.existsSync(p)) } catch { return false }
}

function resolveProcessWatcherPath() {
  const candidates = []
  try {
    if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
      candidates.push(path.join(process.resourcesPath, 'native', 'win32-x64', 'process_watcher.dll'))
      candidates.push(path.join(process.resourcesPath, 'native', 'bin', 'win32-x64', 'process_watcher.dll'))
    }
  } catch {}
  try { candidates.push(path.join(__dirname, '../../native/bin/win32-x64/process_watcher.dll')) } catch {}
  try { candidates.push(path.join(__dirname, '../../native/win32-x64/process_watcher.dll')) } catch {}
  for (const p of candidates) {
    if (fileExists(p)) return p
  }
  return ''
}

function tryLoad() {
  if (lib && startFn && stopFn) return true
  const dllPath = resolveProcessWatcherPath()
  if (!dllPath) return false
  try {
    lib = koffi.load(dllPath)
    startFn = lib.func('__cdecl', 'ProcessWatcher_Start', 'int', ['string16', 'string16', 'string16', 'string16', 'int'])
    stopFn = lib.func('__cdecl', 'ProcessWatcher_Stop', 'void', [])
    setSignedFn = lib.func('__cdecl', 'ProcessWatcher_SetSignedList', 'int', ['string16', 'int'])
    pollFn = lib.func('__cdecl', 'ProcessWatcher_PollNewPid', 'int', [])
    return true
  } catch {
    lib = null
    startFn = null
    stopFn = null
    setSignedFn = null
    pollFn = null
    return false
  }
}

function startProcessWatcher(opts) {
  if (!tryLoad()) return { ok: false, reason: 'dll_missing' }
  const cfg = opts && typeof opts === 'object' ? opts : {}
  const injectorX64 = cfg.injectorX64 || ''
  const injectorX86 = cfg.injectorX86 || ''
  const dllX64 = cfg.dllX64 || ''
  const dllX86 = cfg.dllX86 || ''
  const intervalMs = Number.isFinite(cfg.intervalMs) ? Math.floor(cfg.intervalMs) : 100
  if (!injectorX64 && !injectorX86) return { ok: false, reason: 'injector_missing' }
  if (!dllX64 && !dllX86) return { ok: false, reason: 'dll_missing' }
  const res = startFn(injectorX64, injectorX86, dllX64, dllX86, intervalMs)
  return { ok: res === 1 }
}

function stopProcessWatcher() {
  if (stopFn) {
    try { stopFn() } catch {}
  }
}

function setSignedPaths(paths) {
  if (!tryLoad()) return { ok: false }
  const list = Array.isArray(paths) ? paths.filter(p => typeof p === 'string' && p) : []
  if (!list.length) return { ok: true, added: 0 }
  const payload = list.join('\n')
  const added = setSignedFn(payload, payload.length)
  return { ok: true, added }
}

function pollNewPid() {
  if (!pollFn) return 0
  try { return pollFn() | 0 } catch { return 0 }
}

module.exports = {
  startProcessWatcher,
  stopProcessWatcher,
  setSignedPaths,
  pollNewPid
}
