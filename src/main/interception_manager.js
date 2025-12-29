function asPid(v) {
  const n = typeof v === 'number' ? v : parseInt(String(v), 10)
  if (!Number.isFinite(n) || n <= 0) return null
  return n
}

function createInterceptionQueue(deps = {}) {
  const showFn = typeof deps.showFn === 'function' ? deps.showFn : null
  const nowFn = typeof deps.nowFn === 'function' ? deps.nowFn : () => Date.now()

  let enabled = false
  const pending = []
  const queuedPids = new Set()
  const pausedPids = new Set()
  let activePid = null
  let activeItem = null

  function configure(cfg) {
    const c = cfg && typeof cfg === 'object' ? cfg : {}
    enabled = c.enabled === true
  }

  function getPausedPids() {
    return Array.from(pausedPids)
  }

  function isIdle() {
    return activePid == null
  }

  function logQueueStatus() {
    if (pending.length === 0 && activePid == null) return
    console.log(`\n[Interception Queue Status] Total: ${pending.length + (activePid ? 1 : 0)}`)
    if (activePid) {
      console.log(` - ACTIVE: PID ${activePid}`)
    }
    pending.forEach((item, index) => {
      console.log(` - PENDING[${index}]: PID ${item.pid} (Enqueued: ${new Date(item.enqueuedAt).toLocaleTimeString()})`)
    })
    console.log('')
  }

  function tryShowNext() {
    if (!enabled) return false
    if (!showFn) return false
    if (activePid != null) return false
    const next = pending.shift()
    if (!next) return false
    const pid = next.pid
    try {
      const ok = showFn(next.payload) === true
      if (!ok) {
        pending.unshift(next)
        return false
      }
      activePid = pid
      activeItem = next
      logQueueStatus()
      return true
    } catch {
      pending.unshift(next)
      return false
    }
  }

  function enqueuePausedProcess(payload) {
    if (!enabled) return false
    const p = payload && typeof payload === 'object' ? payload : null
    const pid = p && Number.isFinite(p.pid) ? p.pid : asPid(p && p.pid)
    if (pid == null) return false
    if (queuedPids.has(pid)) return false
    queuedPids.add(pid)
    pausedPids.add(pid)
    pending.push({ pid, payload: p, enqueuedAt: nowFn() })
    logQueueStatus()
    tryShowNext()
    return true
  }

  function markActionResult(pid, ok) {
    const p = asPid(pid)
    if (p == null) return null
    if (activePid !== p) return null
    if (ok === true) {
      const item = activeItem
      pausedPids.delete(p)
      queuedPids.delete(p)
      activePid = null
      activeItem = null
      logQueueStatus()
      setTimeout(() => tryShowNext(), 500)
      return item ? item.payload : null
    }
    return null
  }

  function clearPid(pid) {
    const p = asPid(pid)
    if (p == null) return
    pausedPids.delete(p)
    queuedPids.delete(p)
    if (activePid === p) {
      activePid = null
      activeItem = null
    }
    for (let i = pending.length - 1; i >= 0; i--) {
      if (pending[i] && pending[i].pid === p) pending.splice(i, 1)
    }
    logQueueStatus()
    tryShowNext()
  }

  function clearAll() {
    pending.length = 0
    queuedPids.clear()
    pausedPids.clear()
    activePid = null
    activeItem = null
  }

  return {
    configure,
    enqueuePausedProcess,
    markActionResult,
    clearPid,
    clearAll,
    getPausedPids,
    getAllPausedPayloads: () => {
      const list = []
      if (activeItem) list.push(activeItem.payload)
      pending.forEach(x => list.push(x.payload))
      return list
    },
    isIdle,
    tryShowNext,
    getActivePayload: () => {
      return activeItem ? activeItem.payload : null
    },
    getState: () => ({
      enabled,
      activePid,
      pending: pending.map(x => ({ pid: x.pid, enqueuedAt: x.enqueuedAt })),
      pausedPids: Array.from(pausedPids)
    })
  }
}

module.exports = {
  createInterceptionQueue,
  __test: { asPid }
}
