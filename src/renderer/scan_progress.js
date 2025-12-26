(function (root) {
  function getScanProgressBarState(session, scanning) {
    const s = session || {}
    const isFull = s.mode === 'full'
    const isIndeterminate = !!(scanning && (s.realtime || isFull))
    if (isIndeterminate) {
      return { indeterminate: true, width: '100%', text: '' }
    }
    const total = (s.totalCount > 0) ? s.totalCount : 1
    const percent = Math.max(0, Math.min(100, Math.floor(((s.scannedCount || 0) / total) * 100)))
    return { indeterminate: false, width: percent + '%', text: percent + '%' }
  }

  function createScanQueue(initial, options) {
    const opts = options && typeof options === 'object' ? options : {}
    const compactionThreshold = Number.isFinite(opts.compactionThreshold) ? Math.max(1, opts.compactionThreshold) : 5000
    const arr = []
    if (Array.isArray(initial)) {
      for (const v of initial) {
        if (v) arr.push(v)
      }
    }
    let idx = 0

    function remaining() {
      return Math.max(0, arr.length - idx)
    }

    function compactIfNeeded() {
      if (idx <= 0) return
      if (idx < compactionThreshold) return
      arr.splice(0, idx)
      idx = 0
    }

    function next() {
      if (idx >= arr.length) return null
      const v = arr[idx++]
      compactIfNeeded()
      return v
    }

    function push(v) {
      if (v) arr.push(v)
    }

    function pushMany(list) {
      if (!Array.isArray(list) || list.length === 0) return
      for (const v of list) {
        if (v) arr.push(v)
      }
    }

    return { next, push, pushMany, remaining }
  }

  root.getScanProgressBarState = getScanProgressBarState
  root.createScanQueue = createScanQueue
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { getScanProgressBarState, createScanQueue }
  }
})(typeof window !== 'undefined' ? window : globalThis)
