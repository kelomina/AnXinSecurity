(function (root) {
  function getScanProgressBarState(session, scanning) {
    const s = session || {}
    const isFull = s.mode === 'full'
    const isStopping = !!(s.stopRequested || s.aborted)
    const isIndeterminate = !!(scanning && !isStopping && (s.realtime || isFull))
    if (isIndeterminate) {
      return { indeterminate: true, width: '100%', text: '' }
    }
    const scanned = (s.scannedCount || 0)
    const total = (s.totalCount > 0) ? s.totalCount : Math.max(1, scanned)
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

  function getFileExtLower(p) {
    const s = (typeof p === 'string') ? p.trim() : ''
    if (!s) return ''
    const name = s.replace(/^.*[\\/]/, '')
    const i = name.lastIndexOf('.')
    if (i <= 0 || i === name.length - 1) return ''
    return name.slice(i + 1).toLowerCase()
  }

  function isCommonExtensionFile(p) {
    const ext = getFileExtLower(p)
    return ext === 'exe' || ext === 'dll'
  }

  function shouldScanFileByConfig(filePath, cfg) {
    const onlyCommon = !!(cfg && cfg.scan && cfg.scan.commonExtensionsOnly)
    if (!onlyCommon) return true
    return isCommonExtensionFile(filePath)
  }

  root.getScanProgressBarState = getScanProgressBarState
  root.createScanQueue = createScanQueue
  root.isCommonExtensionFile = isCommonExtensionFile
  root.shouldScanFileByConfig = shouldScanFileByConfig
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { getScanProgressBarState, createScanQueue, isCommonExtensionFile, shouldScanFileByConfig }
  }
})(typeof window !== 'undefined' ? window : globalThis)
