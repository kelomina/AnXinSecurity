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

  root.getScanProgressBarState = getScanProgressBarState
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { getScanProgressBarState }
  }
})(typeof window !== 'undefined' ? window : globalThis)

