(function (root) {
  function toggleClass(el, className, on) {
    if (!el || !el.classList) return
    if (on) el.classList.add(className)
    else el.classList.remove(className)
  }

  function setScanMetricsVisible(doc, visible) {
    if (!doc || typeof doc.getElementById !== 'function') return
    const hidden = !visible
    const curRow = doc.getElementById('scan-current-target-row')
    const metricsRow = doc.getElementById('scan-metrics-row')
    toggleClass(curRow, 'scan-hidden', hidden)
    toggleClass(metricsRow, 'scan-hidden', hidden)
  }

  root.setScanMetricsVisible = setScanMetricsVisible
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { setScanMetricsVisible }
  }
})(typeof window !== 'undefined' ? window : globalThis)

