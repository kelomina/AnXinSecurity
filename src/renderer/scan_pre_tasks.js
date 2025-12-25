(function (root) {
  async function runScanPreTasks(opts) {
    const showLoading = opts && opts.showLoading
    const waitNextPaint = opts && opts.waitNextPaint
    const includeRunningProcesses = !!(opts && opts.includeRunningProcesses)
    const getRunningProcesses = opts && opts.getRunningProcesses

    if (typeof showLoading === 'function') {
      await showLoading()
    }
    if (typeof waitNextPaint === 'function') {
      await waitNextPaint()
    }
    if (includeRunningProcesses && typeof getRunningProcesses === 'function') {
      const res = await getRunningProcesses()
      return Array.isArray(res) ? res : []
    }
    return []
  }

  root.runScanPreTasks = runScanPreTasks
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { runScanPreTasks }
  }
})(typeof window !== 'undefined' ? window : globalThis)

