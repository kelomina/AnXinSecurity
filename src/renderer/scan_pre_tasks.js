(function (root) {
  /**
 * - 函数: `runScanPreTasks`
 * - Function: `runScanPreTasks`
 * - 作用: 梳理并返回runScanPreTasks负责的扫描pretasks局部处理结果。
 * - Purpose: Coordinates and returns the scan pre tasks processing result handled by runScanPreTasks.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `showLoading`、`waitNextPaint`、`Array.isArray`。
 * - Callees: `showLoading`, `waitNextPaint`, `Array.isArray`.
 * - 变量说明: `opts` 为当前流程传入的opts；`showLoading`, `waitNextPaint` 为函数内部派生的中间状态。
 * - Variables: `opts` is the incoming opts for this flow; `showLoading`, `waitNextPaint` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./scan_pre_tasks').runScanPreTasks` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./scan_pre_tasks').runScanPreTasks`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: run | 扫描 | pre | tasks | run | scan | pre | tasks | error handling | 复用
 */
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

