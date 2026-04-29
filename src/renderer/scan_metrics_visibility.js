(function (root) {
  /**
 * - 函数: `toggleClass`
 * - Function: `toggleClass`
 * - 作用: 梳理并返回toggleClass负责的class局部处理结果。
 * - Purpose: Coordinates and returns the class processing result handled by toggleClass.
 * - 调用方: `模块顶层流程`、`setScanMetricsVisible`。
 * - Callers: `模块顶层流程`, `setScanMetricsVisible`.
 * - 被调方: `remove`。
 * - Callees: `remove`.
 * - 变量说明: `el` 为当前流程传入的el；`className` 为当前流程传入的class名称；`on` 为当前流程传入的on。
 * - Variables: `el` is the incoming el for this flow; `className` is the incoming class name for this flow; `on` is the incoming on for this flow.
 * - 接入方式: 在当前模块内部直接调用 `toggleClass(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `toggleClass(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 切换 | class | toggle | class | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  function toggleClass(el, className, on) {
    if (!el || !el.classList) return
    if (on) el.classList.add(className)
    else el.classList.remove(className)
  }

  /**
 * - 函数: `setScanMetricsVisible`
 * - Function: `setScanMetricsVisible`
 * - 作用: 设置扫描metricsvisible状态，并同步影响当前模块内的后续判断。
 * - Purpose: Sets the scan metrics visible state and synchronizes the downstream decisions made inside this module.
 * - 调用方: 当前模块内的后续流程、事件处理或导出接口。
 * - Callers: Downstream flows, event handlers, or exported entry points inside this module.
 * - 被调方: `toggleClass`。
 * - Callees: `toggleClass`.
 * - 变量说明: `doc` 为当前流程传入的doc；`visible` 为当前流程传入的visible；`hidden`, `curRow` 为函数内部派生的中间状态。
 * - Variables: `doc` is the incoming doc for this flow; `visible` is the incoming visible for this flow; `hidden`, `curRow` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./scan_metrics_visibility').setScanMetricsVisible` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./scan_metrics_visibility').setScanMetricsVisible`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 设置 | 扫描 | metrics | visible | set | scan | metrics | visible | error handling | 复用
 */
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

