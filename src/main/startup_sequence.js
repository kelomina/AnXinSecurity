/**
 * - 函数: `runStartupSequence`
 * - Function: `runStartupSequence`
 * - 作用: 串行执行应用启动阶段的关键步骤，保证 UI 预热、阻断扫描、积压任务恢复、安全组件启动和最终界面收尾按既定顺序完成。
 * - Purpose: Runs the critical startup stages in series so UI preparation, blocking scan, backlog recovery, security startup, and final UI finalization all happen in the expected order.
 * - 调用方: `main.js` 的应用启动编排逻辑会调用本函数作为统一启动入口。
 * - Callers: `main.js` uses this helper as the unified startup orchestrator.
 * - 被调方: `prepareUi`、`runBlockingScan`、`startBacklogProcessing`、`startSecurityComponents`、`waitSecurityReady`、`finalizeUi`。
 * - Callees: `prepareUi`, `runBlockingScan`, `startBacklogProcessing`, `startSecurityComponents`, `waitSecurityReady`, and `finalizeUi`.
 * - 变量说明: `deps` 为启动依赖集合；`d` 为已做对象守卫后的依赖引用；其余同名局部变量分别缓存每个必需阶段函数。
 * - Variables: `deps` is the startup dependency bundle, `d` is the guarded object reference, and the remaining like-named locals cache each required stage function.
 * - 接入方式: 所有需要复用主进程启动顺序的场景都应从本函数进入，不要在调用方手工拼接各阶段顺序。
 * - Integration: Any flow that needs the main-process startup order should enter through this helper instead of manually sequencing the stages elsewhere.
 * - 错误处理: 缺失任一关键阶段函数时立即抛出具名错误；任一异步阶段失败时异常继续上抛，由调用方决定是否中止启动或进入降级分支。
 * - Error Handling: It throws a named error immediately when any required stage function is missing, and async stage failures bubble upward so the caller can decide whether to abort startup or degrade gracefully.
 * - 关键词: 启动顺序编排 | startup sequence orchestration | 阻断扫描前置 | blocking scan prerequisite | 安全组件启动 | security component startup | UI收尾 | UI finalization | 串行依赖执行 | serial dependency execution
 */
async function runStartupSequence(deps) {
  const d = deps && typeof deps === 'object' ? deps : {}
  const prepareUi = typeof d.prepareUi === 'function' ? d.prepareUi : null
  const runBlockingScan = typeof d.runBlockingScan === 'function' ? d.runBlockingScan : null
  const startBacklogProcessing = typeof d.startBacklogProcessing === 'function' ? d.startBacklogProcessing : null
  const startSecurityComponents = typeof d.startSecurityComponents === 'function' ? d.startSecurityComponents : null
  const waitSecurityReady = typeof d.waitSecurityReady === 'function' ? d.waitSecurityReady : null
  const finalizeUi = typeof d.finalizeUi === 'function' ? d.finalizeUi : null

  if (!prepareUi) throw new Error('prepareUi_required')
  if (!runBlockingScan) throw new Error('runBlockingScan_required')
  if (!startBacklogProcessing) throw new Error('startBacklogProcessing_required')
  if (!startSecurityComponents) throw new Error('startSecurityComponents_required')
  if (!waitSecurityReady) throw new Error('waitSecurityReady_required')
  if (!finalizeUi) throw new Error('finalizeUi_required')

  await prepareUi()
  await runBlockingScan()
  await startBacklogProcessing()
  await startSecurityComponents()
  await waitSecurityReady()
  await finalizeUi()
}

module.exports = {
  runStartupSequence
}
