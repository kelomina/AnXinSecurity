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

