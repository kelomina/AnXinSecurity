function resolveTrayExitMode({ response, defaultKeep = true } = {}) {
  if (response === 0) return 'keep_service'
  if (response === 1) return 'full_exit'
  return defaultKeep ? 'keep_service' : 'full_exit'
}

module.exports = { resolveTrayExitMode }

