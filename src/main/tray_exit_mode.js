function resolveTrayExitMode({ keep, defaultKeep = true } = {}) {
  if (keep === true) return 'keep_service'
  if (keep === false) return 'full_exit'
  return defaultKeep ? 'keep_service' : 'full_exit'
}

module.exports = { resolveTrayExitMode }
