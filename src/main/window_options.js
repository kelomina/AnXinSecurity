function normalizePositiveInt(value, fallback) {
  const n = Number(value)
  if (!Number.isFinite(n)) return fallback
  const i = Math.floor(n)
  if (i <= 0) return fallback
  return i
}

function resolveMainWindowOptions(config) {
  const windowCfg = config && config.ui && config.ui.window ? config.ui.window : {}
  const minWidth = normalizePositiveInt(windowCfg.minWidth, 600)
  const minHeight = normalizePositiveInt(windowCfg.minHeight, 800)

  const width = Math.max(800, minWidth)
  const height = Math.max(560, minHeight)

  return { width, height, minWidth, minHeight }
}

module.exports = {
  resolveMainWindowOptions
}

