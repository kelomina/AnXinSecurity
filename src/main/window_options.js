function normalizePositiveInt(value, fallback) {
  const n = Number(value)
  if (!Number.isFinite(n)) return fallback
  const i = Math.floor(n)
  if (i <= 0) return fallback
  return i
}

/**
 * - 函数: `resolveMainWindowOptions`
 * - Function: `resolveMainWindowOptions`
 * - 作用: 从配置中提取主窗口宽高与最小尺寸，并在读到异常值时回退到安全默认值，供主进程创建浏览器窗口时统一使用。
 * - Purpose: Extracts the main-window size and minimum constraints from config and falls back to safe defaults when values are invalid, providing one shared source for BrowserWindow creation.
 * - 调用方: `main.js` 创建主窗口前会调用本函数生成窗口尺寸配置。
 * - Callers: `main.js` calls this helper before creating the main window to derive size options.
 * - 被调方: `normalizePositiveInt`、`Math.max`。
 * - Callees: `normalizePositiveInt` and `Math.max`.
 * - 变量说明: `config` 为应用配置对象；`windowCfg` 为 `ui.window` 子配置；`minWidth`/`minHeight` 为清洗后的最小尺寸；`width`/`height` 为最终返回的主窗口尺寸。
 * - Variables: `config` is the application config object, `windowCfg` is the `ui.window` subsection, `minWidth` and `minHeight` are the sanitized minimum constraints, and `width` plus `height` are the final main-window dimensions.
 * - 接入方式: 所有主窗口尺寸计算都应通过本函数统一收口，避免在窗口创建代码中散落默认值与边界裁剪逻辑。
 * - Integration: Route all main-window size calculation through this helper so defaults and boundary clamping do not get duplicated in window-creation code.
 * - 错误处理: 通过 `normalizePositiveInt` 和最小值钳制兜底，不抛异常；即使配置缺失也能稳定返回可用尺寸。
 * - Error Handling: It relies on `normalizePositiveInt` and minimum-value clamping rather than throwing, so missing config still produces usable dimensions.
 * - 关键词: 主窗口尺寸解析 | main window option resolution | 最小宽高约束 | minimum size constraints | 配置回退 | config fallback | BrowserWindow参数 | BrowserWindow options | 尺寸钳制 | size clamping
 */
function resolveMainWindowOptions(config) {
  const windowCfg = config && config.ui && config.ui.window ? config.ui.window : {}
  const minWidth = normalizePositiveInt(windowCfg.minWidth, 800)
  const minHeight = normalizePositiveInt(windowCfg.minHeight, 600)

  const width = Math.max(800, minWidth)
  const height = Math.max(560, minHeight)

  return { width, height, minWidth, minHeight }
}

module.exports = {
  resolveMainWindowOptions
}
