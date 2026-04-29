/**
 * - 函数: `resolveTrayExitMode`
 * - Function: `resolveTrayExitMode`
 * - 作用: 把托盘退出确认中的布尔输入归一化为统一模式字符串，避免主进程在“保留后台服务”和“完全退出”之间重复做条件分支。
 * - Purpose: Normalizes the boolean tray-exit choice into a shared mode string so the main process does not repeat conditional branching between keeping the service alive and fully exiting.
 * - 调用方: `main.js` 的托盘退出确认与退出策略决策逻辑会调用本函数。
 * - Callers: Used by the tray-exit confirmation and exit-policy decision flow in `main.js`.
 * - 被调方: 无额外命名函数，直接依赖参数守卫与条件返回。
 * - Callees: It does not call named helpers and relies only on parameter guards and conditional returns.
 * - 变量说明: `keep` 表示用户显式选择是否保留服务；`defaultKeep` 为用户未选择时的默认退出策略。
 * - Variables: `keep` is the user's explicit choice on whether to keep the service, and `defaultKeep` is the fallback strategy when no explicit choice is made.
 * - 接入方式: 所有托盘退出模式判定都应通过本函数统一返回 `keep_service` 或 `full_exit`，不要在调用方散落布尔翻译逻辑。
 * - Integration: All tray-exit mode resolution should flow through this helper so callers receive either `keep_service` or `full_exit` without duplicating boolean-to-mode translation.
 * - 错误处理: 非显式 `true`/`false` 的输入会回退到 `defaultKeep`，不抛异常。
 * - Error Handling: Any input other than explicit `true` or `false` falls back to `defaultKeep` and does not throw.
 * - 关键词: 托盘退出模式 | tray exit mode | 保留后台服务 | keep background service | 完全退出策略 | full exit policy | 布尔归一化 | boolean normalization | 退出确认结果 | exit confirmation result
 */
function resolveTrayExitMode({ keep, defaultKeep = true } = {}) {
  if (keep === true) return 'keep_service'
  if (keep === false) return 'full_exit'
  return defaultKeep ? 'keep_service' : 'full_exit'
}

module.exports = { resolveTrayExitMode }
