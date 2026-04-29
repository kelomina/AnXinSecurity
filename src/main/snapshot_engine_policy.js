function normalizePathKey(p) {
  if (typeof p !== 'string') return ''
  const s = p.trim()
  if (!s) return ''
  return s.toLowerCase().replace(/\//g, '\\')
}

/**
 * - 函数: `isMalware`
 * - Function: `isMalware`
 * - 作用: 统一识别扫描结果对象中的恶意命中标记，供快照策略在不同字段命名下做兼容判断。
 * - Purpose: Normalizes malware-hit detection across differently shaped scan-result objects so snapshot policy can make a compatible decision.
 * - 调用方: `decideSnapshotActions`。
 * - Callers: `decideSnapshotActions`.
 * - 被调方: 无，仅执行对象字段判定。
 * - Callees: None; it only evaluates object fields.
 * - 变量说明: `res` 为按路径查询得到的扫描结果对象，可能包含 `infected`、`is_malware`、`malicious` 等布尔标记。
 * - Variables: `res` is the per-path scan-result object and may contain boolean markers such as `infected`, `is_malware`, or `malicious`.
 * - 接入方式: 供快照决策链内部复用；若新增扫描结果字段，应优先在本函数内补齐兼容映射。
 * - Integration: Reuse it inside the snapshot-decision flow; if new result-field names appear, extend the compatibility mapping here first.
 * - 错误处理: 输入为空或不是对象时直接返回 `false`，避免调用方因字段访问失败中断策略计算。
 * - Error Handling: Returns `false` immediately when the input is empty or not an object, preventing field-access errors from breaking policy evaluation.
 * - 关键词: 恶意结果识别 | malware result detection | 扫描结果兼容 | scan result compatibility | 布尔标记判断 | boolean flag evaluation | 快照策略 | snapshot policy | 风险决策 | risk decision
 */
function isMalware(res) {
  if (!res || typeof res !== 'object') return false
  if (res.infected === true) return true
  if (res.is_malware === true) return true
  if (res.malicious === true) return true
  return false
}

/**
 * - 函数: `getPayloadPaths`
 * - Function: `getPayloadPaths`
 * - 作用: 从单条拦截快照中提取待判定路径，合并主进程映像与未签名 DLL 列表，并按归一化路径去重。
 * - Purpose: Extracts candidate paths from a single interception snapshot, merging the main process image and unsigned DLL list while deduplicating by normalized path.
 * - 调用方: `decideSnapshotActions`。
 * - Callers: `decideSnapshotActions`.
 * - 被调方: `normalizePathKey`、`Set`。
 * - Callees: `normalizePathKey` and `Set`.
 * - 变量说明: `payload` 为单条快照载荷；`out` 收集原始候选路径；`dlls` 为事件中的未签名 DLL 列表；`seen` 与 `uniq` 分别用于去重索引和最终输出。
 * - Variables: `payload` is one snapshot payload; `out` collects raw candidate paths; `dlls` holds unsigned DLL entries; `seen` and `uniq` store the dedupe index and final output.
 * - 接入方式: 任何需要从快照载荷提取扫描路径的逻辑都应复用本函数，避免在调用方重复拼接字段和去重规则。
 * - Integration: Any flow that extracts scan paths from snapshot payloads should reuse this helper instead of duplicating field selection and dedupe rules.
 * - 错误处理: 载荷结构不完整时按空路径集合处理，只返回当前能安全提取出的字符串路径。
 * - Error Handling: Treats incomplete payload structures as empty path sets and only returns string paths that can be extracted safely.
 * - 关键词: 快照路径提取 | snapshot path extraction | 主映像路径 | main image path | 未签名DLL | unsigned DLL | 路径去重 | path deduplication | 归一化键 | normalized key
 */
function getPayloadPaths(payload) {
  const p = payload && typeof payload === 'object' ? payload : null
  const out = []
  const imagePath = p && p.process && typeof p.process.imagePath === 'string' ? p.process.imagePath : ''
  if (imagePath) out.push(imagePath)
  const dlls = p && p.event && p.event.data && Array.isArray(p.event.data.unsignedDlls) ? p.event.data.unsignedDlls : []
  for (const d of dlls) {
    if (typeof d === 'string' && d) out.push(d)
  }
  const seen = new Set()
  const uniq = []
  for (const x of out) {
    const k = normalizePathKey(x)
    if (!k || seen.has(k)) continue
    seen.add(k)
    uniq.push(x)
  }
  return uniq
}

/**
 * - 函数: `decideSnapshotActions`
 * - Function: `decideSnapshotActions`
 * - 作用: 结合拦截快照列表与按路径索引的扫描结果，生成允许放行路径、清理拦截状态的 PID，以及需要恢复执行的暂停 PID。
 * - Purpose: Combines interception snapshots with scan results indexed by path to produce allowed paths, PIDs whose interception state can be cleared, and paused PIDs that should be resumed.
 * - 调用方: `main.js` 中的 `handleSnapshotScanDone`。
 * - Callers: `handleSnapshotScanDone` in `main.js`.
 * - 被调方: `getPayloadPaths`、`normalizePathKey`、`isMalware`、`Map`、`Set`。
 * - Callees: `getPayloadPaths`, `normalizePathKey`, `isMalware`, `Map`, and `Set`.
 * - 变量说明: `payloads` 为待评估的快照数组；`scanByPath` 为路径到扫描结果的映射；`allowPaths` 汇总可放行路径；`clearPids` 记录可移除拦截状态的 PID；`resumePids` 记录需要恢复执行的暂停 PID。
 * - Variables: `payloads` is the snapshot array to evaluate; `scanByPath` maps paths to scan results; `allowPaths` accumulates allowed paths; `clearPids` stores PIDs whose interception state can be cleared; `resumePids` stores paused PIDs to resume.
 * - 接入方式: 启动快照扫描完成后，将 worker 回传的快照列表与主进程扫描结果映射一并传入本函数，统一收口后续放行决策。
 * - Integration: After snapshot scanning completes, pass the worker snapshots and the main-process scan-result map into this helper to centralize all follow-up allow/resume decisions.
 * - 错误处理: 非数组输入会退化为空列表，缺失 `Map#get` 能力时回退为空映射；单条载荷不合法时仅跳过该项，不影响整体决策输出。
 * - Error Handling: Non-array inputs degrade to empty lists, missing `Map#get` capability falls back to an empty map, and invalid payload entries are skipped without affecting the overall decision result.
 * - 关键词: 快照决策汇总 | snapshot decision aggregation | 放行路径 | allow paths | 恢复进程 | resume processes | 清理拦截状态 | clear interception state | 扫描结果映射 | scan result map
 */
function decideSnapshotActions(payloads, scanByPath) {
  const arr = Array.isArray(payloads) ? payloads : []
  const map = (scanByPath && typeof scanByPath.get === 'function') ? scanByPath : new Map()

  const allowPaths = new Set()
  const clearPids = []
  const resumePids = []

  for (const p of arr) {
    const pid = p && Number.isFinite(p.pid) ? p.pid : parseInt(String(p && p.pid), 10)
    if (!Number.isFinite(pid) || pid <= 0) continue
    const paths = getPayloadPaths(p)
    if (!paths.length) continue

    let anyMalware = false
    for (const x of paths) {
      const k = normalizePathKey(x)
      const res = k ? map.get(k) : undefined
      if (isMalware(res)) {
        anyMalware = true
        break
      }
    }

    if (!anyMalware) {
      for (const x of paths) allowPaths.add(x)
      clearPids.push(pid)
      if (p.paused === true) resumePids.push(pid)
    }
  }

  return { allowPaths: Array.from(allowPaths), clearPids, resumePids }
}

module.exports = { normalizePathKey, isMalware, getPayloadPaths, decideSnapshotActions }
