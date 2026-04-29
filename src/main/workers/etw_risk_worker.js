const { parentPort } = require('worker_threads')
const path = require('path')
const fs = require('fs')
const { createScannerClient } = require('../scanner_client')

let winapi = null
try { winapi = require('../winapi') } catch { winapi = null }

let cfg = {
  appDirLower: '',
  systemRootDirLower: ((process.env.SystemRoot || 'C:\\Windows') + '\\').toLowerCase().replace(/\//g, '\\'),
  scanner: null,
  scan: null
}

/**
 * - 函数: `postMessage`
 * - Function: `postMessage`
 * - 作用: 向主线程回传 ETW 风险 worker 产生的 `risk_payload`，是本 worker 唯一的告警输出通道。
 * - Purpose: Sends `risk_payload` alerts produced by the ETW risk worker back to the main thread and acts as this worker’s sole outbound alert channel.
 * - 调用方: `handleProcessStart`、`handleFileEvent`、`handleRuleMatch` 在命中可疑样本后调用。
 * - Callers: Called by `handleProcessStart`, `handleFileEvent`, and `handleRuleMatch` after suspicious samples are confirmed.
 * - 被调方: `parentPort.postMessage`。
 * - Callees: `parentPort.postMessage`.
 * - 变量说明: `msg` 为发往主线程的风险告警消息，通常包含 `type: 'risk_payload'` 与完整告警 `payload`。
 * - Variables: `msg` is the risk alert sent to the main thread, usually containing `type: 'risk_payload'` and the full alert `payload`.
 * - 接入方式: 仅在 `etw_risk_worker` 内部使用；新增风险输出类型时应继续通过本函数统一发送。
 * - Integration: Use only inside `etw_risk_worker`; new risk-output message types should still be sent through this helper.
 * - 错误处理: `parentPort` 缺失时直接返回；本函数不主动吞掉 `postMessage` 异常，因此调用方需要保证消息结构完整。
 * - Error Handling: Returns immediately when `parentPort` is missing; this helper does not actively swallow `postMessage` failures, so callers must keep payloads valid.
 * - 关键词: 风险告警 | risk alert | risk_payload | 主线程桥接 | main-thread bridge | ETW worker | 告警回传 | alert dispatch | parentPort | security event
 */
function postMessage(msg) {
  if (!parentPort) return
  parentPort.postMessage(msg)
}

/**
 * - 函数: `normalizeLowerPath`
 * - Function: `normalizeLowerPath`
 * - 作用: 把文件或目录路径统一规整为“小写 + 反斜杠”的比较形式，作为 App 目录过滤、系统目录判断和风险事件归一路径比较的基础工具。
 * - Purpose: Normalizes file or directory paths into a “lowercase + backslashes” comparison form, serving as the base helper for app-dir filtering, system-dir checks, and path comparisons across risk events.
 * - 调用方: `normalizeLowerDir`、`shouldSkipAppDir` 直接复用；`handleProcessStart`、`handleFileEvent`、`handleRuleMatch` 在比较系统目录与目标路径时调用。
 * - Callers: Reused directly by `normalizeLowerDir` and `shouldSkipAppDir`, and called by `handleProcessStart`, `handleFileEvent`, and `handleRuleMatch` when comparing system directories and target paths.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `p` 为待规整的原始路径文本。
 * - Variables: `p` is the raw path text being normalized.
 * - 接入方式: 应作为本 worker 内部路径比较的统一入口；新的路径过滤条件不要各自重复做大小写和分隔符规整。
 * - Integration: It should remain the single path-normalization entry inside this worker; new path filters should not duplicate their own case and separator normalization.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 小写路径归一化 | lower path normalization | backslash normalization | appDir filter | systemRoot compare | risk path compare | canonical path text | ETW risk helper
 */
function normalizeLowerPath(p) {
  if (typeof p !== 'string') return ''
  return p.trim().toLowerCase().replace(/\//g, '\\')
}

/**
 * - 函数: `normalizeLowerDir`
 * - Function: `normalizeLowerDir`
 * - 作用: 在 `normalizeLowerPath()` 的基础上进一步保证目录路径总是以反斜杠结尾，便于后续做“是否位于某目录下”的前缀判断。
 * - Purpose: Builds on `normalizeLowerPath()` and additionally guarantees a trailing backslash so later “is this path under a directory” checks can rely on prefix matching.
 * - 调用方: `parentPort.on('message')` 处理 `config` 消息时调用，用于初始化 `cfg.appDirLower` 与 `cfg.systemRootDirLower`。
 * - Callers: Called by `parentPort.on('message')` while handling the `config` message to initialize `cfg.appDirLower` and `cfg.systemRootDirLower`.
 * - 被调方: `normalizeLowerPath`。
 * - Callees: `normalizeLowerPath`.
 * - 变量说明: `p` 为原始目录路径；`s` 为规整后的目录文本。
 * - Variables: `p` is the raw directory path; `s` is the normalized directory text.
 * - 接入方式: 应作为目录前缀比较的统一入口；新的目录型配置字段应优先经由本函数归一化。
 * - Integration: It should remain the shared entry for directory-prefix comparisons; new directory-style config fields should be normalized through it first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 小写目录归一化 | lower directory normalization | trailing backslash | appDirLower | systemRootDirLower | prefix compare prep | config normalization | path helper
 */
function normalizeLowerDir(p) {
  let s = normalizeLowerPath(p)
  if (s && !s.endsWith('\\')) s += '\\'
  return s
}

/**
 * - 函数: `isUnderDir`
 * - Function: `isUnderDir`
 * - 作用: 判断一个已归一化路径是否落在某个已归一化目录前缀下，用于识别应用目录内文件和系统目录内主体。
 * - Purpose: Determines whether a normalized path falls under a normalized directory prefix, enabling recognition of files under the app directory and actors under the system directory.
 * - 调用方: `shouldSkipAppDir` 直接复用；`handleProcessStart`、`handleFileEvent`、`handleRuleMatch` 在判定系统目录主体时调用。
 * - Callers: Reused directly by `shouldSkipAppDir`, and called by `handleProcessStart`, `handleFileEvent`, and `handleRuleMatch` when judging system-directory actors.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `lowerPath` 为已规整的小写路径；`lowerDir` 为已规整且带尾反斜杠的目录前缀。
 * - Variables: `lowerPath` is the normalized lowercase path; `lowerDir` is the normalized directory prefix with a trailing backslash.
 * - 接入方式: 仅作为路径前缀判定 helper 使用；新的目录归属判断应优先复用它。
 * - Integration: Use it only as the path-prefix membership helper; new directory-membership checks should reuse it first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 目录归属判断 | under directory check | prefix match | appDir membership | systemRoot membership | normalized path compare | path containment | risk filter helper
 */
function isUnderDir(lowerPath, lowerDir) {
  if (!lowerPath || !lowerDir) return false
  return lowerPath.startsWith(lowerDir)
}

/**
 * - 函数: `shouldSkipAppDir`
 * - Function: `shouldSkipAppDir`
 * - 作用: 判断某个路径是否位于当前应用目录下，用于避免风险 worker 把本程序自身目录中的文件和模块当成可疑落地样本反复扫描。
 * - Purpose: Determines whether a path is inside the current app directory so the risk worker does not repeatedly rescan files and modules that belong to the product itself.
 * - 调用方: `handleProcessStart`、`handleFileEvent`、`handleRuleMatch` 在做签名补扫前都会先调用本函数降噪。
 * - Callers: Called by `handleProcessStart`, `handleFileEvent`, and `handleRuleMatch` before any signature follow-up scan as a noise-reduction guard.
 * - 被调方: `normalizeLowerPath`、`isUnderDir`。
 * - Callees: `normalizeLowerPath`, `isUnderDir`.
 * - 变量说明: `p` 为待判断路径；`lower` 为归一化后的路径文本。
 * - Variables: `p` is the path being evaluated; `lower` is the normalized path text.
 * - 接入方式: 应作为“是否跳过应用自身目录”这一规则的统一入口；新的风险处理分支若也要排除产品目录，应优先复用本函数。
 * - Integration: It should be the single entry for the “skip the product’s own directory” rule; new risk-handling branches that need the same exclusion should reuse it.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 应用目录跳过 | skip app directory | self-noise suppression | appDirLower check | self file exclusion | ETW risk filter | product directory guard | rescan noise control
 */
function shouldSkipAppDir(p) {
  const lower = normalizeLowerPath(p || '')
  return !!(lower && cfg.appDirLower && isUnderDir(lower, cfg.appDirLower))
}

const scannerClient = createScannerClient(() => ({ scanner: cfg.scanner || {}, scan: cfg.scan || {} }))

/**
 * - 函数: `isMalware`
 * - Function: `isMalware`
 * - 作用: 兼容不同扫描结果字段名，把 `infected / is_malware / malicious` 三类返回统一折叠成风险 worker 可消费的恶意布尔 verdict。
 * - Purpose: Unifies scanner results with different field names by folding `infected / is_malware / malicious` into one boolean malware verdict consumable by the risk worker.
 * - 调用方: `scanFileWithHashCache` 在归一化扫描结果并生成最终 verdict 时调用。
 * - Callers: Called by `scanFileWithHashCache` while normalizing scan results into the final verdict.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `res` 为 `scannerClient` 返回的原始扫描结果对象。
 * - Variables: `res` is the raw scan result object returned by `scannerClient`.
 * - 接入方式: 应作为扫描结果布尔恶意判定的统一入口；新增 verdict 字段兼容时优先扩展本函数。
 * - Integration: It should remain the shared entry for boolean malware verdict checks; new verdict field compatibility should be added here first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 恶意布尔归一化 | malware boolean normalization | infected flag | is_malware flag | malicious flag | scanner verdict fold | risk worker helper | unified malware check
 */
function isMalware(res) {
  if (!res || typeof res !== 'object') return false
  if (res.infected === true) return true
  if (res.is_malware === true) return true
  if (res.malicious === true) return true
  return false
}

/**
 * - 函数: `scanFileWithHashCache`
 * - Function: `scanFileWithHashCache`
 * - 作用: 结合本地扫描缓存与 `scannerClient.scanFile()` 对目标文件做风险判定，优先复用已有 verdict，未命中缓存时再落到真实扫描，是 ETW 风险筛查的统一扫描入口。
 * - Purpose: Combines the local scan cache with `scannerClient.scanFile()` to evaluate a target file, preferring cached verdicts first and falling back to real scanning when needed, making it the unified scan entry for ETW risk screening.
 * - 调用方: `handleProcessStart`、`handleFileEvent`、`handleRuleMatch` 在需要对目标文件做签名/恶意判定时调用。
 * - Callers: Called by `handleProcessStart`, `handleFileEvent`, and `handleRuleMatch` whenever a target file needs signature or malware evaluation.
 * - 被调方: `scanFile`、`isMalware`、`path.extname`、`Number.isFinite`、`Math.max`、`Math.floor`。
 * - Callees: `scanFile`, `isMalware`, `path.extname`, `Number.isFinite`, `Math.max`, `Math.floor`.
 * - 变量说明: `filePath` 为待判定文件；`requestIdPrefix` 用于生成扫描请求 ID；`lookup` 为缓存查询结果；`res` 为真实扫描结果；`verdict/hash/malware` 为最终归一化判定。
 * - Variables: `filePath` is the file under evaluation; `requestIdPrefix` generates the scan request id; `lookup` is the cache lookup result; `res` is the real scan result; `verdict/hash/malware` are the normalized final verdict fields.
 * - 接入方式: 仅供本 worker 的风险处理入口复用；新增 ETW 风险场景应继续走本函数，保持缓存、大小限制和 common-extension 策略一致。
 * - Integration: Reuse only from risk-handling entries in this worker; new ETW risk scenarios should continue to go through this helper so cache usage, file-size limits, and common-extension policy stay consistent.
 * - 错误处理: 参数无效、扫描器不可用、缓存 API 不可用或文件过大时直接返回 `skipped`；其余文件系统异常通过局部容错继续，让风险 worker 尽量不中断整条事件流。
 * - Error Handling: Returns `skipped` for invalid input, unavailable scanner/cache APIs, or oversized files; other filesystem errors are tolerated locally so the ETW event stream keeps flowing.
 * - 关键词: 扫描缓存 | scan cache | hash verdict | scannerClient.scanFile | 恶意判定 | malware verdict | 文件筛查 | file screening | ETW risk | cache fallback
 */
async function scanFileWithHashCache(filePath, requestIdPrefix) {
  const p = typeof filePath === 'string' ? filePath : ''
  if (!p) return { ok: false, skipped: true }
  if (!scannerClient || typeof scannerClient.scanFile !== 'function') return { ok: false, skipped: true }
  if (!winapi || typeof winapi.scanCacheLookupByFile !== 'function' || typeof winapi.scanCacheStore !== 'function') return { ok: false, skipped: true }

  const scanCfg = cfg.scan && typeof cfg.scan === 'object' ? cfg.scan : {}
  const onlyCommonExt = scanCfg.commonExtensionsOnly === true
  const ext = path.extname(p).toLowerCase()
  if (onlyCommonExt && ext !== '.exe' && ext !== '.dll') return { ok: false, skipped: true }

  const sc = cfg.scanner && typeof cfg.scanner === 'object' ? cfg.scanner : {}
  const maxMB = Number.isFinite(sc.maxFileSizeMB) ? Math.max(1, Math.floor(sc.maxFileSizeMB)) : 500
  try {
    const st = fs.statSync(p)
    if (st && st.size > maxMB * 1024 * 1024) return { ok: false, skipped: true, tooLarge: true }
  } catch {}

  let lookup = null
  try { lookup = winapi.scanCacheLookupByFile(p) } catch { lookup = null }
  if (lookup && lookup.hit === true) {
    return { ok: true, cached: true, verdict: lookup.verdict, hash: lookup.hash, malware: lookup.verdict === 2 }
  }

  const rid = `${requestIdPrefix || 'etw_scan'}_${Date.now()}_${Math.random().toString(16).slice(2)}`
  const res = await scannerClient.scanFile(p, rid)
  const malware = isMalware(res)
  const verdict = malware ? 2 : 1
  const hash = lookup && typeof lookup.hash === 'string' ? lookup.hash : null
  if (hash) {
    try { winapi.scanCacheStore(hash, verdict) } catch {}
  }
  return { ok: true, cached: false, verdict, hash, malware, res }
}

/**
 * - 函数: `handleProcessStart`
 * - Function: `handleProcessStart`
 * - 作用: 在进程启动事件到达时检查启动进程及其已加载 DLL 的签名状态，对未签名目标执行补充扫描；一旦确认命中恶意样本，就挂起进程并向主线程上报告警。
 * - Purpose: Handles process-start events by checking the signature state of the launched process and its loaded DLLs, scanning unsigned targets as needed, and suspending/reporting the process once malware is confirmed.
 * - 调用方: `parentPort.on('message')` 收到 `type === 'process_start'` 后经 `enqueue()` 排队调用。
 * - Callers: Queued through `enqueue()` by `parentPort.on('message')` after receiving `type === 'process_start'`.
 * - 被调方: `shouldSkipAppDir`、`normalizeLowerPath`、`isUnderDir`、`push`、`scanFileWithHashCache`、`postMessage`。
 * - Callees: `shouldSkipAppDir`, `normalizeLowerPath`, `isUnderDir`, `push`, `scanFileWithHashCache`, `postMessage`.
 * - 变量说明: `job` 为进程启动任务；`pid/imagePath` 标识进程主体；`unsignedTargets` 收集待补扫的未签名文件；`malwareHit` 保存最终命中的恶意样本信息。
 * - Variables: `job` is the process-start task; `pid/imagePath` identify the process; `unsignedTargets` collects unsigned files to rescan; `malwareHit` stores the final malicious hit.
 * - 接入方式: 仅在 ETW 进程启动风险链路中使用；新增进程启动类规则若需要做落地文件复扫，应优先沿用本函数。
 * - Integration: Use only in the ETW process-start risk path; new process-start rules that need follow-up file rescans should reuse this function.
 * - 错误处理: 多数签名校验与模块枚举异常通过局部容错跳过；只有真正构造出 `malwareHit` 时才输出 `risk_payload`，避免把不确定噪声升级成告警。
 * - Error Handling: Most signature-check and module-enumeration failures are tolerated locally; a `risk_payload` is emitted only when a concrete `malwareHit` exists, preventing noisy uncertainty from becoming an alert.
 * - 关键词: 进程启动风险 | process-start risk | DLL补扫 | module rescan | 未签名目标 | unsigned targets | suspendProcessByPid | malwareHit | risk_payload | ETW process
 */
async function handleProcessStart(job) {
  const pid = Number.isFinite(job && job.pid) ? job.pid : parseInt(String(job && job.pid), 10)
  const imagePath = typeof (job && job.imagePath) === 'string' ? job.imagePath : ''
  if (!Number.isFinite(pid) || pid <= 0) return
  if (!imagePath) return
  if (!winapi || typeof winapi.verifyTrust !== 'function') return
  if (shouldSkipAppDir(imagePath)) return

  const lowerImg = normalizeLowerPath(imagePath)
  let procSigned = false
  try { procSigned = winapi.verifyTrust(imagePath) === true } catch { procSigned = false }
  if (procSigned && isUnderDir(lowerImg, cfg.systemRootDirLower)) return

  const unsignedTargets = []
  if (!procSigned) unsignedTargets.push(imagePath)

  await new Promise((r) => setTimeout(r, 350))
  const bufBytes = Number.isFinite(job && job.modulesBufferBytes) ? Math.max(4096, Math.min(1024 * 1024, Math.floor(job.modulesBufferBytes))) : 262144
  let mods = []
  try { mods = winapi.getProcessModules(pid, bufBytes) } catch { mods = [] }
  const arr = Array.isArray(mods) ? mods : []
  for (const mp0 of arr) {
    const mp = typeof mp0 === 'string' ? mp0 : ''
    if (!mp) continue
    const lower = normalizeLowerPath(mp)
    if (!lower.endsWith('.dll')) continue
    if (shouldSkipAppDir(lower)) continue
    let ok = false
    try { ok = winapi.verifyTrust(mp) === true } catch { ok = false }
    if (ok) continue
    unsignedTargets.push(mp)
    if (unsignedTargets.length >= 16) break
  }

  if (!unsignedTargets.length) return
  let malwareHit = null
  for (const target of unsignedTargets) {
    const r = await scanFileWithHashCache(target, 'etw_procstart')
    if (r && r.ok && r.malware) {
      malwareHit = { path: target, verdict: r.verdict, hash: r.hash || null, res: r.res || null }
      break
    }
  }
  if (!malwareHit) return

  let paused = false
  if (winapi && typeof winapi.suspendProcessByPid === 'function') {
    try { paused = winapi.suspendProcessByPid(pid) === true } catch { paused = false }
  }
  postMessage({
    type: 'risk_payload',
    payload: {
      pid,
      paused,
      triggeredAt: Date.now(),
      threatType: '进程启动签名异常',
      severity: 5,
      recommendAction: 'block',
      match: { ruleId: 'process_start_signature_scan', provider: 'Process', op: 'Start', target: imagePath },
      process: { name: typeof job.processName === 'string' ? job.processName : '', imagePath },
      event: { provider: 'Process', data: { type: 'ProcessStartSignature', processSigned: procSigned, unsignedTargets, malwareHit } }
    }
  })
}

/**
 * - 函数: `handleFileEvent`
 * - Function: `handleFileEvent`
 * - 作用: 对 ETW 文件操作事件中的目标文件做签名与恶意判定；若文件本身未签名且扫描命中恶意，则尝试挂起行为主体并回传文件风险告警。
 * - Purpose: Evaluates the signature and malware state of ETW file-operation targets; if the file is unsigned and scans as malicious, it optionally suspends the actor process and reports a file-risk alert.
 * - 调用方: `parentPort.on('message')` 收到 `type === 'file_event'` 后经 `enqueue()` 排队调用。
 * - Callers: Queued through `enqueue()` by `parentPort.on('message')` after receiving `type === 'file_event'`.
 * - 被调方: `shouldSkipAppDir`、`normalizeLowerPath`、`isUnderDir`、`scanFileWithHashCache`、`postMessage`、`Number.isFinite`。
 * - Callees: `shouldSkipAppDir`, `normalizeLowerPath`, `isUnderDir`, `scanFileWithHashCache`, `postMessage`, `Number.isFinite`.
 * - 变量说明: `job` 为文件事件任务；`pid/filePath/op` 描述行为主体和操作；`actorImage` 为触发文件动作的进程镜像；`scan` 保存最终扫描结论。
 * - Variables: `job` is the file-event task; `pid/filePath/op` describe the actor and action; `actorImage` is the process image that triggered the file action; `scan` stores the final scan verdict.
 * - 接入方式: 仅在文件类 ETW 风险链路中使用；新增文件写入/落地类规则如果需要扫描文件实体，应优先复用本函数。
 * - Integration: Use only in file-oriented ETW risk flows; new write/dropper style rules that need file-entity scanning should reuse this function first.
 * - 错误处理: 系统目录中的已签名主体会被提前放行；只有目标文件未签名且扫描确认恶意时才上报告警，降低误报。
 * - Error Handling: Signed actors under system directories are early-allowed; an alert is emitted only when the target file is unsigned and scanning confirms malware, reducing false positives.
 * - 关键词: 文件风险事件 | file risk event | 文件签名异常 | unsigned file | actorImage | 文件落地扫描 | file rescan | suspend process | risk_payload | ETW file
 */
async function handleFileEvent(job) {
  const pid = Number.isFinite(job && job.pid) ? job.pid : parseInt(String(job && job.pid), 10)
  const filePath = typeof (job && job.filePath) === 'string' ? job.filePath : ''
  const op = typeof (job && job.op) === 'string' ? job.op : ''
  const actorImage = typeof (job && job.actorImage) === 'string' ? job.actorImage : ''
  if (!Number.isFinite(pid) || pid <= 0) return
  if (!filePath) return
  if (!winapi || typeof winapi.verifyTrust !== 'function') return
  if (shouldSkipAppDir(filePath)) return
  if (actorImage && shouldSkipAppDir(actorImage)) return

  const actorLower = normalizeLowerPath(actorImage)
  if (actorLower && isUnderDir(actorLower, cfg.systemRootDirLower)) {
    let ok = false
    try { ok = winapi.verifyTrust(actorImage) === true } catch { ok = false }
    if (ok) return
  }

  let fileSigned = false
  try { fileSigned = winapi.verifyTrust(filePath) === true } catch { fileSigned = false }
  if (fileSigned) return

  const scan = await scanFileWithHashCache(filePath, 'etw_file')
  if (!(scan && scan.ok && scan.malware)) return

  let paused = false
  if (winapi && typeof winapi.suspendProcessByPid === 'function') {
    try { paused = winapi.suspendProcessByPid(pid) === true } catch { paused = false }
  }
  postMessage({
    type: 'risk_payload',
    payload: {
      pid,
      paused,
      triggeredAt: Date.now(),
      threatType: '文件操作签名异常',
      severity: 5,
      recommendAction: 'block',
      match: { ruleId: 'file_event_signature_scan', provider: 'File', op, target: filePath },
      process: { name: typeof job.processName === 'string' ? job.processName : '', imagePath: actorImage },
      event: { provider: 'File', data: { type: 'FileSignature', op, filePath, malwareHit: { verdict: scan.verdict, hash: scan.hash || null, res: scan.res || null } } }
    }
  })
}

/**
 * - 函数: `handleRuleMatch`
 * - Function: `handleRuleMatch`
 * - 作用: 在 ETW 规则已初步命中后，对命中的落地文件再次执行签名/恶意确认，并结合规则元数据构造更完整的拦截告警。
 * - Purpose: After an ETW rule has already matched preliminarily, revalidates the matched file through signature/malware checks and enriches the final interception alert with rule metadata.
 * - 调用方: `parentPort.on('message')` 收到 `type === 'rule_match'` 后经 `enqueue()` 排队调用。
 * - Callers: Queued through `enqueue()` by `parentPort.on('message')` after receiving `type === 'rule_match'`.
 * - 被调方: `shouldSkipAppDir`、`normalizeLowerPath`、`isUnderDir`、`scanFileWithHashCache`、`postMessage`、`Number.isFinite`。
 * - Callees: `shouldSkipAppDir`, `normalizeLowerPath`, `isUnderDir`, `scanFileWithHashCache`, `postMessage`, `Number.isFinite`.
 * - 变量说明: `job` 为规则命中任务；`scanPath` 为需要补扫的目标路径；`ruleId/provider/op/threatType/severity` 为构造最终告警所需的规则上下文；`scan` 保存复扫结论。
 * - Variables: `job` is the rule-match task; `scanPath` is the path that needs a follow-up scan; `ruleId/provider/op/threatType/severity` carry rule context for the final alert; `scan` stores the follow-up verdict.
 * - 接入方式: 仅在规则匹配后的二次确认链路使用；新增规则引擎若已有初筛能力，可通过本函数补齐文件级恶意确认。
 * - Integration: Use only in the post-match secondary-confirmation path; new rule engines that already have a first-pass match can reuse this function to add file-level malware confirmation.
 * - 错误处理: 已签名目标和允许动作会被提前降噪放行；只有复扫命中恶意时才向主线程回传 `risk_payload`，避免规则初筛直接触发高风险处置。
 * - Error Handling: Signed targets and allow-listed actions are quieted early; `risk_payload` is returned to the main thread only when the follow-up scan confirms malware, preventing raw first-pass matches from triggering high-risk remediation immediately.
 * - 关键词: 规则二次确认 | rule confirmation | rule_match | scanPath | 风险增强 | enriched alert | malware confirmation | severity | recommendAction | ETW match
 */
async function handleRuleMatch(job) {
  const pid = Number.isFinite(job && job.pid) ? job.pid : parseInt(String(job && job.pid), 10)
  const imagePath = typeof (job && job.imagePath) === 'string' ? job.imagePath : ''
  const scanPath = typeof (job && job.scanPath) === 'string' ? job.scanPath : ''
  const provider = typeof (job && job.provider) === 'string' ? job.provider : ''
  const op = typeof (job && job.op) === 'string' ? job.op : ''
  const ruleId = typeof (job && job.ruleId) === 'string' ? job.ruleId : ''
  const threatType = typeof (job && job.threatType) === 'string' ? job.threatType : ''
  const severity = Number.isFinite(job && job.severity) ? job.severity : parseInt(String(job && job.severity), 10)
  const recommendAction = typeof (job && job.recommendAction) === 'string' ? job.recommendAction : 'block'
  if (!Number.isFinite(pid) || pid <= 0) return
  if (!scanPath) return
  if (!winapi || typeof winapi.verifyTrust !== 'function') return
  if (imagePath && shouldSkipAppDir(imagePath)) return
  if (shouldSkipAppDir(scanPath)) return

  const actorLower = normalizeLowerPath(imagePath)
  if (actorLower && isUnderDir(actorLower, cfg.systemRootDirLower)) {
    let ok = false
    try { ok = winapi.verifyTrust(imagePath) === true } catch { ok = false }
    if (ok) return
  }

  let signed = false
  try { signed = winapi.verifyTrust(scanPath) === true } catch { signed = false }
  if (signed) return

  const scan = await scanFileWithHashCache(scanPath, 'etw_match')
  if (!(scan && scan.ok && scan.malware)) return

  let paused = false
  if (recommendAction !== 'allow' && winapi && typeof winapi.suspendProcessByPid === 'function') {
    try { paused = winapi.suspendProcessByPid(pid) === true } catch { paused = false }
  }
  postMessage({
    type: 'risk_payload',
    payload: {
      pid,
      paused,
      triggeredAt: Date.now(),
      threatType: threatType || ruleId || 'ETW_MATCH',
      severity: Number.isFinite(severity) ? severity : 4,
      recommendAction,
      match: { ruleId: ruleId || 'ETW_MATCH', provider, op, target: scanPath },
      process: { name: typeof job.processName === 'string' ? job.processName : '', imagePath },
      event: { provider, data: { type: 'RuleMatchScan', match: job.match || null, scanPath, malwareHit: { verdict: scan.verdict, hash: scan.hash || null, res: scan.res || null } } },
      context: Array.isArray(job.context) ? job.context : []
    }
  })
}

const queue = []
let busy = false
const keys = new Set()

/**
 * - 函数: `enqueue`
 * - Function: `enqueue`
 * - 作用: 将 ETW 风险任务按去重键放入串行执行队列，避免同一 PID/文件/规则在极短时间内被重复扫描，是风险 worker 的入口节流器。
 * - Purpose: Queues ETW risk jobs behind a deduplication key so the same PID/file/rule is not rescanned repeatedly in a short window, making it the intake throttler of the risk worker.
 * - 调用方: `parentPort.on('message')` 在处理 `process_start`、`file_event`、`rule_match` 三类消息时调用。
 * - Callers: Called by `parentPort.on('message')` while dispatching `process_start`, `file_event`, and `rule_match` messages.
 * - 被调方: `push`。
 * - Callees: `push`.
 * - 变量说明: `key` 为去重键；`fn` 为真正要执行的风险任务；`keys` 记录当前已经在队列或执行中的任务键；`queue` 保存待执行任务闭包。
 * - Variables: `key` is the deduplication key; `fn` is the actual risk task; `keys` records jobs already queued or running; `queue` stores pending task closures.
 * - 接入方式: 仅在本 worker 内部作为统一入队点使用；新增风险事件类型时建议先设计稳定去重键，再通过本函数接入。
 * - Integration: Use only as the unified queue entry inside this worker; new risk-event types should design a stable dedupe key first and then feed into this helper.
 * - 错误处理: 空键或重复键直接丢弃；任务执行异常会被局部吞掉，但最终一定会从 `keys` 中移除，避免重复键永久卡死。
 * - Error Handling: Empty or duplicate keys are dropped immediately; task failures are swallowed locally, but the key is always removed from `keys` so dedupe entries do not get stuck forever.
 * - 关键词: 去重入队 | deduped enqueue | ETW节流 | ETW throttling | keys set | queue push | 防抖扫描 | duplicate suppression | setImmediate | risk scheduler
 */
function enqueue(key, fn) {
  const k = typeof key === 'string' ? key : ''
  if (!k) return
  if (keys.has(k)) return
  keys.add(k)
  queue.push(async () => {
    try { await fn() } catch {}
    keys.delete(k)
  })
  setImmediate(pump)
}

/**
 * - 函数: `pump`
 * - Function: `pump`
 * - 作用: 顺序消费 `enqueue()` 写入的风险任务队列，保证同一时刻只有一个任务在执行，从而避免签名校验、扫描缓存和挂起动作互相踩踏。
 * - Purpose: Consumes the risk-task queue written by `enqueue()` sequentially, ensuring only one task runs at a time so signature checks, scan-cache access, and process suspension do not interfere with each other.
 * - 调用方: `enqueue` 在新任务写入队列后通过 `setImmediate(pump)` 触发。
 * - Callers: Triggered by `enqueue` through `setImmediate(pump)` whenever new work enters the queue.
 * - 被调方: 队列中的任务闭包。
 * - Callees: The queued task closures themselves.
 * - 变量说明: 无显式入参；`busy` 表示当前是否已有任务在执行；`job` 为从队列取出的待执行风险任务。
 * - Variables: No explicit parameters; `busy` marks whether a task is already executing; `job` is the queued risk task popped from the queue.
 * - 接入方式: 仅作为本 worker 的内部调度器使用；新增任务类型无需直接调用它，只需经由 `enqueue()` 触发。
 * - Integration: Use only as the internal scheduler of this worker; new task types should not call it directly and should go through `enqueue()` instead.
 * - 错误处理: 借助 `busy` 防止重入；`finally` 中必定复位 `busy`，避免单次任务异常后整个调度器永久失活。
 * - Error Handling: Prevents re-entry through `busy`; `finally` always resets `busy`, so one task failure cannot permanently stall the scheduler.
 * - 关键词: 串行调度 | serial scheduler | queue pump | busy flag | 风险任务 | risk jobs | setImmediate | 顺序消费 | non-reentrant | ETW worker
 */
async function pump() {
  if (busy) return
  busy = true
  try {
    while (queue.length) {
      const job = queue.shift()
      if (job) await job()
    }
  } finally {
    busy = false
  }
}

if (parentPort) {
  parentPort.on('message', (msg) => {
    const m = msg && typeof msg === 'object' ? msg : {}
    if (m.type === 'config') {
      const appDir = typeof m.appDir === 'string' ? m.appDir : ''
      cfg.appDirLower = normalizeLowerDir(appDir)
      const sr = typeof m.systemRoot === 'string' ? m.systemRoot : (process.env.SystemRoot || 'C:\\Windows')
      cfg.systemRootDirLower = normalizeLowerDir(sr)
      cfg.scanner = m.scanner && typeof m.scanner === 'object' ? m.scanner : null
      cfg.scan = m.scan && typeof m.scan === 'object' ? m.scan : null
      return
    }
    if (m.type === 'process_start') {
      const pid = Number.isFinite(m.pid) ? m.pid : parseInt(String(m.pid), 10)
      enqueue(`procstart:${pid}`, () => handleProcessStart(m))
      return
    }
    if (m.type === 'file_event') {
      const pid = Number.isFinite(m.pid) ? m.pid : parseInt(String(m.pid), 10)
      const fp = typeof m.filePath === 'string' ? m.filePath : ''
      enqueue(`file:${pid}:${m.op}:${fp}`, () => handleFileEvent(m))
      return
    }
    if (m.type === 'rule_match') {
      const pid = Number.isFinite(m.pid) ? m.pid : parseInt(String(m.pid), 10)
      const sp = typeof m.scanPath === 'string' ? m.scanPath : ''
      enqueue(`match:${pid}:${m.ruleId}:${sp}`, () => handleRuleMatch(m))
    }
  })
}
