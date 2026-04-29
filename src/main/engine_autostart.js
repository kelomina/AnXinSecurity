const fs = require('fs')
const path = require('path')
const childProcess = require('child_process')
const net = require('net')

/**
 * - 函数: `normalizeProcessName`
 * - Function: `normalizeProcessName`
 * - 作用: 规范化 `taskkill` 等 Windows 进程控制命令使用的进程名，确保空白输入被过滤，并在需要时补齐 `.exe` 后缀。
 * - Purpose: Normalizes process names used by Windows process-control commands such as `taskkill`, filtering blank input and appending the `.exe` suffix when necessary.
 * - 调用方: `killProcessWin32` 在拼接 `taskkill` 命令前调用本函数。
 * - Callers: `killProcessWin32` invokes this helper before composing the `taskkill` command.
 * - 被调方: 字符串 `trim`、`toLowerCase`、`endsWith`。
 * - Callees: String `trim`, `toLowerCase`, and `endsWith`.
 * - 变量说明: `name` 为待规范化的进程名；`trimmed` 为去除首尾空白后的结果；返回值为可直接送入命令行的进程名字符串。
 * - Variables: `name` is the raw process name, `trimmed` is the whitespace-trimmed result, and the return value is the normalized name ready for command-line use.
 * - 接入方式: 所有基于进程名执行 Windows 控制命令的逻辑都应先经过本函数，不要在调用方重复拼接 `.exe` 后缀。
 * - Integration: Any Windows control flow driven by process name should pass through this helper first instead of rebuilding `.exe` suffix logic in each caller.
 * - 错误处理: 非字符串或空白输入统一返回空字符串，由上层据此终止后续命令执行。
 * - Error Handling: Non-string or blank input collapses to an empty string so upper layers can stop the command flow safely.
 * - 关键词: 进程名规范化 | process name normalization | taskkill参数准备 | taskkill argument prep | exe后缀补齐 | exe suffix completion | Windows进程控制 | Windows process control | 空白输入过滤 | blank input filtering
 */
function normalizeProcessName(name) {
  if (typeof name !== 'string') return ''
  const trimmed = name.trim()
  return trimmed.toLowerCase().endsWith('.exe') ? trimmed : (trimmed ? (trimmed + '.exe') : '')
}

/**
 * - 函数: `isAbsolutePath`
 * - Function: `isAbsolutePath`
 * - 作用: 判断给定字符串是否为可用的绝对路径，供引擎可执行文件路径解析链路区分“直接使用”与“按基础目录拼接”两种分支。
 * - Purpose: Checks whether the given string is a usable absolute path so the engine executable resolver can decide between direct use and base-directory resolution.
 * - 调用方: `resolveExePath`。
 * - Callers: `resolveExePath`.
 * - 被调方: `path.isAbsolute`。
 * - Callees: `path.isAbsolute`.
 * - 变量说明: `p` 为待检测路径；返回值表示该路径是否为非空绝对路径。
 * - Variables: `p` is the path under inspection, and the return value indicates whether it is a non-empty absolute path.
 * - 接入方式: 本模块内部所有需要区分绝对路径与相对路径的逻辑都应复用本函数。
 * - Integration: Any internal logic that needs to distinguish absolute from relative paths should reuse this helper.
 * - 错误处理: 非字符串或空字符串直接返回 `false`，让上层继续走相对路径解析或失败回退。
 * - Error Handling: Non-string and empty-string input returns `false`, allowing callers to continue with relative-path resolution or fallback handling.
 * - 关键词: 绝对路径判断 | absolute path check | 可执行文件定位 | executable location | 路径分支选择 | path branch selection | 基础目录解析 | base directory resolution | 路径守卫 | path guard
 */
function isAbsolutePath(p) {
  return typeof p === 'string' && p.length > 0 && path.isAbsolute(p)
}

/**
 * - 函数: `resolveExePath`
 * - Function: `resolveExePath`
 * - 作用: 根据绝对路径或相对路径候选解析扫描引擎可执行文件实际位置，是自动启动流程选定启动目标的核心路径定位器。
 * - Purpose: Resolves the real scanner-engine executable location from either an absolute or relative candidate, making it the core path locator used by autostart.
 * - 调用方: `startIfNeeded`。
 * - Callers: `startIfNeeded`.
 * - 被调方: `isAbsolutePath`、`fs.existsSync`、`path.resolve`、数组 `filter`。
 * - Callees: `isAbsolutePath`, `fs.existsSync`, `path.resolve`, and array `filter`.
 * - 变量说明: `exePathOrRelative` 为配置里的可执行路径候选；`baseDirs` 为相对路径解析根目录集合；`deps.fs`/`deps.path` 支持测试替身；`raw` 为裁剪空白后的输入；`bases` 为有效基础目录列表。
 * - Variables: `exePathOrRelative` is the configured executable-path candidate, `baseDirs` is the list of roots for relative resolution, `deps.fs` and `deps.path` support test doubles, `raw` is the trimmed input, and `bases` is the filtered base-directory list.
 * - 接入方式: 自动启动链路应统一通过本函数拿到最终 exe 路径；若将来支持多平台或多候选文件名，也应继续在这里扩展。
 * - Integration: The autostart flow should always obtain the final executable path through this helper; if multi-platform or multi-candidate support is added later, extend this function rather than branching elsewhere.
 * - 错误处理: 输入为空、绝对路径不存在或所有相对路径候选都失效时返回 `null`，交由上层给出 `exe_not_found` 等结构化结果。
 * - Error Handling: Empty input, missing absolute paths, or exhausted relative candidates all return `null`, allowing upper layers to emit structured results such as `exe_not_found`.
 * - 关键词: exe路径解析 | exe path resolution | 相对路径查找 | relative path lookup | 自动启动目标定位 | autostart target lookup | 文件存在校验 | file existence validation | 依赖注入测试 | dependency-injected testing
 */
function resolveExePath(exePathOrRelative, baseDirs, deps = {}) {
  const fsMod = deps.fs || fs
  const pathMod = deps.path || path
  const raw = typeof exePathOrRelative === 'string' ? exePathOrRelative.trim() : ''
  if (!raw) return null

  if (isAbsolutePath(raw)) {
    return fsMod.existsSync(raw) ? raw : null
  }

  const bases = Array.isArray(baseDirs) ? baseDirs.filter(Boolean) : []
  for (const base of bases) {
    const full = pathMod.resolve(base, raw)
    if (fsMod.existsSync(full)) return full
  }
  return null
}

/**
 * - 函数: `spawnDetachedHidden`
 * - Function: `spawnDetachedHidden`
 * - 作用: 以隐藏窗口、分离子进程和忽略标准流的方式启动扫描引擎，使其在 Electron 主进程退出引用后仍可继续运行。
 * - Purpose: Launches the scanner engine as a hidden detached child process with ignored stdio so it can keep running after the Electron main process releases its reference.
 * - 调用方: `startIfNeeded` 在确认引擎未运行后调用本函数。
 * - Callers: `startIfNeeded` calls this helper after confirming the engine is not already running.
 * - 被调方: `child_process.spawn`、`child.unref`。
 * - Callees: `child_process.spawn` and `child.unref`.
 * - 变量说明: `exePath` 为目标可执行文件；`args` 为启动参数数组；`spawnOptions` 支持自定义环境变量；`deps.childProcess` 支持注入测试替身；`child` 为已创建的子进程对象。
 * - Variables: `exePath` is the target executable, `args` is the argument array, `spawnOptions` allows custom environment variables, `deps.childProcess` supports injected test doubles, and `child` is the spawned process object.
 * - 接入方式: 任何需要用同一“后台隐藏分离”策略启动引擎的逻辑都应复用本函数，不要在多个调用方重复拼 `spawn` 选项。
 * - Integration: Any engine-launch flow that needs the same detached hidden behavior should reuse this helper instead of rebuilding `spawn` options in multiple places.
 * - 错误处理: 本函数不吞掉 `spawn` 抛出的异常，让上层 `startIfNeeded` 明确区分 `spawn_failed` 场景。
 * - Error Handling: It does not swallow exceptions from `spawn`, allowing `startIfNeeded` to classify failures explicitly as `spawn_failed`.
 * - 关键词: 隐藏分离启动 | hidden detached launch | 子进程脱钩 | child process unref | 后台引擎拉起 | background engine start | spawn封装 | spawn wrapper | 环境变量透传 | environment passthrough
 */
function spawnDetachedHidden(exePath, args, spawnOptions = {}, deps = {}) {
  const cp = deps.childProcess || childProcess
  const opts = spawnOptions && typeof spawnOptions === 'object' ? spawnOptions : {}
  const child = cp.spawn(exePath, Array.isArray(args) ? args : [], {
    detached: true,
    windowsHide: true,
    stdio: 'ignore',
    env: opts.env || process.env
  })
  child.unref()
  return child
}

/**
 * - 函数: `resolveIpcOptions`
 * - Function: `resolveIpcOptions`
 * - 作用: 归一化扫描引擎 IPC 连接参数，统一处理环境变量覆盖、默认地址和超时配置，供健康检查与控制命令复用。
 * - Purpose: Normalizes scanner-engine IPC connection settings, handling environment overrides, default endpoint values, and timeout configuration for reuse by health checks and control commands.
 * - 调用方: `checkEngineHealth`、`startIfNeeded`、`postExitCommand`。
 * - Callers: `checkEngineHealth`, `startIfNeeded`, and `postExitCommand`.
 * - 被调方: 字符串 `trim`、`Number.isFinite`、`parseInt`。
 * - Callees: String `trim`, `Number.isFinite`, and `parseInt`.
 * - 变量说明: `options` 为自动启动配置对象；`ipc` 为其中的 IPC 子配置；`envHost`/`envPort` 为环境变量覆盖项；`host`、`port`、`connectTimeoutMs`、`timeoutMs` 为最终标准化结果。
 * - Variables: `options` is the autostart config object, `ipc` is its IPC subsection, `envHost` and `envPort` are environment overrides, and `host`, `port`, `connectTimeoutMs`, and `timeoutMs` are the normalized outputs.
 * - 接入方式: 所有与扫描引擎建立 IPC 连接的逻辑都应先走本函数，保证地址和超时约定一致。
 * - Integration: Any logic that connects to the scanner engine over IPC should pass through this helper first so endpoint and timeout conventions stay aligned.
 * - 错误处理: 非法端口和缺失配置会自动回退到 `127.0.0.1:8765` 及默认超时，而不是抛异常中断启动流程。
 * - Error Handling: Invalid ports and missing settings fall back automatically to `127.0.0.1:8765` and default timeouts instead of throwing and interrupting startup.
 * - 关键词: IPC参数归一化 | IPC option normalization | 环境变量覆盖 | environment override | 默认端口回退 | default port fallback | 健康检查配置 | health-check config | 控制通道设置 | control channel setup
 */
function resolveIpcOptions(options) {
  const ipc = options && options.ipc ? options.ipc : {}
  const envHost = process.env.SCANNER_SERVICE_IPC_HOST
  const envPort = process.env.SCANNER_SERVICE_IPC_PORT
  const host = (typeof (envHost || ipc.host) === 'string' && (envHost || ipc.host).trim()) ? (envHost || ipc.host).trim() : '127.0.0.1'
  const parsedPort = parseInt(envPort || ipc.port, 10)
  const port = Number.isFinite(parsedPort) && parsedPort > 0 && parsedPort < 65536 ? parsedPort : 8765
  const connectTimeoutMs = Number.isFinite(ipc.connectTimeoutMs) ? ipc.connectTimeoutMs : 300
  const timeoutMs = Number.isFinite(ipc.timeoutMs) ? ipc.timeoutMs : 800
  return { host, port, connectTimeoutMs, timeoutMs }
}

/**
 * - 函数: `ipcRoundTrip`
 * - Function: `ipcRoundTrip`
 * - 作用: 向本地扫描引擎发送一次带 4 字节长度前缀的 JSON IPC 请求，并等待完整响应，是健康检查、控制命令等主进程到引擎通信的底层传输封装。
 * - Purpose: Sends a length-prefixed JSON IPC request to the local scanner engine and waits for the full response, serving as the low-level transport wrapper for health checks, control commands, and similar main-process-to-engine communication.
 * - 调用方: `checkEngineHealth`、`postExitCommand` 等面向引擎控制面的上层函数会复用本函数。
 * - Callers: Reused by higher-level control-surface functions such as `checkEngineHealth` and `postExitCommand`.
 * - 被调方: `net.createConnection`、`socket.write/end/destroy`、`setTimeout`、`cleanup`、`finish`、`JSON.parse`、`Buffer.concat`。
 * - Callees: `net.createConnection`, `socket.write/end/destroy`, `setTimeout`, `cleanup`, `finish`, `JSON.parse`, and `Buffer.concat`.
 * - 变量说明: `host`/`port` 为目标引擎地址；`msg` 为待发送协议对象；`connectTimeoutMs` 与 `timeoutMs` 分别控制连接和总超时；`buf` 累积响应字节流；`expectedLen` 记录响应体长度；`done` 防止 Promise 重复收口。
 * - Variables: `host` and `port` point to the target engine, `msg` is the protocol payload, `connectTimeoutMs` and `timeoutMs` define connection and total deadlines, `buf` accumulates response bytes, `expectedLen` tracks the body length, and `done` prevents the Promise from being settled twice.
 * - 接入方式: 所有需要与扫描引擎做一次性请求/响应交互的函数都应通过本函数封装帧格式；如后续扩展新命令类型，优先复用这里而不是各自直接拼 socket 协议。
 * - Integration: Any function that performs one-shot request/response IPC with the scanner engine should route through this framing helper; if new command types are added later, reuse this function instead of manually assembling socket protocol logic elsewhere.
 * - 错误处理: 连接超时、总超时、连接关闭、协议长度非法、JSON 解析失败和 socket 错误都会通过 `reject` 抛给上层；资源释放由 `finish -> cleanup` 统一收口。
 * - Error Handling: Connection timeout, total timeout, premature close, invalid protocol length, JSON parse failures, and socket errors all reject the Promise to the caller; resource cleanup is centralized through `finish -> cleanup`.
 * - 关键词: 引擎IPC往返 | engine IPC round trip | 长度前缀协议 | length-prefixed protocol | socket请求响应 | socket request-response | 健康探测底座 | health-check transport | 本地控制通道 | local control channel
 */
function ipcRoundTrip(host, port, msg, connectTimeoutMs, timeoutMs, deps = {}) {
  const netMod = deps.net || net
  const json = Buffer.from(JSON.stringify(msg), 'utf-8')
  const frame = Buffer.allocUnsafe(4)
  frame.writeUInt32BE(json.length, 0)
  const out = Buffer.concat([frame, json])

  return new Promise((resolve, reject) => {
    let done = false
    let buf = Buffer.alloc(0)
    let expectedLen = null

    const socket = netMod.createConnection({ host, port })
    socket.setNoDelay(true)

    const connectTimer = setTimeout(() => {
      try { socket.destroy(new Error('CONNECT_TIMEOUT')) } catch {}
    }, Math.max(1, connectTimeoutMs))

    const timer = setTimeout(() => {
      try { socket.destroy(new Error('TIMEOUT')) } catch {}
    }, Math.max(1, timeoutMs + connectTimeoutMs))

    /**
     * - 函数: `cleanup`
     * - Function: `cleanup`
     * - 作用: 统一清理本次 IPC 往返使用的超时器和 socket 监听器，保证 `finish` 收口后不会再重复触发事件回调。
     * - Purpose: Clears the timers and socket listeners for the current IPC round trip so no later event callback can fire again after `finish` settles the request.
     * - 调用方: 仅由 `finish` 调用，属于 `ipcRoundTrip` 的内部资源释放步骤。
     * - Callers: Called only by `finish` as the internal resource-release step of `ipcRoundTrip`.
     * - 被调方: `clearTimeout`、`socket.removeAllListeners`、`socket.on`。
     * - Callees: `clearTimeout`, `socket.removeAllListeners`, and `socket.on`.
     * - 变量说明: 无显式入参；依赖外层闭包中的 `connectTimer`、`timer` 和 `socket`，分别表示连接超时器、总超时器与当前连接对象。
     * - Variables: There are no explicit parameters; it closes over `connectTimer`, `timer`, and `socket`, which represent the connect timeout, total timeout, and current socket object.
     * - 接入方式: 仅供 `ipcRoundTrip` 内部使用；若后续扩展更多事件处理，也应继续由本函数统一摘除监听器。
     * - Integration: This helper is internal to `ipcRoundTrip`; if more socket events are added later, they should still be detached here.
     * - 错误处理: 清理动作全部包在 `try` 中静默执行，确保即使 socket 已销毁或监听器状态异常，也不影响 Promise 最终收口。
     * - Error Handling: Cleanup steps run inside silent `try` blocks so even a destroyed socket or inconsistent listener state cannot interfere with final Promise settlement.
     * - 关键词: IPC清理 | IPC cleanup | 监听器摘除 | listener teardown | 超时器回收 | timer cleanup | 资源收口 | resource finalization | socket善后 | socket teardown
     */
    function cleanup() {
      clearTimeout(connectTimer)
      clearTimeout(timer)
      try { socket.removeAllListeners() } catch {}
      try { socket.on('error', () => {}) } catch {}
    }

    /**
     * - 函数: `finish`
     * - Function: `finish`
     * - 作用: 为本次 IPC Promise 提供单次收口点，负责防重、调用清理逻辑，并把结果统一路由到 `resolve` 或 `reject`。
     * - Purpose: Acts as the one-time completion gate for the IPC Promise, preventing duplicate settlement, invoking cleanup, and routing the outcome to either `resolve` or `reject`.
     * - 调用方: `socket.once('connect')`、`socket.on('data')`、`socket.once('error')`、`socket.once('close')` 等事件处理分支都会调用。
     * - Callers: Invoked by event branches such as `socket.once('connect')`, `socket.on('data')`, `socket.once('error')`, and `socket.once('close')`.
     * - 被调方: `cleanup`、Promise 的 `resolve`、`reject`。
     * - Callees: `cleanup`, and the Promise `resolve` and `reject` callbacks.
     * - 变量说明: `err` 表示失败原因；`res` 为解析后的成功响应；`done` 是闭包中的幂等开关，防止重复完成。
     * - Variables: `err` holds the failure reason, `res` is the parsed success response, and `done` is the idempotency flag in the outer closure.
     * - 接入方式: 仅限 `ipcRoundTrip` 内部事件处理分支调用；新增事件源时若会结束本次请求，也应统一调用本函数而不是直接 `resolve/reject`。
     * - Integration: It should only be called by `ipcRoundTrip` event handlers; any newly added terminal event should also settle through this helper instead of calling `resolve` or `reject` directly.
     * - 错误处理: 如果已完成则直接忽略后续调用；否则先清理资源，再根据 `err` 是否存在决定拒绝还是成功返回。
     * - Error Handling: Subsequent calls are ignored once the request is settled; otherwise resources are cleaned first, and the function rejects or resolves based on whether `err` is present.
     * - 关键词: Promise收口 | Promise settlement | 幂等完成 | idempotent finish | 事件终态汇总 | terminal event funnel | 统一reject resolve | unified resolve reject | IPC完成门闩 | IPC completion gate
     */
    function finish(err, res) {
      if (done) return
      done = true
      cleanup()
      if (err) return reject(err)
      resolve(res)
    }

    socket.once('connect', () => {
      clearTimeout(connectTimer)
      try {
        socket.write(out)
      } catch (e) {
        finish(e)
      }
    })

    socket.on('data', (chunk) => {
      try {
        const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
        buf = buf.length ? Buffer.concat([buf, b]) : b
        if (expectedLen == null) {
          if (buf.length < 4) return
          expectedLen = buf.readUInt32BE(0)
          if (!Number.isFinite(expectedLen) || expectedLen < 0 || expectedLen > 64 * 1024 * 1024) return finish(new Error('IPC_PROTOCOL'))
        }
        if (buf.length < 4 + expectedLen) return
        const body = buf.subarray(4, 4 + expectedLen)
        const parsed = JSON.parse(body.toString('utf-8'))
        try { socket.end() } catch {}
        finish(null, parsed)
      } catch (e) {
        finish(e)
      }
    })

    socket.once('error', (err) => finish(err))
    socket.once('close', () => {
      if (done) return
      finish(new Error('IPC_CLOSED'))
    })
  })
}

/**
 * - 函数: `checkEngineHealth`
 * - Function: `checkEngineHealth`
 * - 作用: 通过 IPC 向扫描引擎发送 `health` 请求，并把响应规整成布尔值，用于启动前探活、启动后轮询和异常退出时的状态确认。
 * - Purpose: Sends a `health` IPC request to the scanner engine and normalizes the response to a boolean, so callers can use it for pre-start probing, post-start polling, and state checks around shutdown.
 * - 调用方: `startIfNeeded` 会在拉起引擎前先探测是否已运行；`main.js` 的启动序列也会在后续等待阶段反复调用本函数确认引擎是否真正健康。
 * - Callers: `startIfNeeded` probes the engine first to avoid duplicate launches, and the startup sequence in `main.js` repeatedly calls this function afterward to confirm the engine is actually healthy.
 * - 被调方: `resolveIpcOptions`、`ipcRoundTrip`、字符串 `trim`、`Number.isFinite`。
 * - Callees: `resolveIpcOptions`, `ipcRoundTrip`, string `trim`, and `Number.isFinite`.
 * - 变量说明: `hostOrOptions` 支持对象模式和旧式 host 字符串模式；`portOrDeps` 在对象模式下表示依赖注入，在旧式模式下表示端口；`maybeDeps` 为旧式签名的依赖注入；`msg` 为健康检查报文。
 * - Variables: `hostOrOptions` supports both object-based options and the legacy host-string signature, `portOrDeps` represents injected dependencies in object mode or the port in legacy mode, `maybeDeps` carries dependencies for the legacy signature, and `msg` is the health-check payload.
 * - 接入方式: 推荐使用对象签名 `checkEngineHealth({ ipc: ... }, deps)`，这样可与自动启动配置保持一致；旧式 `(host, port, deps)` 形式仅作为兼容保留。
 * - Integration: Prefer the object signature `checkEngineHealth({ ipc: ... }, deps)` so it aligns with the auto-start configuration flow; the legacy `(host, port, deps)` form is kept only for compatibility.
 * - 错误处理: 网络错误、协议错误或引擎返回异常都会在内部被折叠为 `false`，确保上层只按“健康/不健康”两态决策，无需处理底层 socket 细节。
 * - Error Handling: Network failures, protocol problems, or abnormal engine responses are all collapsed to `false`, allowing callers to reason only in terms of healthy versus unhealthy without dealing with socket-level details.
 * - 关键词: 引擎健康探测 | engine health probe | 启动前探活 | pre-start liveness check | 布尔健康结果 | boolean health result | IPC探针 | IPC probe | 自动启动依赖 | autostart dependency
 */
function checkEngineHealth(hostOrOptions, portOrDeps, maybeDeps) {
  let host = '127.0.0.1'
  let port = 8765
  let deps = {}

  if (hostOrOptions && typeof hostOrOptions === 'object') {
    const opt = resolveIpcOptions(hostOrOptions)
    host = opt.host
    port = opt.port
    deps = portOrDeps || {}
    const msg = { version: 1, type: 'health', payload: {}, timeout_ms: opt.timeoutMs }
    return ipcRoundTrip(host, port, msg, opt.connectTimeoutMs, opt.timeoutMs, deps)
      .then((res) => !!(res && res.ok))
      .catch(() => false)
  }

  host = typeof hostOrOptions === 'string' && hostOrOptions.trim() ? hostOrOptions.trim() : '127.0.0.1'
  const p = parseInt(portOrDeps, 10)
  port = Number.isFinite(p) && p > 0 && p < 65536 ? p : 8765
  deps = maybeDeps || {}
  const msg = { version: 1, type: 'health', payload: {}, timeout_ms: 800 }
  return ipcRoundTrip(host, port, msg, 300, 800, deps)
    .then((res) => !!(res && res.ok))
    .catch(() => false)
}

/**
 * - 函数: `startIfNeeded`
 * - Function: `startIfNeeded`
 * - 作用: 在 Windows 平台按配置解析扫描引擎可执行文件，先做健康探测，再决定是否以隐藏分离进程方式拉起引擎，是应用启动阶段的自动拉起入口。
 * - Purpose: Resolves the scanner-engine executable on Windows, probes current health first, and only then decides whether to launch the engine as a hidden detached process, making it the auto-start entry during app bootstrap.
 * - 调用方: `main.js` 的启动流程会在安全组件初始化前调用本函数，避免重复启动或找不到引擎时阻塞后续链路。
 * - Callers: Called by the startup flow in `main.js` before the rest of the security components initialize so repeated launches and missing-engine cases do not block later bootstrap stages.
 * - 被调方: `resolveIpcOptions`、`resolveExePath`、`checkEngineHealth`、`spawnDetachedHidden`。
 * - Callees: `resolveIpcOptions`, `resolveExePath`, `checkEngineHealth`, and `spawnDetachedHidden`.
 * - 变量说明: `options` 提供平台、引擎路径、参数和 IPC 配置；`deps` 支持注入测试替身；`baseDirs` 为相对路径解析根目录；`exePath` 为最终可执行文件路径；`running` 表示探活结果。
 * - Variables: `options` carries platform, engine path, args, and IPC configuration, `deps` allows test doubles, `baseDirs` are the roots for relative-path resolution, `exePath` is the resolved executable path, and `running` is the liveness probe result.
 * - 接入方式: 推荐仅由启动编排层调用；若后续新增“手动重启引擎”入口，也应复用本函数的路径解析和探活逻辑，而不是重新实现一套启动判断。
 * - Integration: It is best invoked only by bootstrap orchestration code; if a future "manual engine restart" entry is added, it should reuse this function's path resolution and liveness checks instead of reimplementing start conditions elsewhere.
 * - 错误处理: 非 Windows、找不到可执行文件、引擎已在运行或启动异常都会返回结构化 `{ started, reason, path }` 结果，不抛出异常，让上层按原因决定日志、重试或降级策略。
 * - Error Handling: Unsupported platform, missing executable, an already running engine, or spawn failures all return a structured `{ started, reason, path }` result instead of throwing, letting upper layers decide whether to log, retry, or degrade gracefully.
 * - 关键词: 引擎自动启动 | engine autostart | 可执行路径解析 | executable path resolution | 启动前探活 | pre-launch probe | 分离隐藏进程 | detached hidden process | 启动结果枚举 | startup result enum
 */
async function startIfNeeded(options, deps = {}) {
  const platform = (options && options.platform) || process.platform
  if (platform !== 'win32') return { started: false, reason: 'unsupported_platform' }

  const engine = options && options.engine ? options.engine : {}
  const baseDirs = options && options.baseDirs ? options.baseDirs : []
  const exeCandidate = engine.exePath || engine.exeRelativePath || ''
  const ipcOpt = resolveIpcOptions(options || {})

  const exePath = resolveExePath(exeCandidate, baseDirs, deps)
  if (!exePath) return { started: false, reason: 'exe_not_found' }

  const running = await checkEngineHealth({ ipc: { host: ipcOpt.host, port: ipcOpt.port, connectTimeoutMs: ipcOpt.connectTimeoutMs, timeoutMs: ipcOpt.timeoutMs } }, deps)
  if (running) return { started: false, reason: 'already_running', path: exePath }

  try {
    const mergedEnv = { ...process.env, SCANNER_SERVICE_IPC_HOST: ipcOpt.host, SCANNER_SERVICE_IPC_PORT: String(ipcOpt.port) }
    spawnDetachedHidden(exePath, engine.args || [], { env: mergedEnv }, deps)
    return { started: true, reason: 'started', path: exePath }
  } catch {
    return { started: false, reason: 'spawn_failed', path: exePath }
  }
}

/**
 * - 函数: `postExitCommand`
 * - Function: `postExitCommand`
 * - 作用: 通过 IPC 向扫描引擎发送退出控制命令，并把响应规整成 `{ ok, status }`，供主进程在应用退出或重启前尝试温和关闭引擎。
 * - Purpose: Sends an exit control command to the scanner engine over IPC and normalizes the reply into `{ ok, status }`, allowing the main process to attempt a graceful engine shutdown before app exit or restart.
 * - 调用方: `main.js` 的退出收尾流程会优先调用本函数，失败后再考虑使用 `killProcessWin32` 做更强制的清理。
 * - Callers: The shutdown-finalization flow in `main.js` calls this function first and only considers `killProcessWin32` if graceful shutdown fails.
 * - 被调方: `resolveIpcOptions`、`ipcRoundTrip`、`Number.isFinite`。
 * - Callees: `resolveIpcOptions`, `ipcRoundTrip`, and `Number.isFinite`.
 * - 变量说明: `options` 提供目标 IPC 地址；`timeoutMs` 为本次退出命令等待时间；`token` 为可选控制令牌；`msg` 为发往引擎的 `control/exit` 报文；`status` 为引擎返回的业务状态。
 * - Variables: `options` provides the target IPC endpoint, `timeoutMs` defines how long to wait, `token` is an optional control token, `msg` is the outgoing `control/exit` payload, and `status` is the business-level status returned by the engine.
 * - 接入方式: 适合在所有“先温和退出再考虑强杀”的引擎关闭链路中复用；新增控制命令时也可参照本函数构造统一的 `control` 消息格式。
 * - Integration: Reuse it in any engine-shutdown flow that prefers graceful termination before force killing; future control commands can follow this function's `control` message pattern as well.
 * - 错误处理: IPC 失败、响应缺失或 `ok !== true` 时统一返回 `{ ok: false, status: null }`，避免上层因控制通道异常抛错而跳过后续兜底清理。
 * - Error Handling: IPC failures, missing responses, or replies where `ok !== true` are all normalized to `{ ok: false, status: null }`, preventing control-channel errors from skipping later fallback cleanup steps.
 * - 关键词: 引擎退出命令 | engine exit command | 温和关闭 | graceful shutdown | 控制报文 | control payload | 退出状态归一化 | exit status normalization | 关闭前清理 | pre-shutdown cleanup
 */
function postExitCommand(options, timeoutMs, token, deps = {}) {
  const opt = resolveIpcOptions(options || {})
  const to = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : opt.timeoutMs
  const msg = { version: 1, type: 'control', payload: token ? { command: 'exit', token } : { command: 'exit' }, timeout_ms: to }

  return ipcRoundTrip(opt.host, opt.port, msg, opt.connectTimeoutMs, to, deps)
    .then((res) => {
      if (!res || res.ok !== true) return { ok: false, status: null }
      const status = res && res.payload && res.payload.status ? res.payload.status : null
      return { ok: true, status }
    })
    .catch(() => ({ ok: false, status: null }))
}

/**
 * - 函数: `killProcessWin32`
 * - Function: `killProcessWin32`
 * - 作用: 使用 `taskkill /F /IM /T` 强制终止指定 Windows 进程树，是温和退出失败后的最后兜底清理手段。
 * - Purpose: Force-kills the target Windows process tree with `taskkill /F /IM /T`, serving as the final fallback cleanup path when graceful shutdown fails.
 * - 调用方: `main.js` 在 `postExitCommand` 关闭引擎失败后会调用本函数强制结束扫描引擎进程。
 * - Callers: `main.js` calls this helper to force-stop the scanner engine when `postExitCommand` cannot shut it down gracefully.
 * - 被调方: `normalizeProcessName`、`child_process.exec`。
 * - Callees: `normalizeProcessName` and `child_process.exec`.
 * - 变量说明: `processName` 为待结束的进程名；`deps.childProcess` 支持测试注入；`cp` 为最终使用的子进程模块；`pn` 为规范化后的进程名；`cmd` 为生成的 `taskkill` 命令。
 * - Variables: `processName` is the process name to terminate, `deps.childProcess` supports test injection, `cp` is the child-process module in use, `pn` is the normalized process name, and `cmd` is the generated `taskkill` command.
 * - 接入方式: 仅建议用于 Windows 平台且温和退出失败后的兜底链路；其他调用方若需要强杀进程，也应复用本函数而不是自行拼命令。
 * - Integration: Use it only as a Windows fallback after graceful shutdown fails; any other force-kill flow should reuse this helper instead of composing shell commands manually.
 * - 错误处理: 进程名无效时直接返回 `Promise.resolve(false)`；`taskkill` 执行失败也解析为 `false`，由上层决定是否继续退出应用。
 * - Error Handling: Invalid process names return `Promise.resolve(false)`, and `taskkill` execution failures are also normalized to `false`, leaving the caller to decide whether app shutdown should continue.
 * - 关键词: Windows强杀进程 | Windows force kill | taskkill兜底 | taskkill fallback | 引擎退出清理 | engine shutdown cleanup | 进程树终止 | process-tree termination | 命令执行回退 | command-exec fallback
 */
function killProcessWin32(processName, deps = {}) {
  const cp = deps.childProcess || childProcess
  const pn = normalizeProcessName(processName)
  if (!pn) return Promise.resolve(false)
  return new Promise((resolve) => {
    const cmd = `taskkill /F /IM ${pn} /T`
    cp.exec(cmd, { windowsHide: true }, (err) => {
      if (err) return resolve(false)
      resolve(true)
    })
  })
}

module.exports = {
  normalizeProcessName,
  resolveExePath,
  spawnDetachedHidden,
  startIfNeeded,
  postExitCommand,
  killProcessWin32,
  checkEngineHealth
}
