function asPid(v) {
  const n = typeof v === 'number' ? v : parseInt(String(v), 10)
  if (!Number.isFinite(n) || n < 0) return null
  return n
}

/**
 * - 函数: `createInterceptionQueue`
 * - Function: `createInterceptionQueue`
 * - 作用: 创建一份可维护暂停进程、待展示队列和当前活动弹窗状态的拦截管理器，是主进程接收拦截事件后的统一状态容器。
 * - Purpose: Creates an interception manager that tracks paused processes, pending dialog items, and the currently active task, serving as the shared state container after the main process receives interception events.
 * - 调用方: `main.js` 会在启动阶段创建单例 `interceptionQueue`，随后通过其公开方法管理拦截弹窗、恢复和终止动作。
 * - Callers: `main.js` creates a singleton `interceptionQueue` during startup and then drives interception dialogs, resume actions, and terminate actions through its public methods.
 * - 被调方: `configure`、`enqueuePausedProcess`、`markActionResult`、`clearPid`、`clearAll`、`getPausedPids`、`isIdle`、`tryShowNext` 等内部方法构成返回对象。
 * - Callees: The returned object is composed around internal methods such as `configure`, `enqueuePausedProcess`, `markActionResult`, `clearPid`, `clearAll`, `getPausedPids`, `isIdle`, and `tryShowNext`.
 * - 变量说明: `deps.showFn` 为弹窗展示回调；`deps.nowFn` 为时间注入点；`pending` 保存待处理任务；`queuedPids` 与 `pausedPids` 分别负责去重和暂停态集合；`activePid`/`activeItem` 表示当前展示项。
 * - Variables: `deps.showFn` is the dialog-display callback, `deps.nowFn` is the injected clock, `pending` stores queued tasks, `queuedPids` and `pausedPids` handle deduplication and paused-state tracking, and `activePid` plus `activeItem` represent the current dialog item.
 * - 接入方式: 主进程应只通过返回对象公开的方法交互，不要在外部直接共享或篡改内部集合；若未来加入新队列策略，优先继续在本工厂函数内部扩展。
 * - Integration: The main process should interact only through the returned public methods and must not mutate internal sets directly; if new queue policies are added later, extend them inside this factory.
 * - 错误处理: 本工厂函数自身不抛业务异常，核心容错由返回对象各方法内部完成；当依赖缺失时会退化为不可展示但仍可维护状态的管理器。
 * - Error Handling: The factory itself does not throw business-level errors; fault tolerance is handled inside the returned methods, and missing dependencies degrade into a manager that can still keep state even if dialogs cannot be shown.
 * - 关键词: 拦截队列工厂 | interception queue factory | 暂停进程管理 | paused process management | 弹窗状态容器 | dialog state container | 主进程拦截单例 | main-process interception singleton | 队列调度入口 | queue scheduling entry
 */
function createInterceptionQueue(deps = {}) {
  const showFn = typeof deps.showFn === 'function' ? deps.showFn : null
  const nowFn = typeof deps.nowFn === 'function' ? deps.nowFn : () => Date.now()

  let enabled = false
  const pending = []
  const queuedPids = new Set()
  const pausedPids = new Set()
  let activePid = null
  let activeItem = null
  let showRetryTimer = null

  /**
   * - 函数: `configure`
   * - Function: `configure`
   * - 作用: 根据外部拦截配置切换队列管理器是否启用，是主进程把配置文件里的拦截开关同步到运行态的入口。
   * - Purpose: Toggles whether the queue manager is enabled based on external interception config, acting as the bridge from persisted configuration into runtime interception behavior.
   * - 调用方: `main.js` 在创建 `interceptionQueue` 后会调用 `configure(icfg)` 同步 ETW 拦截配置。
   * - Callers: `main.js` calls `configure(icfg)` after creating `interceptionQueue` to sync ETW interception settings.
   * - 被调方: 无额外命名函数，主要依赖对象守卫与布尔赋值。
 * - Callees: It uses only object guards and boolean assignment without additional named helpers.
   * - 变量说明: `cfg` 为拦截配置对象；`c` 为安全归一化后的配置引用；`enabled` 表示当前队列是否允许接收并展示拦截任务。
   * - Variables: `cfg` is the interception config object, `c` is the normalized safe reference, and `enabled` indicates whether the queue may currently accept and display interception tasks.
   * - 接入方式: 所有配置变更都应通过本函数更新开关，避免外部直接改写闭包内的 `enabled` 状态。
   * - Integration: Route all enable/disable config changes through this helper instead of mutating the closure-level `enabled` flag from outside.
   * - 错误处理: 非对象配置会回退为空对象，并把队列判定为未启用，不会抛异常打断主进程启动。
   * - Error Handling: Non-object input falls back to an empty config and leaves the queue disabled, preventing malformed config from interrupting bootstrap.
   * - 关键词: 拦截配置同步 | interception config sync | 启用开关 | enable switch | 运行态配置 | runtime configuration | 队列门控 | queue gating | 主进程初始化 | main-process initialization
   */
  function configure(cfg) {
    const c = cfg && typeof cfg === 'object' ? cfg : {}
    enabled = c.enabled === true
  }

  /**
   * - 函数: `getPausedPids`
   * - Function: `getPausedPids`
   * - 作用: 返回当前仍被认为处于暂停态的 PID 列表，供批量恢复、窗口收尾和状态检查逻辑读取快照。
   * - Purpose: Returns the list of PIDs still considered paused so batch resume, dialog cleanup, and state-inspection flows can read a snapshot.
   * - 调用方: `main.js` 会在批量恢复、单个恢复前校验和其他状态收尾逻辑中调用本函数。
   * - Callers: `main.js` uses this helper during batch resume, pre-resume validation, and other cleanup/state-check flows.
   * - 被调方: `Array.from`。
   * - Callees: `Array.from`.
   * - 变量说明: 无显式入参；`pausedPids` 为闭包内暂停态 PID 集合；返回值是新的数组快照，避免外部直接持有内部集合引用。
   * - Variables: There are no explicit parameters; `pausedPids` is the closure-level paused PID set, and the return value is a fresh array snapshot so callers do not hold the internal set by reference.
   * - 接入方式: 需要读取暂停态集合时应调用本函数，不要直接暴露 `pausedPids` 本身。
   * - Integration: Use this helper whenever paused-state inspection is needed instead of exposing `pausedPids` directly.
   * - 错误处理: 本函数没有显式异常分支，始终返回数组；即使集合为空，也稳定返回空数组。
   * - Error Handling: There is no explicit exception path; the function always returns an array and yields an empty array when no PID is paused.
   * - 关键词: 暂停PID快照 | paused PID snapshot | 批量恢复前检查 | pre-resume inspection | 集合只读导出 | read-only set export | 队列状态查询 | queue state query | 拦截暂停态 | interception paused state
   */
  function getPausedPids() {
    return Array.from(pausedPids)
  }

  /**
   * - 函数: `isIdle`
   * - Function: `isIdle`
   * - 作用: 判断当前是否没有活动中的拦截弹窗任务，供主进程决定是否隐藏拦截窗口或继续推进后续 UI 流程。
   * - Purpose: Checks whether there is no interception task currently occupying the active dialog slot so the main process can decide whether to hide the interception window or continue other UI flows.
   * - 调用方: `main.js` 在恢复、阻止等动作完成后会调用本函数判断是否需要隐藏拦截窗口。
   * - Callers: `main.js` calls this helper after resume/block actions to decide whether the interception window should be hidden.
   * - 被调方: 无额外命名函数，直接读取 `activePid` 状态。
 * - Callees: It does not call additional named helpers and reads `activePid` directly.
   * - 变量说明: 无显式入参；`activePid` 为当前占用弹窗的进程 ID，`null` 代表队列空闲。
   * - Variables: There are no explicit parameters; `activePid` is the PID currently occupying the dialog, and `null` means the queue is idle.
   * - 接入方式: 任何基于“当前是否还有活动项”做 UI 收尾判断的逻辑都应复用本函数，而不是外部推断队列状态。
   * - Integration: Any UI-cleanup logic that depends on whether an active item still exists should reuse this helper instead of inferring queue state externally.
   * - 错误处理: 本函数只返回布尔值，不抛异常；状态为空时稳定返回 `true`。
   * - Error Handling: The function only returns a boolean and does not throw; it deterministically returns `true` when no active task exists.
   * - 关键词: 队列空闲判断 | queue idle check | 活动弹窗状态 | active dialog state | 窗口隐藏条件 | window hide condition | 主进程UI收尾 | main-process UI cleanup | 当前任务占位 | active task occupancy
   */
  function isIdle() {
    return activePid == null
  }

  /**
   * - 函数: `logQueueStatus`
   * - Function: `logQueueStatus`
   * - 作用: 把当前拦截队列的活动项和待处理项打印到控制台，便于排查展示卡住、重复入队或状态不同步问题。
   * - Purpose: Prints the active interception item and pending queue contents to the console so stalled dialogs, duplicate enqueues, or state-sync issues can be diagnosed.
   * - 调用方: `tryShowNext`、`enqueuePausedProcess`、`markActionResult`、`clearPid`。
   * - Callers: `tryShowNext`, `enqueuePausedProcess`, `markActionResult`, and `clearPid`.
   * - 被调方: `console.log`、`pending.forEach`、`Date`、`toLocaleTimeString`。
   * - Callees: `console.log`, `pending.forEach`, `Date`, and `toLocaleTimeString`.
   * - 变量说明: 无显式入参；`pending` 保存待展示项；`activePid` 为当前活动 PID；`item.enqueuedAt` 用于格式化入队时间。
   * - Variables: There are no explicit parameters; `pending` stores queued items, `activePid` is the current active PID, and `item.enqueuedAt` is formatted as the enqueue timestamp.
   * - 接入方式: 仅供队列内部状态变更点调用；若以后要改为结构化日志，也应从本函数统一切换。
   * - Integration: This helper should remain internal to queue state-transition points; if logging moves to a structured format later, switch it here centrally.
   * - 错误处理: 当队列和活动项都为空时直接静默返回，避免产生无意义日志噪音。
   * - Error Handling: It silently returns when both the queue and active slot are empty, avoiding meaningless log noise.
   * - 关键词: 队列状态日志 | queue status log | 控制台诊断 | console diagnostics | 入队时间打印 | enqueue timestamp display | 活动项观测 | active item visibility | 状态排障 | state troubleshooting
   */
  function logQueueStatus() {
    if (pending.length === 0 && activePid == null) return
    console.log(`\n[Interception Queue Status] Total: ${pending.length + (activePid ? 1 : 0)}`)
    if (activePid) {
      console.log(` - ACTIVE: PID ${activePid}`)
    }
    pending.forEach((item, index) => {
      console.log(` - PENDING[${index}]: PID ${item.pid} (Enqueued: ${new Date(item.enqueuedAt).toLocaleTimeString()})`)
    })
    console.log('')
  }

  /**
   * - 函数: `tryShowNext`
   * - Function: `tryShowNext`
   * - 作用: 从待处理拦截队列中取出下一个暂停进程并调用展示回调，是“入队 -> 弹窗确认 -> 结果回写”这条链路的核心调度点。
   * - Purpose: Pulls the next paused-process item from the pending interception queue and invokes the display callback, making it the core scheduler for the "enqueue -> dialog confirmation -> result write-back" flow.
   * - 调用方: `enqueuePausedProcess` 在新事件入队时触发，`markActionResult` 在当前任务处理完成后续播，`clearPid` 在清理旧 PID 后补位；主进程也会通过导出 API 间接触发。
   * - Callers: Triggered by `enqueuePausedProcess` when new events arrive, by `markActionResult` after the current item finishes, and by `clearPid` after stale PIDs are removed; the main process can also invoke it indirectly through the exported API.
   * - 被调方: `showFn`、`logQueueStatus`、队列 `shift/push/unshift`、`setTimeout`、`unref`。
   * - Callees: `showFn`, `logQueueStatus`, queue `shift/push/unshift`, `setTimeout`, and `unref`.
   * - 变量说明: 无显式入参；`pending` 保存待展示项；`activePid`/`activeItem` 表示当前占用弹窗的任务；`showRetryTimer` 控制展示失败后的补播；`next` 为本次尝试出队的对象。
   * - Variables: There are no explicit parameters; `pending` stores queued items waiting to be shown, `activePid` and `activeItem` describe the task currently occupying the dialog, `showRetryTimer` controls delayed retries after display failures, and `next` is the item dequeued for this attempt.
   * - 接入方式: 应只由队列管理函数或导出 API 调用；若未来新增展示条件或节流策略，继续集中在本函数处理，不要让多个调用点各自维护重试计时器。
   * - Integration: It should only be driven by queue-management helpers or the exported API; if future display constraints or throttling rules are added, keep them centralized here rather than letting multiple callers maintain their own retry timers.
   * - 错误处理: 未启用、缺少展示函数、已有活动项或队列为空时直接返回 `false`；展示回调返回假值时把任务移回队尾并延迟重试；抛异常时把任务放回队首，避免任务丢失。
   * - Error Handling: Returns `false` immediately when disabled, when no display callback exists, when another item is already active, or when the queue is empty; a falsey callback result moves the item back to the tail and schedules a retry, while thrown errors put the item back at the front so it is not lost.
   * - 关键词: 拦截调度 | interception scheduling | 队列续播 | queue replay | 暂停进程弹窗 | paused process dialog | 重试计时器 | retry timer | 活动项切换 | active item switch
   */
  function tryShowNext() {
    if (!enabled) return false
    if (!showFn) return false
    if (activePid != null) return false
    const next = pending.shift()
    if (!next) return false
    const pid = next.pid
    try {
      const ok = showFn(next.payload) === true
      if (!ok) {
        pending.push(next)
        if (!showRetryTimer) {
          showRetryTimer = setTimeout(() => {
            showRetryTimer = null
            try { tryShowNext() } catch {}
          }, 200)
          try { if (showRetryTimer.unref) showRetryTimer.unref() } catch {}
        }
        return false
      }
      activePid = pid
      activeItem = next
      logQueueStatus()
      return true
    } catch {
      pending.unshift(next)
      return false
    }
  }

  /**
   * - 函数: `enqueuePausedProcess`
   * - Function: `enqueuePausedProcess`
   * - 作用: 接收新的暂停进程载荷，完成 PID 归一化、重复任务合并和首次入队，然后尝试立刻拉起展示流程，是 worker/主进程告警进入拦截队列的入口。
   * - Purpose: Accepts a new paused-process payload, normalizes the PID, merges duplicate tasks, enqueues first-time items, and then tries to start the display flow immediately, serving as the entry point from worker or main-process alerts into the interception queue.
   * - 调用方: `main.js` 中 worker 消息分发、行为告警处理和调试补发路径会调用导出的 `interceptionQueue.enqueuePausedProcess(...)`。
   * - Callers: Called by worker-message dispatch, behavior-alert handling, and replay/debug paths in `main.js` through the exported `interceptionQueue.enqueuePausedProcess(...)` API.
   * - 被调方: `logQueueStatus`、`tryShowNext`、`Number.isFinite`、`asPid`、`queuedPids.has/add`、`pausedPids.add`、`pending.push`。
   * - Callees: `logQueueStatus`, `tryShowNext`, `Number.isFinite`, `asPid`, `queuedPids.has/add`, `pausedPids.add`, and `pending.push`.
   * - 变量说明: `payload` 为上游传入的进程告警对象；`p` 是校验后的对象引用；`pid` 为归一化后的进程 ID；`queuedPids` 负责去重；`pausedPids` 标记当前仍处于暂停态的 PID。
   * - Variables: `payload` is the upstream process-alert object, `p` is the validated object reference, `pid` is the normalized process ID, `queuedPids` handles deduplication, and `pausedPids` marks PIDs still considered paused.
   * - 接入方式: 所有新的拦截任务都应从本函数进入，确保重复 PID 更新时只刷新已有队列项；不要在外部直接写 `pending`、`queuedPids` 或 `pausedPids`。
   * - Integration: All new interception tasks should enter here so duplicate PID updates refresh existing queue items instead of creating inconsistent state; callers should not mutate `pending`, `queuedPids`, or `pausedPids` directly.
   * - 错误处理: 管理器未启用、载荷为空或 PID 无法解析时返回 `false`；重复 PID 若能定位到活动项或待处理项则只更新数据，不重复排队；真正入队后即使展示失败，任务仍保留给后续重试。
   * - Error Handling: Returns `false` when the manager is disabled, the payload is invalid, or the PID cannot be resolved; duplicate PIDs refresh the active or pending item in place instead of requeueing, and once an item is truly queued it remains available for later retries even if display fails.
   * - 关键词: 暂停进程入队 | paused process enqueue | PID归一化 | PID normalization | 重复任务合并 | duplicate task merge | worker告警接入 | worker alert intake | 拦截队列入口 | interception queue entry
   */
  function enqueuePausedProcess(payload) {
    if (!enabled) return false
    const p = payload && typeof payload === 'object' ? payload : null
    const pid = p && Number.isFinite(p.pid) ? p.pid : asPid(p && p.pid)
    if (pid == null) return false
    if (queuedPids.has(pid)) {
      if (activePid === pid && activeItem) {
        activeItem.payload = p
        activeItem.enqueuedAt = nowFn()
        logQueueStatus()
        return true
      }
      for (let i = pending.length - 1; i >= 0; i--) {
        if (pending[i] && pending[i].pid === pid) {
          pending[i].payload = p
          pending[i].enqueuedAt = nowFn()
          logQueueStatus()
          return true
        }
      }
      return false
    }
    queuedPids.add(pid)
    if (p && p.paused === true) pausedPids.add(pid)
    pending.push({ pid, payload: p, enqueuedAt: nowFn() })
    logQueueStatus()
    tryShowNext()
    return true
  }

  /**
   * - 函数: `markActionResult`
   * - Function: `markActionResult`
   * - 作用: 在用户或上游逻辑完成拦截决策后，回收当前活动项的 PID 占位并返回原始载荷，供主进程继续执行后续放行、阻止或记录操作。
   * - Purpose: Releases the active PID slot after a user or upstream flow finishes an interception decision and returns the original payload so the main process can continue allow, block, or audit actions.
   * - 调用方: `main.js` 中拦截结果 IPC、流程回调和清理逻辑会调用导出的 `markActionResult(...)`。
   * - Callers: Called by interception-result IPC handlers, follow-up flow callbacks, and cleanup logic in `main.js` through the exported `markActionResult(...)` API.
   * - 被调方: `asPid`、`pausedPids.delete`、`queuedPids.delete`、`logQueueStatus`、`tryShowNext`、`setTimeout`。
   * - Callees: `asPid`, `pausedPids.delete`, `queuedPids.delete`, `logQueueStatus`, `tryShowNext`, and `setTimeout`.
   * - 变量说明: `pid` 为待结算进程 ID；`ok` 表示本次拦截动作是否已成功落地；`item` 保存当前活动项；返回值为原始 `payload`，便于调用方继续上报或落盘。
   * - Variables: `pid` is the process ID being settled, `ok` indicates whether the interception action finished successfully, `item` stores the active queue entry, and the return value is the original `payload` for follow-up reporting or persistence.
   * - 接入方式: 所有“用户已处理当前弹窗”的收口逻辑都应走本函数，保证 `activePid`、`queuedPids`、`pausedPids` 三套状态同步释放。
   * - Integration: Any "the current dialog has been handled" flow should converge through this function so `activePid`, `queuedPids`, and `pausedPids` are released in sync.
   * - 错误处理: PID 非法或不是当前活动项时返回 `null`；仅在 `ok === true` 时真正出队并延迟续播下一项，避免失败状态误清空当前上下文。
   * - Error Handling: Returns `null` when the PID is invalid or is not the current active item; it only truly dequeues and resumes playback when `ok === true`, preventing failed flows from clearing active context incorrectly.
   * - 关键词: 拦截结果回收 | interception result release | 活动PID释放 | active PID release | 结果载荷回传 | payload handoff | 队列续播延迟 | delayed queue resume | 状态收口 | state finalization
   */
  function markActionResult(pid, ok) {
    const p = asPid(pid)
    if (p == null) return null
    if (activePid !== p) return null
    if (ok === true) {
      const item = activeItem
      pausedPids.delete(p)
      queuedPids.delete(p)
      activePid = null
      activeItem = null
      logQueueStatus()
      setTimeout(() => tryShowNext(), 500)
      return item ? item.payload : null
    }
    return null
  }

  /**
   * - 函数: `clearPid`
   * - Function: `clearPid`
   * - 作用: 把指定 PID 从暂停集合、去重集合、活动项和待处理队列里一并清除，用于进程提前退出、人工取消或批量清理后的状态纠偏。
   * - Purpose: Clears the specified PID from the paused set, deduplication set, active slot, and pending queue in one place, so queue state can be repaired after early process exit, manual cancellation, or bulk cleanup.
   * - 调用方: `main.js` 中的拦截清理计划、进程退出处理和恢复路径会调用导出的 `clearPid(...)`。
   * - Callers: Called by interception cleanup plans, process-exit handling, and recovery paths in `main.js` through the exported `clearPid(...)` API.
   * - 被调方: `asPid`、`pausedPids.delete`、`queuedPids.delete`、`logQueueStatus`、`tryShowNext`、数组 `splice`。
   * - Callees: `asPid`, `pausedPids.delete`, `queuedPids.delete`, `logQueueStatus`, `tryShowNext`, and array `splice`.
   * - 变量说明: `pid` 为待清理的进程 ID；`p` 为归一化后的 PID；`pending` 中可能有多条与该 PID 对应的历史项；`activePid`/`activeItem` 代表当前展示中的任务。
   * - Variables: `pid` is the process ID to clear, `p` is the normalized PID, `pending` may contain multiple historical items for that PID, and `activePid` plus `activeItem` represent the task currently on screen.
   * - 接入方式: 当外部已确认某 PID 不应再展示或等待结果时，应优先调用本函数做整体验证状态清理，而不是只删队列中的单条记录。
   * - Integration: When outside logic knows a PID should no longer be shown or awaited, prefer this function for full state cleanup instead of deleting only one pending queue item.
   * - 错误处理: PID 无法解析时直接返回；即使目标 PID 已不存在也保持幂等，清理后仍会尝试续播下一项，避免队列被脏状态卡住。
   * - Error Handling: It returns immediately when the PID cannot be parsed; the operation remains idempotent even if the PID is already gone, and it still tries to resume playback afterward so stale state cannot stall the queue.
   * - 关键词: PID整体验证清理 | full PID state cleanup | 队列纠偏 | queue repair | 活动项复位 | active item reset | 进程退出回收 | process-exit recovery | 幂等删除 | idempotent removal
   */
  function clearPid(pid) {
    const p = asPid(pid)
    if (p == null) return
    pausedPids.delete(p)
    queuedPids.delete(p)
    if (activePid === p) {
      activePid = null
      activeItem = null
    }
    for (let i = pending.length - 1; i >= 0; i--) {
      if (pending[i] && pending[i].pid === p) pending.splice(i, 1)
    }
    logQueueStatus()
    tryShowNext()
  }

  /**
   * - 函数: `clearAll`
   * - Function: `clearAll`
   * - 作用: 一次性清空待处理队列、暂停 PID 集合和当前活动项，用于批量恢复后收尾或异常情况下的整队复位。
   * - Purpose: Clears the pending queue, paused PID set, and current active item in one operation, which is useful after batch resume or during emergency queue reset flows.
   * - 调用方: `main.js` 在批量恢复暂停进程的收尾逻辑和异常回退分支中调用本函数。
   * - Callers: `main.js` calls this helper in the finalization path after resuming paused processes and in error fallback branches.
   * - 被调方: `queuedPids.clear`、`pausedPids.clear`，并直接重置 `pending`、`activePid`、`activeItem`。
   * - Callees: It uses `queuedPids.clear`, `pausedPids.clear`, and directly resets `pending`, `activePid`, and `activeItem`.
   * - 变量说明: 无显式入参；`pending` 为待展示任务数组；`queuedPids` 为去重集合；`pausedPids` 为暂停态集合；`activePid`/`activeItem` 为当前活动项。
   * - Variables: There are no explicit parameters; `pending` is the queued task array, `queuedPids` is the deduplication set, `pausedPids` is the paused-state set, and `activePid` plus `activeItem` represent the current active entry.
   * - 接入方式: 任何需要“整队清空”的逻辑都应调用本函数，不要在外部分别清多个集合，否则容易漏掉活动项状态。
   * - Integration: Any full queue reset should call this helper instead of clearing multiple sets externally, otherwise active-item state can easily be missed.
   * - 错误处理: 本函数不抛异常，空队列上调用也保持幂等，方便主进程在 `try/catch` 收尾中重复使用。
   * - Error Handling: It does not throw, and calling it on an already empty queue remains idempotent, which makes it safe inside repeated cleanup paths.
   * - 关键词: 整队清空 | full queue reset | 暂停集合复位 | paused set reset | 活动项清除 | active item clear | 批量恢复收尾 | batch-resume cleanup | 幂等队列重置 | idempotent queue reset
   */
  function clearAll() {
    pending.length = 0
    queuedPids.clear()
    pausedPids.clear()
    activePid = null
    activeItem = null
  }

  return {
    configure,
    enqueuePausedProcess,
    markActionResult,
    clearPid,
    clearAll,
    getPausedPids,
    getAllPausedPayloads: () => {
      const list = []
      if (activeItem) list.push(activeItem.payload)
      pending.forEach(x => list.push(x.payload))
      return list
    },
    isIdle,
    tryShowNext,
    getActivePayload: () => {
      return activeItem ? activeItem.payload : null
    },
    getState: () => ({
      enabled,
      activePid,
      pending: pending.map(x => ({ pid: x.pid, enqueuedAt: x.enqueuedAt })),
      pausedPids: Array.from(pausedPids)
    })
  }
}

module.exports = {
  createInterceptionQueue,
  __test: { asPid }
}
