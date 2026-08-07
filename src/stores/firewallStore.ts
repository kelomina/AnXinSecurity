/**
 * 网络防火墙状态仓库
 * Network firewall state store
 *
 * 持有防火墙状态、事件流、待裁决队列与流量统计，并订阅内核推送的
 * network-event / network-intercepted 两个事件。
 * Holds the firewall status, event stream, pending queue and traffic statistics,
 * and subscribes to the two kernel-pushed events network-event and
 * network-intercepted.
 *
 * 按 AGENTS.md 的分层要求，本层只做状态管理，不直接 invoke，全部经 src/api/firewall.ts。
 * Per the layering rule in AGENTS.md this layer only manages state; it never
 * calls invoke directly and always goes through src/api/firewall.ts.
 *
 * 中文关键词：防火墙仓库，事件订阅，乐观更新，失败回滚
 * English keywords: firewall store, event subscription, optimistic update, rollback
 */
import { create } from 'zustand'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import {
  flushFirewallCache,
  getFirewallStatus,
  getNetworkEvents,
  getNetworkPending,
  getNetworkStats,
  handleNetworkDecision,
  reloadFirewallRules,
  setFirewallEnabled,
  setFirewallMode,
  startFirewall,
  stopFirewall,
  type FirewallEvent,
  type FirewallStatus,
  type FirewallTrafficStats,
  type PendingConnection,
} from '../api/firewall'

/**
 * 界面保留的事件条数上限。
 * 后端环形缓冲是 500 条，这里保持一致：再多也只是内存里躺着，用户不会往下翻那么远。
 * Cap on events kept in the UI. The backend ring buffer holds 500 and this
 * matches it: anything more just sits in memory, since nobody scrolls that far.
 */
const MAX_UI_EVENTS = 500

/** 未连接驱动时的占位状态 / Placeholder status while the driver is not connected */
const EMPTY_STATUS: FirewallStatus = {
  running: false,
  driverConnected: false,
  capabilities: 0,
  driverVersion: '',
  mode: 'silent',
  enabled: false,
  ruleCount: 0,
  domainRuleCount: 0,
  limitCount: 0,
  pendingCount: 0,
  ruleWarnings: [],
}

interface FirewallState {
  status: FirewallStatus
  events: FirewallEvent[]
  pending: PendingConnection[]
  stats: FirewallTrafficStats | null

  /** 正在进行的写操作，用于禁用按钮 / In-flight write operation, used to disable buttons */
  controlPending: 'enabled' | 'mode' | 'rules' | 'cache' | null
  /** 最近一次操作的错误信息 / Error from the most recent operation */
  controlError: string | null
  /** 事件监听是否已挂上 / Whether the event listeners are attached */
  listening: boolean

  refreshStatus: () => Promise<void>
  refreshEvents: (limit?: number) => Promise<void>
  refreshPending: () => Promise<void>
  refreshStats: () => Promise<void>
  refreshAll: () => Promise<void>

  setEnabled: (enabled: boolean) => Promise<void>
  setMode: (mode: string) => Promise<void>
  reloadRules: () => Promise<string[]>
  clearRememberedChoices: () => Promise<void>
  decide: (
    decisionId: number,
    action: 'allow' | 'block',
    remember?: boolean,
    rememberProcess?: boolean,
  ) => Promise<boolean>

  startListening: () => Promise<void>
  stopListening: () => void
  clearError: () => void
}

/** 事件取消订阅句柄。放在模块作用域，避免把不可序列化的函数塞进 store 状态。 */
/*  Unlisten handles. Kept at module scope so non-serializable functions never
 *  end up inside the store state. */
let unlistenHandles: UnlistenFn[] = []

/** 把后端错误统一成可读文案 / Normalizes a backend error into readable text */
function describeError(action: string, error: unknown): string {
  const detail = error instanceof Error ? error.message : String(error)
  return `${action}: ${detail}`
}

export const useFirewallStore = create<FirewallState>((set, get) => ({
  status: EMPTY_STATUS,
  events: [],
  pending: [],
  stats: null,
  controlPending: null,
  controlError: null,
  listening: false,

  /**
   * 函数名称：refreshStatus
   * 函数作用：拉取防火墙运行状态。
   * Purpose: Fetches the firewall runtime status.
   * 错误处理：失败时回落到全 false 的占位状态而不是抛出 —— 界面需要能显示"未运行"。
   * Error handling: falls back to the all-false placeholder rather than throwing,
   *                 because the UI still needs to render "not running".
   * 中文关键词：状态刷新，降级展示
   * English keywords: status refresh, degraded display
   */
  refreshStatus: async () => {
    try {
      set({ status: await getFirewallStatus() })
    } catch (e) {
      console.error('[firewallStore] Failed to read firewall status:', e)
      set({ status: EMPTY_STATUS })
    }
  },

  refreshEvents: async (limit = MAX_UI_EVENTS) => {
    try {
      set({ events: await getNetworkEvents(limit) })
    } catch (e) {
      console.error('[firewallStore] Failed to read network events:', e)
    }
  },

  refreshPending: async () => {
    try {
      set({ pending: await getNetworkPending() })
    } catch (e) {
      console.error('[firewallStore] Failed to read the pending queue:', e)
    }
  },

  refreshStats: async () => {
    try {
      set({ stats: await getNetworkStats() })
    } catch (e) {
      // 统计需要驱动在线；未安装驱动时读不到是正常的，不当作错误展示
      //  Statistics need a live driver; failing without one is expected and is
      //  not surfaced as an error
      set({ stats: null })
    }
  },

  refreshAll: async () => {
    await Promise.all([
      get().refreshStatus(),
      get().refreshEvents(),
      get().refreshPending(),
      get().refreshStats(),
    ])
  },

  /**
   * 函数名称：setEnabled
   * 函数作用：切换防火墙总开关，先乐观更新界面，失败时回滚。
   * Purpose: Toggles the master switch with an optimistic UI update and rollback
   *          on failure.
   *
   * 顺序是「写配置 → 拉起/停止服务 → 回读真实状态」。回读这一步不能省：
   * 配置写成功但驱动没装时，开关会停在"已开启"而实际什么都没拦，
   * 必须让界面显示驱动未连接。
   * The order is: persist config, start/stop the service, then read the real
   * status back. That last step is essential — with the config saved but no
   * driver installed the switch would sit on "enabled" while nothing is actually
   * filtered, so the UI must show that the driver is not connected.
   *
   * 调用方：SettingsPage 与 FirewallPage 的总开关
   * Called by: the master switch on SettingsPage and FirewallPage
   * 中文关键词：总开关，乐观更新，失败回滚，回读校验
   * English keywords: master switch, optimistic update, rollback, read-back
   */
  setEnabled: async (enabled: boolean) => {
    const previous = get().status
    set({
      status: { ...previous, enabled },
      controlPending: 'enabled',
      controlError: null,
    })

    try {
      await setFirewallEnabled(enabled)
      if (enabled) {
        await startFirewall()
      } else {
        await stopFirewall()
      }
      await get().refreshStatus()
    } catch (e) {
      console.error('[firewallStore] Failed to toggle the firewall:', e)
      set({
        status: previous,
        controlError: describeError(enabled ? 'enable' : 'disable', e),
      })
      throw e
    } finally {
      set({ controlPending: null })
    }
  },

  /**
   * 函数名称：setMode
   * 函数作用：切换运行模式，失败时回滚界面。
   * Purpose: Switches the operating mode, rolling the UI back on failure.
   * 中文关键词：运行模式，失败回滚
   * English keywords: operating mode, rollback
   */
  setMode: async (mode: string) => {
    const previous = get().status
    set({
      status: { ...previous, mode },
      controlPending: 'mode',
      controlError: null,
    })

    try {
      await setFirewallMode(mode)
      await get().refreshStatus()
    } catch (e) {
      console.error('[firewallStore] Failed to switch the firewall mode:', e)
      set({ status: previous, controlError: describeError('set mode', e) })
      throw e
    } finally {
      set({ controlPending: null })
    }
  },

  /**
   * 函数名称：reloadRules
   * 函数作用：重新加载规则文件并下发，返回编译告警。
   * Purpose: Reloads the rule file, pushes it, and returns compile warnings.
   * 返回值：告警列表；非空表示有规则被跳过或表被截断，界面必须展示出来
   * Returns: warnings; a non-empty list means rules were skipped or tables
   *          truncated and the UI must surface it
   * 中文关键词：规则重载，编译告警
   * English keywords: rule reload, compile warnings
   */
  reloadRules: async () => {
    set({ controlPending: 'rules', controlError: null })
    try {
      const warnings = await reloadFirewallRules()
      await get().refreshStatus()
      return warnings
    } catch (e) {
      console.error('[firewallStore] Failed to reload firewall rules:', e)
      set({ controlError: describeError('reload rules', e) })
      throw e
    } finally {
      set({ controlPending: null })
    }
  },

  clearRememberedChoices: async () => {
    set({ controlPending: 'cache', controlError: null })
    try {
      await flushFirewallCache()
      await get().refreshStatus()
    } catch (e) {
      console.error('[firewallStore] Failed to clear remembered choices:', e)
      set({ controlError: describeError('clear remembered choices', e) })
      throw e
    } finally {
      set({ controlPending: null })
    }
  },

  /**
   * 函数名称：decide
   * 函数作用：提交连接裁决并把该条从待决队列中移除。
   * Purpose: Submits a verdict and removes the entry from the pending queue.
   * 返回值：true 表示驱动已按用户选择处理；false 表示驱动已先按超时策略处理
   * Returns: true when the driver applied the user's choice; false when the
   *          driver's timeout policy had already resolved it
   * 中文关键词：连接裁决，待决队列，超时竞态
   * English keywords: connection verdict, pending queue, timeout race
   */
  decide: async (decisionId, action, remember = false, rememberProcess = false) => {
    try {
      const result = await handleNetworkDecision(decisionId, action, remember, rememberProcess)
      set((state) => ({
        pending: state.pending.filter((item) => item.decisionId !== decisionId),
      }))
      return !result.alreadyResolved
    } catch (e) {
      console.error('[firewallStore] Failed to submit the network verdict:', e)
      // 提交失败也要把条目摘掉：驱动那边的超时最终会兜底，
      // 让一个点不动的弹窗一直挂在界面上只会让用户以为程序卡死。
      //  Drop the entry even on failure: the driver's timeout is the backstop,
      //  and leaving an unresponsive prompt on screen only makes the user think
      //  the app has hung.
      set((state) => ({
        pending: state.pending.filter((item) => item.decisionId !== decisionId),
        controlError: describeError('submit verdict', e),
      }))
      throw e
    }
  },

  /**
   * 函数名称：startListening
   * 函数作用：订阅 network-event 与 network-intercepted 两个后端事件。
   * Purpose: Subscribes to the network-event and network-intercepted backend events.
   *
   * 重复调用是安全的：已订阅时直接返回，避免同一个事件被处理多次。
   * Repeat calls are safe: it returns early when already subscribed so a single
   * event is never handled twice.
   *
   * 调用方：FirewallPage 挂载时
   * Called by: FirewallPage on mount
   * 中文关键词：事件订阅，幂等，重复挂载
   * English keywords: event subscription, idempotent, double mount
   */
  startListening: async () => {
    if (get().listening) {
      return
    }
    set({ listening: true })

    try {
      const unlistenEvent = await listen<FirewallEvent>('network-event', (payload) => {
        set((state) => {
          const next = [payload.payload, ...state.events]
          return { events: next.length > MAX_UI_EVENTS ? next.slice(0, MAX_UI_EVENTS) : next }
        })
      })

      const unlistenIntercept = await listen<PendingConnection>(
        'network-intercepted',
        (payload) => {
          set((state) => {
            // 同一个 decisionId 只保留一条，重复推送不叠加
            //  Keep one entry per decisionId; repeated pushes do not stack
            const withoutDuplicate = state.pending.filter(
              (item) => item.decisionId !== payload.payload.decisionId,
            )
            return { pending: [...withoutDuplicate, payload.payload] }
          })
        },
      )

      unlistenHandles = [unlistenEvent, unlistenIntercept]
    } catch (e) {
      console.error('[firewallStore] Failed to subscribe to firewall events:', e)
      set({ listening: false })
    }
  },

  stopListening: () => {
    for (const unlisten of unlistenHandles) {
      try {
        unlisten()
      } catch (e) {
        console.error('[firewallStore] Failed to unsubscribe:', e)
      }
    }
    unlistenHandles = []
    set({ listening: false })
  },

  clearError: () => set({ controlError: null }),
}))
