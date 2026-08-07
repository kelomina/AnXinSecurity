import React, { useCallback, useEffect, useRef, useState } from 'react'
import { listen } from '@tauri-apps/api/event'
import { getCurrentWindow, UserAttentionType } from '@tauri-apps/api/window'
import InterceptionModal from './InterceptionModal'
import { useI18nStore } from '../stores/i18nStore'
import { useThemeStore } from '../stores/themeStore'
import { handleInterception, peekCurrentInterception } from '../api/process'
import { getNetworkPending, handleNetworkDecision, type PendingConnection } from '../api/firewall'
import type { InterceptionData } from '../types/interception'
import { normalizeInterceptionEventPayload } from '../utils/interceptionPayload'
import { Checkbox } from '@fluentui/react-components'

const DEFAULT_INTERCEPTION_ACTION = 'block'
const INTERCEPTION_AUTO_DECISION_SECONDS = 60

/**
 * 独立拦截窗口应用
 * Independent interception window application
 *
 * 窗口生命周期完全由后端 InterceptionService 控制：
 * - 后端 try_show_next 负责准备隐藏窗口、推送事件
 * - 后端 mark_decision_with_window 负责隐藏窗口
 * - 后端 handle_interception 命令在隐藏后立即调用 try_show_next 轮播下一个
 * 前端只做：接收事件/拉取当前条目 → 渲染弹窗 → 唤醒窗口 → 发送决策命令
 * 这样独立窗口不会在还没拿到拦截数据时先显示空红色背景。
 *
 * Window lifecycle is fully controlled by the backend InterceptionService:
 * - Backend try_show_next prepares the hidden window and emits events
 * - Backend mark_decision_with_window hides the window
 * - Backend handle_interception calls try_show_next after hiding for queue rotation
 * Frontend only: receives events/pulls current entry → renders modal → brings the window forward → sends decision command
 * This prevents the independent window from showing an empty red background before interception data is ready.
 */
const InterceptionWindowApp: React.FC = () => {
  const { loadTranslations, t } = useI18nStore()
  const { initializeTheme } = useThemeStore()
  const [interceptionData, setInterceptionData] = useState<InterceptionData | null>(null)
  const [remainingSeconds, setRemainingSeconds] = useState(INTERCEPTION_AUTO_DECISION_SECONDS)
  const [decisionInFlightPid, setDecisionInFlightPid] = useState<number | null>(null)
  const autoDecisionTriggeredPidRef = useRef<number | null>(null)

  // 网络连接询问 / Network connection prompt
  const [networkData, setNetworkData] = useState<PendingConnection | null>(null)
  const [networkRemember, setNetworkRemember] = useState(false)
  const [networkSeconds, setNetworkSeconds] = useState(0)
  const [networkDecisionInFlight, setNetworkDecisionInFlight] = useState<number | null>(null)

  useEffect(() => {
    let mounted = true
    let cleanupTheme: (() => void) | void
    let cleanupEventListener: (() => void) | void

    const bringToFront = async () => {
      const currentWindow = getCurrentWindow()
      await currentWindow.show().catch(() => {})
      await currentWindow.unminimize().catch(() => {})
      await currentWindow.setAlwaysOnTop(true).catch(() => {})
      await currentWindow.requestUserAttention(UserAttentionType.Critical).catch(() => {})
      await currentWindow.setFocus().catch(() => {})
    }

    const init = async () => {
      cleanupTheme = initializeTheme() || undefined
      await loadTranslations().catch((err) => {
        console.error('[InterceptionWindow] Translation fallback activated:', err)
      })

      // 注册事件监听 — 接收后端推送的拦截事件 / Register event listener for backend push
      const unlisten = await listen<Record<string, unknown>>('process-intercepted', async (event) => {
        if (!mounted) return
        const nextInterception = normalizeInterceptionEventPayload(event.payload, t)
        setInterceptionData((current) => {
          if (current?.pid && current.pid === nextInterception.pid) {
            return current
          }
          return nextInterception
        })
        await bringToFront()
      }).catch((err) => {
        console.error('[InterceptionWindow] Event listener registration failed:', err)
        return null
      })

      if (!mounted) {
        unlisten?.()
        return
      }
      cleanupEventListener = unlisten || undefined

      // Webview 加载完成后主动拉取当前待处理的拦截 / Pull current pending interception after webview loads
      // 解决首次启动时 emit_to 早于 JS 监听注册的竞争 / Fixes race where emit_to fires before JS listener is registered
      const current = await peekCurrentInterception().catch((err) => {
        console.error('[InterceptionWindow] Failed to peek current interception:', err)
        return null
      })
      if (!mounted) return
      if (current && typeof current === 'object') {
        setInterceptionData(normalizeInterceptionEventPayload(current as Record<string, unknown>, t))
        await bringToFront()
      }
    }

    init().catch((err) => {
      console.error('[InterceptionWindow] Initialization failed:', err)
    })

    return () => {
      mounted = false
      if (cleanupTheme) {
        cleanupTheme()
      }
      if (cleanupEventListener) {
        cleanupEventListener()
      }
    }
  }, [initializeTheme, loadTranslations, t])

  useEffect(() => {
    if (!interceptionData?.pid) {
      autoDecisionTriggeredPidRef.current = null
      setRemainingSeconds(INTERCEPTION_AUTO_DECISION_SECONDS)
      return
    }

    autoDecisionTriggeredPidRef.current = null
    setRemainingSeconds(INTERCEPTION_AUTO_DECISION_SECONDS)
    const timer = window.setInterval(() => {
      setRemainingSeconds((current) => {
        if (current <= 1) {
          window.clearInterval(timer)
          return 0
        }
        return current - 1
      })
    }, 1000)

    return () => window.clearInterval(timer)
  }, [interceptionData?.pid])

  const submitDecision = useCallback((action: 'allow' | 'block') => {
    const pid = interceptionData?.pid
    if (!pid || decisionInFlightPid === pid) return

    setDecisionInFlightPid(pid)
    handleInterception(pid, action)
      .then(() => {
        setInterceptionData((current) => (current?.pid === pid ? null : current))
      })
      .catch((err) => {
        console.error(`[InterceptionWindow] ${action} failed:`, err)
      })
      .finally(() => {
        setDecisionInFlightPid((current) => (current === pid ? null : current))
      })
  }, [decisionInFlightPid, interceptionData])

  useEffect(() => {
    if (!interceptionData?.pid || remainingSeconds !== 0) return
    if (autoDecisionTriggeredPidRef.current === interceptionData.pid) return
    autoDecisionTriggeredPidRef.current = interceptionData.pid
    submitDecision(DEFAULT_INTERCEPTION_ACTION)
  }, [interceptionData?.pid, remainingSeconds, submitDecision])

  /**
   * 处理允许 — 命令成功后清除当前弹窗，后端会继续轮播下一条。
   * 后端 handle_interception 会调用 mark_decision_with_window（隐藏）+ try_show_next（显示下一个或保持隐藏）。
   * Handle allow — clears the current modal after the command succeeds; the backend rotates to the next entry.
   * Backend handle_interception calls mark_decision_with_window (hide) + try_show_next (show next or keep hidden).
   */
  const handleAllow = useCallback(() => {
    submitDecision('allow')
  }, [submitDecision])

  /**
   * 处理阻止 — 同上 / Handle block — same as above
   */
  const handleBlock = useCallback(() => {
    submitDecision('block')
  }, [submitDecision])

  /**
   * 关闭按钮在 window 模式下不渲染，此回调仅作为安全降级。
   * Close button is not rendered in window mode; this callback is a safety fallback only.
   */
  const handleClose = useCallback(() => {
    setInterceptionData((current) => (current ? null : current))
  }, [])

  // ==========================================================================
  // 网络连接询问 / Network connection prompt
  //
  // 与进程拦截共用同一个窗口和同一个弹窗组件，但决策通道完全独立：
  // 进程拦截按 PID 裁决，网络连接按驱动分配的 decisionId 裁决。
  // 两者同时待决时优先展示进程拦截 —— 那边有一个被挂起的进程在等，
  // 代价比一条被挂起的连接高得多。
  //  Shares the window and modal component with process interception, but the
  //  decision channel is entirely separate: process interception is keyed by PID,
  //  a network connection by the driver-assigned decisionId. When both are
  //  pending, process interception wins — a suspended process is a far higher
  //  cost to leave waiting than a suspended connection.
  // ==========================================================================

  useEffect(() => {
    let mounted = true
    let cleanup: (() => void) | undefined

    const bringToFront = async () => {
      const currentWindow = getCurrentWindow()
      await currentWindow.show().catch(() => {})
      await currentWindow.unminimize().catch(() => {})
      await currentWindow.setAlwaysOnTop(true).catch(() => {})
      await currentWindow.requestUserAttention(UserAttentionType.Critical).catch(() => {})
      await currentWindow.setFocus().catch(() => {})
    }

    const init = async () => {
      const unlisten = await listen<PendingConnection>('network-intercepted', async (event) => {
        if (!mounted) return
        setNetworkData((current) =>
          current && current.decisionId === event.payload.decisionId ? current : event.payload,
        )
        setNetworkRemember(false)
        await bringToFront()
      }).catch((err) => {
        console.error('[InterceptionWindow] Network event listener registration failed:', err)
        return null
      })

      if (!mounted) {
        unlisten?.()
        return
      }
      cleanup = unlisten || undefined

      // 与进程拦截同理：补拉一次，避免事件早于监听注册
      //  Same as process interception: backfill once in case the event fired
      //  before the listener was registered
      const pending = await getNetworkPending().catch(() => [])
      if (!mounted || pending.length === 0) return
      setNetworkData(pending[0])
      await bringToFront()
    }

    init().catch((err) => {
      console.error('[InterceptionWindow] Network prompt initialization failed:', err)
    })

    return () => {
      mounted = false
      cleanup?.()
    }
  }, [])

  /**
   * 倒计时来自驱动给出的 expiresAt，而不是前端自己定的固定秒数。
   * 归零时只把弹窗收掉，绝不自动提交裁决 —— 驱动的超时扫描已经会按配置的
   * timeoutAction 完成这次分类，前端再提交一次只会撞上一个必然失败的竞态。
   * The countdown comes from the driver's expiresAt rather than a fixed
   * frontend duration. On reaching zero the prompt is only dismissed, never
   * auto-submitted: the driver's timeout sweep has already completed the
   * classification with the configured timeoutAction, and submitting again would
   * only enter a race it is guaranteed to lose.
   */
  useEffect(() => {
    if (!networkData) {
      setNetworkSeconds(0)
      return
    }

    const tick = () => {
      const remaining = Math.max(0, Math.ceil((networkData.expiresAt - Date.now()) / 1000))
      setNetworkSeconds(remaining)
      if (remaining === 0) {
        setNetworkData((current) =>
          current?.decisionId === networkData.decisionId ? null : current,
        )
      }
    }

    tick()
    const timer = window.setInterval(tick, 1000)
    return () => window.clearInterval(timer)
  }, [networkData])

  const submitNetworkDecision = useCallback(
    (action: 'allow' | 'block') => {
      const decisionId = networkData?.decisionId
      if (!decisionId || networkDecisionInFlight === decisionId) return

      setNetworkDecisionInFlight(decisionId)
      handleNetworkDecision(decisionId, action, networkRemember, false)
        .catch((err) => {
          console.error(`[InterceptionWindow] Network ${action} failed:`, err)
        })
        .finally(() => {
          setNetworkDecisionInFlight((current) => (current === decisionId ? null : current))
          setNetworkData((current) => (current?.decisionId === decisionId ? null : current))
          setNetworkRemember(false)
        })
    },
    [networkData, networkDecisionInFlight, networkRemember],
  )

  const handleNetworkAllow = useCallback(() => submitNetworkDecision('allow'), [submitNetworkDecision])
  const handleNetworkBlock = useCallback(() => submitNetworkDecision('block'), [submitNetworkDecision])
  const handleNetworkClose = useCallback(() => setNetworkData(null), [])

  // 进程拦截优先，网络询问排在它后面 / Process interception first, network prompt second
  const showNetworkPrompt = interceptionData === null && networkData !== null

  if (showNetworkPrompt && networkData) {
    const endpoint = `${networkData.remoteAddress}:${networkData.remotePort}`
    return (
      <div className="interception-window-root has-interception">
        <InterceptionModal
          isOpen
          onClose={handleNetworkClose}
          onAllow={handleNetworkAllow}
          onBlock={handleNetworkBlock}
          title={t('intercept_network_title')}
          message={t('intercept_network_message')
            .replace('{process}', networkData.processName || `PID ${networkData.pid}`)
            .replace('{remote}', endpoint)}
          processName={networkData.processName || `PID ${networkData.pid}`}
          riskLevel="medium"
          filePath={networkData.processPath}
          mode="window"
          defaultAction={DEFAULT_INTERCEPTION_ACTION}
          remainingSeconds={networkSeconds}
          autoDecisionSeconds={Math.max(
            1,
            Math.ceil((networkData.expiresAt - networkData.timestamp) / 1000),
          )}
          decisionPending={networkDecisionInFlight === networkData.decisionId}
          allowLabel={t('intercept_network_allow')}
          blockLabel={t('intercept_network_block')}
          extraControl={
            <div style={{ padding: '0 24px 8px' }}>
              <Checkbox
                checked={networkRemember}
                label={t('intercept_network_remember')}
                onChange={(_, data) => setNetworkRemember(Boolean(data.checked))}
              />
            </div>
          }
        />
      </div>
    )
  }

  return (
    <div
      className={`interception-window-root${interceptionData ? ' has-interception' : ''}`}
    >
      <InterceptionModal
        isOpen={interceptionData !== null}
        onClose={handleClose}
        onAllow={handleAllow}
        onBlock={handleBlock}
        title={interceptionData?.title || t('intercept_title')}
        message={interceptionData?.message || t('intercept_window_waiting')}
        processName={interceptionData?.processName || ''}
        riskLevel={interceptionData?.riskLevel || 'medium'}
        filePath={interceptionData?.filePath}
        mode="window"
        defaultAction={DEFAULT_INTERCEPTION_ACTION}
        remainingSeconds={remainingSeconds}
        autoDecisionSeconds={INTERCEPTION_AUTO_DECISION_SECONDS}
        decisionPending={decisionInFlightPid === interceptionData?.pid}
      />
    </div>
  )
}

export default InterceptionWindowApp
