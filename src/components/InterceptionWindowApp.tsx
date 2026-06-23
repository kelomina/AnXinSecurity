import React, { useCallback, useEffect, useRef, useState } from 'react'
import { listen } from '@tauri-apps/api/event'
import { getCurrentWindow, UserAttentionType } from '@tauri-apps/api/window'
import InterceptionModal from './InterceptionModal'
import { useI18nStore } from '../stores/i18nStore'
import { useThemeStore } from '../stores/themeStore'
import { handleInterception, peekCurrentInterception } from '../api/process'
import type { InterceptionData } from '../types/interception'
import { normalizeInterceptionEventPayload } from '../utils/interceptionPayload'

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

  return (
    <div
      className={`interception-window-root${interceptionData ? ' has-interception' : ''}`}
    >
      <InterceptionModal
        isOpen={interceptionData !== null}
        onClose={handleClose}
        onAllow={handleAllow}
        onBlock={handleBlock}
        title={interceptionData?.title || t('intercept_title', '威胁拦截')}
        message={interceptionData?.message || t('intercept_window_waiting', '正在等待安全拦截事件')}
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
