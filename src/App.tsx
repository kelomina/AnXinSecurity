/**
 * 应用根组件
 * Application root component
 *
 * 负责：布局骨架（标题栏 + 侧边栏 + 主内容区）、页面路由分发、
 *       TrayExitPrompt 全局弹窗集成、Toast 容器挂载、启动画面。
 * Responsible for: Layout skeleton (titlebar + sidebar + content), page routing,
 *       TrayExitPrompt global modal, Toast container, SplashScreen.
 *
 * 调用方：main.tsx（通过 ReactDOM.createRoot 渲染）
 * Called by: main.tsx (rendered via ReactDOM.createRoot)
 *
 * 中文关键词：根组件，布局，路由，页面切换，弹窗，拦截，托盘退出，启动画面
 * English keywords: root component, layout, routing, page switch, modal, intercept, tray exit, splash
 */
import React, { useEffect, useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { listen } from '@tauri-apps/api/event'
import { useConfigStore } from './stores/configStore'
import { useThemeStore } from './stores/themeStore'
import { useI18nStore } from './stores/i18nStore'
import { onSnapshotProgress, onSnapshotResult } from './api/snapshot'
import Sidebar from './components/Sidebar'
import TitleBar from './components/TitleBar'
import Toast from './components/Toast'
import OverviewPage from './components/OverviewPage'
import ScanPage from './components/ScanPage'
import QuarantinePage from './components/QuarantinePage'
import BehaviorPage from './components/BehaviorPage'
import SettingsPage from './components/SettingsPage'
import TrayExitPrompt from './components/TrayExitPrompt'
import SplashScreen, {
  type StartupPhaseItem,
  type StartupPhaseStatus,
  type StartupSnapshotSummary,
} from './components/SplashScreen'
import BehaviorLifecyclePage from './components/BehaviorLifecyclePage'

const pageVariants = {
  initial: { opacity: 0, y: 8 },
  animate: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -8 }
}

const pageTransition = {
  duration: 0.25,
  ease: 'easeOut' as const
}

const PHASE_STATUS_RANK: Record<StartupPhaseStatus, number> = {
  pending: 0,
  active: 1,
  warning: 2,
  complete: 3,
  error: 4,
}

const STARTUP_PHASE_DEFINITIONS: Array<Omit<StartupPhaseItem, 'status'>> = [
  {
    id: 'config',
    labelKey: 'splash_phase_config',
    detailKey: 'splash_phase_config_detail',
  },
  {
    id: 'theme',
    labelKey: 'splash_phase_theme',
    detailKey: 'splash_phase_theme_detail',
  },
  {
    id: 'i18n',
    labelKey: 'splash_phase_i18n',
    detailKey: 'splash_phase_i18n_detail',
  },
  {
    id: 'listeners',
    labelKey: 'splash_phase_event_listeners',
    detailKey: 'splash_phase_event_listeners_detail',
  },
  {
    id: 'protection',
    labelKey: 'splash_phase_protection',
    detailKey: 'splash_phase_protection_detail',
  },
  {
    id: 'snapshot',
    labelKey: 'splash_phase_snapshot',
    detailKey: 'splash_phase_snapshot_detail',
  },
  {
    id: 'ready',
    labelKey: 'splash_phase_ready',
    detailKey: 'splash_phase_ready_detail',
  },
]

function buildStartupPhases(statuses: Record<string, StartupPhaseStatus>): StartupPhaseItem[] {
  return STARTUP_PHASE_DEFINITIONS.map((phase) => ({
    ...phase,
    status: statuses[phase.id] ?? 'pending',
  }))
}

const App: React.FC = () => {
  const { currentPage, loadConfig, setCurrentPage } = useConfigStore()
  const { initializeTheme } = useThemeStore()
  const { loadTranslations, t } = useI18nStore()
  const [isExitPromptOpen, setIsExitPromptOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [splashStatusKey, setSplashStatusKey] = useState('splash_status_bootstrap')
  const [startupPhaseStatuses, setStartupPhaseStatuses] = useState<Record<string, StartupPhaseStatus>>({
    config: 'active',
    theme: 'pending',
    i18n: 'pending',
    listeners: 'pending',
    protection: 'pending',
    snapshot: 'pending',
    ready: 'pending',
  })
  const [snapshotProgress, setSnapshotProgress] = useState<number | null>(null)
  const [snapshotCurrent, setSnapshotCurrent] = useState(0)
  const [snapshotTotal, setSnapshotTotal] = useState(0)
  const [snapshotSummary, setSnapshotSummary] = useState<StartupSnapshotSummary | null>(null)
  const [lifecyclePid, setLifecyclePid] = useState<number | null>(null)
  const [lifecycleName, setLifecycleName] = useState('')

  /**
   * 初始化 / Initialize
   */
  useEffect(() => {
    let mounted = true
    let snapshotProgressStarted = false
    let noProgressFallbackTimer: number | null = null
    let hideSplashTimer: number | null = null
    const cleanupFns: Array<() => void> = []

    const setPhaseStatus = (phaseId: string, status: StartupPhaseStatus) => {
      if (!mounted) return
      setStartupPhaseStatuses((current) => {
        const currentStatus = current[phaseId]
        if (
          currentStatus
          && status !== 'error'
          && PHASE_STATUS_RANK[currentStatus] > PHASE_STATUS_RANK[status]
        ) {
          return current
        }
        return {
          ...current,
          [phaseId]: status,
        }
      })
    }

    const setStatusKey = (statusKey: string) => {
      if (!mounted) return
      setSplashStatusKey(statusKey)
    }

    const addAsyncCleanup = (cleanupPromise: Promise<() => void>) => {
      cleanupPromise.then((cleanup) => {
        if (mounted) {
          cleanupFns.push(cleanup)
          return
        }
        cleanup()
      }).catch((err) => {
        console.error('Failed to register event listener:', err)
      })
    }

    const finishStartupScreen = (
      delayMs = 600,
      readyStatus: StartupPhaseStatus = 'complete',
      readyStatusKey = 'splash_status_ready',
    ) => {
      if (!mounted) return
      setPhaseStatus('ready', readyStatus)
      setStatusKey(readyStatusKey)
      if (hideSplashTimer !== null) {
        window.clearTimeout(hideSplashTimer)
      }
      hideSplashTimer = window.setTimeout(() => {
        if (mounted) {
          setIsLoading(false)
        }
      }, delayMs)
    }

    const init = async () => {
      const cleanupSnapshotProgress = onSnapshotProgress((progress) => {
        snapshotProgressStarted = true
        if (noProgressFallbackTimer !== null) {
          window.clearTimeout(noProgressFallbackTimer)
          noProgressFallbackTimer = null
        }
        const total = Math.max(0, progress.total || 0)
        const current = Math.max(0, Math.min(progress.current || 0, total || progress.current || 0))
        const percent = total > 0 ? (current / total) * 100 : null
        setSnapshotCurrent(current)
        setSnapshotTotal(total)
        setSnapshotProgress(percent)
        setPhaseStatus('protection', 'complete')
        setPhaseStatus('snapshot', 'active')
        setStatusKey('splash_status_snapshot')
      })
      cleanupFns.push(cleanupSnapshotProgress)

      const cleanupSnapshotResult = onSnapshotResult((result) => {
        if (noProgressFallbackTimer !== null) {
          window.clearTimeout(noProgressFallbackTimer)
          noProgressFallbackTimer = null
        }
        setSnapshotSummary({
          baselineComplete: result.baselineComplete,
          deepScanCompleted: result.deepScanCompleted,
          deepScanPendingModules: Math.max(0, result.deepScanPendingModules || 0),
          deepScanPendingProcesses: Math.max(0, result.deepScanPendingProcesses || 0),
          unknownProcesses: Math.max(0, result.unknownProcesses || 0),
          unknownModules: Math.max(0, result.unknownModules || 0),
          maliciousProcesses: Math.max(0, result.maliciousProcesses || 0),
          maliciousModules: Math.max(0, result.maliciousModules || 0),
          unsignedModuleAlerts: Math.max(0, result.unsignedModuleAlerts || 0),
          durationMs: Math.max(0, result.durationMs || 0),
        })
        if (
          result.deepScanCompleted ||
          (result.deepScanPendingModules <= 0 && result.deepScanPendingProcesses <= 0)
        ) {
          setSnapshotProgress(100)
          setPhaseStatus('snapshot', 'complete')
          setStatusKey('splash_status_snapshot_complete')
          finishStartupScreen()
        } else {
          setSnapshotProgress(96)
          setPhaseStatus('snapshot', 'warning')
          setStatusKey('splash_status_pending_checks')
          finishStartupScreen(1200, 'warning', 'splash_status_pending_checks')
        }
      })
      cleanupFns.push(cleanupSnapshotResult)

      setPhaseStatus('config', 'active')
      setStatusKey('splash_status_loading_config')
      await loadConfig()
      setPhaseStatus('config', 'complete')

      setPhaseStatus('theme', 'active')
      setStatusKey('splash_status_theme')
      initializeTheme()
      setPhaseStatus('theme', 'complete')

      setPhaseStatus('i18n', 'active')
      setStatusKey('splash_status_i18n')
      await loadTranslations()
      setPhaseStatus('i18n', 'complete')

      setPhaseStatus('listeners', 'active')
      setStatusKey('splash_status_events')
      addAsyncCleanup(listen('tray-exit-requested', () => {
        setIsExitPromptOpen(true)
      }))

      setPhaseStatus('listeners', 'complete')

      setPhaseStatus('protection', 'active')
      setStatusKey('splash_status_protection')
      noProgressFallbackTimer = window.setTimeout(() => {
        if (snapshotProgressStarted) return
        setPhaseStatus('snapshot', 'warning')
        setStatusKey('splash_status_pending_checks')
        finishStartupScreen(1200)
      }, 8000)
    }

    init().catch((err) => {
      console.error('Initialization failed:', err)
      setPhaseStatus('ready', 'error')
      setStatusKey('splash_status_failed')
    })

    return () => {
      mounted = false
      if (noProgressFallbackTimer !== null) {
        window.clearTimeout(noProgressFallbackTimer)
      }
      if (hideSplashTimer !== null) {
        window.clearTimeout(hideSplashTimer)
      }
      cleanupFns.forEach((cleanup) => cleanup())
    }
  }, [loadConfig, initializeTheme, loadTranslations, t])

  /** 打开行为生命周期页 / Open behavior lifecycle page */
  const handleOpenLifecycle = useCallback((pid: number, processName: string) => {
    setLifecyclePid(pid)
    setLifecycleName(processName)
    setCurrentPage('behavior-lifecycle')
  }, [setCurrentPage])

  /** 渲染当前页面组件 / Render current page component */
  const renderPage = () => {
    switch (currentPage) {
      case 'overview':
        return <OverviewPage onOpenLifecycle={handleOpenLifecycle} />
      case 'scan':
        return <ScanPage />
      case 'quarantine':
        return <QuarantinePage />
      case 'behavior':
        return <BehaviorPage onOpenLifecycle={handleOpenLifecycle} />
      case 'behavior-lifecycle':
        return lifecyclePid ? (
          <BehaviorLifecyclePage
            pid={lifecyclePid}
            processName={lifecycleName}
            onBack={() => setCurrentPage('behavior')}
          />
        ) : (
          <BehaviorPage onOpenLifecycle={handleOpenLifecycle} />
        )
      case 'settings':
        return <SettingsPage />
      default:
        return <OverviewPage onOpenLifecycle={handleOpenLifecycle} />
    }
  }

  return (
    <div className="app-layout">
      {/* 启动画面 / Splash screen */}
      <SplashScreen
        isVisible={isLoading}
        statusText={t(splashStatusKey)}
        phases={buildStartupPhases(startupPhaseStatuses)}
        snapshotProgress={snapshotProgress}
        snapshotCurrent={snapshotCurrent}
        snapshotTotal={snapshotTotal}
        snapshotSummary={snapshotSummary}
      />

      <TitleBar />
      <Sidebar />
      <main className="content">
        <AnimatePresence mode="wait">
          <motion.div
            key={currentPage}
            initial="initial"
            animate="animate"
            exit="exit"
            variants={pageVariants}
            transition={pageTransition}
            className="page-container"
          >
            {renderPage()}
          </motion.div>
        </AnimatePresence>
      </main>

      {/* 托盘退出确认弹窗 */}
      <TrayExitPrompt
        isOpen={isExitPromptOpen}
        onClose={() => setIsExitPromptOpen(false)}
      />

      {/* 全局 Toast 通知 */}
      <Toast />
    </div>
  )
}

export default App
