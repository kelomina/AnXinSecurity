/**
 * 应用根组件
 * Application root component
 *
 * 负责：布局骨架（标题栏 + 侧边栏 + 主内容区）、页面路由分发、
 *       TrayExitPrompt 全局弹窗集成、Toast 容器挂载、启动画面。
 * Responsible for: Layout skeleton (titlebar + sidebar + content), page routing,
 *       Toast container, SplashScreen. (exit-confirm modal moved to the Tray process)
 *
 * 调用方：main.tsx（通过 ReactDOM.createRoot 渲染）
 * Called by: main.tsx (rendered via ReactDOM.createRoot)
 *
 * 中文关键词：根组件，布局，路由，页面切换，弹窗，拦截，托盘退出，启动画面
 * English keywords: root component, layout, routing, page switch, modal, intercept, tray exit, splash
 */
import React, { useEffect, useState, useCallback, lazy, Suspense } from 'react'
import { listen } from '@tauri-apps/api/event'
import { getCurrentWindow } from '@tauri-apps/api/window'
import { useConfigStore } from './stores/configStore'
import { useThemeStore } from './stores/themeStore'
import { useI18nStore } from './stores/i18nStore'
import { onSnapshotProgress, onSnapshotResult } from './api/snapshot'
import { getPrivilegeStatus } from './api/privilege'
import { startEngine, scannerHealth } from './api/scanner'
import Sidebar from './components/Sidebar'
import TitleBar from './components/TitleBar'
import Toast from './components/Toast'
import SplashScreen, {
  type StartupPhaseItem,
  type StartupPhaseStatus,
  type StartupSnapshotSummary,
} from './components/SplashScreen'

// 页面组件按需加载：闪屏期间只需要 SplashScreen / TitleBar / Sidebar，
// 六个页面（合计数千行 + Fluent 组件）不该进入首屏 bundle 拖慢启动。
// SplashScreen 必须保持静态导入——它就是加载期间要显示的东西。
//  Pages are code-split: the splash phase only needs SplashScreen / TitleBar / Sidebar, so the
//  six pages (several thousand lines plus Fluent components) must stay out of the initial
//  bundle. SplashScreen itself stays statically imported - it is what shows while loading.
const OverviewPage = lazy(() => import('./components/OverviewPage'))
const ScanPage = lazy(() => import('./components/ScanPage'))
const QuarantinePage = lazy(() => import('./components/QuarantinePage'))
const BehaviorPage = lazy(() => import('./components/BehaviorPage'))
const FirewallPage = lazy(() => import('./components/FirewallPage'))
const SettingsPage = lazy(() => import('./components/SettingsPage'))
const BehaviorLifecyclePage = lazy(() => import('./components/BehaviorLifecyclePage'))
const ProcessLifecyclePage = lazy(() => import('./components/ProcessLifecyclePage'))

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
  // 用 selector 只订阅 action 引用，避免整店订阅让根组件随 themeMode/actualTheme/
  // animationsEnabled 的任何变化重渲染整棵页面树（zustand 的 action 引用是稳定的）。
  //  Subscribe to the action references via selectors: a whole-store subscription would
  //  re-render the entire page tree on every themeMode / actualTheme / animationsEnabled
  //  change. zustand action references are stable, so the init effect will not re-run.
  const initializeTheme = useThemeStore((state) => state.initializeTheme)
  const syncFromConfig = useThemeStore((state) => state.syncFromConfig)
  const { loadTranslations, t } = useI18nStore()
  const [isLoading, setIsLoading] = useState(true)
  // 非管理员权限提示 / Non-admin privilege warning
  const [showPrivilegeWarning, setShowPrivilegeWarning] = useState(false)
  // 远程会话状态 / Remote session state
  const [isRemoteSession, setIsRemoteSession] = useState(false)
  // 内存节省模式 / Memory-saving mode
  const [isLowPowerMode, setIsLowPowerMode] = useState(false)
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

      // config 与 i18n 两次 IPC 往返互不依赖，先发起再统一 await，让它们重叠，
      // 中间穿插纯本地的主题初始化，缩短闪屏时间。
      // loadConfig / loadTranslations 内部都自行吞掉异常并回退，不会产生未处理拒绝。
      //  The config and i18n round-trips are independent: kick both off and await them together
      //  so they overlap, with the purely local theme init in between. Both loaders swallow their
      //  own errors and fall back, so no unhandled rejection can escape here.
      setPhaseStatus('config', 'active')
      setStatusKey('splash_status_loading_config')
      const configPromise = loadConfig()

      setPhaseStatus('theme', 'active')
      setStatusKey('splash_status_theme')
      const cleanupTheme = initializeTheme()
      if (cleanupTheme) {
        cleanupFns.push(cleanupTheme)
      }
      setPhaseStatus('theme', 'complete')

      setPhaseStatus('i18n', 'active')
      setStatusKey('splash_status_i18n')
      const translationsPromise = loadTranslations()

      // 配置就绪后把后端的外观设置同步到 themeStore。
      // 顺序很重要：必须在 initializeTheme() 之后，否则 initializeTheme 的
      // set({ actualTheme }) 会把配置推导出的主题覆盖掉。
      // 用 getState() 而不是订阅值，避免在 effect 闭包里读到旧值。
      //  Sync the backend appearance settings into themeStore once the config resolves.
      //  Order matters: this must follow initializeTheme(), whose set({ actualTheme }) would
      //  otherwise overwrite the config-derived theme. getState() avoids reading a stale value
      //  captured by the effect closure.
      await configPromise
      setPhaseStatus('config', 'complete')
      syncFromConfig(useConfigStore.getState().config)

      await translationsPromise
      setPhaseStatus('i18n', 'complete')

      setPhaseStatus('listeners', 'active')
      setStatusKey('splash_status_events')

      // 监听内存节省模式切换（主窗口隐藏到托盘时进入，显示时退出）
      //  Listen for memory-saving mode changes (enter when main window hidden to tray, exit when shown)
      addAsyncCleanup(listen<boolean>('memory-mode-changed', (event) => {
        setIsLowPowerMode(event.payload)
      }))

      // 监听远程会话状态变化（检测到远程控制软件时隐藏 UI）
      //  Listen for remote session state changes (hide UI when remote control software detected)
      addAsyncCleanup(listen<{ is_remote: boolean }>('remote-session-changed', (event) => {
        const isRemote = event.payload.is_remote
        setIsRemoteSession(isRemote)
        if (isRemote) {
          // 检测到远程会话，隐藏主窗口（后台防护继续运行）
          //  Remote session detected, hide main window (background protection continues)
          const currentWindow = getCurrentWindow()
          currentWindow.hide().catch(() => {})
        }
      }))

      setPhaseStatus('listeners', 'complete')

      // 检查管理员权限和 IPC 连接状态
      //  Check admin privileges and IPC connection status
      let serviceConnected = false
      try {
        const status = await getPrivilegeStatus()
        serviceConnected = status.service_connected
        if (!status.is_elevated) {
          setShowPrivilegeWarning(true)
        }
      } catch (err) {
        console.error('Failed to check privilege status:', err)
      }

      // 如果已连接服务进程，防护由 SYSTEM 服务提供，跳过本地快照等待
      //  If connected to service process, protection is provided by SYSTEM service,
      //  skip local snapshot waiting — snapshot runs in service process and results
      //  will arrive via IPC event forwarding
      if (serviceConnected) {
        setPhaseStatus('protection', 'complete')
        setPhaseStatus('snapshot', 'complete')
        setStatusKey('splash_status_snapshot_complete')
        finishStartupScreen()
        return
      }

      setPhaseStatus('protection', 'active')
      setStatusKey('splash_status_protection')

      // 引擎自检：首次安装时默认启动引擎
      //  Engine self-check: auto-start engine on first install
      try {
        const health = await scannerHealth()
        if (health.status !== 'running') {
          await startEngine()
        }
      } catch (err) {
        console.error('Engine auto-start check failed:', err)
      }

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
  }, [loadConfig, initializeTheme, syncFromConfig, loadTranslations, t])

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
      case 'firewall':
        return <FirewallPage />
      case 'process-lifecycle':
        return <ProcessLifecyclePage />
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
        {/* 非管理员权限警告横幅 / Non-admin privilege warning banner */}
        {showPrivilegeWarning && (
          <div className="privilege-warning-banner">
            <span>{t('warning_non_admin_title')}</span>
            <span>{t('warning_non_admin_message')}</span>
            <button
              className="privilege-warning-close"
              onClick={() => setShowPrivilegeWarning(false)}
              aria-label={t('common_close')}
            >
              ×
            </button>
          </div>
        )}
        {/*
          页面外壳保持稳定：只用 data-current-page 标记当前页，不要给容器加 React key。
          带 key 会让 React 在切页时卸载并重建整棵子树，丢掉页面状态并造成可见闪烁。
          Keep the page shell stable: mark the active page with data-current-page and never give
          this container a React key, which would unmount and rebuild the whole subtree on every
          page switch, discarding page state and causing a visible flash.
        */}
        {/*
          fallback 用同一个空的 page-container，保证代码分片加载期间布局尺寸不跳变。
          Fallback reuses an empty page-container so the layout does not shift while a chunk loads.
        */}
        <Suspense fallback={<div className="page-container" />}>
          <div className="page-container" data-current-page={currentPage} data-low-power={isLowPowerMode ? 'true' : 'false'} data-remote={isRemoteSession ? 'true' : 'false'}>
            {renderPage()}
          </div>
        </Suspense>
      </main>

      {/* 全局 Toast 通知 */}
      <Toast />
    </div>
  )
}

export default App
