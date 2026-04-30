/**
 * 应用根组件
 * Application root component
 *
 * 负责：布局骨架（标题栏 + 侧边栏 + 主内容区）、页面路由分发、
 *       TrayExitPrompt 和 InterceptionModal 全局弹窗集成、Toast 容器挂载、启动画面。
 * Responsible for: Layout skeleton (titlebar + sidebar + content), page routing,
 *       TrayExitPrompt and InterceptionModal global modals, Toast container, SplashScreen.
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
import { handleInterception } from './api/process'
import Sidebar from './components/Sidebar'
import TitleBar from './components/TitleBar'
import Toast from './components/Toast'
import OverviewPage from './components/OverviewPage'
import ScanPage from './components/ScanPage'
import QuarantinePage from './components/QuarantinePage'
import BehaviorPage from './components/BehaviorPage'
import SettingsPage from './components/SettingsPage'
import TrayExitPrompt from './components/TrayExitPrompt'
import InterceptionModal from './components/InterceptionModal'
import SplashScreen from './components/SplashScreen'
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

interface InterceptionData {
  title: string
  message: string
  processName: string
  riskLevel: 'high' | 'medium' | 'low'
  filePath?: string
  pid?: number
}

const App: React.FC = () => {
  const { currentPage, loadConfig, setCurrentPage } = useConfigStore()
  const { initializeTheme } = useThemeStore()
  const { loadTranslations } = useI18nStore()
  const [isExitPromptOpen, setIsExitPromptOpen] = useState(false)
  const [interceptionData, setInterceptionData] = useState<InterceptionData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [splashStatus, setSplashStatus] = useState('正在初始化安全服务')
  const [lifecyclePid, setLifecyclePid] = useState<number | null>(null)
  const [lifecycleName, setLifecycleName] = useState('')

  /**
   * 初始化 / Initialize
   */
  useEffect(() => {
    const init = async () => {
      setSplashStatus('正在加载配置')
      await loadConfig()

      setSplashStatus('正在初始化主题')
      initializeTheme()

      setSplashStatus('正在加载语言包')
      await loadTranslations()

      // 监听托盘退出请求事件
      const unlistenTray = listen('tray-exit-requested', () => {
        setIsExitPromptOpen(true)
      })

      // 监听进程拦截事件
      const unlistenIntercept = listen<Record<string, unknown>>('process-intercepted', (event) => {
        const payload = event.payload
        setInterceptionData({
          title: (payload.title as string) || '进程行为拦截',
          message: (payload.message as string) || '检测到可疑进程行为，需要您的确认',
          processName: (payload.processName as string) || '未知进程',
          riskLevel: (payload.riskLevel as InterceptionData['riskLevel']) || 'medium',
          filePath: payload.filePath as string | undefined,
          pid: payload.pid as number | undefined,
        })
      })

      setSplashStatus('即将完成')
      // 最小启动时间保证 / Minimum startup time guarantee
      setTimeout(() => {
        setIsLoading(false)
      }, 800)

      return () => {
        unlistenTray.then(u => u())
        unlistenIntercept.then(u => u())
      }
    }

    init().catch((err) => {
      console.error('Initialization failed:', err)
      setSplashStatus('初始化失败')
    })
  }, [loadConfig, initializeTheme, loadTranslations])

  /** 关闭拦截弹窗 / Close interception modal */
  const handleCloseInterception = useCallback(() => {
    setInterceptionData(null)
  }, [])

  /** 处理拦截 — 阻止 / Handle interception block */
  const handleInterceptionBlock = useCallback(() => {
    if (interceptionData?.pid) {
      handleInterception(interceptionData.pid, 'block').catch(console.error)
    }
    setInterceptionData(null)
  }, [interceptionData])

  /** 处理拦截 — 允许 / Handle interception allow */
  const handleInterceptionAllow = useCallback(() => {
    if (interceptionData?.pid) {
      handleInterception(interceptionData.pid, 'allow').catch(console.error)
    }
    setInterceptionData(null)
  }, [interceptionData])

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
    <div className="app">
      {/* 启动画面 / Splash screen */}
      <SplashScreen isVisible={isLoading} statusText={splashStatus} />

      <TitleBar />
      <div className="app-body">
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
      </div>

      {/* 托盘退出确认弹窗 */}
      <TrayExitPrompt
        isOpen={isExitPromptOpen}
        onClose={() => setIsExitPromptOpen(false)}
      />

      {/* 进程拦截弹窗 */}
      <InterceptionModal
        isOpen={interceptionData !== null}
        onClose={handleCloseInterception}
        onAllow={handleInterceptionAllow}
        onBlock={handleInterceptionBlock}
        title={interceptionData?.title || '进程行为拦截'}
        message={interceptionData?.message || ''}
        processName={interceptionData?.processName || ''}
        riskLevel={interceptionData?.riskLevel || 'medium'}
        filePath={interceptionData?.filePath}
      />

      {/* 全局 Toast 通知 */}
      <Toast />
    </div>
  )
}

export default App
