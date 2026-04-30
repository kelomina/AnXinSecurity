import React, { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useConfigStore } from './stores/configStore'
import { useThemeStore } from './stores/themeStore'
import Sidebar from './components/Sidebar'
import OverviewPage from './components/OverviewPage'
import ScanPage from './components/ScanPage'
import QuarantinePage from './components/QuarantinePage'
import BehaviorPage from './components/BehaviorPage'
import SettingsPage from './components/SettingsPage'
import TrayExitPrompt from './components/TrayExitPrompt'

const pageVariants = {
  initial: { opacity: 0, y: 8 },
  animate: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -8 }
}

const pageTransition = {
  duration: 0.25,
  ease: 'easeOut' as const
}

const App: React.FC = () => {
  const { currentPage, loadConfig } = useConfigStore()
  const { initializeTheme } = useThemeStore()
  const [isExitPromptOpen, setIsExitPromptOpen] = useState(false)

  useEffect(() => {
    loadConfig()
    const cleanup = initializeTheme()
    return () => {
      if (typeof cleanup === 'function') {
        cleanup()
      }
    }
  }, [loadConfig, initializeTheme])

  const renderPage = () => {
    switch (currentPage) {
      case 'overview':
        return <OverviewPage />
      case 'scan':
        return <ScanPage />
      case 'quarantine':
        return <QuarantinePage />
      case 'behavior':
        return <BehaviorPage />
      case 'settings':
        return <SettingsPage />
      default:
        return <OverviewPage />
    }
  }

  return (
    <div className="app">
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
      <TrayExitPrompt 
        isOpen={isExitPromptOpen}
        onClose={() => setIsExitPromptOpen(false)}
      />
    </div>
  )
}

export default App
