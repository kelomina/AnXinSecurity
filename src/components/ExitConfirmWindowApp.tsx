import React, { useEffect, useState } from 'react'
import { getCurrentWindow } from '@tauri-apps/api/window'
import { listen } from '@tauri-apps/api/event'
import { useI18nStore } from '../stores/i18nStore'
import TrayExitPrompt from './TrayExitPrompt'

/**
 * 独立退出确认窗口应用（AnXinTray 进程的 exit-confirm 窗口）
 * Standalone exit-confirmation window application (the "exit-confirm" window of the AnXinTray process)
 *
 * 生命周期：托盘「退出」菜单创建/显示本窗口并 emit tray-exit-requested；
 * 用户确认后 invoke execute_exit（内部经 IPC 停止服务进程）→ 整个 GUI 一起退出；
 * 取消则仅隐藏窗口，托盘与服务继续驻留。
 * Lifecycle: the tray "exit" menu creates/shows this window and emits tray-exit-requested;
 * on confirm, execute_exit is invoked (stopping the service via IPC) and the whole GUI
 * exits together; cancel only hides the window — tray and service stay resident.
 */
const ExitConfirmWindowApp: React.FC = () => {
  const { loadTranslations } = useI18nStore()
  const [isOpen, setIsOpen] = useState(true)

  useEffect(() => {
    let mounted = true
    let cleanup: (() => void) | undefined

    loadTranslations().catch((err) => {
      console.error('[ExitConfirm] Translation fallback activated:', err)
    })

    listen('tray-exit-requested', () => {
      if (mounted) setIsOpen(true)
    })
      .then((unlisten) => {
        if (!mounted) {
          unlisten()
          return
        }
        cleanup = unlisten
      })
      .catch((err) => {
        console.error('[ExitConfirm] Event listener registration failed:', err)
      })

    // 托盘每次点击「退出」都会先 emit tray-exit-requested 再显示窗口，
    // 上面的监听已覆盖「再次退出时重新打开对话框」的场景。
    //  The tray emits tray-exit-requested before showing the window every time "exit"
    //  is clicked; the listener above covers re-opening the dialog.

    return () => {
      mounted = false
      cleanup?.()
    }
  }, [loadTranslations])

  const handleClose = () => {
    setIsOpen(false)
    void getCurrentWindow().hide().catch(() => {})
  }

  return <TrayExitPrompt isOpen={isOpen} onClose={handleClose} />
}

export default ExitConfirmWindowApp
