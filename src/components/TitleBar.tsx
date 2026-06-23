/**
 * 窗口标题栏组件
 * Window title bar component
 *
 * 自定义窗口标题栏，支持最小化、最大化/还原、关闭操作。
 * 使用 Tauri Window API 控制窗口。
 * Custom window title bar with minimize, maximize/restore, and close buttons.
 * Uses Tauri Window API to control the window.
 *
 * 调用方：App.tsx（挂载在根布局顶部）
 * Called by: App.tsx (mounted at top of root layout)
 *
 * 中文关键词：标题栏，窗口控制，最小化，最大化，关闭，拖拽区域
 * English keywords: title bar, window controls, minimize, maximize, close, drag region
 */
import React, { useEffect, useState } from 'react'
import { Moon, Sun } from 'lucide-react'
import { getCurrentWindow } from '@tauri-apps/api/window'
import { useThemeStore } from '../stores/themeStore'
import { useI18nStore } from '../stores/i18nStore'
import { Button, makeStyles, shorthands, tokens } from '@fluentui/react-components'

const useStyles = makeStyles({
  titlebar: {
    gridColumn: '1 / -1',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    height: '32px',
    ...shorthands.padding('0', '8px', '0', '16px'),
    backgroundColor: tokens.colorNeutralBackground2,
    WebkitAppRegion: 'drag',
    userSelect: 'none',
    ...shorthands.borderBottom('1px', 'solid', tokens.colorNeutralStroke2),
  },
  titlebarLeft: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('8px'),
  },
  titlebarIcon: {
    color: tokens.colorBrandForeground1,
  },
  titlebarText: {
    fontSize: '13px',
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground1,
  },
  titlebarRight: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('0'),
    WebkitAppRegion: 'no-drag',
  },
  titlebarBtn: {
    width: '36px',
    height: '32px',
    minWidth: '36px',
    ...shorthands.borderRadius('0'),
    ...shorthands.padding('0'),
    ':hover': {
      backgroundColor: tokens.colorNeutralBackground1Hover,
    },
  },
  closeBtn: {
    ':hover': {
      backgroundColor: '#C84F5A',
      color: '#fff',
    },
  },
  themeToggleBtn: {
    width: '36px',
    height: '32px',
    minWidth: '36px',
    ...shorthands.borderRadius('0'),
    ...shorthands.padding('0'),
  },
})

const TitleBar: React.FC = () => {
  const appWindow = getCurrentWindow()
  const [isMaximized, setIsMaximized] = useState(false)
  const { themeMode, setThemeMode } = useThemeStore()
  const { t } = useI18nStore()
  const styles = useStyles()

  /**
   * 初始化：检查窗口是否已最大化
   * Init: check if window is currently maximized
   */
  useEffect(() => {
    appWindow.isMaximized().then(setIsMaximized).catch((e) => console.error('[TitleBar] isMaximized failed:', e))
  }, [appWindow])

  /**
   * 最小化窗口 / Minimize window
   */
  const handleMinimize = async () => {
    try {
      await appWindow.minimize()
    } catch (e) {
      console.error('[TitleBar] Minimize failed:', e)
    }
  }

  /**
   * 最大化/还原窗口 / Maximize / restore window
   */
  const handleMaximize = async () => {
    try {
      await appWindow.toggleMaximize()
      setIsMaximized(!isMaximized)
    } catch (e) {
      console.error('[TitleBar] Toggle maximize failed:', e)
    }
  }

  /**
   * 关闭窗口（最小化到托盘） / Close window (minimize to tray)
   */
  const handleClose = async () => {
    // 点击关闭时最小化到托盘，而不是直接关闭
    // Minimize to tray on close, not actual exit
    try {
      const { invoke } = await import('@tauri-apps/api/core')
      await invoke('minimize_to_tray')
    } catch {
      await appWindow.hide()
    }
  }

  /**
   * 切换主题 / Toggle theme
   */
  const handleToggleTheme = () => {
    const newTheme = themeMode === 'dark' ? 'light' : 'dark'
    setThemeMode(newTheme)
  }

  return (
    <header className={styles.titlebar}>
      <div className={styles.titlebarLeft}>
        <img src="/favicon.ico" alt="AnXin Security" width="18" height="18" className={styles.titlebarIcon} />
        <span className={styles.titlebarText}>AnXin Security</span>
      </div>
      <div className={styles.titlebarRight}>
        <Button
          appearance="subtle"
          icon={themeMode === 'dark' ? <Moon size={16} /> : <Sun size={16} />}
          className={styles.themeToggleBtn}
          onClick={handleToggleTheme}
          title={t('titlebar_toggle_theme')}
        />
        <Button
          appearance="subtle"
          className={styles.titlebarBtn}
          onClick={handleMinimize}
          title={t('titlebar_minimize')}
        >
          <svg width="12" height="12" viewBox="0 0 12 12">
            <line x1="1" y1="6" x2="11" y2="6" stroke="currentColor" strokeWidth="1.2"/>
          </svg>
        </Button>
        <Button
          appearance="subtle"
          className={styles.titlebarBtn}
          onClick={handleMaximize}
          title={isMaximized ? t('titlebar_restore') : t('titlebar_maximize')}
        >
          <svg width="12" height="12" viewBox="0 0 12 12">
            <rect x="1.5" y="1.5" width="9" height="9" stroke="currentColor" strokeWidth="1.2" fill="none"/>
          </svg>
        </Button>
        <Button
          appearance="subtle"
          className={`${styles.titlebarBtn} ${styles.closeBtn}`}
          onClick={handleClose}
          title={t('titlebar_close')}
        >
          <svg width="12" height="12" viewBox="0 0 12 12">
            <line x1="1" y1="1" x2="11" y2="11" stroke="currentColor" strokeWidth="1.2"/>
            <line x1="11" y1="1" x2="1" y2="11" stroke="currentColor" strokeWidth="1.2"/>
          </svg>
        </Button>
      </div>
    </header>
  )
}

export default TitleBar
