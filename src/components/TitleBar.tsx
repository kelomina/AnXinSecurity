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
import { Maximize2, Minus, X } from './icons'
import { getCurrentWindow } from '@tauri-apps/api/window'
import { useI18nStore } from '../stores/i18nStore'
import { Button, makeStyles, shorthands, tokens } from '@fluentui/react-components'

const useStyles = makeStyles({
  titlebar: {
    gridColumn: '1 / -1',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    height: '32px',
    ...shorthands.padding('0', '8px', '0', '12px'),
    backgroundColor: tokens.colorNeutralBackground1,
    WebkitAppRegion: 'drag',
    userSelect: 'none',
    ...shorthands.borderBottom('1px', 'solid', tokens.colorNeutralStroke1),
  },
  titlebarLeft: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('8px'),
  },
  titlebarIcon: {
    flexShrink: 0,
  },
  titlebarText: {
    fontSize: '12px',
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
    width: '46px',
    height: '32px',
    minWidth: '46px',
    ...shorthands.borderRadius('0'),
    ...shorthands.padding('0'),
    ':hover': {
      backgroundColor: tokens.colorNeutralBackground1Hover,
    },
  },
  closeBtn: {
    ':hover': {
      backgroundColor: tokens.colorStatusDangerForeground2,
      color: tokens.colorNeutralForegroundOnBrand,
    },
  },
})

const TitleBar: React.FC = () => {
  const appWindow = getCurrentWindow()
  const [isMaximized, setIsMaximized] = useState(false)
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
   * 关闭窗口 = 退出 Main 进程（拆分架构）
   * Close window = exit the Main process (split architecture)
   *
   * 后台防护由独立服务进程承担，托盘进程继续驻留；关闭主界面不影响防护。
   * Background protection is owned by the dedicated service process and the tray
   * process stays resident; closing the main window does not affect protection.
   */
  const handleClose = async () => {
    try {
      const { invoke } = await import('@tauri-apps/api/core')
      await invoke('close_main_window')
    } catch {
      await appWindow.hide()
    }
  }

  return (
    <header className={styles.titlebar}>
      <div className={styles.titlebarLeft}>
        <img src="/favicon.ico" alt="AnXin Security" width="16" height="16" className={styles.titlebarIcon} />
        <span className={styles.titlebarText}>AnXin Security</span>
      </div>
      <div className={styles.titlebarRight}>
        <Button
          appearance="subtle"
          icon={<Minus size={14} />}
          className={styles.titlebarBtn}
          onClick={handleMinimize}
          title={t('titlebar_minimize')}
          aria-label={t('titlebar_minimize')}
        />
        <Button
          appearance="subtle"
          icon={<Maximize2 size={13} />}
          className={styles.titlebarBtn}
          onClick={handleMaximize}
          title={isMaximized ? t('titlebar_restore') : t('titlebar_maximize')}
          aria-label={isMaximized ? t('titlebar_restore') : t('titlebar_maximize')}
        />
        <Button
          appearance="subtle"
          icon={<X size={14} />}
          className={`${styles.titlebarBtn} ${styles.closeBtn}`}
          onClick={handleClose}
          title={t('titlebar_close')}
          aria-label={t('titlebar_close')}
        />
      </div>
    </header>
  )
}

export default TitleBar
