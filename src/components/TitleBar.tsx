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
import { Minus, Square, Maximize, X } from 'lucide-react'
import { getCurrentWindow } from '@tauri-apps/api/window'

const TitleBar: React.FC = () => {
  const appWindow = getCurrentWindow()
  const [isMaximized, setIsMaximized] = useState(false)

  /**
   * 初始化：检查窗口是否已最大化
   * Init: check if window is currently maximized
   */
  useEffect(() => {
    appWindow.isMaximized().then(setIsMaximized).catch(() => {})
  }, [appWindow])

  /**
   * 最小化窗口 / Minimize window
   */
  const handleMinimize = async () => {
    await appWindow.minimize()
  }

  /**
   * 最大化/还原窗口 / Maximize / restore window
   */
  const handleMaximize = async () => {
    await appWindow.toggleMaximize()
    setIsMaximized(!isMaximized)
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

  return (
    <header className="titlebar">
      <div className="titlebar-drag-region">
        <span className="titlebar-title">AnXin Security</span>
      </div>
      <div className="titlebar-controls">
        <button className="titlebar-btn" onClick={handleMinimize} title="最小化/Minimize">
          <Minus size={16} />
        </button>
        <button className="titlebar-btn" onClick={handleMaximize} title={isMaximized ? '还原/Restore' : '最大化/Maximize'}>
          {isMaximized ? <Maximize size={14} /> : <Square size={14} />}
        </button>
        <button className="titlebar-btn titlebar-close" onClick={handleClose} title="关闭/Close">
          <X size={16} />
        </button>
      </div>
    </header>
  )
}

export default TitleBar
