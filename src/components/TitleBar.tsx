import React from 'react'
import { Minus, Square, X } from 'lucide-react'
import { getCurrentWindow } from '@tauri-apps/api/window'

const TitleBar: React.FC = () => {
  const appWindow = getCurrentWindow()

  const handleMinimize = async () => {
    await appWindow.minimize()
  }

  const handleMaximize = async () => {
    await appWindow.toggleMaximize()
  }

  const handleClose = async () => {
    await appWindow.close()
  }

  return (
    <header className="titlebar">
      <div className="titlebar-drag-region">
        <span className="titlebar-title">AnXin Security</span>
      </div>
      <div className="titlebar-controls">
        <button className="titlebar-btn" onClick={handleMinimize} title="最小化">
          <Minus size={16} />
        </button>
        <button className="titlebar-btn" onClick={handleMaximize} title="最大化">
          <Square size={14} />
        </button>
        <button className="titlebar-btn titlebar-close" onClick={handleClose} title="关闭">
          <X size={16} />
        </button>
      </div>
    </header>
  )
}

export default TitleBar
