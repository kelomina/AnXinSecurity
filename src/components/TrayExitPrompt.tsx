/**
 * 托盘退出确认弹窗
 * Tray exit confirmation prompt
 *
 * 监听 tray-exit-requested 事件，显示退出确认对话框。
 * 用户必须勾选"我确认要退出AnXin Security"后方可点击确认退出按钮。
 * Listens for tray-exit-requested event and displays exit confirmation dialog.
 * User must check "I confirm to exit AnXin Security" to enable the confirm button.
 *
 * 调用方：App.tsx（由 tray-exit-requested 事件触发 isOpen）
 * Called by: App.tsx (triggered via tray-exit-requested event setting isOpen)
 *
 * 中文关键词：托盘退出，退出确认，确认勾选，退出弹窗
 * English keywords: tray exit, exit confirmation, confirm checkbox, exit prompt
 */
import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Power, X } from 'lucide-react'
import { invoke } from '@tauri-apps/api/core'

interface TrayExitPromptProps {
  isOpen: boolean
  onClose: () => void
}

const TrayExitPrompt: React.FC<TrayExitPromptProps> = ({ isOpen, onClose }) => {
  const [confirmed, setConfirmed] = useState<boolean>(false)
  const [isLoading, setIsLoading] = useState<boolean>(false)

  const handleConfirm = async () => {
    try {
      setIsLoading(true)
      await invoke('execute_exit', { keepService: false })
    } catch (error) {
      console.error('Failed to execute exit:', error)
      setIsLoading(false)
    }
  }

  const handleCancel = () => {
    setConfirmed(false)
    onClose()
  }

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          className="modal-overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={handleCancel}
        >
          <motion.div
            className="modal-surface"
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.95, opacity: 0 }}
            transition={{ type: 'spring', damping: 25, stiffness: 300 }}
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: '420px' }}
          >
            <div className="modal-header">
              <div className="modal-icon" style={{ color: '#ef4444' }}>
                <Power size={24} />
              </div>
              <h3>退出应用</h3>
              <button className="modal-close" onClick={handleCancel} disabled={isLoading}>
                <X size={18} />
              </button>
            </div>

            <div className="modal-body">
              <p className="modal-message">
                确定要退出 AnXin Security 吗？
              </p>

              <div className="exit-options" style={{ marginTop: '16px' }}>
                <label className="checkbox-label" style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={confirmed}
                    onChange={(e) => setConfirmed(e.target.checked)}
                    disabled={isLoading}
                    style={{ width: '16px', height: '16px', cursor: 'pointer' }}
                  />
                  <span>我确认要退出 AnXin Security</span>
                </label>
              </div>
            </div>

            <div className="modal-actions" style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
              <button
                className="btn btn-outline-secondary"
                onClick={handleCancel}
                disabled={isLoading}
              >
                取消
              </button>
              <button
                className="btn btn-danger"
                onClick={handleConfirm}
                disabled={!confirmed || isLoading}
              >
                {isLoading ? '退出中...' : '确认退出'}
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

export default TrayExitPrompt
