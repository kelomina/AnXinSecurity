import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Power, X } from 'lucide-react'
import { listen } from '@tauri-apps/api/event'
import { invoke } from '@tauri-apps/api/core'

interface ExitConfirmation {
  keep_service: boolean
  prompt_enabled: boolean
}

interface TrayExitPromptProps {
  isOpen: boolean
  onClose: () => void
}

const TrayExitPrompt: React.FC<TrayExitPromptProps> = ({ isOpen, onClose }) => {
  const [keepService, setKeepService] = useState<boolean>(true)
  const [isLoading, setIsLoading] = useState<boolean>(false)

  // 监听托盘退出请求事件
  useEffect(() => {
    const unlisten = listen('tray-exit-requested', async () => {
      // 获取退出确认配置
      try {
        const config: ExitConfirmation = await invoke('request_exit_confirmation')
        setKeepService(config.keep_service)
        
        if (config.prompt_enabled) {
          // 显示确认对话框
          onClose() // 先关闭当前状态
          setTimeout(() => onClose(), 0) // 触发重新打开
        } else {
          // 直接执行退出，不显示确认对话框
          await executeExit(config.keep_service)
        }
      } catch (error) {
        console.error('Failed to get exit confirmation:', error)
      }
    })

    return () => {
      unlisten.then(unsubscribe => unsubscribe())
    }
  }, [onClose])

  const executeExit = async (keep: boolean) => {
    try {
      setIsLoading(true)
      await invoke('execute_exit', { keepService: keep })
    } catch (error) {
      console.error('Failed to execute exit:', error)
      setIsLoading(false)
    }
  }

  const handleConfirm = async () => {
    await executeExit(keepService)
  }

  const handleCancel = () => {
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
                    checked={keepService}
                    onChange={(e) => setKeepService(e.target.checked)}
                    disabled={isLoading}
                    style={{ width: '16px', height: '16px', cursor: 'pointer' }}
                  />
                  <span>保持扫描引擎服务运行</span>
                </label>
                <p className="option-description" style={{ 
                  fontSize: '12px', 
                  color: '#6b7280', 
                  marginLeft: '24px',
                  marginTop: '4px'
                }}>
                  {keepService 
                    ? '扫描引擎将继续在后台运行，提供实时保护' 
                    : '扫描引擎将完全停止，系统将不再受保护'}
                </p>
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
                className="btn btn-primary" 
                onClick={handleConfirm}
                disabled={isLoading}
                style={{ backgroundColor: '#ef4444', borderColor: '#ef4444' }}
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
