/**
 * Toast 通知组件
 * Toast notification component
 *
 * 全局 Toast 通知容器，从 useToastStore 读取通知列表并渲染在屏幕右下角。
 * Global toast notification container, reads from useToastStore and renders at bottom-right.
 *
 * 调用方：App.tsx（挂载在根组件中）
 * Called by: App.tsx (mounted in root component)
 *
 * 被调用方：useToastStore（读取 toasts 列表）
 * Calls: useToastStore (reads toasts list)
 *
 * 中文关键词：Toast，通知，消息提示，全局通知，右下角弹窗
 * English keywords: toast, notification, message alert, global notification, bottom-right popup
 */
import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X, Info, CheckCircle, AlertTriangle, AlertOctagon } from 'lucide-react'
import { useToastStore, type ToastType } from '../stores/toastStore'

/** 获取 Toast 图标 / Get toast icon */
const getToastIcon = (type: ToastType) => {
  switch (type) {
    case 'success': return <CheckCircle size={18} />
    case 'warning': return <AlertTriangle size={18} />
    case 'error': return <AlertOctagon size={18} />
    default: return <Info size={18} />
  }
}

const Toast: React.FC = () => {
  const { toasts, removeToast } = useToastStore()

  return (
    <div className="toast-container">
      <AnimatePresence>
        {toasts.map((toast) => (
          <motion.div
            key={toast.id}
            className={`toast-item toast-${toast.type}`}
            initial={{ opacity: 0, x: 80, scale: 0.95 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 80, scale: 0.95 }}
            transition={{ type: 'spring', damping: 25, stiffness: 300 }}
          >
            <span className="toast-icon">{getToastIcon(toast.type)}</span>
            <span className="toast-message">{toast.message}</span>
            <button className="toast-close" onClick={() => removeToast(toast.id)}>
              <X size={14} />
            </button>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  )
}

export default Toast
