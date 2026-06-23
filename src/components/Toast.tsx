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
import {
  makeStyles,
  shorthands,
  tokens,
} from '@fluentui/react-components'

const useStyles = makeStyles({
  toastContainer: {
    position: 'fixed',
    bottom: '24px',
    right: '24px',
    zIndex: 10000,
    display: 'flex',
    flexDirection: 'column',
    ...shorthands.gap('8px'),
    maxWidth: '380px',
    WebkitAppRegion: 'no-drag',
  },
  toastItem: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('10px'),
    ...shorthands.padding('12px', '16px'),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    boxShadow: tokens.shadow16,
    backdropFilter: 'blur(20px)',
    fontSize: tokens.fontSizeBase300,
  },
  toastIcon: {
    flexShrink: 0,
    display: 'flex',
    alignItems: 'center',
  },
  toastIconInfo: {
    color: tokens.colorPaletteBlueForeground2,
  },
  toastIconSuccess: {
    color: tokens.colorPaletteGreenForeground2,
  },
  toastIconWarning: {
    color: tokens.colorPaletteYellowForeground2,
  },
  toastIconError: {
    color: tokens.colorPaletteRedForeground2,
  },
  toastMessage: {
    flex: 1,
    color: tokens.colorNeutralForeground1,
  },
  toastClose: {
    flexShrink: 0,
    width: '24px',
    height: '24px',
    ...shorthands.border('none'),
    background: 'transparent',
    color: tokens.colorNeutralForeground3,
    cursor: 'pointer',
    ...shorthands.borderRadius(tokens.borderRadiusSmall),
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    transitionProperty: 'background',
    transitionDuration: tokens.durationNormal,
    ':hover': {
      backgroundColor: tokens.colorNeutralBackground1Hover,
      color: tokens.colorNeutralForeground1,
    },
  },
})

/** 获取 Toast 图标 / Get toast icon */
const getToastIcon = (type: ToastType) => {
  switch (type) {
    case 'success': return <CheckCircle size={18} />
    case 'warning': return <AlertTriangle size={18} />
    case 'error': return <AlertOctagon size={18} />
    default: return <Info size={18} />
  }
}

/** 获取图标样式类 / Get icon style class */
const getToastIconClass = (type: ToastType, styles: ReturnType<typeof useStyles>) => {
  switch (type) {
    case 'success': return styles.toastIconSuccess
    case 'warning': return styles.toastIconWarning
    case 'error': return styles.toastIconError
    default: return styles.toastIconInfo
  }
}

const Toast: React.FC = () => {
  const { toasts, removeToast } = useToastStore()
  const styles = useStyles()

  return (
    <div className={styles.toastContainer}>
      <AnimatePresence>
        {toasts.map((toast) => (
          <motion.div
            key={toast.id}
            className={styles.toastItem}
            initial={{ opacity: 0, x: 80, scale: 0.95 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 80, scale: 0.95 }}
            transition={{ type: 'spring', damping: 25, stiffness: 300 }}
          >
            <span className={`${styles.toastIcon} ${getToastIconClass(toast.type, styles)}`}>
              {getToastIcon(toast.type)}
            </span>
            <span className={styles.toastMessage}>{toast.message}</span>
            <button
              className={styles.toastClose}
              onClick={() => removeToast(toast.id)}
              aria-label="Close notification"
            >
              <X size={14} />
            </button>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  )
}

export default Toast
