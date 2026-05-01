/**
 * Toast 通知状态管理 Store
 * Toast notification state management store
 *
 * 管理全局 Toast 通知的添加、移除和生命周期。
 * Manages global Toast notification add, remove, and lifecycle.
 */
import { create } from 'zustand'

/** Toast 类型/Toast type */
export type ToastType = 'info' | 'success' | 'warning' | 'error'

/** Toast 消息项/Toast message item */
export interface ToastItem {
  id: string
  type: ToastType
  message: string
  duration?: number
}

/** Toast 状态接口/Toast state interface */
interface ToastState {
  toasts: ToastItem[]
  /**
   * 函数名称：addToast
   * 函数作用：添加一条 Toast 通知，自动在 duration 毫秒后移除。
   * Purpose: Adds a toast notification, auto-removes after duration ms.
   * 参数：type — 通知类型 / message — 消息内容 / duration — 显示时长(ms)，默认 4000
   * 调用方：任意组件通过 useToastStore 调用
   * 中文关键词：通知，Toast，消息提示，弹窗消息
   * English keywords: notification, toast, message alert, popup message
   */
  addToast: (type: ToastType, message: string, duration?: number) => void
  /**
   * 函数名称：removeToast
   * 函数作用：移除指定 ID 的 Toast 通知。
   * Purpose: Removes a toast notification by ID.
   * 调用方：Toast 组件自动调用 / 手动关闭
   * Called by: Toast component auto-call / manual dismiss
   * 中文关键词：移除通知，关闭Toast，清除消息
   * English keywords: remove notification, dismiss toast, clear message
   */
  removeToast: (id: string) => void
}

export const useToastStore = create<ToastState>((set) => ({
  toasts: [],

  addToast: (type, message, duration = 4000) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`
    set((state) => ({
      toasts: [...state.toasts, { id, type, message, duration }],
    }))

    if (duration > 0) {
      setTimeout(() => {
        set((state) => ({
          toasts: state.toasts.filter((t) => t.id !== id),
        }))
      }, duration)
    }
  },

  removeToast: (id) => {
    set((state) => ({
      toasts: state.toasts.filter((t) => t.id !== id),
    }))
  },
}))
