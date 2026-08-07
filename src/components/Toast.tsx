/**
 * Toast 通知组件
 * Toast notification component
 *
 * 保持 useToastStore 调用入口不变，渲染层使用 Fluent UI React v9 的
 * Toaster / useToastController / Toast 组件。
 */
import React from 'react'
import {
  Button,
  Toast as FluentToast,
  ToastBody,
  ToastTitle,
  ToastTrigger,
  Toaster,
  useToastController,
} from '@fluentui/react-components'
import { X } from './icons'
import { useToastStore, type ToastType } from '../stores/toastStore'
import { useI18nStore } from '../stores/i18nStore'

const TOASTER_ID = 'anxin-global-toaster'

type ToastIntent = 'info' | 'success' | 'warning' | 'error'

const getToastIntent = (type: ToastType): ToastIntent => {
  switch (type) {
    case 'success': return 'success'
    case 'warning': return 'warning'
    case 'error': return 'error'
    default: return 'info'
  }
}

const ToastDispatcher: React.FC = () => {
  const toasts = useToastStore((state) => state.toasts)
  const removeToast = useToastStore((state) => state.removeToast)
  const { t } = useI18nStore()
  const { dispatchToast, dismissToast } = useToastController(TOASTER_ID)
  const dispatchedIds = React.useRef(new Set<string>())

  React.useEffect(() => {
    const activeIds = new Set(toasts.map((toast) => toast.id))

    toasts.forEach((toast) => {
      if (dispatchedIds.current.has(toast.id)) return

      dispatchedIds.current.add(toast.id)
      dispatchToast(
        <FluentToast>
          <ToastTitle
            action={
              <ToastTrigger>
                <Button
                  appearance="transparent"
                  size="small"
                  icon={<X size={14} />}
                  aria-label={t('toast_close_notification')}
                  onClick={() => removeToast(toast.id)}
                />
              </ToastTrigger>
            }
          >
            {toast.message}
          </ToastTitle>
          <ToastBody />
        </FluentToast>,
        {
          toastId: toast.id,
          intent: getToastIntent(toast.type),
          timeout: toast.duration ?? 4000,
          onStatusChange: (_, data) => {
            if (data.status === 'dismissed' || data.status === 'unmounted') {
              dispatchedIds.current.delete(toast.id)
              removeToast(toast.id)
            }
          },
        },
      )
    })

    dispatchedIds.current.forEach((id) => {
      if (!activeIds.has(id)) {
        dismissToast(id)
        dispatchedIds.current.delete(id)
      }
    })
  }, [dismissToast, dispatchToast, removeToast, t, toasts])

  return null
}

const Toast: React.FC = () => (
  <>
    <Toaster toasterId={TOASTER_ID} position="bottom-end" pauseOnHover pauseOnWindowBlur />
    <ToastDispatcher />
  </>
)

export default Toast
