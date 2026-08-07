import {
  Dialog,
  DialogSurface,
  DialogTitle,
  DialogBody,
  DialogContent,
  DialogActions,
  Button,
  Spinner,
  makeStyles,
  tokens,
} from '@fluentui/react-components'
import type { DialogOpenChangeData } from '@fluentui/react-components'
import React from 'react'
import { useI18nStore } from '../../stores/i18nStore'

export interface ConfirmDialogProps {
  open: boolean
  title: string
  message?: string
  confirmText?: string
  cancelText?: string
  intent?: 'danger' | 'warning' | 'info' | 'success'
  onConfirm: () => void
  onCancel: () => void
  loading?: boolean
}

const useStyles = makeStyles({
  surface: {
    maxWidth: '480px',
    borderLeftWidth: '4px',
    borderLeftStyle: 'solid',
    borderLeftColor: tokens.colorBrandStroke1,
  },
  surfaceDanger: {
    borderLeftColor: tokens.colorPaletteRedBorderActive,
  },
  surfaceWarning: {
    borderLeftColor: tokens.colorPaletteYellowBorderActive,
  },
  titleId: {
    /* utility anchor — no styles needed */
  },
  confirmButtonDanger: {
    backgroundColor: tokens.colorPaletteRedBackground3,
    color: tokens.colorNeutralForegroundOnBrand,
    ':hover': {
      backgroundColor: tokens.colorPaletteRedBackground2,
    },
    ':active': {
      backgroundColor: tokens.colorPaletteRedBackground1,
    },
  },
})

const DIALOG_TITLE_ID = 'confirm-dialog-title'

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  open,
  title,
  message,
  confirmText,
  cancelText,
  intent = 'info',
  onConfirm,
  onCancel,
  loading = false,
}) => {
  const styles = useStyles()
  const { t } = useI18nStore()
  const surfaceClassName = [
    styles.surface,
    intent === 'danger' ? styles.surfaceDanger : '',
    intent === 'warning' ? styles.surfaceWarning : '',
  ].filter(Boolean).join(' ')

  if (!open) {
    return null
  }

  const handleOpenChange = (_: unknown, data: DialogOpenChangeData): void => {
    if (!data.open) {
      onCancel()
    }
  }

  const handleConfirm = (): void => {
    if (!loading) {
      onConfirm()
    }
  }

  const handleCancel = (): void => {
    onCancel()
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogSurface
        className={surfaceClassName}
        role="dialog"
        aria-modal="true"
        aria-labelledby={DIALOG_TITLE_ID}
      >
        <DialogTitle id={DIALOG_TITLE_ID}>{title}</DialogTitle>
        <DialogBody>
          <DialogContent>{message}</DialogContent>
        </DialogBody>
        <DialogActions>
          <Button
            appearance="secondary"
            onClick={handleCancel}
          >
            {cancelText ?? t('common_cancel')}
          </Button>
          <Button
            appearance="primary"
            className={intent === 'danger' ? styles.confirmButtonDanger : undefined}
            onClick={handleConfirm}
            disabled={loading}
            icon={loading ? <Spinner size="tiny" /> : undefined}
            iconPosition="after"
          >
            {confirmText ?? t('modal_confirm')}
          </Button>
        </DialogActions>
      </DialogSurface>
    </Dialog>
  )
}
