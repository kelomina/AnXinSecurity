/**
 * 托盘退出确认弹窗
 * Tray exit confirmation prompt
 *
 * 调用方：App.tsx（由 tray-exit-requested 事件触发 isOpen）
 * Called by: App.tsx (triggered via tray-exit-requested event setting isOpen)
 */
import React, { useState } from 'react'
import { Power } from './icons'
import { invoke } from '@tauri-apps/api/core'
import { useI18nStore } from '../stores/i18nStore'
import {
  Button,
  Checkbox,
  Dialog,
  DialogSurface,
  DialogTitle,
  DialogBody,
  DialogContent,
  DialogActions,
  makeStyles,
  shorthands,
  tokens,
} from '@fluentui/react-components'
import type { DialogOpenChangeData } from '@fluentui/react-components'

const useStyles = makeStyles({
  surface: {
    width: '420px',
    maxWidth: '90vw',
    overflow: 'hidden',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('12px'),
    ...shorthands.padding('20px', '24px', '16px'),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  iconWrap: {
    width: '40px',
    height: '40px',
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    backgroundColor: tokens.colorPaletteRedBackground2,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: 0,
    color: tokens.colorPaletteRedForeground2,
  },
  title: {
    fontSize: tokens.fontSizeBase400,
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground1,
    flex: 1,
  },
  message: {
    fontSize: tokens.fontSizeBase300,
    color: tokens.colorNeutralForeground2,
    marginBottom: '16px',
    lineHeight: tokens.lineHeightBase300,
  },
  actions: {
    display: 'flex',
    justifyContent: 'flex-end',
    ...shorthands.gap('8px'),
    ...shorthands.padding('12px', '24px', '20px'),
    borderTop: `1px solid ${tokens.colorNeutralStroke1}`,
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

interface TrayExitPromptProps {
  isOpen: boolean
  onClose: () => void
}

const TrayExitPrompt: React.FC<TrayExitPromptProps> = ({ isOpen, onClose }) => {
  const { t } = useI18nStore()
  const styles = useStyles()
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

  const handleOpenChange = (_: unknown, data: DialogOpenChangeData): void => {
    if (!data.open) {
      handleCancel()
    }
  }

  return (
    <Dialog open={isOpen} onOpenChange={handleOpenChange}>
      <DialogSurface
        className={styles.surface}
        role="dialog"
        aria-modal="true"
        aria-labelledby="tray-exit-prompt-title"
      >
        <div className={styles.header}>
          <div className={styles.iconWrap}>
            <Power size={20} />
          </div>
          <DialogTitle id="tray-exit-prompt-title" className={styles.title}>
            {t('tray_exit_title')}
          </DialogTitle>
        </div>

        <DialogBody>
          <DialogContent>
            <p className={styles.message}>{t('tray_exit_message')}</p>
            <Checkbox
              checked={confirmed}
              onChange={(_, data) => setConfirmed(!!data.checked)}
              disabled={isLoading}
              label={t('tray_exit_confirm_label')}
            />
          </DialogContent>
        </DialogBody>

        <DialogActions className={styles.actions}>
          <Button appearance="secondary" onClick={handleCancel} disabled={isLoading}>
            {t('tray_exit_cancel')}
          </Button>
          <Button
            appearance="primary"
            className={styles.confirmButtonDanger}
            onClick={handleConfirm}
            disabled={!confirmed || isLoading}
          >
            {isLoading ? t('tray_exit_exiting') : t('tray_exit_confirm_btn')}
          </Button>
        </DialogActions>
      </DialogSurface>
    </Dialog>
  )
}

export default TrayExitPrompt
