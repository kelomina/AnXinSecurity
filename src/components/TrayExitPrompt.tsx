/**
 * 托盘退出确认弹窗
 * Tray exit confirmation prompt
 *
 * 调用方：App.tsx（由 tray-exit-requested 事件触发 isOpen）
 * Called by: App.tsx (triggered via tray-exit-requested event setting isOpen)
 */
import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Power } from 'lucide-react'
import { invoke } from '@tauri-apps/api/core'
import { useI18nStore } from '../stores/i18nStore'
import {
  Button,
  Checkbox,
  makeStyles,
  shorthands,
  tokens,
} from '@fluentui/react-components'

const useStyles = makeStyles({
  overlay: {
    position: 'fixed',
    inset: 0,
    backgroundColor: 'rgba(0,0,0,0.5)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 9999,
    backdropFilter: 'blur(4px)',
  },
  surface: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    boxShadow: tokens.shadow28,
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
  body: {
    ...shorthands.padding('16px', '24px'),
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

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          className={styles.overlay}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={handleCancel}
        >
          <motion.div
            className={styles.surface}
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.95, opacity: 0 }}
            transition={{ type: 'spring', damping: 25, stiffness: 300 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className={styles.header}>
              <div className={styles.iconWrap}>
                <Power size={20} />
              </div>
              <span className={styles.title}>{t('tray_exit_title')}</span>
            </div>

            <div className={styles.body}>
              <p className={styles.message}>{t('tray_exit_message')}</p>
              <Checkbox
                checked={confirmed}
                onChange={(_, data) => setConfirmed(!!data.checked)}
                disabled={isLoading}
                label={t('tray_exit_confirm_label')}
              />
            </div>

            <div className={styles.actions}>
              <Button appearance="secondary" onClick={handleCancel} disabled={isLoading}>
                {t('tray_exit_cancel')}
              </Button>
              <Button
                appearance="primary"
                onClick={handleConfirm}
                disabled={!confirmed || isLoading}
                style={{ backgroundColor: tokens.colorPaletteRedBackground3, color: '#fff' }}
              >
                {isLoading ? t('tray_exit_exiting') : t('tray_exit_confirm_btn')}
              </Button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

export default TrayExitPrompt
