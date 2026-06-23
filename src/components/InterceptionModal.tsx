import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertOctagon, AlertTriangle, ShieldOff, X } from 'lucide-react'
import { useI18nStore } from '../stores/i18nStore'
import {
  Button,
  makeStyles,
  shorthands,
  tokens,
} from '@fluentui/react-components'

interface InterceptionModalProps {
  isOpen: boolean
  onClose: () => void
  onAllow: () => void
  onBlock: () => void
  title: string
  message: string
  processName: string
  riskLevel: 'high' | 'medium' | 'low'
  filePath?: string
  mode?: 'modal' | 'window'
  defaultAction?: 'allow' | 'block'
  remainingSeconds?: number
  autoDecisionSeconds?: number
  decisionPending?: boolean
}

const useStyles = makeStyles({
  overlay: {
    position: 'fixed',
    inset: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.6)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 9999,
    backdropFilter: 'blur(8px)',
  },
  overlayWindow: {
    backgroundColor: 'rgba(8, 11, 16, 0.95)',
  },
  surface: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    ...shorthands.border('1px', 'solid'),
    boxShadow: tokens.shadow64,
    maxWidth: '560px',
    width: '90vw',
    overflow: 'hidden',
    position: 'relative',
  },
  surfaceWindow: {
    maxWidth: 'none',
    width: '100%',
    minHeight: '100%',
    ...shorthands.borderRadius('0'),
  },
  alertStrip: {
    height: '4px',
    width: '100%',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('12px'),
    ...shorthands.padding('20px', '24px'),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    position: 'relative',
  },
  headerDraggable: {
    WebkitAppRegion: 'drag',
    userSelect: 'none',
  },
  iconWrapper: {
    width: '48px',
    height: '48px',
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: 0,
  },
  titleGroup: {
    flex: 1,
  },
  eyebrow: {
    fontSize: tokens.fontSizeBase200,
    fontWeight: tokens.fontWeightSemibold,
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    marginBottom: '4px',
  },
  title: {
    fontSize: tokens.fontSizeBase400,
    fontWeight: tokens.fontWeightSemibold,
    margin: 0,
  },
  countdown: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-end',
    ...shorthands.gap('2px'),
    fontSize: tokens.fontSizeBase200,
  },
  countdownLabel: {
    color: tokens.colorNeutralForeground3,
  },
  countdownAction: {
    fontWeight: tokens.fontWeightSemibold,
  },
  countdownTime: {
    fontSize: tokens.fontSizeBase300,
    fontWeight: tokens.fontWeightBold,
    fontFamily: 'Consolas, "Courier New", monospace',
  },
  closeButton: {
    position: 'absolute',
    top: '12px',
    right: '12px',
    width: '32px',
    height: '32px',
    minWidth: '32px',
    ...shorthands.padding('0'),
    ...shorthands.border('none'),
    backgroundColor: 'transparent',
    color: tokens.colorNeutralForeground3,
    cursor: 'pointer',
    ...shorthands.borderRadius(tokens.borderRadiusSmall),
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    WebkitAppRegion: 'no-drag',
    ':hover': {
      backgroundColor: tokens.colorNeutralBackground1Hover,
      color: tokens.colorNeutralForeground1,
    },
  },
  body: {
    ...shorthands.padding('20px', '24px'),
  },
  message: {
    fontSize: tokens.fontSizeBase300,
    color: tokens.colorNeutralForeground2,
    marginTop: 0,
    marginBottom: '16px',
    lineHeight: tokens.lineHeightBase300,
  },
  detailPanel: {
    ...shorthands.padding('16px'),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.border('1px', 'solid'),
    marginBottom: '16px',
  },
  detail: {
    display: 'flex',
    ...shorthands.gap('8px'),
    marginBottom: '8px',
    fontSize: tokens.fontSizeBase300,
    ':last-child': {
      marginBottom: 0,
    },
  },
  detailLabel: {
    color: tokens.colorNeutralForeground3,
    flexShrink: 0,
  },
  detailValue: {
    color: tokens.colorNeutralForeground1,
    fontFamily: 'Consolas, "Courier New", monospace',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  riskBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    ...shorthands.gap('6px'),
    marginTop: '4px',
    ...shorthands.padding('4px', '12px'),
    ...shorthands.borderRadius(tokens.borderRadiusCircular),
    fontSize: tokens.fontSizeBase200,
    fontWeight: tokens.fontWeightSemibold,
  },
  timeoutTrack: {
    height: '3px',
    width: '100%',
    backgroundColor: tokens.colorNeutralBackground3,
    position: 'relative',
    overflow: 'hidden',
  },
  timeoutBar: {
    height: '100%',
    transitionProperty: 'width',
    transitionDuration: '1s',
    transitionTimingFunction: 'linear',
  },
  actions: {
    display: 'flex',
    ...shorthands.gap('12px'),
    justifyContent: 'flex-end',
    ...shorthands.padding('16px', '24px'),
    borderTop: `1px solid ${tokens.colorNeutralStroke1}`,
  },
})

const InterceptionModal: React.FC<InterceptionModalProps> = ({
  isOpen,
  onClose,
  onAllow,
  onBlock,
  title,
  message,
  processName,
  riskLevel,
  filePath,
  mode = 'modal',
  defaultAction = 'block',
  remainingSeconds,
  autoDecisionSeconds,
  decisionPending = false
}) => {
  const { t } = useI18nStore()
  const styles = useStyles()

  const riskColors = {
    high: {
      bg: tokens.colorPaletteRedBackground2,
      text: tokens.colorPaletteRedForeground2,
      border: tokens.colorPaletteRedBorder2,
      label: t('intercept_level_high', '高')
    },
    medium: {
      bg: tokens.colorPaletteYellowBackground2,
      text: tokens.colorPaletteYellowForeground2,
      border: tokens.colorPaletteYellowBorder2,
      label: t('intercept_level_medium', '中')
    },
    low: {
      bg: tokens.colorPaletteBlueBackground2,
      text: tokens.colorPaletteBlueForeground2,
      border: tokens.colorPaletteYellowBorder2, // Using yellow as blue border2 doesn't exist
      label: t('intercept_level_low', '低')
    },
  }

  const riskStyle = riskColors[riskLevel]
  const isWindowMode = mode === 'window'
  const showAutoDecision = isWindowMode && typeof remainingSeconds === 'number'
  const autoDecisionLabel = defaultAction === 'block'
    ? t('intercept_btn_block_process', '阻止进程')
    : t('intercept_btn_allow_run', '允许运行')

  const surfaceMotion = isWindowMode
    ? {
      initial: { y: 8, opacity: 0 },
      animate: { y: 0, opacity: 1 },
      exit: { y: 8, opacity: 0 },
    }
    : {
      initial: { scale: 0.95, opacity: 0 },
      animate: { scale: 1, opacity: 1 },
      exit: { scale: 0.95, opacity: 0 },
    }

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          className={`${styles.overlay} ${isWindowMode ? styles.overlayWindow : ''}`}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={isWindowMode ? undefined : onClose}
        >
          <motion.div
            className={`${styles.surface} ${isWindowMode ? styles.surfaceWindow : ''}`}
            initial={surfaceMotion.initial}
            animate={surfaceMotion.animate}
            exit={surfaceMotion.exit}
            transition={{ type: 'spring', damping: 25, stiffness: 300 }}
            onClick={(e) => e.stopPropagation()}
            style={{
              borderColor: riskStyle.border,
              boxShadow: isWindowMode
                ? `inset 0 0 0 1px ${riskStyle.border}, 0 0 42px ${riskStyle.border}`
                : `0 0 0 1px ${riskStyle.border}, 0 24px 60px rgba(0,0,0,0.38), 0 0 48px ${riskStyle.border}`
            }}
          >
            <div className={styles.alertStrip} style={{ backgroundColor: riskStyle.text }} />

            <div
              className={`${styles.header} ${isWindowMode ? styles.headerDraggable : ''}`}
              data-tauri-drag-region={isWindowMode ? true : undefined}
            >
              <div className={styles.iconWrapper} style={{ backgroundColor: riskStyle.bg }}>
                {riskLevel === 'high' ? (
                  <ShieldOff size={26} color={riskStyle.text} />
                ) : riskLevel === 'medium' ? (
                  <AlertOctagon size={26} color={riskStyle.text} />
                ) : (
                  <AlertTriangle size={26} color={riskStyle.text} />
                )}
              </div>
              <div className={styles.titleGroup}>
                <div className={styles.eyebrow} style={{ color: riskStyle.text }}>
                  {t('intercept_security_alert', '安全拦截警报')}
                </div>
                <h3 className={styles.title} style={{ color: riskStyle.text }}>{title}</h3>
              </div>
              {showAutoDecision && (
                <div className={styles.countdown} title={t('intercept_default_action_hint', '超时后将自动执行默认操作')}>
                  <span className={styles.countdownLabel}>
                    {t('intercept_default_action_label', '默认')}
                  </span>
                  <span className={styles.countdownAction}>{autoDecisionLabel}</span>
                  <span className={styles.countdownTime} style={{ color: riskStyle.text }}>
                    {t('intercept_auto_block_countdown', '{seconds}s').replace('{seconds}', String(remainingSeconds))}
                  </span>
                </div>
              )}
              {mode !== 'window' && (
                <button className={styles.closeButton} onClick={onClose}>
                  <X size={18} />
                </button>
              )}
            </div>

            <div className={styles.body}>
              <p className={styles.message}>{message}</p>

              <div
                className={styles.detailPanel}
                style={{
                  borderColor: riskStyle.border,
                  backgroundColor: riskStyle.bg
                }}
              >
                <div className={styles.detail}>
                  <span className={styles.detailLabel}>{t('intercept_label_process', '进程：')}</span>
                  <span className={styles.detailValue} style={{ fontWeight: 600 }} title={processName}>
                    {processName}
                  </span>
                </div>
                {filePath && (
                  <div className={styles.detail}>
                    <span className={styles.detailLabel}>{t('intercept_label_path', '路径：')}</span>
                    <span className={styles.detailValue} title={filePath}>
                      {filePath}
                    </span>
                  </div>
                )}
                <div className={styles.riskBadge} style={{
                  backgroundColor: riskStyle.bg,
                  color: riskStyle.text,
                  border: `1px solid ${riskStyle.border}`,
                }}>
                  <AlertTriangle size={13} />
                  {riskStyle.label}
                </div>
              </div>
            </div>

            {showAutoDecision && typeof autoDecisionSeconds === 'number' && autoDecisionSeconds > 0 && (
              <div className={styles.timeoutTrack}>
                <div
                  className={styles.timeoutBar}
                  style={{
                    width: `${Math.max(0, Math.min(100, (remainingSeconds / autoDecisionSeconds) * 100))}%`,
                    backgroundColor: riskStyle.text
                  }}
                />
              </div>
            )}

            <div className={styles.actions}>
              <Button
                appearance="outline"
                onClick={onAllow}
                disabled={decisionPending}
              >
                {t('intercept_btn_allow_run', '允许运行')}
              </Button>
              <Button
                appearance="primary"
                onClick={onBlock}
                disabled={decisionPending}
                autoFocus={defaultAction === 'block'}
                style={{
                  backgroundColor: riskStyle.text,
                  borderColor: riskStyle.text,
                  boxShadow: `0 0 20px ${riskStyle.border}`
                }}
              >
                {decisionPending
                  ? t('intercept_btn_processing', '处理中...')
                  : t('intercept_btn_block_process', '阻止进程')}
              </Button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

export default InterceptionModal
