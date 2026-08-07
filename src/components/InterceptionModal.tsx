import React from 'react'
import { AlertOctagon, AlertTriangle, ShieldOff, X } from './icons'
import { useI18nStore } from '../stores/i18nStore'
import {
  Dialog,
  DialogSurface,
  DialogTitle,
  DialogBody,
  DialogContent,
  DialogActions,
  Button,
  ProgressBar,
  makeStyles,
  shorthands,
  tokens,
} from '@fluentui/react-components'
import type { DialogOpenChangeData } from '@fluentui/react-components'

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
  /**
   * 按钮上方的附加控件，网络连接询问用它放"记住此选择"。
   * 可选，进程拦截路径不传，行为完全不变。
   * Extra control rendered above the buttons; the network prompt uses it for
   * "remember this choice". Optional — the process-interception path omits it and
   * behaves exactly as before.
   */
  extraControl?: React.ReactNode
  /** 覆盖放行按钮文案 / Overrides the allow button label */
  allowLabel?: string
  /** 覆盖阻止按钮文案 / Overrides the block button label */
  blockLabel?: string
}

const DIALOG_TITLE_ID = 'interception-modal-title'

const useStyles = makeStyles({
  surface: {
    maxWidth: '560px',
    width: '90vw',
  },
  surfaceWindowFull: {
    maxWidth: '100%',
    width: '100%',
    height: '100%',
    maxHeight: '100%',
    borderRadius: '0',
    border: 'none',
    boxShadow: 'none',
  },
  alertStrip: {
    height: '4px',
    width: '100%',
  },
  alertStripHigh: {
    backgroundColor: tokens.colorPaletteRedForeground2,
  },
  alertStripMedium: {
    backgroundColor: tokens.colorPaletteYellowForeground2,
  },
  alertStripLow: {
    backgroundColor: tokens.colorPaletteBlueForeground2,
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
  iconWrapperHigh: {
    backgroundColor: tokens.colorPaletteRedBackground2,
    color: tokens.colorPaletteRedForeground2,
  },
  iconWrapperMedium: {
    backgroundColor: tokens.colorPaletteYellowBackground2,
    color: tokens.colorPaletteYellowForeground2,
  },
  iconWrapperLow: {
    backgroundColor: tokens.colorPaletteBlueBackground2,
    color: tokens.colorPaletteBlueForeground2,
  },
  titleGroup: {
    flex: 1,
  },
  eyebrow: {
    fontSize: tokens.fontSizeBase200,
    fontWeight: tokens.fontWeightSemibold,
    textTransform: 'uppercase',
    letterSpacing: 0,
    marginBottom: '4px',
  },
  eyebrowHigh: {
    color: tokens.colorPaletteRedForeground2,
  },
  eyebrowMedium: {
    color: tokens.colorPaletteYellowForeground2,
  },
  eyebrowLow: {
    color: tokens.colorPaletteBlueForeground2,
  },
  title: {
    fontSize: tokens.fontSizeBase400,
    fontWeight: tokens.fontWeightSemibold,
    margin: 0,
  },
  titleHigh: {
    color: tokens.colorPaletteRedForeground2,
  },
  titleMedium: {
    color: tokens.colorPaletteYellowForeground2,
  },
  titleLow: {
    color: tokens.colorPaletteBlueForeground2,
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
  countdownTimeHigh: {
    color: tokens.colorPaletteRedForeground2,
  },
  countdownTimeMedium: {
    color: tokens.colorPaletteYellowForeground2,
  },
  countdownTimeLow: {
    color: tokens.colorPaletteBlueForeground2,
  },
  closeButton: {
    position: 'absolute',
    top: '12px',
    right: '12px',
    width: '32px',
    height: '32px',
    minWidth: '32px',
    ...shorthands.padding('0'),
    ...shorthands.borderRadius(tokens.borderRadiusSmall),
    WebkitAppRegion: 'no-drag',
  },
  detailPanel: {
    ...shorthands.padding('16px'),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.border('1px', 'solid'),
    marginBottom: '16px',
  },
  detailPanelHigh: {
    ...shorthands.borderColor(tokens.colorPaletteRedBorder2),
    backgroundColor: tokens.colorPaletteRedBackground2,
  },
  detailPanelMedium: {
    ...shorthands.borderColor(tokens.colorPaletteYellowBorder2),
    backgroundColor: tokens.colorPaletteYellowBackground2,
  },
  detailPanelLow: {
    ...shorthands.borderColor(tokens.colorPaletteYellowBorder2),
    backgroundColor: tokens.colorPaletteBlueBackground2,
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
  processValue: {
    fontWeight: tokens.fontWeightSemibold,
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
  riskBadgeHigh: {
    backgroundColor: tokens.colorPaletteRedBackground2,
    color: tokens.colorPaletteRedForeground2,
    ...shorthands.border('1px', 'solid', tokens.colorPaletteRedBorder2),
  },
  riskBadgeMedium: {
    backgroundColor: tokens.colorPaletteYellowBackground2,
    color: tokens.colorPaletteYellowForeground2,
    ...shorthands.border('1px', 'solid', tokens.colorPaletteYellowBorder2),
  },
  riskBadgeLow: {
    backgroundColor: tokens.colorPaletteBlueBackground2,
    color: tokens.colorPaletteBlueForeground2,
    ...shorthands.border('1px', 'solid', tokens.colorPaletteBlueBorderActive),
  },
  timeoutTrack: {
    width: '100%',
  },
  message: {
    fontSize: tokens.fontSizeBase300,
    color: tokens.colorNeutralForeground2,
    marginTop: 0,
    marginBottom: '16px',
    lineHeight: tokens.lineHeightBase300,
  },
  surfaceHigh: {
    borderLeft: `4px solid ${tokens.colorPaletteRedForeground2}`,
    ...shorthands.borderColor(tokens.colorPaletteRedBorder2),
  },
  surfaceMedium: {
    borderLeft: `4px solid ${tokens.colorPaletteYellowForeground2}`,
    ...shorthands.borderColor(tokens.colorPaletteYellowBorder2),
  },
  surfaceLow: {
    borderLeft: `4px solid ${tokens.colorPaletteBlueForeground2}`,
    ...shorthands.borderColor(tokens.colorPaletteYellowBorder2),
  },
  surfaceWindow: {
    boxShadow: tokens.shadow28,
  },
  surfaceModal: {
    boxShadow: tokens.shadow64,
  },
  blockButtonHigh: {
    backgroundColor: tokens.colorPaletteRedForeground2,
    ...shorthands.borderColor(tokens.colorPaletteRedForeground2),
    boxShadow: tokens.shadow8,
  },
  blockButtonMedium: {
    backgroundColor: tokens.colorPaletteYellowForeground2,
    ...shorthands.borderColor(tokens.colorPaletteYellowForeground2),
    boxShadow: tokens.shadow8,
  },
  blockButtonLow: {
    backgroundColor: tokens.colorPaletteBlueForeground2,
    ...shorthands.borderColor(tokens.colorPaletteBlueForeground2),
    boxShadow: tokens.shadow8,
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
  decisionPending = false,
  extraControl,
  allowLabel,
  blockLabel
}) => {
  const { t } = useI18nStore()
  const styles = useStyles()
  const isWindowMode = mode === 'window'

  const riskColors = {
    high: {
      bg: tokens.colorPaletteRedBackground2,
      text: tokens.colorPaletteRedForeground2,
      border: tokens.colorPaletteRedBorder2,
      label: t('intercept_level_high')
    },
    medium: {
      bg: tokens.colorPaletteYellowBackground2,
      text: tokens.colorPaletteYellowForeground2,
      border: tokens.colorPaletteYellowBorder2,
      label: t('intercept_level_medium')
    },
    low: {
      bg: tokens.colorPaletteBlueBackground2,
      text: tokens.colorPaletteBlueForeground2,
      border: tokens.colorPaletteYellowBorder2, // Using yellow as blue border2 doesn't exist
      label: t('intercept_level_low')
    },
  }

  const riskLabel = riskColors[riskLevel].label
  const riskClassName = riskLevel === 'high' ? 'High' : riskLevel === 'medium' ? 'Medium' : 'Low'
  const surfaceClassName = [
    styles.surface,
    styles[`surface${riskClassName}` as keyof typeof styles],
    isWindowMode ? styles.surfaceWindowFull : styles.surfaceModal,
  ].join(' ')
  const alertStripClassName = [
    styles.alertStrip,
    styles[`alertStrip${riskClassName}` as keyof typeof styles],
  ].join(' ')
  const iconWrapperClassName = [
    styles.iconWrapper,
    styles[`iconWrapper${riskClassName}` as keyof typeof styles],
  ].join(' ')
  const eyebrowClassName = [
    styles.eyebrow,
    styles[`eyebrow${riskClassName}` as keyof typeof styles],
  ].join(' ')
  const titleClassName = [
    styles.title,
    styles[`title${riskClassName}` as keyof typeof styles],
  ].join(' ')
  const countdownClassName = [
    styles.countdownTime,
    styles[`countdownTime${riskClassName}` as keyof typeof styles],
  ].join(' ')
  const detailPanelClassName = [
    styles.detailPanel,
    styles[`detailPanel${riskClassName}` as keyof typeof styles],
  ].join(' ')
  const riskBadgeClassName = [
    styles.riskBadge,
    styles[`riskBadge${riskClassName}` as keyof typeof styles],
  ].join(' ')
  const blockButtonClassName = styles[`blockButton${riskClassName}` as keyof typeof styles]
  const showAutoDecision = isWindowMode && typeof remainingSeconds === 'number'
  const autoDecisionProgress = showAutoDecision && typeof autoDecisionSeconds === 'number' && autoDecisionSeconds > 0
    ? Math.max(0, Math.min(1, remainingSeconds / autoDecisionSeconds))
    : undefined
  const autoDecisionLabel = defaultAction === 'block'
    ? t('intercept_btn_block_process')
    : t('intercept_btn_allow_run')

  const handleOpenChange = (_: unknown, data: DialogOpenChangeData): void => {
    if (!data.open) {
      onClose()
    }
  }

  return (
    <Dialog open={isOpen} onOpenChange={handleOpenChange}>
      <DialogSurface
        className={surfaceClassName}
        role="dialog"
        aria-modal="true"
        aria-labelledby={DIALOG_TITLE_ID}
      >
        <div className={alertStripClassName} />

        <div
          className={`${styles.header} ${isWindowMode ? styles.headerDraggable : ''}`}
          data-tauri-drag-region={isWindowMode ? true : undefined}
        >
          <div className={iconWrapperClassName}>
            {riskLevel === 'high' ? (
              <ShieldOff size={26} />
            ) : riskLevel === 'medium' ? (
              <AlertOctagon size={26} />
            ) : (
              <AlertTriangle size={26} />
            )}
          </div>
          <div className={styles.titleGroup}>
            <div className={eyebrowClassName}>
              {t('intercept_security_alert')}
            </div>
            <DialogTitle id={DIALOG_TITLE_ID} className={titleClassName} as="h3">{title}</DialogTitle>
          </div>
          {showAutoDecision && (
            <div className={styles.countdown} title={t('intercept_default_action_hint')}>
              <span className={styles.countdownLabel}>
                {t('intercept_default_action_label')}
              </span>
              <span className={styles.countdownAction}>{autoDecisionLabel}</span>
              <span className={countdownClassName}>
                {t('intercept_auto_block_countdown').replace('{seconds}', String(remainingSeconds))}
              </span>
            </div>
          )}
          {mode !== 'window' && (
            <Button
              appearance="subtle"
              size="small"
              className={styles.closeButton}
              icon={<X size={18} />}
              onClick={onClose}
              aria-label={t('common_cancel')}
            />
          )}
        </div>

        <DialogBody>
          <DialogContent>
            <p className={styles.message}>{message}</p>

            <div
              className={detailPanelClassName}
            >
              <div className={styles.detail}>
                <span className={styles.detailLabel}>{t('intercept_label_process')}</span>
                <span className={`${styles.detailValue} ${styles.processValue}`} title={processName}>
                  {processName}
                </span>
              </div>
              {filePath && (
                <div className={styles.detail}>
                  <span className={styles.detailLabel}>{t('intercept_label_path')}</span>
                  <span className={styles.detailValue} title={filePath}>
                    {filePath}
                  </span>
                </div>
              )}
              <div className={riskBadgeClassName}>
                <AlertTriangle size={13} />
                {riskLabel}
              </div>
            </div>

            {showAutoDecision && typeof autoDecisionSeconds === 'number' && autoDecisionSeconds > 0 && (
              <div className={styles.timeoutTrack}>
                <ProgressBar
                  value={autoDecisionProgress}
                  thickness="medium"
                  aria-label={t('intercept_default_action_hint')}
                />
              </div>
            )}
          </DialogContent>
        </DialogBody>

        {extraControl}

        <DialogActions>
          <Button
            appearance="outline"
            onClick={onAllow}
            disabled={decisionPending}
          >
            {allowLabel ?? t('intercept_btn_allow_run')}
          </Button>
          <Button
            appearance="primary"
            onClick={onBlock}
            disabled={decisionPending}
            autoFocus={defaultAction === 'block'}
            className={blockButtonClassName}
          >
            {decisionPending
              ? t('intercept_btn_processing')
              : (blockLabel ?? t('intercept_btn_block_process'))}
          </Button>
        </DialogActions>
      </DialogSurface>
    </Dialog>
  )
}

export default InterceptionModal
