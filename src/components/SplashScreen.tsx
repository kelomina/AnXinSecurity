/**
 * 启动阶段页面组件
 * Startup phase screen component
 *
 * 调用方：App.tsx (初始化阶段)
 * Called by: App.tsx (during initialization phase)
 */
import React, { useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useI18nStore } from '../stores/i18nStore'
import {
  makeStyles,
  shorthands,
  tokens,
  ProgressBar,
} from '@fluentui/react-components'

export type StartupPhaseStatus = 'pending' | 'active' | 'complete' | 'warning' | 'error'

export interface StartupPhaseItem {
  id: string
  labelKey: string
  detailKey?: string
  status: StartupPhaseStatus
}

export interface StartupSnapshotSummary {
  baselineComplete: boolean
  deepScanCompleted: boolean
  deepScanPendingModules: number
  deepScanPendingProcesses: number
  unknownProcesses: number
  unknownModules: number
  maliciousProcesses: number
  maliciousModules: number
  unsignedModuleAlerts: number
  durationMs: number
}

interface SplashScreenProps {
  isVisible: boolean
  statusText?: string
  phases?: StartupPhaseItem[]
  snapshotProgress?: number | null
  snapshotCurrent?: number
  snapshotTotal?: number
  snapshotSummary?: StartupSnapshotSummary | null
}

const statusWeight: Record<StartupPhaseStatus, number> = {
  pending: 0,
  active: 0.5,
  warning: 0.65,
  error: 0.65,
  complete: 1,
}

function clampProgress(value: number): number {
  if (!Number.isFinite(value)) return 0
  return Math.max(0, Math.min(100, value))
}

function formatTemplate(template: string, values: Record<string, string | number>): string {
  return Object.entries(values).reduce(
    (text, [key, value]) => text.split(`{${key}}`).join(String(value)),
    template,
  )
}

const useStyles = makeStyles({
  overlay: {
    position: 'fixed',
    inset: 0,
    backgroundColor: tokens.colorNeutralBackground1,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 10000,
  },
  dialogSurface: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    boxShadow: tokens.shadow28,
    width: '480px',
    maxWidth: '90vw',
    ...shorthands.padding('32px'),
  },
  titleRow: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('16px'),
    marginBottom: '24px',
  },
  titleIcon: {
    width: '48px',
    height: '48px',
    flexShrink: 0,
    '& img': {
      width: '100%',
      height: '100%',
      objectFit: 'contain',
    },
  },
  titleText: {
    '& h1': {
      fontSize: tokens.fontSizeBase500,
      fontWeight: tokens.fontWeightSemibold,
      color: tokens.colorNeutralForeground1,
      marginBottom: '2px',
    },
    '& span': {
      fontSize: tokens.fontSizeBase200,
      color: tokens.colorNeutralForeground3,
    },
  },
  fieldLabel: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '8px',
    fontSize: tokens.fontSizeBase300,
    color: tokens.colorNeutralForeground2,
  },
  fieldValue: {
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorBrandForeground1,
  },
  fieldHelper: {
    marginTop: '6px',
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
  },
  phaseList: {
    display: 'flex',
    flexDirection: 'column',
    ...shorthands.gap('6px'),
    marginTop: '20px',
  },
  phaseCard: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('10px'),
    ...shorthands.padding('8px', '12px'),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    fontSize: tokens.fontSizeBase300,
    backgroundColor: tokens.colorNeutralBackground3,
    color: tokens.colorNeutralForeground3,
  },
  phaseCardActive: {
    backgroundColor: tokens.colorBrandBackground2,
    color: tokens.colorBrandForeground1,
  },
  phaseCardComplete: {
    backgroundColor: tokens.colorPaletteGreenBackground2,
    color: tokens.colorPaletteGreenForeground2,
  },
  phaseCardError: {
    backgroundColor: tokens.colorPaletteRedBackground2,
    color: tokens.colorPaletteRedForeground2,
  },
  phaseCardWarning: {
    backgroundColor: tokens.colorPaletteYellowBackground2,
    color: tokens.colorPaletteYellowForeground2,
  },
  phaseIcon: {
    flexShrink: 0,
    width: '16px',
    height: '16px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
})

const SplashScreen: React.FC<SplashScreenProps> = ({
  isVisible,
  phases = [],
  snapshotProgress,
  snapshotCurrent = 0,
  snapshotTotal = 0,
}) => {
  const { t } = useI18nStore()
  const styles = useStyles()

  const overallProgress = useMemo(() => {
    if (phases.length === 0) return null
    const totalWeight = phases.reduce((sum, phase) => sum + statusWeight[phase.status], 0)
    return clampProgress((totalWeight / phases.length) * 100)
  }, [phases])

  const normalizedSnapshotProgress =
    typeof snapshotProgress === 'number' ? clampProgress(snapshotProgress) : null
  const visibleProgress = normalizedSnapshotProgress ?? overallProgress ?? 12

  const snapshotCounter =
    snapshotTotal > 0
      ? formatTemplate(t('splash_snapshot_counter'), {
        current: snapshotCurrent,
        total: snapshotTotal,
      })
      : t('splash_snapshot_waiting')

  const getPhaseCardClass = (status: StartupPhaseStatus) => {
    switch (status) {
      case 'active': return `${styles.phaseCard} ${styles.phaseCardActive}`
      case 'complete': return `${styles.phaseCard} ${styles.phaseCardComplete}`
      case 'error': return `${styles.phaseCard} ${styles.phaseCardError}`
      case 'warning': return `${styles.phaseCard} ${styles.phaseCardWarning}`
      default: return styles.phaseCard
    }
  }

  const renderPhaseIcon = (status: StartupPhaseStatus) => {
    if (status === 'complete') {
      return (
        <svg className={styles.phaseIcon} viewBox="0 0 20 20" fill="none">
          <path d="M6.5 10.5L9 13L14 7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      )
    }
    if (status === 'active') {
      return (
        <motion.svg
          className={styles.phaseIcon}
          viewBox="0 0 20 20"
          fill="none"
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
        >
          <circle cx="10" cy="10" r="7.25" stroke="currentColor" strokeWidth="1.5" opacity="0.2" />
          <path d="M10 2.75C13.866 2.75 17 5.884 17 9.75" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
        </motion.svg>
      )
    }
    if (status === 'error') {
      return (
        <svg className={styles.phaseIcon} viewBox="0 0 20 20" fill="none">
          <path d="M10 6V11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          <circle cx="10" cy="14" r="0.75" fill="currentColor" />
        </svg>
      )
    }
    if (status === 'warning') {
      return (
        <svg className={styles.phaseIcon} viewBox="0 0 20 20" fill="none">
          <path d="M10 6V11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          <circle cx="10" cy="14" r="0.75" fill="currentColor" />
        </svg>
      )
    }
    return (
      <svg className={styles.phaseIcon} viewBox="0 0 20 20" fill="none">
        <circle cx="10" cy="10" r="7.25" stroke="currentColor" strokeWidth="1.5" />
        <path d="M10 6.5V10L12 12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    )
  }

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          className={styles.overlay}
          initial={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.4 }}
          role="status"
          aria-live="polite"
        >
          <motion.div
            className={styles.dialogSurface}
            initial={{ opacity: 0, y: 12, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ duration: 0.45, ease: 'easeOut' }}
          >
            <div className={styles.titleRow}>
              <div className={styles.titleIcon}>
                <img src="/favicon.ico" alt="AnXin Security" />
              </div>
              <div className={styles.titleText}>
                <h1>{t('splash_stage_title')}</h1>
                <span>{t('splash_stage_label')}</span>
              </div>
            </div>

            <div className={styles.fieldLabel}>
              <span>{t('splash_overall_progress')}</span>
              <span className={styles.fieldValue}>{Math.round(visibleProgress)}%</span>
            </div>
            <ProgressBar value={visibleProgress / 100} thickness="large" />
            <div className={styles.fieldHelper}>{snapshotCounter}</div>

            <div className={styles.phaseList}>
              {phases.map((phase) => (
                <div key={phase.id} className={getPhaseCardClass(phase.status)}>
                  {renderPhaseIcon(phase.status)}
                  <span>{t(phase.labelKey)}</span>
                </div>
              ))}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

export default SplashScreen
