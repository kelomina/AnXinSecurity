/**
 * 启动阶段页面组件
 * Startup phase screen component
 *
 * 调用方：App.tsx (初始化阶段)
 * Called by: App.tsx (during initialization phase)
 */
import React, { useMemo } from 'react'
import { AlertTriangle, Check, Clock3, LoaderCircle } from './icons'
import { useI18nStore } from '../stores/i18nStore'
import { useThemeStore } from '../stores/themeStore'
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
  summaryGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
    ...shorthands.gap('8px'),
    marginTop: '16px',
  },
  summaryItem: {
    display: 'flex',
    flexDirection: 'column',
    ...shorthands.gap('2px'),
    ...shorthands.padding('8px', '12px'),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    backgroundColor: tokens.colorNeutralBackground3,
    minWidth: 0,
  },
  summaryLabel: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
  },
  summaryValue: {
    fontSize: tokens.fontSizeBase300,
    color: tokens.colorNeutralForeground1,
  },
  securityNote: {
    marginTop: '12px',
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
    textAlign: 'center',
  },
  phaseText: {
    display: 'flex',
    flexDirection: 'column',
    ...shorthands.gap('2px'),
    minWidth: 0,
  },
  phaseDetail: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
    // 阶段说明是次要信息，不应与阶段名争夺注意力
    //  The stage detail is secondary and must not compete with the stage name
    opacity: 0.85,
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
  phaseIconSpinning: {
    animation: 'spin 1s linear infinite',
  },
  overlayAnimated: {
    animationName: 'splashFadeIn',
    animationDuration: '0.4s',
    animationTimingFunction: 'ease-out',
  },
  surfaceAnimated: {
    animationName: 'splashSlideIn',
    animationDuration: '0.45s',
    animationTimingFunction: 'ease-out',
  },
})

const SplashScreen: React.FC<SplashScreenProps> = ({
  isVisible,
  phases = [],
  snapshotProgress,
  snapshotCurrent = 0,
  snapshotTotal = 0,
  snapshotSummary = null,
}) => {
  const { t } = useI18nStore()
  const animationsEnabled = useThemeStore((state) => state.animationsEnabled)
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
      return <Check size={16} className={styles.phaseIcon} />
    }
    if (status === 'active') {
      return <LoaderCircle size={16} className={`${styles.phaseIcon} ${animationsEnabled ? styles.phaseIconSpinning : ''}`} />
    }
    if (status === 'error') {
      return <AlertTriangle size={16} className={styles.phaseIcon} />
    }
    if (status === 'warning') {
      return <AlertTriangle size={16} className={styles.phaseIcon} />
    }
    return <Clock3 size={16} className={styles.phaseIcon} />
  }

  // 摘要合计：进程与模块分开统计对用户没有意义，按类别合并展示。
  // snapshotSummary 为空时（快照结果尚未到达）走等待态分支，这里统一取 0。
  //  Summary totals: splitting processes and modules is meaningless to the user, so they are
  //  merged per category. When snapshotSummary is null (result not in yet) the waiting branch
  //  renders instead and these stay 0.
  const deepScanPendingTotal = snapshotSummary
    ? snapshotSummary.deepScanPendingModules + snapshotSummary.deepScanPendingProcesses
    : 0
  const unknownTotal = snapshotSummary
    ? snapshotSummary.unknownProcesses + snapshotSummary.unknownModules
    : 0
  const threatTotal = snapshotSummary
    ? snapshotSummary.maliciousProcesses + snapshotSummary.maliciousModules
    : 0

  const overlayClassName = [
    styles.overlay,
    animationsEnabled ? styles.overlayAnimated : '',
  ].filter(Boolean).join(' ')
  const surfaceClassName = [
    styles.dialogSurface,
    animationsEnabled ? styles.surfaceAnimated : '',
  ].filter(Boolean).join(' ')

  return (
    <>
      {isVisible && (
        <div className={overlayClassName} role="status" aria-live="polite">
          <div className={surfaceClassName}>
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
                <div
                  key={phase.id}
                  className={getPhaseCardClass(phase.status)}
                  data-status={phase.status}
                >
                  {renderPhaseIcon(phase.status)}
                  {/*
                    每个阶段除了名称还要给出正在做什么，让"可信环境自检"过程对用户透明。
                    detailKey 早已由 App.tsx 为全部 7 个阶段提供、i18n 两个语言包也都有对应文案，
                    但此前从未渲染。
                    Each stage shows what it is actually doing so the trusted-environment
                    self-check stays transparent. detailKey has long been supplied by App.tsx for
                    all seven stages and exists in both locale files, but was never rendered.
                  */}
                  <div className={styles.phaseText}>
                    <span>{t(phase.labelKey)}</span>
                    {phase.detailKey && (
                      <span className={styles.phaseDetail}>{t(phase.detailKey)}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {/*
              快照结果摘要：把「可信基线 / 深度校验 / 未知项 / 威胁项」四项如实摊开。
              StartupSnapshotSummary 与全部 i18n 文案早已就绪，但此前从未渲染，
              用户只能看到进度条却不知道自检到底查出了什么。
              措辞刻意避免任何"基线已完成可信"式的结论——未完成的深度校验必须显示为待确认。
              Snapshot summary: lays out trusted baseline / deep verification / unknown items /
              threats as they actually are. StartupSnapshotSummary and every i18n string were
              already in place but never rendered, leaving users with a progress bar and no idea
              what the self-check found. Deliberately avoids conclusive wording like "trusted":
              incomplete deep verification must read as still pending.
            */}
            <div className={`splash-summary-grid ${styles.summaryGrid}`}>
              {snapshotSummary ? (
                <>
                  <div className={styles.summaryItem}>
                    <span className={styles.summaryLabel}>{t('splash_summary_baseline')}</span>
                    <span className={styles.summaryValue}>
                      {snapshotSummary.baselineComplete
                        ? t('splash_summary_baseline_ready')
                        : t('splash_summary_baseline_pending')}
                    </span>
                  </div>
                  <div className={styles.summaryItem}>
                    <span className={styles.summaryLabel}>{t('splash_summary_deep_scan')}</span>
                    <span className={styles.summaryValue}>
                      {snapshotSummary.deepScanCompleted
                        ? t('splash_summary_deep_done')
                        : formatTemplate(t('splash_summary_deep_pending'), {
                            count: deepScanPendingTotal,
                          })}
                    </span>
                  </div>
                  <div className={styles.summaryItem}>
                    <span className={styles.summaryLabel}>{t('splash_summary_unknown')}</span>
                    <span className={styles.summaryValue}>
                      {formatTemplate(t('splash_summary_unknown_value'), {
                        count: unknownTotal,
                      })}
                    </span>
                  </div>
                  <div className={styles.summaryItem}>
                    <span className={styles.summaryLabel}>{t('splash_summary_threats')}</span>
                    <span className={styles.summaryValue}>
                      {formatTemplate(t('splash_summary_threats_value'), {
                        count: threatTotal,
                      })}
                    </span>
                  </div>
                </>
              ) : (
                <div className={styles.summaryItem}>
                  <span className={styles.summaryValue}>{t('splash_summary_waiting')}</span>
                </div>
              )}
            </div>

            <div className={styles.securityNote}>{t('splash_security_note')}</div>
          </div>
        </div>
      )}
    </>
  )
}

export default SplashScreen
