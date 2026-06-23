/**
 * 概览页面
 * Overview page
 */
import React, { useEffect, useState, useRef, useCallback } from 'react'
import { useConfigStore } from '../stores/configStore'
import { useQuarantineStore } from '../stores/quarantineStore'
import { useI18nStore } from '../stores/i18nStore'
import { scannerHealth, startEngine, stopEngine } from '../api/scanner'
import { getRecentLogs, clearLogs, onLogEvent } from '../api/logs'
import { getRiskStatus, onRiskEvent, type RiskAssessment } from '../api/risk'
import { onFileHookEvent } from '../api/behavior'
import { Activity, Database, ShieldCheck, ShieldAlert, Eye, FileWarning, Trash2, AlertTriangle, Power, PowerOff } from 'lucide-react'
import { Button, makeStyles, shorthands, tokens } from '@fluentui/react-components'

const useStyles = makeStyles({
  page: {
    paddingBottom: '24px',
  },
  pageTitle: {
    fontSize: tokens.fontSizeBase600,
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground1,
    marginBottom: '20px',
  },
  engineCard: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('16px', '20px'),
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '16px',
  },
  engineCardRunning: {
    ...shorthands.borderColor(tokens.colorPaletteGreenBorderActive),
  },
  engineLeft: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('12px'),
  },
  engineIcon: {
    width: '40px',
    height: '40px',
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: 0,
  },
  engineLabel: {
    fontWeight: tokens.fontWeightSemibold,
    fontSize: tokens.fontSizeBase400,
    color: tokens.colorNeutralForeground1,
  },
  engineSub: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground2,
  },
  infoGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(4, 1fr)',
    ...shorthands.gap('12px'),
    marginBottom: '16px',
  },
  infoCard: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('16px'),
  },
  infoCardIcon: {
    width: '36px',
    height: '36px',
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    backgroundColor: tokens.colorBrandBackground2,
    color: tokens.colorBrandForeground1,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: '10px',
  },
  infoCardLabel: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground2,
    fontWeight: tokens.fontWeightSemibold,
    marginBottom: '4px',
  },
  infoCardValue: {
    fontSize: tokens.fontSizeBase600,
    fontWeight: tokens.fontWeightBold,
    color: tokens.colorNeutralForeground1,
    lineHeight: '1.2',
  },
  infoCardSub: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground2,
    marginTop: '4px',
  },
  logPanel: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    marginTop: '16px',
    overflow: 'hidden',
  },
  logHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    ...shorthands.padding('14px', '20px'),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  logHeaderTitle: {
    fontWeight: tokens.fontWeightSemibold,
    fontSize: tokens.fontSizeBase300,
    color: tokens.colorNeutralForeground1,
  },
  logBody: {
    maxHeight: '280px',
    overflowY: 'auto',
    ...shorthands.padding('8px', '0'),
    fontFamily: 'Consolas, "Courier New", monospace',
    fontSize: tokens.fontSizeBase200,
  },
  logEmpty: {
    ...shorthands.padding('20px'),
    textAlign: 'center' as const,
    color: tokens.colorNeutralForeground3,
  },
  logRow: {
    ...shorthands.padding('4px', '20px'),
    display: 'flex',
    ...shorthands.gap('8px'),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
})

interface OverviewPageProps {
  onOpenLifecycle?: (pid: number, processName: string) => void
}

const OverviewPage: React.FC<OverviewPageProps> = (_props) => {
  const styles = useStyles()
  const config = useConfigStore((state) => state.config)
  const refreshMonitoringRuntimeStatus = useConfigStore((state) => state.refreshMonitoringRuntimeStatus)
  const quarantineItems = useQuarantineStore((state) => state.items)
  const loadQuarantineItems = useQuarantineStore((state) => state.loadItems)
  const { t } = useI18nStore()
  const [engineStatus, setEngineStatus] = useState<'running' | 'stopped' | 'error' | 'loading'>('loading')
  const [engineAction, setEngineAction] = useState<'start' | 'stop' | null>(null)
  const [logs, setLogs] = useState<string[]>([])
  const [riskEventCount, setRiskEventCount] = useState<number>(0)
  const [lastRiskLevel, setLastRiskLevel] = useState<string | null>(null)
  const [fileHookEventCount, setFileHookEventCount] = useState<number>(0)

  const riskCleanupRef = useRef<(() => void) | null>(null)
  const riskMountedRef = useRef(true)

  const refreshEngineHealth = useCallback(async () => {
    try {
      const health = await scannerHealth()
      if (health.status === 'running') {
        setEngineStatus('running')
      } else if (health.status === 'stopped') {
        setEngineStatus('stopped')
      } else {
        setEngineStatus('error')
      }
    } catch (e) {
      console.error('[OverviewPage] Failed to check engine health:', e)
      setEngineStatus('error')
    }
  }, [])

  const handleToggleEngine = async () => {
    const shouldStop = engineStatus === 'running'
    setEngineAction(shouldStop ? 'stop' : 'start')
    try {
      if (shouldStop) {
        await stopEngine()
      } else {
        await startEngine()
      }
      await refreshEngineHealth()
    } catch (e) {
      console.error('[OverviewPage] Failed to toggle engine:', e)
      setEngineStatus('error')
    } finally {
      setEngineAction(null)
    }
  }

  const formatRuntimeLogLine = useCallback((runtimeEvent: Record<string, unknown>) => {
    const nestedEvent = runtimeEvent.event && typeof runtimeEvent.event === 'object'
      ? runtimeEvent.event as Record<string, unknown>
      : null
    const nestedData = nestedEvent?.data && typeof nestedEvent.data === 'object'
      ? nestedEvent.data as Record<string, unknown>
      : null
    const rawTimestamp = runtimeEvent.timestamp ?? runtimeEvent.timestampMs ?? nestedEvent?.timestamp
    const timestamp = typeof rawTimestamp === 'number'
      ? new Date(rawTimestamp)
      : typeof rawTimestamp === 'string'
        ? new Date(rawTimestamp)
        : new Date()
    const ts = Number.isNaN(timestamp.getTime())
      ? new Date().toLocaleTimeString('zh-CN')
      : timestamp.toLocaleTimeString('zh-CN')
    const provider = String(runtimeEvent.provider || nestedEvent?.provider || 'ETW')
    const op = String(runtimeEvent.operation || nestedData?.type || nestedData?.operation || runtimeEvent.type || '')
    const path = String(runtimeEvent.path || nestedData?.fileName || nestedData?.keyName || nestedData?.processName || nestedData?.remoteAddress || '')
    const pid = Number(runtimeEvent.pid || nestedEvent?.pid || 0)
    return `[${ts}] PID:${pid} ${provider}/${op} ${path}`
  }, [])

  const formatLogLine = useCallback((line: string) => {
    try {
      const parsed = JSON.parse(line) as Record<string, unknown>
      return formatRuntimeLogLine(parsed)
    } catch {
      return line
    }
  }, [formatRuntimeLogLine])

  useEffect(() => {
    refreshEngineHealth()
    refreshMonitoringRuntimeStatus()
    loadQuarantineItems()
    getRecentLogs().then((recentLogs) => {
      setLogs(recentLogs.map(formatLogLine).reverse().slice(0, 200))
    }).catch((e: unknown) => { console.error('[OverviewPage] Failed to load recent logs:', e) })
    getRiskStatus().then((status) => { setRiskEventCount(status.eventCount) }).catch(() => {})
    const interval = setInterval(() => {
      refreshEngineHealth()
      refreshMonitoringRuntimeStatus()
    }, 30000)
    return () => clearInterval(interval)
  }, [formatLogLine, loadQuarantineItems, refreshEngineHealth, refreshMonitoringRuntimeStatus])

  useEffect(() => {
    const unlisten = onLogEvent((line) => {
      setLogs((prev) => [formatLogLine(line), ...prev].slice(0, 200))
    })
    return () => { unlisten() }
  }, [formatLogLine])

  useEffect(() => {
    const unlisten = onFileHookEvent(() => {
      setFileHookEventCount((prev) => prev + 1)
    })
    return () => { unlisten() }
  }, [])

  useEffect(() => {
    riskMountedRef.current = true
    riskCleanupRef.current = null
    onRiskEvent((assessment: RiskAssessment) => {
      if (riskMountedRef.current) {
        setRiskEventCount((prev) => prev + 1)
        setLastRiskLevel(assessment.riskLevel)
      }
    }).then((unlisten) => {
      if (riskMountedRef.current) {
        riskCleanupRef.current = unlisten
      } else {
        unlisten()
      }
    })
    return () => {
      riskMountedRef.current = false
      if (riskCleanupRef.current) {
        riskCleanupRef.current()
      }
    }
  }, [])

  const quarantinedCount = quarantineItems.filter(i => i.status === 'quarantined').length
  const totalSize = quarantineItems.reduce((sum, i) => sum + i.fileSize, 0)
  const engineStatusLabel = engineStatus === 'loading'
    ? t('overview_engine_checking')
    : engineStatus === 'running'
      ? t('overview_engine_running')
      : engineStatus === 'stopped'
        ? t('overview_engine_stopped')
        : t('overview_engine_error')
  const engineButtonLabel = engineAction
    ? (engineAction === 'start' ? t('overview_engine_starting') : t('overview_engine_stopping'))
    : engineStatus === 'running'
      ? t('overview_engine_stop_btn')
      : t('overview_engine_start_btn')
  const isEngineButtonDisabled = engineStatus === 'loading' || engineAction !== null

  const engineIconBg = engineStatus === 'running'
    ? tokens.colorPaletteGreenBackground2
    : engineStatus === 'error'
      ? tokens.colorPaletteRedBackground2
      : tokens.colorPaletteBlueBackground2

  const riskCardBorderColor = lastRiskLevel === 'high'
    ? tokens.colorPaletteRedBorderActive
    : lastRiskLevel === 'medium'
      ? tokens.colorPaletteYellowBorderActive
      : undefined

  const formatSize = (bytes: number) =>
    bytes < 1024 ? `${bytes} B` : bytes < 1048576 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1048576).toFixed(1)} MB`

  return (
    <section id="page-overview" className={styles.page}>
      <h1 className={styles.pageTitle}>AnXin Security</h1>

      {/* 引擎状态卡片 */}
      <div className={`${styles.engineCard}${engineStatus === 'running' ? ` ${styles.engineCardRunning}` : ''}`}>
        <div className={styles.engineLeft}>
          <div className={styles.engineIcon} style={{ backgroundColor: engineIconBg }}>
            {engineStatus === 'running'
              ? <ShieldCheck size={20} color={tokens.colorPaletteGreenForeground2} />
              : engineStatus === 'error'
                ? <ShieldAlert size={20} color={tokens.colorPaletteRedForeground2} />
                : <Activity size={20} color={tokens.colorPaletteBlueForeground2} />}
          </div>
          <div>
            <div className={styles.engineLabel}>{engineStatusLabel}</div>
            <div className={styles.engineSub}>
              {engineStatus === 'running' ? t('overview_engine_all_modules') : t('overview_engine_status_desc')}
            </div>
          </div>
        </div>
        <Button
          appearance={engineStatus === 'running' ? 'outline' : 'primary'}
          size="small"
          onClick={handleToggleEngine}
          disabled={isEngineButtonDisabled}
          title={engineStatus === 'running' ? t('overview_engine_stop_title') : t('overview_engine_start_title')}
          icon={engineAction
            ? <Activity size={14} />
            : engineStatus === 'running'
              ? <PowerOff size={14} />
              : <Power size={14} />}
          style={engineStatus === 'running' ? { color: tokens.colorPaletteRedForeground2, borderColor: tokens.colorPaletteRedBorderActive } : undefined}
        >
          {engineButtonLabel}
        </Button>
      </div>

      {/* 信息卡片网格 */}
      <div className={styles.infoGrid}>
        <div className={styles.infoCard}>
          <div className={styles.infoCardIcon}>
            <Eye size={20} />
          </div>
          <div className={styles.infoCardLabel}>{t('overview_realtime_monitoring')}</div>
          <div className={styles.infoCardValue} style={{ fontSize: tokens.fontSizeBase400 }}>
            {config?.behaviorMonitoring?.enabled ? t('overview_running') : t('overview_disabled')}
          </div>
          <div className={styles.infoCardSub}>
            {config?.behaviorMonitoring?.enabled ? t('overview_monitoring_active') : t('overview_monitoring_off')}
          </div>
        </div>

        <div className={styles.infoCard}>
          <div className={styles.infoCardIcon} style={{ backgroundColor: tokens.colorPaletteYellowBackground2, color: tokens.colorPaletteYellowForeground2 }}>
            <FileWarning size={20} />
          </div>
          <div className={styles.infoCardLabel}>{t('overview_event_log')}</div>
          <div className={styles.infoCardValue}>{fileHookEventCount}</div>
          <div className={styles.infoCardSub}>{t('overview_today')}</div>
        </div>

        <div className={styles.infoCard}>
          <div className={styles.infoCardIcon} style={{ backgroundColor: tokens.colorPaletteRedBackground2, color: tokens.colorPaletteRedForeground2 }}>
            <Database size={20} />
          </div>
          <div className={styles.infoCardLabel}>{t('overview_quarantine_files')}</div>
          <div className={styles.infoCardValue}>{quarantinedCount}</div>
          <div className={styles.infoCardSub}>{formatSize(totalSize)}</div>
        </div>

        <div className={styles.infoCard} style={riskCardBorderColor ? { borderColor: riskCardBorderColor } : undefined}>
          <div className={styles.infoCardIcon} style={{ backgroundColor: tokens.colorPaletteRedBackground2, color: tokens.colorPaletteRedForeground2 }}>
            <AlertTriangle size={20} />
          </div>
          <div className={styles.infoCardLabel}>{t('overview_risk_events')}</div>
          <div className={styles.infoCardValue} style={
            lastRiskLevel === 'high'
              ? { color: tokens.colorPaletteRedForeground2 }
              : lastRiskLevel === 'medium'
                ? { color: tokens.colorPaletteYellowForeground2 }
                : undefined
          }>
            {riskEventCount}
          </div>
          <div className={styles.infoCardSub}>
            {lastRiskLevel
              ? `最近: ${lastRiskLevel === 'high' ? t('overview_risk_high') : lastRiskLevel === 'medium' ? t('overview_risk_medium') : t('overview_risk_low')}`
              : t('overview_no_risk')}
          </div>
        </div>
      </div>

      {/* 实时日志面板 */}
      <div className={styles.logPanel}>
        <div className={styles.logHeader}>
          <span className={styles.logHeaderTitle}>{t('overview_realtime_event_log')}</span>
          <Button
            appearance="secondary"
            size="small"
            icon={<Trash2 size={14} />}
            onClick={() => { clearLogs(); setLogs([]) }}
          >
            {t('overview_clear')}
          </Button>
        </div>
        <div className={styles.logBody}>
          {logs.length === 0 ? (
            <div className={styles.logEmpty}>{t('overview_no_logs')}</div>
          ) : (
            logs.map((line, i) => (
              <div key={i} className={styles.logRow}>
                <span style={{ color: tokens.colorNeutralForeground4, minWidth: 28, textAlign: 'right' as const, opacity: 0.5 }}>{i + 1}</span>
                <span style={{ color: tokens.colorNeutralForeground3 }}>
                  {line.match(/^\[([^\]]+)\]/) ? `[${line.match(/^\[([^\]]+)\]/)![1]}]` : ''}
                </span>
                <span style={{ color: tokens.colorPaletteBlueForeground2 }}>
                  {line.match(/PID:\d+/) ? line.match(/PID:\d+/)![0] : ''}
                </span>
                <span style={{ color: tokens.colorPaletteYellowForeground2, fontWeight: tokens.fontWeightSemibold }}>
                  {line.match(/\] (.+?\/\S+)/) ? line.match(/\] (.+?\/\S+)/)![1] : ''}
                </span>
                <span style={{ color: tokens.colorNeutralForeground1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const }}>
                  {line.replace(/^\[[^\]]+\]\s*PID:\d+\s*\S+\/\S+\s*/, '')}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </section>
  )
}

export default OverviewPage
