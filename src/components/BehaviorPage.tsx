/**
 * EDR 页面（原行为分析页面）
 * EDR page (formerly Behavior Analysis page)
 *
 * 显示实时 ETW 事件流、历史事件查询、进程摘要列表。
 * EDR 功能的启停控制已迁移到设置页面中的"EDR 行为监控"开关。
 * Displays real-time ETW event stream, historical event queries, process summary list.
 * EDR on/off control has been moved to the "EDR Behavior Monitoring" toggle in Settings.
 *
 * 调用方：App.tsx (路由分发)
 * Called by: App.tsx (page routing)
 *
 * 中文关键词：EDR，端点检测与响应，ETW事件，实时监控，进程行为
 * English keywords: EDR, endpoint detection and response, ETW event, real-time monitoring, process behavior
 */
import React, { useEffect, useState, useCallback, useMemo } from 'react'
import {
  listEvents,
  listProcesses,
  clearAllEvents,
  clearEtwDiagnostics,
  exportEtwDiagnostics,
  getEtwDiagnosticsSnapshot,
  onEtwEvent,
  onFileHookEvent,
  type EtwEvent,
  type BehaviorProcess,
  type EtwDiagnosticsSnapshot,
} from '../api/behavior'
import { useConfigStore } from '../stores/configStore'
import { useI18nStore } from '../stores/i18nStore'
import { Play, Pause, Trash2, Shield, AlertTriangle, Download, RefreshCw } from './icons'
import {
  Button,
  Badge,
  makeStyles,
  shorthands,
  tokens,
  Skeleton,
  SkeletonItem,
  Table,
  TableHeader,
  TableHeaderCell,
  TableBody,
  TableRow,
  TableCell,
} from '@fluentui/react-components'

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
  warningCard: {
    backgroundColor: tokens.colorPaletteYellowBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorPaletteYellowBorder2),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('16px'),
    marginBottom: '16px',
    display: 'flex',
    alignItems: 'flex-start',
    ...shorthands.gap('16px'),
  },
  warningIcon: {
    color: tokens.colorPaletteYellowForeground2,
    flexShrink: 0,
    marginTop: '2px',
  },
  warningTitle: {
    fontSize: tokens.fontSizeBase400,
    fontWeight: tokens.fontWeightSemibold,
    marginBottom: '8px',
    color: tokens.colorNeutralForeground1,
  },
  warningDesc: {
    fontSize: tokens.fontSizeBase300,
    color: tokens.colorNeutralForeground2,
  },
  card: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('16px'),
    marginBottom: '16px',
  },
  controlBar: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('8px'),
  },
  hookCounter: {
    color: tokens.colorNeutralForeground3,
    fontSize: tokens.fontSizeBase200,
    marginLeft: '4px',
  },
  controlSpacer: {
    marginLeft: 'auto',
    display: 'flex',
    ...shorthands.gap('8px'),
  },
  cardEmptyCentered: {
    ...shorthands.padding('48px'),
    textAlign: 'center',
  },
  emptyStateIconLarge: {
    color: tokens.colorNeutralForeground3,
    marginBottom: '16px',
    opacity: 0.3,
  },
  mutedParagraph: {
    color: tokens.colorNeutralForeground3,
    fontSize: tokens.fontSizeBase300,
  },
  statsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    ...shorthands.gap('12px'),
    marginBottom: '16px',
  },
  statCard: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.padding('12px', '16px'),
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  statCardProcess: {
    backgroundColor: tokens.colorPaletteBlueBackground2,
  },
  statCardFile: {
    backgroundColor: tokens.colorPaletteYellowBackground2,
  },
  statCardRegistry: {
    backgroundColor: tokens.colorNeutralBackground4,
  },
  statLabel: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground2,
    fontWeight: tokens.fontWeightSemibold,
  },
  statValue: {
    fontSize: tokens.fontSizeBase500,
    fontWeight: tokens.fontWeightBold,
    color: tokens.colorNeutralForeground1,
  },
  statLabelProcess: {
    color: tokens.colorPaletteBlueForeground2,
  },
  statValueProcess: {
    color: tokens.colorPaletteBlueForeground2,
  },
  statLabelFile: {
    color: tokens.colorPaletteYellowForeground2,
  },
  statValueFile: {
    color: tokens.colorPaletteYellowForeground2,
  },
  statLabelRegistry: {
    color: tokens.colorNeutralForeground3,
  },
  statValueRegistry: {
    color: tokens.colorNeutralForeground3,
  },
  tabBar: {
    display: 'flex',
    ...shorthands.gap('8px'),
    marginBottom: '16px',
  },
  tableContainer: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    overflow: 'hidden',
  },
  tableToolbar: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    ...shorthands.padding('14px', '20px'),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  sectionHeader: {
    fontWeight: tokens.fontWeightSemibold,
    fontSize: tokens.fontSizeBase300,
  },
  tableScroll: {
    overflowX: 'auto',
  },
  emptyState: {
    ...shorthands.padding('40px', '20px'),
    textAlign: 'center' as const,
    color: tokens.colorNeutralForeground3,
  },
  emptyIcon: {
    marginBottom: '16px',
  },
  textMono: {
    fontFamily: 'Consolas, "Courier New", monospace',
    fontSize: tokens.fontSizeBase200,
  },
  textWrap: {
    wordBreak: 'break-word',
  },
  textBreakAll: {
    wordBreak: 'break-all',
  },
  mutedText: {
    color: tokens.colorNeutralForeground3,
  },
  truncate: {
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  diagCard: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.padding('12px'),
    marginBottom: '8px',
  },
  diagLabel: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
    marginBottom: '4px',
  },
  diagValue: {
    fontSize: tokens.fontSizeBase300,
    fontFamily: 'Consolas, "Courier New", monospace',
    color: tokens.colorNeutralForeground1,
  },
  diagValueLarge: {
    fontSize: tokens.fontSizeBase500,
    fontWeight: tokens.fontWeightSemibold,
  },
  diagHeader: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('8px'),
    marginBottom: '12px',
  },
  diagActions: {
    marginLeft: 'auto',
    display: 'flex',
    ...shorthands.gap('8px'),
  },
  diagDescription: {
    color: tokens.colorNeutralForeground3,
    fontSize: tokens.fontSizeBase200,
    marginBottom: '12px',
  },
  diagCounterGrid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    ...shorthands.gap('12px'),
    fontSize: tokens.fontSizeBase200,
  },
  diagSection: {
    marginTop: '12px',
  },
  diagSectionTitle: {
    color: tokens.colorNeutralForeground3,
    marginBottom: '8px',
    fontSize: tokens.fontSizeBase200,
  },
  bucketGrid: {
    display: 'grid',
    ...shorthands.gap('8px'),
  },
  bucketCard: {
    ...shorthands.padding('10px', '12px'),
    backgroundColor: tokens.colorNeutralBackground3,
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    display: 'grid',
    ...shorthands.gap('4px'),
  },
  bucketBadges: {
    display: 'flex',
    ...shorthands.gap('8px'),
    flexWrap: 'wrap',
    alignItems: 'center',
  },
  diagnosticsMessage: {
    marginTop: '12px',
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
    wordBreak: 'break-all',
  },
  skeletonRow: {
    marginBottom: '8px',
  },
  skeletonItem: {
    height: '40px',
  },
  registryBadge: {
    backgroundColor: tokens.colorNeutralBackground4,
    color: tokens.colorNeutralForeground3,
  },
  processRowInteractive: {
    cursor: 'pointer',
  },
})

/** 页面属性 / Page props */
interface BehaviorPageProps {
  /** 打开行为生命周期详情的回调 / Callback to open behavior lifecycle detail */
  onOpenLifecycle?: (pid: number, processName: string) => void
}

const BehaviorPage: React.FC<BehaviorPageProps> = ({ onOpenLifecycle }) => {
  const styles = useStyles()
  const [events, setEvents] = useState<EtwEvent[]>([])
  const [processes, setProcesses] = useState<BehaviorProcess[]>([])
  const [loading, setLoading] = useState(true)
  const [pidFilter, _setPidFilter] = useState<number | null>(null)
  const [viewMode, setViewMode] = useState<'events' | 'processes'>('events')
  const [fileHookEventCount, setFileHookEventCount] = useState(0)
  const [etwDiagnostics, setEtwDiagnostics] = useState<EtwDiagnosticsSnapshot | null>(null)
  const [diagnosticsLoading, setDiagnosticsLoading] = useState(false)
  const [diagnosticsMessage, setDiagnosticsMessage] = useState('')
  const { config, devModeUnlocked } = useConfigStore()
  const { t } = useI18nStore()
  const edrEnabled = config?.behaviorMonitoring?.enabled ?? false

  /** 事件统计 / Event statistics */
  const stats = useMemo(() => {
    const total = events.length
    const processCount = events.filter((e) => e.type.toLowerCase() === 'process' || e.type.toLowerCase().includes('process')).length
    const fileCount = events.filter((e) => e.type.toLowerCase() === 'file' || e.type.toLowerCase().includes('file')).length
    const registryCount = events.filter((e) => e.type.toLowerCase() === 'registry' || e.type.toLowerCase().includes('registry')).length
    return { total, processCount, fileCount, registryCount }
  }, [events])

  /**
   * 初始化：加载历史事件、监听实时事件、加载进程列表
   * Initialize: load history, listen for real-time events, load process list
   */
  useEffect(() => {
    if (!edrEnabled) {
      setLoading(false)
      return
    }

    const unlisten = onEtwEvent((event) => {
      setEvents((prev) => [event, ...prev].slice(0, 500))
    })

    loadHistory()
    loadProcesses()
    if (devModeUnlocked) {
      loadEtwDiagnostics()
    }

    return () => {
      unlisten()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [edrEnabled, devModeUnlocked])

  /**
   * 监听文件 Hook 专用事件 / Listen for dedicated file Hook events.
   * 后端也会把 Hook 事件兼容发送到 etw-event；这里仅计数，避免事件列表重复显示。
   * Backend also emits Hook events to etw-event for compatibility; this effect only counts them to avoid duplicate list entries.
   */
  useEffect(() => {
    if (!edrEnabled) {
      setFileHookEventCount(0)
      return
    }

    const unlisten = onFileHookEvent(() => {
      setFileHookEventCount((prev) => prev + 1)
    })

    return () => {
      unlisten()
    }
  }, [edrEnabled])

  /**
   * 加载历史事件 / Load historical events
   */
  const loadHistory = useCallback(async () => {
    try {
      setLoading(true)
      const history = await listEvents({ limit: 100, pid: pidFilter ?? undefined })
      setEvents(history)
    } catch (e) {
      console.error('Failed to load history:', e)
    } finally {
      setLoading(false)
    }
  }, [pidFilter])

  /**
   * 加载进程摘要列表 / Load process summary list
   */
  const loadProcesses = useCallback(async () => {
    try {
      const procList = await listProcesses(50)
      setProcesses(procList)
    } catch (e) {
      console.error('Failed to load processes:', e)
    }
  }, [])

  /**
   * 加载 ETW 现场诊断快照 / Load ETW field diagnostics snapshot.
   * 这只读取后端环形缓存，不会改变拦截策略。
   * This only reads the backend ring buffer and does not change interception policy.
   */
  const loadEtwDiagnostics = useCallback(async () => {
    try {
      setDiagnosticsLoading(true)
      setDiagnosticsMessage('')
      const snapshot = await getEtwDiagnosticsSnapshot()
      setEtwDiagnostics(snapshot)
    } catch (e) {
      console.error('Failed to load ETW diagnostics:', e)
      setDiagnosticsMessage(t('behavior_diag_load_failed'))
    } finally {
      setDiagnosticsLoading(false)
    }
  }, [t])

  /**
   * 清除所有事件 / Clear all events
   */
  const handleClearEvents = async () => {
    try {
      await clearAllEvents()
      setEvents([])
    } catch (e) {
      console.error('Failed to clear events:', e)
    }
  }

  /**
   * 刷新数据和进程 / Refresh events and processes
   */
  const handleRefresh = async () => {
    await Promise.all([loadHistory(), loadProcesses(), loadEtwDiagnostics()])
  }

  /**
   * 清空 ETW 诊断缓存 / Clear ETW diagnostics cache.
   */
  const handleClearDiagnostics = async () => {
    try {
      setDiagnosticsLoading(true)
      setDiagnosticsMessage('')
      await clearEtwDiagnostics()
      await loadEtwDiagnostics()
      setDiagnosticsMessage(t('behavior_diag_clear_done'))
    } catch (e) {
      console.error('Failed to clear ETW diagnostics:', e)
      setDiagnosticsMessage(t('behavior_diag_clear_failed'))
    } finally {
      setDiagnosticsLoading(false)
    }
  }

  /**
   * 导出 ETW 诊断缓存 / Export ETW diagnostics cache.
   */
  const handleExportDiagnostics = async () => {
    try {
      setDiagnosticsLoading(true)
      setDiagnosticsMessage('')
      const path = await exportEtwDiagnostics()
      setDiagnosticsMessage(`${t('behavior_diag_export_done')} ${path}`)
      await loadEtwDiagnostics()
    } catch (e) {
      console.error('Failed to export ETW diagnostics:', e)
      setDiagnosticsMessage(t('behavior_diag_export_failed'))
    } finally {
      setDiagnosticsLoading(false)
    }
  }

  /**
   * 获取事件类型 badge 类 / Get event type badge class.
   */
  const getTypeBadgeClassName = (type: string): string | undefined => (
    type === 'Registry' ? styles.registryBadge : undefined
  )

  /**
   * 把统计对象转成简短文本 / Convert counter map to short display text.
   */
  const formatTopCounters = (counts: Record<string, number> | undefined, maxItems = 6): string => {
    if (!counts) {
      return '-'
    }
    const entries = Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, maxItems)
    if (entries.length === 0) {
      return '-'
    }
    return entries.map(([key, value]) => `${key}: ${value}`).join(' / ')
  }

  const aggregateBuckets = useMemo(() => {
    return (etwDiagnostics?.aggregateBuckets ?? []).slice(0, 8)
  }, [etwDiagnostics])

  return (
    <section id="page-behavior" className={styles.page}>
      <h1 className={styles.pageTitle}>{t('behavior_title')}</h1>

      {/* EDR 关闭提示 / EDR disabled notice */}
      {!edrEnabled && (
        <div className={styles.warningCard}>
          <AlertTriangle size={24} className={styles.warningIcon} />
          <div>
            <h3 className={styles.warningTitle}>{t('behavior_edr_disabled_title')}</h3>
            <p className={styles.warningDesc}>
              {t('behavior_edr_disabled_desc')}
            </p>
          </div>
        </div>
      )}

      {/* 控制栏 / Control bar */}
      <div className={styles.card}>
        <div className={styles.controlBar}>
          <Button
            appearance="primary"
            size="small"
            icon={<Play size={14} />}
            onClick={handleRefresh}
            disabled={loading || !edrEnabled}
          >
            {t('behavior_start_monitor')}
          </Button>
          <Button
            appearance="outline"
            size="small"
            icon={<Pause size={14} />}
            disabled={!edrEnabled}
          >
            {t('behavior_pause')}
          </Button>
          <Button
            appearance="outline"
            size="small"
            icon={<Trash2 size={14} />}
            onClick={handleClearEvents}
            disabled={!edrEnabled}
          >
            {t('behavior_clear_log')}
          </Button>
          <span className={styles.hookCounter}>
            Hook: {fileHookEventCount}
          </span>
          <div className={styles.controlSpacer}>
            <Button
              appearance={viewMode === 'events' ? 'primary' : 'outline'}
              size="small"
              onClick={() => setViewMode('events')}
            >
              {t('behavior_realtime_events')}
            </Button>
            <Button
              appearance={viewMode === 'processes' ? 'primary' : 'outline'}
              size="small"
              onClick={() => setViewMode('processes')}
            >
              {t('behavior_label_processes')}
            </Button>
          </div>
        </div>
      </div>

      {/* EDR 关闭时隐藏事件内容 / Hide event content when EDR is off */}
      {!edrEnabled ? (
        <div className={`${styles.card} ${styles.cardEmptyCentered}`}>
          <Shield size={64} className={styles.emptyStateIconLarge} />
          <p className={styles.mutedParagraph}>
            {t('behavior_edr_disabled_hint')}
          </p>
        </div>
      ) : (
        <>
          {/* ETW 现场诊断 — 仅在开发者模式解锁后显示 / ETW field diagnostics — only show when dev mode unlocked */}
          {devModeUnlocked && (
          <div className={styles.card}>
            <div className={styles.diagHeader}>
              <div className={styles.sectionHeader}>{t('behavior_diag_title')}</div>
              <Badge
                appearance="filled"
                color={etwDiagnostics?.collecting ? 'success' : 'warning'}
              >
                {etwDiagnostics?.collecting ? t('behavior_diag_collecting') : t('behavior_diag_not_collecting')}
              </Badge>
              <div className={styles.diagActions}>
                <Button
                  appearance="outline"
                  size="small"
                  icon={<RefreshCw size={14} />}
                  onClick={loadEtwDiagnostics}
                  disabled={diagnosticsLoading}
                >
                  {t('behavior_diag_refresh')}
                </Button>
                <Button
                  appearance="outline"
                  size="small"
                  icon={<Trash2 size={14} />}
                  onClick={handleClearDiagnostics}
                  disabled={diagnosticsLoading}
                >
                  {t('behavior_diag_clear')}
                </Button>
                <Button
                  appearance="outline"
                  size="small"
                  icon={<Download size={14} />}
                  onClick={handleExportDiagnostics}
                  disabled={diagnosticsLoading}
                >
                  {t('behavior_diag_export')}
                </Button>
              </div>
            </div>
            <p className={styles.diagDescription}>
              {t('behavior_diag_desc')}
            </p>
            <div className={styles.statsGrid}>
              <div className={styles.diagCard}>
                <div className={styles.diagLabel}>{t('behavior_diag_total_raw')}</div>
                <div className={`${styles.diagValue} ${styles.diagValueLarge}`}>{etwDiagnostics?.totalRaw ?? 0}</div>
              </div>
              <div className={styles.diagCard}>
                <div className={styles.diagLabel}>{t('behavior_diag_after_filter')}</div>
                <div className={`${styles.diagValue} ${styles.diagValueLarge}`}>{etwDiagnostics?.totalAfterFilter ?? 0}</div>
              </div>
              <div className={styles.diagCard}>
                <div className={styles.diagLabel}>{t('behavior_diag_matched')}</div>
                <div className={`${styles.diagValue} ${styles.diagValueLarge}`}>{etwDiagnostics?.totalMatched ?? 0}</div>
              </div>
              <div className={styles.diagCard}>
                <div className={styles.diagLabel}>{t('behavior_diag_dropped')}</div>
                <div className={`${styles.diagValue} ${styles.diagValueLarge}`}>{etwDiagnostics?.totalDroppedSystemPid ?? 0}</div>
              </div>
            </div>
            <div className={styles.diagCounterGrid}>
              <div>
                <div className={styles.diagLabel}>{t('behavior_diag_provider_counts')}</div>
                <div className={`${styles.textMono} ${styles.textWrap}`}>
                  {formatTopCounters(etwDiagnostics?.providerCounts)}
                </div>
              </div>
              <div>
                <div className={styles.diagLabel}>{t('behavior_diag_operation_counts')}</div>
                <div className={`${styles.textMono} ${styles.textWrap}`}>
                  {formatTopCounters(etwDiagnostics?.operationCounts)}
                </div>
              </div>
              <div>
                <div className={styles.diagLabel}>{t('behavior_diag_rule_counts')}</div>
                <div className={`${styles.textMono} ${styles.textWrap}`}>
                  {formatTopCounters(etwDiagnostics?.ruleCounts)}
                </div>
              </div>
              <div>
                <div className={styles.diagLabel}>{t('behavior_diag_recent_counts')}</div>
                <div className={styles.textMono}>
                  {t('behavior_diag_recent_raw')} {etwDiagnostics?.recentRaw.length ?? 0} / {t('behavior_diag_recent_normalized')} {etwDiagnostics?.recentNormalized.length ?? 0} / {t('behavior_diag_capacity')} {etwDiagnostics?.capacity ?? 0}
                </div>
              </div>
            </div>
            <div className={styles.diagSection}>
              <div className={styles.diagSectionTitle}>
                {t('behavior_diag_hot_buckets')} {etwDiagnostics?.aggregateCapacity ?? 0} / {etwDiagnostics?.aggregateEvictions ?? 0}
              </div>
              <div className={styles.bucketGrid}>
                {aggregateBuckets.length === 0 ? (
                  <div className={`${styles.textMono} ${styles.mutedText}`}>
                    -
                  </div>
                ) : (
                  aggregateBuckets.map((bucket) => (
                    <div
                      key={bucket.key}
                      className={styles.bucketCard}
                    >
                      <div className={styles.bucketBadges}>
                        <Badge appearance="filled" color="informative">{bucket.stage}</Badge>
                        <Badge appearance="filled" color="warning">{bucket.count}</Badge>
                        {bucket.provider && <Badge appearance="filled" color="success">{bucket.provider}</Badge>}
                        {bucket.operation && <Badge appearance="filled" color="informative">{bucket.operation}</Badge>}
                        {bucket.ruleId && <Badge appearance="filled" color="warning">{bucket.ruleId}</Badge>}
                        {bucket.threatType && <Badge appearance="filled" color="danger">{bucket.threatType}</Badge>}
                      </div>
                      <div className={`${styles.textMono} ${styles.textWrap}`}>
                        {bucket.key}
                      </div>
                      <div className={`${styles.textMono} ${styles.mutedText}`}>
                        {bucket.firstSeen} → {bucket.lastSeen}
                      </div>
                      <div className={`${styles.textMono} ${styles.mutedText} ${styles.textWrap}`}>
                        {bucket.sample.path || bucket.pathKey || '-'}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
            {diagnosticsMessage && (
              <div className={styles.diagnosticsMessage}>
                {diagnosticsMessage}
              </div>
            )}
          </div>
          )}

          {/* 事件统计 / Event statistics */}
          <div className={styles.card}>
            <div className={styles.sectionHeader}>{t('behavior_event_stats')}</div>
            <div className={styles.statsGrid}>
              <div className={styles.statCard}>
                <div className={styles.statLabel}>{t('behavior_stats_total')}</div>
                <div className={styles.statValue}>{stats.total}</div>
              </div>
              <div className={`${styles.statCard} ${styles.statCardProcess}`}>
                <div className={`${styles.statLabel} ${styles.statLabelProcess}`}>{t('behavior_stats_process')}</div>
                <div className={`${styles.statValue} ${styles.statValueProcess}`}>{stats.processCount}</div>
              </div>
              <div className={`${styles.statCard} ${styles.statCardFile}`}>
                <div className={`${styles.statLabel} ${styles.statLabelFile}`}>{t('behavior_stats_file')}</div>
                <div className={`${styles.statValue} ${styles.statValueFile}`}>{stats.fileCount}</div>
              </div>
              <div className={`${styles.statCard} ${styles.statCardRegistry}`}>
                <div className={`${styles.statLabel} ${styles.statLabelRegistry}`}>{t('behavior_stats_registry')}</div>
                <div className={`${styles.statValue} ${styles.statValueRegistry}`}>{stats.registryCount}</div>
              </div>
            </div>
          </div>

          {/* 事件列表视图 / Event list view */}
          {viewMode === 'events' && (
            <div className={styles.tableContainer}>
              <div className={styles.tableToolbar}>
                <span className={styles.sectionHeader}>{t('behavior_realtime_events')}</span>
                <Badge appearance="filled" color="informative">{events.length} {t('behavior_event_count_unit')}</Badge>
              </div>

              <div className={styles.tableScroll}>
                {loading ? (
                  <div>
                    {[1, 2, 3, 4, 5].map((i) => (
                      <Skeleton key={i} className={styles.skeletonRow}>
                        <SkeletonItem className={styles.skeletonItem} />
                      </Skeleton>
                    ))}
                  </div>
                ) : events.length === 0 ? (
                  <div className={styles.emptyState}>
                    <Shield size={48} className={styles.emptyIcon} />
                    <p>{t('behavior_empty')}</p>
                  </div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHeaderCell>{t('behavior_th_ts')}</TableHeaderCell>
                        <TableHeaderCell>{t('behavior_label_pid')}</TableHeaderCell>
                        <TableHeaderCell>{t('behavior_th_type')}</TableHeaderCell>
                        <TableHeaderCell>{t('behavior_th_provider')}</TableHeaderCell>
                        <TableHeaderCell>{t('behavior_th_op')}</TableHeaderCell>
                        <TableHeaderCell>{t('behavior_th_target')}</TableHeaderCell>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {events.map((event, index) => (
                        <TableRow key={index}>
                          <TableCell className={styles.textMono}>{event.timestamp}</TableCell>
                          <TableCell>{event.pid}</TableCell>
                          <TableCell>
                            <Badge
                              appearance="filled"
                              color={event.type === 'Process' ? 'informative' : event.type === 'File' ? 'warning' : event.type === 'Network' ? 'success' : 'informative'}
                              className={getTypeBadgeClassName(event.type)}
                            >
                              {event.type}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge
                              appearance="filled"
                              color={event.provider?.toLowerCase().includes('hook') ? 'warning' : 'informative'}
                              title={event.provider}
                            >
                              {event.provider}
                            </Badge>
                          </TableCell>
                          <TableCell className={`${styles.textMono} ${styles.truncate}`} title={event.operation}>
                            {event.operation || '-'}
                          </TableCell>
                          <TableCell className={`${styles.textMono} ${styles.truncate}`} title={event.path}>
                            {event.path || '-'}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </div>
            </div>
          )}

          {/* 进程摘要视图 / Process summary view */}
          {viewMode === 'processes' && (
            <div className={styles.tableContainer}>
              <div className={styles.tableToolbar}>
                <span className={styles.sectionHeader}>{t('behavior_label_processes')}</span>
                <Badge appearance="filled" color="informative">{processes.length} {t('behavior_process_count_unit')}</Badge>
              </div>

              <div className={styles.tableScroll}>
                {processes.length === 0 ? (
                  <div className={styles.emptyState}>
                    <Shield size={48} className={styles.emptyIcon} />
                    <p>{t('behavior_empty')}</p>
                  </div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHeaderCell>{t('behavior_th_last_activity')}</TableHeaderCell>
                        <TableHeaderCell>{t('behavior_label_pid')}</TableHeaderCell>
                        <TableHeaderCell>{t('behavior_th_event_count')}</TableHeaderCell>
                        <TableHeaderCell>{t('behavior_th_process_name')}</TableHeaderCell>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {processes.map((proc, index) => (
                        <TableRow
                          key={index}
                          tabIndex={onOpenLifecycle ? 0 : undefined}
                          className={onOpenLifecycle ? styles.processRowInteractive : undefined}
                          onClick={() => onOpenLifecycle?.(proc.pid, proc.processName)}
                          onKeyDown={(e) => {
                            if (onOpenLifecycle && (e.key === 'Enter' || e.key === ' ')) {
                              e.preventDefault()
                              onOpenLifecycle(proc.pid, proc.processName)
                            }
                          }}
                        >
                          <TableCell className={styles.textMono}>{proc.lastSeen}</TableCell>
                          <TableCell>{proc.pid}</TableCell>
                          <TableCell>
                            <Badge appearance="filled" color="informative">
                              {proc.eventCount}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <strong>{proc.processName}</strong>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </section>
  )
}

export default BehaviorPage
