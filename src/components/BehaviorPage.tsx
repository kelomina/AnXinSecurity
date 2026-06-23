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
import { Play, Pause, Trash2, Shield, AlertTriangle, Download, RefreshCw } from 'lucide-react'
import {
  Button,
  Badge,
  makeStyles,
  shorthands,
  tokens,
  Skeleton,
  SkeletonItem,
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
  tableScroll: {
    maxHeight: '500px',
    overflowX: 'auto',
    overflowY: 'auto',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse' as const,
    fontSize: tokens.fontSizeBase300,
    '& thead': {
      backgroundColor: tokens.colorNeutralBackground3,
      position: 'sticky' as const,
      top: 0,
      zIndex: 1,
    },
    '& th': {
      ...shorthands.padding('12px', '16px'),
      textAlign: 'left' as const,
      fontWeight: tokens.fontWeightSemibold,
      color: tokens.colorNeutralForeground2,
      borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    },
    '& td': {
      ...shorthands.padding('12px', '16px'),
      borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    },
    '& tbody tr': {
      ':hover': {
        backgroundColor: tokens.colorNeutralBackground1Hover,
      },
    },
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
  const { config } = useConfigStore()
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
    loadEtwDiagnostics()

    return () => {
      unlisten()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [edrEnabled])

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
   * 获取事件类型 badge 样式 / Get event type badge style
   * Registry 类型需要自定义紫色样式 / Registry type needs custom purple style
   */
  const getTypeBadgeStyle = (type: string): React.CSSProperties | undefined => {
    if (type === 'Registry') {
      return { background: 'rgba(143,112,177,0.13)', color: '#8F70B1' }
    }
    return undefined
  }

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
          <span style={{ color: tokens.colorNeutralForeground3, fontSize: tokens.fontSizeBase200, marginLeft: '4px' }}>
            Hook: {fileHookEventCount}
          </span>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: '8px' }}>
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
        <div className={styles.card} style={{ padding: '48px', textAlign: 'center' }}>
          <Shield size={64} style={{ color: tokens.colorNeutralForeground3, marginBottom: '16px', opacity: 0.3 }} />
          <p style={{ color: tokens.colorNeutralForeground3, fontSize: tokens.fontSizeBase300 }}>
            {t('behavior_edr_disabled_hint')}
          </p>
        </div>
      ) : (
        <>
          {/* ETW 现场诊断 / ETW field diagnostics */}
          <div className={styles.card}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <div style={{ fontWeight: tokens.fontWeightSemibold, fontSize: tokens.fontSizeBase300 }}>{t('behavior_diag_title')}</div>
              <Badge
                appearance="filled"
                color={etwDiagnostics?.collecting ? 'success' : 'warning'}
              >
                {etwDiagnostics?.collecting ? t('behavior_diag_collecting') : t('behavior_diag_not_collecting')}
              </Badge>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: '8px' }}>
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
            <p style={{ color: tokens.colorNeutralForeground3, fontSize: tokens.fontSizeBase200, marginBottom: '12px' }}>
              {t('behavior_diag_desc')}
            </p>
            <div className={styles.statsGrid}>
              <div className={styles.diagCard}>
                <div className={styles.diagLabel}>{t('behavior_diag_total_raw')}</div>
                <div className={styles.diagValue} style={{ fontSize: tokens.fontSizeBase500, fontWeight: tokens.fontWeightSemibold }}>{etwDiagnostics?.totalRaw ?? 0}</div>
              </div>
              <div className={styles.diagCard}>
                <div className={styles.diagLabel}>{t('behavior_diag_after_filter')}</div>
                <div className={styles.diagValue} style={{ fontSize: tokens.fontSizeBase500, fontWeight: tokens.fontWeightSemibold }}>{etwDiagnostics?.totalAfterFilter ?? 0}</div>
              </div>
              <div className={styles.diagCard}>
                <div className={styles.diagLabel}>{t('behavior_diag_matched')}</div>
                <div className={styles.diagValue} style={{ fontSize: tokens.fontSizeBase500, fontWeight: tokens.fontWeightSemibold }}>{etwDiagnostics?.totalMatched ?? 0}</div>
              </div>
              <div className={styles.diagCard}>
                <div className={styles.diagLabel}>{t('behavior_diag_dropped')}</div>
                <div className={styles.diagValue} style={{ fontSize: tokens.fontSizeBase500, fontWeight: tokens.fontWeightSemibold }}>{etwDiagnostics?.totalDroppedSystemPid ?? 0}</div>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: tokens.fontSizeBase200 }}>
              <div>
                <div style={{ color: tokens.colorNeutralForeground3, marginBottom: '4px' }}>{t('behavior_diag_provider_counts')}</div>
                <div className={styles.textMono} style={{ wordBreak: 'break-word' }}>
                  {formatTopCounters(etwDiagnostics?.providerCounts)}
                </div>
              </div>
              <div>
                <div style={{ color: 'var(--muted-fg)', marginBottom: '4px' }}>{t('behavior_diag_operation_counts')}</div>
                <div className="text-mono" style={{ wordBreak: 'break-word' }}>
                  {formatTopCounters(etwDiagnostics?.operationCounts)}
                </div>
              </div>
              <div>
                <div style={{ color: 'var(--muted-fg)', marginBottom: '4px' }}>{t('behavior_diag_rule_counts')}</div>
                <div className="text-mono" style={{ wordBreak: 'break-word' }}>
                  {formatTopCounters(etwDiagnostics?.ruleCounts)}
                </div>
              </div>
              <div>
                <div style={{ color: 'var(--muted-fg)', marginBottom: '4px' }}>{t('behavior_diag_recent_counts')}</div>
                <div className="text-mono">
                  {t('behavior_diag_recent_raw')} {etwDiagnostics?.recentRaw.length ?? 0} / {t('behavior_diag_recent_normalized')} {etwDiagnostics?.recentNormalized.length ?? 0} / {t('behavior_diag_capacity')} {etwDiagnostics?.capacity ?? 0}
                </div>
              </div>
            </div>
            <div style={{ marginTop: '12px' }}>
              <div style={{ color: 'var(--muted-fg)', marginBottom: '8px', fontSize: '12px' }}>
                {t('behavior_diag_hot_buckets')} {etwDiagnostics?.aggregateCapacity ?? 0} / {etwDiagnostics?.aggregateEvictions ?? 0}
              </div>
              <div style={{ display: 'grid', gap: '8px' }}>
                {aggregateBuckets.length === 0 ? (
                  <div className="text-mono" style={{ color: 'var(--muted-fg)' }}>
                    -
                  </div>
                ) : (
                  aggregateBuckets.map((bucket) => (
                    <div
                      key={bucket.key}
                      style={{
                        padding: '10px 12px',
                        background: 'var(--input-bg)',
                        borderRadius: 'var(--radius-medium)',
                        border: '1px solid var(--border-color)',
                        display: 'grid',
                        gap: '4px'
                      }}
                    >
                      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
                        <Badge appearance="filled" color="informative">{bucket.stage}</Badge>
                        <Badge appearance="filled" color="warning">{bucket.count}</Badge>
                        {bucket.provider && <Badge appearance="filled" color="success">{bucket.provider}</Badge>}
                        {bucket.operation && <Badge appearance="filled" color="informative">{bucket.operation}</Badge>}
                        {bucket.ruleId && <Badge appearance="filled" color="warning">{bucket.ruleId}</Badge>}
                        {bucket.threatType && <Badge appearance="filled" color="danger">{bucket.threatType}</Badge>}
                      </div>
                      <div className={styles.textMono} style={{ fontSize: tokens.fontSizeBase200, wordBreak: 'break-word' }}>
                        {bucket.key}
                      </div>
                      <div style={{ fontSize: tokens.fontSizeBase200, color: tokens.colorNeutralForeground3 }}>
                        {bucket.firstSeen} → {bucket.lastSeen}
                      </div>
                      <div style={{ fontSize: tokens.fontSizeBase200, color: tokens.colorNeutralForeground3, wordBreak: 'break-word' }}>
                        {bucket.sample.path || bucket.pathKey || '-'}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
            {diagnosticsMessage && (
              <div style={{ marginTop: '12px', fontSize: tokens.fontSizeBase200, color: tokens.colorNeutralForeground3, wordBreak: 'break-all' }}>
                {diagnosticsMessage}
              </div>
            )}
          </div>

          {/* 事件统计 / Event statistics */}
          <div className={styles.card}>
            <div style={{ fontWeight: tokens.fontWeightSemibold, fontSize: tokens.fontSizeBase300, marginBottom: '12px' }}>{t('behavior_event_stats')}</div>
            <div className={styles.statsGrid}>
              <div className={styles.statCard}>
                <div className={styles.statLabel}>{t('behavior_stats_total')}</div>
                <div className={styles.statValue}>{stats.total}</div>
              </div>
              <div className={styles.statCard} style={{ backgroundColor: tokens.colorPaletteBlueBorderActive }}>
                <div style={{ fontSize: tokens.fontSizeBase200, color: tokens.colorPaletteBlueForeground2 }}>{t('behavior_stats_process')}</div>
                <div style={{ fontSize: tokens.fontSizeBase500, fontWeight: tokens.fontWeightSemibold, color: tokens.colorPaletteBlueForeground2 }}>{stats.processCount}</div>
              </div>
              <div className={styles.statCard} style={{ backgroundColor: tokens.colorPaletteYellowBackground2 }}>
                <div style={{ fontSize: tokens.fontSizeBase200, color: tokens.colorPaletteYellowForeground2 }}>{t('behavior_stats_file')}</div>
                <div style={{ fontSize: tokens.fontSizeBase500, fontWeight: tokens.fontWeightSemibold, color: tokens.colorPaletteYellowForeground2 }}>{stats.fileCount}</div>
              </div>
              <div className={styles.statCard} style={{ backgroundColor: 'rgba(143,112,177,0.13)' }}>
                <div style={{ fontSize: tokens.fontSizeBase200, color: '#8F70B1' }}>{t('behavior_stats_registry')}</div>
                <div style={{ fontSize: tokens.fontSizeBase500, fontWeight: tokens.fontWeightSemibold, color: '#8F70B1' }}>{stats.registryCount}</div>
              </div>
            </div>
          </div>

          {/* 事件列表视图 / Event list view */}
          {viewMode === 'events' && (
            <div className={styles.tableContainer}>
              <div className={styles.tableToolbar}>
                <span style={{ fontWeight: tokens.fontWeightSemibold, fontSize: tokens.fontSizeBase300 }}>{t('behavior_realtime_events')}</span>
                <Badge appearance="filled" color="informative">{events.length} {t('behavior_event_count_unit')}</Badge>
              </div>

              <div className={styles.tableScroll}>
                {loading ? (
                  <div>
                    {[1, 2, 3, 4, 5].map((i) => (
                      <Skeleton key={i} style={{ marginBottom: '8px' }}>
                        <SkeletonItem style={{ height: '40px' }} />
                      </Skeleton>
                    ))}
                  </div>
                ) : events.length === 0 ? (
                  <div className={styles.emptyState}>
                    <Shield size={48} className={styles.emptyIcon} />
                    <p>{t('behavior_empty')}</p>
                  </div>
                ) : (
                  <table className={styles.table}>
                    <thead>
                      <tr>
                        <th>{t('behavior_th_ts')}</th>
                        <th>{t('behavior_label_pid')}</th>
                        <th>{t('behavior_th_type')}</th>
                        <th>{t('behavior_th_provider')}</th>
                        <th>{t('behavior_th_op')}</th>
                        <th>{t('behavior_th_target')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {events.map((event, index) => (
                        <tr key={index}>
                          <td className={styles.textMono}>{event.timestamp}</td>
                          <td>{event.pid}</td>
                          <td>
                            <Badge
                              appearance="filled"
                              color={event.type === 'Process' ? 'informative' : event.type === 'File' ? 'warning' : event.type === 'Network' ? 'success' : 'informative'}
                              style={getTypeBadgeStyle(event.type)}
                            >
                              {event.type}
                            </Badge>
                          </td>
                          <td>
                            <Badge
                              appearance="filled"
                              color={event.provider?.toLowerCase().includes('hook') ? 'warning' : 'informative'}
                              title={event.provider}
                            >
                              {event.provider}
                            </Badge>
                          </td>
                          <td className={`${styles.textMono} ${styles.truncate}`} title={event.operation}>
                            {event.operation || '-'}
                          </td>
                          <td className={`${styles.textMono} ${styles.truncate}`} title={event.path}>
                            {event.path || '-'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          )}

          {/* 进程摘要视图 / Process summary view */}
          {viewMode === 'processes' && (
            <div className={styles.tableContainer}>
              <div className={styles.tableToolbar}>
                <span style={{ fontWeight: tokens.fontWeightSemibold, fontSize: tokens.fontSizeBase300 }}>{t('behavior_label_processes')}</span>
                <Badge appearance="filled" color="informative">{processes.length} {t('behavior_process_count_unit')}</Badge>
              </div>

              <div className={styles.tableScroll}>
                {processes.length === 0 ? (
                  <div className={styles.emptyState}>
                    <Shield size={48} className={styles.emptyIcon} />
                    <p>{t('behavior_empty')}</p>
                  </div>
                ) : (
                  <table className={styles.table}>
                    <thead>
                      <tr>
                        <th>{t('behavior_th_last_activity')}</th>
                        <th>{t('behavior_label_pid')}</th>
                        <th>{t('behavior_th_event_count')}</th>
                        <th>{t('behavior_th_process_name')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {processes.map((proc, index) => (
                        <tr
                          key={index}
                          style={{ cursor: onOpenLifecycle ? 'pointer' : 'default' }}
                          onClick={() => onOpenLifecycle?.(proc.pid, proc.processName)}
                        >
                          <td className={styles.textMono}>{proc.lastSeen}</td>
                          <td>{proc.pid}</td>
                          <td>
                            <Badge appearance="filled" color="informative">
                              {proc.eventCount}
                            </Badge>
                          </td>
                          <td>
                            <strong>{proc.processName}</strong>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
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
