/**
 * 进程生命周期页 — 采集健康 + BYOVD 探针 + 进程树 + 生命周期事件流
 * Process lifecycle page — collector health + BYOVD probe + process tree + lifecycle events
 *
 * 展示 AnXinProcMon 驱动的运行状态（§4.6 命令 / §13.7 探针告警）：
 * - 健康卡片：驱动连接、版本、队列水位、回调活性心跳
 * - 探针卡片：BYOVD 主动探针统计（发射/回报/失败/告警/纠偏）
 * - 回调失明告警横幅（process-monitor-tampered）
 * - 进程树（get_process_tree）
 * - 生命周期事件列表（list_lifecycle_events + process-lifecycle-event 实时）
 *
 * 调用方：App.tsx (currentPage === 'process-lifecycle')
 * Called by: App.tsx (currentPage === 'process-lifecycle')
 *
 * 中文关键词：进程生命周期，探针统计，进程树，回调失明告警，健康状态
 * English keywords: process lifecycle, probe stats, process tree, callback-blindness alert, health
 */
import React, { useEffect, useState, useCallback, useMemo } from 'react'
import { makeStyles, shorthands, tokens, Badge, Button, Card, Skeleton, SkeletonItem } from '@fluentui/react-components'
import { useI18nStore } from '../stores/i18nStore'
import {
  getProcMonitorHealth,
  getProcessTree,
  listLifecycleEvents,
  onProcessLifecycleEvent,
  onProcessMonitorTampered,
  type ProcMonitorHealth,
  type ProcessTreeNode,
  type LifecycleEvent,
  type TamperedAlert,
  type LifecyclePush,
  EVENT_TYPE_NAMES,
  PROC_FLAG_PPID_SPOOFED,
  PROC_FLAG_TOKEN_ELEVATED,
  PROC_FLAG_TOKEN_HIGH_INTEGRITY,
} from '../api/processLifecycle'
import { AlertTriangle, CheckCircle, RefreshCw, Activity } from './icons'

const useStyles = makeStyles({
  page: {
    maxWidth: '1400px',
    margin: '0 auto',
    paddingBottom: '24px',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('12px'),
    marginBottom: '16px',
  },
  pageTitle: {
    fontSize: tokens.fontSizeBase600,
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground1,
    marginTop: 0,
    marginBottom: '4px',
  },
  subtitle: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
    margin: 0,
  },
  cards: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
    ...shorthands.gap('12px'),
    marginBottom: '20px',
  },
  card: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('16px'),
  },
  cardTitle: {
    fontSize: tokens.fontSizeBase300,
    fontWeight: tokens.fontWeightSemibold,
    marginTop: 0,
    marginBottom: '12px',
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('8px'),
  },
  statRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '6px',
    fontSize: tokens.fontSizeBase200,
  },
  statLabel: {
    color: tokens.colorNeutralForeground3,
  },
  statValue: {
    color: tokens.colorNeutralForeground1,
    fontFamily: 'Consolas, "Courier New", monospace',
  },
  banner: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('12px'),
    backgroundColor: tokens.colorPaletteRedBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorPaletteRedBorderActive),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('12px', '16px'),
    marginBottom: '20px',
  },
  bannerText: {
    margin: 0,
    color: tokens.colorPaletteRedForeground2,
    fontSize: tokens.fontSizeBase300,
    fontWeight: tokens.fontWeightSemibold,
    flexGrow: 1,
  },
  bannerSub: {
    margin: 0,
    color: tokens.colorPaletteRedForeground2,
    fontSize: tokens.fontSizeBase200,
    opacity: 0.85,
  },
  sectionTitle: {
    fontSize: tokens.fontSizeBase400,
    fontWeight: tokens.fontWeightSemibold,
    marginBottom: '12px',
    color: tokens.colorNeutralForeground1,
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('8px'),
  },
  tree: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('12px', '16px'),
    marginBottom: '20px',
    maxHeight: '360px',
    overflowY: 'auto',
  },
  treeNode: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('8px'),
    padding: '2px 0',
    fontSize: tokens.fontSizeBase200,
  },
  treeNodeLine: {
    fontFamily: 'Consolas, "Courier New", monospace',
    color: tokens.colorNeutralForeground2,
  },
  treePath: {
    color: tokens.colorNeutralForeground3,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    maxWidth: '420px',
  },
  eventList: {},
  eventItem: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.padding('10px', '16px'),
    marginBottom: '8px',
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('12px'),
    flexWrap: 'wrap',
  },
  eventTimestamp: {
    fontSize: tokens.fontSizeBase200,
    fontFamily: 'Consolas, "Courier New", monospace',
    color: tokens.colorNeutralForeground3,
  },
  eventPid: {
    fontSize: tokens.fontSizeBase200,
    fontFamily: 'Consolas, "Courier New", monospace',
    color: tokens.colorNeutralForeground3,
  },
  eventPath: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground2,
    marginLeft: 'auto',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    maxWidth: '360px',
  },
  emptyState: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('32px', '20px'),
    textAlign: 'center' as const,
    color: tokens.colorNeutralForeground3,
    fontSize: tokens.fontSizeBase200,
  },
  errorText: {
    color: tokens.colorPaletteRedForeground2,
    marginBottom: '8px',
  },
  skeletonRow: {
    marginBottom: '8px',
  },
  skeletonItem: {
    height: '48px',
  },
  headerActions: {
    marginLeft: 'auto',
  },
  badge: {
    fontSize: tokens.fontSizeBase100,
    fontFamily: 'Consolas, "Courier New", monospace',
  },
})

/** 递归渲染进程树 / Recursively render the process tree */
function renderTree(nodes: ProcessTreeNode[], t: (k: string, f?: string) => string, depth = 0): React.ReactNode {
  return nodes.map((node) => (
    <div key={node.pid}>
      <div className="tree-node-inline" style={{ paddingLeft: `${depth * 20}px` }}>
        <span style={{ fontFamily: 'Consolas, "Courier New", monospace', color: 'var(--colorNeutralForeground2, #616161)' }}>
          {depth > 0 ? '└─ ' : ''}{node.pid}
        </span>
        <span style={{ color: 'var(--colorNeutralForeground3, #8a8a8a)' }}>
          {node.imagePath ? ` ${node.imagePath}` : ' (unknown path)'}
        </span>
        {node.restored && (
          <Badge appearance="outline" color="warning" size="small">
            {t('process_lifecycle_restored')}
          </Badge>
        )}
        <Badge appearance="filled" color={node.alive ? 'success' : 'danger'} size="small">
          {node.alive ? t('process_lifecycle_alive') : t('process_lifecycle_exited')}
        </Badge>
      </div>
      {node.children.length > 0 && renderTree(node.children, t, depth + 1)}
    </div>
  ))
}

const ProcessLifecyclePage: React.FC = () => {
  const styles = useStyles()
  const { t } = useI18nStore()
  const [health, setHealth] = useState<ProcMonitorHealth | null>(null)
  const [tree, setTree] = useState<ProcessTreeNode[]>([])
  const [events, setEvents] = useState<LifecycleEvent[]>([])
  const [alert, setAlert] = useState<TamperedAlert | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  /**
   * 函数名称：refreshAll
   * 函数作用：拉取健康状态、进程树与事件列表。
   * Purpose: Fetches health, process tree and the event list.
   * 调用方：页面初始化、刷新按钮、实时事件回调（局部刷新）
   * Called by: page init, refresh button, realtime callbacks (partial refresh)
   * 中文关键词：刷新，健康状态，进程树，事件列表
   * English keywords: refresh, health status, process tree, event list
   */
  const refreshAll = useCallback(async () => {
    try {
      setError(null)
      const [h, tr, ev] = await Promise.all([
        getProcMonitorHealth(),
        getProcessTree(),
        listLifecycleEvents(500),
      ])
      setHealth(h)
      setTree(tr)
      setEvents(ev)
    } catch (e) {
      setError(`${t('process_lifecycle_load_error')}: ${e}`)
    } finally {
      setLoading(false)
    }
    // t 参与错误文案拼装，进依赖数组；语言切换后重拉以新语言报错。
    //  t builds the error message; switching language reloads with the new language.
  }, [t])

  useEffect(() => {
    void refreshAll()

    // 实时生命周期事件（create/exit 追加到列表头） / realtime lifecycle events
    const offLifecycle = onProcessLifecycleEvent((payload: LifecyclePush) => {
      setEvents((prev) => {
        const record: LifecycleEvent = {
          pid: payload.pid,
          parentPid: payload.parentPid ?? 0,
          eventType: payload.event === 'create' ? 1 : 2,
          eventTime: payload.ts ?? 0,
          tsMs: payload.ts ? Math.floor(payload.ts / 10000) : Date.now(),
          sessionId: payload.sessionId ?? 0,
          exitStatus: payload.exitStatus ?? 0,
          flags: payload.flags ?? 0,
          imagePath: payload.imagePath ?? null,
          restored: false,
        }
        return [record, ...prev].slice(0, 500)
      })
    })

    // 回调失明告警 / callback-blindness alert
    const offTampered = onProcessMonitorTampered((payload: TamperedAlert) => {
      setAlert(payload)
      // 告警同时触发一次状态刷新，前端能看到纠偏后的进程树
      //  The alert triggers a state refresh so the reconciled tree becomes visible.
      void getProcessTree().then(setTree).catch(() => undefined)
    })

    return () => {
      offLifecycle()
      offTampered()
    }
  }, [refreshAll])

  /** 格式化毫秒时间戳 / Format an epoch-ms timestamp */
  const formatTs = (tsMs: number) => {
    if (!tsMs) return '-'
    try {
      return new Date(tsMs).toLocaleTimeString('zh-CN', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        fractionalDigits: 3,
      } as Intl.DateTimeFormatOptions)
    } catch {
      return String(tsMs)
    }
  }

  /** 事件类型展示名 / Event type display name */
  const eventTypeName = (t: (k: string, f?: string) => string, type: number): string => {
    const name = EVENT_TYPE_NAMES[type]
    if (!name) return `#${type}`
    const key = `process_lifecycle_event_${name}`
    const localized = t(key)
    return localized === key ? name : localized
  }

  /** 事件标志徽章 / Event-flag badges */
  const flagBadges = useMemo(() => {
    return (flags: number): string[] => {
      const badges: string[] = []
      if (flags & PROC_FLAG_PPID_SPOOFED) badges.push('PPID-SPOOF')
      if (flags & PROC_FLAG_TOKEN_ELEVATED) badges.push('ELEVATED')
      if (flags & PROC_FLAG_TOKEN_HIGH_INTEGRITY) badges.push('HIGH-INTEGRITY')
      return badges
    }
  }, [])

  const driverVersion = health
    ? `${health.driverMajor}.${health.driverMinor}.${health.driverPatch}`
    : '-'

  return (
    <div className={styles.page}>
      {/* 头部 / Header */}
      <div className={styles.header}>
        <div>
          <h2 className={styles.pageTitle}>{t('process_lifecycle_title')}</h2>
          <p className={styles.subtitle}>{t('process_lifecycle_subtitle')}</p>
        </div>
        <div className={styles.headerActions}>
          <Button
            appearance="outline"
            icon={<RefreshCw size={16} />}
            onClick={() => {
              setLoading(true)
              void refreshAll()
            }}
          >
            {t('process_lifecycle_refresh')}
          </Button>
        </div>
      </div>

      {/* 错误提示 / Error display */}
      {error && (
        <div className={styles.banner}>
          <AlertTriangle size={18} color={tokens.colorPaletteRedForeground2} />
          <p className={styles.bannerText}>{error}</p>
          <Button appearance="outline" onClick={() => { setLoading(true); void refreshAll() }}>
            {t('process_lifecycle_retry')}
          </Button>
        </div>
      )}

      {/* 回调失明告警横幅 / Callback-blindness alert banner */}
      {alert && (
        <div className={styles.banner} role="alert">
          <AlertTriangle size={22} color={tokens.colorPaletteRedForeground2} />
          <div>
            <p className={styles.bannerText}>{t('process_lifecycle_tampered_title')}</p>
            <p className={styles.bannerSub}>
              {t('process_lifecycle_tampered_detail')} ({alert.missingSeconds}s)
              {alert.reconciledProcesses > 0
                ? ` / ${t('process_lifecycle_tampered_reconciled')} ${alert.reconciledProcesses}`
                : ''}
            </p>
          </div>
        </div>
      )}

      {/* 加载骨架 / Loading skeleton */}
      {loading && !health && (
        <div>
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className={styles.skeletonRow}>
              <SkeletonItem className={styles.skeletonItem} />
            </Skeleton>
          ))}
        </div>
      )}

      {/* 健康 + 探针卡片 / Health + probe cards */}
      {health && (
        <div className={styles.cards}>
          <Card className={styles.card}>
            <h3 className={styles.cardTitle}>
              <Activity size={16} />
              {t('process_lifecycle_health_card')}
            </h3>
            <div className={styles.statRow}>
              <span className={styles.statLabel}>{t('process_lifecycle_status')}</span>
              {health.connected ? (
                <Badge appearance="filled" color="success">{t('process_lifecycle_connected')}</Badge>
              ) : (
                <Badge appearance="filled" color="danger">{t('process_lifecycle_disconnected')}</Badge>
              )}
            </div>
            <div className={styles.statRow}>
              <span className={styles.statLabel}>{t('process_lifecycle_driver_version')}</span>
              <span className={styles.statValue}>{driverVersion}</span>
            </div>
            <div className={styles.statRow}>
              <span className={styles.statLabel}>{t('process_lifecycle_table_size')}</span>
              <span className={styles.statValue}>{health.tableSize}</span>
            </div>
            <div className={styles.statRow}>
              <span className={styles.statLabel}>{t('process_lifecycle_queue_depth')}</span>
              <span className={styles.statValue}>
                L:{health.lifecycleDepth} / B:{health.behaviorDepth}
              </span>
            </div>
            <div className={styles.statRow}>
              <span className={styles.statLabel}>{t('process_lifecycle_dropped')}</span>
              <span className={styles.statValue}>
                L:{health.lifecycleDropped} / B:{health.behaviorDropped}
              </span>
            </div>
            <div className={styles.statRow}>
              <span className={styles.statLabel}>{t('process_lifecycle_last_callback')}</span>
              <span className={styles.statValue}>{health.lastCallbackTickMs} ms</span>
            </div>
          </Card>

          <Card className={styles.card}>
            <h3 className={styles.cardTitle}>
              <CheckCircle size={16} />
              {t('process_lifecycle_probe_card')}
            </h3>
            <div className={styles.statRow}>
              <span className={styles.statLabel}>{t('process_lifecycle_probe_total')}</span>
              <span className={styles.statValue}>{health.probeTotal}</span>
            </div>
            <div className={styles.statRow}>
              <span className={styles.statLabel}>{t('process_lifecycle_probe_reported')}</span>
              <span className={styles.statValue}>{health.probeReportedOk}</span>
            </div>
            <div className={styles.statRow}>
              <span className={styles.statLabel}>{t('process_lifecycle_probe_missed')}</span>
              <span className={styles.statValue}>{health.probeMissedRounds}</span>
            </div>
            <div className={styles.statRow}>
              <span className={styles.statLabel}>{t('process_lifecycle_probe_alerts')}</span>
              <span className={styles.statValue}>{health.tamperedAlerts}</span>
            </div>
            <div className={styles.statRow}>
              <span className={styles.statLabel}>{t('process_lifecycle_probe_reconciled')}</span>
              <span className={styles.statValue}>{health.lastReconcileCount}</span>
            </div>
          </Card>
        </div>
      )}

      {/* 进程树 / Process tree */}
      {health && (
        <>
          <h3 className={styles.sectionTitle}>
            <Activity size={16} />
            {t('process_lifecycle_tree_title')} ({tree.length})
          </h3>
          {tree.length > 0 ? (
            <div className={styles.tree}>{renderTree(tree, t)}</div>
          ) : (
            <div className={styles.emptyState}>{t('process_lifecycle_tree_empty')}</div>
          )}
        </>
      )}

      {/* 生命周期事件列表 / Lifecycle event list */}
      <h3 className={styles.sectionTitle}>
        <Activity size={16} />
        {t('process_lifecycle_events_title')} ({events.length})
      </h3>
      {events.length > 0 ? (
        <div className={styles.eventList}>
          {events.map((event, index) => {
            const badges = flagBadges(event.flags)
            return (
              <div key={`${event.pid}-${event.eventTime}-${index}`} className={styles.eventItem}>
                <span className={styles.eventTimestamp}>{formatTs(event.tsMs)}</span>
                <span className={styles.eventPid}>PID:{event.pid}</span>
                <Badge
                  appearance="filled"
                  color={event.eventType === 1 ? 'success' : event.eventType === 2 ? 'danger' : 'subtle'}
                  className={styles.badge}
                >
                  {eventTypeName(t, event.eventType)}
                </Badge>
                {event.restored && (
                  <Badge appearance="outline" color="warning" size="small" className={styles.badge}>
                    {t('process_lifecycle_restored')}
                  </Badge>
                )}
                {badges.map((b) => (
                  <Badge key={b} appearance="filled" color="danger" size="small" className={styles.badge}>
                    {b}
                  </Badge>
                ))}
                <span className={styles.eventPath}>{event.imagePath || ''}</span>
              </div>
            )
          })}
        </div>
      ) : (
        <div className={styles.emptyState}>{t('process_lifecycle_events_empty')}</div>
      )}
    </div>
  )
}

export default ProcessLifecyclePage
