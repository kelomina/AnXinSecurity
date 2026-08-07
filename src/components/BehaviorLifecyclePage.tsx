/**
 * 行为生命周期页 — 进程详情 + 事件时间线 + MITRE ATT&CK 映射
 * Behavior lifecycle page — process detail + event timeline + MITRE ATT&CK mapping
 *
 * 展示单个进程的完整行为时间线和威胁映射。
 * Displays the complete behavior timeline and threat mapping for a single process.
 *
 * 调用方：App.tsx (currentPage === 'behavior-lifecycle')
 * Called by: App.tsx (currentPage === 'behavior-lifecycle')
 *
 * 中文关键词：行为生命周期，进程时间线，MITRE ATT&CK，威胁映射
 * English keywords: behavior lifecycle, process timeline, MITRE ATT&CK, threat mapping
 */
import React, { useEffect, useState, useMemo, useCallback } from 'react'
import { listen } from '@tauri-apps/api/event'
import { listEvents } from '../api/behavior'
import { loadMitreRules, type MitreRule } from '../api/scanRules'
import type { EtwEvent } from '../api/behavior'
import { ArrowLeft, Search } from './icons'
import { useI18nStore } from '../stores/i18nStore'
import {
  Button,
  Badge,
  makeStyles,
  shorthands,
  tokens,
  Skeleton,
  SkeletonItem,
} from '@fluentui/react-components'

/** MITRE ATT&CK 映射项 / MITRE ATT&CK mapping entry */
interface MitreMapping {
  tactic: string
  techniqueId: string
  techniqueName: string
}

/** 默认 MITRE 规则（API 不可用时的兜底）/ Default MITRE rules (fallback when API unavailable) */
const DEFAULT_MITRE_RULES: Record<string, MitreMapping> = {
  'Process:Start': { tactic: 'Execution', techniqueId: 'T1106', techniqueName: 'Native API' },
  'Process:Stop': { tactic: 'Impact', techniqueId: 'T1485', techniqueName: 'Data Destruction' },
  'File:Create': { tactic: 'Collection', techniqueId: 'T1005', techniqueName: 'Data from Local System' },
  'File:Delete': { tactic: 'Defense Evasion', techniqueId: 'T1070', techniqueName: 'Indicator Removal' },
  'File:Rename': { tactic: 'Defense Evasion', techniqueId: 'T1070', techniqueName: 'Indicator Removal' },
  'Registry:SetValue': { tactic: 'Persistence', techniqueId: 'T1112', techniqueName: 'Modify Registry' },
  'Registry:CreateKey': { tactic: 'Persistence', techniqueId: 'T1112', techniqueName: 'Modify Registry' },
  'Registry:DeleteValue': { tactic: 'Defense Evasion', techniqueId: 'T1112', techniqueName: 'Modify Registry' },
  'Network:Connect': { tactic: 'Command and Control', techniqueId: 'T1071', techniqueName: 'Application Layer Protocol' },
}

type MitreRulesMap = Record<string, MitreMapping>

/** 将 API 返回的规则数组转换为 key → 映射 的查找表 / Convert API rules array to key→mapping lookup table */
function buildMitreMap(rules: MitreRule[]): MitreRulesMap {
  const map: MitreRulesMap = {}
  for (const r of rules) {
    const key = `${r.provider}:${r.op}`
    map[key] = { tactic: r.tactic, techniqueId: r.techniqueId, techniqueName: r.techniqueName }
  }
  return map
}

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
    marginBottom: '24px',
  },
  pageTitle: {
    fontSize: tokens.fontSizeBase600,
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground1,
    marginTop: 0,
    marginBottom: '4px',
  },
  pidLabel: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
    fontFamily: 'Consolas, "Courier New", monospace',
  },
  errorCard: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorPaletteRedBorderActive),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('16px'),
    marginBottom: '16px',
  },
  errorText: {
    color: tokens.colorPaletteRedForeground2,
    marginTop: 0,
    marginBottom: '8px',
  },
  sectionTitle: {
    fontSize: tokens.fontSizeBase400,
    fontWeight: tokens.fontWeightSemibold,
    marginBottom: '12px',
    color: tokens.colorNeutralForeground1,
  },
  tacticGrid: {
    display: 'flex',
    flexWrap: 'wrap',
    ...shorthands.gap('8px'),
    marginBottom: '20px',
  },
  tacticSection: {
    marginBottom: '20px',
  },
  tacticCard: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.padding('8px', '16px'),
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('8px'),
  },
  tacticName: {
    fontWeight: tokens.fontWeightSemibold,
    fontSize: tokens.fontSizeBase200,
  },
  eventList: {},
  eventItem: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.padding('12px', '16px'),
    marginBottom: '8px',
    cursor: 'pointer',
    transitionProperty: 'all',
    transitionDuration: tokens.durationNormal,
    ':hover': {
      backgroundColor: tokens.colorNeutralBackground1Hover,
      boxShadow: tokens.shadow4,
    },
  },
  eventHeader: {
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
  eventProvider: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground2,
    marginLeft: 'auto',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  eventDetails: {
    marginTop: '12px',
    ...shorthands.padding('12px'),
    backgroundColor: tokens.colorNeutralBackground3,
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    fontSize: tokens.fontSizeBase200,
    fontFamily: 'Consolas, "Courier New", monospace',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    maxHeight: '300px',
    overflowY: 'auto',
    color: tokens.colorNeutralForeground2,
  },
  emptyState: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('40px', '20px'),
    textAlign: 'center' as const,
  },
  emptyIcon: {
    fontSize: '48px',
    marginBottom: '16px',
  },
  emptyText: {
    color: tokens.colorNeutralForeground3,
    marginTop: 0,
    marginBottom: '8px',
  },
  emptySubtext: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
    marginTop: 0,
  },
  mitreTag: {
    fontSize: tokens.fontSizeBase100,
    color: tokens.colorNeutralForeground3,
    fontFamily: 'Consolas, "Courier New", monospace',
  },
  skeletonRow: {
    marginBottom: '8px',
  },
  skeletonItem: {
    height: '48px',
  },
  mutedText: {
    color: tokens.colorNeutralForeground3,
  },
})

interface BehaviorLifecyclePageProps {
  pid: number
  processName: string
  onBack: () => void
}

const BehaviorLifecyclePage: React.FC<BehaviorLifecyclePageProps> = ({ pid, processName, onBack }) => {
  const styles = useStyles()
  const { t } = useI18nStore()
  const [events, setEvents] = useState<EtwEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null)
  const [mitreRules, setMitreRules] = useState<MitreRulesMap>(DEFAULT_MITRE_RULES)

  /** 从配置文件加载 MITRE 规则 / Load MITRE rules from config */
  const loadMitreConfig = useCallback(async () => {
    try {
      const rules = await loadMitreRules()
      if (rules.length > 0) {
        setMitreRules(buildMitreMap(rules))
      }
    } catch {
      // API 不可用时使用默认规则 / Use default rules when API unavailable
    }
  }, [])

  /**
   * 函数名称：loadEvents
   * 函数作用：按当前 PID 加载行为事件列表。
   * Purpose: Loads behavior events for the current PID.
   * 调用方：页面初始化 useEffect，错误重试按钮。
   * Called by: page initialization useEffect, error retry button.
   * 中文关键词：行为事件，进程详情，重试加载
   * English keywords: behavior events, process detail, retry loading
   */
  const loadEvents = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const result = await listEvents({ pid, limit: 200 })
      setEvents(result)
    } catch (e) {
      setError(`${t('behavior_lifecycle_load_error')}: ${e}`)
    } finally {
      setLoading(false)
    }
    // t 参与错误文案拼装，必须进依赖数组：切换语言后重新加载要用新语言报错。
    // useI18nStore 的 t 在语言包变化时才会换引用，不会造成额外重跑。
    //  t builds the error message, so it belongs in the deps: after a language switch a reload
    //  must report in the new language. The t reference from useI18nStore only changes when the
    //  translations change, so this does not cause extra runs.
  }, [pid, t])

  useEffect(() => {
    loadEvents()
    loadMitreConfig()

    // 监听实时事件 / Listen for real-time events
    const unlisten = listen<Record<string, unknown>>('etw-event', (event) => {
      const payload = event.payload as unknown as EtwEvent
      if (payload && (payload.pid === pid)) {
        setEvents((prev) => [payload, ...prev].slice(0, 500))
      }
    })

    return () => {
      unlisten.then((u) => u())
    }
  }, [loadEvents, loadMitreConfig, pid])

  /** 获取 MITRE 映射（优先使用配置文件，兜底默认规则）/ Get MITRE mapping (config first, fallback default) */
  const getMitreMapping = useCallback((event: EtwEvent): MitreMapping | null => {
    const provider = event.provider || ''
    const operation = event.operation || event.type || ''
    const key = `${provider}:${operation}`
    return mitreRules[key] || null
  }, [mitreRules])

  /** 按 MITRE 战术分组 / Group by MITRE tactic */
  const tacticGroups = useMemo(() => {
    const groups: Record<string, EtwEvent[]> = {}
    events.forEach((event) => {
      const mapping = getMitreMapping(event)
      const tactic = mapping?.tactic || 'Uncategorized'
      if (!groups[tactic]) groups[tactic] = []
      groups[tactic].push(event)
    })
    return groups
  }, [events, getMitreMapping])

  /** 格式化时间 / Format timestamp */
  const formatTime = (ts: string) => {
    try {
      const d = new Date(ts)
      return d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalDigits: 3 } as Intl.DateTimeFormatOptions)
    } catch {
      return ts
    }
  }

  return (
    <div className={styles.page}>
      {/* 头部 / Header */}
      <div className={styles.header}>
        <Button
          appearance="subtle"
          icon={<ArrowLeft size={16} />}
          onClick={onBack}
        >
          {t('btn_back')}
        </Button>
        <div>
          <h2 className={styles.pageTitle}>
            {processName}
          </h2>
          <span className={styles.pidLabel}>
            PID: {pid}
          </span>
        </div>
      </div>

      {/* 错误提示 / Error display */}
      {error && (
        <div className={styles.errorCard}>
          <p className={styles.errorText}>{error}</p>
          <Button appearance="outline" onClick={loadEvents}>
            {t('behavior_lifecycle_retry')}
          </Button>
        </div>
      )}

      {/* 加载骨架 / Loading skeleton */}
      {loading && (
        <div>
          {[1, 2, 3, 4, 5].map((i) => (
            <Skeleton key={i} className={styles.skeletonRow}>
              <SkeletonItem className={styles.skeletonItem} />
            </Skeleton>
          ))}
        </div>
      )}

      {/* 事件时间线 / Event timeline */}
      {!loading && events.length > 0 && (
        <>
          {/* MITRE ATT&CK 战术面板 / MITRE ATT&CK tactic panel */}
          <div className={styles.tacticSection}>
            <h3 className={styles.sectionTitle}>
              {t('behavior_lifecycle_mitre_mapping')}
            </h3>
            <div className={styles.tacticGrid}>
              {Object.keys(tacticGroups).map((tactic) => (
                <div key={tactic} className={styles.tacticCard}>
                  <span className={styles.tacticName}>{tactic}</span>
                  <Badge appearance="filled" color="brand">
                    {tacticGroups[tactic].length}
                  </Badge>
                </div>
              ))}
            </div>
          </div>

          {/* 事件时间线列表 / Event timeline list */}
          <h3 className={styles.sectionTitle}>
            {t('behavior_lifecycle_timeline_title')} ({events.length} {t('behavior_event_count_unit')})
          </h3>
          <div className={styles.eventList}>
            {events.map((event, index) => {
              const mitre = getMitreMapping(event)
              const eventId = event.id || `${event.pid}-${index}`
              const isExpanded = expandedEvent === eventId

              return (
                <div
                  key={eventId}
                  className={styles.eventItem}
                  tabIndex={0}
                  role="button"
                  aria-expanded={isExpanded}
                  onClick={() => setExpandedEvent(isExpanded ? null : eventId)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      setExpandedEvent(isExpanded ? null : eventId)
                    }
                  }}
                >
                  <div className={styles.eventHeader}>
                    <span className={styles.eventTimestamp}>{formatTime(event.timestamp)}</span>
                    <span className={styles.eventPid}>PID:{event.pid}</span>
                    <Badge
                      appearance="filled"
                      color={mitre ? 'danger' : 'subtle'}
                    >
                      {event.type || event.operation || 'Unknown'}
                    </Badge>
                    {mitre && (
                      <>
                        <Badge appearance="filled" color="warning">
                          {mitre.tactic}
                        </Badge>
                        <span className={styles.mitreTag}>
                          {mitre.techniqueId}: {mitre.techniqueName}
                        </span>
                      </>
                    )}
                    <span className={styles.eventProvider}>
                      {event.provider || ''} {event.path || event.details || ''}
                    </span>
                  </div>

                  {/* 展开的详情 / Expanded details */}
                  {isExpanded && (
                    <div className={styles.eventDetails}>
                      {event.details ? (
                        (() => {
                          try {
                            const parsed = typeof event.details === 'string' ? JSON.parse(event.details) : event.details
                            return JSON.stringify(parsed, null, 2)
                          } catch {
                            return event.details
                          }
                        })()
                      ) : (
                        <span className={styles.mutedText}>{t('behavior_lifecycle_no_details')}</span>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </>
      )}

      {/* 空状态 / Empty state */}
      {!loading && events.length === 0 && (
        <div className={styles.emptyState}>
          <div className={styles.emptyIcon}>
            <Search size={48} color={tokens.colorNeutralForeground3} />
          </div>
          <p className={styles.emptyText}>{t('behavior_lifecycle_no_data')}</p>
          <p className={styles.emptySubtext}>
            {t('behavior_lifecycle_empty_hint')}
          </p>
        </div>
      )}
    </div>
  )
}

export default BehaviorLifecyclePage
