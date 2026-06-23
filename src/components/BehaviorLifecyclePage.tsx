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
import { ArrowLeft, Search } from 'lucide-react'
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
  eventList: {
    maxHeight: '60vh',
    overflowY: 'auto',
  },
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
})

interface BehaviorLifecyclePageProps {
  pid: number
  processName: string
  onBack: () => void
}

const BehaviorLifecyclePage: React.FC<BehaviorLifecyclePageProps> = ({ pid, processName, onBack }) => {
  const styles = useStyles()
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
      setError(`加载事件失败: ${e}`)
    } finally {
      setLoading(false)
    }
  }, [pid])

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
          返回
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
            重试
          </Button>
        </div>
      )}

      {/* 加载骨架 / Loading skeleton */}
      {loading && (
        <div>
          {[1, 2, 3, 4, 5].map((i) => (
            <Skeleton key={i} style={{ marginBottom: '8px' }}>
              <SkeletonItem style={{ height: '48px' }} />
            </Skeleton>
          ))}
        </div>
      )}

      {/* 事件时间线 / Event timeline */}
      {!loading && events.length > 0 && (
        <>
          {/* MITRE ATT&CK 战术面板 / MITRE ATT&CK tactic panel */}
          <div style={{ marginBottom: '20px' }}>
            <h3 className={styles.sectionTitle}>
              MITRE ATT&CK 映射
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
            行为时间线 ({events.length} 条记录)
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
                  onClick={() => setExpandedEvent(isExpanded ? null : eventId)}
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
                        <span style={{ color: tokens.colorNeutralForeground3 }}>无额外详情</span>
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
          <p className={styles.emptyText}>该进程暂无行为数据</p>
          <p className={styles.emptySubtext}>
            请确认行为监控已启用，且该进程产生了系统级操作
          </p>
        </div>
      )}
    </div>
  )
}

export default BehaviorLifecyclePage
