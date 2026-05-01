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
import React, { useEffect, useState, useMemo } from 'react'
import { listen } from '@tauri-apps/api/event'
import { listEvents } from '../api/behavior'
import { loadMitreRules, type MitreRule } from '../api/scanRules'
import type { EtwEvent } from '../api/behavior'

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

interface BehaviorLifecyclePageProps {
  pid: number
  processName: string
  onBack: () => void
}

const BehaviorLifecyclePage: React.FC<BehaviorLifecyclePageProps> = ({ pid, processName, onBack }) => {
  const [events, setEvents] = useState<EtwEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null)
  const [mitreRules, setMitreRules] = useState<MitreRulesMap>(DEFAULT_MITRE_RULES)

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
  }, [pid])

  /** 从配置文件加载 MITRE 规则 / Load MITRE rules from config */
  const loadMitreConfig = async () => {
    try {
      const rules = await loadMitreRules()
      if (rules.length > 0) {
        setMitreRules(buildMitreMap(rules))
      }
    } catch {
      // API 不可用时使用默认规则 / Use default rules when API unavailable
    }
  }

  const loadEvents = async () => {
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
  }

  /** 获取 MITRE 映射（优先使用配置文件，兜底默认规则）/ Get MITRE mapping (config first, fallback default) */
  const getMitreMapping = (event: EtwEvent): MitreMapping | null => {
    const provider = event.provider || ''
    const operation = event.operation || event.type || ''
    const key = `${provider}:${operation}`
    return mitreRules[key] || null
  }

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
  }, [events])

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
    <div className="page">
      {/* 头部 / Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
        <button className="btn btn-outline-secondary btn-sm" onClick={onBack}>
          ← 返回
        </button>
        <div>
          <h2 className="page-title" style={{ margin: 0 }}>
            {processName}
          </h2>
          <span style={{ fontSize: '12px', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
            PID: {pid}
          </span>
        </div>
      </div>

      {/* 错误提示 / Error display */}
      {error && (
        <div className="card" style={{ marginBottom: '16px', borderColor: 'var(--danger)' }}>
          <p style={{ color: 'var(--danger)', margin: 0 }}>{error}</p>
          <button className="btn btn-outline-danger btn-sm" style={{ marginTop: '8px' }} onClick={loadEvents}>
            重试
          </button>
        </div>
      )}

      {/* 加载骨架 / Loading skeleton */}
      {loading && (
        <div className="skeleton-list">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="skeleton-event" style={{ height: '48px', marginBottom: '8px' }} />
          ))}
        </div>
      )}

      {/* 事件时间线 / Event timeline */}
      {!loading && events.length > 0 && (
        <>
          {/* MITRE ATT&CK 战术面板 / MITRE ATT&CK tactic panel */}
          <div style={{ marginBottom: '20px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '12px' }}>
              MITRE ATT&CK 映射
            </h3>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
              {Object.keys(tacticGroups).map((tactic) => (
                <div
                  key={tactic}
                  className="card"
                  style={{
                    padding: '8px 16px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    backgroundColor: 'var(--bg-secondary)',
                  }}
                >
                  <span style={{ fontWeight: 600, fontSize: '13px' }}>{tactic}</span>
                  <span className="badge" style={{ backgroundColor: 'var(--brand-color)', color: '#fff' }}>
                    {tacticGroups[tactic].length}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* 事件时间线列表 / Event timeline list */}
          <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '12px' }}>
            行为时间线 ({events.length} 条记录)
          </h3>
          <div className="event-list" style={{ maxHeight: '60vh', overflowY: 'auto' }}>
            {events.map((event, index) => {
              const mitre = getMitreMapping(event)
              const eventId = event.id || `${event.pid}-${index}`
              const isExpanded = expandedEvent === eventId

              return (
                <div
                  key={eventId}
                  className="event-item"
                  style={{ cursor: 'pointer' }}
                  onClick={() => setExpandedEvent(isExpanded ? null : eventId)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
                    <span className="event-timestamp">{formatTime(event.timestamp)}</span>
                    <span className="event-pid">PID:{event.pid}</span>
                    <span className={`event-type-badge severity-${mitre ? 'high' : 'low'}`}>
                      {event.type || event.operation || 'Unknown'}
                    </span>
                    {mitre && (
                      <>
                        <span className="badge" style={{ backgroundColor: 'var(--warning)', color: '#000' }}>
                          {mitre.tactic}
                        </span>
                        <span style={{ fontSize: '11px', color: 'var(--text-tertiary)', fontFamily: 'monospace' }}>
                          {mitre.techniqueId}: {mitre.techniqueName}
                        </span>
                      </>
                    )}
                    <span className="event-provider" style={{ marginLeft: 'auto' }}>
                      {event.provider || ''} {event.path || event.details || ''}
                    </span>
                  </div>

                  {/* 展开的详情 / Expanded details */}
                  {isExpanded && (
                    <div
                      style={{
                        marginTop: '12px',
                        padding: '12px',
                        backgroundColor: 'var(--bg-tertiary)',
                        borderRadius: '8px',
                        fontSize: '12px',
                        fontFamily: 'monospace',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                        maxHeight: '300px',
                        overflowY: 'auto',
                      }}
                    >
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
                        <span style={{ color: 'var(--text-tertiary)' }}>无额外详情</span>
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
        <div className="empty-state">
          <div className="empty-icon">🔍</div>
          <p>该进程暂无行为数据</p>
          <p style={{ fontSize: '13px', color: 'var(--text-tertiary)' }}>
            请确认行为监控已启用，且该进程产生了系统级操作
          </p>
        </div>
      )}
    </div>
  )
}

export default BehaviorLifecyclePage
