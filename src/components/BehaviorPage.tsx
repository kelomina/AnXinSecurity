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
import React, { useEffect, useState, useCallback } from 'react'
import {
  listEvents,
  listProcesses,
  clearAllEvents,
  onEtwEvent,
  type EtwEvent,
  type BehaviorProcess,
} from '../api/behavior'
import { useConfigStore } from '../stores/configStore'
import { Trash2, RotateCcw, Filter, Shield, AlertTriangle } from 'lucide-react'

/** 页面属性 / Page props */
interface BehaviorPageProps {
  /** 打开行为生命周期详情的回调 / Callback to open behavior lifecycle detail */
  onOpenLifecycle?: (pid: number, processName: string) => void
}

const BehaviorPage: React.FC<BehaviorPageProps> = ({ onOpenLifecycle }) => {
  const [events, setEvents] = useState<EtwEvent[]>([])
  const [processes, setProcesses] = useState<BehaviorProcess[]>([])
  const [loading, setLoading] = useState(true)
  const [pidFilter, _setPidFilter] = useState<number | null>(null)
  const [viewMode, setViewMode] = useState<'events' | 'processes'>('events')
  const { config } = useConfigStore()
  const edrEnabled = config?.behaviorMonitoring?.enabled ?? false

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

    return () => {
      unlisten()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
    await Promise.all([loadHistory(), loadProcesses()])
  }

  /**
   * 获取事件类型 badge 样式 / Get event type badge style
   */
  const getEventTypeClass = (type: string) => {
    const lowerType = type.toLowerCase()
    if (lowerType.includes('start') || lowerType.includes('create')) return 'severity-low'
    if (lowerType.includes('stop') || lowerType.includes('terminate')) return 'severity-high'
    if (lowerType.includes('network') || lowerType.includes('connect')) return 'severity-medium'
    return ''
  }

  return (
    <section id="page-behavior" className="page">
      <h1 className="page-title">EDR</h1>

      {/* EDR 关闭提示 / EDR disabled notice */}
      {!edrEnabled && (
        <div className="card" style={{
          padding: '24px',
          marginBottom: '16px',
          background: 'rgba(255, 193, 7, 0.08)',
          border: '1px solid rgba(255, 193, 7, 0.2)',
          borderRadius: '12px',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '12px'
        }}>
          <AlertTriangle size={24} style={{ color: '#f59e0b', flexShrink: 0, marginTop: '2px' }} />
          <div>
            <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '4px' }}>EDR 功能已关闭</h3>
            <p style={{ fontSize: '14px', color: 'var(--muted-fg)' }}>
              EDR（端点检测与响应）功能消耗较多系统资源，非必要不建议开启。
              如需开启，请前往 <strong>设置 → 监控设置</strong> 中启用"EDR 行为监控"开关。
            </p>
          </div>
        </div>
      )}

      {/* 控制栏 / Controls */}
      <div className="behavior-controls card">
        <button onClick={handleClearEvents} className="btn btn-outline-secondary">
          <Trash2 size={16} />
          清除事件
        </button>
        <button onClick={handleRefresh} disabled={loading || !edrEnabled} className="btn btn-outline-secondary">
          <RotateCcw size={16} />
          刷新
        </button>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '8px' }}>
          <button
            className={`btn ${viewMode === 'events' ? 'btn-primary' : 'btn-outline-secondary'}`}
            onClick={() => setViewMode('events')}
          >
            <Filter size={16} />
            事件列表
          </button>
          <button
            className={`btn ${viewMode === 'processes' ? 'btn-primary' : 'btn-outline-secondary'}`}
            onClick={() => setViewMode('processes')}
          >
            <Shield size={16} />
            进程摘要
          </button>
        </div>
      </div>

      {/* EDR 关闭时隐藏事件内容 / Hide event content when EDR is off */}
      {!edrEnabled ? (
        <div className="card" style={{ padding: '48px', textAlign: 'center' }}>
          <Shield size={64} style={{ color: 'var(--muted-fg)', marginBottom: '16px', opacity: 0.3 }} />
          <p style={{ color: 'var(--muted-fg)', fontSize: '15px' }}>
            EDR 功能已关闭，请在设置中开启以查看事件数据。
          </p>
        </div>
      ) : (
        <>
          {/* 事件列表视图 / Event list view */}
          {viewMode === 'events' && (
            <div className="event-list card">
              <div className="event-header">
                <h3>事件列表</h3>
                <span className="event-count">{events.length}</span>
              </div>

              {loading ? (
                <div className="skeleton-list">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <div key={i} className="skeleton-event skeleton" />
                  ))}
                </div>
              ) : events.length === 0 ? (
                <div className="empty-state">
                  <Shield size={48} className="empty-icon" />
                  <p>暂无行为事件。请确认 EDR 监控正在运行。</p>
                </div>
              ) : (
                <div>
                  {events.map((event, index) => (
                    <div key={index} className="event-item">
                      <span className="event-timestamp">{event.timestamp}</span>
                      <span className="event-pid">PID: {event.pid}</span>
                      <span className={`event-type-badge ${getEventTypeClass(event.type)}`}>{event.type}</span>
                      <span className="event-provider" title={event.provider}>
                        {event.provider}
                        {event.path && ` — ${event.path}`}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* 进程摘要视图 / Process summary view */}
          {viewMode === 'processes' && (
            <div className="event-list card">
              <div className="event-header">
                <h3>进程摘要</h3>
                <span className="event-count">{processes.length}</span>
              </div>

              {processes.length === 0 ? (
                <div className="empty-state">
                  <Shield size={48} className="empty-icon" />
                  <p>暂无进程摘要数据。</p>
                </div>
              ) : (
                <div>
                  {processes.map((proc, index) => (
                    <div
                      key={index}
                      className="event-item"
                      style={{ cursor: onOpenLifecycle ? 'pointer' : 'default' }}
                      onClick={() => onOpenLifecycle?.(proc.pid, proc.processName)}
                    >
                      <span className="event-timestamp">{proc.lastSeen}</span>
                      <span className="event-pid">PID: {proc.pid}</span>
                      <span className="event-type-badge severity-low">事件数: {proc.eventCount}</span>
                      <span className="event-provider">{proc.processName}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}
    </section>
  )
}

export default BehaviorPage