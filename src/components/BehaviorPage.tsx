/**
 * 行为分析页面
 * Behavior analysis page
 *
 * 显示实时 ETW 事件流、历史事件查询、进程摘要列表。
 * 支持暂停/恢复监控、清除事件、按 PID 过滤。
 * Displays real-time ETW event stream, historical event queries, process summary list.
 * Supports pause/resume monitoring, clear events, filter by PID.
 *
 * 调用方：App.tsx (路由分发)
 * Called by: App.tsx (page routing)
 *
 * 中文关键词：行为分析，ETW事件，实时监控，进程行为，事件过滤，暂停恢复
 * English keywords: behavior analysis, ETW event, real-time monitoring, process behavior, event filter, pause resume
 */
import React, { useEffect, useState, useCallback } from 'react'
import {
  listEvents,
  listProcesses,
  pauseEtw,
  resumeEtw,
  clearAllEvents,
  onEtwEvent,
  type EtwEvent,
  type BehaviorProcess,
} from '../api/behavior'
import { Pause, Play, Trash2, RotateCcw, Filter, Shield } from 'lucide-react'

/** 页面属性 / Page props */
interface BehaviorPageProps {
  /** 打开行为生命周期详情的回调 / Callback to open behavior lifecycle detail */
  onOpenLifecycle?: (pid: number, processName: string) => void
}

const BehaviorPage: React.FC<BehaviorPageProps> = ({ onOpenLifecycle }) => {
  const [events, setEvents] = useState<EtwEvent[]>([])
  const [processes, setProcesses] = useState<BehaviorProcess[]>([])
  const [etwPaused, setEtwPaused] = useState(false)
  const [loading, setLoading] = useState(true)
  const [pidFilter, _setPidFilter] = useState<number | null>(null)
  const [viewMode, setViewMode] = useState<'events' | 'processes'>('events')

  /**
   * 初始化：加载历史事件、监听实时事件、加载进程列表
   * Initialize: load history, listen for real-time events, load process list
   */
  useEffect(() => {
    // 监听实时 ETW 事件 / Listen for real-time ETW events
    const unlisten = onEtwEvent((event) => {
      setEvents((prev) => [event, ...prev].slice(0, 500))
    })

    loadHistory()
    loadProcesses()

    return () => {
      unlisten()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

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
   * 暂停 ETW 监控 / Pause ETW monitoring
   */
  const handlePauseEtw = async () => {
    try {
      await pauseEtw()
      setEtwPaused(true)
    } catch (e) {
      console.error('Failed to pause ETW:', e)
    }
  }

  /**
   * 恢复 ETW 监控 / Resume ETW monitoring
   */
  const handleResumeEtw = async () => {
    try {
      await resumeEtw()
      setEtwPaused(false)
    } catch (e) {
      console.error('Failed to resume ETW:', e)
    }
  }

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
      <h1 className="page-title">行为分析</h1>

      {/* 控制栏 / Controls */}
      <div className="behavior-controls card">
        <button onClick={handlePauseEtw} disabled={etwPaused} className="btn btn-warning">
          <Pause size={16} />
          暂停监控
        </button>
        <button onClick={handleResumeEtw} disabled={!etwPaused} className="btn btn-success">
          <Play size={16} />
          恢复监控
        </button>
        <button onClick={handleClearEvents} className="btn btn-outline-secondary">
          <Trash2 size={16} />
          清除事件
        </button>
        <button onClick={handleRefresh} disabled={loading} className="btn btn-outline-secondary">
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
              <p>暂无行为事件。请确认 ETW 监控正在运行。</p>
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
    </section>
  )
}

export default BehaviorPage
