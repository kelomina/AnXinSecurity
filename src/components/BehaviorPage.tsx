import React, { useEffect, useState } from 'react'
import { listEvents, pauseEtw, resumeEtw, onEtwEvent, EtwEvent } from '../api/behavior'

const BehaviorPage: React.FC = () => {
  const [events, setEvents] = useState<EtwEvent[]>([])
  const [etwPaused, setEtwPaused] = useState(false)

  useEffect(() => {
    // 监听实时 ETW 事件
    const unlisten = onEtwEvent((event) => {
      setEvents((prev) => [event, ...prev].slice(0, 500))
    })

    // 加载历史事件
    loadHistory()

    return () => {
      unlisten()
    }
  }, [])

  const loadHistory = async () => {
    try {
      const history = await listEvents({ limit: 100 })
      setEvents(history)
    } catch (e) {
      console.error('Failed to load history:', e)
    }
  }

  const handlePauseEtw = async () => {
    try {
      await pauseEtw()
      setEtwPaused(true)
    } catch (e) {
      console.error('Failed to pause ETW:', e)
    }
  }

  const handleResumeEtw = async () => {
    try {
      await resumeEtw()
      setEtwPaused(false)
    } catch (e) {
      console.error('Failed to resume ETW:', e)
    }
  }

  return (
    <section id="page-behavior" className="page">
      <h1>行为分析</h1>

      <div className="controls">
        <button onClick={handlePauseEtw} disabled={etwPaused} className="btn btn-warning">
          暂停监控
        </button>
        <button onClick={handleResumeEtw} disabled={!etwPaused} className="btn btn-success">
          恢复监控
        </button>
      </div>

      <div className="event-list">
        <h3>事件列表 ({events.length})</h3>
        {events.map((event, index) => (
          <div key={index} className="event-item">
            <span className="timestamp">{event.timestamp}</span>
            <span className="pid">PID: {event.pid}</span>
            <span className="type">{event.type}</span>
            <span className="provider">{event.provider}</span>
          </div>
        ))}
      </div>
    </section>
  )
}

export default BehaviorPage
