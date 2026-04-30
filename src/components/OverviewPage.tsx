import React, { useEffect, useState } from 'react'
import { useConfigStore } from '../stores/configStore'
import { scannerHealth } from '../api/scanner'
import { ShieldCheck, ShieldAlert, Clock, Eye } from 'lucide-react'

const OverviewPage: React.FC = () => {
  const config = useConfigStore((state) => state.config)
  const [engineStatus, setEngineStatus] = useState<'ok' | 'error' | 'loading'>('loading')

  useEffect(() => {
    const checkHealth = async () => {
      try {
        await scannerHealth()
        setEngineStatus('ok')
      } catch (e) {
        setEngineStatus('error')
      }
    }

    checkHealth()
    const interval = setInterval(checkHealth, 30000)
    return () => clearInterval(interval)
  }, [])

  return (
    <section id="page-overview" className="page">
      <h1 className="page-title">{config?.brand || 'AnXin Security'}</h1>

      {/* 引擎状态卡片 - 带脉动动画 */}
      <div className="status-card card">
        <div className="status-header">
          <h3>引擎状态</h3>
          {engineStatus === 'ok' && <ShieldCheck size={24} className="status-icon success" />}
          {engineStatus === 'error' && <ShieldAlert size={24} className="status-icon error" />}
        </div>
        <div className={`engine-status ${engineStatus}`}>
          {engineStatus === 'loading' && '检查中...'}
          {engineStatus === 'ok' && '✓ 引擎运行正常'}
          {engineStatus === 'error' && '✗ 引擎异常'}
        </div>
      </div>

      {/* 信息卡片网格 */}
      <div className="info-cards-grid">
        <div className="info-card card">
          <div className="card-icon">
            <Eye size={20} />
          </div>
          <div className="card-content">
            <h4>实时监控</h4>
            <p className="card-value">
              {config?.behaviorMonitoring?.enabled ? '已启用' : '已禁用'}
            </p>
          </div>
        </div>
        
        <div className="info-card card">
          <div className="card-icon">
            <Clock size={20} />
          </div>
          <div className="card-content">
            <h4>主题模式</h4>
            <p className="card-value">{config?.ui?.themeMode || '系统'}</p>
          </div>
        </div>
      </div>
    </section>
  )
}

export default OverviewPage
