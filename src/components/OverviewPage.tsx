/**
 * 概览页面
 * Overview page
 *
 * 显示引擎健康状态、系统信息、实时监控状态、隔离区文件数、
 * 实时ETW日志面板、快照扫描结果、风险分析统计等概览信息。
 * Displays engine health, system info, monitoring status, quarantine count,
 * real-time ETW log panel, snapshot results, risk stats, etc.
 *
 * 中文关键词：概览，引擎状态，系统信息，日志面板，快照结果
 * English keywords: overview, engine status, system info, log panel, snapshot result
 */
import React, { useEffect, useState } from 'react'
import { useConfigStore } from '../stores/configStore'
import { useQuarantineStore } from '../stores/quarantineStore'
import { scannerHealth } from '../api/scanner'
import { getSystemInfo, type SystemInfo } from '../api/system'

import { getRecentLogs, clearLogs } from '../api/logs'
import { listen } from '@tauri-apps/api/event'
import { Activity, Cpu, Database, HardDrive, ShieldCheck, ShieldAlert, Eye, FileWarning, Layers, Trash2 } from 'lucide-react'

interface OverviewPageProps {
  onOpenLifecycle?: (pid: number, processName: string) => void
}

const OverviewPage: React.FC<OverviewPageProps> = (_props) => {
  const config = useConfigStore((state) => state.config)
  const quarantineItems = useQuarantineStore((state) => state.items)
  const loadQuarantineItems = useQuarantineStore((state) => state.loadItems)
  const [engineStatus, setEngineStatus] = useState<'ok' | 'error' | 'loading'>('loading')
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null)
  const [logs, setLogs] = useState<string[]>([])
  const [snapshotResult, setSnapshotResult] = useState<Record<string, unknown> | null>(null)

  // 引擎健康检查 + 初始化加载
  useEffect(() => {
    const checkHealth = async () => {
      try {
        await scannerHealth()
        setEngineStatus('ok')
      } catch { setEngineStatus('error') }
    }
    checkHealth()
    loadQuarantineItems()

    // 加载系统信息
    getSystemInfo().then(setSystemInfo).catch((e: unknown) => { console.error('[OverviewPage] Failed to load system info:', e) })
    // 加载日志
    getRecentLogs().then(setLogs).catch((e: unknown) => { console.error('[OverviewPage] Failed to load recent logs:', e) })

    const interval = setInterval(checkHealth, 30000)
    return () => clearInterval(interval)
  }, [loadQuarantineItems])

  // 监听实时日志事件
  useEffect(() => {
    const unlisten = listen<Record<string, unknown>>('etw-event', (event) => {
      const ts = new Date().toLocaleTimeString('zh-CN')
      const provider = (event.payload.provider as string) || 'ETW'
      const op = (event.payload.operation as string) || (event.payload.type as string) || ''
      const path = (event.payload.path as string) || ''
      const pid = event.payload.pid
      const line = `[${ts}] PID:${pid} ${provider}/${op} ${path}`
      setLogs((prev) => [line, ...prev].slice(0, 200))
    })
    return () => { unlisten.then((u) => u()) }
  }, [])

  // 监听快照结果
  useEffect(() => {
    const unlisten = listen<Record<string, unknown>>('snapshot-result', (event) => {
      setSnapshotResult(event.payload as Record<string, unknown>)
    })
    return () => { unlisten.then((u) => u()) }
  }, [])

  const quarantinedCount = quarantineItems.filter(i => i.status === 'quarantined').length
  const totalSize = quarantineItems.reduce((sum, i) => sum + i.fileSize, 0)
  const themeLabel = config?.ui?.themeMode === 'system' ? '跟随系统' : config?.ui?.themeMode === 'light' ? '浅色' : '深色'

  return (
    <section id="page-overview" className="page">
      <h1 className="page-title">{config?.brand || 'AnXin Security'}</h1>

      {/* 引擎状态 + 签名库版本 */}
      <div className="status-card card" style={{ marginBottom: '16px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {engineStatus === 'ok' ? <ShieldCheck size={20} color="var(--success)" /> : engineStatus === 'error' ? <ShieldAlert size={20} color="var(--danger)" /> : <Activity size={20} />}
            <span>
              {engineStatus === 'loading' ? '检查中...' : engineStatus === 'ok' ? '引擎运行正常' : '引擎异常 — 请检查引擎是否已启动'}
            </span>
          </div>

        </div>
      </div>

      {/* 信息卡片网格 */}
      <div className="info-cards-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '12px', marginBottom: '16px' }}>
        {/* 系统信息卡片 */}
        <div className="info-card card">
          <div className="card-icon"><Cpu size={20} /></div>
          <div className="card-content">
            <h4>处理器</h4>
            <p className="card-value" style={{ fontSize: '12px' }}>{systemInfo?.cpuName?.split('@')[0]?.trim() || '--'}</p>
            <p style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>{systemInfo?.cpuCores || '--'} 核心</p>
          </div>
        </div>

        <div className="info-card card">
          <div className="card-icon"><Eye size={20} /></div>
          <div className="card-content">
            <h4>实时监控</h4>
            <p className="card-value">{config?.behaviorMonitoring?.enabled ? '已启用' : '已禁用'}</p>
          </div>
        </div>

        <div className="info-card card">
          <div className="card-icon"><Database size={20} /></div>
          <div className="card-content">
            <h4>隔离文件数</h4>
            <p className="card-value">{quarantinedCount}</p>
          </div>
        </div>

        <div className="info-card card">
          <div className="card-icon"><HardDrive size={20} /></div>
          <div className="card-content">
            <h4>隔离区占用</h4>
            <p className="card-value">
              {totalSize < 1024 ? `${totalSize} B` : totalSize < 1048576 ? `${(totalSize / 1024).toFixed(1)} KB` : `${(totalSize / 1048576).toFixed(1)} MB`}
            </p>
          </div>
        </div>

        <div className="info-card card">
          <div className="card-icon"><Layers size={20} /></div>
          <div className="card-content">
            <h4>主题</h4>
            <p className="card-value">{themeLabel}</p>
          </div>
        </div>

        {/* 快照结果卡片 */}
        {snapshotResult && (
          <div className="info-card card" style={{ borderColor: 'var(--warning)' }}>
            <div className="card-icon"><FileWarning size={20} color="var(--warning)" /></div>
            <div className="card-content">
              <h4>启动快照</h4>
              <p className="card-value" style={{ fontSize: '12px' }}>
                {(snapshotResult.unsignedProcesses as number) || 0} 个未签名
              </p>
              <p style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>
                共 {(snapshotResult.totalProcesses as number) || 0} 进程
              </p>
            </div>
          </div>
        )}
      </div>

      {/* 实时日志面板 */}
      <div className="card" style={{ marginBottom: '16px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <h3 style={{ fontSize: '14px', fontWeight: 600, margin: 0 }}>实时事件日志</h3>
          <button className="btn btn-outline-secondary btn-sm" onClick={() => { clearLogs(); setLogs([]) }}>
            <Trash2 size={14} /> 清除
          </button>
        </div>
        <div style={{
          maxHeight: '200px',
          overflowY: 'auto',
          fontFamily: 'monospace',
          fontSize: '11px',
          background: 'var(--bg-tertiary)',
          borderRadius: '8px',
          padding: '8px',
          lineHeight: 1.6,
          color: 'var(--text-secondary)',
          wordBreak: 'break-all',
        }}>
          {logs.length === 0 ? (
            <span style={{ color: 'var(--text-tertiary)' }}>等待事件...</span>
          ) : (
            logs.map((line, i) => (
              <div key={i}>{line}</div>
            ))
          )}
        </div>
      </div>
    </section>
  )
}

export default OverviewPage
