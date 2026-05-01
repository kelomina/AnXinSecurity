/**
 * 文件扫描页面
 * File scan page
 *
 * 提供文件/目录选择、扫描控制、进度显示、威胁结果展示功能。
 * Provides file/directory selection, scan controls, progress display, threat results.
 *
 * 调用方：App.tsx (路由分发)
 * Called by: App.tsx (page routing)
 *
 * 中文关键词：文件扫描，威胁检测，扫描进度，选择文件，选择目录，扫描结果
 * English keywords: file scan, threat detection, scan progress, select file, select directory, scan result
 */
import React from 'react'
import { useScannerStore } from '../stores/scannerStore'
import { Play, Pause, FolderOpen, FileSearch, AlertTriangle, X, Shield, CheckCircle } from 'lucide-react'
import { open } from '@tauri-apps/plugin-dialog'

const ScanPage: React.FC = () => {
  const {
    selectedFiles,
    isScanning,
    scanProgress,
    currentFile,
    scanResults,
    lastScanStats,
    error,
    addSelectedFiles,
    clearSelection,
    startScan,
    cancelScan,
    clearError,
  } = useScannerStore()

  /**
   * 选择目录扫描 / Select directory to scan
   */
  const handleSelectDirectory = async () => {
    try {
      const selected = await open({
        directory: true,
        multiple: true,
        title: '选择要扫描的目录'
      })
      if (selected) {
        addSelectedFiles(Array.isArray(selected) ? selected : [selected])
      }
    } catch (e) {
      console.error('[ScanPage] Select directory failed:', e)
    }
  }

  /**
   * 选择文件扫描 / Select files to scan
   */
  const handleSelectFiles = async () => {
    try {
      const selected = await open({
        multiple: true,
        title: '选择要扫描的文件',
        filters: [{
          name: 'Executable Files',
          extensions: ['exe', 'dll', 'bat', 'cmd', 'ps1', 'js', 'vbs', 'msi', 'scr']
        }]
      })
      if (selected) {
        addSelectedFiles(Array.isArray(selected) ? selected : [selected])
      }
    } catch (e) {
      console.error('[ScanPage] Select files failed:', e)
    }
  }

  /**
   * 开始扫描或取消 / Start scan or cancel
   */
  const handleStartScan = async () => {
    if (isScanning) {
      await cancelScan()
    } else {
      await startScan()
    }
  }

  /**
   * 获取严重程度徽章 / Get severity badge component
   */
  const getSeverityBadge = (verdict: string, threatType?: string) => {
    switch (verdict) {
      case 'malware':
        return (
          <span className="severity-badge severity-high">
            <AlertTriangle size={14} />
            {threatType || '恶意软件'}
          </span>
        )
      case 'suspicious':
        return (
          <span className="severity-badge severity-medium">
            {threatType || '可疑'}
          </span>
        )
      case 'clean':
        return (
          <span className="severity-badge severity-low">
            <CheckCircle size={14} />
            安全
          </span>
        )
      default:
        return <span className="severity-badge">未知</span>
    }
  }

  const threats = scanResults.filter(r => r.verdict !== 'clean')

  return (
    <section id="page-scan" className="page">
      <h1 className="page-title">文件扫描</h1>

      {/* 扫描控制区 / Scan controls */}
      <div className="scan-controls card">
        <div className="scan-actions">
          <button
            onClick={handleSelectDirectory}
            disabled={isScanning}
            className="btn btn-outline-secondary scan-action"
          >
            <FolderOpen size={18} />
            <span>选择目录</span>
          </button>
          <button
            onClick={handleSelectFiles}
            disabled={isScanning}
            className="btn btn-outline-secondary scan-action"
          >
            <FileSearch size={18} />
            <span>选择文件</span>
          </button>
          <button
            onClick={handleStartScan}
            disabled={selectedFiles.length === 0 && !isScanning}
            className={`btn btn-primary scan-action ${isScanning ? 'btn-danger' : ''}`}
          >
            {isScanning ? <Pause size={18} /> : <Play size={18} />}
            <span>{isScanning ? '取消扫描' : '开始扫描'}</span>
          </button>
        </div>
      </div>

      {/* 已选文件列表 / Selected file list */}
      {selectedFiles.length > 0 && !isScanning && (
        <div className="card" style={{ marginBottom: '1rem' }}>
          <div className="section-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <h3>已选择文件 ({selectedFiles.length})</h3>
            <button onClick={clearSelection} className="btn btn-outline-secondary" style={{ padding: '6px 12px', fontSize: '13px' }}>
              <X size={16} />
              清除选择
            </button>
          </div>
          <div className="file-list" style={{ maxHeight: '200px', overflowY: 'auto' }}>
            {selectedFiles.slice(0, 10).map((path, index) => (
              <div key={index} className="file-item" style={{ padding: '0.5rem', borderBottom: '1px solid var(--divider-color)' }}>
                <span className="file-path" style={{ fontSize: '0.9rem' }}>{path}</span>
              </div>
            ))}
            {selectedFiles.length > 10 && (
              <p style={{ padding: '0.5rem', textAlign: 'center', color: 'var(--muted-fg)' }}>
                ...还有 {selectedFiles.length - 10} 个文件
              </p>
            )}
          </div>
        </div>
      )}

      {/* 进度条 / Progress bar */}
      {isScanning && (
        <div className="scan-progress card">
          <div className="progress-header">
            <span>扫描进度</span>
            <span className="progress-text">{scanProgress}%</span>
          </div>
          <div className="progress-bar-container">
            <div
              className={`progress-bar ${scanProgress === 0 ? 'scan-indeterminate' : ''}`}
              style={{ width: scanProgress > 0 ? `${scanProgress}%` : undefined }}
            />
          </div>
          {currentFile && (
            <p style={{ fontSize: '12px', color: 'var(--muted-fg)', marginTop: '8px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              正在扫描: {currentFile}
            </p>
          )}
        </div>
      )}

      {/* 错误提示 / Error display */}
      {error && (
        <div className="card" style={{ marginBottom: '1rem', borderColor: 'var(--color-danger)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--color-danger)' }}>
            <AlertTriangle size={20} />
            <span>{error}</span>
            <button
              onClick={clearError}
              className="btn btn-outline-secondary"
              style={{ marginLeft: 'auto', padding: '6px' }}
            >
              <X size={18} />
            </button>
          </div>
        </div>
      )}

      {/* 扫描统计 / Scan statistics */}
      {lastScanStats && !isScanning && (
        <div className="scan-stats card" style={{ marginBottom: '1rem' }}>
          <div className="stat-item">
            <span className="stat-label">扫描文件数</span>
            <span className="stat-value">{lastScanStats.totalFiles}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">发现威胁</span>
            <span className="stat-value danger">{lastScanStats.threatsFound}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">安全文件</span>
            <span className="stat-value success">{lastScanStats.cleanFiles}</span>
          </div>
          {lastScanStats.elapsedTime > 0 && (
            <div className="stat-item">
              <span className="stat-label">耗时</span>
              <span className="stat-value">{lastScanStats.elapsedTime}s</span>
            </div>
          )}
        </div>
      )}

      {/* 检测结果 / Detection results */}
      <div className="threat-list card">
        <h3>检测结果</h3>

        {!isScanning && scanResults.length === 0 ? (
          <div className="empty-state">
            <Shield size={48} className="empty-icon" />
            <p>{selectedFiles.length === 0 ? '请选择文件或目录开始扫描' : '暂无检测结果'}</p>
          </div>
        ) : threats.length === 0 && !isScanning && scanResults.length > 0 ? (
          <div className="empty-state">
            <CheckCircle size={48} className="empty-icon" style={{ color: 'var(--color-success)' }} />
            <p>未检测到威胁，所有文件都是安全的</p>
          </div>
        ) : threats.length > 0 ? (
          <div className="threat-scroll">
            <table>
              <thead>
                <tr>
                  <th className="select-col">
                    <input type="checkbox" />
                  </th>
                  <th>文件路径</th>
                  <th>检测结果</th>
                  <th>威胁类型</th>
                  <th>严重程度</th>
                </tr>
              </thead>
              <tbody>
                {threats.map((threat, index) => (
                  <tr key={index}>
                    <td className="select-col">
                      <input type="checkbox" />
                    </td>
                    <td className="path-cell">
                      {threat.description || threat.fileId || '未知文件'}
                    </td>
                    <td>
                      <strong style={{ color: threat.verdict === 'malware' ? 'var(--color-danger)' : 'var(--color-warning)' }}>
                        {threat.verdict.toUpperCase()}
                      </strong>
                    </td>
                    <td>{threat.threatType || '-'}</td>
                    <td>
                      {getSeverityBadge(threat.verdict, threat.threatType)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </section>
  )
}

export default ScanPage
