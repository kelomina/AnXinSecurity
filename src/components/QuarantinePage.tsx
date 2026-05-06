import React, { useEffect, useState } from 'react'
import { useQuarantineStore } from '../stores/quarantineStore'
import { RefreshCw, Shield, AlertTriangle, CheckCircle, XCircle, Trash2, RotateCcw } from 'lucide-react'
import { formatFileSize, formatDate } from '../api/quarantine'

const QuarantinePage: React.FC = () => {
  const {
    items,
    loading,
    error,
    selectedIds,
    loadItems,
    restoreItem,
    deleteItem,
    toggleSelection,
    clearSelection,
  } = useQuarantineStore()

  const [filter, setFilter] = useState<'all' | 'quarantined' | 'restored'>('all')
  const [confirmDialog, setConfirmDialog] = useState<{
    type: 'restore' | 'delete'
    id: string
    fileName: string
  } | null>(null)

  // 加载隔离区列表
  useEffect(() => {
    loadItems()
  }, [loadItems])

  // 过滤后的项目
  const filteredItems = items.filter(item => {
    if (filter === 'all') return true
    return item.status === filter
  })

  // 统计信息
  const totalSize = items.reduce((sum, item) => sum + item.fileSize, 0)
  const quarantinedCount = items.filter(i => i.status === 'quarantined').length

  // 处理恢复
  const handleRestore = async (id: string) => {
    try {
      await restoreItem(id)
      setConfirmDialog(null)
    } catch (err) {
      console.error('Restore failed:', err)
    }
  }

  // 处理删除
  const handleDelete = async (id: string) => {
    try {
      await deleteItem(id)
      setConfirmDialog(null)
    } catch (err) {
      console.error('Delete failed:', err)
    }
  }

  // 批量删除
  const handleBatchDelete = async () => {
    for (const id of selectedIds) {
      try {
        await deleteItem(id)
      } catch (err) {
        console.error(`Failed to delete ${id}:`, err)
      }
    }
    clearSelection()
  }

  // 获取状态徽章样式
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'quarantined':
        return (
          <span className="severity-badge severity-high">
            <Shield size={14} />
            隔离中
          </span>
        )
      case 'restored':
        return (
          <span className="severity-badge severity-low">
            <CheckCircle size={14} />
            已恢复
          </span>
        )
      default:
        return <span className="severity-badge">{status}</span>
    }
  }

  return (
    <section id="page-quarantine" className="page">
      <h1 className="page-title">隔离区</h1>

      {/* 统计卡片 */}
      <div className="scan-stats card" style={{ marginBottom: '1rem' }}>
        <div className="stat-item">
          <span className="stat-label">隔离文件数</span>
          <span className="stat-value">{quarantinedCount}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">总大小</span>
          <span className="stat-value">{formatFileSize(totalSize)}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">总计录数</span>
          <span className="stat-value">{items.length}</span>
        </div>
      </div>

      {/* 工具栏 */}
      <div className="card" style={{ marginBottom: '1rem' }}>
        <div className="section-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <button
              onClick={() => loadItems()}
              disabled={loading}
              className="btn btn-outline-secondary"
              style={{ padding: '0.5rem' }}
            >
              <RefreshCw size={18} className={loading ? 'spinning' : ''} />
            </button>
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value as any)}
              className="btn btn-outline-secondary"
              style={{ cursor: 'pointer' }}
            >
              <option value="all">全部</option>
              <option value="quarantined">隔离中</option>
              <option value="restored">已恢复</option>
            </select>
          </div>
          {selectedIds.length > 0 && (
            <button
              onClick={handleBatchDelete}
              className="btn btn-danger"
            >
              <Trash2 size={16} />
              批量删除 ({selectedIds.length})
            </button>
          )}
        </div>
      </div>

      {/* 错误提示 */}
      {error && (
        <div className="card" style={{ marginBottom: '1rem', borderColor: 'var(--color-danger)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--color-danger)' }}>
            <AlertTriangle size={20} />
            <span>{error}</span>
            <button
              onClick={() => useQuarantineStore.setState({ error: null })}
              className="btn-icon"
              style={{ marginLeft: 'auto' }}
            >
              <XCircle size={18} />
            </button>
          </div>
        </div>
      )}

      {/* 数据表格 */}
      <div className="threat-list quarantine-list card">
        <h3>隔离文件列表</h3>

        {loading ? (
          <div className="skeleton-table">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="skeleton-row skeleton" />
            ))}
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="empty-state">
            <Shield size={48} className="empty-icon" />
            <p>{items.length === 0 ? '暂无隔离文件' : '没有符合筛选条件的记录'}</p>
          </div>
        ) : (
          <div className="threat-scroll">
            <table>
              <thead>
                <tr>
                  <th className="select-col">
                    <input
                      type="checkbox"
                      checked={selectedIds.length === filteredItems.length && filteredItems.length > 0}
                      onChange={(e) => {
                        if (e.target.checked) {
                          filteredItems.forEach(item => {
                            if (!selectedIds.includes(item.id)) {
                              toggleSelection(item.id)
                            }
                          })
                        } else {
                          clearSelection()
                        }
                      }}
                    />
                  </th>
                  <th className="quarantine-file-col">文件名</th>
                  <th className="quarantine-path-col">原始路径</th>
                  <th className="quarantine-threat-col">威胁类型</th>
                  <th className="quarantine-size-col">文件大小</th>
                  <th className="quarantine-date-col">隔离日期</th>
                  <th className="quarantine-status-col">状态</th>
                  <th className="quarantine-actions-col">操作</th>
                </tr>
              </thead>
              <tbody>
                {filteredItems.map((item) => {
                  const originalPath = item.originalPath || '未知路径'
                  const fileName = originalPath.split(/[\\/]/).pop() || originalPath
                  return (
                    <tr key={item.id}>
                      <td className="select-col">
                        <input
                          type="checkbox"
                          checked={selectedIds.includes(item.id)}
                          onChange={() => toggleSelection(item.id)}
                        />
                      </td>
                      <td className="quarantine-file-cell" title={fileName}>
                        <strong>{fileName}</strong>
                      </td>
                      <td className="path-cell" title={originalPath}>
                        {originalPath}
                      </td>
                      <td className="quarantine-threat-cell">
                        {item.threatType ? (
                          <span className="severity-badge severity-medium">
                            {item.threatType}
                          </span>
                        ) : (
                          <span className="text-muted">-</span>
                        )}
                      </td>
                      <td className="quarantine-size-cell">{formatFileSize(item.fileSize)}</td>
                      <td className="quarantine-date-cell">{formatDate(item.isolatedAt)}</td>
                      <td className="quarantine-status-cell">{getStatusBadge(item.status)}</td>
                      <td className="quarantine-actions-cell">
                        <div className="quarantine-actions">
                          {item.status === 'quarantined' && (
                            <button
                              onClick={() => setConfirmDialog({
                                type: 'restore',
                                id: item.id,
                                fileName
                              })}
                              className="btn btn-outline-primary btn-sm"
                              title="恢复文件"
                            >
                              <RotateCcw size={14} />
                              恢复
                            </button>
                          )}
                          <button
                            onClick={() => setConfirmDialog({
                              type: 'delete',
                              id: item.id,
                              fileName
                            })}
                            className="btn btn-outline-danger btn-sm"
                            title="永久删除"
                          >
                            <Trash2 size={14} />
                            删除
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 确认对话框 */}
      {confirmDialog && (
        <div className="modal-overlay" onClick={() => setConfirmDialog(null)}>
          <div className="modal-surface quarantine-confirm-modal" onClick={(e) => e.stopPropagation()}>
            <h3>
              {confirmDialog.type === 'restore' ? '确认恢复' : '确认删除'}
            </h3>
            <p>
              {confirmDialog.type === 'restore' ? (
                <>
                  确定要恢复文件 <strong>{confirmDialog.fileName}</strong> 到原始位置吗？
                  <br />
                  <span style={{ color: 'var(--color-warning)', fontSize: '0.9rem' }}>
                    注意：如果原文件位置存在同名文件，可能会被覆盖。
                  </span>
                </>
              ) : (
                <>
                  确定要永久删除 <strong>{confirmDialog.fileName}</strong> 吗？
                  <br />
                  <span style={{ color: 'var(--color-danger)', fontSize: '0.9rem' }}>
                    警告：此操作不可撤销，文件将被安全擦除。
                  </span>
                </>
              )}
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end', marginTop: '1rem' }}>
              <button
                onClick={() => setConfirmDialog(null)}
                className="btn btn-outline-secondary"
              >
                取消
              </button>
              <button
                onClick={() => {
                  if (confirmDialog.type === 'restore') {
                    handleRestore(confirmDialog.id)
                  } else {
                    handleDelete(confirmDialog.id)
                  }
                }}
                className={`btn ${confirmDialog.type === 'restore' ? 'btn-primary' : 'btn-danger'}`}
              >
                确认
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

export default QuarantinePage
