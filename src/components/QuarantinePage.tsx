import React, { useEffect, useState } from 'react'
import { useQuarantineStore } from '../stores/quarantineStore'
import { useI18nStore } from '../stores/i18nStore'
import { RefreshCw, Shield, AlertTriangle, XCircle, Trash2, RotateCcw } from 'lucide-react'
import { formatFileSize } from '../api/quarantine'
import { Button, Checkbox, makeStyles, shorthands, tokens } from '@fluentui/react-components'

const useStyles = makeStyles({
  page: {
    paddingBottom: '24px',
  },
  pageTitle: {
    fontSize: tokens.fontSizeBase600,
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground1,
    marginBottom: '20px',
  },
  infoGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, 1fr)',
    ...shorthands.gap('12px'),
    marginBottom: '16px',
  },
  infoCard: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('16px'),
    textAlign: 'center' as const,
  },
  infoCardLabel: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
  },
  infoCardValue: {
    fontSize: tokens.fontSizeBase600,
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground1,
  },
  errorCard: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorPaletteRedBorderActive),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('16px'),
    marginBottom: '16px',
  },
  errorContent: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('8px'),
    color: tokens.colorPaletteRedForeground2,
  },
  tableContainer: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    overflow: 'hidden',
  },
  tableToolbar: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    ...shorthands.padding('14px', '20px'),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  toolbarLeft: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('8px'),
  },
  tableScroll: {
    overflowX: 'auto',
    overflowY: 'auto',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse' as const,
    fontSize: tokens.fontSizeBase300,
    '& thead': {
      backgroundColor: tokens.colorNeutralBackground3,
      position: 'sticky' as const,
      top: 0,
      zIndex: 1,
    },
    '& th': {
      ...shorthands.padding('12px', '16px'),
      textAlign: 'left' as const,
      fontWeight: tokens.fontWeightSemibold,
      color: tokens.colorNeutralForeground2,
      borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    },
    '& td': {
      ...shorthands.padding('12px', '16px'),
      borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    },
    '& tbody tr': {
      ':hover': {
        backgroundColor: tokens.colorNeutralBackground1Hover,
      },
    },
  },
  checkboxCell: {
    width: '36px',
  },
  pathCell: {
    fontFamily: 'Consolas, "Courier New", monospace',
    fontSize: tokens.fontSizeBase200,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  badge: {
    display: 'inline-block',
    ...shorthands.padding('4px', '8px'),
    ...shorthands.borderRadius(tokens.borderRadiusSmall),
    fontSize: tokens.fontSizeBase200,
    fontWeight: tokens.fontWeightSemibold,
  },
  badgeHigh: {
    backgroundColor: tokens.colorPaletteRedBackground2,
    color: tokens.colorPaletteRedForeground2,
  },
  badgeMedium: {
    backgroundColor: tokens.colorPaletteYellowBackground2,
    color: tokens.colorPaletteYellowForeground2,
  },
  badgeSafe: {
    backgroundColor: tokens.colorPaletteGreenBackground2,
    color: tokens.colorPaletteGreenForeground2,
  },
  emptyState: {
    ...shorthands.padding('40px', '20px'),
    textAlign: 'center' as const,
  },
  emptyIcon: {
    color: tokens.colorNeutralForeground3,
    marginBottom: '16px',
  },
  emptyText: {
    color: tokens.colorNeutralForeground3,
  },
  skeletonTable: {
    ...shorthands.padding('20px'),
    display: 'flex',
    flexDirection: 'column',
    ...shorthands.gap('12px'),
  },
  skeletonRow: {
    height: '48px',
    backgroundColor: tokens.colorNeutralBackground3,
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    animation: 'pulse 1.5s ease-in-out infinite',
  },
  actionButtons: {
    display: 'flex',
    ...shorthands.gap('8px'),
  },
  overlay: {
    position: 'fixed',
    inset: 0,
    backgroundColor: 'rgba(0,0,0,0.5)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 9999,
    backdropFilter: 'blur(4px)',
  },
  modalSurface: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    boxShadow: tokens.shadow28,
    width: '480px',
    maxWidth: '90vw',
    overflow: 'hidden',
  },
  modalHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    ...shorthands.padding('20px', '24px'),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  modalTitle: {
    fontSize: tokens.fontSizeBase400,
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground1,
    margin: 0,
  },
  modalClose: {
    width: '32px',
    height: '32px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    ...shorthands.border('none'),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    backgroundColor: 'transparent',
    color: tokens.colorNeutralForeground2,
    cursor: 'pointer',
    ':hover': {
      backgroundColor: tokens.colorNeutralBackground1Hover,
    },
  },
  modalBody: {
    ...shorthands.padding('16px', '24px'),
  },
  modalMessage: {
    fontSize: tokens.fontSizeBase300,
    color: tokens.colorNeutralForeground2,
    marginBottom: '12px',
  },
  warningBox: {
    ...shorthands.padding('12px'),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.border('1px', 'solid'),
  },
  warningBoxRestore: {
    backgroundColor: 'rgba(199,146,85,0.09)',
    ...shorthands.borderColor('rgba(199,146,85,0.16)'),
  },
  warningBoxDelete: {
    backgroundColor: 'rgba(214,107,109,0.09)',
    ...shorthands.borderColor('rgba(214,107,109,0.16)'),
  },
  warningText: {
    fontSize: tokens.fontSizeBase200,
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('6px'),
  },
  modalFooter: {
    display: 'flex',
    justifyContent: 'flex-end',
    ...shorthands.gap('8px'),
    ...shorthands.padding('12px', '24px', '20px'),
    borderTop: `1px solid ${tokens.colorNeutralStroke1}`,
  },
})

const QuarantinePage: React.FC = () => {
  const styles = useStyles()
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
  const { t } = useI18nStore()

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
          <span className={`${styles.badge} ${styles.badgeHigh}`}>
            {t('quarantine_filter_quarantined')}
          </span>
        )
      case 'restored':
        return (
          <span className={`${styles.badge} ${styles.badgeSafe}`}>
            {t('quarantine_filter_restored')}
          </span>
        )
      default:
        return <span className={styles.badge}>{status}</span>
    }
  }

  return (
    <section id="page-quarantine" className={styles.page}>
      <h1 className={styles.pageTitle}>{t('quarantine_title')}</h1>

      {/* 统计卡片 */}
      <div className={styles.infoGrid}>
        <div className={styles.infoCard}>
          <div className={styles.infoCardLabel}>{t('quarantine_label_files')}</div>
          <div className={styles.infoCardValue}>{quarantinedCount}</div>
        </div>
        <div className={styles.infoCard}>
          <div className={styles.infoCardLabel}>{t('quarantine_total_size')}</div>
          <div className={styles.infoCardValue} style={{ fontSize: tokens.fontSizeBase500 }}>{formatFileSize(totalSize)}</div>
        </div>
        <div className={styles.infoCard}>
          <div className={styles.infoCardLabel}>{t('quarantine_total_records')}</div>
          <div className={styles.infoCardValue}>{items.length}</div>
        </div>
      </div>

      {/* 错误提示 */}
      {error && (
        <div className={styles.errorCard}>
          <div className={styles.errorContent}>
            <AlertTriangle size={20} />
            <span style={{ flex: 1 }}>{error}</span>
            <Button
              appearance="secondary"
              size="small"
              icon={<XCircle size={18} />}
              onClick={() => useQuarantineStore.setState({ error: null })}
            />
          </div>
        </div>
      )}

      {/* 数据表格 */}
      <div className={styles.tableContainer}>
        <div className={styles.tableToolbar}>
          <div className={styles.toolbarLeft}>
            <Button
              appearance="secondary"
              size="small"
              onClick={() => loadItems()}
              disabled={loading}
              icon={<RefreshCw size={14} className={loading ? 'spinning' : ''} />}
            >
              {t('quarantine_refresh')}
            </Button>
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value as any)}
              style={{
                padding: '6px 10px',
                borderRadius: tokens.borderRadiusMedium,
                border: `1px solid ${tokens.colorNeutralStroke1}`,
                backgroundColor: tokens.colorNeutralBackground3,
                color: tokens.colorNeutralForeground1,
                fontSize: tokens.fontSizeBase300,
                cursor: 'pointer',
              }}
            >
              <option value="all">{t('quarantine_filter_all')}</option>
              <option value="quarantined">{t('quarantine_filter_quarantined')}</option>
              <option value="restored">{t('quarantine_filter_restored')}</option>
            </select>
          </div>
          <Button
            appearance="outline"
            size="small"
            onClick={handleBatchDelete}
            disabled={selectedIds.length === 0}
            style={{ color: tokens.colorPaletteRedForeground2, borderColor: tokens.colorPaletteRedBorderActive }}
          >
            {t('quarantine_batch_delete').replace('{count}', String(selectedIds.length))}
          </Button>
        </div>

        <div className={styles.tableScroll}>
          {loading ? (
            <div className={styles.skeletonTable}>
              {[1, 2, 3, 4, 5].map((i) => (
                <div key={i} className={styles.skeletonRow} />
              ))}
            </div>
          ) : filteredItems.length === 0 ? (
            <div className={styles.emptyState}>
              <Shield size={48} className={styles.emptyIcon} />
              <p className={styles.emptyText}>{items.length === 0 ? t('quarantine_empty') : t('quarantine_no_match')}</p>
            </div>
          ) : (
            <table className={styles.table}>
              <thead>
                <tr>
                  <th className={styles.checkboxCell}>
                    <Checkbox
                      checked={selectedIds.length === filteredItems.length && filteredItems.length > 0}
                      onChange={(_, data) => {
                        if (data.checked) {
                          filteredItems.forEach(item => {
                            if (!selectedIds.includes(item.id)) {
                              toggleSelection(item.id)
                            }
                          })
                        } else {
                          clearSelection()
                        }
                      }}
                      aria-label={t('quarantine_aria_select_all')}
                    />
                  </th>
                  <th>{t('quarantine_th_filename')}</th>
                  <th>{t('quarantine_th_original_path')}</th>
                  <th>{t('quarantine_th_threat_type')}</th>
                  <th>{t('quarantine_th_size')}</th>
                  <th>{t('quarantine_th_status')}</th>
                  <th>{t('quarantine_th_actions')}</th>
                </tr>
              </thead>
              <tbody>
                {filteredItems.map((item) => {
                  const originalPath = item.originalPath || t('quarantine_unknown_path')
                  const fileName = originalPath.split(/[\\/]/).pop() || originalPath
                  return (
                    <tr key={item.id}>
                      <td>
                        <Checkbox
                          checked={selectedIds.includes(item.id)}
                          onChange={() => toggleSelection(item.id)}
                          aria-label={t('quarantine_aria_select_file').replace('{file}', fileName)}
                        />
                      </td>
                      <td title={fileName}>
                        <strong>{fileName}</strong>
                      </td>
                      <td className={styles.pathCell} title={originalPath}>
                        {originalPath}
                      </td>
                      <td>
                        {item.threatType ? (
                          <span className={`${styles.badge} ${styles.badgeMedium}`}>
                            {item.threatType}
                          </span>
                        ) : (
                          <span style={{ color: tokens.colorNeutralForeground3 }}>-</span>
                        )}
                      </td>
                      <td>{formatFileSize(item.fileSize)}</td>
                      <td>{getStatusBadge(item.status)}</td>
                      <td>
                        {item.status === 'restored' ? (
                          <span style={{ color: tokens.colorNeutralForeground3 }}>—</span>
                        ) : (
                          <div className={styles.actionButtons}>
                            {item.status === 'quarantined' && (
                              <Button
                                appearance="outline"
                                size="small"
                                onClick={() => setConfirmDialog({
                                  type: 'restore',
                                  id: item.id,
                                  fileName
                                })}
                                icon={<RotateCcw size={14} />}
                                title={t('quarantine_restore_file_title')}
                              >
                                {t('quarantine_restore')}
                              </Button>
                            )}
                            <Button
                              appearance="outline"
                              size="small"
                              onClick={() => setConfirmDialog({
                                type: 'delete',
                                id: item.id,
                                fileName
                              })}
                              icon={<Trash2 size={14} />}
                              style={{ color: tokens.colorPaletteRedForeground2, borderColor: tokens.colorPaletteRedBorderActive }}
                              title={t('quarantine_delete_file_title')}
                            >
                              {t('quarantine_delete')}
                            </Button>
                          </div>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* 确认对话框 */}
      {confirmDialog && (
        <div className={styles.overlay} onClick={() => setConfirmDialog(null)}>
          <div className={styles.modalSurface} onClick={(e) => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <h3 className={styles.modalTitle}>
                {confirmDialog.type === 'restore' ? t('quarantine_confirm_restore') : t('quarantine_confirm_delete')}
              </h3>
              <button className={styles.modalClose} onClick={() => setConfirmDialog(null)}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
              </button>
            </div>
            <div className={styles.modalBody}>
              {confirmDialog.type === 'restore' ? (
                <>
                  <p className={styles.modalMessage}>{t('quarantine_restore_desc').replace('{file}', confirmDialog.fileName)}</p>
                  <div className={`${styles.warningBox} ${styles.warningBoxRestore}`}>
                    <p className={styles.warningText} style={{ color: tokens.colorPaletteYellowForeground2 }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
                      {t('quarantine_restore_warning')}
                    </p>
                  </div>
                </>
              ) : (
                <>
                  <p className={styles.modalMessage}>{t('quarantine_delete_desc').replace('{file}', confirmDialog.fileName)}</p>
                  <div className={`${styles.warningBox} ${styles.warningBoxDelete}`}>
                    <p className={styles.warningText} style={{ color: tokens.colorPaletteRedForeground2 }}>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/></svg>
                      {t('quarantine_delete_warning')}
                    </p>
                  </div>
                </>
              )}
            </div>
            <div className={styles.modalFooter}>
              <Button
                appearance="secondary"
                size="small"
                onClick={() => setConfirmDialog(null)}
              >
                取消
              </Button>
              <Button
                appearance="primary"
                size="small"
                onClick={() => {
                  if (confirmDialog.type === 'restore') {
                    handleRestore(confirmDialog.id)
                  } else {
                    handleDelete(confirmDialog.id)
                  }
                }}
                style={confirmDialog.type === 'delete' ? { backgroundColor: tokens.colorPaletteRedBackground3, color: '#fff' } : undefined}
              >
                {confirmDialog.type === 'restore' ? '确认恢复' : '确认删除'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}

export default QuarantinePage
