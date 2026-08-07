import React, { useEffect, useState } from 'react'
import { useQuarantineStore } from '../stores/quarantineStore'
import { useI18nStore } from '../stores/i18nStore'
import { RefreshCw, Shield, AlertTriangle, XCircle, Trash2, RotateCcw } from './icons'
import { formatFileSize } from '../api/quarantine'
import { Button, Checkbox, Dropdown, Option, makeStyles, shorthands, tokens, Table, TableHeader, TableHeaderCell, TableBody, TableRow, TableCell, Badge } from '@fluentui/react-components'
import { ConfirmDialog } from './common/ConfirmDialog'

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
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    boxShadow: tokens.shadow4,
    ...shorthands.padding('16px', '20px'),
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
  infoCardValueCompact: {
    fontSize: tokens.fontSizeBase500,
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
  errorMessage: {
    flex: 1,
  },
  tableContainer: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    boxShadow: tokens.shadow4,
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
  filterDropdown: {
    minWidth: '120px',
  },
  tableScroll: {
    overflowX: 'auto',
    // 必须限高并允许纵向滚动：表头用了 position: sticky，
    // 没有受限高度的滚动容器时 sticky 不生效，隔离项一多表格就无限拉长把页面撑爆。
    //  A bounded height with vertical scrolling is required: the header uses position: sticky,
    //  which does nothing without a height-constrained scroll container, and the table would
    //  otherwise grow without limit as quarantine entries pile up.
    maxHeight: '300px',
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
      ...shorthands.padding('10px', '16px'),
      textAlign: 'left' as const,
      fontWeight: tokens.fontWeightSemibold,
      color: tokens.colorNeutralForeground1,
      borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
      whiteSpace: 'nowrap',
    },
    '& td': {
      ...shorthands.padding('10px', '16px'),
      borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
      verticalAlign: 'middle',
    },
    '& tbody tr': {
      ':hover': {
        backgroundColor: tokens.colorNeutralBackground1Hover,
      },
    },
  },
  pathCell: {
    fontFamily: 'Consolas, "Courier New", monospace',
    fontSize: tokens.fontSizeBase200,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  mutedText: {
    color: tokens.colorNeutralForeground3,
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
  dangerButton: {
    color: tokens.colorPaletteRedForeground2,
    ...shorthands.borderColor(tokens.colorPaletteRedBorderActive),
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
          <Badge appearance="filled" color="danger">
            {t('quarantine_filter_quarantined')}
          </Badge>
        )
      case 'restored':
        return (
          <Badge appearance="filled" color="brand">
            {t('quarantine_filter_restored')}
          </Badge>
        )
      default:
        return <Badge appearance="filled" color="informative">{status}</Badge>
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
          <div className={`${styles.infoCardValue} ${styles.infoCardValueCompact}`}>{formatFileSize(totalSize)}</div>
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
            <span className={styles.errorMessage}>{error}</span>
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
            <Dropdown
              value={filter === 'all' ? t('quarantine_filter_all') : filter === 'quarantined' ? t('quarantine_filter_quarantined') : t('quarantine_filter_restored')}
              selectedOptions={[filter]}
              onOptionSelect={(_, data) => setFilter(data.optionValue as 'all' | 'quarantined' | 'restored')}
              className={styles.filterDropdown}
            >
              <Option value="all">{t('quarantine_filter_all')}</Option>
              <Option value="quarantined">{t('quarantine_filter_quarantined')}</Option>
              <Option value="restored">{t('quarantine_filter_restored')}</Option>
            </Dropdown>
          </div>
          <Button
            appearance="outline"
            size="small"
            onClick={handleBatchDelete}
            disabled={selectedIds.length === 0}
            className={styles.dangerButton}
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
            <Table className={styles.table}>
              <TableHeader>
                <TableRow>
                  <TableHeaderCell>
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
                  </TableHeaderCell>
                  <TableHeaderCell>{t('quarantine_th_filename')}</TableHeaderCell>
                  <TableHeaderCell>{t('quarantine_th_original_path')}</TableHeaderCell>
                  <TableHeaderCell>{t('quarantine_th_threat_type')}</TableHeaderCell>
                  <TableHeaderCell>{t('quarantine_th_size')}</TableHeaderCell>
                  <TableHeaderCell>{t('quarantine_th_status')}</TableHeaderCell>
                  <TableHeaderCell>{t('quarantine_th_actions')}</TableHeaderCell>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredItems.map((item) => {
                  const originalPath = item.originalPath || t('quarantine_unknown_path')
                  const fileName = originalPath.split(/[\\/]/).pop() || originalPath
                  return (
                    <TableRow key={item.id}>
                      <TableCell>
                        <Checkbox
                          checked={selectedIds.includes(item.id)}
                          onChange={() => toggleSelection(item.id)}
                          aria-label={t('quarantine_aria_select_file').replace('{file}', fileName)}
                        />
                      </TableCell>
                      <TableCell>
                        <strong>{fileName}</strong>
                      </TableCell>
                      <TableCell className={styles.pathCell} title={originalPath}>
                        {originalPath}
                      </TableCell>
                      <TableCell>
                        {item.threatType ? (
                          <Badge appearance="filled" color="warning">
                            {item.threatType}
                          </Badge>
                        ) : (
                          <span className={styles.mutedText}>-</span>
                        )}
                      </TableCell>
                      <TableCell>{formatFileSize(item.fileSize)}</TableCell>
                      <TableCell>{getStatusBadge(item.status)}</TableCell>
                      <TableCell>
                        {item.status === 'restored' ? (
                          <span className={styles.mutedText}>-</span>
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
                              className={styles.dangerButton}
                              title={t('quarantine_delete_file_title')}
                            >
                              {t('quarantine_delete')}
                            </Button>
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </div>
      </div>

      {/* 确认对话框 */}
      <ConfirmDialog
        open={confirmDialog !== null && confirmDialog.type === 'restore'}
        title={t('quarantine_confirm_restore')}
        message={confirmDialog?.type === 'restore' ? t('quarantine_restore_desc').replace('{file}', confirmDialog.fileName) + '\n\n' + t('quarantine_restore_warning') : ''}
        confirmText={t('quarantine_confirm_restore')}
        cancelText={t('common_cancel')}
        intent="warning"
        onConfirm={() => confirmDialog && handleRestore(confirmDialog.id)}
        onCancel={() => setConfirmDialog(null)}
      />
      <ConfirmDialog
        open={confirmDialog !== null && confirmDialog.type === 'delete'}
        title={t('quarantine_confirm_delete')}
        message={confirmDialog?.type === 'delete' ? t('quarantine_delete_desc').replace('{file}', confirmDialog.fileName) + '\n\n' + t('quarantine_delete_warning') : ''}
        confirmText={t('quarantine_confirm_delete')}
        cancelText={t('common_cancel')}
        intent="danger"
        onConfirm={() => confirmDialog && handleDelete(confirmDialog.id)}
        onCancel={() => setConfirmDialog(null)}
      />
    </section>
  )
}

export default QuarantinePage
