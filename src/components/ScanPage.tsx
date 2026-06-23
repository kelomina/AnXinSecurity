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
import { useI18nStore } from '../stores/i18nStore'
import { useToastStore } from '../stores/toastStore'
import { Play, Pause, FolderOpen, FileSearch, AlertTriangle, Loader, X, Shield, CheckCircle, Trash2, ShieldCheck } from 'lucide-react'
import { open } from '@tauri-apps/plugin-dialog'
import { startBackgroundWalk, onWalkFileBatch, onWalkComplete } from '../api/fs'
import { addToAllowlist } from '../api/allowlist'
import { isolateFile } from '../api/quarantine'
import { Button, Checkbox, ProgressBar, makeStyles, shorthands, tokens } from '@fluentui/react-components'

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
  card: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('16px'),
    marginBottom: '16px',
  },
  buttonGrid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr 1fr',
    ...shorthands.gap('12px'),
  },
  selectedFilesHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '12px',
  },
  selectedFilesTitle: {
    fontWeight: tokens.fontWeightSemibold,
    fontSize: tokens.fontSizeBase300,
  },
  fileList: {
    fontFamily: 'Consolas, "Courier New", monospace',
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground2,
    display: 'flex',
    flexDirection: 'column',
    ...shorthands.gap('4px'),
  },
  filePath: {
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  moreFiles: {
    textAlign: 'center' as const,
    color: tokens.colorNeutralForeground2,
  },
  progressHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '8px',
  },
  progressTitle: {
    fontWeight: tokens.fontWeightSemibold,
    fontSize: tokens.fontSizeBase300,
  },
  progressValue: {
    fontSize: tokens.fontSizeBase600,
    fontWeight: tokens.fontWeightBold,
    color: tokens.colorBrandForeground1,
  },
  progressHelper: {
    marginTop: '6px',
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground2,
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
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
  infoGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(4, 1fr)',
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
    color: tokens.colorNeutralForeground2,
    fontWeight: tokens.fontWeightSemibold,
  },
  infoCardValue: {
    fontSize: tokens.fontSizeBase600,
    fontWeight: tokens.fontWeightBold,
    color: tokens.colorNeutralForeground1,
  },
  emptyState: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('40px', '20px'),
    textAlign: 'center' as const,
  },
  emptyIcon: {
    color: tokens.colorNeutralForeground2,
    marginBottom: '16px',
  },
  emptyText: {
    color: tokens.colorNeutralForeground2,
  },
  successState: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('40px', '20px'),
    textAlign: 'center' as const,
  },
  successIcon: {
    color: tokens.colorPaletteGreenForeground2,
    marginBottom: '16px',
  },
  successText: {
    color: tokens.colorPaletteGreenForeground2,
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
  toolbarTitle: {
    fontWeight: tokens.fontWeightSemibold,
    fontSize: tokens.fontSizeBase300,
  },
  toolbarRight: {
    display: 'flex',
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
    '& tbody tr.selected': {
      backgroundColor: tokens.colorBrandBackground2,
    },
  },
  checkboxCell: {
    width: '36px',
  },
  pathCell: {
    fontFamily: 'Consolas, "Courier New", monospace',
    fontSize: tokens.fontSizeBase200,
    maxWidth: '300px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  },
  badge: {
    display: 'inline-flex',
    alignItems: 'center',
    ...shorthands.gap('4px'),
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
  badgeLow: {
    backgroundColor: tokens.colorPaletteGreenBackground2,
    color: tokens.colorPaletteGreenForeground2,
  },
  badgeNeutral: {
    backgroundColor: tokens.colorNeutralBackground5,
    color: tokens.colorNeutralForeground2,
  },
  badgeCount: {
    backgroundColor: tokens.colorPaletteYellowBackground2,
    color: tokens.colorPaletteYellowForeground2,
  },
  threatTypeText: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
  },
})

const ScanPage: React.FC = () => {
  const styles = useStyles()
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
    removeScanResultsByPath,
    clearError,
    appendPendingFiles,
    setWalkComplete,
  } = useScannerStore()
  const { t } = useI18nStore()
  const addToast = useToastStore((state) => state.addToast)

  const [isWalking, setIsWalking] = React.useState(false)
  const [selectedThreatPaths, setSelectedThreatPaths] = React.useState<string[]>([])
  const [threatAction, setThreatAction] = React.useState<'clear' | 'trust' | null>(null)

  /**
   * 选择目录扫描 / Select directory to scan
   */
  const handleSelectDirectory = async () => {
    let unlistenBatch: (() => void) | null = null
    let unlistenComplete: (() => void) | null = null
    let dirs: string[] = []

    try {
      const selected = await open({
        directory: true,
        multiple: true,
        title: t('scan_dialog_select_directory')
      })
      if (!selected) return

      dirs = Array.isArray(selected) ? selected : [selected]
      setIsWalking(true)

      const initialFiles: string[] = []
      let completedWalks = 0
      const totalWalks = dirs.length
      let isInInitialPhase = true

      unlistenBatch = onWalkFileBatch((files) => {
        if (isInInitialPhase) {
          initialFiles.push(...files)
        } else {
          appendPendingFiles(files)
        }
      })

      unlistenComplete = onWalkComplete(() => {
        completedWalks++
        if (completedWalks >= totalWalks) {
          setWalkComplete()
          setIsWalking(false)
        }
      })

      for (const dir of dirs) {
        await startBackgroundWalk(dir, ['Windows', 'System32', 'AppData', '$Recycle.Bin'])
      }

      await Promise.race([
        new Promise<void>(resolve => setTimeout(resolve, 3000)),
        new Promise<void>(resolve => {
          const checkInterval = setInterval(() => {
            if (completedWalks >= totalWalks) {
              clearInterval(checkInterval)
              resolve()
            }
          }, 100)
        })
      ])

      isInInitialPhase = false

      if (initialFiles.length > 0) {
        addSelectedFiles(initialFiles)
        startScan()
      }

      while (completedWalks < totalWalks) {
        if (!useScannerStore.getState().isScanning && !isInInitialPhase) {
          break
        }
        await new Promise(resolve => setTimeout(resolve, 500))
      }

    } catch (e) {
      console.error('[ScanPage] Select directory failed:', e)
    } finally {
      unlistenBatch?.()
      unlistenComplete?.()
      setIsWalking(false)
    }
  }

  /**
   * 选择文件扫描 / Select files to scan
   */
  const handleSelectFiles = async () => {
    try {
      const selected = await open({
        multiple: true,
        title: t('scan_dialog_select_file'),
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
  const getSeverityBadge = (verdict: string) => {
    switch (verdict) {
      case 'malware':
        return (
          <span className={`${styles.badge} ${styles.badgeHigh}`}>
            <AlertTriangle size={14} />
            {t('intercept_level_critical', '严重')}
          </span>
        )
      case 'suspicious':
        return (
          <span className={`${styles.badge} ${styles.badgeMedium}`}>
            {t('intercept_level_high', '高')}
          </span>
        )
      case 'clean':
        return (
          <span className={`${styles.badge} ${styles.badgeLow}`}>
            <CheckCircle size={14} />
            {t('intercept_level_low', '低')}
          </span>
        )
      default:
        return <span className={`${styles.badge} ${styles.badgeNeutral}`}>{t('intercept_level_unknown', '未知')}</span>
    }
  }

  const threats = React.useMemo(
    () => scanResults.filter(r => r.verdict && r.verdict !== 'clean'),
    [scanResults]
  )
  const threatPaths = React.useMemo(
    () => threats.map(threat => threat.fileId || threat.description || '').filter(Boolean),
    [threats]
  )
  const selectedThreats = threats.filter(threat =>
    selectedThreatPaths.includes(threat.fileId || threat.description || '')
  )
  const hasSelectedThreats = selectedThreats.length > 0

  React.useEffect(() => {
    setSelectedThreatPaths((currentPaths) =>
      currentPaths.filter(path => threatPaths.includes(path))
    )
  }, [threatPaths])

  const getThreatFilePath = (threat: (typeof threats)[number]): string => (
    threat.fileId || threat.description || ''
  )

  const toggleThreatSelection = (path: string) => {
    if (!path) return

    setSelectedThreatPaths((currentPaths) =>
      currentPaths.includes(path)
        ? currentPaths.filter(selectedPath => selectedPath !== path)
        : [...currentPaths, path]
    )
  }

  const handleSelectAllThreats = (checked: boolean) => {
    setSelectedThreatPaths(checked ? threatPaths : [])
  }

  const handleClearThreats = async () => {
    if (!hasSelectedThreats) return

    setThreatAction('clear')
    let failedCount = 0
    const clearedThreatPaths: string[] = []

    for (const threat of selectedThreats) {
      const threatPath = getThreatFilePath(threat)
      if (!threatPath) {
        failedCount++
        continue
      }

      try {
        await isolateFile(threatPath, threat.threatType || threat.verdict)
        clearedThreatPaths.push(threatPath)
      } catch (err) {
        failedCount++
        console.error(`[ScanPage] Clear threat failed: ${threatPath}`, err)
      }
    }

    setThreatAction(null)
    setSelectedThreatPaths([])
    removeScanResultsByPath(clearedThreatPaths)

    if (failedCount > 0) {
      addToast('error', t('scan_toast_clear_failed').replace('{count}', String(failedCount)))
    } else {
      addToast('success', t('scan_toast_clear_success').replace('{count}', String(selectedThreats.length)))
    }
  }

  const handleAddTrust = async () => {
    if (!hasSelectedThreats) return

    setThreatAction('trust')
    let failedCount = 0

    for (const threat of selectedThreats) {
      const threatPath = getThreatFilePath(threat)
      if (!threatPath) {
        failedCount++
        continue
      }

      try {
        await addToAllowlist(threatPath, 'Added from scan threat result')
      } catch (err) {
        failedCount++
        console.error(`[ScanPage] Add trust failed: ${threatPath}`, err)
      }
    }

    setThreatAction(null)
    setSelectedThreatPaths([])

    if (failedCount > 0) {
      addToast('error', t('scan_toast_trust_failed').replace('{count}', String(failedCount)))
    } else {
      addToast('success', t('scan_toast_trust_success').replace('{count}', String(selectedThreats.length)))
    }
  }

  return (
    <section id="page-scan" className={styles.page}>
      <h1 className={styles.pageTitle}>{t('scan_title')}</h1>

      {/* 扫描控制区 / Scan controls */}
      <div className={styles.card}>
        <div className={styles.buttonGrid}>
          <Button
            appearance="outline"
            onClick={handleSelectDirectory}
            disabled={isScanning || isWalking}
            icon={isWalking ? <Loader size={18} className="spinning" /> : <FolderOpen size={18} />}
          >
            {isWalking ? t('scan_walking') : t('scan_select_directory')}
          </Button>
          <Button
            appearance="outline"
            onClick={handleSelectFiles}
            disabled={isScanning}
            icon={<FileSearch size={18} />}
          >
            {t('scan_select_file')}
          </Button>
          <Button
            appearance={isScanning ? 'primary' : 'primary'}
            onClick={handleStartScan}
            disabled={selectedFiles.length === 0 && !isScanning}
            icon={isScanning ? <Pause size={18} /> : <Play size={18} />}
            style={isScanning ? { backgroundColor: tokens.colorPaletteRedBackground3, color: '#fff' } : undefined}
          >
            {isScanning ? t('scan_cancel') : t('scan_start')}
          </Button>
        </div>
      </div>

      {/* 已选文件列表 / Selected file list */}
      {selectedFiles.length > 0 && !isScanning && (
        <div className={styles.card}>
          <div className={styles.selectedFilesHeader}>
            <span className={styles.selectedFilesTitle}>{t('scan_selected_files').replace('{count}', String(selectedFiles.length))}</span>
            <Button appearance="secondary" size="small" icon={<X size={16} />} onClick={clearSelection}>
              {t('scan_clear_selection')}
            </Button>
          </div>
          <div className={styles.fileList}>
            {selectedFiles.slice(0, 10).map((path, index) => (
              <div key={index} className={styles.filePath} title={path}>{path}</div>
            ))}
            {selectedFiles.length > 10 && (
              <div className={styles.moreFiles}>
                {t('scan_more_files').replace('{count}', String(selectedFiles.length - 10))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* 进度条 / Progress bar */}
      {isScanning && (
        <div className={styles.card}>
          <div className={styles.progressHeader}>
            <span className={styles.progressTitle}>{t('scan_progress')}</span>
            <span className={styles.progressValue}>{scanProgress}%</span>
          </div>
          <ProgressBar value={scanProgress / 100} thickness="large" />
          {currentFile && (
            <div className={styles.progressHelper}>
              {t('scan_scanning_file').replace('{file}', currentFile)}
            </div>
          )}
        </div>
      )}

      {/* 错误提示 / Error display */}
      {error && (
        <div className={styles.errorCard}>
          <div className={styles.errorContent}>
            <AlertTriangle size={20} />
            <span style={{ flex: 1 }}>{error}</span>
            <Button appearance="secondary" size="small" icon={<X size={18} />} onClick={clearError} />
          </div>
        </div>
      )}

      {/* 扫描统计 / Scan statistics */}
      {lastScanStats && !isScanning && (
        <div className={styles.infoGrid}>
          <div className={styles.infoCard}>
            <div className={styles.infoCardLabel}>{t('scan_stat_files')}</div>
            <div className={styles.infoCardValue}>{lastScanStats.totalFiles}</div>
          </div>
          <div className={styles.infoCard}>
            <div className={styles.infoCardLabel}>{t('scan_stat_threats')}</div>
            <div className={styles.infoCardValue} style={{ color: tokens.colorPaletteRedForeground2 }}>{lastScanStats.threatsFound}</div>
          </div>
          <div className={styles.infoCard}>
            <div className={styles.infoCardLabel}>{t('scan_stat_clean')}</div>
            <div className={styles.infoCardValue} style={{ color: tokens.colorPaletteGreenForeground2 }}>{lastScanStats.cleanFiles}</div>
          </div>
          {lastScanStats.elapsedTime > 0 && (
            <div className={styles.infoCard}>
              <div className={styles.infoCardLabel}>{t('scan_stat_elapsed')}</div>
              <div className={styles.infoCardValue}>{lastScanStats.elapsedTime}s</div>
            </div>
          )}
        </div>
      )}

      {/* 检测结果 / Detection results */}
      {!isScanning && scanResults.length === 0 ? (
        <div className={styles.emptyState}>
          <Shield size={48} className={styles.emptyIcon} />
          <p className={styles.emptyText}>
            {selectedFiles.length === 0 ? t('scan_empty_hint') : t('scan_no_results')}
          </p>
        </div>
      ) : threats.length === 0 && !isScanning && scanResults.length > 0 ? (
        <div className={styles.successState}>
          <CheckCircle size={48} className={styles.successIcon} />
          <p className={styles.successText}>{t('scan_all_clean')}</p>
        </div>
      ) : threats.length > 0 ? (
        <div className={styles.tableContainer}>
          <div className={styles.tableToolbar}>
            <div className={styles.toolbarLeft}>
              <AlertTriangle size={16} style={{ color: tokens.colorPaletteYellowForeground2 }} />
              <span className={styles.toolbarTitle}>{t('scan_threats_found').replace('{count}', String(threats.length))}</span>
              <span className={`${styles.badge} ${styles.badgeCount}`}>{t('scan_selected_count').replace('{count}', String(selectedThreatPaths.length))}</span>
            </div>
            <div className={styles.toolbarRight}>
              <Button
                appearance="primary"
                size="small"
                onClick={handleClearThreats}
                disabled={!hasSelectedThreats || threatAction !== null}
                icon={threatAction === 'clear' ? <Loader size={14} className="spinning" /> : <Trash2 size={14} />}
                style={{ backgroundColor: tokens.colorPaletteRedBackground3, color: '#fff' }}
                title={t('scan_quarantine_title')}
              >
                {t('scan_clear_threats')}
              </Button>
              <Button
                appearance="secondary"
                size="small"
                onClick={handleAddTrust}
                disabled={!hasSelectedThreats || threatAction !== null}
                icon={threatAction === 'trust' ? <Loader size={14} className="spinning" /> : <ShieldCheck size={14} />}
                title={t('scan_trust_title')}
              >
                {t('scan_add_trust')}
              </Button>
            </div>
          </div>
          <div className={styles.tableScroll}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th className={styles.checkboxCell}>
                    <Checkbox
                      checked={threatPaths.length > 0 && selectedThreatPaths.length === threatPaths.length}
                      onChange={(_, data) => handleSelectAllThreats(!!data.checked)}
                      aria-label={t('scan_select_all')}
                    />
                  </th>
                  <th>{t('scan_th_file_path')}</th>
                  <th>{t('scan_th_result')}</th>
                  <th>{t('scan_th_threat_type')}</th>
                  <th style={{ width: '80px' }}>{t('scan_th_severity')}</th>
                </tr>
              </thead>
              <tbody>
                {threats.map((threat, index) => {
                  const threatPath = getThreatFilePath(threat)
                  const isSelected = selectedThreatPaths.includes(threatPath)

                  return (
                    <tr key={`${threatPath}-${index}`} className={isSelected ? 'selected' : ''}>
                      <td>
                        <Checkbox
                          checked={isSelected}
                          disabled={!threatPath}
                          onChange={() => toggleThreatSelection(threatPath)}
                          aria-label={`${t('scan_select_threat_file')} ${threatPath || index + 1}`}
                        />
                      </td>
                      <td className={styles.pathCell} title={threatPath || undefined}>
                        {threatPath || t('scan_unknown_file')}
                      </td>
                      <td>
                        <span className={`${styles.badge} ${threat.verdict === 'malware' ? styles.badgeHigh : styles.badgeMedium}`}>
                          {(threat.verdict ?? 'unknown').toUpperCase()}
                        </span>
                      </td>
                      <td className={styles.threatTypeText}>
                        {threat.threatType || '-'}
                      </td>
                      <td>
                        {getSeverityBadge(threat.verdict)}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </section>
  )
}

export default ScanPage
