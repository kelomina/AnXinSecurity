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
   *
   * 最多等待遍历 3 秒，随后自动开始扫描已发现的文件。
   * 遍历在后台持续进行，新发现的文件会自动追加到扫描队列。
   * Waits at most 3 seconds for directory traversal, then auto-starts
   * scanning discovered files. Walk continues in background; newly
   * discovered files are automatically appended to the scan queue.
   */
  const handleSelectDirectory = async () => {
    let unlistenBatch: (() => void) | null = null
    let unlistenComplete: (() => void) | null = null
    let dirs: string[] = []

    try {
      const selected = await open({
        directory: true,
        multiple: true,
        title: '选择要扫描的目录'
      })
      if (!selected) return

      dirs = Array.isArray(selected) ? selected : [selected]
      setIsWalking(true)

      // 3 秒内收集的文件 / Files collected within 3 seconds
      const initialFiles: string[] = []
      // 已完成的遍历数
      let completedWalks = 0
      const totalWalks = dirs.length
      // 是否仍在初始收集阶段
      let isInInitialPhase = true

      // 注册文件批次监听 / Register file batch listener
      unlistenBatch = onWalkFileBatch((files) => {
        if (isInInitialPhase) {
          initialFiles.push(...files)
        } else {
          appendPendingFiles(files)
        }
      })

      // 注册遍历完成监听 / Register walk complete listener
      unlistenComplete = onWalkComplete(() => {
        completedWalks++
        if (completedWalks >= totalWalks) {
          setWalkComplete()
          setIsWalking(false)
        }
      })

      // 启动所有后台遍历 / Start all background walks
      for (const dir of dirs) {
        await startBackgroundWalk(dir, ['Windows', 'System32', 'AppData', '$Recycle.Bin'])
      }

      // 等待 3 秒或全部遍历完成（先到先得）
      // Wait 3 seconds or all walks complete, whichever comes first
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

      // 切换到直接追加模式，开始扫描
      // Switch to direct-append mode and start scanning
      isInInitialPhase = false

      if (initialFiles.length > 0) {
        addSelectedFiles(initialFiles)
        startScan()
      }

      // 等待全部遍历完成（保持监听器存活）
      // Wait for all walks to finish (keeping listeners alive)
      while (completedWalks < totalWalks) {
        await new Promise(resolve => setTimeout(resolve, 500))
      }

    } catch (e) {
      console.error('[ScanPage] Select directory failed:', e)
    } finally {
      // 清理监听器
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
   *
   * 根据 verdict 显示对应的本地化严重程度文本。
   * Shows localized severity level text based on verdict.
   */
  const getSeverityBadge = (verdict: string) => {
    switch (verdict) {
      case 'malware':
        return (
          <span className="severity-badge severity-high">
            <AlertTriangle size={14} />
            {t('intercept_level_critical', '严重')}
          </span>
        )
      case 'suspicious':
        return (
          <span className="severity-badge severity-medium">
            {t('intercept_level_high', '高')}
          </span>
        )
      case 'clean':
        return (
          <span className="severity-badge severity-low">
            <CheckCircle size={14} />
            {t('intercept_level_low', '低')}
          </span>
        )
      default:
        return <span className="severity-badge">{t('intercept_level_unknown', '未知')}</span>
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

  /**
   * 函数名称：getThreatFilePath
   * 函数作用：从扫描威胁结果中提取可传递给隔离区或信任列表 API 的文件路径。
   * English purpose: Extracts the file path from a threat result for quarantine or allowlist APIs.
   * 调用方：ScanPage 威胁表格渲染、toggleThreatSelection、handleClearThreats、handleAddTrust。
   * Called by: ScanPage threat table rendering, toggleThreatSelection, handleClearThreats, handleAddTrust.
   * 被调用方：无外部服务；仅读取 ScanResult.fileId 与 ScanResult.description。
   * Calls: No external service; reads ScanResult.fileId and ScanResult.description.
   * 参数说明：threat 为 ScanResult，不能为空；优先使用后端统一映射的 fileId，description 仅作为兼容回退。
   * Parameters: threat is a non-null ScanResult; fileId is preferred, description is a compatibility fallback.
   * 返回值说明：返回文件路径字符串；空字符串表示当前结果缺少可操作路径。
   * Returns: File path string; empty string means no actionable path is available.
   * 内部关键变量：无持久变量；函数为纯映射。
   * Internal variables: No persistent variable; this is a pure mapping.
   * 接入方式：仅应在扫描结果 UI 层使用；不管理事务、不做权限校验。
   * Integration: Use only in the scan-result UI layer; no transaction or permission handling.
   * 错误处理：不抛异常；缺失路径时返回空字符串，由调用方跳过或禁用操作。
   * Error handling: Does not throw; returns empty path for callers to skip or disable actions.
   * 副作用：无数据库、文件、缓存、外部 API 副作用。
   * Side effects: No database, file, cache, or external API side effects.
   * 事务边界：无 Unit of Work；无 commit/rollback。
   * Transaction boundary: No Unit of Work; no commit/rollback.
   * 并发与幂等：纯函数，可重复调用，线程安全。
   * Concurrency and idempotency: Pure, repeatable, thread-safe.
   * 中文关键词：威胁路径，扫描结果，文件路径，隔离操作，信任操作，威胁选择，结果映射，路径回退，清除威胁，添加信任
   * English keywords: threat path, scan result, file path, quarantine action, trust action, threat selection, result mapping, path fallback, clear threat, add trust
   */
  const getThreatFilePath = (threat: (typeof threats)[number]): string => (
    threat.fileId || threat.description || ''
  )

  /**
   * 函数名称：toggleThreatSelection
   * 函数作用：切换单个威胁文件的选中状态，用于后续清除威胁或添加信任。
   * English purpose: Toggles one threat file selection for clear-threat or add-trust actions.
   * 调用方：ScanPage 威胁表格行 checkbox。
   * Called by: ScanPage threat table row checkbox.
   * 被调用方：setSelectedThreatPaths。
   * Calls: setSelectedThreatPaths.
   * 参数说明：path 为威胁文件路径，不能为空字符串；空路径会直接忽略。
   * Parameters: path is a threat file path and must not be empty; empty paths are ignored.
   * 返回值说明：无返回值；通过 React state 更新 UI。
   * Returns: No return value; updates UI via React state.
   * 内部关键变量：currentPaths 为当前已选路径集合，仅在 setState 回调内有效。
   * Internal variables: currentPaths is the current selected path list, scoped to the state callback.
   * 接入方式：仅由 UI 事件调用；不应从 store 或后端层调用。
   * Integration: Called only by UI events; should not be called from store or backend layers.
   * 错误处理：空路径直接返回原状态，不抛异常。
   * Error handling: Empty path keeps state unchanged and does not throw.
   * 副作用：仅修改组件本地状态。
   * Side effects: Only mutates local component state.
   * 事务边界：无 Unit of Work；无 commit/rollback。
   * Transaction boundary: No Unit of Work; no commit/rollback.
   * 并发与幂等：React 状态更新是幂等切换；重复点击会恢复原状态。
   * Concurrency and idempotency: React state update toggles idempotently; repeated clicks restore previous state.
   * 中文关键词：威胁选择，复选框，扫描结果，清除威胁，添加信任，选中文件，本地状态，文件路径，表格操作，批量操作
   * English keywords: threat selection, checkbox, scan result, clear threat, add trust, selected file, local state, file path, table action, batch action
   */
  const toggleThreatSelection = (path: string) => {
    if (!path) return

    setSelectedThreatPaths((currentPaths) =>
      currentPaths.includes(path)
        ? currentPaths.filter(selectedPath => selectedPath !== path)
        : [...currentPaths, path]
    )
  }

  /**
   * 函数名称：handleSelectAllThreats
   * 函数作用：全选或取消全选当前检测到的可操作威胁文件。
   * English purpose: Selects or clears all currently actionable threat files.
   * 调用方：ScanPage 威胁表格表头 checkbox。
   * Called by: ScanPage threat table header checkbox.
   * 被调用方：setSelectedThreatPaths。
   * Calls: setSelectedThreatPaths.
   * 参数说明：checked 为 checkbox 目标状态。
   * Parameters: checked is the target checkbox state.
   * 返回值说明：无返回值；通过 React state 更新 UI。
   * Returns: No return value; updates UI via React state.
   * 内部关键变量：threatPaths 为当前威胁结果中的路径白名单。
   * Internal variables: threatPaths is the current allowlist of threat result paths.
   * 接入方式：仅由扫描页 UI 事件调用。
   * Integration: Called only from ScanPage UI events.
   * 错误处理：无可操作路径时写入空数组，不抛异常。
   * Error handling: Writes an empty array when no actionable path exists; does not throw.
   * 副作用：仅修改组件本地状态。
   * Side effects: Only mutates local component state.
   * 事务边界：无 Unit of Work；无 commit/rollback。
   * Transaction boundary: No Unit of Work; no commit/rollback.
   * 并发与幂等：同一 checked 状态重复调用结果一致。
   * Concurrency and idempotency: Repeated calls with the same checked state produce the same result.
   * 中文关键词：全选威胁，取消全选，扫描结果，复选框，威胁路径，批量清除，批量信任，文件选择，本地状态，表格表头
   * English keywords: select all threats, clear selection, scan result, checkbox, threat path, batch clear, batch trust, file selection, local state, table header
   */
  const handleSelectAllThreats = (checked: boolean) => {
    setSelectedThreatPaths(checked ? threatPaths : [])
  }

  /**
   * 函数名称：handleClearThreats
   * 函数作用：将已选威胁文件逐个隔离，实现“清除威胁”操作。
   * English purpose: Quarantines selected threat files one by one for the clear-threat action.
   * 调用方：ScanPage “清除威胁”按钮。
   * Called by: ScanPage "Clear threats" button.
   * 被调用方：api/quarantine.isolateFile、toastStore.addToast、setSelectedThreatPaths、setThreatAction。
   * Calls: api/quarantine.isolateFile, toastStore.addToast, setSelectedThreatPaths, setThreatAction.
   * 参数说明：无参数；使用当前 selectedThreatPaths 对应的 selectedThreats。
   * Parameters: No parameters; uses selectedThreats derived from selectedThreatPaths.
   * 返回值说明：Promise<void>；成功和失败通过 Toast 呈现。
   * Returns: Promise<void>; success and failure are reported through Toast.
   * 内部关键变量：failedCount 记录隔离失败数量；threatPath 为当前处理文件路径。
   * Internal variables: failedCount tracks quarantine failures; threatPath is the current file path.
   * 接入方式：仅由接口层 UI 调用；隔离事务由后端 QuarantineService 管理。
   * Integration: Called only from the UI layer; quarantine transaction is managed by backend QuarantineService.
   * 错误处理：单个文件失败会记录 console.error 并继续处理，其后汇总提示。
   * Error handling: Per-file failures are logged with console.error and processing continues, then summarized.
   * 副作用：调用后端隔离文件，会加密写入隔离区、删除原文件、写数据库并触发后端事件。
   * Side effects: Calls backend quarantine, which encrypts to quarantine, removes original file, writes DB, and emits backend events.
   * 事务边界：前端不管理 Unit of Work；后端 isolate_file 管理一致性边界。
   * Transaction boundary: Frontend does not manage Unit of Work; backend isolate_file owns consistency.
   * 并发与幂等：串行执行；重复点击通过 threatAction 禁用避免并发；已隔离文件再次处理可能由后端返回失败。
   * Concurrency and idempotency: Serial execution; threatAction disables concurrent clicks; already quarantined files may fail in backend.
   * 中文关键词：清除威胁，隔离文件，威胁处理，批量操作，扫描结果，恶意文件，文件路径，隔离区，错误汇总，Fluent按钮
   * English keywords: clear threat, isolate file, threat handling, batch action, scan result, malware file, file path, quarantine, error summary, Fluent button
   */
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
      addToast('error', `清除威胁完成，${failedCount} 个文件处理失败`)
    } else {
      addToast('success', `已清除 ${selectedThreats.length} 个威胁`)
    }
  }

  /**
   * 函数名称：handleAddTrust
   * 函数作用：将已选威胁文件逐个加入启动信任列表。
   * English purpose: Adds selected threat files to the startup allowlist one by one.
   * 调用方：ScanPage “添加信任”按钮。
   * Called by: ScanPage "Add trust" button.
   * 被调用方：api/allowlist.addToAllowlist、toastStore.addToast、setSelectedThreatPaths、setThreatAction。
   * Calls: api/allowlist.addToAllowlist, toastStore.addToast, setSelectedThreatPaths, setThreatAction.
   * 参数说明：无参数；使用当前 selectedThreatPaths 对应的 selectedThreats。
   * Parameters: No parameters; uses selectedThreats derived from selectedThreatPaths.
   * 返回值说明：Promise<void>；成功和失败通过 Toast 呈现。
   * Returns: Promise<void>; success and failure are reported through Toast.
   * 内部关键变量：failedCount 记录加入信任失败数量；threatPath 为当前处理文件路径。
   * Internal variables: failedCount tracks allowlist failures; threatPath is the current file path.
   * 接入方式：仅由接口层 UI 调用；配置保存由后端 allowlist command 管理。
   * Integration: Called only from the UI layer; config persistence is managed by backend allowlist command.
   * 错误处理：单个文件失败会记录 console.error 并继续处理，其后汇总提示。
   * Error handling: Per-file failures are logged with console.error and processing continues, then summarized.
   * 副作用：调用后端写入启动信任列表配置，可能计算文件 hash。
   * Side effects: Calls backend to persist startup allowlist config and may compute file hash.
   * 事务边界：无前端 Unit of Work；后端配置保存负责持久化一致性。
   * Transaction boundary: No frontend Unit of Work; backend config save owns persistence consistency.
   * 并发与幂等：串行执行；重复添加已存在项可能由后端返回失败并汇总。
   * Concurrency and idempotency: Serial execution; duplicate entries may fail in backend and are summarized.
   * 中文关键词：添加信任，允许列表，启动信任，威胁文件，批量操作，扫描结果，文件路径，配置保存，错误汇总，Fluent按钮
   * English keywords: add trust, allowlist, startup trust, threat file, batch action, scan result, file path, config save, error summary, Fluent button
   */
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
      addToast('error', `添加信任完成，${failedCount} 个文件处理失败`)
    } else {
      addToast('success', `已添加 ${selectedThreats.length} 个文件到信任列表`)
    }
  }

  return (
    <section id="page-scan" className="page">
      <h1 className="page-title">文件扫描</h1>

      {/* 扫描控制区 / Scan controls */}
      <div className="scan-controls card">
        <div className="scan-actions">
          <button
            onClick={handleSelectDirectory}
            disabled={isScanning || isWalking}
            className="btn btn-outline-secondary scan-action"
          >
            {isWalking ? <Loader size={18} className="spinning" /> : <FolderOpen size={18} />}
            <span>{isWalking ? '正在遍历...' : '选择目录'}</span>
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
          <>
          <div className="threat-toolbar" role="region" aria-label="威胁处理操作">
            <div className="threat-toolbar-summary">
              <AlertTriangle size={18} />
              <span>已检测到 {threats.length} 个威胁</span>
              <span className="threat-toolbar-count">已选择 {selectedThreatPaths.length}</span>
            </div>
            <div className="threat-toolbar-actions">
              <button
                type="button"
                className="btn btn-danger threat-command"
                onClick={handleClearThreats}
                disabled={!hasSelectedThreats || threatAction !== null}
                title="将选中的威胁文件隔离到隔离区"
              >
                {threatAction === 'clear' ? <Loader size={16} className="spinning" /> : <Trash2 size={16} />}
                <span>清除威胁</span>
              </button>
              <button
                type="button"
                className="btn btn-outline-primary threat-command"
                onClick={handleAddTrust}
                disabled={!hasSelectedThreats || threatAction !== null}
                title="将选中的威胁文件加入启动信任列表"
              >
                {threatAction === 'trust' ? <Loader size={16} className="spinning" /> : <ShieldCheck size={16} />}
                <span>添加信任</span>
              </button>
            </div>
          </div>
          <div className="threat-scroll">
            <table>
              <thead>
                <tr>
                  <th className="select-col">
                    <input
                      type="checkbox"
                      checked={threatPaths.length > 0 && selectedThreatPaths.length === threatPaths.length}
                      onChange={(event) => handleSelectAllThreats(event.target.checked)}
                      aria-label="选择全部威胁"
                    />
                  </th>
                  <th>文件路径</th>
                  <th>检测结果</th>
                  <th>威胁类型</th>
                  <th>严重程度</th>
                </tr>
              </thead>
              <tbody>
                {threats.map((threat, index) => {
                  const threatPath = getThreatFilePath(threat)

                  return (
                  <tr key={`${threatPath}-${index}`}>
                    <td className="select-col">
                      <input
                        type="checkbox"
                        checked={selectedThreatPaths.includes(threatPath)}
                        disabled={!threatPath}
                        onChange={() => toggleThreatSelection(threatPath)}
                        aria-label={`选择威胁文件 ${threatPath || index + 1}`}
                      />
                    </td>
                    <td className="path-cell" title={threatPath || undefined}>
                      {threatPath || '未知文件'}
                    </td>
                    <td>
                      <strong style={{ color: threat.verdict === 'malware' ? 'var(--color-danger)' : 'var(--color-warning)' }}>
                        {(threat.verdict ?? 'unknown').toUpperCase()}
                      </strong>
                    </td>
                    <td>{threat.threatType || '-'}</td>
                    <td>
                      {getSeverityBadge(threat.verdict)}
                    </td>
                  </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          </>
        ) : null}
      </div>
    </section>
  )
}

export default ScanPage
