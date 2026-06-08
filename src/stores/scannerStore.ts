/**
 * 扫描状态管理 Store
 * Scanner state management store
 *
 * 使用 Zustand 管理文件扫描的状态：选中文件、扫描进度、扫描结果等。
 * Uses Zustand to manage file scanning state: selected files, scan progress, results, etc.
 */
import { create } from 'zustand'
import { scanFile, scanBatch, cancelScan, onScanProgress, type ScanResult, type ScanProgressEvent } from '../api/scanner'

/** 扫描统计信息/Scan statistics */
interface ScanStats {
  totalFiles: number
  threatsFound: number
  cleanFiles: number
  elapsedTime: number
}

/** 扫描状态接口/Scanner state interface */
interface ScannerState {
  selectedFiles: string[]
  isScanning: boolean
  scanProgress: number
  currentFile?: string
  scanResults: ScanResult[]
  lastScanStats?: ScanStats
  error: string | null
  pendingFiles: string[]
  isWalkComplete: boolean

  setSelectedFiles: (files: string[]) => void
  addSelectedFiles: (files: string[]) => void
  clearSelection: () => void
  startScan: () => Promise<void>
  cancelScan: () => Promise<void>
  clearResults: () => void
  removeScanResultsByPath: (paths: string[]) => void
  clearError: () => void
  appendPendingFiles: (files: string[]) => void
  setWalkComplete: () => void
}

export const useScannerStore = create<ScannerState>((set, get) => ({
  selectedFiles: [],
  isScanning: false,
  scanProgress: 0,
  currentFile: undefined,
  scanResults: [],
  lastScanStats: undefined,
  error: null,
  pendingFiles: [],
  isWalkComplete: false,

  /**
   * 函数名称：setSelectedFiles
   * 函数作用：直接设置选中文件列表（覆盖旧列表）。
   * Purpose: Directly sets the selected file list (replaces old list).
   * 调用方：外部直接调用
   * Called by: External direct calls
   * 中文关键词：设置文件，文件选择，覆盖选择
   * English keywords: set files, file selection, replace selection
   */
  setSelectedFiles: (files) => set({ selectedFiles: files }),

  /**
   * 函数名称：addSelectedFiles
   * 函数作用：追加文件到选中列表（自动去重）。
   * Purpose: Appends files to the selection list (auto dedup).
   * 调用方：ScanPage 文件/目录选择按钮
   * Called by: ScanPage file/directory selection buttons
   * 中文关键词：添加文件，追加选择，去重
   * English keywords: add files, append selection, dedup
   */
  addSelectedFiles: (files) => {
    const { selectedFiles } = get()
    const unique = [...new Set([...selectedFiles, ...files])]
    set({ selectedFiles: unique, error: null })
  },

  /**
   * 函数名称：clearSelection
   * 函数作用：清空所有已选文件。
   * Purpose: Clears all selected files.
   * 调用方：ScanPage 清除选择按钮
   * Called by: ScanPage clear selection button
   * 中文关键词：清除选择，清空文件，重置选择
   * English keywords: clear selection, clear files, reset selection
   */
  clearSelection: () => set({ selectedFiles: [] }),

  /**
   * 函数名称：startScan
   * 函数作用：开始扫描选中文件，支持增量追加。
   *   扫描当前 selectedFiles 后，自动检查 pendingFiles：
   *   - 有等待文件 → 移到 selectedFiles 继续扫描
   *   - 无等待文件 + 遍历未完成 → 轮询等待
   *   - 无等待文件 + 遍历完成 → 结束
   * Purpose: Starts scanning selected files with incremental append support.
   *   After current batch, checks pendingFiles:
   *   - Has pending → move to selectedFiles and continue
   *   - No pending + walk incomplete → poll and wait
   *   - No pending + walk complete → finish
   * 调用方：ScanPage 开始扫描按钮 / handleSelectDirectory（自动触发）
   * Called by: ScanPage start scan button / handleSelectDirectory (auto-trigger)
   * 副作用：调用引擎 TCP API，监听进度事件，更新 store 状态
   * Side effect: Calls engine TCP API, listens for progress events, updates store state
   * 错误处理：引擎连接失败、扫描超时、返回值异常均捕获并设置 error
   * Error handling: Engine connection failures, scan timeouts, abnormal returns all caught and set to error
   * 中文关键词：开始扫描，增量扫描，边扫边遍历，批量扫描
   * English keywords: start scan, incremental scan, scan-while-walk, batch scan
   */
  startScan: async () => {
    const { selectedFiles } = get()
    if (selectedFiles.length === 0) {
      set({ error: '请先选择文件或目录' })
      return
    }

    set({ isScanning: true, scanProgress: 0, error: null, scanResults: [], lastScanStats: undefined })

    const startTime = Date.now()

    // 监听扫描进度事件（逐文件进度推送）
    // Listen for scan progress events (per-file progress push)
    const unlistenProgress = onScanProgress((progress: ScanProgressEvent) => {
      set({
        scanProgress: progress.percentage,
        currentFile: progress.currentFile,
      })
    })

    const allResults: ScanResult[] = []

    try {
      // 循环扫描：处理当前批次 → 检查 pending → 继续或结束
      // Loop: process current batch → check pending → continue or finish
      let shouldContinueScanning = true
      while (shouldContinueScanning) {
        const currentBatch = get().selectedFiles
        if (currentBatch.length === 0) {
          shouldContinueScanning = false
          continue
        }

        let batchResults: ScanResult[]

        if (currentBatch.length === 1) {
          const result = await scanFile(currentBatch[0])
          batchResults = [result]
        } else {
          const batchResult = await scanBatch(currentBatch)
          batchResults = batchResult.results || []
        }

        allResults.push(...batchResults)

        // 更新已完成的扫描结果
        // Update completed scan results
        const threats = allResults.filter(r => r.verdict && r.verdict !== 'clean').length
        const clean = allResults.length - threats
        const elapsedTime = Math.round((Date.now() - startTime) / 1000)

        set({
          scanResults: [...allResults],
          selectedFiles: [],
          lastScanStats: {
            totalFiles: allResults.length,
            threatsFound: threats,
            cleanFiles: clean,
            elapsedTime,
          }
        })

        // 检查下一批待扫描文件
        // Check next batch
        const state = get()
        if (state.pendingFiles.length > 0) {
          // 有等待文件 → 移到 selectedFiles 继续扫描
          // Has pending files → move to selectedFiles and continue
          set({
            selectedFiles: [...state.pendingFiles],
            pendingFiles: [],
          })
        } else if (state.isWalkComplete) {
          // 遍历完成 + 无等待 → 全部扫描完成
          // Walk complete + no pending → all done
          shouldContinueScanning = false
        } else {
          // 遍历未完成但无等待文件 → 等待轮询
          // Walk incomplete but no pending → poll and wait
          // 每次轮询间隔 500ms，防止忙等
          // 500ms poll interval to prevent busy waiting
          await new Promise(resolve => setTimeout(resolve, 500))
          // 继续循环检查 pendingFiles / isWalkComplete
          // Continue loop to re-check pendingFiles / isWalkComplete
        }
      }
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : '扫描失败',
        isScanning: false,
        scanProgress: 0,
        currentFile: undefined,
      })
      return
    } finally {
      unlistenProgress()
    }

    // 正常结束
    // Normal completion
    set({
      isScanning: false,
      scanProgress: 100,
      currentFile: undefined,
    })
  },

  /**
   * 函数名称：cancelScan
   * 函数作用：取消当前扫描操作。向引擎发送取消请求并终止本地状态。
   * Purpose: Cancels the current scan. Sends cancel request to engine and terminates local state.
   * 调用方：ScanPage 取消按钮（isScanning=true 时点击）
   * Called by: ScanPage cancel button (clicked when isScanning=true)
   * 副作用：调用后端 cancel_scan 命令，重置本地扫描状态
   * Side effect: Calls backend cancel_scan command, resets local scan state
   * 中文关键词：取消扫描，终止扫描，中断操作，取消操作
   * English keywords: cancel scan, abort scan, interrupt operation, cancel operation
   */
  cancelScan: async () => {
    // 尝试向引擎发送取消请求（fire-and-forget）
    // Try to send cancel request to engine (fire-and-forget)
    try {
      await cancelScan()
    } catch (e) {
      // 忽略后端取消失败，前端状态仍需重置
      // Ignore backend cancel failure, frontend state still needs reset
      console.error('[scannerStore] Cancel scan failed:', e)
    }
    set({ isScanning: false, scanProgress: 0, currentFile: undefined })
  },

  /**
   * 函数名称：clearResults
   * 函数作用：清空扫描结果和统计信息。
   * Purpose: Clears scan results and stats.
   * 调用方：ScanPage 重新扫描前
   * Called by: ScanPage before re-scanning
   * 中文关键词：清除结果，重置扫描，清空检测
   * English keywords: clear results, reset scan, clear detection
   */
  clearResults: () => set({ scanResults: [], lastScanStats: undefined }),

  /**
   * 函数名称：removeScanResultsByPath
   * 函数作用：从当前扫描结果中移除指定文件路径对应的结果，并同步刷新最近一次扫描统计。
   * English purpose: Removes scan results for the given file paths and refreshes the latest scan stats.
   * 调用方：ScanPage handleClearThreats（威胁隔离成功后）。
   * Called by: ScanPage handleClearThreats after successful quarantine.
   * 被调用方：Zustand set。
   * Calls: Zustand set.
   * 参数说明：paths 为已处理文件路径列表；空数组表示不改变状态。
   * Parameters: paths is the list of handled file paths; an empty array keeps state unchanged.
   * 返回值说明：无返回值；通过 store 状态更新扫描结果。
   * Returns: No return value; updates scan results through store state.
   * 内部关键变量：pathSet 用于 O(1) 判断结果是否应移除；remainingResults 为保留结果。
   * Internal variables: pathSet enables O(1) removal checks; remainingResults keeps results not removed.
   * 接入方式：仅由扫描页 UI 层在确认文件已处理后调用。
   * Integration: Called only by the scan UI layer after files are confirmed handled.
   * 错误处理：不抛异常；空路径会被过滤。
   * Error handling: Does not throw; empty paths are filtered.
   * 副作用：只修改前端 store；不写文件、不写数据库、不调用后端。
   * Side effects: Only mutates frontend store; no file, database, or backend calls.
   * 事务边界：无 Unit of Work；后端隔离事务已在调用前完成。
   * Transaction boundary: No Unit of Work; backend quarantine transaction has already completed before this call.
   * 并发与幂等：对同一路径重复调用结果一致。
   * Concurrency and idempotency: Repeated calls for the same path produce the same state.
   * 中文关键词：扫描结果，移除结果，清除威胁，隔离成功，统计刷新，前端状态，路径匹配，威胁列表，幂等，Zustand
   * English keywords: scan result, remove result, clear threat, quarantine success, stats refresh, frontend state, path matching, threat list, idempotent, Zustand
   */
  removeScanResultsByPath: (paths: string[]) => {
    const pathSet = new Set(paths.filter(Boolean))
    if (pathSet.size === 0) return

    set((state) => {
      const remainingResults = state.scanResults.filter((result) =>
        !pathSet.has(result.fileId) && !(result.description && pathSet.has(result.description))
      )
      const threatsFound = remainingResults.filter(result => result.verdict && result.verdict !== 'clean').length
      const cleanFiles = remainingResults.length - threatsFound

      return {
        scanResults: remainingResults,
        lastScanStats: state.lastScanStats
          ? {
              ...state.lastScanStats,
              totalFiles: remainingResults.length,
              threatsFound,
              cleanFiles,
            }
          : undefined,
      }
    })
  },

  /**
   * 函数名称：clearError
   * 函数作用：清除错误信息。
   * Purpose: Clears the error message.
   * 调用方：ScanPage 错误卡片关闭按钮
   * Called by: ScanPage error card close button
   * 中文关键词：清除错误，关闭错误提示
   * English keywords: clear error, dismiss error
   */
  clearError: () => set({ error: null }),

  /**
   * 函数名称：appendPendingFiles
   * 函数作用：将后台遍历新发现的文件加入待扫描队列。
   *   若正在扫描则放入 pendingFiles，等待当前批次完成后自动处理；
   *   若未在扫描则直接加入 selectedFiles。
   * Purpose: Adds newly discovered files from background walk to the scan queue.
   *   If scanning: adds to pendingFiles, auto-processed after current batch.
   *   If not scanning: directly adds to selectedFiles.
   * 调用方：ScanPage handleSelectDirectory（walk-file-batch 事件回调）
   * Called by: ScanPage handleSelectDirectory (walk-file-batch event callback)
   * 中文关键词：追加文件，待扫描队列，增量扫描
   * English keywords: append files, pending queue, incremental scan
   */
  appendPendingFiles: (files: string[]) => {
    const { isScanning, isWalkComplete } = get()
    if (isScanning) {
      // 正在扫描 → 放入待扫描队列，当前批次完成后自动处理
      // Scanning → queue for next batch cycle
      set(state => ({ pendingFiles: [...state.pendingFiles, ...files] }))
    } else if (!isWalkComplete) {
      // 未在扫描 + 遍历未完成 → 放入 selectedFiles 供用户触发扫描
      // Not scanning + walk in progress → add to selectedFiles
      set(state => {
        const unique = [...new Set([...state.selectedFiles, ...files])]
        return { selectedFiles: unique }
      })
    }
  },

  /**
   * 函数名称：setWalkComplete
   * 函数作用：标记后台遍历已完成，通知扫描循环可以结束。
   * Purpose: Marks background walk as complete, notifying the scan loop to finish.
   * 调用方：ScanPage handleSelectDirectory（walk-complete 事件回调）
   * Called by: ScanPage handleSelectDirectory (walk-complete event callback)
   * 中文关键词：遍历完成，扫描结束，后台遍历状态
   * English keywords: walk complete, scan finish, background walk status
   */
  setWalkComplete: () => set({ isWalkComplete: true }),
}))
