import { create } from 'zustand'
import { scanFile, scanBatch, type ScanResult } from '../api/scanner'

interface ScanStats {
  totalFiles: number
  threatsFound: number
  cleanFiles: number
  elapsedTime: number
}

interface ScannerState {
  selectedFiles: string[]
  isScanning: boolean
  scanProgress: number
  currentFile?: string
  scanResults: ScanResult[]
  lastScanStats?: ScanStats
  error: string | null

  setSelectedFiles: (files: string[]) => void
  addSelectedFiles: (files: string[]) => void
  clearSelection: () => void
  startScan: () => Promise<void>
  cancelScan: () => void
  clearResults: () => void
}

export const useScannerStore = create<ScannerState>((set, get) => ({
  selectedFiles: [],
  isScanning: false,
  scanProgress: 0,
  currentFile: undefined,
  scanResults: [],
  lastScanStats: undefined,
  error: null,

  setSelectedFiles: (files) => set({ selectedFiles: files }),

  addSelectedFiles: (files) => {
    const { selectedFiles } = get()
    const unique = [...new Set([...selectedFiles, ...files])]
    set({ selectedFiles: unique })
  },

  clearSelection: () => set({ selectedFiles: [] }),

  startScan: async () => {
    const { selectedFiles } = get()
    if (selectedFiles.length === 0) {
      set({ error: '请先选择文件或目录' })
      return
    }

    set({ isScanning: true, scanProgress: 0, error: null, scanResults: [] })

    try {
      let results: ScanResult[]

      if (selectedFiles.length === 1) {
        const result = await scanFile(selectedFiles[0])
        results = [result]
      } else {
        const batchResult = await scanBatch(selectedFiles)
        results = batchResult.results || []
      }

      const threats = results.filter(r => r.verdict !== 'clean').length
      const clean = results.length - threats

      set({
        scanResults: results,
        isScanning: false,
        scanProgress: 100,
        lastScanStats: {
          totalFiles: results.length,
          threatsFound: threats,
          cleanFiles: clean,
          elapsedTime: 0,
        }
      })
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : '扫描失败',
        isScanning: false
      })
    }
  },

  cancelScan: () => set({ isScanning: false, scanProgress: 0 }),

  clearResults: () => set({ scanResults: [], lastScanStats: undefined }),
}))
