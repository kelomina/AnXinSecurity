import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { setAnimationsEnabled } from '../api/config'

export type ThemeMode = 'system' | 'light' | 'dark'

interface ThemeState {
  themeMode: ThemeMode
  actualTheme: 'light' | 'dark'
  animationsEnabled: boolean
  setThemeMode: (mode: ThemeMode) => void
  toggleAnimations: () => void
  initializeTheme: () => (() => void) | void
}

// 检测系统主题
const getSystemTheme = (): 'light' | 'dark' => {
  if (typeof window === 'undefined') return 'dark'
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

// 应用主题到 DOM
const applyTheme = (theme: 'light' | 'dark') => {
  document.documentElement.setAttribute('data-theme', theme)
}

export const useThemeStore = create<ThemeState>()(
  persist(
    (set, get) => ({
      themeMode: 'system',
      actualTheme: getSystemTheme(),
      animationsEnabled: true,
      
      setThemeMode: (mode: ThemeMode) => {
        const actualTheme = mode === 'system' ? getSystemTheme() : mode
        applyTheme(actualTheme)
        set({ themeMode: mode, actualTheme })
      },
      
      /**
       * 函数名称：toggleAnimations
       * 函数作用：切换动画开关并同步到后端持久化。
       * Purpose: Toggles animations and syncs to backend persistence.
       * 调用方：SettingsPage 动画开关
       * Called by: SettingsPage animation toggle
       * 副作用：修改 DOM data-animations 属性，调用后端 set_animations_enabled 持久化
       * Side effect: Modifies DOM data-animations attribute, calls backend set_animations_enabled
       * 中文关键词：动画开关，切换动画，动画持久化
       * English keywords: animation toggle, toggle animation, animation persistence
       */
      toggleAnimations: () => {
        const enabled = !get().animationsEnabled
        document.body.setAttribute('data-animations', enabled ? 'on' : 'off')
        set({ animationsEnabled: enabled })
        // 同步到后端持久化 / Sync to backend persistence
        setAnimationsEnabled(enabled).catch(err => {
          console.error('Failed to persist animation setting:', err)
        })
      },
      
      initializeTheme: () => {
        // 监听系统主题变化
        const mediaQuery = window.matchMedia('(prefers-color-scheme: light)')
        const handleChange = (e: MediaQueryListEvent) => {
          if (get().themeMode === 'system') {
            const newTheme = e.matches ? 'light' : 'dark'
            applyTheme(newTheme)
            set({ actualTheme: newTheme })
          }
        }
        
        mediaQuery.addEventListener('change', handleChange)
        
        // 初始化应用主题
        const { themeMode } = get()
        const initialTheme = themeMode === 'system' ? getSystemTheme() : themeMode
        applyTheme(initialTheme)
        set({ actualTheme: initialTheme })
        
        // 初始化动画状态
        document.body.setAttribute('data-animations', get().animationsEnabled ? 'on' : 'off')
        
        // 返回清理函数
        return () => mediaQuery.removeEventListener('change', handleChange)
      }
    }),
    {
      name: 'anxin-theme-storage',
      partialize: (state) => ({
        themeMode: state.themeMode,
        animationsEnabled: state.animationsEnabled
      })
    }
  )
)
