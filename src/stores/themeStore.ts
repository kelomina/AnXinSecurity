import { create } from 'zustand'
import { persist } from 'zustand/middleware'

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
      
      toggleAnimations: () => {
        const enabled = !get().animationsEnabled
        document.body.setAttribute('data-animations', enabled ? 'on' : 'off')
        set({ animationsEnabled: enabled })
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
