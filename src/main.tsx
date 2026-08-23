import React from 'react'
import ReactDOM from 'react-dom/client'
import { FluentProvider } from '@fluentui/react-components'
import { getCurrentWindow } from '@tauri-apps/api/window'
import ErrorBoundary from './components/ErrorBoundary'
import App from './App'
import InterceptionWindowApp from './components/InterceptionWindowApp'
import ExitConfirmWindowApp from './components/ExitConfirmWindowApp'
import { customLightTheme, customDarkTheme } from './theme/customTheme'
import './styles/global.css'

const currentWindow = getCurrentWindow()
const windowLabel = currentWindow.label
const isInterceptionWindow = windowLabel === 'interception'
const isExitConfirmWindow = windowLabel === 'exit-confirm'

let RootComponent: React.FC = App
if (isInterceptionWindow) {
  RootComponent = InterceptionWindowApp
} else if (isExitConfirmWindow) {
  RootComponent = ExitConfirmWindowApp
}

// 拦截窗口标记：用于全局 CSS 覆盖 Fluent Dialog 默认 padding/backdrop
if (isInterceptionWindow || isExitConfirmWindow) {
  document.body.classList.add('interception-window')
}

// Fluent 2 Provider wrapper with theme detection
const Root = () => {
  const [theme, setTheme] = React.useState<'light' | 'dark'>(() => {
    const root = document.documentElement
    const currentTheme = root.getAttribute('data-theme')
    if (currentTheme === 'light' || currentTheme === 'dark') return currentTheme
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  })

  React.useEffect(() => {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.attributeName === 'data-theme') {
          const newTheme = document.documentElement.getAttribute('data-theme')
          if (newTheme === 'light' || newTheme === 'dark') {
            setTheme(newTheme)
          }
        }
      })
    })

    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme']
    })

    return () => observer.disconnect()
  }, [])

  return (
    <FluentProvider theme={theme === 'dark' ? customDarkTheme : customLightTheme}>
      <ErrorBoundary>
        <RootComponent />
      </ErrorBoundary>
    </FluentProvider>
  )
}

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
)
