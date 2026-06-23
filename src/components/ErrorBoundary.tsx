/**
 * 错误边界组件
 * Error Boundary component
 *
 * 捕获 React 组件树中的未处理错误，显示友好的错误恢复界面。
 * Catches unhandled errors in the React component tree and displays a friendly recovery UI.
 *
 * 调用方：main.tsx（包裹 App 组件）
 * Called by: main.tsx (wraps App component)
 *
 * 中文关键词：错误边界，异常捕获，错误恢复，React错误处理，降级UI
 * English keywords: error boundary, exception catch, error recovery, React error handling, fallback UI
 */
import { Component, ErrorInfo, ReactNode } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'
import { useI18nStore } from '../stores/i18nStore'
import { makeStyles, shorthands, tokens, Button } from '@fluentui/react-components'

const useErrorStyles = () => makeStyles({
  container: {
    display: 'grid',
    gridTemplateRows: '32px 1fr',
    gridTemplateColumns: '240px 1fr',
    height: '100vh',
    width: '100%',
  },
  content: {
    gridRow: '2',
    gridColumn: '2',
    overflowY: 'auto',
    ...shorthands.padding('24px'),
    backgroundColor: tokens.colorNeutralBackground1,
  },
  card: {
    maxWidth: '480px',
    margin: '80px auto',
    textAlign: 'center' as const,
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('32px'),
    boxShadow: tokens.shadow16,
  },
  icon: {
    marginBottom: '16px',
  },
  title: {
    marginBottom: '12px',
    fontSize: tokens.fontSizeBase500,
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground1,
  },
  description: {
    color: tokens.colorNeutralForeground3,
    marginBottom: '16px',
    fontSize: tokens.fontSizeBase300,
  },
  errorBox: {
    backgroundColor: tokens.colorNeutralBackground3,
    ...shorthands.border('1px', 'solid', tokens.colorPaletteRedBorder1),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.padding('12px'),
    marginBottom: '16px',
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorPaletteRedForeground2,
    textAlign: 'left' as const,
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    maxHeight: '120px',
    overflowY: 'auto',
    fontFamily: 'Consolas, "Courier New", monospace',
  },
})()

interface ErrorBoundaryProps {
  children: ReactNode
}

interface ErrorBoundaryState {
  hasError: boolean
  error: Error | null
}

class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('[ErrorBoundary] Unhandled error:', error, errorInfo)
    // 尝试上报错误到主进程日志 / Try to report error to main process log
    try {
      const reportError = async () => {
        const { reportError: report } = await import('../api/errorTrace')
        await report(`${error.message}\n${error.stack || ''}\nComponent Stack: ${errorInfo.componentStack || ''}`, 'renderer')
      }
      reportError()
    } catch {
      // 上报失败不影响错误展示 / Reporting failure doesn't affect error display
    }
  }

  /**
   * 处理重新加载 / Handle reload action
   *
   * 先重置错误状态使组件树重新渲染，再执行页面重载以清空 store 中的脏数据。
   * Resets error state to re-render the component tree, then reloads the page to clear stale store data.
   *
   * 调用方：ErrorBoundary 重新加载按钮
   * Called by: ErrorBoundary reload button
   *
   * 副作用：调用 window.location.reload() 完全重载页面
   * Side effects: calls window.location.reload() to fully reload the page
   *
   * 中文关键词：重新加载，错误恢复，页面重载
   * English keywords: reload, error recovery, page reload
   */
  handleReload = (): void => {
    this.setState({ hasError: false, error: null })
    window.location.reload()
  }

  render(): ReactNode {
    if (this.state.hasError) {
      const { t } = useI18nStore.getState()
      const styles = useErrorStyles()

      return (
        <div className={styles.container}>
          <div className={styles.content}>
            <div className={styles.card}>
              <div className={styles.icon}>
                <AlertTriangle size={48} color={tokens.colorPaletteRedForeground2} />
              </div>
              <h2 className={styles.title}>{t('error_boundary_title')}</h2>
              <p className={styles.description}>
                {t('error_boundary_desc')}
              </p>
              {this.state.error && (
                <pre className={styles.errorBox}>
                  {this.state.error.message}
                </pre>
              )}
              <Button
                appearance="primary"
                icon={<RefreshCw size={16} />}
                onClick={this.handleReload}
              >
                {t('error_boundary_reload')}
              </Button>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

export default ErrorBoundary
