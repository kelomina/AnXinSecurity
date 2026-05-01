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
      return (
        <div className="app">
          <div className="content">
            <div className="error-boundary">
              <div className="card" style={{ maxWidth: '480px', margin: '80px auto', textAlign: 'center' }}>
                <div className="empty-icon">
                  <AlertTriangle size={48} style={{ color: 'var(--color-danger)' }} />
                </div>
                <h2 style={{ marginBottom: '12px' }}>应用发生错误</h2>
                <p style={{ color: 'var(--muted-fg)', marginBottom: '8px', fontSize: '14px' }}>
                  AnXin Security 遇到了意外错误，您可以尝试刷新恢复。
                </p>
                {this.state.error && (
                  <pre style={{
                    background: 'var(--panel-bg)',
                    border: '1px solid var(--panel-border)',
                    borderRadius: 'var(--radius-medium)',
                    padding: '12px',
                    marginBottom: '16px',
                    fontSize: '12px',
                    color: 'var(--color-danger)',
                    textAlign: 'left',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    maxHeight: '120px',
                    overflowY: 'auto',
                  }}>
                    {this.state.error.message}
                  </pre>
                )}
                <button className="btn btn-primary" onClick={this.handleReload}>
                  <RefreshCw size={16} />
                  重新加载
                </button>
              </div>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

export default ErrorBoundary
