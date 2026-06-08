/**
 * 设置页面
 * Settings page
 *
 * 提供通用设置、信任项目和开发者设置。
 * Provides general settings, unified trust item management, and dev settings.
 *
 * 中文关键词：设置，信任项目，排除项合并，允许项目合并
 * English keywords: settings, trust items, merged exclusions, merged allowlist
 */
import React, { useEffect, useState } from 'react'
import { useConfigStore } from '../stores/configStore'
import { useThemeStore, ThemeMode } from '../stores/themeStore'
import { Moon, Sun, Monitor, Zap, FolderOpen, FilePlus, Trash2, Shield, Plus, Key } from 'lucide-react'
import { open } from '@tauri-apps/plugin-dialog'

import { devSettingsUnlock, devSettingsSave } from '../api/devSettings'

/**
 * 函数名称：SettingsPage
 * 函数作用：渲染设置页；在单个“信任项目”入口下统一管理允许项目和扫描排除项，并保留通用和开发者设置。
 * Function name: SettingsPage
 * Purpose: Renders the settings page; manages allowed items and scan exclusions through one trust item workflow while keeping general and dev settings.
 * 调用方：应用路由/页面容器间接渲染本组件；当前仅确认 SettingsPage 作为默认导出被页面注册逻辑使用。
 * Called by: The app route/page container renders this component indirectly; currently confirmed as the default SettingsPage export.
 * 被调用方：useConfigStore 的 loadTrustItems/addTrustItem/removeTrustItem、useThemeStore、Tauri dialog open、devSettingsUnlock、devSettingsSave。
 * Calls: useConfigStore loadTrustItems/addTrustItem/removeTrustItem, useThemeStore, Tauri dialog open, devSettingsUnlock, devSettingsSave.
 * 参数说明：无 React props。
 * Parameters: No React props.
 * 返回值说明：React.FC 渲染结果；空状态由各列表的 empty-state 分支表达。
 * Returns: React.FC render output; empty list states are rendered by the empty-state branches.
 * 错误处理：设置命令失败时以 alert 或页面消息反馈；不吞掉 Promise 异常。
 * Error handling: Command failures are shown through alerts or page messages; Promise errors are not silently swallowed.
 * 副作用：通过统一信任项目 store action 写入运行时允许项目/排除项和监控配置；不直接写配置文件。
 * Side effects: Uses unified trust item store actions to persist runtime allowed items/exclusions and monitoring settings; does not write config files directly.
 * 中文关键词：设置页，信任项目，功能合并，允许项目，排除项，扫描生效，监控生效，运行时列表，配置页
 * English keywords: settings page, trust items, function merge, allowed items, exclusions, scan effective, monitor effective, runtime lists, config page
 */
const SettingsPage: React.FC = () => {
  const {
    config, setBehaviorMonitoring, setProcessMonitoring, setFileMonitoring,
    trustItems,
    loadTrustItems, addTrustItem, removeTrustItem
  } = useConfigStore()
  const { themeMode, setThemeMode, animationsEnabled, toggleAnimations } = useThemeStore()

  const [activeTab, setActiveTab] = useState<'general'|'trust'|'dev'>('general')
  const [confirmDeleteTrustIndex, setConfirmDeleteTrustIndex] = useState<number | null>(null)

  // 信任项目表单
  const [newTrustPath, setNewTrustPath] = useState('')
  const [newTrustType, setNewTrustType] = useState<'file' | 'directory'>('file')
  const [newTrustDesc, setNewTrustDesc] = useState('')

  // 开发者设置
  const [devPassword, setDevPassword] = useState('')
  const [devData, setDevData] = useState('')
  const [devUnlocked, setDevUnlocked] = useState(false)
  const [devMessage, setDevMessage] = useState('')
  useEffect(() => { loadTrustItems() }, [loadTrustItems])

  const themeOptions: { value: ThemeMode; label: string; icon: React.ElementType }[] = [
    { value: 'system', label: '跟随系统', icon: Monitor },
    { value: 'light', label: '浅色模式', icon: Sun },
    { value: 'dark', label: '深色模式', icon: Moon },
  ]

  // 信任项目操作
  const handleSelectTrustDir = async () => {
    const selected = await open({ directory: true, multiple: false, title: '选择要信任的目录' })
    if (selected) {
      setNewTrustPath(selected as string)
      setNewTrustType('directory')
    }
  }
  const handleSelectTrustFile = async () => {
    const selected = await open({ multiple: false, title: '选择要信任的文件或程序' })
    if (selected) {
      setNewTrustPath(selected as string)
      setNewTrustType('file')
    }
  }
  const handleAddTrustItem = async () => {
    if (!newTrustPath.trim()) return
    try {
      await addTrustItem(newTrustPath, newTrustType, newTrustDesc || undefined)
      setNewTrustPath('')
      setNewTrustDesc('')
      setNewTrustType('file')
    } catch (e) {
      alert(`添加失败: ${e}`)
    }
  }
  const handleRemoveTrustItem = async (index: number) => {
    const entry = trustItems[index]; if (!entry) return
    try {
      await removeTrustItem(entry.path)
      setConfirmDeleteTrustIndex(null)
    } catch (e) {
      alert(`删除失败: ${e}`)
    }
  }

  // 开发者设置操作
  const handleDevUnlock = async () => {
    try { const result = await devSettingsUnlock(devPassword); setDevData(JSON.stringify(result, null, 2)); setDevUnlocked(true); setDevMessage('解锁成功') }
    catch (e) { setDevMessage(`解锁失败: ${e}`) }
  }
  const handleDevSave = async () => {
    try {
      await devSettingsSave(devPassword, JSON.parse(devData))
      setDevMessage('保存成功')
    }
    catch (e) { setDevMessage(`保存失败: ${e}`) }
  }

  const tabs = [
    { id: 'general' as const, label: '通用设置' },
    { id: 'trust' as const, label: `信任项目 (${trustItems.length})` },
    { id: 'dev' as const, label: '开发者' },
  ]

  return (
    <section id="page-settings" className="page">
      <h1 className="page-title">设置</h1>

      {/* 选项卡导航 */}
      <div className="settings-tabs card" style={{ marginBottom: '16px', padding: '8px' }}>
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {tabs.map(t => (
            <button key={t.id}
              className={`btn btn-sm ${activeTab === t.id ? 'btn-primary' : 'btn-outline-secondary'}`}
              onClick={() => setActiveTab(t.id)}>
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* 通用设置 */}
      {activeTab === 'general' && (<>
        <div className="settings-section card">
          <h3>监控设置</h3>
          <div className="toggle-setting">
            <div className="toggle-info">
              <span className="toggle-label">EDR 行为监控</span>
              <span className="toggle-description">
                实时监控系统进程行为，消耗较多系统资源，非必要不建议开启
              </span>
            </div>
            <div
              className={`toggle-switch ${config?.behaviorMonitoring?.enabled ? 'toggle-active' : ''}`}
              onClick={() => {
                setBehaviorMonitoring(!(config?.behaviorMonitoring?.enabled || false))
              }}
              role="switch"
              aria-checked={config?.behaviorMonitoring?.enabled || false}
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  setBehaviorMonitoring(!(config?.behaviorMonitoring?.enabled || false))
                }
              }}
            >
              <span className="toggle-slider" />
            </div>
          </div>

          <div className="toggle-setting" style={{ borderTop: '1px solid var(--panel-border)', paddingTop: '12px' }}>
            <div className="toggle-info">
              <span className="toggle-label">进程监控</span>
              <span className="toggle-description">
                遍历系统进程并对新创建的进程调用扫描引擎进行检测
              </span>
            </div>
            <div
              className={`toggle-switch ${config?.processMonitoring?.enabled ? 'toggle-active' : ''}`}
              onClick={() => {
                setProcessMonitoring(!(config?.processMonitoring?.enabled || false))
              }}
              role="switch"
              aria-checked={config?.processMonitoring?.enabled || false}
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  setProcessMonitoring(!(config?.processMonitoring?.enabled || false))
                }
              }}
            >
              <span className="toggle-slider" />
            </div>
          </div>

          <div className="toggle-setting" style={{ borderTop: '1px solid var(--panel-border)', paddingTop: '12px' }}>
            <div className="toggle-info">
              <span className="toggle-label">文件监控</span>
              <span className="toggle-description">
                从 ETW 中读取文件创建和修改事件，对这些事件中的文件调用扫描引擎进行检测
              </span>
            </div>
            <div
              className={`toggle-switch ${config?.fileMonitoring?.enabled ? 'toggle-active' : ''}`}
              onClick={() => {
                setFileMonitoring(!(config?.fileMonitoring?.enabled || false))
              }}
              role="switch"
              aria-checked={config?.fileMonitoring?.enabled || false}
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  setFileMonitoring(!(config?.fileMonitoring?.enabled || false))
                }
              }}
            >
              <span className="toggle-slider" />
            </div>
          </div>
        </div>
        <div className="settings-section card">
          <h3>界面设置</h3>
          <div className="setting-group">
            <label className="setting-label">主题模式</label>
            <div className="theme-selector">
              {themeOptions.map(o => {
                const Icon = o.icon
                return (
                  <button key={o.value} className={`theme-option ${themeMode === o.value ? 'active' : ''}`} onClick={() => setThemeMode(o.value)}>
                    <Icon size={20} /><span>{o.label}</span>
                  </button>
                )
              })}
            </div>
          </div>
          <div className="toggle-setting">
            <div className="toggle-info">
              <div className="toggle-label-row"><Zap size={18} /><span className="toggle-label">启用动画效果</span></div>
              <span className="toggle-description">页面切换和交互动画</span>
            </div>
            <div
              className={`toggle-switch ${animationsEnabled ? 'toggle-active' : ''}`}
              onClick={toggleAnimations}
              role="switch"
              aria-checked={animationsEnabled}
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  toggleAnimations()
                }
              }}
            >
              <span className="toggle-slider" />
            </div>
          </div>
        </div>
      </>)}

      {/* 信任项目 */}
      {activeTab === 'trust' && (
        <div className="settings-section card">
          <h3>信任项目</h3>
          <p style={{ color: 'var(--muted-fg)', fontSize: '14px', marginBottom: '16px' }}>信任项目会在扫描和实时保护中跳过；文件项目会同时加入启动允许列表。</p>
          <div className="setting-group">
            <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
              <input type="text" value={newTrustPath} onChange={(e) => setNewTrustPath(e.target.value)} placeholder="输入路径或点击右侧按钮选择"
                style={{ flex: 1, padding: '10px 12px', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)', background: 'var(--panel-bg)', color: 'var(--app-fg)' }} />
              <button className="btn btn-outline-secondary" onClick={handleSelectTrustDir}><FolderOpen size={18} /></button>
              <button className="btn btn-outline-secondary" onClick={handleSelectTrustFile}><FilePlus size={18} /></button>
            </div>
            <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
              <input type="text" value={newTrustDesc} onChange={(e) => setNewTrustDesc(e.target.value)} placeholder="描述（可选）"
                style={{ flex: 1, padding: '10px 12px', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)', background: 'var(--panel-bg)', color: 'var(--app-fg)', fontSize: '13px' }} />
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <label style={{ fontSize: '14px', color: 'var(--muted-fg)' }}><input type="radio" checked={newTrustType === 'file'} onChange={() => setNewTrustType('file')} style={{ marginRight: '4px' }} />文件</label>
              <label style={{ fontSize: '14px', color: 'var(--muted-fg)' }}><input type="radio" checked={newTrustType === 'directory'} onChange={() => setNewTrustType('directory')} style={{ marginRight: '4px' }} />目录</label>
              <button className="btn btn-primary" onClick={handleAddTrustItem} disabled={!newTrustPath.trim()} style={{ marginLeft: 'auto' }}><Plus size={16} />添加信任项目</button>
            </div>
          </div>
          <div style={{ marginTop: '16px' }}>
            {trustItems.length === 0 ? (
              <div className="empty-state" style={{ padding: '32px' }}><Shield size={48} /><p>暂无信任项目</p></div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {trustItems.map((entry, index) => (
                  <div key={index} style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '12px', background: 'var(--panel-bg)', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: '14px', fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{entry.path}</div>
                      <div style={{ fontSize: '12px', color: 'var(--muted-fg)', marginTop: '2px' }}>
                        {entry.entry_type === 'directory' ? '目录' : '文件'}
                        {' · '}
                        {entry.sources.includes('allowlist') ? '启动允许' : '扫描排除'}
                        {entry.hash && ` · SHA256: ${entry.hash.substring(0, 16)}...`}
                        {entry.description && ` · ${entry.description}`}
                      </div>
                    </div>
                    <button className="btn btn-outline-danger btn-sm" onClick={() => setConfirmDeleteTrustIndex(index)}><Trash2 size={16} /></button>
                  </div>
                ))}
              </div>
            )}
          </div>
          {confirmDeleteTrustIndex !== null && trustItems[confirmDeleteTrustIndex] && (
            <div className="modal-overlay" onClick={() => setConfirmDeleteTrustIndex(null)}>
              <div className="modal-surface" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '400px' }}>
                <h3>确认删除</h3>
                <p style={{ marginTop: '8px', color: 'var(--muted-fg)' }}>确定要移除 <strong>{trustItems[confirmDeleteTrustIndex].path}</strong> 吗？</p>
                <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', marginTop: '16px' }}>
                  <button className="btn btn-outline-secondary" onClick={() => setConfirmDeleteTrustIndex(null)}>取消</button>
                  <button className="btn btn-danger" onClick={() => handleRemoveTrustItem(confirmDeleteTrustIndex)}>确认删除</button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 开发者设置 */}
      {activeTab === 'dev' && (
        <div className="settings-section card">
          <h3>开发者设置</h3>
          <p style={{ color: 'var(--muted-fg)', fontSize: '14px', marginBottom: '16px' }}>密码保护的加密配置。修改前请确认了解各项配置的作用。</p>
          {devMessage && <div style={{ padding: '8px 12px', marginBottom: '12px', borderRadius: '8px', background: devMessage.includes('失败') ? 'rgba(255,77,79,0.1)' : 'rgba(82,196,26,0.1)', color: devMessage.includes('失败') ? 'var(--danger)' : 'var(--success)', fontSize: '14px' }}>{devMessage}</div>}
          {!devUnlocked ? (
            <div>
              <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
                <input type="password" value={devPassword} onChange={(e) => setDevPassword(e.target.value)} placeholder="输入开发者密码"
                  style={{ flex: 1, padding: '10px 12px', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)', background: 'var(--panel-bg)', color: 'var(--app-fg)' }} />
                <button className="btn btn-primary" onClick={handleDevUnlock} disabled={!devPassword}><Key size={16} />解锁</button>
              </div>
            </div>
          ) : (
            <div>
              <textarea value={devData} onChange={(e) => setDevData(e.target.value)}
                style={{ width: '100%', minHeight: '300px', padding: '12px', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)', background: 'var(--panel-bg)', color: 'var(--app-fg)', fontFamily: 'monospace', fontSize: '12px', resize: 'vertical' }} />
              <div style={{ display: 'flex', gap: '8px', marginTop: '12px', justifyContent: 'flex-end' }}>
                <button className="btn btn-outline-secondary" onClick={() => { setDevUnlocked(false); setDevMessage('') }}>锁定</button>
                <button className="btn btn-primary" onClick={handleDevSave}>保存</button>
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  )
}

export default SettingsPage
