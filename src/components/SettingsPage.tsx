import React, { useEffect, useState } from 'react'
import { useConfigStore } from '../stores/configStore'
import { useThemeStore, ThemeMode } from '../stores/themeStore'
import { Moon, Sun, Monitor, Zap, FolderOpen, FilePlus, Trash2, Shield, Plus, X } from 'lucide-react'
import { open } from '@tauri-apps/plugin-dialog'

const SettingsPage: React.FC = () => {
  const { 
    config, 
    setBehaviorMonitoring,
    exclusions,
    allowlist,
    loadExclusions,
    addExclusion,
    removeExclusion,
    loadAllowlist,
    addToAllowlist,
    removeFromAllowlist
  } = useConfigStore()
  
  const { themeMode, setThemeMode, animationsEnabled, toggleAnimations } = useThemeStore()

  // 本地状态管理
  const [newExclusionPath, setNewExclusionPath] = useState('')
  const [newExclusionType, setNewExclusionType] = useState<'file' | 'directory'>('directory')
  const [newAllowlistPath, setNewAllowlistPath] = useState('')
  const [activeTab, setActiveTab] = useState<'general' | 'exclusions' | 'allowlist'>('general')

  // 加载排除项和允许列表
  useEffect(() => {
    loadExclusions()
    loadAllowlist()
  }, [loadExclusions, loadAllowlist])

  const themeOptions: { value: ThemeMode; label: string; icon: React.ElementType }[] = [
    { value: 'system', label: '跟随系统', icon: Monitor },
    { value: 'light', label: '浅色模式', icon: Sun },
    { value: 'dark', label: '深色模式', icon: Moon },
  ]

  // 选择排除目录
  const handleSelectExclusionDir = async () => {
    const selected = await open({
      directory: true,
      multiple: false,
      title: '选择要排除的目录'
    })
    if (selected) {
      setNewExclusionPath(selected as string)
    }
  }

  // 选择排除文件
  const handleSelectExclusionFile = async () => {
    const selected = await open({
      multiple: false,
      title: '选择要排除的文件'
    })
    if (selected) {
      setNewExclusionPath(selected as string)
    }
  }

  // 添加排除项
  const handleAddExclusion = async () => {
    if (!newExclusionPath.trim()) return
    try {
      await addExclusion(newExclusionPath, newExclusionType)
      setNewExclusionPath('')
    } catch (e) {
      alert(`添加失败: ${e}`)
    }
  }

  // 选择允许的程序
  const handleSelectAllowlistFile = async () => {
    const selected = await open({
      multiple: false,
      title: '选择要允许的程序',
      filters: [{ name: 'Executable', extensions: ['exe'] }]
    })
    if (selected) {
      setNewAllowlistPath(selected as string)
    }
  }

  // 添加到允许列表
  const handleAddToAllowlist = async () => {
    if (!newAllowlistPath.trim()) return
    try {
      await addToAllowlist(newAllowlistPath)
      setNewAllowlistPath('')
    } catch (e) {
      alert(`添加失败: ${e}`)
    }
  }

  return (
    <section id="page-settings" className="page">
      <h1 className="page-title">设置</h1>

      {/* 选项卡导航 */}
      <div className="settings-tabs card" style={{ marginBottom: '16px', padding: '8px' }}>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            className={`btn ${activeTab === 'general' ? 'btn-primary' : 'btn-outline-secondary'}`}
            onClick={() => setActiveTab('general')}
            style={{ flex: 1 }}
          >
            通用设置
          </button>
          <button
            className={`btn ${activeTab === 'exclusions' ? 'btn-primary' : 'btn-outline-secondary'}`}
            onClick={() => setActiveTab('exclusions')}
            style={{ flex: 1 }}
          >
            排除项 ({exclusions.length})
          </button>
          <button
            className={`btn ${activeTab === 'allowlist' ? 'btn-primary' : 'btn-outline-secondary'}`}
            onClick={() => setActiveTab('allowlist')}
            style={{ flex: 1 }}
          >
            启动允许列表 ({allowlist.length})
          </button>
        </div>
      </div>

      {/* 通用设置 */}
      {activeTab === 'general' && (
        <>
          {/* 监控设置 */}
          <div className="settings-section card">
            <h3>监控设置</h3>
            <label className="toggle-setting">
              <div className="toggle-info">
                <span className="toggle-label">启用行为监控</span>
                <span className="toggle-description">实时监控系统进程行为</span>
              </div>
              <div className="toggle-switch">
                <input
                  type="checkbox"
                  checked={config?.behaviorMonitoring?.enabled || false}
                  onChange={(e) => setBehaviorMonitoring(e.target.checked)}
                  className="toggle-input"
                />
                <span className="toggle-slider" />
              </div>
            </label>
          </div>

          {/* 界面设置 */}
          <div className="settings-section card">
            <h3>界面设置</h3>
            
            {/* 主题切换 */}
            <div className="setting-group">
              <label className="setting-label">主题模式</label>
              <div className="theme-selector">
                {themeOptions.map((option) => {
                  const Icon = option.icon
                  const isActive = themeMode === option.value
                  
                  return (
                    <button
                      key={option.value}
                      className={`theme-option ${isActive ? 'active' : ''}`}
                      onClick={() => setThemeMode(option.value)}
                    >
                      <Icon size={20} />
                      <span>{option.label}</span>
                    </button>
                  )
                })}
              </div>
            </div>

            {/* 动画开关 */}
            <label className="toggle-setting">
              <div className="toggle-info">
                <div className="toggle-label-row">
                  <Zap size={18} className="toggle-icon" />
                  <span className="toggle-label">启用动画效果</span>
                </div>
                <span className="toggle-description">页面切换和交互动画</span>
              </div>
              <div className="toggle-switch">
                <input
                  type="checkbox"
                  checked={animationsEnabled}
                  onChange={toggleAnimations}
                  className="toggle-input"
                />
                <span className="toggle-slider" />
              </div>
            </label>
          </div>
        </>
      )}

      {/* 排除项管理 */}
      {activeTab === 'exclusions' && (
        <div className="settings-section card">
          <h3>扫描排除项</h3>
          <p style={{ color: 'var(--muted-fg)', fontSize: '14px', marginBottom: '16px' }}>
            添加要从扫描中排除的目录或文件。排除的项目不会被安全引擎检查。
          </p>

          {/* 添加排除项表单 */}
          <div className="setting-group">
            <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
              <input
                type="text"
                value={newExclusionPath}
                onChange={(e) => setNewExclusionPath(e.target.value)}
                placeholder="输入路径或点击下方按钮选择"
                style={{
                  flex: 1,
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-medium)',
                  border: '1px solid var(--panel-border)',
                  background: 'var(--panel-bg)',
                  color: 'var(--app-fg)'
                }}
              />
              <button className="btn btn-outline-secondary" onClick={handleSelectExclusionDir} title="选择目录">
                <FolderOpen size={18} />
              </button>
              <button className="btn btn-outline-secondary" onClick={handleSelectExclusionFile} title="选择文件">
                <FilePlus size={18} />
              </button>
            </div>
            
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <label style={{ fontSize: '14px', color: 'var(--muted-fg)' }}>
                <input
                  type="radio"
                  checked={newExclusionType === 'directory'}
                  onChange={() => setNewExclusionType('directory')}
                  style={{ marginRight: '4px' }}
                />
                目录
              </label>
              <label style={{ fontSize: '14px', color: 'var(--muted-fg)' }}>
                <input
                  type="radio"
                  checked={newExclusionType === 'file'}
                  onChange={() => setNewExclusionType('file')}
                  style={{ marginRight: '4px' }}
                />
                文件
              </label>
              <button 
                className="btn btn-primary" 
                onClick={handleAddExclusion}
                disabled={!newExclusionPath.trim()}
                style={{ marginLeft: 'auto' }}
              >
                <Plus size={16} />
                添加
              </button>
            </div>
          </div>

          {/* 排除项列表 */}
          <div style={{ marginTop: '16px' }}>
            {exclusions.length === 0 ? (
              <div className="empty-state" style={{ padding: '32px' }}>
                <Shield size={48} className="empty-icon" />
                <p>暂无排除项</p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {exclusions.map((entry, index) => (
                  <div 
                    key={index}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      padding: '12px',
                      background: 'var(--panel-bg)',
                      borderRadius: 'var(--radius-medium)',
                      border: '1px solid var(--panel-border)'
                    }}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ 
                        fontSize: '14px', 
                        fontWeight: 500,
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis'
                      }}>
                        {entry.path}
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--muted-fg)', marginTop: '2px' }}>
                        {entry.entry_type === 'directory' ? '目录' : '文件'}
                        {entry.description && ` · ${entry.description}`}
                      </div>
                    </div>
                    <button 
                      className="btn btn-outline-secondary"
                      onClick={() => removeExclusion(entry.path)}
                      title="移除"
                      style={{ padding: '8px' }}
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* 启动允许列表 */}
      {activeTab === 'allowlist' && (
        <div className="settings-section card">
          <h3>启动允许列表</h3>
          <p style={{ color: 'var(--muted-fg)', fontSize: '14px', marginBottom: '16px' }}>
            添加到允许列表的程序在启动时将不会被拦截或扫描。请谨慎添加，仅允许可信程序。
          </p>

          {/* 添加允许项表单 */}
          <div className="setting-group">
            <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
              <input
                type="text"
                value={newAllowlistPath}
                onChange={(e) => setNewAllowlistPath(e.target.value)}
                placeholder="输入程序路径或点击下方按钮选择"
                style={{
                  flex: 1,
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-medium)',
                  border: '1px solid var(--panel-border)',
                  background: 'var(--panel-bg)',
                  color: 'var(--app-fg)'
                }}
              />
              <button className="btn btn-outline-secondary" onClick={handleSelectAllowlistFile} title="选择程序">
                <FilePlus size={18} />
              </button>
            </div>
            
            <button 
              className="btn btn-primary" 
              onClick={handleAddToAllowlist}
              disabled={!newAllowlistPath.trim()}
              style={{ width: '100%' }}
            >
              <Plus size={16} />
              添加到允许列表
            </button>
          </div>

          {/* 允许列表 */}
          <div style={{ marginTop: '16px' }}>
            {allowlist.length === 0 ? (
              <div className="empty-state" style={{ padding: '32px' }}>
                <Shield size={48} className="empty-icon" />
                <p>暂无允许的程序</p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {allowlist.map((entry, index) => (
                  <div 
                    key={index}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      padding: '12px',
                      background: 'var(--panel-bg)',
                      borderRadius: 'var(--radius-medium)',
                      border: '1px solid var(--panel-border)'
                    }}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ 
                        fontSize: '14px', 
                        fontWeight: 500,
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis'
                      }}>
                        {entry.path}
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--muted-fg)', marginTop: '2px' }}>
                        {entry.hash ? `SHA256: ${entry.hash.substring(0, 16)}...` : '未验证哈希'}
                        {entry.description && ` · ${entry.description}`}
                      </div>
                    </div>
                    <button 
                      className="btn btn-outline-secondary"
                      onClick={() => removeFromAllowlist(entry.path)}
                      title="移除"
                      style={{ padding: '8px' }}
                    >
                      <X size={16} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  )
}

export default SettingsPage
