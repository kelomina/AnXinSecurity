/**
 * 设置页面
 * Settings page
 *
 * 提供通用设置、排除项、允许列表、签名库管理、开发者设置、训练功能。
 * Provides general settings, exclusions, allowlist, signature store, dev settings, training.
 *
 * 中文关键词：设置，排除项，允许列表，签名库，开发者设置，训练
 * English keywords: settings, exclusions, allowlist, signature store, dev settings, training
 */
import React, { useEffect, useState } from 'react'
import { useConfigStore } from '../stores/configStore'
import { useThemeStore, ThemeMode } from '../stores/themeStore'
import { Moon, Sun, Monitor, Zap, FolderOpen, FilePlus, Trash2, Shield, Plus, Database, Key, Brain, RefreshCw, Download } from 'lucide-react'
import { open } from '@tauri-apps/plugin-dialog'
import { listSignatureVersions, rollbackSignatureVersion, type SignatureMetadata } from '../api/signatureStore'
import { devSettingsUnlock, devSettingsSave } from '../api/devSettings'
import { trainFromPath, getTrainingStatus, cancelTraining } from '../api/training'

const SettingsPage: React.FC = () => {
  const {
    config, setBehaviorMonitoring,
    exclusions, allowlist,
    loadExclusions, addExclusion, removeExclusion,
    loadAllowlist, addToAllowlist, removeFromAllowlist
  } = useConfigStore()
  const { themeMode, setThemeMode, animationsEnabled, toggleAnimations } = useThemeStore()

  const [activeTab, setActiveTab] = useState<'general'|'exclusions'|'allowlist'|'signature'|'dev'|'training'>('general')
  const [confirmDeleteIndex, setConfirmDeleteIndex] = useState<number | null>(null)
  const [confirmDeleteAllow, setConfirmDeleteAllow] = useState<number | null>(null)

  // 排除项表单
  const [newExclusionPath, setNewExclusionPath] = useState('')
  const [newExclusionType, setNewExclusionType] = useState<'file' | 'directory'>('directory')
  const [newExclusionDesc, setNewExclusionDesc] = useState('')
  // 允许列表表单
  const [newAllowlistPath, setNewAllowlistPath] = useState('')
  const [newAllowlistDesc, setNewAllowlistDesc] = useState('')

  // 签名库状态
  const [sigMeta, setSigMeta] = useState<SignatureMetadata | null>(null)
  const [sigLoading, setSigLoading] = useState(false)
  // 开发者设置
  const [devPassword, setDevPassword] = useState('')
  const [devData, setDevData] = useState('')
  const [devUnlocked, setDevUnlocked] = useState(false)
  const [devMessage, setDevMessage] = useState('')
  // 训练
  const [trainPath, setTrainPath] = useState('')
  const [trainStatus, setTrainStatus] = useState('idle')

  useEffect(() => { loadExclusions(); loadAllowlist() }, [loadExclusions, loadAllowlist])

  const loadSigVersions = async () => {
    setSigLoading(true)
    try { setSigMeta(await listSignatureVersions()) } catch (e) { console.error('[SettingsPage] Failed to load signature versions:', e) }
    setSigLoading(false)
  }

  useEffect(() => {
    if (activeTab === 'signature') loadSigVersions()
  }, [activeTab])

  const themeOptions: { value: ThemeMode; label: string; icon: React.ElementType }[] = [
    { value: 'system', label: '跟随系统', icon: Monitor },
    { value: 'light', label: '浅色模式', icon: Sun },
    { value: 'dark', label: '深色模式', icon: Moon },
  ]

  // 排除项操作
  const handleSelectExclusionDir = async () => {
    const selected = await open({ directory: true, multiple: false, title: '选择要排除的目录' })
    if (selected) setNewExclusionPath(selected as string)
  }
  const handleSelectExclusionFile = async () => {
    const selected = await open({ multiple: false, title: '选择要排除的文件' })
    if (selected) setNewExclusionPath(selected as string)
  }
  const handleAddExclusion = async () => {
    if (!newExclusionPath.trim()) return
    try { await addExclusion(newExclusionPath, newExclusionType, newExclusionDesc || undefined); setNewExclusionPath(''); setNewExclusionDesc('') }
    catch (e) { alert(`添加失败: ${e}`) }
  }
  const handleRemoveExclusion = async (index: number) => {
    const entry = exclusions[index]; if (!entry) return
    try { await removeExclusion(entry.path); setConfirmDeleteIndex(null) }
    catch (e) { alert(`删除失败: ${e}`) }
  }

  // 允许列表操作
  const handleSelectAllowlistFile = async () => {
    const selected = await open({ multiple: false, title: '选择要允许的程序', filters: [{ name: 'Executable', extensions: ['exe'] }] })
    if (selected) setNewAllowlistPath(selected as string)
  }
  const handleAddToAllowlist = async () => {
    if (!newAllowlistPath.trim()) return
    try { await addToAllowlist(newAllowlistPath, newAllowlistDesc || undefined); setNewAllowlistPath(''); setNewAllowlistDesc('') }
    catch (e) { alert(`添加失败: ${e}`) }
  }
  const handleRemoveFromAllowlist = async (index: number) => {
    const entry = allowlist[index]; if (!entry) return
    try { await removeFromAllowlist(entry.path); setConfirmDeleteAllow(null) }
    catch (e) { alert(`删除失败: ${e}`) }
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

  // 训练操作
  const handleStartTrain = async () => {
    if (!trainPath.trim()) { alert('请输入训练样本目录路径'); return }
    try {
      await trainFromPath(trainPath)
      setTrainStatus('training')
      // 轮询训练状态
      const poll = setInterval(async () => {
        const status = await getTrainingStatus()
        if (status === '"completed"' || status === '"failed"') {
          setTrainStatus(status === '"completed"' ? 'completed' : 'failed')
          clearInterval(poll)
        }
      }, 2000)
    }
    catch (e) { alert(`训练启动失败: ${e}`) }
  }
  const handleCancelTrain = async () => {
    await cancelTraining()
    setTrainStatus('idle')
  }
  const handleSelectTrainDir = async () => {
    const selected = await open({ directory: true, multiple: false, title: '选择训练样本目录' })
    if (selected) setTrainPath(selected as string)
  }

  // 签名库回滚
  const handleRollbackSig = async (version: string) => {
    if (!confirm(`确定要回滚签名库到版本 ${version} 吗？回滚后安全防护能力可能降低。`)) return
    try { await rollbackSignatureVersion(version); loadSigVersions() }
    catch (e) { alert(`回滚失败: ${e}`) }
  }

  const tabs = [
    { id: 'general' as const, label: '通用设置' },
    { id: 'exclusions' as const, label: `排除项 (${exclusions.length})` },
    { id: 'allowlist' as const, label: `允许列表 (${allowlist.length})` },
    { id: 'signature' as const, label: '签名库' },
    { id: 'dev' as const, label: '开发者' },
    { id: 'training' as const, label: '模型训练' },
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
              <span className="toggle-label">启用行为监控</span>
              <span className="toggle-description">实时监控系统进程行为</span>
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

      {/* 排除项 */}
      {activeTab === 'exclusions' && (
        <div className="settings-section card">
          <h3>扫描排除项</h3>
          <p style={{ color: 'var(--muted-fg)', fontSize: '14px', marginBottom: '16px' }}>添加要从扫描中排除的目录或文件。</p>
          <div className="setting-group">
            <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
              <input type="text" value={newExclusionPath} onChange={(e) => setNewExclusionPath(e.target.value)} placeholder="输入路径或点击下方按钮选择"
                style={{ flex: 1, padding: '10px 12px', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)', background: 'var(--panel-bg)', color: 'var(--app-fg)' }} />
              <button className="btn btn-outline-secondary" onClick={handleSelectExclusionDir}><FolderOpen size={18} /></button>
              <button className="btn btn-outline-secondary" onClick={handleSelectExclusionFile}><FilePlus size={18} /></button>
            </div>
            <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
              <input type="text" value={newExclusionDesc} onChange={(e) => setNewExclusionDesc(e.target.value)} placeholder="描述（可选）"
                style={{ flex: 1, padding: '10px 12px', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)', background: 'var(--panel-bg)', color: 'var(--app-fg)', fontSize: '13px' }} />
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <label style={{ fontSize: '14px', color: 'var(--muted-fg)' }}><input type="radio" checked={newExclusionType === 'directory'} onChange={() => setNewExclusionType('directory')} style={{ marginRight: '4px' }} />目录</label>
              <label style={{ fontSize: '14px', color: 'var(--muted-fg)' }}><input type="radio" checked={newExclusionType === 'file'} onChange={() => setNewExclusionType('file')} style={{ marginRight: '4px' }} />文件</label>
              <button className="btn btn-primary" onClick={handleAddExclusion} disabled={!newExclusionPath.trim()} style={{ marginLeft: 'auto' }}><Plus size={16} />添加</button>
            </div>
          </div>
          <div style={{ marginTop: '16px' }}>
            {exclusions.length === 0 ? (
              <div className="empty-state" style={{ padding: '32px' }}><Shield size={48} /><p>暂无排除项</p></div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {exclusions.map((entry, index) => (
                  <div key={index} style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '12px', background: 'var(--panel-bg)', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: '14px', fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{entry.path}</div>
                      <div style={{ fontSize: '12px', color: 'var(--muted-fg)', marginTop: '2px' }}>{entry.entry_type === 'directory' ? '目录' : '文件'}{entry.description && ` · ${entry.description}`}</div>
                    </div>
                    <button className="btn btn-outline-danger btn-sm" onClick={() => setConfirmDeleteIndex(index)}><Trash2 size={16} /></button>
                  </div>
                ))}
              </div>
            )}
          </div>
          {confirmDeleteIndex !== null && exclusions[confirmDeleteIndex] && (
            <div className="modal-overlay" onClick={() => setConfirmDeleteIndex(null)}>
              <div className="modal-surface" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '400px' }}>
                <h3>确认删除</h3>
                <p style={{ marginTop: '8px', color: 'var(--muted-fg)' }}>确定要移除 <strong>{exclusions[confirmDeleteIndex].path}</strong> 吗？</p>
                <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', marginTop: '16px' }}>
                  <button className="btn btn-outline-secondary" onClick={() => setConfirmDeleteIndex(null)}>取消</button>
                  <button className="btn btn-danger" onClick={() => handleRemoveExclusion(confirmDeleteIndex)}>确认删除</button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 允许列表 */}
      {activeTab === 'allowlist' && (
        <div className="settings-section card">
          <h3>启动允许列表</h3>
          <p style={{ color: 'var(--muted-fg)', fontSize: '14px', marginBottom: '16px' }}>允许的程序在启动时将不会被拦截。请谨慎添加。</p>
          <div className="setting-group">
            <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
              <input type="text" value={newAllowlistPath} onChange={(e) => setNewAllowlistPath(e.target.value)} placeholder="输入程序路径或选择文件"
                style={{ flex: 1, padding: '10px 12px', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)', background: 'var(--panel-bg)', color: 'var(--app-fg)' }} />
              <button className="btn btn-outline-secondary" onClick={handleSelectAllowlistFile}><FilePlus size={18} /></button>
            </div>
            <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
              <input type="text" value={newAllowlistDesc} onChange={(e) => setNewAllowlistDesc(e.target.value)} placeholder="描述（可选）"
                style={{ flex: 1, padding: '10px 12px', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)', background: 'var(--panel-bg)', color: 'var(--app-fg)', fontSize: '13px' }} />
            </div>
            <button className="btn btn-primary" onClick={handleAddToAllowlist} disabled={!newAllowlistPath.trim()} style={{ width: '100%' }}><Plus size={16} />添加到允许列表</button>
          </div>
          <div style={{ marginTop: '16px' }}>
            {allowlist.length === 0 ? (
              <div className="empty-state" style={{ padding: '32px' }}><Shield size={48} /><p>暂无允许的程序</p></div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {allowlist.map((entry, index) => (
                  <div key={index} style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '12px', background: 'var(--panel-bg)', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: '14px', fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{entry.path}</div>
                      <div style={{ fontSize: '12px', color: 'var(--muted-fg)', marginTop: '2px' }}>{entry.hash ? `SHA256: ${entry.hash.substring(0, 16)}...` : '未验证哈希'}{entry.description && ` · ${entry.description}`}</div>
                    </div>
                    <button className="btn btn-outline-danger btn-sm" onClick={() => setConfirmDeleteAllow(index)}><Trash2 size={16} /></button>
                  </div>
                ))}
              </div>
            )}
          </div>
          {confirmDeleteAllow !== null && allowlist[confirmDeleteAllow] && (
            <div className="modal-overlay" onClick={() => setConfirmDeleteAllow(null)}>
              <div className="modal-surface" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '400px' }}>
                <h3>确认删除</h3>
                <p style={{ marginTop: '8px', color: 'var(--muted-fg)' }}>确定要移除 <strong>{allowlist[confirmDeleteAllow].path}</strong> 吗？</p>
                <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', marginTop: '16px' }}>
                  <button className="btn btn-outline-secondary" onClick={() => setConfirmDeleteAllow(null)}>取消</button>
                  <button className="btn btn-danger" onClick={() => handleRemoveFromAllowlist(confirmDeleteAllow)}>确认删除</button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 签名库管理 */}
      {activeTab === 'signature' && (
        <div className="settings-section card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h3 style={{ margin: 0 }}>签名库版本管理</h3>
            <button className="btn btn-outline-secondary btn-sm" onClick={loadSigVersions} disabled={sigLoading}>
              <RefreshCw size={14} className={sigLoading ? 'spinning' : ''} /> 刷新
            </button>
          </div>
          <p style={{ color: 'var(--muted-fg)', fontSize: '14px', marginBottom: '16px' }}>
            当前版本: <strong>{sigMeta?.currentVersion || '--'}</strong>
          </p>
          {sigLoading ? (
            <div className="skeleton-list">{Array(3).fill(0).map((_, i) => <div key={i} className="skeleton-event" style={{ height: '48px', marginBottom: '8px' }} />)}</div>
          ) : sigMeta?.versions?.length ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {sigMeta.versions.map((v, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '12px', background: 'var(--panel-bg)', borderRadius: 'var(--radius-medium)', border: v.current ? '2px solid var(--brand-color)' : '1px solid var(--panel-border)' }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                      <span style={{ fontWeight: 600 }}>{v.version}</span>
                      {v.current && <span style={{ fontSize: '11px', background: 'var(--brand-color)', color: '#fff', padding: '2px 8px', borderRadius: '10px' }}>当前</span>}
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-tertiary)', marginTop: '4px' }}>{v.date} · {v.count} 条签名</div>
                  </div>
                  {!v.current && (
                    <button className="btn btn-outline-warning btn-sm" onClick={() => handleRollbackSig(v.version)}>
                      <Download size={14} /> 回滚到此版本
                    </button>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state"><Database size={48} /><p>暂无版本信息</p></div>
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

      {/* 模型训练 */}
      {activeTab === 'training' && (
        <div className="settings-section card">
          <h3>ML 模型训练</h3>
          <p style={{ color: 'var(--muted-fg)', fontSize: '14px', marginBottom: '16px' }}>选择包含恶意样本的目录，提交训练任务给扫描引擎。训练过程可能需要数分钟。</p>
          <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
            <input type="text" value={trainPath} onChange={(e) => setTrainPath(e.target.value)} placeholder="训练样本目录路径"
              style={{ flex: 1, padding: '10px 12px', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)', background: 'var(--panel-bg)', color: 'var(--app-fg)' }} />
            <button className="btn btn-outline-secondary" onClick={handleSelectTrainDir}><FolderOpen size={18} /></button>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            {trainStatus === 'idle' ? (
              <button className="btn btn-primary" onClick={handleStartTrain} disabled={!trainPath.trim()} style={{ flex: 1 }}>
                <Brain size={16} />开始训练
              </button>
            ) : trainStatus === 'training' ? (
              <button className="btn btn-warning" onClick={handleCancelTrain} style={{ flex: 1 }}>
                取消训练
              </button>
            ) : (
              <button className="btn btn-outline-secondary" onClick={() => setTrainStatus('idle')} style={{ flex: 1 }}>
                <RefreshCw size={16} />重新训练
              </button>
            )}
          </div>
          {trainStatus === 'training' && (
            <div style={{ marginTop: '12px', padding: '12px', background: 'var(--bg-tertiary)', borderRadius: '8px' }}>
              <span style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>训练进行中...请等待完成</span>
              <div className="progress-bar" style={{ marginTop: '8px' }}><div className="progress-bar scan-indeterminate" /></div>
            </div>
          )}
          {trainStatus === 'completed' && (
            <div style={{ marginTop: '12px', padding: '12px', background: 'rgba(82,196,26,0.1)', borderRadius: '8px', color: 'var(--success)' }}>训练完成！</div>
          )}
          {trainStatus === 'failed' && (
            <div style={{ marginTop: '12px', padding: '12px', background: 'rgba(255,77,79,0.1)', borderRadius: '8px', color: 'var(--danger)' }}>训练失败，请检查样本和引擎状态。</div>
          )}
        </div>
      )}
    </section>
  )
}

export default SettingsPage
