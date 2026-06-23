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
import { useI18nStore } from '../stores/i18nStore'
import { FolderOpen, FilePlus, Trash2, Shield, Plus, Key, Moon, Sun, Monitor } from 'lucide-react'
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
    monitoringRuntimeStatus, monitoringControlPending, monitoringControlError,
    refreshMonitoringRuntimeStatus,
    trustItems,
    loadTrustItems, addTrustItem, removeTrustItem
  } = useConfigStore()
  const { themeMode, setThemeMode, animationsEnabled, toggleAnimations } = useThemeStore()
  const { locale, setLocale, t } = useI18nStore()

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
  const [devMessageIsError, setDevMessageIsError] = useState(false)
  useEffect(() => {
    loadTrustItems()
    refreshMonitoringRuntimeStatus()
  }, [loadTrustItems, refreshMonitoringRuntimeStatus])

  const themeOptions: { value: ThemeMode; icon: React.ReactNode; labelKey: string }[] = [
    { value: 'dark', icon: <Moon size={20} />, labelKey: 'settings_theme_dark' },
    { value: 'light', icon: <Sun size={20} />, labelKey: 'settings_theme_light' },
    { value: 'system', icon: <Monitor size={20} />, labelKey: 'settings_theme_system' },
  ]

  // 信任项目操作
  const handleSelectTrustDir = async () => {
    const selected = await open({ directory: true, multiple: false, title: t('settings_trust_type_directory') })
    if (selected) {
      setNewTrustPath(selected as string)
      setNewTrustType('directory')
    }
  }
  const handleSelectTrustFile = async () => {
    const selected = await open({ multiple: false, title: t('settings_trust_type_file') })
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
      alert(`${t('settings_dev_save_failed')}: ${e}`)
    }
  }
  const handleRemoveTrustItem = async (index: number) => {
    const entry = trustItems[index]; if (!entry) return
    try {
      await removeTrustItem(entry.path)
      setConfirmDeleteTrustIndex(null)
    } catch (e) {
      alert(`${t('delete_failed')}: ${e}`)
    }
  }

  /**
   * 函数名称：handleMonitoringToggle
   * 函数作用：统一处理监控开关点击，等待后端运行态控制完成；失败时由 configStore 回滚配置并写入错误状态。
   * Function name: handleMonitoringToggle
   * Purpose: Handles monitoring toggle clicks and waits for backend runtime control; configStore rolls config back and writes error state on failure.
   * 调用方：设置页 EDR/进程/文件监控三个开关。
   * Called by: Settings page EDR/process/file monitoring toggles.
   * 被调用方：configStore.setBehaviorMonitoring、setProcessMonitoring、setFileMonitoring。
   * Calls: configStore setBehaviorMonitoring, setProcessMonitoring, setFileMonitoring.
   * 参数说明：kind 为监控类型；enabled 为目标状态。
   * Parameters: kind is the monitoring type; enabled is the target state.
   * 错误处理：Store 已记录错误和回滚 UI；这里额外 console.error，避免未处理 Promise 异常。
   * Error handling: Store records the error and rolls back UI; this function also logs to avoid unhandled Promise failures.
   * 中文关键词：监控开关，运行态控制，失败回滚，设置页
   * English keywords: monitoring toggle, runtime control, rollback on failure, settings page
   */
  const handleMonitoringToggle = async (
    kind: 'behavior' | 'process' | 'file',
    enabled: boolean
  ) => {
    try {
      if (kind === 'behavior') {
        await setBehaviorMonitoring(enabled)
      } else if (kind === 'process') {
        await setProcessMonitoring(enabled)
      } else {
        await setFileMonitoring(enabled)
      }
    } catch (e) {
      console.error(`[SettingsPage] ${kind} monitoring toggle failed:`, e)
    }
  }

  // 开发者设置操作
  const handleDevUnlock = async () => {
    try { const result = await devSettingsUnlock(devPassword); setDevData(JSON.stringify(result, null, 2)); setDevUnlocked(true); setDevMessage(t('settings_dev_unlock_success')); setDevMessageIsError(false) }
    catch (e) { setDevMessage(`${t('settings_dev_unlock_failed')}: ${e}`); setDevMessageIsError(true) }
  }
  const handleDevSave = async () => {
    try {
      await devSettingsSave(devPassword, JSON.parse(devData))
      setDevMessage(t('settings_dev_save_success')); setDevMessageIsError(false)
    }
    catch (e) { setDevMessage(`${t('settings_dev_save_failed')}: ${e}`); setDevMessageIsError(true) }
  }

  return (
    <section id="page-settings" className="page">
      <h1 className="page-title">{t('settings_title')}</h1>

      {/* 外观组 */}
      <div className="settings-group">
        <div className="settings-group-title">{t('settings_group_appearance')}</div>
        <div className="card card-no-hover">
          <div style={{ fontWeight: 500, fontSize: 14, marginBottom: 8 }}>{t('settings_theme_mode')}</div>
          <div className="theme-selector">
            {themeOptions.map(o => (
              <div
                key={o.value}
                className={`theme-option ${themeMode === o.value ? 'selected' : ''}`}
                onClick={() => setThemeMode(o.value)}
              >
                <div className="theme-option-icon">{o.icon}</div>
                <div className="theme-option-label">{t(o.labelKey)}</div>
              </div>
            ))}
          </div>
          <div className="settings-item" style={{ marginTop: 8 }}>
            <div className="settings-item-icon" style={{ background: 'rgba(199,146,85,0.09)', color: 'var(--color-warning)' }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
            </div>
            <div className="settings-item-text">
              <div className="settings-item-title">{t('settings_disable_animations')}</div>
              <div className="settings-item-desc">{t('settings_disable_animations_desc')}</div>
            </div>
            <div className="settings-item-control">
              <div
                className={`toggle ${!animationsEnabled ? 'on' : ''}`}
                onClick={toggleAnimations}
                role="switch"
                aria-checked={!animationsEnabled}
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    toggleAnimations()
                  }
                }}
              >
                <div className="toggle-knob"></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 安全配置组 */}
      <div className="settings-group">
        <div className="settings-group-title">{t('settings_group_security')}</div>
        <div className="card card-no-hover" style={{ padding: '4px 20px' }}>
          {monitoringControlError && (
            <div style={{ padding: '12px', marginBottom: '12px', borderRadius: 'var(--radius-medium)', background: 'var(--color-danger-bg)', color: 'var(--color-danger)', fontSize: '14px' }}>
              {monitoringControlError}
            </div>
          )}
          <div style={{ padding: '12px', marginBottom: '12px', fontSize: '13px', color: 'var(--muted-fg)', background: 'var(--input-bg)', borderRadius: 'var(--radius-medium)' }}>
            {t('settings_monitoring_status')}
            <strong style={{ marginLeft: '6px', color: monitoringRuntimeStatus?.etwCollecting ? 'var(--color-success)' : 'var(--color-warning)' }}>
              ETW {monitoringRuntimeStatus ? (monitoringRuntimeStatus.etwCollecting ? t('settings_monitoring_collecting') : t('settings_monitoring_stopped')) : t('settings_monitoring_loading')}
            </strong>
            <strong style={{ marginLeft: '10px', color: monitoringRuntimeStatus?.processWatcherRunning ? 'var(--color-success)' : 'var(--color-warning)' }}>
              APIHook {monitoringRuntimeStatus ? (monitoringRuntimeStatus.processWatcherRunning ? t('settings_monitoring_running') : t('settings_monitoring_stopped')) : t('settings_monitoring_loading')}
            </strong>
            <strong style={{ marginLeft: '10px', color: monitoringRuntimeStatus?.hookRunning ? 'var(--color-success)' : 'var(--color-warning)' }}>
              Hook {monitoringRuntimeStatus ? (monitoringRuntimeStatus.hookRunning ? t('settings_monitoring_running') : t('settings_monitoring_stopped')) : t('settings_monitoring_loading')}
            </strong>
          </div>
          <div className="settings-item">
            <div className="settings-item-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            <div className="settings-item-text">
              <div className="settings-item-title">{t('settings_behavior_monitoring')}</div>
              <div className="settings-item-desc">{t('settings_behavior_monitoring_desc')}</div>
            </div>
            <div className="settings-item-control">
              <div
                className={`toggle ${config?.behaviorMonitoring?.enabled ? 'on' : ''}`}
                onClick={() => {
                  if (monitoringControlPending === null) {
                    void handleMonitoringToggle('behavior', !(config?.behaviorMonitoring?.enabled || false))
                  }
                }}
                role="switch"
                aria-checked={config?.behaviorMonitoring?.enabled || false}
                aria-disabled={monitoringControlPending !== null}
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    if (monitoringControlPending === null) {
                      void handleMonitoringToggle('behavior', !(config?.behaviorMonitoring?.enabled || false))
                    }
                  }
                }}
              >
                <div className="toggle-knob"></div>
              </div>
            </div>
          </div>
          <div className="settings-item">
            <div className="settings-item-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
            </div>
            <div className="settings-item-text">
              <div className="settings-item-title">{t('settings_etw_collection')}</div>
              <div className="settings-item-desc">{t('settings_etw_collection_desc')}</div>
            </div>
            <div className="settings-item-control">
              <div
                className={`toggle ${config?.behaviorMonitoring?.enabled ? 'on' : ''}`}
                onClick={() => {
                  if (monitoringControlPending === null) {
                    void handleMonitoringToggle('behavior', !(config?.behaviorMonitoring?.enabled || false))
                  }
                }}
                role="switch"
                aria-checked={config?.behaviorMonitoring?.enabled || false}
                aria-disabled={monitoringControlPending !== null}
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    if (monitoringControlPending === null) {
                      void handleMonitoringToggle('behavior', !(config?.behaviorMonitoring?.enabled || false))
                    }
                  }
                }}
              >
                <div className="toggle-knob"></div>
              </div>
            </div>
          </div>
          <div className="settings-item">
            <div className="settings-item-icon" style={{ background: 'rgba(199,146,85,0.09)', color: 'var(--color-warning)' }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>
            </div>
            <div className="settings-item-text">
              <div className="settings-item-title">{t('settings_file_hook')}</div>
              <div className="settings-item-desc">{t('settings_file_hook_desc')}</div>
            </div>
            <div className="settings-item-control">
              <div
                className={`toggle ${config?.fileMonitoring?.enabled ? 'on' : ''}`}
                onClick={() => {
                  if (monitoringControlPending === null) {
                    void handleMonitoringToggle('file', !(config?.fileMonitoring?.enabled || false))
                  }
                }}
                role="switch"
                aria-checked={config?.fileMonitoring?.enabled || false}
                aria-disabled={monitoringControlPending !== null}
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    if (monitoringControlPending === null) {
                      void handleMonitoringToggle('file', !(config?.fileMonitoring?.enabled || false))
                    }
                  }
                }}
              >
                <div className="toggle-knob"></div>
              </div>
            </div>
          </div>
          <div className="settings-item">
            <div className="settings-item-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>
            </div>
            <div className="settings-item-text">
              <div className="settings-item-title">{t('settings_process_monitoring')}</div>
              <div className="settings-item-desc">{t('settings_process_monitoring_desc')}</div>
            </div>
            <div className="settings-item-control">
              <div
                className={`toggle ${config?.processMonitoring?.enabled ? 'on' : ''}`}
                onClick={() => {
                  if (monitoringControlPending === null) {
                    void handleMonitoringToggle('process', !(config?.processMonitoring?.enabled || false))
                  }
                }}
                role="switch"
                aria-checked={config?.processMonitoring?.enabled || false}
                aria-disabled={monitoringControlPending !== null}
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    if (monitoringControlPending === null) {
                      void handleMonitoringToggle('process', !(config?.processMonitoring?.enabled || false))
                    }
                  }
                }}
              >
                <div className="toggle-knob"></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 扫描配置组 */}
      <div className="settings-group">
        <div className="settings-group-title">{t('settings_group_scan')}</div>
        <div className="card card-no-hover" style={{ padding: '4px 20px' }}>
          <div className="settings-item" style={{ cursor: 'pointer' }}>
            <div className="settings-item-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
            </div>
            <div className="settings-item-text">
              <div className="settings-item-title">{t('settings_scan_rules')}</div>
              <div className="settings-item-desc">{t('settings_scan_rules_desc')}</div>
            </div>
            <div className="settings-item-control">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--muted-fg)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m9 18 6-6-6-6"/></svg>
            </div>
          </div>
          <div className="settings-item" style={{ cursor: 'pointer' }}>
            <div className="settings-item-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m6 14 1.5-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.54 6a2 2 0 0 1-1.95 1.5H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H18a2 2 0 0 1 2 2v2"/></svg>
            </div>
            <div className="settings-item-text">
              <div className="settings-item-title">{t('settings_exclusions')}</div>
              <div className="settings-item-desc">{t('settings_exclusions_desc')}</div>
            </div>
            <div className="settings-item-control">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--muted-fg)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m9 18 6-6-6-6"/></svg>
            </div>
          </div>
        </div>
      </div>

      {/* 系统组 */}
      <div className="settings-group">
        <div className="settings-group-title">{t('settings_group_system')}</div>
        <div className="card card-no-hover" style={{ padding: '4px 20px' }}>
          <div className="settings-item">
            <div className="settings-item-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>
            </div>
            <div className="settings-item-text">
              <div className="settings-item-title">{t('settings_language')}</div>
              <div className="settings-item-desc">{t('settings_language_desc')}</div>
            </div>
            <div className="settings-item-control">
              <select
                className="custom-select"
                value={locale}
                onChange={(e) => void setLocale(e.target.value)}
              >
                <option value="zh-CN">{t('locale_zh_CN')}</option>
                <option value="en-US">{t('locale_en_US')}</option>
              </select>
            </div>
          </div>
          <div className="settings-item">
            <div className="settings-item-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
            </div>
            <div className="settings-item-text">
              <div className="settings-item-title">{t('settings_version')}</div>
              <div className="settings-item-desc">{t('settings_version_desc')}</div>
            </div>
            <div className="settings-item-control">
              <span style={{ fontSize: '13px', color: 'var(--muted-fg)' }}>v1.0.0</span>
            </div>
          </div>
        </div>
      </div>

      {/* 信任项目 */}
      <div className="settings-group">
        <div className="settings-group-title">{t('settings_group_trust')}</div>
        <div className="card card-no-hover">
          <div style={{ padding: '16px', borderBottom: '1px solid var(--panel-border)' }}>
            <p style={{ color: 'var(--muted-fg)', fontSize: '14px', marginBottom: '16px' }}>{t('settings_trust_desc')}</p>
            <div style={{ display: 'flex', gap: '12px', marginBottom: '12px' }}>
              <input type="text" value={newTrustPath} onChange={(e) => setNewTrustPath(e.target.value)} placeholder={t('settings_trust_path_placeholder')}
                style={{ flex: 1, padding: '12px', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)', background: 'var(--panel-bg)', color: 'var(--app-fg)' }} />
              <button className="btn btn-outline-secondary" onClick={handleSelectTrustDir}><FolderOpen size={18} /></button>
              <button className="btn btn-outline-secondary" onClick={handleSelectTrustFile}><FilePlus size={18} /></button>
            </div>
            <div style={{ display: 'flex', gap: '12px', marginBottom: '12px' }}>
              <input type="text" value={newTrustDesc} onChange={(e) => setNewTrustDesc(e.target.value)} placeholder={t('settings_trust_desc_placeholder')}
                style={{ flex: 1, padding: '12px', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)', background: 'var(--panel-bg)', color: 'var(--app-fg)', fontSize: '14px' }} />
            </div>
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
              <label style={{ fontSize: '14px', color: 'var(--muted-fg)' }}><input type="radio" checked={newTrustType === 'file'} onChange={() => setNewTrustType('file')} style={{ marginRight: '6px' }} />{t('settings_trust_type_file')}</label>
              <label style={{ fontSize: '14px', color: 'var(--muted-fg)' }}><input type="radio" checked={newTrustType === 'directory'} onChange={() => setNewTrustType('directory')} style={{ marginRight: '6px' }} />{t('settings_trust_type_directory')}</label>
              <button className="btn btn-primary" onClick={handleAddTrustItem} disabled={!newTrustPath.trim()} style={{ marginLeft: 'auto' }}><Plus size={16} />{t('settings_trust_add')}</button>
            </div>
          </div>
          <div style={{ padding: '16px' }}>
            {trustItems.length === 0 ? (
              <div className="empty-state" style={{ padding: '48px' }}><Shield size={48} /><p>{t('settings_trust_empty')}</p></div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {trustItems.map((entry, index) => (
                  <div key={index} style={{ display: 'flex', alignItems: 'center', gap: '16px', padding: '16px', background: 'var(--panel-bg)', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: '14px', fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', marginBottom: '4px' }}>{entry.path}</div>
                      <div style={{ fontSize: '13px', color: 'var(--muted-fg)' }}>
                        {entry.entry_type === 'directory' ? t('settings_trust_type_directory') : t('settings_trust_type_file')}
                        {' · '}
                        {entry.sources.includes('allowlist') ? t('settings_trust_source_allowlist') : t('settings_trust_source_exclusion')}
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
        </div>
        {confirmDeleteTrustIndex !== null && trustItems[confirmDeleteTrustIndex] && (
          <div className="modal-overlay" onClick={() => setConfirmDeleteTrustIndex(null)}>
            <div className="modal-surface" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '400px' }}>
              <h3>{t('settings_confirm_delete')}</h3>
              <p style={{ marginTop: '12px', color: 'var(--muted-fg)' }}>{t('settings_confirm_delete_trust').replace('{path}', trustItems[confirmDeleteTrustIndex].path)}</p>
              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', marginTop: '24px' }}>
                <button className="btn btn-outline-secondary" onClick={() => setConfirmDeleteTrustIndex(null)}>{t('cancel')}</button>
                <button className="btn btn-danger" onClick={() => handleRemoveTrustItem(confirmDeleteTrustIndex)}>{t('settings_confirm_delete')}</button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 开发者设置 */}
      <div className="settings-group">
        <div className="settings-group-title">{t('settings_group_developer')}</div>
        <div className="card card-no-hover">
          <div style={{ padding: '16px' }}>
            <p style={{ color: 'var(--muted-fg)', fontSize: '14px', marginBottom: '16px' }}>{t('settings_dev_desc')}</p>
            {devMessage && <div style={{ padding: '12px', marginBottom: '12px', borderRadius: 'var(--radius-medium)', background: devMessageIsError ? 'var(--color-danger-bg)' : 'var(--color-success-bg)', color: devMessageIsError ? 'var(--color-danger)' : 'var(--color-success)', fontSize: '14px' }}>{devMessage}</div>}
            {!devUnlocked ? (
              <div>
                <div style={{ display: 'flex', gap: '12px', marginBottom: '12px' }}>
                  <input type="password" value={devPassword} onChange={(e) => setDevPassword(e.target.value)} placeholder={t('settings_dev_password_placeholder')}
                    style={{ flex: 1, padding: '12px', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)', background: 'var(--panel-bg)', color: 'var(--app-fg)' }} />
                  <button className="btn btn-primary" onClick={handleDevUnlock} disabled={!devPassword}><Key size={16} />{t('settings_dev_unlock_btn')}</button>
                </div>
              </div>
            ) : (
              <div>
                <textarea value={devData} onChange={(e) => setDevData(e.target.value)}
                  style={{ width: '100%', minHeight: '300px', padding: '12px', borderRadius: 'var(--radius-medium)', border: '1px solid var(--panel-border)', background: 'var(--panel-bg)', color: 'var(--app-fg)', fontFamily: 'var(--font-mono)', fontSize: '13px', resize: 'vertical' }} />
                <div style={{ display: 'flex', gap: '12px', marginTop: '16px', justifyContent: 'flex-end' }}>
                  <button className="btn btn-outline-secondary" onClick={() => { setDevUnlocked(false); setDevMessage(''); setDevMessageIsError(false) }}>{t('settings_dev_lock_btn')}</button>
                  <button className="btn btn-primary" onClick={handleDevSave}>{t('settings_dev_save_btn')}</button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  )
}

export default SettingsPage
