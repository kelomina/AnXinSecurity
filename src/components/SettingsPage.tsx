/**
 * 设置页面 - Fluent 2版本
 * Settings page - Fluent 2 version
 *
 * 提供通用设置、信任项目和开发者设置。使用 Fluent 2 组件库。
 * Provides general settings, unified trust item management, and dev settings using Fluent 2 components.
 */
import React, { useEffect, useState } from 'react'
import { useConfigStore } from '../stores/configStore'
import { useThemeStore, ThemeMode } from '../stores/themeStore'
import { useI18nStore } from '../stores/i18nStore'
import { FolderOpen, FilePlus, Trash2, Shield, Plus, Key, Moon, Sun, Monitor } from 'lucide-react'
import { open } from '@tauri-apps/plugin-dialog'
import {
  Button,
  Switch,
  Input,
  Textarea,
  Radio,
  RadioGroup,
  Text,
  makeStyles,
  shorthands,
  tokens,
} from '@fluentui/react-components'
import { devSettingsUnlock, devSettingsSave } from '../api/devSettings'

const useStyles = makeStyles({
  page: {
    maxWidth: '1200px',
    margin: '0 auto',
  },
  pageTitle: {
    fontSize: tokens.fontSizeHero800,
    fontWeight: tokens.fontWeightBold,
    color: tokens.colorBrandForeground1,
    marginBottom: '24px',
  },
  settingsGroup: {
    marginBottom: '16px',
  },
  settingsGroupTitle: {
    fontSize: tokens.fontSizeBase400,
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorBrandForeground1,
    ...shorthands.padding('12px', '0', '8px'),
    marginBottom: '0',
  },
  card: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('20px'),
    boxShadow: tokens.shadow8,
  },
  cardNoPadding: {
    ...shorthands.padding('4px', '20px'),
  },
  settingsItem: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('12px'),
    ...shorthands.padding('14px', '0'),
    ...shorthands.borderBottom('1px', 'solid', tokens.colorNeutralStroke2),
    ':last-child': {
      borderBottomStyle: 'none',
    },
  },
  settingsItemIcon: {
    width: '36px',
    height: '36px',
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: tokens.colorBrandBackground2,
    color: tokens.colorBrandForeground1,
    flexShrink: 0,
  },
  settingsItemText: {
    flex: 1,
  },
  settingsItemTitle: {
    fontSize: tokens.fontSizeBase300,
    fontWeight: tokens.fontWeightMedium,
    color: tokens.colorNeutralForeground1,
  },
  settingsItemDesc: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
    marginTop: '2px',
  },
  settingsItemControl: {
    flexShrink: 0,
  },
  themeSelector: {
    display: 'flex',
    ...shorthands.gap('12px'),
    marginTop: '8px',
  },
  themeOption: {
    flex: 1,
    ...shorthands.padding('16px'),
    ...shorthands.border('2px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    cursor: 'pointer',
    textAlign: 'center' as const,
    transitionProperty: 'all',
    transitionDuration: tokens.durationNormal,
    backgroundColor: tokens.colorNeutralBackground2,
    ':hover': {
      borderColor: tokens.colorBrandStroke1 as any,
    },
  },
  themeOptionSelected: {
    borderColor: tokens.colorBrandStroke1 as any,
    backgroundColor: tokens.colorBrandBackground2,
  },
  themeOptionIcon: {
    fontSize: '24px',
    marginBottom: '4px',
  },
  themeOptionLabel: {
    fontSize: tokens.fontSizeBase200,
    fontWeight: tokens.fontWeightMedium,
  },
  monitoringStatus: {
    ...shorthands.padding('12px'),
    marginBottom: '12px',
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
  },
  errorMessage: {
    ...shorthands.padding('12px'),
    marginBottom: '12px',
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    backgroundColor: tokens.colorPaletteRedBackground2,
    color: tokens.colorPaletteRedForeground2,
    fontSize: tokens.fontSizeBase300,
  },
  trustItemsContainer: {
    display: 'flex',
    flexDirection: 'column',
    ...shorthands.gap('12px'),
  },
  trustItem: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('16px'),
    ...shorthands.padding('16px'),
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke2),
  },
  trustItemInfo: {
    flex: 1,
    minWidth: 0,
  },
  trustItemPath: {
    fontSize: tokens.fontSizeBase300,
    fontWeight: tokens.fontWeightMedium,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    marginBottom: '4px',
  },
  trustItemMeta: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
  },
  emptyState: {
    textAlign: 'center',
    ...shorthands.padding('48px', '24px'),
    color: tokens.colorNeutralForeground3,
  },
  inputField: {
    width: '100%',
  },
  flexRow: {
    display: 'flex',
    ...shorthands.gap('12px'),
    marginBottom: '12px',
  },
  flexGrow: {
    flex: 1,
  },
})

const SettingsPage: React.FC = () => {
  const {
    config,
    setBehaviorMonitoring,
    setProcessMonitoring,
    setFileMonitoring,
    monitoringRuntimeStatus,
    monitoringControlPending,
    monitoringControlError,
    refreshMonitoringRuntimeStatus,
    trustItems,
    loadTrustItems,
    addTrustItem,
    removeTrustItem,
  } = useConfigStore()
  const { themeMode, setThemeMode, animationsEnabled, toggleAnimations } = useThemeStore()
  const { locale, setLocale, t } = useI18nStore()
  const styles = useStyles()

  const [newTrustPath, setNewTrustPath] = useState('')
  const [newTrustType, setNewTrustType] = useState<'file' | 'directory'>('file')
  const [newTrustDesc, setNewTrustDesc] = useState('')
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
    const entry = trustItems[index]
    if (!entry) return
    if (!confirm(t('settings_confirm_delete_trust').replace('{path}', entry.path))) return
    try {
      await removeTrustItem(entry.path)
    } catch (e) {
      alert(`${t('delete_failed')}: ${e}`)
    }
  }

  const handleMonitoringToggle = async (kind: 'behavior' | 'process' | 'file', enabled: boolean) => {
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

  const handleDevUnlock = async () => {
    try {
      const result = await devSettingsUnlock(devPassword)
      setDevData(JSON.stringify(result, null, 2))
      setDevUnlocked(true)
      setDevMessage(t('settings_dev_unlock_success'))
      setDevMessageIsError(false)
    } catch (e) {
      setDevMessage(`${t('settings_dev_unlock_failed')}: ${e}`)
      setDevMessageIsError(true)
    }
  }

  const handleDevSave = async () => {
    try {
      await devSettingsSave(devPassword, JSON.parse(devData))
      setDevMessage(t('settings_dev_save_success'))
      setDevMessageIsError(false)
    } catch (e) {
      setDevMessage(`${t('settings_dev_save_failed')}: ${e}`)
      setDevMessageIsError(true)
    }
  }

  return (
    <section id="page-settings" className={styles.page}>
      <h1 className={styles.pageTitle}>{t('settings_title')}</h1>

      {/* 外观组 */}
      <div className={styles.settingsGroup}>
        <div className={styles.settingsGroupTitle}>{t('settings_group_appearance')}</div>
        <div className={styles.card}>
          <Text weight="medium" size={300} style={{ marginBottom: 8 }}>
            {t('settings_theme_mode')}
          </Text>
          <div className={styles.themeSelector}>
            {themeOptions.map((o) => (
              <div
                key={o.value}
                className={`${styles.themeOption} ${themeMode === o.value ? styles.themeOptionSelected : ''}`}
                onClick={() => setThemeMode(o.value)}
              >
                <div className={styles.themeOptionIcon}>{o.icon}</div>
                <div className={styles.themeOptionLabel}>{t(o.labelKey)}</div>
              </div>
            ))}
          </div>
          <div className={styles.settingsItem} style={{ marginTop: 8 }}>
            <div className={styles.settingsItemIcon} style={{ backgroundColor: 'rgba(199,146,85,0.09)', color: 'var(--color-warning)' }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 6v6l4 2" />
              </svg>
            </div>
            <div className={styles.settingsItemText}>
              <div className={styles.settingsItemTitle}>{t('settings_disable_animations')}</div>
              <div className={styles.settingsItemDesc}>{t('settings_disable_animations_desc')}</div>
            </div>
            <div className={styles.settingsItemControl}>
              <Switch checked={!animationsEnabled} onChange={toggleAnimations} />
            </div>
          </div>
        </div>
      </div>

      {/* 安全配置组 */}
      <div className={styles.settingsGroup}>
        <div className={styles.settingsGroupTitle}>{t('settings_group_security')}</div>
        <div className={`${styles.card} ${styles.cardNoPadding}`}>
          {monitoringControlError && <div className={styles.errorMessage}>{monitoringControlError}</div>}
          <div className={styles.monitoringStatus}>
            {t('settings_monitoring_status')}
            <strong style={{ marginLeft: '6px', color: monitoringRuntimeStatus?.etwCollecting ? tokens.colorPaletteGreenForeground2 : tokens.colorPaletteYellowForeground2 }}>
              ETW {monitoringRuntimeStatus ? (monitoringRuntimeStatus.etwCollecting ? t('settings_monitoring_collecting') : t('settings_monitoring_stopped')) : t('settings_monitoring_loading')}
            </strong>
            <strong style={{ marginLeft: '10px', color: monitoringRuntimeStatus?.processWatcherRunning ? tokens.colorPaletteGreenForeground2 : tokens.colorPaletteYellowForeground2 }}>
              APIHook {monitoringRuntimeStatus ? (monitoringRuntimeStatus.processWatcherRunning ? t('settings_monitoring_running') : t('settings_monitoring_stopped')) : t('settings_monitoring_loading')}
            </strong>
            <strong style={{ marginLeft: '10px', color: monitoringRuntimeStatus?.hookRunning ? tokens.colorPaletteGreenForeground2 : tokens.colorPaletteYellowForeground2 }}>
              Hook {monitoringRuntimeStatus ? (monitoringRuntimeStatus.hookRunning ? t('settings_monitoring_running') : t('settings_monitoring_stopped')) : t('settings_monitoring_loading')}
            </strong>
          </div>
          <div className={styles.settingsItem}>
            <div className={styles.settingsItemIcon}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <div className={styles.settingsItemText}>
              <div className={styles.settingsItemTitle}>{t('settings_behavior_monitoring')}</div>
              <div className={styles.settingsItemDesc}>{t('settings_behavior_monitoring_desc')}</div>
            </div>
            <div className={styles.settingsItemControl}>
              <Switch
                checked={config?.behaviorMonitoring?.enabled || false}
                onChange={(_, data) => {
                  if (monitoringControlPending === null) {
                    void handleMonitoringToggle('behavior', data.checked)
                  }
                }}
                disabled={monitoringControlPending !== null}
              />
            </div>
          </div>
          <div className={styles.settingsItem}>
            <div className={styles.settingsItemIcon}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="4" y="4" width="16" height="16" rx="2" />
                <rect x="9" y="9" width="6" height="6" />
                <path d="M15 2v2" />
                <path d="M15 20v2" />
                <path d="M2 15h2" />
                <path d="M2 9h2" />
                <path d="M20 15h2" />
                <path d="M20 9h2" />
                <path d="M9 2v2" />
                <path d="M9 20v2" />
              </svg>
            </div>
            <div className={styles.settingsItemText}>
              <div className={styles.settingsItemTitle}>{t('settings_process_monitoring')}</div>
              <div className={styles.settingsItemDesc}>{t('settings_process_monitoring_desc')}</div>
            </div>
            <div className={styles.settingsItemControl}>
              <Switch
                checked={config?.processMonitoring?.enabled || false}
                onChange={(_, data) => {
                  if (monitoringControlPending === null) {
                    void handleMonitoringToggle('process', data.checked)
                  }
                }}
                disabled={monitoringControlPending !== null}
              />
            </div>
          </div>
          <div className={styles.settingsItem}>
            <div className={styles.settingsItemIcon} style={{ backgroundColor: 'rgba(199,146,85,0.09)', color: 'var(--color-warning)' }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M15 3h6v6" />
                <path d="M10 14 21 3" />
                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
              </svg>
            </div>
            <div className={styles.settingsItemText}>
              <div className={styles.settingsItemTitle}>{t('settings_file_hook')}</div>
              <div className={styles.settingsItemDesc}>{t('settings_file_hook_desc')}</div>
            </div>
            <div className={styles.settingsItemControl}>
              <Switch
                checked={config?.fileMonitoring?.enabled || false}
                onChange={(_, data) => {
                  if (monitoringControlPending === null) {
                    void handleMonitoringToggle('file', data.checked)
                  }
                }}
                disabled={monitoringControlPending !== null}
              />
            </div>
          </div>
        </div>
      </div>

      {/* 系统组 */}
      <div className={styles.settingsGroup}>
        <div className={styles.settingsGroupTitle}>{t('settings_group_system')}</div>
        <div className={`${styles.card} ${styles.cardNoPadding}`}>
          <div className={styles.settingsItem}>
            <div className={styles.settingsItemIcon}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
                <path d="M2 12h20" />
              </svg>
            </div>
            <div className={styles.settingsItemText}>
              <div className={styles.settingsItemTitle}>{t('settings_language')}</div>
              <div className={styles.settingsItemDesc}>{t('settings_language_desc')}</div>
            </div>
            <div className={styles.settingsItemControl}>
              <select
                className="custom-select"
                value={locale}
                onChange={(e) => void setLocale(e.target.value)}
                style={{
                  padding: '6px 12px',
                  backgroundColor: tokens.colorNeutralBackground2,
                  border: `1px solid ${tokens.colorNeutralStroke1}`,
                  borderRadius: tokens.borderRadiusMedium,
                  color: tokens.colorNeutralForeground1,
                  fontSize: tokens.fontSizeBase200,
                }}
              >
                <option value="zh-CN">{t('locale_zh_CN')}</option>
                <option value="en-US">{t('locale_en_US')}</option>
              </select>
            </div>
          </div>
          <div className={styles.settingsItem}>
            <div className={styles.settingsItemIcon}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 16v-4" />
                <path d="M12 8h.01" />
              </svg>
            </div>
            <div className={styles.settingsItemText}>
              <div className={styles.settingsItemTitle}>{t('settings_version')}</div>
              <div className={styles.settingsItemDesc}>{t('settings_version_desc')}</div>
            </div>
            <div className={styles.settingsItemControl}>
              <Text size={200} style={{ color: tokens.colorNeutralForeground3 }}>
                v1.0.0
              </Text>
            </div>
          </div>
        </div>
      </div>

      {/* 信任项目 */}
      <div className={styles.settingsGroup}>
        <div className={styles.settingsGroupTitle}>{t('settings_group_trust')}</div>
        <div className={styles.card}>
          <Text size={300} style={{ color: tokens.colorNeutralForeground3, marginBottom: '16px', display: 'block' }}>
            {t('settings_trust_desc')}
          </Text>
          <div className={styles.flexRow}>
            <Input
              className={styles.flexGrow}
              value={newTrustPath}
              onChange={(_, data) => setNewTrustPath(data.value)}
              placeholder={t('settings_trust_path_placeholder')}
            />
            <Button appearance="secondary" icon={<FolderOpen size={18} />} onClick={handleSelectTrustDir} />
            <Button appearance="secondary" icon={<FilePlus size={18} />} onClick={handleSelectTrustFile} />
          </div>
          <div className={styles.flexRow}>
            <Input
              className={styles.flexGrow}
              value={newTrustDesc}
              onChange={(_, data) => setNewTrustDesc(data.value)}
              placeholder={t('settings_trust_desc_placeholder')}
            />
          </div>
          <div className={styles.flexRow} style={{ alignItems: 'center' }}>
            <RadioGroup value={newTrustType} onChange={(_, data) => setNewTrustType(data.value as 'file' | 'directory')}>
              <Radio value="file" label={t('settings_trust_type_file')} />
              <Radio value="directory" label={t('settings_trust_type_directory')} />
            </RadioGroup>
            <Button appearance="primary" icon={<Plus size={16} />} onClick={handleAddTrustItem} disabled={!newTrustPath.trim()} style={{ marginLeft: 'auto' }}>
              {t('settings_trust_add')}
            </Button>
          </div>
          <div style={{ marginTop: '16px' }}>
            {trustItems.length === 0 ? (
              <div className={styles.emptyState}>
                <Shield size={48} />
                <p>{t('settings_trust_empty')}</p>
              </div>
            ) : (
              <div className={styles.trustItemsContainer}>
                {trustItems.map((entry, index) => (
                  <div key={index} className={styles.trustItem}>
                    <div className={styles.trustItemInfo}>
                      <div className={styles.trustItemPath}>{entry.path}</div>
                      <div className={styles.trustItemMeta}>
                        {entry.entry_type === 'directory' ? t('settings_trust_type_directory') : t('settings_trust_type_file')}
                        {' · '}
                        {entry.sources.includes('allowlist') ? t('settings_trust_source_allowlist') : t('settings_trust_source_exclusion')}
                        {entry.hash && ` · SHA256: ${entry.hash.substring(0, 16)}...`}
                        {entry.description && ` · ${entry.description}`}
                      </div>
                    </div>
                    <Button appearance="subtle" icon={<Trash2 size={16} />} onClick={() => handleRemoveTrustItem(index)} />
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 开发者设置 */}
      <div className={styles.settingsGroup}>
        <div className={styles.settingsGroupTitle}>{t('settings_group_developer')}</div>
        <div className={styles.card}>
          <Text size={300} style={{ color: tokens.colorNeutralForeground3, marginBottom: '16px', display: 'block' }}>
            {t('settings_dev_desc')}
          </Text>
          {devMessage && (
            <div
              style={{
                padding: '12px',
                marginBottom: '12px',
                borderRadius: tokens.borderRadiusMedium,
                background: devMessageIsError ? tokens.colorPaletteRedBackground2 : tokens.colorPaletteGreenBackground2,
                color: devMessageIsError ? tokens.colorPaletteRedForeground2 : tokens.colorPaletteGreenForeground2,
                fontSize: tokens.fontSizeBase300,
              }}
            >
              {devMessage}
            </div>
          )}
          {!devUnlocked ? (
            <div className={styles.flexRow}>
              <Input
                type="password"
                className={styles.flexGrow}
                value={devPassword}
                onChange={(_, data) => setDevPassword(data.value)}
                placeholder={t('settings_dev_password_placeholder')}
              />
              <Button appearance="primary" icon={<Key size={16} />} onClick={handleDevUnlock} disabled={!devPassword}>
                {t('settings_dev_unlock_btn')}
              </Button>
            </div>
          ) : (
            <div>
              <Textarea
                value={devData}
                onChange={(_, data) => setDevData(data.value)}
                rows={15}
                style={{ width: '100%', fontFamily: 'var(--font-mono)', fontSize: '13px' }}
              />
              <div className={styles.flexRow} style={{ justifyContent: 'flex-end', marginTop: '16px' }}>
                <Button
                  appearance="secondary"
                  onClick={() => {
                    setDevUnlocked(false)
                    setDevMessage('')
                    setDevMessageIsError(false)
                  }}
                >
                  {t('settings_dev_lock_btn')}
                </Button>
                <Button appearance="primary" onClick={handleDevSave}>
                  {t('settings_dev_save_btn')}
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

export default SettingsPage
