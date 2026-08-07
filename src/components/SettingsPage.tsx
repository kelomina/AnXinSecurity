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
import { useFirewallStore } from '../stores/firewallStore'
import { useHypervisorStore } from '../stores/hypervisorStore'
import {
  Clock3,
  Cpu,
  ExternalLink,
  FilePlus,
  Firewall,
  FolderOpen,
  Globe2,
  Info,
  Key,
  Monitor,
  Moon,
  Plus,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Trash2,
} from './icons'
import { open } from '@tauri-apps/plugin-dialog'
import { ConfirmDialog } from './common/ConfirmDialog'
import {
  Button,
  Switch,
  Input,
  Textarea,
  Radio,
  RadioGroup,
  Dropdown,
  Option,
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
  settingsItemSpaced: {
    marginTop: '8px',
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
  settingsItemIconWarning: {
    backgroundColor: tokens.colorPaletteYellowBackground2,
    color: tokens.colorPaletteYellowForeground2,
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
      ...shorthands.borderColor(tokens.colorBrandStroke1),
    },
  },
  themeOptionSelected: {
    ...shorthands.borderColor(tokens.colorBrandStroke1),
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
  monitoringStatusValue: {
    marginLeft: '10px',
  },
  monitoringStatusValueFirst: {
    marginLeft: '6px',
  },
  monitoringStatusOk: {
    color: tokens.colorPaletteGreenForeground2,
  },
  monitoringStatusWarn: {
    color: tokens.colorPaletteYellowForeground2,
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
  flexRow: {
    display: 'flex',
    ...shorthands.gap('12px'),
    marginBottom: '12px',
  },
  flexRowCenter: {
    alignItems: 'center',
  },
  flexRowEnd: {
    justifyContent: 'flex-end',
    marginTop: '16px',
  },
  flexGrow: {
    flex: 1,
  },
  fieldLabel: {
    display: 'block',
    marginBottom: '8px',
  },
  radioLabel: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    ...shorthands.gap('8px'),
  },
  secondaryText: {
    color: tokens.colorNeutralForeground3,
  },
  blockDescription: {
    display: 'block',
    color: tokens.colorNeutralForeground3,
    marginBottom: '16px',
  },
  addTrustButton: {
    marginLeft: 'auto',
  },
  trustItemsList: {
    marginTop: '16px',
  },
  devMessage: {
    ...shorthands.padding('12px'),
    marginBottom: '12px',
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    fontSize: tokens.fontSizeBase300,
  },
  devMessageError: {
    backgroundColor: tokens.colorPaletteRedBackground2,
    color: tokens.colorPaletteRedForeground2,
  },
  devMessageSuccess: {
    backgroundColor: tokens.colorPaletteGreenBackground2,
    color: tokens.colorPaletteGreenForeground2,
  },
  devTextarea: {
    width: '100%',
    fontFamily: 'Consolas, "Courier New", monospace',
    fontSize: '13px',
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
    devModeUnlocked,
    setDevModeUnlocked,
  } = useConfigStore()
  const { themeMode, setThemeMode, animationsEnabled, toggleAnimations } = useThemeStore()
  const { locale, setLocale, t } = useI18nStore()
  const {
    status: firewallStatus,
    controlPending: firewallControlPending,
    setEnabled: setFirewallEnabled,
    refreshStatus: refreshFirewallStatus,
  } = useFirewallStore()
  const {
    status: hypervisorStatus,
    controlPending: hypervisorControlPending,
    controlError: hypervisorControlError,
    setEnabled: setHypervisorEnabled,
    refreshStatus: refreshHypervisorStatus,
  } = useHypervisorStore()
  const styles = useStyles()

  const [newTrustPath, setNewTrustPath] = useState('')
  const [newTrustType, setNewTrustType] = useState<'file' | 'directory'>('file')
  const [newTrustDesc, setNewTrustDesc] = useState('')
  const [devPassword, setDevPassword] = useState('')
  const [devData, setDevData] = useState('')
  const [devMessage, setDevMessage] = useState('')
  const [devMessageIsError, setDevMessageIsError] = useState(false)
  const [trustError, setTrustError] = useState('')
  const [deleteConfirm, setDeleteConfirm] = useState<{ path: string; index: number } | null>(null)

  useEffect(() => {
    loadTrustItems()
    refreshMonitoringRuntimeStatus()
    // 防火墙开关必须显示后端的真实状态而不是配置文件里的值：
    // 配置写着已启用但驱动没装时，开关应当能反映出来。
    //  The firewall switch must reflect the backend's real state rather than the
    //  config file: with the config saying enabled but no driver installed, the
    //  switch needs to be able to show it.
    void refreshFirewallStatus()
    // 元核防护同理：配置写 enabled 但驱动未通过环境检查或未安装时，
    // 开关必须显示真实状态而不是配置值。
    //  Same for hypervisor protection: with the config saying enabled but the
    //  driver missing or the environment check failing, the switch must show
    //  the real state rather than the config value.
    void refreshHypervisorStatus()
  }, [loadTrustItems, refreshMonitoringRuntimeStatus, refreshFirewallStatus, refreshHypervisorStatus])

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
    setTrustError('')
    try {
      await addTrustItem(newTrustPath, newTrustType, newTrustDesc || undefined)
      setNewTrustPath('')
      setNewTrustDesc('')
      setNewTrustType('file')
    } catch (e) {
      const msg = `${t('settings_dev_save_failed')}: ${e}`
      console.warn('[SettingsPage] Add trust item failed:', e)
      setTrustError(msg)
    }
  }

  const handleRemoveTrustItem = async (index: number) => {
    const entry = trustItems[index]
    if (!entry) return
    setDeleteConfirm({ path: entry.path, index })
  }

  const handleDeleteConfirm = async () => {
    if (!deleteConfirm) return
    setDeleteConfirm(null)
    setTrustError('')
    try {
      await removeTrustItem(deleteConfirm.path)
    } catch (e) {
      const msg = `${t('delete_failed')}: ${e}`
      console.warn('[SettingsPage] Remove trust item failed:', e)
      setTrustError(msg)
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
      setDevModeUnlocked(true)
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
    <>
    <section id="page-settings" className={styles.page}>
      <h1 className={styles.pageTitle}>{t('settings_title')}</h1>

      {/* 外观组 */}
      <div className={styles.settingsGroup}>
        <div className={styles.settingsGroupTitle}>{t('settings_group_appearance')}</div>
        <div className={styles.card}>
          <Text weight="medium" size={300} className={styles.fieldLabel}>
            {t('settings_theme_mode')}
          </Text>
          <RadioGroup
            value={themeMode}
            onChange={(_, data) => setThemeMode(data.value as ThemeMode)}
            className={styles.themeSelector}
          >
            {themeOptions.map((o) => (
              <Radio
                key={o.value}
                value={o.value}
                label={
                  <span className={styles.radioLabel}>
                    <span className={styles.themeOptionIcon}>{o.icon}</span>
                    <span className={styles.themeOptionLabel}>{t(o.labelKey)}</span>
                  </span>
                }
              />
            ))}
          </RadioGroup>
          <div className={`${styles.settingsItem} ${styles.settingsItemSpaced}`}>
            <div className={`${styles.settingsItemIcon} ${styles.settingsItemIconWarning}`}>
              <Clock3 size={18} />
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
            <strong className={`${styles.monitoringStatusValueFirst} ${monitoringRuntimeStatus?.etwCollecting ? styles.monitoringStatusOk : styles.monitoringStatusWarn}`}>
              ETW {monitoringRuntimeStatus ? (monitoringRuntimeStatus.etwCollecting ? t('settings_monitoring_collecting') : t('settings_monitoring_stopped')) : t('settings_monitoring_loading')}
            </strong>
            <strong className={`${styles.monitoringStatusValue} ${monitoringRuntimeStatus?.processWatcherRunning ? styles.monitoringStatusOk : styles.monitoringStatusWarn}`}>
              APIHook {monitoringRuntimeStatus ? (monitoringRuntimeStatus.processWatcherRunning ? t('settings_monitoring_running') : t('settings_monitoring_stopped')) : t('settings_monitoring_loading')}
            </strong>
            <strong className={`${styles.monitoringStatusValue} ${monitoringRuntimeStatus?.hookRunning ? styles.monitoringStatusOk : styles.monitoringStatusWarn}`}>
              Hook {monitoringRuntimeStatus ? (monitoringRuntimeStatus.hookRunning ? t('settings_monitoring_running') : t('settings_monitoring_stopped')) : t('settings_monitoring_loading')}
            </strong>
          </div>
          <div className={styles.settingsItem}>
            <div className={styles.settingsItemIcon}>
              <ShieldCheck size={18} />
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
              <Cpu size={18} />
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
            <div className={`${styles.settingsItemIcon} ${styles.settingsItemIconWarning}`}>
              <ExternalLink size={18} />
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
          {/*
            网络防火墙开关。与上面几个监控开关的区别在于：这个开关会真的切断
            用户的网络连接，因此它的运行状态（尤其是"驱动未连接"）必须在防火墙
            页面上有完整交代，这里只做最基本的启停。
            Network firewall switch. Unlike the monitoring toggles above, this one
            can genuinely cut the user's network, so its runtime state — above all
            "driver not connected" — is spelled out in full on the firewall page.
            This row only does the basic on/off.
          */}
          <div className={styles.settingsItem}>
            <div className={`${styles.settingsItemIcon} ${styles.settingsItemIconWarning}`}>
              <Firewall size={18} />
            </div>
            <div className={styles.settingsItemText}>
              <div className={styles.settingsItemTitle}>{t('settings_network_firewall')}</div>
              <div className={styles.settingsItemDesc}>
                {t('settings_network_firewall_desc')}
              </div>
            </div>
            <div className={styles.settingsItemControl}>
              <Switch
                checked={firewallStatus.enabled}
                onChange={(_, data) => {
                  if (firewallControlPending === null) {
                    void setFirewallEnabled(data.checked).catch(() => {
                      // 错误由 firewallStore 记录，防火墙页面统一展示
                      //  The error is recorded by firewallStore and shown on the firewall page
                    })
                  }
                }}
                disabled={firewallControlPending !== null}
              />
            </div>
          </div>
          {/*
            元核防护开关。默认关闭，用户开启时会先做环境检查（驱动是否已安装、
            服务是否可启动），通过后才真正拉起 hypervisor 驱动接管系统虚拟化。
            这是改变系统虚拟化姿态的高风险动作，所以开关状态必须反映后端真实
            接管情况，而不能只看配置文件里的 enabled 值。
            Hypervisor protection switch. Defaults to off; turning it on runs an
            environment check first (driver installed, service startable) and only
            then brings up the hypervisor driver to take over system virtualization.
            This is a high-risk action that alters the system's virtualization
            posture, so the switch must reflect the real takeover state from the
            backend rather than just the enabled flag in the config file.
          */}
          <div className={styles.settingsItem}>
            <div className={`${styles.settingsItemIcon} ${styles.settingsItemIconWarning}`}>
              <ShieldAlert size={18} />
            </div>
            <div className={styles.settingsItemText}>
              <div className={styles.settingsItemTitle}>{t('settings_hypervisor_protection')}</div>
              <div className={styles.settingsItemDesc}>
                {t('settings_hypervisor_protection_desc')}
              </div>
            </div>
            <div className={styles.settingsItemControl}>
              <Switch
                checked={hypervisorStatus.driverConnected}
                onChange={(_, data) => {
                  if (!hypervisorControlPending) {
                    void setHypervisorEnabled(data.checked).catch(() => {
                      // 错误由 hypervisorStore 记录并在下方统一展示
                      //  The error is recorded by hypervisorStore and shown below
                    })
                  }
                }}
                disabled={hypervisorControlPending}
              />
            </div>
          </div>
          {hypervisorControlError && (
            <div className={styles.errorMessage}>{hypervisorControlError}</div>
          )}
        </div>
      </div>

      {/* 系统组 */}
      <div className={styles.settingsGroup}>
        <div className={styles.settingsGroupTitle}>{t('settings_group_system')}</div>
        <div className={`${styles.card} ${styles.cardNoPadding}`}>
          <div className={styles.settingsItem}>
            <div className={styles.settingsItemIcon}>
              <Globe2 size={18} />
            </div>
            <div className={styles.settingsItemText}>
              <div className={styles.settingsItemTitle} id="settings-language-label">{t('settings_language')}</div>
              <div className={styles.settingsItemDesc}>{t('settings_language_desc')}</div>
            </div>
            <div className={styles.settingsItemControl}>
              <Dropdown
                value={locale === 'zh-CN' ? t('locale_zh_CN') : t('locale_en_US')}
                selectedOptions={[locale]}
                onOptionSelect={(_, data) => {
                  if (data.optionValue) void setLocale(data.optionValue)
                }}
                aria-labelledby="settings-language-label"
              >
                <Option value="zh-CN">{t('locale_zh_CN')}</Option>
                <Option value="en-US">{t('locale_en_US')}</Option>
              </Dropdown>
            </div>
          </div>
          <div className={styles.settingsItem}>
            <div className={styles.settingsItemIcon}>
              <Info size={18} />
            </div>
            <div className={styles.settingsItemText}>
              <div className={styles.settingsItemTitle}>{t('settings_version')}</div>
              <div className={styles.settingsItemDesc}>{t('settings_version_desc')}</div>
            </div>
            <div className={styles.settingsItemControl}>
              <Text size={200} className={styles.secondaryText}>
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
          <Text size={300} className={styles.blockDescription}>
            {t('settings_trust_desc')}
          </Text>
          {trustError && (
            <div className={styles.errorMessage}>{trustError}</div>
          )}
          <div className={styles.flexRow}>
            <Input
              className={styles.flexGrow}
              value={newTrustPath}
              onChange={(_, data) => setNewTrustPath(data.value)}
              placeholder={t('settings_trust_path_placeholder')}
            />
            <Button appearance="secondary" icon={<FolderOpen size={18} />} onClick={handleSelectTrustDir} aria-label={t('settings_select_directory')} />
            <Button appearance="secondary" icon={<FilePlus size={18} />} onClick={handleSelectTrustFile} aria-label={t('settings_select_file')} />
          </div>
          <div className={styles.flexRow}>
            <Input
              className={styles.flexGrow}
              value={newTrustDesc}
              onChange={(_, data) => setNewTrustDesc(data.value)}
              placeholder={t('settings_trust_desc_placeholder')}
            />
          </div>
          <div className={`${styles.flexRow} ${styles.flexRowCenter}`}>
            <RadioGroup value={newTrustType} onChange={(_, data) => setNewTrustType(data.value as 'file' | 'directory')}>
              <Radio value="file" label={t('settings_trust_type_file')} />
              <Radio value="directory" label={t('settings_trust_type_directory')} />
            </RadioGroup>
            <Button appearance="primary" icon={<Plus size={16} />} onClick={handleAddTrustItem} disabled={!newTrustPath.trim()} className={styles.addTrustButton}>
              {t('settings_trust_add')}
            </Button>
          </div>
          <div className={styles.trustItemsList}>
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
                    <Button appearance="subtle" icon={<Trash2 size={16} />} onClick={() => handleRemoveTrustItem(index)} aria-label={t('settings_delete_trust')} />
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
          <Text size={300} className={styles.blockDescription}>
            {t('settings_dev_desc')}
          </Text>
          {devMessage && (
            <div
              className={`${styles.devMessage} ${devMessageIsError ? styles.devMessageError : styles.devMessageSuccess}`}
            >
              {devMessage}
            </div>
          )}
          {!devModeUnlocked ? (
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
                className={styles.devTextarea}
              />
              <div className={`${styles.flexRow} ${styles.flexRowEnd}`}>
                <Button
                  appearance="secondary"
                  onClick={() => {
                    setDevModeUnlocked(false)
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

    <ConfirmDialog
      open={deleteConfirm !== null}
      title={t('settings_confirm_delete_trust_title')}
      message={deleteConfirm ? t('settings_confirm_delete_trust').replace('{path}', deleteConfirm.path) : ''}
      confirmText={t('quarantine_confirm_delete')}
      cancelText={t('common_cancel')}
      intent="danger"
      onConfirm={handleDeleteConfirm}
      onCancel={() => setDeleteConfirm(null)}
    />
    </>
  )
}

export default SettingsPage
