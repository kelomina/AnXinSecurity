/**
 * 网络防火墙页面
 * Network firewall page
 *
 * 展示驱动状态、运行模式、规则统计、实时连接事件与按进程流量。
 * Shows the driver status, operating mode, rule counts, live connection events
 * and per-process traffic.
 *
 * 调用方：App.tsx (路由分发)
 * Called by: App.tsx (page routing)
 *
 * 中文关键词：防火墙，流量管控，连接事件，驱动状态
 * English keywords: firewall, traffic control, connection events, driver status
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Badge,
  Button,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHeader,
  TableHeaderCell,
  TableRow,
  makeStyles,
  shorthands,
  tokens,
} from '@fluentui/react-components'
import { useFirewallStore } from '../stores/firewallStore'
import { useI18nStore } from '../stores/i18nStore'
import { AlertTriangle, Firewall, RefreshCw, Trash2 } from './icons'
import { FIREWALL_CAP, type FirewallEvent, isNetFilterInstalled, installNetFilterDriver } from '../api/firewall'

const useStyles = makeStyles({
  page: {
    paddingBottom: '24px',
  },
  pageTitle: {
    fontSize: tokens.fontSizeBase600,
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground1,
    marginBottom: '4px',
  },
  pageDesc: {
    fontSize: tokens.fontSizeBase300,
    color: tokens.colorNeutralForeground2,
    marginBottom: '20px',
  },
  card: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('16px'),
    marginBottom: '16px',
  },
  warningCard: {
    backgroundColor: tokens.colorPaletteYellowBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorPaletteYellowBorder2),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.padding('16px'),
    marginBottom: '16px',
    display: 'flex',
    alignItems: 'flex-start',
    ...shorthands.gap('16px'),
  },
  warningIcon: {
    color: tokens.colorPaletteYellowForeground2,
    flexShrink: 0,
    marginTop: '2px',
  },
  warningTitle: {
    fontSize: tokens.fontSizeBase400,
    fontWeight: tokens.fontWeightSemibold,
    marginBottom: '8px',
    color: tokens.colorNeutralForeground1,
  },
  warningDesc: {
    fontSize: tokens.fontSizeBase300,
    color: tokens.colorNeutralForeground2,
  },
  warningList: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground2,
    ...shorthands.margin('8px', '0', '0', '0'),
    paddingLeft: '18px',
  },
  cardHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    ...shorthands.gap('12px'),
    marginBottom: '12px',
    flexWrap: 'wrap',
  },
  cardTitle: {
    fontSize: tokens.fontSizeBase400,
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground1,
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('8px'),
  },
  actionRow: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('8px'),
    flexWrap: 'wrap',
  },
  metricGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
    ...shorthands.gap('12px'),
  },
  metric: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke2),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.padding('12px'),
  },
  metricLabel: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
    marginBottom: '4px',
  },
  metricValue: {
    fontSize: tokens.fontSizeBase500,
    fontWeight: tokens.fontWeightSemibold,
    color: tokens.colorNeutralForeground1,
  },
  modeRow: {
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('8px'),
    flexWrap: 'wrap',
  },
  modeHint: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
    marginTop: '8px',
  },
  errorText: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorPaletteRedForeground1,
    marginTop: '8px',
  },
  tableWrapper: {
    overflowX: 'auto',
  },
  emptyState: {
    fontSize: tokens.fontSizeBase300,
    color: tokens.colorNeutralForeground3,
    textAlign: 'center',
    ...shorthands.padding('24px'),
  },
  monospace: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase200,
  },
})

/** 运行模式选项 / Operating mode options */
const MODES = ['silent', 'prompt', 'learn'] as const

/** 把字节数渲染成可读单位 / Renders a byte count in readable units */
function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`
}

/** 把毫秒时间戳渲染成本地时间 / Renders a millisecond timestamp as local time */
function formatTime(timestamp: number): string {
  if (!timestamp) return '-'
  return new Date(timestamp).toLocaleTimeString()
}

/** 动作对应的徽章配色 / Badge colour for an action */
function actionAppearance(action: string): 'success' | 'danger' | 'warning' | 'subtle' {
  if (action === 'allow') return 'success'
  if (action === 'block') return 'danger'
  if (action === 'prompt') return 'warning'
  return 'subtle'
}

const FirewallPage: React.FC = () => {
  const styles = useStyles()
  const { t } = useI18nStore()

  const {
    status,
    events,
    stats,
    controlPending,
    controlError,
    refreshAll,
    refreshStatus,
    setEnabled,
    setMode,
    reloadRules,
    clearRememberedChoices,
    startListening,
    stopListening,
  } = useFirewallStore()

  const [reloadWarnings, setReloadWarnings] = useState<string[]>([])
  // 驱动安装状态：'checking' | 'not-installed' | 'installing' | 'installed'
  //  Driver install state machine for the first-click install prompt flow.
  const [driverInstallState, setDriverInstallState] = useState<
    'checking' | 'not-installed' | 'installing' | 'installed'
  >('checking')
  const [installError, setInstallError] = useState<string | null>(null)
  // 安装成功后需要提示重启；用户离开本页或刷新后清除。
  //  After a successful install the user must reboot; cleared on unmount or refresh.
  const [needsReboot, setNeedsReboot] = useState(false)

  useEffect(() => {
    void refreshAll()
    void startListening()
    return () => {
      stopListening()
    }
  }, [refreshAll, startListening, stopListening])

  // 首次进入防火墙页时检测驱动是否已安装。未安装时显示安装提示，
  // 而不是直接展示空白的功能界面——用户需要知道「为什么这里不能用」。
  //  Check whether the driver is installed on first entry. If not, show an
  //  install prompt instead of an empty feature page — the user needs to know
  //  "why this page does not work yet".
  useEffect(() => {
    let mounted = true
    void (async () => {
      try {
        const installed = await isNetFilterInstalled()
        if (mounted) {
          setDriverInstallState(installed ? 'installed' : 'not-installed')
        }
      } catch {
        // 检测失败时保守地视为已安装，避免误弹安装提示阻断正常使用
        //  On detection failure, conservatively assume installed to avoid
        //  blocking normal usage with a spurious install prompt
        if (mounted) setDriverInstallState('installed')
      }
    })()
    return () => { mounted = false }
  }, [])

  const handleInstallDriver = useCallback(async () => {
    setDriverInstallState('installing')
    setInstallError(null)
    try {
      await installNetFilterDriver()
      // 安装成功：服务已创建为 SYSTEM_START，下次重启后由内核加载。
      // 切到 'installed' 让界面显示「请重启电脑」提示。
      //  Install succeeded: the service is created as SYSTEM_START and will be
      //  loaded by the kernel on next reboot. Switch to 'installed' to show
      //  the "please reboot" prompt.
      setDriverInstallState('installed')
      setNeedsReboot(true)
    } catch (e) {
      setDriverInstallState('not-installed')
      setInstallError(e instanceof Error ? e.message : String(e))
    }
  }, [])

  const handleToggle = useCallback(
    async (enabled: boolean) => {
      try {
        await setEnabled(enabled)
      } catch {
        // 错误已写入 store 的 controlError，界面下方统一展示
        //  The error is recorded in the store's controlError and rendered below
      }
    },
    [setEnabled],
  )

  const handleModeChange = useCallback(
    async (mode: string) => {
      try {
        await setMode(mode)
      } catch {
        /* 同上 / same as above */
      }
    },
    [setMode],
  )

  const handleReload = useCallback(async () => {
    try {
      setReloadWarnings(await reloadRules())
    } catch {
      setReloadWarnings([])
    }
  }, [reloadRules])

  const handleClearCache = useCallback(async () => {
    try {
      await clearRememberedChoices()
    } catch {
      /* 同上 / same as above */
    }
  }, [clearRememberedChoices])

  /**
   * 驱动未连接是最需要突出的状态：开关可以是"已启用"，但只要驱动没连上，
   * 实际上一条流量都没有被管控。不明确说出来，用户会以为自己受保护。
   * A disconnected driver is the status that matters most: the switch can read
   * "enabled" while not a single packet is actually being controlled. Saying so
   * plainly is the difference between the user knowing and merely assuming.
   */
  const driverMissing = status.enabled && !status.driverConnected

  const capabilityLabels = useMemo(() => {
    if (!status.driverConnected) return []
    const labels: string[] = []
    if (status.capabilities & (FIREWALL_CAP.ALE_V4 | FIREWALL_CAP.ALE_V6)) {
      labels.push(t('firewall_cap_connection', 'Connection control'))
    }
    if (status.capabilities & FIREWALL_CAP.PEND) {
      labels.push(t('firewall_cap_prompt', 'Prompt on unknown'))
    }
    if (status.capabilities & FIREWALL_CAP.DATAGRAM) {
      labels.push(t('firewall_cap_dns', 'DNS filtering'))
    }
    if (status.capabilities & FIREWALL_CAP.STREAM) {
      labels.push(t('firewall_cap_inspect', 'Content inspection'))
    }
    if (status.capabilities & FIREWALL_CAP.RATE_LIMIT) {
      labels.push(t('firewall_cap_ratelimit', 'Rate limiting'))
    }
    if (status.capabilities & FIREWALL_CAP.FLOW_STATS) {
      labels.push(t('firewall_cap_stats', 'Traffic statistics'))
    }
    return labels
  }, [status.capabilities, status.driverConnected, t])

  const warnings = reloadWarnings.length > 0 ? reloadWarnings : status.ruleWarnings

  return (
    <section id="page-firewall" className={styles.page}>
      <h1 className={styles.pageTitle}>{t('firewall_title', 'Network Firewall')}</h1>
      <p className={styles.pageDesc}>{t('firewall_desc', '')}</p>

      {/*
        驱动安装提示。首次进入防火墙页且驱动未安装时显示，引导用户安装驱动并重启。
        安装成功后显示「请重启电脑」提示，直到用户重启。
        安装期间禁用按钮防止重复点击。
        Driver install prompt. Shown when the user first enters the firewall page
        and the driver is not yet installed, guiding them to install and reboot.
        After install succeeds, a "please reboot" prompt is shown until the user reboots.
        The button is disabled during install to prevent duplicate clicks.
      */}
      {(driverInstallState === 'not-installed' || driverInstallState === 'installing') && (
        <div className={styles.warningCard}>
          <AlertTriangle className={styles.warningIcon} size={20} />
          <div>
            <div className={styles.warningTitle}>
              {t('firewall_install_prompt_title', 'Driver not installed')}
            </div>
            <div className={styles.warningDesc}>
              {t('firewall_install_prompt_desc', 'The network filter driver is not installed. Click "Install" to copy the driver and create the system service. After installation, please restart your computer to load the driver.')}
            </div>
            {installError && (
              <div className={styles.errorText}>{installError}</div>
            )}
            <div style={{ marginTop: '12px' }}>
              <Button
                appearance="primary"
                onClick={() => void handleInstallDriver()}
                disabled={driverInstallState === 'installing'}
              >
                {driverInstallState === 'installing'
                  ? t('firewall_installing', 'Installing...')
                  : t('firewall_install_button', 'Install Driver')}
              </Button>
            </div>
          </div>
        </div>
      )}

      {needsReboot && (
        <div className={styles.warningCard}>
          <AlertTriangle className={styles.warningIcon} size={20} />
          <div>
            <div className={styles.warningTitle}>
              {t('firewall_reboot_required_title', 'Restart required')}
            </div>
            <div className={styles.warningDesc}>
              {t('firewall_reboot_required_desc', 'The driver has been installed as a system-start service. Please restart your computer to load it. After reboot, return to this page to use the firewall.')}
            </div>
          </div>
        </div>
      )}

      {driverMissing && (
        <div className={styles.warningCard}>
          <AlertTriangle className={styles.warningIcon} size={20} />
          <div>
            <div className={styles.warningTitle}>
              {t('firewall_driver_missing_title', 'Driver not connected')}
            </div>
            <div className={styles.warningDesc}>
              {t('firewall_driver_missing_desc', '')}
            </div>
          </div>
        </div>
      )}

      {warnings.length > 0 && (
        <div className={styles.warningCard}>
          <AlertTriangle className={styles.warningIcon} size={20} />
          <div>
            <div className={styles.warningTitle}>
              {t('firewall_rule_warnings_title', 'Some rules were not applied')}
            </div>
            <div className={styles.warningDesc}>
              {t('firewall_rule_warnings_desc', '')}
            </div>
            <ul className={styles.warningList}>
              {warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* 控制卡片 / Control card */}
      <div className={styles.card}>
        <div className={styles.cardHeader}>
          <div className={styles.cardTitle}>
            <Firewall size={18} />
            {t('firewall_control_title', 'Traffic control')}
          </div>
          <div className={styles.actionRow}>
            <Button
              appearance="subtle"
              icon={<RefreshCw size={16} />}
              disabled={controlPending !== null}
              onClick={() => void refreshStatus()}
            >
              {t('firewall_refresh', 'Refresh')}
            </Button>
            <Button
              appearance="subtle"
              icon={<RefreshCw size={16} />}
              disabled={controlPending !== null || !status.driverConnected}
              onClick={() => void handleReload()}
            >
              {t('firewall_reload_rules', 'Reload rules')}
            </Button>
            <Button
              appearance="subtle"
              icon={<Trash2 size={16} />}
              disabled={controlPending !== null || !status.driverConnected}
              onClick={() => void handleClearCache()}
            >
              {t('firewall_clear_remembered', 'Clear remembered choices')}
            </Button>
          </div>
        </div>

        <Switch
          checked={status.enabled}
          disabled={controlPending === 'enabled'}
          label={t('firewall_enable', 'Enable network firewall')}
          onChange={(_, data) => void handleToggle(data.checked)}
        />

        <div className={styles.modeRow} style={{ marginTop: '12px' }}>
          {MODES.map((mode) => (
            <Button
              key={mode}
              appearance={status.mode === mode ? 'primary' : 'secondary'}
              disabled={controlPending === 'mode' || !status.enabled}
              onClick={() => void handleModeChange(mode)}
            >
              {t(`firewall_mode_${mode}`, mode)}
            </Button>
          ))}
        </div>
        <div className={styles.modeHint}>{t(`firewall_mode_${status.mode}_hint`, '')}</div>

        {capabilityLabels.length > 0 && (
          <div className={styles.actionRow} style={{ marginTop: '12px' }}>
            {capabilityLabels.map((label) => (
              <Badge key={label} appearance="tint" color="brand">
                {label}
              </Badge>
            ))}
          </div>
        )}

        {controlError && <div className={styles.errorText}>{controlError}</div>}
      </div>

      {/* 指标卡片 / Metrics card */}
      <div className={styles.card}>
        <div className={styles.cardTitle} style={{ marginBottom: '12px' }}>
          {t('firewall_metrics_title', 'Status')}
        </div>
        <div className={styles.metricGrid}>
          <div className={styles.metric}>
            <div className={styles.metricLabel}>{t('firewall_metric_driver', 'Driver')}</div>
            <div className={styles.metricValue}>
              {status.driverConnected
                ? status.driverVersion || t('firewall_connected', 'Connected')
                : t('firewall_disconnected', 'Not connected')}
            </div>
          </div>
          <div className={styles.metric}>
            <div className={styles.metricLabel}>{t('firewall_metric_rules', 'Rules')}</div>
            <div className={styles.metricValue}>{status.ruleCount}</div>
          </div>
          <div className={styles.metric}>
            <div className={styles.metricLabel}>
              {t('firewall_metric_domain_rules', 'Domain rules')}
            </div>
            <div className={styles.metricValue}>{status.domainRuleCount}</div>
          </div>
          <div className={styles.metric}>
            <div className={styles.metricLabel}>{t('firewall_metric_pending', 'Awaiting decision')}</div>
            <div className={styles.metricValue}>{status.pendingCount}</div>
          </div>
          {stats && (
            <>
              <div className={styles.metric}>
                <div className={styles.metricLabel}>
                  {t('firewall_metric_events_dropped', 'Events dropped')}
                </div>
                <div className={styles.metricValue}>{stats.eventsDropped}</div>
              </div>
              <div className={styles.metric}>
                <div className={styles.metricLabel}>
                  {t('firewall_metric_timed_out', 'Timed out')}
                </div>
                <div className={styles.metricValue}>{stats.pendingTimedOut}</div>
              </div>
            </>
          )}
        </div>
      </div>

      {/* 事件表格 / Event table */}
      <div className={styles.card}>
        <div className={styles.cardTitle} style={{ marginBottom: '12px' }}>
          {t('firewall_events_title', 'Recent connections')}
        </div>

        {events.length === 0 ? (
          <div className={styles.emptyState}>{t('firewall_events_empty', 'No events yet')}</div>
        ) : (
          <div className={styles.tableWrapper}>
            <Table size="small" aria-label={t('firewall_events_title', 'Recent connections')}>
              <TableHeader>
                <TableRow>
                  <TableHeaderCell>{t('firewall_th_time', 'Time')}</TableHeaderCell>
                  <TableHeaderCell>{t('firewall_th_process', 'Process')}</TableHeaderCell>
                  <TableHeaderCell>{t('firewall_th_direction', 'Direction')}</TableHeaderCell>
                  <TableHeaderCell>{t('firewall_th_protocol', 'Protocol')}</TableHeaderCell>
                  <TableHeaderCell>{t('firewall_th_remote', 'Remote')}</TableHeaderCell>
                  <TableHeaderCell>{t('firewall_th_domain', 'Domain')}</TableHeaderCell>
                  <TableHeaderCell>{t('firewall_th_action', 'Action')}</TableHeaderCell>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((event: FirewallEvent, index: number) => (
                  <TableRow key={`${event.timestamp}-${event.decisionId}-${index}`}>
                    <TableCell>{formatTime(event.timestamp)}</TableCell>
                    <TableCell title={event.processPath}>
                      {event.processName || `PID ${event.pid}`}
                    </TableCell>
                    <TableCell>
                      {t(`firewall_dir_${event.direction}`, event.direction)}
                    </TableCell>
                    <TableCell className={styles.monospace}>{event.protocol}</TableCell>
                    <TableCell className={styles.monospace}>
                      {event.remoteAddress}
                      {event.remotePort ? `:${event.remotePort}` : ''}
                    </TableCell>
                    <TableCell title={event.domain}>{event.domain || '-'}</TableCell>
                    <TableCell>
                      <Badge appearance="tint" color={actionAppearance(event.action)}>
                        {t(`firewall_action_${event.action}`, event.action)}
                        {event.timedOut ? ` (${t('firewall_timed_out', 'timed out')})` : ''}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>

      {/* 按进程流量 / Per-process traffic */}
      {stats && stats.processes.length > 0 && (
        <div className={styles.card}>
          <div className={styles.cardTitle} style={{ marginBottom: '12px' }}>
            {t('firewall_traffic_title', 'Traffic by process')}
          </div>
          <div className={styles.tableWrapper}>
            <Table size="small" aria-label={t('firewall_traffic_title', 'Traffic by process')}>
              <TableHeader>
                <TableRow>
                  <TableHeaderCell>{t('firewall_th_pid', 'PID')}</TableHeaderCell>
                  <TableHeaderCell>{t('firewall_th_bytes_in', 'Received')}</TableHeaderCell>
                  <TableHeaderCell>{t('firewall_th_bytes_out', 'Sent')}</TableHeaderCell>
                  <TableHeaderCell>{t('firewall_th_allowed', 'Allowed')}</TableHeaderCell>
                  <TableHeaderCell>{t('firewall_th_blocked', 'Blocked')}</TableHeaderCell>
                </TableRow>
              </TableHeader>
              <TableBody>
                {stats.processes.map((process) => (
                  <TableRow key={process.pid}>
                    <TableCell className={styles.monospace}>{process.pid}</TableCell>
                    <TableCell>{formatBytes(process.bytesIn)}</TableCell>
                    <TableCell>{formatBytes(process.bytesOut)}</TableCell>
                    <TableCell>{process.connAllowed}</TableCell>
                    <TableCell>{process.connBlocked}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      )}
    </section>
  )
}

export default FirewallPage
