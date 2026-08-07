/**
 * 网络防火墙 API 封装
 * Network firewall API wrapper
 *
 * 封装 AnXinNetFilter 驱动相关的全部 invoke 调用：状态查询、开关与模式、规则重载、
 * 连接裁决、事件与流量统计。
 * Wraps every invoke call related to the AnXinNetFilter driver: status, switches
 * and mode, rule reload, connection verdicts, events and traffic statistics.
 *
 * 按 AGENTS.md 的分层要求，本层只做 invoke 包装，不含任何状态或业务判断。
 * Per the layering rule in AGENTS.md this layer only wraps invoke; it holds no
 * state and makes no business decisions.
 *
 * 中文关键词：防火墙 API，驱动调用，连接裁决
 * English keywords: firewall API, driver invocation, connection verdict
 */
import { invoke } from '@tauri-apps/api/core'

/** 防火墙运行状态 / Firewall runtime status */
export interface FirewallStatus {
  /** 服务是否已启动 / Whether the service has started */
  running: boolean
  /** 驱动是否已连接并完成版本握手 / Whether the driver is connected and handshaken */
  driverConnected: boolean
  /** 驱动实际注册成功的能力位 / Capability bits the driver actually registered */
  capabilities: number
  driverVersion: string
  /** silent / prompt / learn */
  mode: string
  enabled: boolean
  ruleCount: number
  domainRuleCount: number
  limitCount: number
  pendingCount: number
  /** 最近一次规则编译的告警 / Warnings from the last rule compilation */
  ruleWarnings: string[]
}

/** 一条网络事件 / A network event */
export interface FirewallEvent {
  /** 待裁决时非 0 / Non-zero while awaiting a verdict */
  decisionId: number
  /** connect_request / connect_log / dns_query / domain_blocked / flow_closed / rate_limited */
  kind: string
  timestamp: number
  pid: number
  processPath: string
  processName: string
  /** outbound / inbound */
  direction: string
  /** tcp / udp / protoN */
  protocol: string
  localPort: number
  remoteAddress: string
  remotePort: number
  /** allow / block / prompt */
  action: string
  ruleId: number
  domain: string
  bytesIn: number
  bytesOut: number
  /** 由驱动按超时策略兜底处理 / resolved by the driver's timeout policy */
  timedOut: boolean
}

/** 待用户裁决的连接 / A connection awaiting a verdict */
export interface PendingConnection {
  decisionId: number
  pid: number
  processPath: string
  processName: string
  protocol: string
  direction: string
  remoteAddress: string
  remotePort: number
  timestamp: number
  /** 本地推算的过期时刻 / locally computed expiry */
  expiresAt: number
}

/** 单个进程的流量统计 / Traffic statistics for one process */
export interface ProcessTrafficStat {
  pid: number
  activeFlows: number
  bytesIn: number
  bytesOut: number
  connAllowed: number
  connBlocked: number
  lastActivity: number
}

/** 流量统计与队列健康指标 / Traffic statistics and queue health */
export interface FirewallTrafficStats {
  totalProcesses: number
  eventsQueued: number
  eventsDropped: number
  pendingCount: number
  pendingTimedOut: number
  cacheHits: number
  cacheMisses: number
  processes: ProcessTrafficStat[]
}

/** 裁决提交结果 / Result of submitting a verdict */
export interface NetworkDecisionResult {
  ok: boolean
  /** 驱动已因超时先行处理，用户点晚了 / the driver's timeout got there first */
  alreadyResolved: boolean
}

/** 驱动能力位 / Driver capability bits（与 anx_net_ioctl.h 的 ANX_NET_CAP_* 一致） */
export const FIREWALL_CAP = {
  ALE_V4: 0x0000_0001,
  ALE_V6: 0x0000_0002,
  FLOW_STATS: 0x0000_0004,
  STREAM: 0x0000_0008,
  DATAGRAM: 0x0000_0010,
  RATE_LIMIT: 0x0000_0020,
  PEND: 0x0000_0040,
} as const

/**
 * 函数名称：getFirewallStatus
 * 函数作用：查询防火墙运行状态。
 * Purpose: Queries the firewall runtime status.
 * 调用方：firewallStore.refreshStatus()
 * Called by: firewallStore.refreshStatus()
 * 中文关键词：防火墙状态，驱动连接
 * English keywords: firewall status, driver connection
 */
export async function getFirewallStatus(): Promise<FirewallStatus> {
  return await invoke('get_firewall_status')
}

/**
 * 函数名称：startFirewall
 * 函数作用：连接驱动并启动流量管控。
 * Purpose: Connects to the driver and starts traffic control.
 * 调用方：firewallStore.setEnabled()
 * Called by: firewallStore.setEnabled()
 * 中文关键词：启动防火墙
 * English keywords: firewall start
 */
export async function startFirewall(): Promise<boolean> {
  return await invoke('start_firewall')
}

/**
 * 函数名称：stopFirewall
 * 函数作用：停止流量管控并断开驱动，驱动随即恢复全放行。
 * Purpose: Stops traffic control and disconnects; the driver reverts to permit-all.
 * 调用方：firewallStore.setEnabled()
 * Called by: firewallStore.setEnabled()
 * 中文关键词：停止防火墙，恢复放行
 * English keywords: firewall stop, revert to permit
 */
export async function stopFirewall(): Promise<boolean> {
  return await invoke('stop_firewall')
}

/**
 * 函数名称：setFirewallEnabled
 * 函数作用：设置防火墙总开关并持久化到 app.json。
 * Purpose: Sets the master switch and persists it to app.json.
 * 副作用：后端写 config/app.json
 * Side effects: the backend writes config/app.json
 * 中文关键词：总开关，配置持久化
 * English keywords: master switch, config persistence
 */
export async function setFirewallEnabled(enabled: boolean): Promise<boolean> {
  return await invoke('set_firewall_enabled', { enabled })
}

/**
 * 函数名称：setFirewallMode
 * 函数作用：切换运行模式（silent / prompt / learn）。
 * Purpose: Switches the operating mode (silent / prompt / learn).
 * 中文关键词：运行模式，静默，询问，学习
 * English keywords: operating mode, silent, prompt, learn
 */
export async function setFirewallMode(mode: string): Promise<boolean> {
  return await invoke('set_firewall_mode', { mode })
}

/**
 * 函数名称：reloadFirewallRules
 * 函数作用：重新读取 config/firewall_rules.json 并整表下发给驱动。
 * Purpose: Re-reads config/firewall_rules.json and pushes all tables to the driver.
 * 返回值：编译告警列表；为空表示全部规则均已生效
 * Returns: compile warnings; empty means every rule was applied
 * 中文关键词：规则重载，编译告警
 * English keywords: rule reload, compile warnings
 */
export async function reloadFirewallRules(): Promise<string[]> {
  return await invoke('reload_firewall_rules')
}

/**
 * 函数名称：flushFirewallCache
 * 函数作用：清空内核裁决缓存，让"记住的选择"全部失效并重新询问。
 * Purpose: Flushes the kernel verdict cache so every remembered choice is
 *          discarded and connections are asked about again.
 * 中文关键词：清空缓存，重新询问
 * English keywords: flush cache, re-prompt
 */
export async function flushFirewallCache(): Promise<boolean> {
  return await invoke('flush_firewall_cache')
}

/**
 * 函数名称：handleNetworkDecision
 * 函数作用：把用户的允许/阻止选择回送给驱动。
 * Purpose: Sends the user's allow/block choice back to the driver.
 *
 * 参数 remember 记住"该进程 + 该目标"，rememberProcess 记住"该进程的全部目标"。
 * 返回的 alreadyResolved 为真表示驱动已按超时策略处理，不是错误。
 * `remember` caches this process+destination pair; `rememberProcess` caches the
 * process for every destination. A returned alreadyResolved=true means the
 * driver already applied its timeout policy — not an error.
 *
 * 调用方：拦截窗口的允许/阻止按钮
 * Called by: the allow/block buttons in the interception window
 * 中文关键词：网络裁决，记住选择，超时
 * English keywords: network verdict, remember choice, timeout
 */
export async function handleNetworkDecision(
  decisionId: number,
  action: 'allow' | 'block',
  remember = false,
  rememberProcess = false,
): Promise<NetworkDecisionResult> {
  return await invoke('handle_network_decision', {
    decisionId,
    action,
    remember,
    rememberProcess,
  })
}

/**
 * 函数名称：getNetworkPending
 * 函数作用：获取当前待裁决的连接队列。
 * Purpose: Gets the queue of connections awaiting a verdict.
 * 中文关键词：待决队列
 * English keywords: pending queue
 */
export async function getNetworkPending(): Promise<PendingConnection[]> {
  return await invoke('get_network_pending')
}

/**
 * 函数名称：getNetworkEvents
 * 函数作用：获取最近的网络事件，按时间倒序。
 * Purpose: Gets recent network events, newest first.
 * 参数 limit: 条数上限，后端硬上限 500
 * Parameters: limit, hard-capped at 500 by the backend
 * 中文关键词：事件列表，倒序
 * English keywords: event list, newest first
 */
export async function getNetworkEvents(limit = 200): Promise<FirewallEvent[]> {
  return await invoke('get_network_events', { limit })
}

/**
 * 函数名称：getNetworkStats
 * 函数作用：获取按进程的流量统计与内核队列健康指标。
 * Purpose: Gets per-process traffic statistics and kernel queue health.
 * 中文关键词：流量统计，队列健康
 * English keywords: traffic statistics, queue health
 */
export async function getNetworkStats(): Promise<FirewallTrafficStats> {
  return await invoke('get_network_stats')
}

/**
 * 函数名称：isNetFilterInstalled
 * 函数作用：检查 AnXinNetFilter 驱动服务是否已安装。
 * Purpose: Checks whether the AnXinNetFilter driver service is installed.
 * 调用方：FirewallPage 首次进入时检测。
 * Called by: FirewallPage on first entry.
 * 返回值：true = 已安装；false = 未安装（需安装+重启）。
 * Returns: true = installed; false = missing (install + reboot needed).
 * 中文关键词：驱动检测，服务存在
 * English keywords: driver detection, service existence
 */
export async function isNetFilterInstalled(): Promise<boolean> {
  return await invoke('is_netfilter_installed')
}

/**
 * 函数名称：installNetFilterDriver
 * 函数作用：安装 AnXinNetFilter 驱动（复制 .sys + 创建 SYSTEM_START 服务）。
 * Purpose: Installs the AnXinNetFilter driver (copy .sys + create SYSTEM_START service).
 * 调用方：FirewallPage 安装提示弹窗的「安装」按钮。
 * Called by: the "Install" button in the FirewallPage install prompt.
 * 副作用：复制驱动文件到 System32\drivers，创建系统服务。
 * Side effects: copies the driver file to System32\drivers and creates a system service.
 * 中文关键词：驱动安装，创建服务，重启提示
 * English keywords: driver install, create service, reboot prompt
 */
export async function installNetFilterDriver(): Promise<boolean> {
  return await invoke('install_netfilter_driver')
}
