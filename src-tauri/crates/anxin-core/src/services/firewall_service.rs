// 防火墙服务 — AnXinNetFilter.sys 的用户态编排层
//  Firewall service - the user-mode orchestration layer for AnXinNetFilter.sys
//
// 职责 / Responsibilities:
// - 连接驱动、完成版本握手、下发运行配置与三张规则表
//   Connect to the driver, complete the version handshake, push the runtime
//   configuration and the three rule tables
// - 跑事件泵线程，把内核事件转成前端事件
//   Run the event-pump thread and translate kernel events into frontend events
// - 维护待用户裁决的连接队列，并把裁决回送驱动
//   Maintain the queue of connections awaiting a user verdict and send the
//   verdicts back to the driver
//
// 关键安全性质 / Key safety property:
// 驱动缺失、版本不匹配、连接失败都不是致命错误。任何一种情况下服务都退回
// 「未接管」状态，驱动同时会全放行，机器的网络行为与没装这个模块时完全一致。
// A missing driver, a version mismatch or a failed connection are all
// non-fatal. In every case the service falls back to the detached state, the
// driver permits everything, and the machine's networking behaves exactly as if
// this module were not installed.
//
// 中文关键词：防火墙服务，事件泵，裁决队列，降级运行
// English keywords: firewall service, event pump, verdict queue, graceful degradation

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use serde::{Deserialize, Serialize};

use crate::models::config::NetworkFirewallConfig;
use crate::services::firewall_rules::FirewallRuleSet;
use crate::services::service_context::ServiceContext;
use crate::utils::net_driver_client::{
    NetConfig, NetDriverClient, NetEvent, NetVerdict, NetVersion, ACTION_ALLOW, ACTION_BLOCK,
    ACTION_PROMPT, DIR_INBOUND, EVTF_TIMED_OUT, EVT_CONNECT_LOG, EVT_CONNECT_REQUEST,
    EVT_DNS_QUERY, EVT_DOMAIN_BLOCKED, EVT_FLOW_CLOSED, EVT_RATE_LIMITED, FLUSH_ALL, MODE_LEARN,
    MODE_PROMPT, MODE_SILENT, PROTO_TCP, PROTO_UDP, VF_REMEMBER, VF_REMEMBER_PROCESS,
};

/// 前端事件名：每一条网络事件 / Frontend event name for every network event
pub const EVENT_NETWORK: &str = "network-event";
/// 前端事件名：需要用户裁决的连接 / Frontend event name for a connection awaiting a verdict
pub const EVENT_NETWORK_INTERCEPTED: &str = "network-intercepted";

/// 最近事件环形缓冲容量。只用于界面回看，不是审计日志，
/// 因此可以在内存里有界保存并丢弃最旧的。
///  Capacity of the recent-event ring. It backs the UI's scroll-back only, not
///  the audit log, so a bounded in-memory buffer that drops the oldest is fine.
const RECENT_EVENT_CAPACITY: usize = 500;

/// 事件泵在驱动异常时的重试间隔（毫秒）
///  Retry interval in milliseconds when the pump hits a driver error
const PUMP_RETRY_INTERVAL_MS: u64 = 500;

// ============================================================================
// 前端数据类型 / Frontend-facing data types
// ============================================================================

/// 一条网络事件的前端表示 / Frontend representation of a network event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallEventRecord {
    /// 待裁决时非 0 / Non-zero while awaiting a verdict
    pub decision_id: u64,
    /// connect_request / connect_log / dns_query / domain_blocked / flow_closed / rate_limited
    pub kind: String,
    pub timestamp: u64,
    pub pid: u32,
    pub process_path: String,
    pub process_name: String,
    /// outbound / inbound
    pub direction: String,
    /// tcp / udp / other
    pub protocol: String,
    pub local_port: u32,
    pub remote_address: String,
    pub remote_port: u32,
    /// allow / block / prompt
    pub action: String,
    pub rule_id: u32,
    pub domain: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// 决策因超时被驱动兜底处理 / the driver resolved it by timeout
    pub timed_out: bool,
}

/// 待用户裁决的连接 / A connection awaiting the user's verdict
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingConnection {
    pub decision_id: u64,
    pub pid: u32,
    pub process_path: String,
    pub process_name: String,
    pub protocol: String,
    pub direction: String,
    pub remote_address: String,
    pub remote_port: u32,
    pub timestamp: u64,
    /// 本地推算的过期时刻，用于把 UI 上的过期弹窗收掉
    ///  Locally computed expiry, used to retire a stale prompt in the UI
    pub expires_at: u64,
}

/// 防火墙运行状态 / Firewall runtime status
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FirewallStatus {
    /// 服务是否已启动 / Whether the service has been started
    pub running: bool,
    /// 驱动是否已连接并完成握手 / Whether the driver is connected and handshaken
    pub driver_connected: bool,
    /// 驱动实际注册成功的能力位 / Capability bits the driver actually registered
    pub capabilities: u32,
    pub driver_version: String,
    /// silent / prompt / learn
    pub mode: String,
    pub enabled: bool,
    pub rule_count: usize,
    pub domain_rule_count: usize,
    pub limit_count: usize,
    pub pending_count: usize,
    /// 最近一次规则编译产生的告警 / Warnings from the last rule compilation
    pub rule_warnings: Vec<String>,
}

/// 裁决结果 / Outcome of a verdict submission
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictOutcome {
    /// 驱动已按裁决完成该连接 / The driver applied the verdict
    Applied,
    /// 驱动侧已因超时先行处理，用户点晚了 / The driver had already timed it out
    AlreadyResolved,
}

// ============================================================================
// 服务实现 / Service implementation
// ============================================================================

pub struct FirewallService {
    client: Arc<NetDriverClient>,
    /// 事件泵线程与服务共享同一个运行标志，stop() 置 false 后泵线程随即退出。
    ///  The pump thread shares this flag with the service; stop() sets it false
    ///  and the pump exits on its next loop.
    running: Arc<AtomicBool>,
    driver_connected: AtomicBool,
    capabilities: AtomicU32,
    rule_version: AtomicU32,
    driver_version: Mutex<Option<NetVersion>>,
    pump_thread: Mutex<Option<JoinHandle<()>>>,
    pending: Arc<Mutex<HashMap<u64, PendingConnection>>>,
    recent: Arc<Mutex<VecDeque<FirewallEventRecord>>>,
    runtime_config: Mutex<NetConfig>,
    table_counts: Mutex<(usize, usize, usize)>,
    rule_warnings: Mutex<Vec<String>>,
}

impl Default for FirewallService {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallService {
    pub fn new() -> Self {
        Self {
            client: Arc::new(NetDriverClient::new()),
            running: Arc::new(AtomicBool::new(false)),
            driver_connected: AtomicBool::new(false),
            capabilities: AtomicU32::new(0),
            rule_version: AtomicU32::new(0),
            driver_version: Mutex::new(None),
            pump_thread: Mutex::new(None),
            pending: Arc::new(Mutex::new(HashMap::new())),
            recent: Arc::new(Mutex::new(VecDeque::with_capacity(RECENT_EVENT_CAPACITY))),
            runtime_config: Mutex::new(NetConfig::default()),
            table_counts: Mutex::new((0, 0, 0)),
            rule_warnings: Mutex::new(Vec::new()),
        }
    }

    /// 函数名称：start
    /// 函数作用：连接驱动、下发配置与规则、启动事件泵。
    /// Purpose: Connects to the driver, pushes the configuration and rules, and
    ///          starts the event pump.
    ///
    /// 驱动不可用时返回 Err，但调用方应把它当作「功能降级」而不是启动失败：
    /// 防护套件的其他模块必须照常工作。
    /// Returns Err when the driver is unavailable, but callers must treat that
    /// as a degraded feature rather than a startup failure — the rest of the
    /// protection suite has to keep working.
    ///
    /// 调用方：commands/firewall.rs::start_firewall、服务进程启动流程
    /// Called by: commands/firewall.rs::start_firewall and the service startup path
    /// 副作用：打开驱动句柄并创建一个后台线程
    /// Side effects: opens a driver handle and creates a background thread
    /// 并发与幂等：重复调用会先停止已有实例再重启
    /// Concurrency and idempotency: a repeat call stops the existing instance first
    /// 中文关键词：启动防火墙，驱动握手，事件泵
    /// English keywords: firewall start, driver handshake, event pump
    pub fn start(&self, ctx: ServiceContext, config: &NetworkFirewallConfig) -> Result<(), String> {
        if self.running.load(Ordering::SeqCst) {
            self.stop();
        }

        let version = self
            .client
            .connect()
            .map_err(|e| format!("failed to connect to AnXinNetFilter driver: {}", e))?;

        self.capabilities
            .store(version.capabilities, Ordering::SeqCst);
        *self.driver_version.lock().unwrap() = Some(version);
        self.driver_connected.store(true, Ordering::SeqCst);

        // 先装规则再启用：反过来会有一个短暂窗口按默认动作处理全部连接。
        //  Rules first, enable second: the other order leaves a brief window in
        //  which every connection is handled by the default action.
        let warnings = self.apply_rules()?;
        *self.rule_warnings.lock().unwrap() = warnings;

        self.apply_config(config)?;

        self.running.store(true, Ordering::SeqCst);
        self.spawn_pump(ctx);

        Ok(())
    }

    /// 函数名称：stop
    /// 函数作用：停止事件泵并断开驱动，驱动随即恢复全放行。
    /// Purpose: Stops the pump and disconnects; the driver reverts to permitting
    ///          everything.
    /// 调用方：commands/firewall.rs::stop_firewall、应用退出
    /// Called by: commands/firewall.rs::stop_firewall and application shutdown
    /// 中文关键词：停止防火墙，断开驱动，恢复放行
    /// English keywords: firewall stop, driver disconnect, revert to permit
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);

        // 关闭句柄会让阻塞中的 wait_event 立刻返回，泵线程随之退出
        //  Closing the handle makes the blocked wait_event return at once and
        //  the pump thread exits with it
        self.client.disconnect();
        self.driver_connected.store(false, Ordering::SeqCst);

        if let Some(handle) = self.pump_thread.lock().unwrap().take() {
            let _ = handle.join();
        }

        self.pending.lock().unwrap().clear();
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn is_driver_connected(&self) -> bool {
        self.driver_connected.load(Ordering::SeqCst)
    }

    /// 函数名称：apply_config
    /// 函数作用：把应用配置翻译成驱动配置并下发。
    /// Purpose: Translates the app configuration into the driver form and pushes it.
    ///
    /// `self_pid` 填入当前进程：驱动据此对本产品自身的流量豁免，否则上报通道
    /// 有可能被自己的规则拦掉。
    /// `self_pid` carries the current process so the driver exempts our own
    /// traffic; otherwise our reporting channel could be blocked by our own rule.
    ///
    /// 调用方：start、set_mode、set_enabled
    /// Called by: start, set_mode and set_enabled
    /// 中文关键词：配置下发，自身豁免，模式切换
    /// English keywords: config push, self exemption, mode switch
    pub fn apply_config(&self, config: &NetworkFirewallConfig) -> Result<(), String> {
        let driver_config = Self::build_driver_config(config);

        self.client
            .set_config(&driver_config)
            .map_err(|e| format!("failed to push firewall config to the driver: {}", e))?;

        *self.runtime_config.lock().unwrap() = driver_config;
        Ok(())
    }

    /// 把应用层配置映射为驱动配置结构。
    ///  Maps the application configuration onto the driver's configuration struct.
    fn build_driver_config(config: &NetworkFirewallConfig) -> NetConfig {
        let mode = match config.mode.as_str() {
            "prompt" => MODE_PROMPT,
            "learn" => MODE_LEARN,
            _ => MODE_SILENT,
        };

        // 默认动作解析失败时一律回落到放行。把无法识别的配置当成拦截会直接
        // 让机器断网，这是最坏的失败方式。
        //  An unparsable default action falls back to allow. Treating an
        //  unrecognized value as block would cut the machine off the network —
        //  the worst possible failure mode.
        let parse_default = |value: &str| match value {
            "block" => ACTION_BLOCK,
            "prompt" => ACTION_PROMPT,
            _ => ACTION_ALLOW,
        };

        NetConfig {
            enabled: u32::from(config.enabled),
            mode,
            default_outbound: parse_default(&config.default_outbound),
            default_inbound: parse_default(&config.default_inbound),
            prompt_timeout_ms: config.prompt_timeout_ms,
            timeout_action: parse_default(&config.timeout_action),
            enable_dns: u32::from(config.dns_filtering),
            enable_stream_inspect: u32::from(config.content_inspection),
            enable_rate_limit: u32::from(config.rate_limiting),
            enable_stats: u32::from(config.traffic_stats),
            allow_loopback: u32::from(config.allow_loopback),
            self_pid: std::process::id(),
            cache_ttl_ms: config.cache_ttl_ms,
            reserved: [0; 3],
        }
    }

    /// 函数名称：apply_rules
    /// 函数作用：从 config/firewall_rules.json 重新加载并整表下发三张规则表。
    /// Purpose: Reloads config/firewall_rules.json and pushes all three tables.
    /// 返回值：编译过程中的告警列表（被跳过的规则、被截断的表）
    /// Returns: warnings from compilation (skipped rules, truncated tables)
    /// 调用方：start、commands/firewall.rs::reload_firewall_rules
    /// Called by: start and commands/firewall.rs::reload_firewall_rules
    /// 中文关键词：规则重载，整表下发，编译告警
    /// English keywords: rule reload, whole-table push, compile warnings
    pub fn apply_rules(&self) -> Result<Vec<String>, String> {
        let rule_set = FirewallRuleSet::load()?;
        let compiled = rule_set.compile();

        let version = self.rule_version.fetch_add(1, Ordering::SeqCst) + 1;

        self.client
            .set_rules(version, &compiled.rules)
            .map_err(|e| format!("failed to push connection rules: {}", e))?;
        self.client
            .set_domains(version, &compiled.domains)
            .map_err(|e| format!("failed to push domain rules: {}", e))?;
        self.client
            .set_limits(version, &compiled.limits)
            .map_err(|e| format!("failed to push rate limits: {}", e))?;

        *self.table_counts.lock().unwrap() = (
            compiled.rules.len(),
            compiled.domains.len(),
            compiled.limits.len(),
        );
        *self.rule_warnings.lock().unwrap() = compiled.warnings.clone();

        Ok(compiled.warnings)
    }

    /// 函数名称：decide
    /// 函数作用：把用户的允许/阻止决策回送驱动，完成那条被挂起的连接。
    /// Purpose: Sends the user's allow/block decision back to complete the
    ///          pended connection.
    ///
    /// `remember` 为真时同时写入内核裁决缓存，之后同一进程访问同一目标不再询问。
    /// `remember_process` 进一步把范围扩大到该进程的全部目标。
    /// With `remember` the verdict also enters the kernel cache so the same
    /// process reaching the same destination is not asked again.
    /// `remember_process` widens that to every destination of the process.
    ///
    /// 驱动返回「找不到该决策」说明超时扫描已经先行处理，这不是错误。
    /// "Decision not found" means the timeout sweep got there first; not an error.
    ///
    /// 调用方：commands/firewall.rs::handle_network_decision
    /// Called by: commands/firewall.rs::handle_network_decision
    /// 中文关键词：用户裁决，记住选择，超时竞态
    /// English keywords: user verdict, remember choice, timeout race
    pub fn decide(
        &self,
        decision_id: u64,
        allow: bool,
        remember: bool,
        remember_process: bool,
    ) -> Result<VerdictOutcome, String> {
        let mut flags = 0u32;
        if remember {
            flags |= VF_REMEMBER;
        }
        if remember_process {
            flags |= VF_REMEMBER | VF_REMEMBER_PROCESS;
        }

        let verdict = NetVerdict {
            decision_id,
            action: if allow { ACTION_ALLOW } else { ACTION_BLOCK },
            flags,
            cache_ttl_ms: 0,
            reserved: [0; 3],
        };

        let result = self.client.set_verdict(&verdict);

        // 无论驱动怎么回，这条待决记录在界面上都应该消失
        //  Whatever the driver answers, the prompt must disappear from the UI
        self.pending.lock().unwrap().remove(&decision_id);

        match result {
            Ok(()) => Ok(VerdictOutcome::Applied),
            Err(e) if Self::is_decision_gone(&e) => Ok(VerdictOutcome::AlreadyResolved),
            Err(e) => Err(format!("failed to submit verdict {}: {}", decision_id, e)),
        }
    }

    /// 驱动的 STATUS_NOT_FOUND 会被 I/O 管理器映射成 ERROR_NOT_FOUND(1168)。
    ///  The driver's STATUS_NOT_FOUND surfaces as ERROR_NOT_FOUND (1168).
    fn is_decision_gone(err: &std::io::Error) -> bool {
        const ERROR_NOT_FOUND: i32 = 1168;
        err.raw_os_error() == Some(ERROR_NOT_FOUND)
    }

    /// 清空内核裁决缓存，让所有连接重新走一遍规则与询问。
    ///  Flushes the kernel verdict cache so every connection is re-evaluated.
    pub fn flush_cache(&self) -> Result<(), String> {
        self.client
            .flush_cache(FLUSH_ALL, 0, 0)
            .map_err(|e| format!("failed to flush the verdict cache: {}", e))
    }

    /// 读取当前待裁决队列，顺带清掉已经过期的条目。
    ///  Reads the pending queue, dropping entries that have already expired.
    pub fn pending_connections(&self) -> Vec<PendingConnection> {
        let now = Self::now_ms();
        let mut guard = self.pending.lock().unwrap();
        guard.retain(|_, entry| entry.expires_at > now);

        let mut list: Vec<PendingConnection> = guard.values().cloned().collect();
        list.sort_by_key(|entry| entry.timestamp);
        list
    }

    /// 读取最近事件，按时间倒序返回最多 `limit` 条。
    ///  Reads recent events, newest first, capped at `limit`.
    pub fn recent_events(&self, limit: usize) -> Vec<FirewallEventRecord> {
        let guard = self.recent.lock().unwrap();
        guard.iter().rev().take(limit).cloned().collect()
    }

    /// 汇总当前状态供概览页与设置页展示。
    ///  Summarizes the current state for the overview and settings pages.
    pub fn status(&self) -> FirewallStatus {
        let config = *self.runtime_config.lock().unwrap();
        let (rule_count, domain_rule_count, limit_count) = *self.table_counts.lock().unwrap();

        let driver_version = self
            .driver_version
            .lock()
            .unwrap()
            .map(|v| format!("{}.{}.{}", v.driver_major, v.driver_minor, v.driver_patch))
            .unwrap_or_default();

        FirewallStatus {
            running: self.is_running(),
            driver_connected: self.is_driver_connected(),
            capabilities: self.capabilities.load(Ordering::SeqCst),
            driver_version,
            mode: match config.mode {
                MODE_PROMPT => "prompt".to_string(),
                MODE_LEARN => "learn".to_string(),
                _ => "silent".to_string(),
            },
            enabled: config.enabled != 0,
            rule_count,
            domain_rule_count,
            limit_count,
            pending_count: self.pending.lock().unwrap().len(),
            rule_warnings: self.rule_warnings.lock().unwrap().clone(),
        }
    }

    /// 读取驱动侧的进程流量统计。
    ///  Reads per-process traffic statistics from the driver.
    pub fn traffic_stats(&self) -> Result<serde_json::Value, String> {
        let snapshot = self
            .client
            .get_stats()
            .map_err(|e| format!("failed to read traffic statistics: {}", e))?;

        let processes: Vec<serde_json::Value> = snapshot
            .processes
            .iter()
            .map(|p| {
                serde_json::json!({
                    "pid": p.process_id,
                    "activeFlows": p.active_flows,
                    "bytesIn": p.bytes_in,
                    "bytesOut": p.bytes_out,
                    "connAllowed": p.conn_allowed,
                    "connBlocked": p.conn_blocked,
                    "lastActivity": p.last_activity_ms,
                })
            })
            .collect();

        Ok(serde_json::json!({
            "totalProcesses": snapshot.total_processes,
            "eventsQueued": snapshot.events_queued,
            "eventsDropped": snapshot.events_dropped,
            "pendingCount": snapshot.pending_count,
            "pendingTimedOut": snapshot.pending_timed_out,
            "cacheHits": snapshot.cache_hits,
            "cacheMisses": snapshot.cache_misses,
            "processes": processes,
        }))
    }

    // ------------------------------------------------------------------
    // 事件泵 / Event pump
    // ------------------------------------------------------------------

    /// 函数名称：spawn_pump
    /// 函数作用：启动阻塞式事件泵线程。
    /// Purpose: Starts the blocking event-pump thread.
    ///
    /// 泵线程持续阻塞在驱动的倒置调用上。停止方式是关闭句柄（见 stop），
    /// 内核会以 STATUS_CANCELLED 完成挂起的 IRP，wait_event 随即返回错误，
    /// 循环检查到 running 已经为假就退出。
    /// The thread blocks in the driver's inverted call. Stopping happens by
    /// closing the handle (see stop): the kernel completes the pended IRP with
    /// STATUS_CANCELLED, wait_event returns an error, and the loop observes that
    /// running is false and exits.
    ///
    /// 中文关键词：事件泵，阻塞等待，优雅停止
    /// English keywords: event pump, blocking wait, graceful stop
    fn spawn_pump(&self, ctx: ServiceContext) {
        let client = Arc::clone(&self.client);
        let pending = Arc::clone(&self.pending);
        let recent = Arc::clone(&self.recent);
        let running = Arc::clone(&self.running);
        let prompt_timeout_ms = self.runtime_config.lock().unwrap().prompt_timeout_ms;

        let handle = std::thread::Builder::new()
            .name("anxin-firewall-pump".to_string())
            .spawn(move || {
                while running.load(Ordering::SeqCst) {
                    match client.wait_event() {
                        Ok(event) => {
                            Self::handle_event(&ctx, &pending, &recent, &event, prompt_timeout_ms);
                        }
                        Err(err) => {
                            // stop() 的顺序是「置 running=false → disconnect → join」，
                            // 所以走到这里时 running 通常已经是 false，直接退出。
                            //  stop() runs "running=false, disconnect, join", so by
                            //  the time we land here running is normally already
                            //  false and we simply exit.
                            if !running.load(Ordering::SeqCst) {
                                break;
                            }
                            // 句柄已经没了就没有重试的意义
                            //  A gone handle makes retrying pointless
                            if err.kind() == std::io::ErrorKind::NotConnected {
                                break;
                            }
                            eprintln!("[Firewall] event pump error: {}", err);
                            std::thread::sleep(std::time::Duration::from_millis(
                                PUMP_RETRY_INTERVAL_MS,
                            ));
                        }
                    }
                }
            })
            .ok();

        *self.pump_thread.lock().unwrap() = handle;
    }

    /// 处理一条内核事件：转成前端记录、维护待决队列、推送前端事件。
    ///  Handles one kernel event: builds the frontend record, maintains the
    ///  pending queue and pushes the frontend events.
    fn handle_event(
        ctx: &ServiceContext,
        pending: &Arc<Mutex<HashMap<u64, PendingConnection>>>,
        recent: &Arc<Mutex<VecDeque<FirewallEventRecord>>>,
        event: &NetEvent,
        prompt_timeout_ms: u32,
    ) {
        let record = Self::build_record(event);

        // 环形缓冲：超出容量丢弃最旧的一条
        //  Ring buffer: drop the oldest beyond capacity
        {
            let mut guard = recent.lock().unwrap();
            if guard.len() >= RECENT_EVENT_CAPACITY {
                guard.pop_front();
            }
            guard.push_back(record.clone());
        }

        if event.requires_verdict() {
            let entry = PendingConnection {
                decision_id: event.decision_id,
                pid: event.process_id,
                process_path: record.process_path.clone(),
                process_name: record.process_name.clone(),
                protocol: record.protocol.clone(),
                direction: record.direction.clone(),
                remote_address: record.remote_address.clone(),
                remote_port: record.remote_port,
                timestamp: record.timestamp,
                expires_at: Self::now_ms() + u64::from(prompt_timeout_ms),
            };

            pending
                .lock()
                .unwrap()
                .insert(event.decision_id, entry.clone());

            let _ = ctx.emit(EVENT_NETWORK_INTERCEPTED, entry);
        } else if event.decision_id != 0 {
            // 决策已完成（用户点击或驱动超时），把它从待决队列摘掉
            //  The decision completed (user click or driver timeout); retire it
            pending.lock().unwrap().remove(&event.decision_id);
        }

        let _ = ctx.emit(EVENT_NETWORK, record);
    }

    /// 把内核事件结构翻译成前端可读的记录。
    ///  Translates the kernel event structure into a frontend-readable record.
    fn build_record(event: &NetEvent) -> FirewallEventRecord {
        let process_path = event.image_path_string();
        let process_name = process_path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or("")
            .to_string();

        FirewallEventRecord {
            decision_id: event.decision_id,
            kind: Self::kind_name(event.kind),
            timestamp: event.timestamp_ms,
            pid: event.process_id,
            process_path,
            process_name,
            direction: if event.direction == DIR_INBOUND {
                "inbound".to_string()
            } else {
                "outbound".to_string()
            },
            protocol: match event.protocol {
                PROTO_TCP => "tcp".to_string(),
                PROTO_UDP => "udp".to_string(),
                other => format!("proto{}", other),
            },
            local_port: event.local_port,
            remote_address: event.remote_address.to_display_string(),
            remote_port: event.remote_port,
            action: match event.action {
                ACTION_BLOCK => "block".to_string(),
                ACTION_PROMPT => "prompt".to_string(),
                _ => "allow".to_string(),
            },
            rule_id: event.rule_id,
            domain: event.domain_string(),
            bytes_in: event.bytes_in,
            bytes_out: event.bytes_out,
            timed_out: (event.flags & EVTF_TIMED_OUT) != 0,
        }
    }

    fn kind_name(kind: u32) -> String {
        match kind {
            EVT_CONNECT_REQUEST => "connect_request".to_string(),
            EVT_DNS_QUERY => "dns_query".to_string(),
            EVT_DOMAIN_BLOCKED => "domain_blocked".to_string(),
            EVT_FLOW_CLOSED => "flow_closed".to_string(),
            EVT_RATE_LIMITED => "rate_limited".to_string(),
            EVT_CONNECT_LOG => "connect_log".to_string(),
            // 驱动侧会生成但 Rust 尚未建模的事件类型：如实标注，不落到默认归类。
            //  Event kinds the driver can emit that Rust does not model yet: label
            //  them truthfully instead of collapsing into a default category.
            other => format!("unknown_event_{other}"),
        }
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::net_driver_client::NetAddr;

    fn test_config() -> NetworkFirewallConfig {
        NetworkFirewallConfig {
            enabled: true,
            mode: "prompt".to_string(),
            default_outbound: "prompt".to_string(),
            default_inbound: "block".to_string(),
            prompt_timeout_ms: 15_000,
            timeout_action: "allow".to_string(),
            dns_filtering: true,
            content_inspection: true,
            rate_limiting: false,
            traffic_stats: true,
            allow_loopback: true,
            cache_ttl_ms: 60_000,
        }
    }

    #[test]
    fn config_maps_onto_driver_struct() {
        let driver = FirewallService::build_driver_config(&test_config());

        assert_eq!(driver.enabled, 1);
        assert_eq!(driver.mode, MODE_PROMPT);
        assert_eq!(driver.default_outbound, ACTION_PROMPT);
        assert_eq!(driver.default_inbound, ACTION_BLOCK);
        assert_eq!(driver.timeout_action, ACTION_ALLOW);
        assert_eq!(driver.prompt_timeout_ms, 15_000);
        assert_eq!(driver.enable_dns, 1);
        assert_eq!(driver.enable_rate_limit, 0);
        assert_eq!(driver.allow_loopback, 1);
        assert_eq!(driver.self_pid, std::process::id());
    }

    /// 无法识别的默认动作必须回落到放行。把它当成拦截会让整台机器断网，
    /// 这是最坏的失败方式。
    ///  An unrecognized default action must fall back to allow; treating it as
    ///  block would cut the machine off the network — the worst failure mode.
    #[test]
    fn unknown_default_action_falls_back_to_allow() {
        let mut config = test_config();
        config.default_outbound = "explode".to_string();
        config.default_inbound = String::new();
        config.timeout_action = "nonsense".to_string();

        let driver = FirewallService::build_driver_config(&config);
        assert_eq!(driver.default_outbound, ACTION_ALLOW);
        assert_eq!(driver.default_inbound, ACTION_ALLOW);
        assert_eq!(driver.timeout_action, ACTION_ALLOW);
    }

    #[test]
    fn unknown_mode_falls_back_to_silent() {
        let mut config = test_config();
        config.mode = "telepathy".to_string();
        assert_eq!(
            FirewallService::build_driver_config(&config).mode,
            MODE_SILENT
        );
    }

    #[test]
    fn record_extracts_process_name_and_endpoint() {
        let mut event = NetEvent::default();
        event.kind = EVT_CONNECT_LOG;
        event.process_id = 4242;
        event.protocol = PROTO_TCP;
        event.remote_port = 443;
        event.action = ACTION_BLOCK;
        event.remote_address = NetAddr::from_ipv4([93, 184, 216, 34]);

        let path: Vec<u16> = r"\device\harddiskvolume3\program files\app\thing.exe"
            .encode_utf16()
            .collect();
        event.image_path[..path.len()].copy_from_slice(&path);

        let record = FirewallService::build_record(&event);

        assert_eq!(record.pid, 4242);
        assert_eq!(record.process_name, "thing.exe");
        assert_eq!(record.remote_address, "93.184.216.34");
        assert_eq!(record.remote_port, 443);
        assert_eq!(record.protocol, "tcp");
        assert_eq!(record.action, "block");
        assert_eq!(record.kind, "connect_log");
        assert!(!record.timed_out);
    }

    #[test]
    fn record_flags_timeout_resolved_decisions() {
        let mut event = NetEvent::default();
        event.flags |= EVTF_TIMED_OUT;
        assert!(FirewallService::build_record(&event).timed_out);
    }

    #[test]
    fn kind_names_cover_every_event_kind() {
        assert_eq!(
            FirewallService::kind_name(EVT_CONNECT_REQUEST),
            "connect_request"
        );
        assert_eq!(FirewallService::kind_name(EVT_DNS_QUERY), "dns_query");
        assert_eq!(
            FirewallService::kind_name(EVT_DOMAIN_BLOCKED),
            "domain_blocked"
        );
        assert_eq!(FirewallService::kind_name(EVT_FLOW_CLOSED), "flow_closed");
        assert_eq!(FirewallService::kind_name(EVT_RATE_LIMITED), "rate_limited");
        assert_eq!(FirewallService::kind_name(EVT_CONNECT_LOG), "connect_log");
    }

    /// 未连接驱动时的所有操作都必须返回错误而不是 panic。
    ///  Every operation must return an error rather than panic when the driver
    ///  is not connected.
    #[test]
    fn operations_fail_cleanly_without_a_driver() {
        let service = FirewallService::new();

        assert!(!service.is_running());
        assert!(!service.is_driver_connected());
        assert!(service.apply_config(&test_config()).is_err());
        assert!(service.flush_cache().is_err());
        assert!(service.traffic_stats().is_err());
        assert!(service.decide(1, true, false, false).is_err());

        let status = service.status();
        assert!(!status.running);
        assert!(!status.driver_connected);
        assert_eq!(status.pending_count, 0);
    }

    /// 过期的待决条目在读取时必须被清掉，否则界面会一直挂着一个点不掉的弹窗。
    ///  Expired pending entries must be pruned on read, otherwise the UI keeps
    ///  showing a prompt that can never be dismissed.
    #[test]
    fn expired_pending_entries_are_pruned() {
        let service = FirewallService::new();

        let now = FirewallService::now_ms();
        let mut guard = service.pending.lock().unwrap();
        guard.insert(
            1,
            PendingConnection {
                decision_id: 1,
                pid: 1,
                process_path: String::new(),
                process_name: String::new(),
                protocol: "tcp".to_string(),
                direction: "outbound".to_string(),
                remote_address: "1.1.1.1".to_string(),
                remote_port: 80,
                timestamp: now,
                expires_at: now.saturating_sub(1),
            },
        );
        guard.insert(
            2,
            PendingConnection {
                decision_id: 2,
                pid: 2,
                process_path: String::new(),
                process_name: String::new(),
                protocol: "tcp".to_string(),
                direction: "outbound".to_string(),
                remote_address: "2.2.2.2".to_string(),
                remote_port: 80,
                timestamp: now,
                expires_at: now + 60_000,
            },
        );
        drop(guard);

        let list = service.pending_connections();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].decision_id, 2);
    }

    #[test]
    fn recent_events_are_returned_newest_first_and_capped() {
        let service = FirewallService::new();

        {
            let mut guard = service.recent.lock().unwrap();
            for i in 0..5u64 {
                let mut event = NetEvent::default();
                event.timestamp_ms = i;
                guard.push_back(FirewallService::build_record(&event));
            }
        }

        let events = service.recent_events(3);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].timestamp, 4);
        assert_eq!(events[2].timestamp, 2);
    }

    #[test]
    fn ring_buffer_drops_oldest_beyond_capacity() {
        let service = FirewallService::new();

        {
            let mut guard = service.recent.lock().unwrap();
            for i in 0..(RECENT_EVENT_CAPACITY + 10) as u64 {
                if guard.len() >= RECENT_EVENT_CAPACITY {
                    guard.pop_front();
                }
                let mut event = NetEvent::default();
                event.timestamp_ms = i;
                guard.push_back(FirewallService::build_record(&event));
            }
        }

        let guard = service.recent.lock().unwrap();
        assert_eq!(guard.len(), RECENT_EVENT_CAPACITY);
        assert_eq!(guard.front().unwrap().timestamp, 10);
    }
}
