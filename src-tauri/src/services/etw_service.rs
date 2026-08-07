/// ETW 监控服务 — 控制 ETW 会话生命周期，轮询事件，并把高频采集与高价值响应分开处理
/// ETW monitoring service — controls ETW session lifecycle, polls events, and separates high-volume capture from high-value response.
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

use super::etw::session::{
    EtwSession, DEFAULT_FILE_ANY_KEYWORD, DEFAULT_NETWORK_ANY_KEYWORD, DEFAULT_PROCESS_ANY_KEYWORD,
    DEFAULT_REGISTRY_ANY_KEYWORD,
};
use crate::services::behavior_service::BehaviorService;
use crate::services::interception_diagnostics_service::append_interception_diagnostic;
use crate::services::interception_service::{InterceptionEntry, InterceptionService};
use crate::services::process_control_service::is_windows_control_chain_process;
use crate::services::process_scanner_service::{
    enumerate_process_module_info, file_name_from_path, ProcessScannerService,
};
use crate::services::service_context::ServiceContext;
use crate::services::trust_service::TrustService;

const ETW_DIAGNOSTIC_RECENT_CACHE_LIMIT: usize = 4096;
const ETW_DIAGNOSTIC_BUCKET_LIMIT: usize = 16_384;
const ETW_DIAGNOSTIC_TEXT_PREVIEW_LIMIT: usize = 4096;
const ETW_POLL_LOG_INTERVAL_SECS: u64 = 10;
const ETW_IMAGE_LOAD_SKIP_LOG_INTERVAL_SECS: u64 = 10;
const ETW_BEHAVIOR_DB_DEDUP_INTERVAL_SECS: u64 = 10;
const ETW_BEHAVIOR_DB_DEDUP_KEY_LIMIT: usize = 4096;
const ETW_RESPONSE_DEDUP_INTERVAL_SECS: u64 = 2;
const ETW_RESPONSE_DEDUP_KEY_LIMIT: usize = 4096;

static ETW_IMAGE_LOAD_SKIP_LOG_STATE: OnceLock<Mutex<EtwImageLoadSkipLogState>> = OnceLock::new();

/// ETW 诊断缓存中的单条事件摘要。
/// 这个结构只用于现场取证：它记录“我们实际看见了什么”，不参与拦截判定。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EtwDiagnosticEvent {
    pub timestamp: String,
    pub stage: String,
    pub provider: Option<String>,
    pub operation: Option<String>,
    pub pid: Option<u64>,
    pub tid: Option<u64>,
    pub event_id: Option<u64>,
    pub opcode: Option<u64>,
    pub process_name: Option<String>,
    pub path: Option<String>,
    pub raw_user_data_length: Option<u64>,
    pub raw_user_data_preview: Option<String>,
    pub rule_id: Option<String>,
    pub threat_type: Option<String>,
    pub matched: bool,
    pub dropped: bool,
    pub drop_reason: Option<String>,
    pub parse_error: Option<String>,
    pub raw_text_preview: Option<String>,
    pub value: Option<serde_json::Value>,
}

/// ETW 诊断聚合桶。
/// 高频刷屏时，最近事件队列会很快被顶掉；聚合桶用于保留“同类事件出现了多少次”和一个代表样本。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EtwDiagnosticBucket {
    pub key: String,
    pub stage: String,
    pub first_seen: String,
    pub last_seen: String,
    pub count: u64,
    pub provider: Option<String>,
    pub operation: Option<String>,
    pub pid: Option<u64>,
    pub event_id: Option<u64>,
    pub opcode: Option<u64>,
    pub process_name: Option<String>,
    pub path_key: Option<String>,
    pub raw_user_data_length: Option<u64>,
    pub rule_id: Option<String>,
    pub threat_type: Option<String>,
    pub matched: bool,
    pub dropped: bool,
    pub drop_reason: Option<String>,
    pub parse_error: Option<String>,
    pub sample: EtwDiagnosticEvent,
}

/// ETW 诊断缓存快照。
/// 前端或管理员现场可以通过 Tauri command 导出它，用来判断 ETW 是否真的收到 Thread/Image/Process 等事件。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EtwDiagnosticsSnapshot {
    pub started_at: String,
    pub snapshot_at: String,
    pub running: bool,
    pub collecting: bool,
    pub capacity: usize,
    pub aggregate_capacity: usize,
    pub aggregate_evictions: u64,
    pub total_polled: u64,
    pub total_raw: u64,
    pub total_parse_errors: u64,
    pub total_dropped_system_pid: u64,
    pub total_after_filter: u64,
    pub total_normalized: u64,
    pub total_matched: u64,
    pub poll_batches: u64,
    pub last_poll_event_count: usize,
    pub provider_counts: BTreeMap<String, u64>,
    pub operation_counts: BTreeMap<String, u64>,
    pub provider_operation_counts: BTreeMap<String, u64>,
    pub rule_counts: BTreeMap<String, u64>,
    pub threat_counts: BTreeMap<String, u64>,
    pub drop_counts: BTreeMap<String, u64>,
    pub recent_raw: Vec<EtwDiagnosticEvent>,
    pub recent_normalized: Vec<EtwDiagnosticEvent>,
    pub aggregate_buckets: Vec<EtwDiagnosticBucket>,
}

#[derive(Debug, Clone)]
struct EtwDiagnosticsCache {
    started_at: String,
    capacity: usize,
    aggregate_capacity: usize,
    aggregate_evictions: u64,
    total_polled: u64,
    total_raw: u64,
    total_parse_errors: u64,
    total_dropped_system_pid: u64,
    total_after_filter: u64,
    total_normalized: u64,
    total_matched: u64,
    poll_batches: u64,
    last_poll_event_count: usize,
    provider_counts: BTreeMap<String, u64>,
    operation_counts: BTreeMap<String, u64>,
    provider_operation_counts: BTreeMap<String, u64>,
    rule_counts: BTreeMap<String, u64>,
    threat_counts: BTreeMap<String, u64>,
    drop_counts: BTreeMap<String, u64>,
    recent_raw: VecDeque<EtwDiagnosticEvent>,
    recent_normalized: VecDeque<EtwDiagnosticEvent>,
    aggregate_buckets: BTreeMap<String, EtwDiagnosticBucket>,
    aggregate_order: VecDeque<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EtwPollLogSummary {
    polls: u64,
    events: u64,
    non_empty_batches: u64,
    max_batch: usize,
}

#[derive(Debug)]
struct EtwPollLogAccumulator {
    interval: Duration,
    last_log: Instant,
    polls: u64,
    events: u64,
    non_empty_batches: u64,
    max_batch: usize,
}

impl EtwPollLogAccumulator {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_log: Instant::now(),
            polls: 0,
            events: 0,
            non_empty_batches: 0,
            max_batch: 0,
        }
    }

    #[cfg(test)]
    fn new_with_last_log(interval: Duration, last_log: Instant) -> Self {
        Self {
            interval,
            last_log,
            polls: 0,
            events: 0,
            non_empty_batches: 0,
            max_batch: 0,
        }
    }

    fn record(&mut self, event_count: usize, now: Instant) -> Option<EtwPollLogSummary> {
        self.polls = self.polls.saturating_add(1);
        self.events = self.events.saturating_add(event_count as u64);
        if event_count > 0 {
            self.non_empty_batches = self.non_empty_batches.saturating_add(1);
            self.max_batch = self.max_batch.max(event_count);
        }

        if self.events == 0
            || now
                .checked_duration_since(self.last_log)
                .unwrap_or_default()
                < self.interval
        {
            return None;
        }

        let summary = EtwPollLogSummary {
            polls: self.polls,
            events: self.events,
            non_empty_batches: self.non_empty_batches,
            max_batch: self.max_batch,
        };
        self.last_log = now;
        self.polls = 0;
        self.events = 0;
        self.non_empty_batches = 0;
        self.max_batch = 0;
        Some(summary)
    }
}

#[derive(Debug, Default)]
struct EtwImageLoadSkipLogState {
    last_logged_by_key: BTreeMap<String, Instant>,
    suppressed_by_key: BTreeMap<String, u64>,
}

#[derive(Debug)]
struct EtwBehaviorDbGate {
    interval: Duration,
    last_recorded_by_key: BTreeMap<String, Instant>,
}

impl EtwBehaviorDbGate {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_recorded_by_key: BTreeMap::new(),
        }
    }

    fn should_record(&mut self, event: &serde_json::Value, now: Instant) -> bool {
        let key = etw_behavior_db_dedup_key(event);
        let is_recent_duplicate = self
            .last_recorded_by_key
            .get(&key)
            .map(|last_recorded| {
                now.checked_duration_since(*last_recorded)
                    .unwrap_or_default()
                    < self.interval
            })
            .unwrap_or(false);

        if is_recent_duplicate {
            return false;
        }

        self.last_recorded_by_key.insert(key, now);
        self.prune(now);
        true
    }

    fn prune(&mut self, now: Instant) {
        if self.last_recorded_by_key.len() <= ETW_BEHAVIOR_DB_DEDUP_KEY_LIMIT {
            return;
        }

        let retention = self.interval.checked_mul(6).unwrap_or(self.interval);
        self.last_recorded_by_key.retain(|_, last_recorded| {
            now.checked_duration_since(*last_recorded)
                .unwrap_or_default()
                <= retention
        });

        while self.last_recorded_by_key.len() > ETW_BEHAVIOR_DB_DEDUP_KEY_LIMIT {
            let Some(oldest_key) = self.last_recorded_by_key.keys().next().cloned() else {
                break;
            };
            self.last_recorded_by_key.remove(&oldest_key);
        }
    }
}

#[derive(Debug)]
struct EtwResponseGate {
    interval: Duration,
    last_forwarded_by_key: BTreeMap<String, Instant>,
}

impl EtwResponseGate {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_forwarded_by_key: BTreeMap::new(),
        }
    }

    fn should_forward(&mut self, event: &serde_json::Value, now: Instant) -> bool {
        if !is_high_value_realtime_etw_event(event) {
            return false;
        }

        let key = etw_response_dedup_key(event);
        let is_recent_duplicate = self
            .last_forwarded_by_key
            .get(&key)
            .map(|last_forwarded| {
                now.checked_duration_since(*last_forwarded)
                    .unwrap_or_default()
                    < self.interval
            })
            .unwrap_or(false);

        if is_recent_duplicate {
            return false;
        }

        self.last_forwarded_by_key.insert(key, now);
        self.prune(now);
        true
    }

    fn prune(&mut self, now: Instant) {
        if self.last_forwarded_by_key.len() <= ETW_RESPONSE_DEDUP_KEY_LIMIT {
            return;
        }

        let retention = self.interval.checked_mul(30).unwrap_or(self.interval);
        self.last_forwarded_by_key.retain(|_, last_forwarded| {
            now.checked_duration_since(*last_forwarded)
                .unwrap_or_default()
                <= retention
        });

        while self.last_forwarded_by_key.len() > ETW_RESPONSE_DEDUP_KEY_LIMIT {
            let Some(oldest_key) = self.last_forwarded_by_key.keys().next().cloned() else {
                break;
            };
            self.last_forwarded_by_key.remove(&oldest_key);
        }
    }
}

impl EtwDiagnosticsCache {
    fn new(capacity: usize) -> Self {
        Self::with_aggregate_capacity(capacity, ETW_DIAGNOSTIC_BUCKET_LIMIT)
    }

    fn with_aggregate_capacity(capacity: usize, aggregate_capacity: usize) -> Self {
        Self {
            started_at: chrono::Utc::now().to_rfc3339(),
            capacity,
            aggregate_capacity,
            aggregate_evictions: 0,
            total_polled: 0,
            total_raw: 0,
            total_parse_errors: 0,
            total_dropped_system_pid: 0,
            total_after_filter: 0,
            total_normalized: 0,
            total_matched: 0,
            poll_batches: 0,
            last_poll_event_count: 0,
            provider_counts: BTreeMap::new(),
            operation_counts: BTreeMap::new(),
            provider_operation_counts: BTreeMap::new(),
            rule_counts: BTreeMap::new(),
            threat_counts: BTreeMap::new(),
            drop_counts: BTreeMap::new(),
            recent_raw: VecDeque::with_capacity(capacity),
            recent_normalized: VecDeque::with_capacity(capacity),
            aggregate_buckets: BTreeMap::new(),
            aggregate_order: VecDeque::with_capacity(aggregate_capacity),
        }
    }

    fn clear(&mut self) {
        *self = Self::with_aggregate_capacity(self.capacity, self.aggregate_capacity);
    }

    fn record_poll_batch(&mut self, event_count: usize) {
        self.poll_batches = self.poll_batches.saturating_add(1);
        self.total_polled = self.total_polled.saturating_add(event_count as u64);
        self.last_poll_event_count = event_count;
    }

    fn record_parse_error(&mut self, raw_text: &str, error: &str) {
        self.total_parse_errors = self.total_parse_errors.saturating_add(1);
        let event = EtwDiagnosticEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            stage: "parse_error".to_string(),
            provider: None,
            operation: None,
            pid: None,
            tid: None,
            event_id: None,
            opcode: None,
            process_name: None,
            path: None,
            raw_user_data_length: None,
            raw_user_data_preview: None,
            rule_id: None,
            threat_type: None,
            matched: false,
            dropped: true,
            drop_reason: Some("parse_error".to_string()),
            parse_error: Some(error.to_string()),
            raw_text_preview: Some(truncate_diagnostic_text(raw_text)),
            value: None,
        };
        increment_count(&mut self.drop_counts, "parse_error");
        self.record_bucket(event.clone());
        push_bounded(&mut self.recent_raw, event, self.capacity);
    }

    fn record_raw(&mut self, value: &serde_json::Value, drop_reason: Option<&str>) {
        self.total_raw = self.total_raw.saturating_add(1);
        if drop_reason.is_some() {
            self.total_dropped_system_pid = self.total_dropped_system_pid.saturating_add(1);
        } else {
            self.total_after_filter = self.total_after_filter.saturating_add(1);
        }

        let provider = diagnostic_provider(value);
        let operation = diagnostic_operation(value);
        if let Some(provider) = provider.as_deref() {
            increment_count(&mut self.provider_counts, provider);
        }
        if let Some(operation) = operation.as_deref() {
            increment_count(&mut self.operation_counts, operation);
        }
        if let (Some(provider), Some(operation)) = (provider.as_deref(), operation.as_deref()) {
            increment_count(
                &mut self.provider_operation_counts,
                &format!("{}/{}", provider, operation),
            );
        }
        if let Some(reason) = drop_reason {
            increment_count(&mut self.drop_counts, reason);
        }

        let event = build_diagnostic_event("raw", value, drop_reason, None, None);
        self.record_bucket(event.clone());
        push_bounded(&mut self.recent_raw, event, self.capacity);
    }

    fn record_normalized(&mut self, value: &serde_json::Value) {
        self.total_normalized = self.total_normalized.saturating_add(1);
        if value
            .get("matched")
            .and_then(|matched| matched.as_bool())
            .unwrap_or(false)
            || value.get("threatType").is_some()
        {
            self.total_matched = self.total_matched.saturating_add(1);
        }

        if let Some(rule_id) = diagnostic_rule_id(value) {
            increment_count(&mut self.rule_counts, &rule_id);
        }
        if let Some(threat_type) = diagnostic_threat_type(value) {
            increment_count(&mut self.threat_counts, &threat_type);
        }

        let event = build_diagnostic_event("normalized", value, None, None, None);
        self.record_bucket(event.clone());
        push_bounded(&mut self.recent_normalized, event, self.capacity);
    }

    fn record_bucket(&mut self, event: EtwDiagnosticEvent) {
        if self.aggregate_capacity == 0 {
            return;
        }

        let key = diagnostic_bucket_key(&event);
        if let Some(bucket) = self.aggregate_buckets.get_mut(&key) {
            bucket.count = bucket.count.saturating_add(1);
            bucket.last_seen = event.timestamp.clone();
            bucket.matched |= event.matched;
            bucket.dropped |= event.dropped;
            if bucket.sample.value.is_none() && event.value.is_some() {
                bucket.sample = event;
            }
            return;
        }

        while self.aggregate_buckets.len() >= self.aggregate_capacity {
            if let Some(oldest_key) = self.aggregate_order.pop_front() {
                if self.aggregate_buckets.remove(&oldest_key).is_some() {
                    self.aggregate_evictions = self.aggregate_evictions.saturating_add(1);
                }
            } else {
                break;
            }
        }

        let bucket = EtwDiagnosticBucket {
            key: key.clone(),
            stage: event.stage.clone(),
            first_seen: event.timestamp.clone(),
            last_seen: event.timestamp.clone(),
            count: 1,
            provider: event.provider.clone(),
            operation: event.operation.clone(),
            pid: event.pid,
            event_id: event.event_id,
            opcode: event.opcode,
            process_name: event.process_name.clone(),
            path_key: event.path.as_deref().and_then(diagnostic_path_key),
            raw_user_data_length: event.raw_user_data_length,
            rule_id: event.rule_id.clone(),
            threat_type: event.threat_type.clone(),
            matched: event.matched,
            dropped: event.dropped,
            drop_reason: event.drop_reason.clone(),
            parse_error: event.parse_error.clone(),
            sample: event,
        };
        self.aggregate_order.push_back(key.clone());
        self.aggregate_buckets.insert(key, bucket);
    }

    fn snapshot(&self, running: bool, collecting: bool) -> EtwDiagnosticsSnapshot {
        let mut aggregate_buckets: Vec<EtwDiagnosticBucket> =
            self.aggregate_buckets.values().cloned().collect();
        aggregate_buckets.sort_by(|left, right| {
            right
                .count
                .cmp(&left.count)
                .then_with(|| left.key.cmp(&right.key))
        });

        EtwDiagnosticsSnapshot {
            started_at: self.started_at.clone(),
            snapshot_at: chrono::Utc::now().to_rfc3339(),
            running,
            collecting,
            capacity: self.capacity,
            aggregate_capacity: self.aggregate_capacity,
            aggregate_evictions: self.aggregate_evictions,
            total_polled: self.total_polled,
            total_raw: self.total_raw,
            total_parse_errors: self.total_parse_errors,
            total_dropped_system_pid: self.total_dropped_system_pid,
            total_after_filter: self.total_after_filter,
            total_normalized: self.total_normalized,
            total_matched: self.total_matched,
            poll_batches: self.poll_batches,
            last_poll_event_count: self.last_poll_event_count,
            provider_counts: self.provider_counts.clone(),
            operation_counts: self.operation_counts.clone(),
            provider_operation_counts: self.provider_operation_counts.clone(),
            rule_counts: self.rule_counts.clone(),
            threat_counts: self.threat_counts.clone(),
            drop_counts: self.drop_counts.clone(),
            recent_raw: self.recent_raw.iter().cloned().collect(),
            recent_normalized: self.recent_normalized.iter().cloned().collect(),
            aggregate_buckets,
        }
    }
}

pub struct EtwService {
    session: Arc<Mutex<Option<EtwSession>>>,
    tx: broadcast::Sender<String>,
    running: Arc<std::sync::atomic::AtomicBool>,
    collecting: Arc<std::sync::atomic::AtomicBool>,
    diagnostics: Arc<Mutex<EtwDiagnosticsCache>>,
}

impl EtwService {
    /// 函数名称：new
    /// 函数作用：创建 EtwService 实例。
    /// Purpose: Creates an EtwService instance.
    /// 中文关键词：创建服务，ETW初始化
    /// English keywords: create service, ETW initialization
    pub fn new() -> Arc<Mutex<Self>> {
        let (tx, _) = broadcast::channel(2000);
        Arc::new(Mutex::new(Self {
            session: Arc::new(Mutex::new(None)),
            tx,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            collecting: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            diagnostics: Arc::new(Mutex::new(EtwDiagnosticsCache::new(
                ETW_DIAGNOSTIC_RECENT_CACHE_LIMIT,
            ))),
        }))
    }

    /// 函数名称：start
    /// 函数作用：创建 ETW 会话、启用内核提供者、启动后台事件轮询和数据分发任务。
    /// Purpose: Creates ETW session, enables kernel providers, starts background event polling and data dispatch.
    /// 事件分发链路：所有有效事件进入诊断缓存；File 事件进入文件监控；高价值事件才进入日志、行为库、风险分析、拦截和前端实时推送。
    /// Event dispatch chain: all valid events enter diagnostics; File events go to file monitoring; only high-value events enter logs, behavior DB, risk analysis, interception, and realtime frontend push.
    /// 调用方：main.rs start_etw_monitoring，commands::config::set_behavior_monitoring_enabled，commands::behavior::resume_etw。
    /// Called by: main.rs start_etw_monitoring, commands::config::set_behavior_monitoring_enabled, commands::behavior::resume_etw.
    /// 被调用方：EtwSession::new，EtwSession::start，tokio::spawn。
    /// Calls: EtwSession::new, EtwSession::start, tokio::spawn.
    /// 错误处理：ETW 创建/启动错误以 Result 返回；后台任务使用 Tokio runtime，避免设置页同步命令线程缺少 Tokio 上下文时 panic。
    /// Error handling: ETW creation/start errors are returned; background tasks use the Tokio runtime to avoid panic when a settings command thread has no Tokio context.
    /// 中文关键词：启动ETW，事件监控，风险管线，拦截管线，运行时上下文
    /// English keywords: start ETW, event monitoring, risk pipeline, interception pipeline, runtime context
    pub fn start(&self, ctx: ServiceContext) -> Result<(), String> {
        if self.running.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }

        // 创建 ETW Session（内部自动清理已存在的同名 Session）
        let mut session = EtwSession::new("AnXinETWSession")?;

        // 如果 session_handle 为 0，说明 Windows 明确拒绝创建 ETW 会话，通常是缺少管理员/系统分析特权。
        // If session_handle is 0, Windows explicitly denied ETW session creation, usually due to missing administrator/system profile privilege.
        let mut collecting = false;
        if session.session_handle != 0 {
            if let Err(err) = session.start(
                0,
                DEFAULT_PROCESS_ANY_KEYWORD,
                0,
                DEFAULT_FILE_ANY_KEYWORD,
                0,
                DEFAULT_REGISTRY_ANY_KEYWORD,
                0,
                DEFAULT_NETWORK_ANY_KEYWORD,
                1,
                0,
                0,
                65536,
            ) {
                let _ = session.stop(2500);
                return Err(err);
            }
            collecting = true;
        } else {
            eprintln!("[EtwService] ETW skipped (administrator privilege unavailable)");
        }

        let tx = self.tx.clone();
        let running = self.running.clone();
        let session_arc = self.session.clone();
        let diagnostics = self.diagnostics.clone();

        *self.session.lock().map_err(|e| e.to_string())? = Some(session);
        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.collecting
            .store(collecting, std::sync::atomic::Ordering::SeqCst);

        let ctx_clone = ctx.clone();
        tokio::spawn(async move {
            let mut poll_count = 0u64;
            let mut poll_log =
                EtwPollLogAccumulator::new(Duration::from_secs(ETW_POLL_LOG_INTERVAL_SECS));
            let mut behavior_db_gate =
                EtwBehaviorDbGate::new(Duration::from_secs(ETW_BEHAVIOR_DB_DEDUP_INTERVAL_SECS));
            let mut response_gate =
                EtwResponseGate::new(Duration::from_secs(ETW_RESPONSE_DEDUP_INTERVAL_SECS));
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                let events = {
                    let guard = session_arc.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(ref sess) = *guard {
                        sess.poll_events()
                    } else {
                        break;
                    }
                };

                poll_count += 1;
                if poll_count == 1 {
                    eprintln!("[EtwService] Poll #1: {} events collected", events.len());
                } else if let Some(summary) = poll_log.record(events.len(), Instant::now()) {
                    eprintln!(
                        "[EtwService] Poll summary: {} events across {} polls in the last {}s (nonEmptyBatches={}, maxBatch={})",
                        summary.events,
                        summary.polls,
                        ETW_POLL_LOG_INTERVAL_SECS,
                        summary.non_empty_batches,
                        summary.max_batch
                    );
                }
                record_etw_poll_batch(&diagnostics, events.len());

                for json_str in events {
                    // ETW 高频事件只解析一次；PID 0/4/0xFFFFFFFF 是 Windows 系统或无效进程噪音，
                    // 在分发入口丢弃，避免继续进入诊断缓存之后的高成本链路。
                    // Parse high-volume ETW events once; drop system/invalid PIDs before fan-out.
                    let val = match serde_json::from_str::<serde_json::Value>(&json_str) {
                        Ok(value) => value,
                        Err(err) => {
                            record_etw_parse_error(&diagnostics, &json_str, &err.to_string());
                            continue;
                        }
                    };
                    if should_drop_system_etw_event(&val) {
                        record_etw_raw_event(&diagnostics, &val, Some("system_or_invalid_pid"));
                        continue;
                    }
                    record_etw_raw_event(&diagnostics, &val, None);

                    // 先标准化 JSON 格式，再追加到日志缓冲区并通知前端日志面板。
                    // Normalize JSON format first, then append to log buffer and notify frontend log panel.
                    let mut app_event = normalize_etw_app_event(&val);
                    apply_image_load_injection_detection(&ctx_clone, &mut app_event);
                    apply_remote_thread_start_detection(&mut app_event);
                    record_etw_normalized_event(&diagnostics, &app_event);
                    if should_forward_to_file_monitor(&app_event) {
                        let _ = tx.send(json_str.clone());
                    }

                    let should_forward_realtime_response =
                        response_gate.should_forward(&app_event, Instant::now());

                    if should_forward_realtime_response {
                        direct_intercept_realtime_injection_event(&ctx_clone, &app_event);
                        mark_hot_pid_for_realtime_event(&ctx_clone, &app_event);
                        // 写入日志缓冲区并推送实时 log-event。
                        // 前端 OverviewPage 通过 onLogEvent 订阅该事件做实时日志面板；
                        // 此前重构只保留了 append_log（仅入缓冲区、靠轮询才看得到），
                        // 实时推送链路断掉。append_event_log_and_emit 同时负责过滤
                        // PID 0/4/u32::MAX 这类系统噪音。
                        //  Append to the log buffer and push the realtime log-event. The frontend
                        //  OverviewPage subscribes via onLogEvent for its live log panel; the
                        //  refactor had left only append_log (buffer-only, visible solely through
                        //  polling), breaking the realtime path. append_event_log_and_emit also
                        //  filters system noise from PID 0/4/u32::MAX.
                        crate::commands::logs::append_event_log_and_emit(&ctx_clone, &app_event);

                        // 推送到前端 / Emit to frontend
                        if !ctx_clone.is_exiting() {
                            let _ = ctx_clone.emit("etw-event", app_event.clone());
                        }
                    }

                    // 风险分析只接收强信号或低频规则命中。观察型 Thread/start 异常保留在 ETW 诊断缓存，
                    // 避免每个线程事件都写行为库、跑风险分析并唤醒后置扫描。行为库只由 RiskService 写入，
                    // 且同一 PID/规则/路径短窗口内只落一条代表记录，避免 ETW 重复命中刷 SQLite。
                    // Risk analysis only receives strong signals or low-volume rule hits. Observation-only
                    // Thread/start anomalies stay in ETW diagnostics to avoid DB/risk/scanner storms. Behavior DB
                    // writes are owned by RiskService and deduplicated before passing BehaviorService to it.
                    if should_forward_realtime_response {
                        let val_risk = app_event.clone();
                        let ctx_risk = ctx_clone.clone();
                        let behavior_service =
                            if behavior_db_gate.should_record(&app_event, Instant::now()) {
                                ctx_clone
                                    .get::<Mutex<BehaviorService>>()
                                    .and_then(|state| state.lock().ok().map(|guard| guard.clone()))
                            } else {
                                None
                            };
                        tokio::spawn(async move {
                            if let (Some(risk_state), Some(trust_state)) = (
                                ctx_risk.get::<crate::services::risk_service::RiskService>(),
                                ctx_risk.get::<TrustService>(),
                            ) {
                                let risk_event = crate::services::risk_service::RiskEvent {
                                    pid: val_risk.get("pid").and_then(|v| v.as_u64()).unwrap_or(0)
                                        as u32,
                                    process_name: val_risk
                                        .get("processName")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("Unknown")
                                        .to_string(),
                                    file_path: val_risk
                                        .get("path")
                                        .or_else(|| val_risk.get("filePath"))
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string()),
                                    process_path: val_risk
                                        .get("processPath")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string()),
                                    // 规则的建议动作，决定是否允许自动挂起（见 RiskService）
                                    //  The rule's recommended action, which now gates auto-suspend
                                    recommend_action: val_risk
                                        .get("recommendAction")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string()),
                                    threat_type: val_risk
                                        .get("threatType")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown")
                                        .to_string(),
                                    threat_name: val_risk
                                        .get("threatName")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string()),
                                    severity: val_risk
                                        .get("severity")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(30)
                                        as u32,
                                    rule_id: val_risk
                                        .get("ruleId")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    description: val_risk
                                        .get("description")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("ETW rule matched")
                                        .to_string(),
                                    timestamp: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis()
                                        as u64,
                                };
                                let _ = risk_state
                                    .analyze_event(
                                        risk_event,
                                        Some(trust_state.as_ref()),
                                        behavior_service.as_ref(),
                                        &ctx_risk,
                                    )
                                    .await;
                            }
                        });
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        });

        Ok(())
    }

    /// 函数名称：pause
    /// 函数作用：暂停 ETW 监控。
    /// Purpose: Pauses ETW monitoring.
    /// Called by: commands::behavior::pause_etw
    /// 中文关键词：暂停ETW，停止监控
    /// English keywords: pause ETW, stop monitoring
    /// 函数名称：subscribe
    /// 函数作用：获取 ETW 事件广播接收器，用于订阅实时事件。
    /// Purpose: Gets an ETW event broadcast receiver for subscribing to real-time events.
    /// 调用方：file_monitor_service 等需要监听 ETW 事件的服务
    /// Called by: file_monitor_service and other services that need to listen to ETW events
    /// 中文关键词：订阅事件，ETW订阅，事件接收器
    /// English keywords: subscribe events, ETW subscribe, event receiver
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.tx.subscribe()
    }

    pub fn pause(&self) -> Result<(), String> {
        if !self.running.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }

        let mut guard = self.session.lock().map_err(|e| e.to_string())?;
        if let Some(ref mut session) = *guard {
            session.stop(2500)?;
        }
        *guard = None;
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.collecting
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// 函数名称：resume
    /// 函数作用：恢复 ETW 监控。
    /// Purpose: Resumes ETW monitoring.
    /// Called by: commands::behavior::resume_etw
    /// 中文关键词：恢复ETW，重启监控
    /// English keywords: resume ETW, restart monitoring
    pub fn resume(&self, ctx: ServiceContext) -> Result<(), String> {
        self.start(ctx)
    }

    /// 函数名称：is_running
    /// 函数作用：返回 ETW 后台轮询任务是否处于运行状态。
    /// Purpose: Returns whether the ETW background polling task is running.
    /// 调用方：commands::behavior::get_etw_status，配置开关运行态同步。
    /// Called by: commands::behavior::get_etw_status and runtime monitoring toggles.
    /// 中文关键词：ETW状态，运行状态，监控状态
    /// English keywords: ETW status, running status, monitoring status
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// 函数名称：is_collecting
    /// 函数作用：返回 ETW 是否成功启用 Windows provider 并具备真实采集能力。
    /// Purpose: Returns whether ETW successfully enabled Windows providers and can collect real events.
    /// 调用方：commands::behavior::get_etw_status。
    /// Called by: commands::behavior::get_etw_status.
    /// 中文关键词：ETW采集，管理员权限，真实采集
    /// English keywords: ETW collecting, administrator privilege, real collection
    pub fn is_collecting(&self) -> bool {
        self.collecting.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// 函数名称：diagnostics_snapshot
    /// 函数作用：读取 ETW 诊断缓存快照，用于现场确认真实收到的 provider / operation / rule。
    /// Purpose: Reads the ETW diagnostics cache snapshot for field verification of observed providers, operations, and rules.
    pub fn diagnostics_snapshot(&self) -> EtwDiagnosticsSnapshot {
        let running = self.is_running();
        let collecting = self.is_collecting();
        let guard = self
            .diagnostics
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        guard.snapshot(running, collecting)
    }

    /// 函数名称：clear_diagnostics
    /// 函数作用：清空 ETW 诊断缓存，便于用户在受控注入前重置现场样本窗口。
    /// Purpose: Clears ETW diagnostics cache so a field run can start from a clean observation window.
    pub fn clear_diagnostics(&self) {
        let mut guard = self
            .diagnostics
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        guard.clear();
    }
}

fn record_etw_poll_batch(diagnostics: &Arc<Mutex<EtwDiagnosticsCache>>, event_count: usize) {
    let mut guard = diagnostics.lock().unwrap_or_else(|err| err.into_inner());
    guard.record_poll_batch(event_count);
}

fn record_etw_parse_error(
    diagnostics: &Arc<Mutex<EtwDiagnosticsCache>>,
    raw_text: &str,
    error: &str,
) {
    let mut guard = diagnostics.lock().unwrap_or_else(|err| err.into_inner());
    guard.record_parse_error(raw_text, error);
}

fn record_etw_raw_event(
    diagnostics: &Arc<Mutex<EtwDiagnosticsCache>>,
    value: &serde_json::Value,
    drop_reason: Option<&str>,
) {
    let mut guard = diagnostics.lock().unwrap_or_else(|err| err.into_inner());
    guard.record_raw(value, drop_reason);
}

fn record_etw_normalized_event(
    diagnostics: &Arc<Mutex<EtwDiagnosticsCache>>,
    value: &serde_json::Value,
) {
    let mut guard = diagnostics.lock().unwrap_or_else(|err| err.into_inner());
    guard.record_normalized(value);
}

fn push_bounded(
    queue: &mut VecDeque<EtwDiagnosticEvent>,
    event: EtwDiagnosticEvent,
    capacity: usize,
) {
    if capacity == 0 {
        return;
    }
    while queue.len() >= capacity {
        queue.pop_front();
    }
    queue.push_back(event);
}

fn increment_count(map: &mut BTreeMap<String, u64>, key: &str) {
    let normalized = if key.trim().is_empty() {
        "Unknown"
    } else {
        key.trim()
    };
    *map.entry(normalized.to_string()).or_insert(0) += 1;
}

fn diagnostic_bucket_key(event: &EtwDiagnosticEvent) -> String {
    let path_key = event.path.as_deref().and_then(diagnostic_path_key);
    [
        format!(
            "stage={}",
            normalized_bucket_part(Some(event.stage.as_str()))
        ),
        format!(
            "provider={}",
            normalized_bucket_part(event.provider.as_deref())
        ),
        format!(
            "operation={}",
            normalized_bucket_part(event.operation.as_deref())
        ),
        format!(
            "pid={}",
            event
                .pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "None".to_string())
        ),
        format!(
            "eventId={}",
            event
                .event_id
                .map(|event_id| event_id.to_string())
                .unwrap_or_else(|| "None".to_string())
        ),
        format!(
            "opcode={}",
            event
                .opcode
                .map(|opcode| opcode.to_string())
                .unwrap_or_else(|| "None".to_string())
        ),
        format!(
            "rawLen={}",
            event
                .raw_user_data_length
                .map(|raw_len| raw_len.to_string())
                .unwrap_or_else(|| "None".to_string())
        ),
        format!("path={}", normalized_bucket_part(path_key.as_deref())),
        format!("rule={}", normalized_bucket_part(event.rule_id.as_deref())),
        format!(
            "threat={}",
            normalized_bucket_part(event.threat_type.as_deref())
        ),
        format!(
            "drop={}",
            normalized_bucket_part(event.drop_reason.as_deref())
        ),
        format!(
            "parse={}",
            normalized_bucket_part(event.parse_error.as_deref())
        ),
    ]
    .join("|")
}

fn normalized_bucket_part(value: Option<&str>) -> String {
    let trimmed = value.unwrap_or("None").trim();
    if trimmed.is_empty() {
        "None".to_string()
    } else {
        truncate_bucket_part(trimmed)
    }
}

fn diagnostic_path_key(path: &str) -> Option<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }

    let normalized = trimmed.replace('/', "\\");
    normalized
        .rsplit('\\')
        .find(|part| !part.trim().is_empty())
        .map(truncate_bucket_part)
        .or_else(|| Some(truncate_bucket_part(&normalized)))
}

fn truncate_bucket_part(value: &str) -> String {
    const LIMIT: usize = 160;
    let mut result = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index >= LIMIT {
            result.push('…');
            break;
        }
        result.push(ch);
    }
    result
}

fn build_diagnostic_event(
    stage: &str,
    value: &serde_json::Value,
    drop_reason: Option<&str>,
    parse_error: Option<&str>,
    raw_text_preview: Option<String>,
) -> EtwDiagnosticEvent {
    EtwDiagnosticEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        stage: stage.to_string(),
        provider: diagnostic_provider(value),
        operation: diagnostic_operation(value),
        pid: etw_event_pid(value),
        tid: diagnostic_tid(value),
        event_id: diagnostic_event_id(value),
        opcode: diagnostic_opcode(value),
        process_name: diagnostic_process_name(value),
        path: diagnostic_path(value),
        raw_user_data_length: diagnostic_raw_user_data_length(value),
        raw_user_data_preview: diagnostic_raw_user_data_preview(value),
        rule_id: diagnostic_rule_id(value),
        threat_type: diagnostic_threat_type(value),
        matched: value
            .get("matched")
            .and_then(|matched| matched.as_bool())
            .unwrap_or(false),
        dropped: drop_reason.is_some() || parse_error.is_some(),
        drop_reason: drop_reason.map(|reason| reason.to_string()),
        parse_error: parse_error.map(|err| err.to_string()),
        raw_text_preview,
        value: Some(value.clone()),
    }
}

fn truncate_diagnostic_text(text: &str) -> String {
    text.chars()
        .take(ETW_DIAGNOSTIC_TEXT_PREVIEW_LIMIT)
        .collect()
}

fn diagnostic_event_data(value: &serde_json::Value) -> Option<&serde_json::Value> {
    value
        .get("event")
        .and_then(|event| event.get("data"))
        .or_else(|| value.get("data"))
}

fn diagnostic_provider(value: &serde_json::Value) -> Option<String> {
    value
        .get("provider")
        .or_else(|| value.get("event").and_then(|event| event.get("provider")))
        .and_then(|provider| provider.as_str())
        .map(|provider| provider.to_string())
}

fn diagnostic_operation(value: &serde_json::Value) -> Option<String> {
    value
        .get("operation")
        .or_else(|| value.get("op"))
        .or_else(|| diagnostic_event_data(value).and_then(|data| data.get("type")))
        .or_else(|| diagnostic_event_data(value).and_then(|data| data.get("operation")))
        .and_then(|operation| operation.as_str())
        .map(|operation| operation.to_string())
}

fn diagnostic_tid(value: &serde_json::Value) -> Option<u64> {
    value
        .get("tid")
        .or_else(|| value.get("event").and_then(|event| event.get("tid")))
        .and_then(|tid| tid.as_u64())
}

fn diagnostic_event_id(value: &serde_json::Value) -> Option<u64> {
    value
        .get("eventId")
        .or_else(|| value.get("id"))
        .or_else(|| value.get("event").and_then(|event| event.get("id")))
        .and_then(|event_id| event_id.as_u64())
}

fn diagnostic_opcode(value: &serde_json::Value) -> Option<u64> {
    value
        .get("opcode")
        .or_else(|| value.get("event").and_then(|event| event.get("opcode")))
        .and_then(|opcode| opcode.as_u64())
}

fn diagnostic_raw_user_data_length(value: &serde_json::Value) -> Option<u64> {
    value
        .get("rawUserDataLength")
        .or_else(|| {
            value
                .get("event")
                .and_then(|event| event.get("rawUserDataLength"))
        })
        .and_then(|raw_len| raw_len.as_u64())
}

fn diagnostic_raw_user_data_preview(value: &serde_json::Value) -> Option<String> {
    value
        .get("rawUserDataPreview")
        .or_else(|| {
            value
                .get("event")
                .and_then(|event| event.get("rawUserDataPreview"))
        })
        .and_then(|preview| preview.as_str())
        .filter(|preview| !preview.trim().is_empty())
        .map(truncate_diagnostic_text)
}

fn diagnostic_process_name(value: &serde_json::Value) -> Option<String> {
    value
        .get("processName")
        .or_else(|| diagnostic_event_data(value).and_then(|data| data.get("processName")))
        .and_then(|process_name| process_name.as_str())
        .filter(|process_name| !process_name.trim().is_empty())
        .map(|process_name| process_name.to_string())
}

fn diagnostic_path(value: &serde_json::Value) -> Option<String> {
    value
        .get("path")
        .or_else(|| value.get("filePath"))
        .or_else(|| value.get("processPath"))
        .or_else(|| diagnostic_event_data(value).and_then(|data| data.get("fileName")))
        .or_else(|| diagnostic_event_data(value).and_then(|data| data.get("imageName")))
        .or_else(|| diagnostic_event_data(value).and_then(|data| data.get("keyName")))
        .or_else(|| diagnostic_event_data(value).and_then(|data| data.get("processName")))
        .or_else(|| diagnostic_event_data(value).and_then(|data| data.get("remoteAddress")))
        .and_then(|path| path.as_str())
        .filter(|path| !path.trim().is_empty())
        .map(|path| path.to_string())
}

fn diagnostic_rule_id(value: &serde_json::Value) -> Option<String> {
    value
        .get("ruleId")
        .and_then(|rule_id| rule_id.as_str())
        .filter(|rule_id| !rule_id.trim().is_empty())
        .map(|rule_id| rule_id.to_string())
}

fn diagnostic_threat_type(value: &serde_json::Value) -> Option<String> {
    value
        .get("threatType")
        .and_then(|threat_type| threat_type.as_str())
        .filter(|threat_type| !threat_type.trim().is_empty())
        .map(|threat_type| threat_type.to_string())
}

/// 函数名称：normalize_etw_app_event
/// 函数作用：把 Rust ETW 原始嵌套事件和规则命中事件规整为诊断缓存、文件监控和高价值响应链路共享的顶层字段。
/// Purpose: Normalizes Rust ETW nested log events and rule matches into top-level fields shared by diagnostics, file monitor, and high-value response pipelines.
/// 调用方：EtwService::start 后台事件分发循环。
/// Called by: EtwService::start background event dispatch loop.
/// 被调用方：serde_json::json。
/// Calls: serde_json::json.
/// 参数说明：value 为 EtwSession 输出的一条 JSON 事件。
/// Parameters: value is one JSON event emitted by EtwSession.
/// 返回值说明：返回保留原始字段并补齐 provider、operation、path、pid、timestamp 等顶层字段的 JSON。
/// Returns: JSON that preserves original fields and adds top-level provider, operation, path, pid, timestamp fields.
/// 错误处理：字段缺失时使用安全默认值，不抛异常。
/// Error handling: Uses safe defaults for missing fields and does not throw.
/// 中文关键词：ETW事件规整，诊断缓存，文件监控，高价值事件，事件分发
/// English keywords: ETW event normalization, diagnostics cache, file monitor, high-value event, event dispatch
pub fn normalize_etw_app_event(value: &serde_json::Value) -> serde_json::Value {
    if value.get("event").is_none() {
        let mut normalized = value.clone();
        let timestamp = normalized
            .get("timestamp")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        normalized["timestamp"] = serde_json::Value::String(timestamp);
        if normalized.get("operation").is_none() {
            if let Some(op) = normalized.get("op").and_then(|v| v.as_str()) {
                normalized["operation"] = serde_json::Value::String(op.to_string());
            }
        }
        if normalized.get("matched").is_none() && normalized.get("threatType").is_some() {
            normalized["matched"] = serde_json::Value::Bool(true);
        }
        return normalized;
    }

    let event = value.get("event").unwrap_or(value);
    let data = event.get("data").unwrap_or(&serde_json::Value::Null);
    let provider = event
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    let operation = data
        .get("type")
        .or_else(|| data.get("operation"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let path = data
        .get("fileName")
        .or_else(|| data.get("imageName"))
        .or_else(|| data.get("keyName"))
        .or_else(|| data.get("processName"))
        .or_else(|| data.get("remoteAddress"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let timestamp_ms = event
        .get("timestamp")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();

    serde_json::json!({
        "type": value.get("type").and_then(|v| v.as_str()).unwrap_or("log"),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "timestampMs": timestamp_ms,
        "pid": event.get("pid").and_then(|v| v.as_u64()).unwrap_or(0),
        "tid": event.get("tid").and_then(|v| v.as_u64()).unwrap_or(0),
        "provider": provider,
        "operation": operation,
        "path": path,
        "startAddress": data
            .get("startAddress")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        "imageBase": data
            .get("imageBase")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        "imageSize": data
            .get("imageSize")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        "processName": data
            .get("processName")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown"),
        "details": value.clone(),
    })
}

/// 函数名称：apply_image_load_injection_detection
/// 函数作用：对实时 ETW Image/load 事件做轻量注入检测补强：可信宿主进程加载未签名模块时，把普通日志升级为威胁事件。
/// Purpose: Adds lightweight injection detection to real-time ETW Image/load events: when a trusted host process loads an untrusted module, upgrade the log into a threat event.
/// 调用方：EtwService::start 后台事件分发循环。
/// Called by: EtwService::start background dispatch loop.
/// 安全边界：检测只读取目标 PID 路径和模块签名，不修改目标进程；路径缺失或验证失败时保守不升级为可信。
/// Security boundary: Read-only checks only; missing paths or verification errors are not treated as trusted.
fn apply_image_load_injection_detection(ctx: &ServiceContext, event: &mut serde_json::Value) {
    if !event_is_image_load(event) {
        return;
    }

    let raw_module_path = event
        .get("path")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if raw_module_path.is_empty() {
        return;
    }

    let Some(module_path) = etw_image_path_to_verifiable_path(&raw_module_path) else {
        log_image_load_skip(
            "module_path_not_verifiable",
            &raw_module_path,
            "module path is not verifiable",
        );
        return;
    };
    event["path"] = serde_json::Value::String(module_path.clone());

    let module_path_ref = std::path::Path::new(&module_path);
    if !module_path_ref.is_absolute() || !module_path_ref.is_file() {
        log_image_load_skip(
            "module_path_not_file",
            &module_path,
            "module path does not resolve to a file",
        );
        return;
    }

    let pid = event
        .get("pid")
        .and_then(|value| value.as_u64())
        .unwrap_or(0) as u32;
    if pid == 0 || pid == 4 || pid == u32::MAX {
        return;
    }

    let Some(trust_state) = ctx.get::<TrustService>() else {
        return;
    };
    let trust = trust_state.as_ref();

    let module_verdict = match trust.verify_file(&module_path) {
        Ok(verdict) => verdict,
        Err(err) => {
            log_image_load_skip(
                "module_signature_check_failed",
                &module_path,
                &format!("module signature check failed: {}", err),
            );
            return;
        }
    };
    if module_verdict.trusted {
        return;
    }

    let process_path = query_process_image_path_for_etw(pid).unwrap_or_default();
    if process_path.is_empty() {
        return;
    }
    let process_trusted = match trust.verify_file(&process_path) {
        Ok(verdict) => verdict.trusted,
        Err(err) => {
            log_image_load_skip(
                "host_signature_check_failed",
                &process_path,
                &format!("host signature check failed for PID {}: {}", pid, err),
            );
            return;
        }
    };
    if !process_trusted {
        return;
    }

    if let Some(process_name) = std::path::Path::new(&process_path)
        .file_name()
        .and_then(|value| value.to_str())
    {
        event["processName"] = serde_json::Value::String(process_name.to_string());
    }
    event["matched"] = serde_json::Value::Bool(true);
    event["ruleId"] = serde_json::Value::String("trusted_process_unsigned_image_load".to_string());
    event["threatType"] = serde_json::Value::String("可信进程加载未签名模块".to_string());
    event["severity"] = serde_json::Value::Number(serde_json::Number::from(70));
    // 这条合成规则是全链路唯一的强证据：模块未签名 + 宿主已签名可信，两段验签都过了才会到这里。
    // 自动挂起改由 recommendAction 显式驱动后，这里必须写 block，否则唯一有效的自动拦截会被关掉。
    // RiskService 侧同时把本 ruleId 排除在签名豁免之外——宿主可信正是本规则的前提。
    //  This synthetic rule is the only strong evidence in the whole pipeline: an unsigned module
    //  inside a signed, trusted host, reached only after both verification stages pass. Now that
    //  auto-suspend is driven explicitly by recommendAction, this must be "block" or the only
    //  effective automatic interception is switched off. RiskService correspondingly excludes this
    //  ruleId from the signature exemption, since host trust is the rule's premise.
    event["recommendAction"] = serde_json::Value::String("block".to_string());
    event["description"] = serde_json::Value::String(
        "可信宿主进程加载了未签名镜像模块，可能是远程线程 DLL 注入、插件注入或旁加载行为。"
            .to_string(),
    );
    event["filePath"] = serde_json::Value::String(module_path);
    event["processPath"] = serde_json::Value::String(process_path);
}

/// 函数名称：etw_image_path_to_verifiable_path
/// 函数作用：把 ETW Image/load 里的镜像路径转换成 WinVerifyTrust 能打开的普通文件路径。
/// Function name: etw_image_path_to_verifiable_path
/// Purpose: Converts ETW Image/load paths into ordinary file paths that WinVerifyTrust can open.
/// 安全边界：转换失败时返回 None，调用方不能把“不可验证”当成“未签名”。
/// Security boundary: conversion failure returns None; callers must not treat "unverifiable" as unsigned.
fn etw_image_path_to_verifiable_path(path: &str) -> Option<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }

    let normalized_prefix = strip_windows_namespace_prefix(trimmed);
    let normalized_prefix = trim_etw_path_noise_before_device_prefix(normalized_prefix);
    if normalized_prefix.starts_with("\\Device\\") {
        return device_path_to_dos_path(normalized_prefix);
    }

    Some(normalized_prefix.to_string())
}

fn trim_etw_path_noise_before_device_prefix(path: &str) -> &str {
    if path.starts_with("\\Device\\") {
        return path;
    }
    path.find("\\Device\\")
        .map(|index| &path[index..])
        .unwrap_or(path)
}

fn strip_windows_namespace_prefix(path: &str) -> &str {
    path.strip_prefix(r"\\?\")
        .or_else(|| path.strip_prefix(r"\??\"))
        .unwrap_or(path)
}

fn log_image_load_skip(reason_key: &str, path: &str, message: &str) {
    let key = format!(
        "{}|{}",
        reason_key,
        diagnostic_path_key(path).unwrap_or_else(|| "unknown".to_string())
    );
    let now = Instant::now();
    let state = ETW_IMAGE_LOAD_SKIP_LOG_STATE
        .get_or_init(|| Mutex::new(EtwImageLoadSkipLogState::default()));
    let mut guard = state.lock().unwrap_or_else(|err| err.into_inner());
    let should_log = guard
        .last_logged_by_key
        .get(&key)
        .map(|last| {
            now.checked_duration_since(*last).unwrap_or_default()
                >= Duration::from_secs(ETW_IMAGE_LOAD_SKIP_LOG_INTERVAL_SECS)
        })
        .unwrap_or(true);

    if should_log {
        let suppressed = guard.suppressed_by_key.remove(&key).unwrap_or(0);
        guard.last_logged_by_key.insert(key, now);
        if suppressed > 0 {
            eprintln!(
                "[EtwService] skip image-load injection decision: {}: {} (suppressed {} similar messages in the last {}s)",
                message,
                path,
                suppressed,
                ETW_IMAGE_LOAD_SKIP_LOG_INTERVAL_SECS
            );
        } else {
            eprintln!(
                "[EtwService] skip image-load injection decision: {}: {}",
                message, path
            );
        }
    } else {
        *guard.suppressed_by_key.entry(key).or_insert(0) += 1;
    }
}

#[cfg(windows)]
fn device_path_to_dos_path(path: &str) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{GetLogicalDriveStringsW, QueryDosDeviceW};

    let mut drives = vec![0u16; 512];
    let len = unsafe { GetLogicalDriveStringsW(Some(&mut drives)) };
    if len == 0 || len as usize >= drives.len() {
        return None;
    }

    let mut offset = 0usize;
    while offset < len as usize {
        let rest = &drives[offset..];
        let Some(end) = rest.iter().position(|ch| *ch == 0) else {
            break;
        };
        if end == 0 {
            break;
        }
        let drive = String::from_utf16_lossy(&rest[..end]);
        offset += end + 1;

        if drive.len() < 2 {
            continue;
        }
        let drive_name = &drive[..2];
        let drive_wide: Vec<u16> = drive_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut target = vec![0u16; 1024];
        let target_len = unsafe { QueryDosDeviceW(PCWSTR(drive_wide.as_ptr()), Some(&mut target)) };
        if target_len == 0 {
            continue;
        }
        let device_target = String::from_utf16_lossy(&target[..target_len as usize])
            .trim_end_matches('\0')
            .to_string();
        if device_target.is_empty() {
            continue;
        }
        if path.len() < device_target.len()
            || !path[..device_target.len()].eq_ignore_ascii_case(&device_target)
        {
            continue;
        }

        let mut suffix = path[device_target.len()..].to_string();
        if !suffix.is_empty() && !suffix.starts_with('\\') {
            suffix.insert(0, '\\');
        }
        return Some(format!("{}{}", drive_name, suffix));
    }

    None
}

#[cfg(not(windows))]
fn device_path_to_dos_path(_path: &str) -> Option<String> {
    None
}

fn event_is_image_load(event: &serde_json::Value) -> bool {
    event
        .get("provider")
        .and_then(|value| value.as_str())
        .is_some_and(|provider| provider.eq_ignore_ascii_case("Image"))
        && event
            .get("operation")
            .and_then(|value| value.as_str())
            .is_some_and(|operation| operation.eq_ignore_ascii_case("load"))
}

fn query_process_image_path_for_etw(pid: u32) -> Option<String> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::*;
    use windows::Win32::System::Threading::*;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf: Vec<u16> = vec![0u16; 4096];
        let mut size: u32 = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        );
        CloseHandle(handle).ok();
        if ok.is_ok() && size > 0 {
            Some(String::from_utf16_lossy(&buf[..size as usize]))
        } else {
            None
        }
    }
}

/// 函数名称：apply_remote_thread_start_detection
/// 函数作用：对实时 ETW Thread/start 事件做只读检测：如果线程入口地址不落在目标进程任何已加载镜像模块范围内，则升级为可疑远程线程/私有内存执行告警。
/// Purpose: Read-only detection for real-time ETW Thread/start events: if the thread start address is outside all loaded image module ranges of the target process, upgrade it to a suspicious remote-thread/private-memory execution alert.
/// 安全边界：只查询目标进程模块快照，不写入目标进程；无法枚举模块或地址缺失时不告警，避免误报。
fn apply_remote_thread_start_detection(event: &mut serde_json::Value) {
    if !event_is_thread_start(event) {
        return;
    }

    let start_address = event
        .get("startAddress")
        .and_then(|value| value.as_str())
        .and_then(parse_hex_or_decimal_u64)
        .unwrap_or(0);
    if start_address == 0 {
        return;
    }

    let pid = event
        .get("pid")
        .and_then(|value| value.as_u64())
        .unwrap_or(0) as u32;
    if pid == 0 || pid == 4 || pid == u32::MAX {
        return;
    }

    let Ok(modules) = enumerate_process_module_info(pid) else {
        return;
    };
    if modules.is_empty() || address_in_loaded_module(start_address, &modules) {
        return;
    }

    event["matched"] = serde_json::Value::Bool(true);
    event["ruleId"] = serde_json::Value::String("remote_thread_start_outside_image".to_string());
    event["threatType"] = serde_json::Value::String("可疑远程线程入口".to_string());
    event["severity"] = serde_json::Value::Number(serde_json::Number::from(75));
    event["recommendAction"] = serde_json::Value::String("alert".to_string());
    event["description"] = serde_json::Value::String(
        "线程入口地址不在目标进程任何已加载镜像模块范围内，可能是远程线程注入或私有内存执行。"
            .to_string(),
    );
}

/// 函数名称：direct_intercept_realtime_injection_event
/// 函数作用：ETW 注入类事件命中后直接进入拦截队列，避免等待轮询或异步风险分析链路。
/// Function name: direct_intercept_realtime_injection_event
/// Purpose: Directly enqueues realtime ETW injection findings so interception happens before post-event polling/rescans.
fn direct_intercept_realtime_injection_event(ctx: &ServiceContext, event: &serde_json::Value) {
    if ctx.is_exiting() {
        return;
    }

    let Some(rule_id) = event.get("ruleId").and_then(|value| value.as_str()) else {
        return;
    };
    if !is_realtime_preblock_rule(rule_id) {
        return;
    }

    if should_skip_realtime_preblock_for_control_chain(event) {
        append_interception_diagnostic(
            "etw_realtime_preblock_skipped",
            serde_json::json!({
                "reason": "windows_control_chain_process",
                "ruleId": rule_id,
                "pid": event.get("pid").and_then(|value| value.as_u64()).unwrap_or(0),
                "processName": event.get("processName").and_then(|value| value.as_str()).unwrap_or(""),
                "processPath": event.get("processPath").and_then(|value| value.as_str()).unwrap_or(""),
            }),
        );
        eprintln!(
            "[EtwService] Skipping realtime preblock for Windows control-chain process: rule={}, processName={}, processPath={}",
            rule_id,
            event.get("processName").and_then(|value| value.as_str()).unwrap_or(""),
            event.get("processPath").and_then(|value| value.as_str()).unwrap_or("")
        );
        return;
    }

    let pid = event
        .get("pid")
        .and_then(|value| value.as_u64())
        .unwrap_or(0) as u32;
    if pid == 0 || pid == 4 || pid == u32::MAX || pid == std::process::id() {
        return;
    }

    let Some(interception_state) = ctx.get::<InterceptionService>() else {
        return;
    };
    let mut process_path = event
        .get("processPath")
        .or_else(|| event.get("filePath"))
        .or_else(|| event.get("path"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    if process_path.is_empty() {
        process_path = query_process_image_path_for_etw(pid).unwrap_or_default();
    }
    let process_name = event
        .get("processName")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty() && !value.eq_ignore_ascii_case("Unknown"))
        .map(|value| value.to_string())
        .or_else(|| file_name_from_path(&process_path))
        .unwrap_or_else(|| format!("PID {}", pid));
    let risk_level = event
        .get("severity")
        .and_then(|value| value.as_u64())
        .map(|severity| if severity >= 70 { "high" } else { "medium" })
        .unwrap_or("high")
        .to_string();
    let threat_type = event
        .get("ruleId")
        .and_then(|value| value.as_str())
        .unwrap_or("realtime_injection_event")
        .to_string();
    let description = event
        .get("description")
        .and_then(|value| value.as_str())
        .unwrap_or("实时 ETW 注入类事件命中");
    // 实时前置挂起是绕过 RiskService 的第二条拦截路径，判据必须与策略层一致，
    // 否则用户配置的排除目录对它完全无效（策略层拦不住的这里照挂）。
    //  The realtime pre-block is a second interception path that bypasses RiskService, so it
    //  must apply the same criteria; otherwise user-configured exclusions have no effect here.
    if !process_path.trim().is_empty() {
        match crate::services::path_policy_service::is_excluded_path(&process_path) {
            Ok(true) => {
                append_interception_diagnostic(
                    "realtime_preblock_skipped_excluded_path",
                    serde_json::json!({
                        "pid": pid,
                        "ruleId": rule_id,
                        "processPath": process_path,
                    }),
                );
                eprintln!(
                    "[EtwService] Skipping realtime preblock for user-excluded path: rule={}, processPath={}",
                    rule_id, process_path
                );
                return;
            }
            Ok(false) => {}
            Err(err) => {
                // 读排除表失败不能变成绕过通道，按未排除处理
                //  A failed exclusion lookup must not become a bypass; treat as not excluded
                eprintln!(
                    "[EtwService] Exclusion lookup failed for {}: {} (treated as not excluded)",
                    process_path, err
                );
            }
        }
    }

    let payload = serde_json::json!({
        "source": "etw_realtime_preblock",
        "targetType": "process",
        "ruleId": rule_id,
        "event": event,
    });
    let entry = InterceptionEntry {
        pid,
        process_name,
        file_path: process_path,
        risk_level,
        threat_type: Some(threat_type),
        reason: format!("实时 ETW 注入类事件命中：{}", description),
        payload: Some(payload.to_string()),
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
    };

    interception_state.enqueue(entry);
    interception_state.try_show_next(ctx);
}

/// 函数名称：mark_hot_pid_for_realtime_event
/// 函数作用：把已由 ETW 强信号命中的 PID 交给进程扫描器马上做后置证据补全。
/// Function name: mark_hot_pid_for_realtime_event
/// Purpose: Hands strong ETW-matched PIDs to ProcessScannerService for immediate post-event evidence collection.
fn mark_hot_pid_for_realtime_event(ctx: &ServiceContext, event: &serde_json::Value) {
    let Some(rule_id) = event.get("ruleId").and_then(|value| value.as_str()) else {
        return;
    };
    if !is_realtime_evidence_collection_rule(rule_id) {
        return;
    }
    if should_skip_realtime_evidence_collection_for_control_chain(event) {
        append_interception_diagnostic(
            "etw_realtime_evidence_skipped",
            serde_json::json!({
                "reason": "windows_control_chain_process",
                "ruleId": rule_id,
                "pid": event.get("pid").and_then(|value| value.as_u64()).unwrap_or(0),
                "processName": event.get("processName").and_then(|value| value.as_str()).unwrap_or(""),
                "processPath": event.get("processPath").and_then(|value| value.as_str()).unwrap_or(""),
            }),
        );
        eprintln!(
            "[EtwService] Skipping hot PID evidence collection for Windows control-chain process: rule={}, processName={}, processPath={}",
            rule_id,
            event.get("processName").and_then(|value| value.as_str()).unwrap_or(""),
            event.get("processPath").and_then(|value| value.as_str()).unwrap_or("")
        );
        return;
    }

    let pid = event
        .get("pid")
        .and_then(|value| value.as_u64())
        .unwrap_or(0) as u32;
    if let Some(scanner) = ctx.get::<ProcessScannerService>() {
        scanner.mark_hot_pid(pid, rule_id);
    }
}

fn is_realtime_preblock_rule(rule_id: &str) -> bool {
    matches!(rule_id, "trusted_process_unsigned_image_load")
}

fn should_skip_realtime_preblock_for_control_chain(event: &serde_json::Value) -> bool {
    let rule_id = event
        .get("ruleId")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if rule_id != "trusted_process_unsigned_image_load" {
        return false;
    }

    let process_name = event
        .get("processName")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let process_path = event
        .get("processPath")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty());
    let Some(process_path) = process_path else {
        return false;
    };
    is_windows_control_chain_process(process_name, Some(process_path))
}

fn should_skip_realtime_evidence_collection_for_control_chain(event: &serde_json::Value) -> bool {
    should_skip_realtime_preblock_for_control_chain(event)
}

fn is_realtime_evidence_collection_rule(rule_id: &str) -> bool {
    matches!(rule_id, "trusted_process_unsigned_image_load")
}

fn is_observation_only_realtime_rule(rule_id: &str) -> bool {
    matches!(rule_id, "remote_thread_start_outside_image")
}

fn should_forward_to_file_monitor(event: &serde_json::Value) -> bool {
    event
        .get("provider")
        .and_then(|value| value.as_str())
        .is_some_and(|provider| provider.eq_ignore_ascii_case("File"))
}

fn etw_behavior_db_dedup_key(event: &serde_json::Value) -> String {
    let pid = event
        .get("pid")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let provider = event
        .get("provider")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let operation = event
        .get("operation")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let signal = event
        .get("ruleId")
        .or_else(|| event.get("threatType"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("unknown")
        .to_ascii_lowercase();
    let path_key = event
        .get("path")
        .or_else(|| event.get("filePath"))
        .or_else(|| event.get("processPath"))
        .and_then(|value| value.as_str())
        .and_then(diagnostic_path_key)
        .unwrap_or_else(|| "no-path".to_string());

    format!("{pid}|{provider}|{operation}|{signal}|{path_key}")
}

fn etw_response_dedup_key(event: &serde_json::Value) -> String {
    etw_behavior_db_dedup_key(event)
}

fn is_high_value_realtime_etw_event(event: &serde_json::Value) -> bool {
    if event
        .get("ruleId")
        .and_then(|value| value.as_str())
        .is_some_and(is_observation_only_realtime_rule)
    {
        return false;
    }

    event
        .get("matched")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        || event.get("threatType").is_some()
        || event.get("ruleId").is_some()
}

fn event_is_thread_start(event: &serde_json::Value) -> bool {
    event
        .get("provider")
        .and_then(|value| value.as_str())
        .is_some_and(|provider| provider.eq_ignore_ascii_case("Thread"))
        && event
            .get("operation")
            .and_then(|value| value.as_str())
            .is_some_and(|operation| operation.eq_ignore_ascii_case("start"))
}

fn parse_hex_or_decimal_u64(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    trimmed.parse::<u64>().ok()
}

fn address_in_loaded_module(
    address: u64,
    modules: &[crate::services::process_scanner_service::ProcessModuleInfo],
) -> bool {
    modules.iter().any(|module| {
        let start = module.base_address as u64;
        let size = module.image_size as u64;
        if start == 0 || size == 0 {
            return false;
        }
        let Some(end) = start.checked_add(size) else {
            return false;
        };
        address >= start && address < end
    })
}

/// 函数名称：etw_event_pid
/// 函数作用：从 ETW 原始 JSON 中提取明确存在的 PID，兼容顶层 pid 和 Rust ETW 嵌套 event.pid。
/// Purpose: Extracts an explicit PID from raw ETW JSON, supporting top-level pid and nested event.pid.
/// 中文关键词：PID提取，系统事件过滤，高频ETW
/// English keywords: pid extraction, system event filtering, high-volume ETW
fn etw_event_pid(value: &serde_json::Value) -> Option<u64> {
    value
        .get("pid")
        .or_else(|| value.get("event").and_then(|event| event.get("pid")))
        .and_then(|pid| pid.as_u64())
}

const INVALID_WINDOWS_PID_U32_MAX: u64 = u32::MAX as u64;

/// 函数名称：should_drop_system_etw_event
/// 函数作用：判断 ETW 事件是否来自系统或无效 PID 这类不应进入业务日志的 Windows 噪音。
/// Purpose: Returns whether an ETW event belongs to system/invalid PID noise that must not enter business logs.
/// 中文关键词：PID过滤，后端过滤，日志降噪，性能保护
/// English keywords: PID filter, backend filter, log noise reduction, performance guard
fn should_drop_system_etw_event(value: &serde_json::Value) -> bool {
    match etw_event_pid(value) {
        Some(0 | 4) => true,
        Some(pid) => pid == INVALID_WINDOWS_PID_U32_MAX,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::app_lifecycle_service::AppLifecycleService;
    use crate::services::event_bus::EventBus;
    use crate::services::service_context::{ServiceContext, ServiceRegistry};
    use serde_json::json;

    /// 构造用于单元测试的 ServiceContext，并注册传入的拦截服务。
    ///  Build a ServiceContext for unit tests, registering the given interception service.
    fn make_test_context(interception: Arc<InterceptionService>) -> ServiceContext {
        let registry = Arc::new(ServiceRegistry::new());
        let lifecycle = Arc::new(AppLifecycleService::new());
        let event_bus = Arc::new(EventBus::new(64));
        let ctx = ServiceContext::new(registry, lifecycle, event_bus);
        ctx.register::<InterceptionService>(interception);
        ctx
    }

    #[test]
    fn should_drop_system_etw_event_filters_nested_pid_zero_and_four() {
        assert!(should_drop_system_etw_event(&json!({
            "type": "log",
            "event": {
                "pid": 0,
                "provider": "Unknown",
                "data": {}
            }
        })));
        assert!(should_drop_system_etw_event(&json!({
            "type": "log",
            "event": {
                "pid": 4,
                "provider": "Network",
                "data": {
                    "remoteAddress": "127.0.0.1"
                }
            }
        })));
        assert!(should_drop_system_etw_event(&json!({
            "type": "log",
            "event": {
                "pid": 4_294_967_295_u64,
                "provider": "Unknown",
                "data": {}
            }
        })));
    }

    #[test]
    fn should_drop_system_etw_event_filters_top_level_pid_zero_and_four() {
        assert!(should_drop_system_etw_event(&json!({
            "type": "match",
            "pid": 0,
            "provider": "Unknown"
        })));
        assert!(should_drop_system_etw_event(&json!({
            "type": "log",
            "pid": 4,
            "provider": "Network"
        })));
        assert!(should_drop_system_etw_event(&json!({
            "type": "log",
            "pid": 4_294_967_295_u64,
            "provider": "Unknown"
        })));
    }

    #[test]
    fn should_drop_system_etw_event_keeps_normal_or_missing_pid() {
        assert!(!should_drop_system_etw_event(&json!({
            "type": "log",
            "event": {
                "pid": 47216,
                "provider": "Network",
                "data": {}
            }
        })));
        assert!(!should_drop_system_etw_event(&json!({
            "type": "log",
            "event": {
                "provider": "File",
                "data": {
                    "fileName": "C:\\temp\\sample.txt"
                }
            }
        })));
    }

    #[test]
    fn normalize_etw_app_event_maps_image_load_to_path() {
        let normalized = normalize_etw_app_event(&json!({
            "type": "log",
            "event": {
                "timestamp": 1780000000000_u64,
                "pid": 30056,
                "tid": 991,
                "provider": "Image",
                "opcode": 0,
                "id": 5,
                "data": {
                    "type": "load",
                    "imageName": "E:\\Project\\HTML\\AnXinSecurity\\native\\file_hook\\build-calc-probe-x64\\Release\\calc_probe_payload.dll",
                    "imageBase": "0x7ff700000000",
                    "imageSize": 73728
                }
            }
        }));

        assert_eq!(normalized["provider"], "Image");
        assert_eq!(normalized["operation"], "load");
        assert_eq!(normalized["pid"], 30056);
        assert_eq!(
            normalized["path"],
            "E:\\Project\\HTML\\AnXinSecurity\\native\\file_hook\\build-calc-probe-x64\\Release\\calc_probe_payload.dll"
        );
        assert_eq!(normalized["imageBase"], "0x7ff700000000");
        assert_eq!(normalized["imageSize"], 73728);
    }

    #[test]
    fn normalize_etw_app_event_maps_thread_start_address() {
        let normalized = normalize_etw_app_event(&json!({
            "type": "log",
            "event": {
                "timestamp": 1780000000001_u64,
                "pid": 30056,
                "tid": 991,
                "provider": "Thread",
                "opcode": 1,
                "id": 3,
                "data": {
                    "type": "start",
                    "threadId": "thread:777",
                    "startAddress": "0x7ff700001234"
                }
            }
        }));

        assert_eq!(normalized["provider"], "Thread");
        assert_eq!(normalized["operation"], "start");
        assert_eq!(normalized["pid"], 30056);
        assert_eq!(normalized["startAddress"], "0x7ff700001234");
    }

    #[test]
    fn event_is_image_load_only_matches_image_load_events() {
        assert!(event_is_image_load(&json!({
            "provider": "Image",
            "operation": "load",
            "path": "C:\\Temp\\calc_probe_payload.dll"
        })));
        assert!(event_is_image_load(&json!({
            "provider": "image",
            "operation": "LOAD",
            "path": "C:\\Temp\\calc_probe_payload.dll"
        })));
        assert!(!event_is_image_load(&json!({
            "provider": "Image",
            "operation": "unload",
            "path": "C:\\Temp\\calc_probe_payload.dll"
        })));
        assert!(!event_is_image_load(&json!({
            "provider": "File",
            "operation": "load",
            "path": "C:\\Temp\\calc_probe_payload.dll"
        })));
    }

    #[test]
    fn event_is_thread_start_only_matches_thread_start_events() {
        assert!(event_is_thread_start(&json!({
            "provider": "Thread",
            "operation": "start",
            "startAddress": "0x1000"
        })));
        assert!(event_is_thread_start(&json!({
            "provider": "thread",
            "operation": "START",
            "startAddress": "0x1000"
        })));
        assert!(!event_is_thread_start(&json!({
            "provider": "Thread",
            "operation": "stop",
            "startAddress": "0x1000"
        })));
        assert!(!event_is_thread_start(&json!({
            "provider": "Image",
            "operation": "start",
            "startAddress": "0x1000"
        })));
    }

    #[test]
    fn parse_hex_or_decimal_u64_accepts_hex_and_decimal() {
        assert_eq!(parse_hex_or_decimal_u64("0x1000"), Some(4096));
        assert_eq!(parse_hex_or_decimal_u64("4096"), Some(4096));
        assert_eq!(parse_hex_or_decimal_u64(""), None);
        assert_eq!(parse_hex_or_decimal_u64("not-an-address"), None);
    }

    #[test]
    fn etw_poll_log_accumulator_suppresses_empty_polls() {
        let start = Instant::now();
        let mut accumulator =
            EtwPollLogAccumulator::new_with_last_log(Duration::from_secs(10), start);

        assert_eq!(accumulator.record(0, start + Duration::from_secs(10)), None);
        assert_eq!(accumulator.record(0, start + Duration::from_secs(20)), None);
    }

    #[test]
    fn etw_poll_log_accumulator_emits_windowed_summary() {
        let start = Instant::now();
        let mut accumulator =
            EtwPollLogAccumulator::new_with_last_log(Duration::from_secs(10), start);

        assert_eq!(accumulator.record(2, start + Duration::from_secs(5)), None);
        assert_eq!(
            accumulator.record(3, start + Duration::from_secs(11)),
            Some(EtwPollLogSummary {
                polls: 2,
                events: 5,
                non_empty_batches: 2,
                max_batch: 3,
            })
        );
        assert_eq!(accumulator.record(0, start + Duration::from_secs(21)), None);
    }

    #[test]
    fn etw_behavior_db_gate_suppresses_recent_duplicate_signals() {
        let start = Instant::now();
        let mut gate = EtwBehaviorDbGate::new(Duration::from_secs(10));
        let event = json!({
            "pid": 4242,
            "provider": "Image",
            "operation": "load",
            "ruleId": "trusted_process_unsigned_image_load",
            "path": r"C:\Temp\probe.dll"
        });

        assert!(gate.should_record(&event, start));
        assert!(!gate.should_record(&event, start + Duration::from_secs(5)));
        assert!(gate.should_record(&event, start + Duration::from_secs(11)));
    }

    #[test]
    fn etw_behavior_db_gate_keeps_distinct_paths_separate() {
        let start = Instant::now();
        let mut gate = EtwBehaviorDbGate::new(Duration::from_secs(10));
        let first = json!({
            "pid": 4242,
            "provider": "Image",
            "operation": "load",
            "ruleId": "trusted_process_unsigned_image_load",
            "path": r"C:\Temp\first.dll"
        });
        let second = json!({
            "pid": 4242,
            "provider": "Image",
            "operation": "load",
            "ruleId": "trusted_process_unsigned_image_load",
            "path": r"C:\Temp\second.dll"
        });

        assert!(gate.should_record(&first, start));
        assert!(gate.should_record(&second, start + Duration::from_secs(1)));
    }

    #[test]
    fn etw_behavior_db_dedup_key_uses_stable_signal_shape() {
        let left = etw_behavior_db_dedup_key(&json!({
            "pid": 4242,
            "provider": "Image",
            "operation": "Load",
            "ruleId": "trusted_process_unsigned_image_load",
            "path": r"C:\Temp\probe.dll"
        }));
        let right = etw_behavior_db_dedup_key(&json!({
            "pid": 4242,
            "provider": "image",
            "operation": "load",
            "ruleId": "TRUSTED_PROCESS_UNSIGNED_IMAGE_LOAD",
            "path": r"C:\Temp\probe.dll"
        }));

        assert_eq!(left, right);
    }

    #[test]
    fn etw_response_gate_suppresses_recent_duplicate_realtime_responses() {
        let start = Instant::now();
        let mut gate = EtwResponseGate::new(Duration::from_secs(2));
        let event = json!({
            "pid": 4242,
            "provider": "Image",
            "operation": "load",
            "matched": true,
            "ruleId": "trusted_process_unsigned_image_load",
            "threatType": "可信进程加载未签名模块",
            "path": r"C:\Temp\probe.dll"
        });

        assert!(gate.should_forward(&event, start));
        assert!(!gate.should_forward(&event, start + Duration::from_millis(500)));
        assert!(gate.should_forward(&event, start + Duration::from_secs(3)));
    }

    #[test]
    fn etw_response_gate_keeps_distinct_realtime_signals_separate() {
        let start = Instant::now();
        let mut gate = EtwResponseGate::new(Duration::from_secs(2));
        let first = json!({
            "pid": 4242,
            "provider": "Image",
            "operation": "load",
            "matched": true,
            "ruleId": "trusted_process_unsigned_image_load",
            "path": r"C:\Temp\first.dll"
        });
        let second = json!({
            "pid": 4242,
            "provider": "Image",
            "operation": "load",
            "matched": true,
            "ruleId": "trusted_process_unsigned_image_load",
            "path": r"C:\Temp\second.dll"
        });

        assert!(gate.should_forward(&first, start));
        assert!(gate.should_forward(&second, start + Duration::from_millis(500)));
    }

    #[test]
    fn etw_response_gate_rejects_observation_only_events() {
        let start = Instant::now();
        let mut gate = EtwResponseGate::new(Duration::from_secs(2));
        let observation_only = json!({
            "pid": 4242,
            "provider": "Thread",
            "operation": "start",
            "matched": true,
            "ruleId": "remote_thread_start_outside_image",
            "threatType": "可疑远程线程入口"
        });

        assert!(!gate.should_forward(&observation_only, start));
    }

    #[test]
    fn etw_image_path_strips_windows_namespace_prefixes() {
        assert_eq!(
            etw_image_path_to_verifiable_path(r"\\?\C:\Windows\System32\netapi32.dll").as_deref(),
            Some(r"C:\Windows\System32\netapi32.dll")
        );
        assert_eq!(
            etw_image_path_to_verifiable_path(r"\??\C:\Windows\System32\netapi32.dll").as_deref(),
            Some(r"C:\Windows\System32\netapi32.dll")
        );
        assert!(etw_image_path_to_verifiable_path("   ").is_none());
    }

    #[test]
    fn etw_image_path_trims_noise_before_device_prefix() {
        assert_eq!(
            trim_etw_path_noise_before_device_prefix(
                r"@\Device\HarddiskVolume3\Windows\System32\kernel32.dll"
            ),
            r"\Device\HarddiskVolume3\Windows\System32\kernel32.dll"
        );
        assert_eq!(
            trim_etw_path_noise_before_device_prefix(r"C:\Windows\System32\kernel32.dll"),
            r"C:\Windows\System32\kernel32.dll"
        );
    }

    #[cfg(windows)]
    #[test]
    fn etw_image_path_converts_device_path_to_existing_dos_file() {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let drive = system_root.get(..2).unwrap_or("C:");
        let drive_wide: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut target = vec![0u16; 1024];
        let len = unsafe { QueryDosDeviceW(PCWSTR(drive_wide.as_ptr()), Some(&mut target)) };
        assert!(len > 0, "test requires QueryDosDeviceW for system drive");

        let device_root = String::from_utf16_lossy(&target[..len as usize])
            .trim_end_matches('\0')
            .to_string();
        let suffix = system_root
            .get(2..)
            .unwrap_or(r"\Windows")
            .trim_start_matches('\\');
        let device_path = format!(r"{}\{}\System32\kernel32.dll", device_root, suffix);

        let converted = etw_image_path_to_verifiable_path(&device_path)
            .expect("device path should convert to DOS path");
        assert!(
            std::path::Path::new(&converted).is_file(),
            "converted path should be an existing file: {}",
            converted
        );
    }

    #[test]
    fn address_in_loaded_module_uses_half_open_module_range() {
        let modules = vec![
            crate::services::process_scanner_service::ProcessModuleInfo {
                path: r"C:\Windows\System32\kernel32.dll".to_string(),
                base_address: 0x1000,
                image_size: 0x200,
            },
        ];

        assert!(address_in_loaded_module(0x1000, &modules));
        assert!(address_in_loaded_module(0x11ff, &modules));
        assert!(!address_in_loaded_module(0x1200, &modules));
        assert!(!address_in_loaded_module(0x0fff, &modules));
    }

    #[test]
    fn realtime_rule_policy_separates_preblock_from_evidence_collection() {
        assert!(is_realtime_preblock_rule(
            "trusted_process_unsigned_image_load"
        ));
        assert!(!is_realtime_preblock_rule(
            "remote_thread_start_outside_image"
        ));
        assert!(is_realtime_evidence_collection_rule(
            "trusted_process_unsigned_image_load"
        ));
        assert!(!is_realtime_evidence_collection_rule(
            "remote_thread_start_outside_image"
        ));
        assert!(!is_realtime_evidence_collection_rule("ordinary_file_write"));
    }

    #[test]
    fn etw_event_fanout_keeps_file_monitor_on_file_events_only() {
        assert!(should_forward_to_file_monitor(&json!({
            "provider": "File",
            "operation": "create",
            "path": r"C:\Temp\sample.bin"
        })));
        assert!(should_forward_to_file_monitor(&json!({
            "provider": "file",
            "operation": "rename",
            "path": r"C:\Temp\sample.bin"
        })));
        assert!(!should_forward_to_file_monitor(&json!({
            "provider": "Thread",
            "operation": "start",
            "ruleId": "remote_thread_start_outside_image"
        })));
        assert!(!should_forward_to_file_monitor(&json!({
            "provider": "Image",
            "operation": "load",
            "path": r"C:\Temp\probe.dll"
        })));
    }

    #[test]
    fn high_value_etw_fanout_suppresses_observation_only_noise() {
        let observation_only = json!({
            "provider": "Thread",
            "operation": "start",
            "matched": true,
            "ruleId": "remote_thread_start_outside_image",
            "threatType": "可疑远程线程入口"
        });
        assert!(!is_high_value_realtime_etw_event(&observation_only));

        let strong_image_load = json!({
            "provider": "Image",
            "operation": "load",
            "matched": true,
            "ruleId": "trusted_process_unsigned_image_load",
            "threatType": "可信进程加载未签名模块"
        });
        assert!(is_high_value_realtime_etw_event(&strong_image_load));

        assert!(is_high_value_realtime_etw_event(&json!({
            "provider": "Image",
            "operation": "load",
            "matched": true,
            "ruleId": "trusted_process_unsigned_image_load",
            "threatType": "可信进程加载未签名模块"
        })));
        assert!(is_high_value_realtime_etw_event(&json!({
            "provider": "File",
            "operation": "Rename",
            "matched": true,
            "ruleId": "test_rule_trigger"
        })));
        assert!(!is_high_value_realtime_etw_event(&json!({
            "provider": "Network",
            "operation": "connect",
            "pid": 47216
        })));
    }

    #[test]
    fn direct_realtime_interception_queues_strong_image_load_event() {
        let interception = Arc::new(InterceptionService::new_for_tests());
        let ctx = make_test_context(interception.clone());

        direct_intercept_realtime_injection_event(
            &ctx,
            &json!({
                "pid": 43210,
                "processName": "notepad.exe",
                "processPath": r"C:\Windows\System32\notepad.exe",
                "path": r"C:\Temp\calc_probe_payload.dll",
                "ruleId": "trusted_process_unsigned_image_load",
                "description": "trusted process loaded unsigned image",
                "severity": 75
            }),
        );

        let entry = interception
            .entry_for_pid(43210)
            .expect("entry should be queued");
        assert_eq!(
            entry.threat_type.as_deref(),
            Some("trusted_process_unsigned_image_load")
        );
        assert_eq!(entry.risk_level, "high");
        assert!(entry.reason.contains("实时 ETW 注入类事件命中"));
    }

    #[test]
    fn direct_realtime_interception_skips_windows_control_chain_preblock() {
        let interception = Arc::new(InterceptionService::new_for_tests());
        let ctx = make_test_context(interception.clone());

        direct_intercept_realtime_injection_event(
            &ctx,
            &json!({
                "pid": 43211,
                "processName": "powershell.exe",
                "processPath": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "path": r"C:\Temp\unsigned-module.dll",
                "ruleId": "trusted_process_unsigned_image_load",
                "description": "PowerShell Direct control process loaded unsigned image",
                "severity": 90
            }),
        );

        assert!(
            interception.entry_for_pid(43211).is_none(),
            "PowerShell Direct/control-chain processes should keep diagnostics but skip auto-suspend"
        );
    }

    #[test]
    fn realtime_evidence_collection_skips_windows_control_chain() {
        let control_chain = json!({
            "pid": 43213,
            "processName": "powershell.exe",
            "processPath": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "path": r"C:\Temp\unsigned-module.dll",
            "ruleId": "trusted_process_unsigned_image_load",
            "description": "PowerShell Direct control process loaded unsigned image",
            "severity": 90
        });
        let masqueraded = json!({
            "pid": 43214,
            "processName": "powershell.exe",
            "processPath": r"C:\Temp\powershell.exe",
            "path": r"C:\Temp\unsigned-module.dll",
            "ruleId": "trusted_process_unsigned_image_load",
            "description": "masqueraded powershell loaded unsigned image",
            "severity": 90
        });

        assert!(should_skip_realtime_evidence_collection_for_control_chain(
            &control_chain
        ));
        assert!(!should_skip_realtime_evidence_collection_for_control_chain(
            &masqueraded
        ));
    }

    #[test]
    fn direct_realtime_interception_queues_masqueraded_control_chain_name() {
        let interception = Arc::new(InterceptionService::new_for_tests());
        let ctx = make_test_context(interception.clone());

        direct_intercept_realtime_injection_event(
            &ctx,
            &json!({
                "pid": 43212,
                "processName": "powershell.exe",
                "processPath": r"C:\Temp\powershell.exe",
                "path": r"C:\Temp\unsigned-module.dll",
                "ruleId": "trusted_process_unsigned_image_load",
                "description": "masqueraded PowerShell name loaded unsigned image",
                "severity": 90
            }),
        );

        assert!(
            interception.entry_for_pid(43212).is_some(),
            "a suspicious process name alone must not bypass realtime preblock"
        );
    }

    #[test]
    fn direct_realtime_interception_does_not_queue_observation_only_thread_event() {
        let interception = Arc::new(InterceptionService::new_for_tests());
        let ctx = make_test_context(interception.clone());

        direct_intercept_realtime_injection_event(
            &ctx,
            &json!({
                "pid": 43210,
                "processName": "cmd.exe",
                "processPath": r"C:\Windows\System32\cmd.exe",
                "ruleId": "remote_thread_start_outside_image",
                "description": "thread start outside image",
                "severity": 75
            }),
        );

        assert!(
            interception.entry_for_pid(43210).is_none(),
            "isolated remote-thread start evidence must not auto-suspend cmd/control processes"
        );
    }

    #[test]
    fn etw_diagnostics_cache_is_bounded_and_counts_raw_events() {
        let mut cache = EtwDiagnosticsCache::new(2);
        cache.record_poll_batch(3);

        cache.record_raw(
            &json!({
                "type": "log",
                "event": {
                    "pid": 101,
                    "tid": 7,
                    "provider": "Thread",
                    "data": {
                        "type": "start",
                        "startAddress": "0x1000"
                    }
                }
            }),
            None,
        );
        cache.record_raw(
            &json!({
                "type": "log",
                "event": {
                    "pid": 102,
                    "provider": "Image",
                    "data": {
                        "type": "load",
                        "imageName": r"C:\Temp\probe.dll"
                    }
                }
            }),
            None,
        );
        cache.record_raw(
            &json!({
                "type": "log",
                "event": {
                    "pid": 4,
                    "provider": "Network",
                    "data": {
                        "type": "connect",
                        "remoteAddress": "127.0.0.1"
                    }
                }
            }),
            Some("system_or_invalid_pid"),
        );

        let snapshot = cache.snapshot(true, true);

        assert_eq!(snapshot.poll_batches, 1);
        assert_eq!(snapshot.total_polled, 3);
        assert_eq!(snapshot.last_poll_event_count, 3);
        assert_eq!(snapshot.total_raw, 3);
        assert_eq!(snapshot.total_after_filter, 2);
        assert_eq!(snapshot.total_dropped_system_pid, 1);
        assert_eq!(snapshot.recent_raw.len(), 2, "raw cache must stay bounded");
        assert_eq!(snapshot.recent_raw[0].pid, Some(102));
        assert_eq!(snapshot.recent_raw[1].pid, Some(4));
        assert_eq!(snapshot.provider_counts.get("Thread"), Some(&1));
        assert_eq!(snapshot.provider_counts.get("Image"), Some(&1));
        assert_eq!(snapshot.provider_counts.get("Network"), Some(&1));
        assert_eq!(snapshot.operation_counts.get("start"), Some(&1));
        assert_eq!(snapshot.operation_counts.get("load"), Some(&1));
        assert_eq!(snapshot.operation_counts.get("connect"), Some(&1));
        assert_eq!(snapshot.drop_counts.get("system_or_invalid_pid"), Some(&1));
    }

    #[test]
    fn etw_diagnostics_cache_tracks_normalized_matches_and_parse_errors() {
        let mut cache = EtwDiagnosticsCache::new(8);

        cache.record_parse_error("{not-json", "expected value");
        cache.record_normalized(&json!({
            "type": "match",
            "timestamp": "2026-06-18T00:00:00Z",
            "pid": 30056,
            "tid": 991,
            "provider": "Image",
            "operation": "load",
            "path": r"E:\Project\HTML\AnXinSecurity\native\file_hook\probe.dll",
            "matched": true,
            "ruleId": "trusted_process_unsigned_image_load",
            "threatType": "可信进程加载未签名模块"
        }));

        let snapshot = cache.snapshot(false, false);
        let serialized =
            serde_json::to_value(&snapshot).expect("diagnostics snapshot must serialize");

        assert_eq!(snapshot.total_parse_errors, 1);
        assert_eq!(snapshot.total_normalized, 1);
        assert_eq!(snapshot.total_matched, 1);
        assert_eq!(snapshot.drop_counts.get("parse_error"), Some(&1));
        assert_eq!(
            snapshot
                .rule_counts
                .get("trusted_process_unsigned_image_load"),
            Some(&1)
        );
        assert_eq!(
            snapshot.threat_counts.get("可信进程加载未签名模块"),
            Some(&1)
        );
        assert_eq!(
            snapshot.recent_raw[0].drop_reason.as_deref(),
            Some("parse_error")
        );
        assert_eq!(snapshot.recent_normalized[0].matched, true);
        assert_eq!(serialized["capacity"], 8);
        assert_eq!(
            serialized["recentNormalized"][0]["ruleId"],
            "trusted_process_unsigned_image_load"
        );
    }

    #[test]
    fn etw_diagnostics_cache_clear_resets_counts_and_recent_events() {
        let mut cache = EtwDiagnosticsCache::new(4);

        cache.record_poll_batch(1);
        cache.record_raw(
            &json!({
                "type": "log",
                "pid": 1234,
                "provider": "File",
                "operation": "create",
                "path": r"C:\Temp\sample.bin"
            }),
            None,
        );
        cache.record_normalized(&json!({
            "type": "match",
            "pid": 1234,
            "provider": "File",
            "operation": "create",
            "matched": true,
            "ruleId": "test_rule",
            "threatType": "test"
        }));

        cache.clear();
        let snapshot = cache.snapshot(true, false);

        assert_eq!(snapshot.capacity, 4);
        assert_eq!(snapshot.total_polled, 0);
        assert_eq!(snapshot.total_raw, 0);
        assert_eq!(snapshot.total_normalized, 0);
        assert_eq!(snapshot.total_matched, 0);
        assert!(snapshot.provider_counts.is_empty());
        assert!(snapshot.rule_counts.is_empty());
        assert!(snapshot.recent_raw.is_empty());
        assert!(snapshot.recent_normalized.is_empty());
    }

    #[test]
    fn etw_diagnostics_cache_aggregates_repeated_events_into_one_bucket() {
        let mut cache = EtwDiagnosticsCache::with_aggregate_capacity(1, 8);

        for _ in 0..3 {
            cache.record_raw(
                &json!({
                    "type": "log",
                    "event": {
                        "pid": 30056,
                        "provider": "Image",
                        "data": {
                            "type": "load",
                            "imageName": r"E:\Project\HTML\AnXinSecurity\native\file_hook\calc_probe_payload.dll"
                        }
                    }
                }),
                None,
            );
        }

        let snapshot = cache.snapshot(true, true);
        assert_eq!(snapshot.recent_raw.len(), 1);
        assert_eq!(snapshot.total_raw, 3);
        assert_eq!(snapshot.aggregate_buckets.len(), 1);

        let bucket = &snapshot.aggregate_buckets[0];
        assert_eq!(bucket.count, 3);
        assert_eq!(bucket.provider.as_deref(), Some("Image"));
        assert_eq!(bucket.operation.as_deref(), Some("load"));
        assert_eq!(bucket.pid, Some(30056));
        assert!(
            bucket.key.contains("calc_probe_payload.dll"),
            "bucket key should collapse repeated payload path to the filename"
        );
    }

    #[test]
    fn etw_diagnostics_cache_bucket_capacity_evicts_oldest_groups() {
        let mut cache = EtwDiagnosticsCache::with_aggregate_capacity(1, 2);

        cache.record_raw(
            &json!({
                "type": "log",
                "event": {
                    "pid": 100,
                    "provider": "Image",
                    "data": { "type": "load", "imageName": r"C:\Temp\a.dll" }
                }
            }),
            None,
        );
        cache.record_raw(
            &json!({
                "type": "log",
                "event": {
                    "pid": 101,
                    "provider": "Image",
                    "data": { "type": "load", "imageName": r"C:\Temp\b.dll" }
                }
            }),
            None,
        );
        cache.record_raw(
            &json!({
                "type": "log",
                "event": {
                    "pid": 102,
                    "provider": "Image",
                    "data": { "type": "load", "imageName": r"C:\Temp\c.dll" }
                }
            }),
            None,
        );

        let snapshot = cache.snapshot(true, true);
        assert_eq!(snapshot.aggregate_buckets.len(), 2);
        assert_eq!(snapshot.aggregate_evictions, 1);
    }
}
