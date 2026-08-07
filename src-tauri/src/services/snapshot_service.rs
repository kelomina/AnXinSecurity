// 进程快照拦截服务 — 启动时扫描所有运行进程及加载 DLL，暂停未签名进程
// Process snapshot service — scans running processes and loaded DLLs at startup, auto-intercepts only strong evidence.
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};
use tauri::AppHandle;

use crate::services::engine_service::EngineService;
use crate::services::interception_service::{InterceptionEntry, InterceptionService};
use crate::services::path_policy_service::{
    load_path_policy_snapshot, HashAfterPathMissDecision, PathPolicySnapshot,
};
use crate::services::process_scanner_service::{
    detect_module_chain_anomalies, detect_process_image_integrity_from_modules,
    enqueue_module_chain_anomaly_interception, enqueue_process_image_integrity_interception,
    enumerate_process_module_info, file_name_from_path, query_process_image_path, scan_confidence,
    scan_result_is_malware, scan_threat_type, ProcessImageIntegrityResult,
    ProcessImageIntegrityStatus, ProcessModuleInfo,
};
use crate::services::scan_result_cache_service::{CachedScanResult, ScanResultCacheService};
use crate::services::service_context::{AppContext, ServiceContext};
use crate::services::trust_service::{SignatureVerdict, TrustService};

const DEFAULT_STARTUP_SNAPSHOT_SLOW_WARN_MS: u64 = 30_000;
const DEFAULT_STARTUP_TARGET_SCAN_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_STARTUP_MODULE_ENUMERATION_TIMEOUT_MS: u64 = 1_000;
const DEFAULT_STARTUP_SIGNATURE_VERIFY_TIMEOUT_MS: u64 = 1_000;
const AUTO_STARTUP_SIGNATURE_VERIFY_CONCURRENCY: usize = 0;
const FALLBACK_STARTUP_SIGNATURE_VERIFY_CONCURRENCY: usize = 4;
const STARTUP_MODULE_SIGNATURE_TIMEOUT_MULTIPLIER: u32 = 3;
const DEFAULT_STARTUP_REVOCATION_CHECK_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_STARTUP_REVOCATION_CHECK_CONCURRENCY: usize = 4;
const CERT_E_REVOKED: u32 = 0x800B010C;
const CRYPT_E_REVOKED: u32 = 0x80092010;

#[derive(Debug, Clone, Copy)]
pub struct SnapshotScanOptions {
    pub slow_warn_ms: u64,
    pub target_scan_timeout_ms: u64,
    pub module_enumeration_timeout_ms: u64,
    pub signature_verify_timeout_ms: u64,
    pub signature_verify_concurrency: usize,
    pub revocation_check_timeout_ms: u64,
    pub revocation_check_concurrency: usize,
}

impl Default for SnapshotScanOptions {
    fn default() -> Self {
        Self {
            slow_warn_ms: DEFAULT_STARTUP_SNAPSHOT_SLOW_WARN_MS,
            target_scan_timeout_ms: DEFAULT_STARTUP_TARGET_SCAN_TIMEOUT_MS,
            module_enumeration_timeout_ms: DEFAULT_STARTUP_MODULE_ENUMERATION_TIMEOUT_MS,
            signature_verify_timeout_ms: DEFAULT_STARTUP_SIGNATURE_VERIFY_TIMEOUT_MS,
            signature_verify_concurrency: AUTO_STARTUP_SIGNATURE_VERIFY_CONCURRENCY,
            revocation_check_timeout_ms: DEFAULT_STARTUP_REVOCATION_CHECK_TIMEOUT_MS,
            revocation_check_concurrency: DEFAULT_STARTUP_REVOCATION_CHECK_CONCURRENCY,
        }
    }
}

/// 快照扫描结果 / Snapshot scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotResult {
    /// 启动可信基线是否已经完成 / Whether the startup trust baseline has completed
    #[serde(rename = "baselineComplete")]
    pub baseline_complete: bool,
    /// 深度模块检查是否已经完成 / Whether deep module checks have completed
    #[serde(rename = "deepScanCompleted")]
    pub deep_scan_completed: bool,
    /// 仍在后台等待深度检查的模块数 / Modules still pending background deep checks
    #[serde(rename = "deepScanPendingModules")]
    pub deep_scan_pending_modules: u32,
    /// 仍在后台等待模块枚举和主映像完整性检查的进程数 / Processes still pending background module enumeration and image integrity checks
    #[serde(rename = "deepScanPendingProcesses")]
    pub deep_scan_pending_processes: u32,
    /// 扫描进程总数 / Total scanned processes
    #[serde(rename = "totalProcesses")]
    pub total_processes: u32,
    /// 已签名进程数 / Signed process count
    #[serde(rename = "signedProcesses")]
    pub signed_processes: u32,
    /// 未签名进程数 / Unsigned process count
    #[serde(rename = "unsignedProcesses")]
    pub unsigned_processes: u32,
    /// 已暂停进程数 / Paused process count
    #[serde(rename = "pausedProcesses")]
    pub paused_processes: u32,
    /// 已扫描模块数 / Scanned module count
    #[serde(rename = "scannedModules")]
    pub scanned_modules: u32,
    /// 恶意进程数 / Malicious process count
    #[serde(rename = "maliciousProcesses")]
    pub malicious_processes: u32,
    /// 恶意模块数 / Malicious module count
    #[serde(rename = "maliciousModules")]
    pub malicious_modules: u32,
    /// 镂空或主映像异常告警数 / Hollowing or main-image anomaly alert count
    #[serde(rename = "imageIntegrityAlerts")]
    pub image_integrity_alerts: u32,
    /// 未签名加载模块告警数 / Unsigned loaded module alert count
    #[serde(rename = "unsignedModuleAlerts")]
    pub unsigned_module_alerts: u32,
    /// 系统关键进程伪装告警数 / Critical process masquerade alert count
    #[serde(rename = "masqueradeAlerts")]
    pub masquerade_alerts: u32,
    /// 证书吊销告警数 / Certificate revocation alert count
    #[serde(rename = "revocationAlerts")]
    pub revocation_alerts: u32,
    /// 系统关键进程证书吊销状态未知数 / Critical process revocation unknown count
    #[serde(rename = "revocationUnknownCritical")]
    pub revocation_unknown_critical: u32,
    /// 启动快照无法确认的进程数 / Process count with unknown startup trust state
    #[serde(rename = "unknownProcesses")]
    pub unknown_processes: u32,
    /// 启动快照无法确认的模块数 / Module count with unknown startup trust state
    #[serde(rename = "unknownModules")]
    pub unknown_modules: u32,
    /// 模块枚举失败总数 / Total module enumeration failure count
    #[serde(rename = "moduleEnumerationFailures")]
    pub module_enumeration_failures: u32,
    /// 由于系统拒绝访问导致的模块枚举失败数 / Module enumeration failures caused by access denial
    #[serde(rename = "moduleEnumerationAccessDenied")]
    pub module_enumeration_access_denied: u32,
    /// 缓存命中数 / Cache hit count
    #[serde(rename = "cacheHits")]
    pub cache_hits: u32,
    /// 启动快照性能采样 / Startup snapshot performance sampling
    #[serde(rename = "performance")]
    pub performance: SnapshotPerformanceStats,
    /// 扫描耗时（毫秒） / Scan duration (ms)
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
}

/// 启动快照性能采样 / Startup snapshot performance sampling
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotPerformanceStats {
    /// 启动可信基线耗时 / Startup trust baseline duration
    #[serde(rename = "baselineDurationMs")]
    pub baseline_duration_ms: u64,
    /// 后台深度模块检查耗时 / Background deep module scan duration
    #[serde(rename = "deepScanDurationMs")]
    pub deep_scan_duration_ms: u64,
    /// 进程枚举耗时 / Process enumeration duration
    #[serde(rename = "processEnumerationMs")]
    pub process_enumeration_ms: u64,
    /// 路径策略加载耗时 / Path policy load duration
    #[serde(rename = "pathPolicyLoadMs")]
    pub path_policy_load_ms: u64,
    /// 主循环总耗时 / Main loop duration
    #[serde(rename = "processLoopMs")]
    pub process_loop_ms: u64,
    /// 模块枚举累计耗时 / Module enumeration accumulated duration
    #[serde(rename = "moduleEnumerationMs")]
    pub module_enumeration_ms: u64,
    /// 主映像完整性检测累计耗时 / Image integrity accumulated duration
    #[serde(rename = "imageIntegrityMs")]
    pub image_integrity_ms: u64,
    /// 签名验证累计耗时 / Signature verification accumulated duration
    #[serde(rename = "signatureVerificationMs")]
    pub signature_verification_ms: u64,
    /// 进程主文件签名验证累计耗时 / Process main-image signature verification duration
    #[serde(rename = "processSignatureVerificationMs")]
    pub process_signature_verification_ms: u64,
    /// 模块签名验证累计耗时 / Module signature verification duration
    #[serde(rename = "moduleSignatureVerificationMs")]
    pub module_signature_verification_ms: u64,
    /// 本轮实际使用的签名验证并发数 / Effective signature verification concurrency for this run
    #[serde(rename = "signatureVerifyConcurrency")]
    pub signature_verify_concurrency: u32,
    /// 恶意扫描累计耗时 / Target malware scan accumulated duration
    #[serde(rename = "targetScanMs")]
    pub target_scan_ms: u64,
    /// 进程主文件恶意扫描累计耗时 / Process main-image malware scan duration
    #[serde(rename = "processTargetScanMs")]
    pub process_target_scan_ms: u64,
    /// 模块恶意扫描累计耗时 / Module malware scan duration
    #[serde(rename = "moduleTargetScanMs")]
    pub module_target_scan_ms: u64,
    /// 扫描缓存批量落盘耗时 / Batched scan cache flush duration
    #[serde(rename = "scanCacheFlushMs")]
    pub scan_cache_flush_ms: u64,
    /// 模块引用总数 / Total module references
    #[serde(rename = "moduleReferences")]
    pub module_references: u32,
    /// 唯一模块路径数 / Unique module path count
    #[serde(rename = "uniqueModulePaths")]
    pub unique_module_paths: u32,
    /// 触发恶意扫描的唯一路径数 / Unique scanned target path count
    #[serde(rename = "uniqueScanPaths")]
    pub unique_scan_paths: u32,
    /// 签名缓存命中数 / Signature cache hit count
    #[serde(rename = "signatureCacheHits")]
    pub signature_cache_hits: u32,
    /// 签名缓存未命中数 / Signature cache miss count
    #[serde(rename = "signatureCacheMisses")]
    pub signature_cache_misses: u32,
    /// 进程签名超时数 / Process signature timeout count
    #[serde(rename = "processSignatureTimeouts")]
    pub process_signature_timeouts: u32,
    /// 模块签名超时数 / Module signature timeout count
    #[serde(rename = "moduleSignatureTimeouts")]
    pub module_signature_timeouts: u32,
    /// 模块枚举超时数 / Module enumeration timeout count
    #[serde(rename = "moduleEnumerationTimeouts")]
    pub module_enumeration_timeouts: u32,
    /// 签名批处理中合并等待同一文件版本结果的次数 / In-batch signature waiters coalesced by file-version key
    #[serde(rename = "signatureCoalescedWaiters")]
    pub signature_coalesced_waiters: u32,
    /// 无法缓存的签名验证次数 / Signature checks that could not be cached
    #[serde(rename = "signatureCacheUncacheable")]
    pub signature_cache_uncacheable: u32,
    /// 恶意扫描缓存命中数 / Target scan cache hit count
    #[serde(rename = "targetScanCacheHits")]
    pub target_scan_cache_hits: u32,
    /// 恶意扫描缓存未命中数 / Target scan cache miss count
    #[serde(rename = "targetScanCacheMisses")]
    pub target_scan_cache_misses: u32,
    /// 已安排的后台吊销检查目标数 / Scheduled background revocation target count
    #[serde(rename = "revocationTargetsScheduled")]
    pub revocation_targets_scheduled: u32,
}

/// 快照运行上下文 — 统一 AppHandle 和 ServiceContext，使启动快照既能运行在 UI 进程也能运行在服务进程。
///  Snapshot runtime context - unifies AppHandle and ServiceContext so the startup snapshot
///  can run in both the UI process and the service process.
///
/// - `Tauri` 变体用于 UI 进程：事件通过 Tauri emit 直接发给前端。
/// - `Service` 变体用于服务进程：事件通过 event_bus → IPC 桥接转发给 UI 进程。
///  - `Tauri` variant for UI process: events go directly to frontend via Tauri emit.
///  - `Service` variant for service process: events forwarded to UI via event_bus → IPC bridge.
#[derive(Clone)]
pub enum SnapshotContext {
    Tauri(AppHandle),
    Service(ServiceContext),
}

impl AppContext for SnapshotContext {
    fn is_exiting(&self) -> bool {
        match self {
            SnapshotContext::Tauri(h) => h.is_exiting(),
            SnapshotContext::Service(c) => c.is_exiting(),
        }
    }

    fn emit_event<S: serde::Serialize + Clone + Send + 'static>(
        &self,
        event: &str,
        payload: S,
    ) -> Result<(), String> {
        match self {
            SnapshotContext::Tauri(h) => h.emit_event(event, payload),
            SnapshotContext::Service(c) => c.emit_event(event, payload),
        }
    }

    fn emit_to<S: serde::Serialize + Clone + Send + 'static>(
        &self,
        label: &str,
        event: &str,
        payload: S,
    ) -> Result<(), String> {
        match self {
            SnapshotContext::Tauri(h) => h.emit_to(label, event, payload),
            SnapshotContext::Service(c) => c.emit_to(label, event, payload),
        }
    }

    fn show_interception_window(&self) -> Result<(), String> {
        match self {
            SnapshotContext::Tauri(h) => h.show_interception_window(),
            SnapshotContext::Service(c) => c.show_interception_window(),
        }
    }

    fn hide_interception_window(&self) {
        match self {
            SnapshotContext::Tauri(h) => h.hide_interception_window(),
            SnapshotContext::Service(c) => c.hide_interception_window(),
        }
    }
}

/// 进程快照拦截服务 — 启动时安全评估
/// Process snapshot interception service — startup security assessment
///
/// 负责：
/// - 枚举所有运行进程（通过 CreateToolhelp32Snapshot）
/// - 对每个进程执行数字签名验证
/// - 将未签名进程推入拦截队列
/// - 生成快照报告
///
/// Responsible for:
/// - Enumerating all running processes (via CreateToolhelp32Snapshot)
/// - Performing digital signature verification on each process
/// - Pushing strong startup findings to interception queue
/// - Generating snapshot report
pub struct SnapshotService {
    /// 拦截服务引用 / Interception service reference
    interception: Arc<Mutex<Option<Arc<InterceptionService>>>>,
    /// 最后快照结果 / Last snapshot result
    last_result: Arc<Mutex<Option<SnapshotResult>>>,
    /// 后台吊销检查运行编号，避免旧任务覆盖新快照 / Revocation run id to prevent stale async updates
    revocation_run_id: Arc<AtomicU64>,
}

impl SnapshotService {
    /// 函数名称：new
    /// 函数作用：创建 SnapshotService 实例。
    /// Purpose: Creates a SnapshotService instance.
    /// Called by: main.rs setup()
    /// 中文关键词：进程快照，启动扫描，安全评估
    /// English keywords: process snapshot, startup scan, security assessment
    pub fn new() -> Self {
        Self {
            interception: Arc::new(Mutex::new(None)),
            last_result: Arc::new(Mutex::new(None)),
            revocation_run_id: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 函数名称：set_interception_service
    /// 函数作用：设置拦截服务引用。
    /// Purpose: Sets the interception service reference.
    /// Called by: main.rs setup()
    pub fn set_interception_service(&self, svc: Arc<InterceptionService>) {
        *self.interception.lock().unwrap_or_else(|e| e.into_inner()) = Some(svc);
    }

    /// 函数名称：take_startup_snapshot
    /// 函数作用：执行启动时进程快照扫描；验证签名前检查主映像完整性，并实时读取排除项和允许列表，命中时视为可信跳过拦截。
    ///   同一轮快照内复用路径策略和相同路径扫描结果，并在结束时批量持久化扫描缓存，减少启动刷屏和重复 I/O。
    ///   对无法打开的非完整路径只做未知统计，避免对 svchost.exe 这类进程名反复执行必然失败的 SHA-256 扫描，但不计入可信进程。
    /// Function name: take_startup_snapshot
    /// Purpose: Executes startup process snapshot scan; checks main-image integrity before signature verification, reads exclusions and allowlist, and treats matching processes as trusted.
    ///   Reuses path policy and scan results for identical paths within one snapshot and batches cache persistence at the end to reduce startup log spam and repeated I/O.
    ///   Counts unopenable non-full paths as unknown so names such as svchost.exe do not repeatedly trigger guaranteed SHA-256 scan failures but are not counted as trusted.
    /// Called by: main.rs setup() at startup (after ETW monitoring starts)
    /// 参数 trust: 信任验证服务 / Trust verification service
    /// 参数 ctx: 快照运行上下文（UI 进程用 AppHandle，服务进程用 ServiceContext）/ Snapshot runtime context (AppHandle for UI process, ServiceContext for service process)
    /// 副作用：通过 ctx 发射 "snapshot-progress" 和 "snapshot-result" 事件; 高/中风险进程入拦截队列
    /// Side effects: emits "snapshot-progress" and "snapshot-result" via ctx; high/medium risk processes enqueued
    /// 中文关键词：启动快照，进程扫描，签名验证，进程镂空，映像完整性，DLL枚举，去重扫描，批量缓存，日志节流，路径策略，启动监控，事件总线
    /// English keywords: startup snapshot, process scan, signature verification, process hollowing, image integrity, DLL enumeration, deduplicated scan, batched cache, log throttle, path policy, startup monitor, event bus
    pub async fn take_startup_snapshot(
        &self,
        trust: Arc<TrustService>,
        engine: Arc<EngineService>,
        cache: Arc<ScanResultCacheService>,
        ctx: &SnapshotContext,
        options: SnapshotScanOptions,
    ) -> Result<SnapshotResult, String> {
        let start_time = Instant::now();
        let revocation_run_id = self
            .revocation_run_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let slow_warn = Duration::from_millis(options.slow_warn_ms.max(1));
        let target_scan_timeout = Duration::from_millis(options.target_scan_timeout_ms.max(1));
        let module_enumeration_timeout =
            Duration::from_millis(options.module_enumeration_timeout_ms.max(1));
        let signature_verify_timeout =
            Duration::from_millis(options.signature_verify_timeout_ms.max(1));
        let module_signature_verify_timeout =
            startup_module_signature_verify_timeout(signature_verify_timeout, target_scan_timeout);
        let signature_verify_concurrency =
            resolve_startup_signature_verify_concurrency(options.signature_verify_concurrency);
        let revocation_check_timeout =
            Duration::from_millis(options.revocation_check_timeout_ms.max(1));
        let revocation_check_concurrency = options.revocation_check_concurrency.max(1);

        let mut performance = SnapshotPerformanceStats::default();
        performance.signature_verify_concurrency =
            signature_verify_concurrency.min(u32::MAX as usize) as u32;
        let mut unique_module_paths: HashSet<String> = HashSet::new();

        // 枚举所有运行进程 / Enumerate all running processes
        let process_enumeration_start = Instant::now();
        let processes = enumerate_all_processes()?;
        performance.process_enumeration_ms = elapsed_ms(process_enumeration_start);
        let total = processes.len() as u32;

        // 通知前端进度 / Notify frontend of progress
        if !ctx.is_exiting() {
            let _ = ctx.emit_event(
                "snapshot-progress",
                serde_json::json!({
                    "stage": "scanning",
                    "total": total,
                    "current": 0,
                }),
            );
        }

        let mut signed: u32 = 0;
        let mut unsigned: u32 = 0;
        let mut paused: u32 = 0;
        let mut scanned_modules: u32 = 0;
        let mut malicious_processes: u32 = 0;
        let malicious_modules: u32 = 0;
        let mut image_integrity_alerts: u32 = 0;
        let mut masquerade_alerts: u32 = 0;
        let revocation_alerts: u32 = 0;
        let revocation_unknown_critical: u32 = 0;
        let mut unknown_processes: u32 = 0;
        let mut unknown_modules: u32 = 0;
        let mut cache_hits: u32 = 0;
        let mut skipped_unscannable_processes: u32 = 0;
        let mut skipped_unscannable_modules: u32 = 0;
        let mut skipped_trusted_processes: u32 = 0;
        let skipped_trusted_modules: u32 = 0;
        let unsigned_module_alerts: u32 = 0;
        let mut signature_timeouts: u32 = 0;
        let mut process_signature_timeouts: u32 = 0;
        let module_signature_timeouts: u32 = 0;
        let mut scan_failures: u32 = 0;
        let mut module_enumeration_failures: u32 = 0;
        let mut module_enumeration_access_denied: u32 = 0;
        let mut module_enumeration_timeouts: u32 = 0;
        let mut first_scan_failure: Option<String> = None;
        let mut first_access_denied_module_enumeration_failure: Option<String> = None;
        let mut first_unexpected_module_enumeration_failure: Option<String> = None;
        let mut startup_scan_results: HashMap<String, StartupScanCachedOutcome> = HashMap::new();
        let mut startup_signature_cache = StartupSignatureCache::default();
        let mut revocation_targets: Vec<RevocationCheckTarget> = Vec::new();
        let path_policy_load_start = Instant::now();
        let path_policy = load_path_policy_snapshot()?;
        performance.path_policy_load_ms = elapsed_ms(path_policy_load_start);
        let mut slow_warning_logged = false;

        let interception_ref = {
            let interception_guard = self.interception.lock().unwrap_or_else(|e| e.into_inner());
            interception_guard.clone()
        };

        let mut all_modules_requiring_signature: Vec<StartupModuleSignatureTarget> = Vec::new();
        let mut deferred_process_module_checks: Vec<StartupDeferredProcessModuleCheck> = Vec::new();
        let process_signature_prefetch_targets: Vec<StartupModuleSignatureTarget> = processes
            .iter()
            .filter_map(|proc_info| {
                if proc_info.pid == std::process::id() || proc_info.pid <= 4 {
                    return None;
                }
                if matches!(
                    detect_process_masquerade(&proc_info.name, &proc_info.path),
                    MasqueradeVerdict::Suspicious { .. }
                ) || path_policy.should_skip_by_path_only(&proc_info.path)
                {
                    return None;
                }
                let target = inspect_startup_target_with_scan_key(
                    &proc_info.path,
                    proc_info.scan_key.clone(),
                );
                if !target.is_scannable() || target.signature_cache_key.is_none() {
                    return None;
                }
                Some(StartupModuleSignatureTarget {
                    pid: proc_info.pid,
                    process_name: proc_info.name.clone(),
                    process_path: proc_info.path.clone(),
                    path: proc_info.path.clone(),
                    scan_key: proc_info.scan_key.clone(),
                    target,
                })
            })
            .collect();
        if !process_signature_prefetch_targets.is_empty() {
            let signature_start = Instant::now();
            let prefetch_count = process_signature_prefetch_targets.len();
            let _prefetched_process_signatures = startup_signature_cache
                .verify_module_targets_concurrent(
                    trust.clone(),
                    process_signature_prefetch_targets,
                    signature_verify_timeout,
                    signature_verify_concurrency,
                )
                .await;
            let signature_elapsed = elapsed_ms(signature_start);
            performance.signature_verification_ms = performance
                .signature_verification_ms
                .saturating_add(signature_elapsed);
            performance.process_signature_verification_ms = performance
                .process_signature_verification_ms
                .saturating_add(signature_elapsed);
            if startup_snapshot_debug_logging_enabled() {
                eprintln!(
                    "[StartupSnapshot] Process signature prefetch done: {} targets, {}ms",
                    prefetch_count, signature_elapsed
                );
            }
        }
        let process_loop_start = Instant::now();
        for (i, proc_info) in processes.iter().enumerate() {
            if !slow_warning_logged && start_time.elapsed() >= slow_warn {
                slow_warning_logged = true;
                eprintln!(
                    "[StartupSnapshot] Slow scan warning after {}/{} processes ({}ms threshold); continuing to finish trust baseline",
                    i,
                    processes.len(),
                    options.slow_warn_ms
                );
            }

            // 跳过自身进程 / Skip own process
            if proc_info.pid == std::process::id() {
                signed += 1;
                continue;
            }

            // 跳过系统进程（PID 0 和 4） / Skip system processes (PID 0 and 4)
            if proc_info.pid <= 4 {
                signed += 1;
                continue;
            }

            let process_masquerade_verdict =
                detect_process_masquerade(&proc_info.name, &proc_info.path);
            match &process_masquerade_verdict {
                MasqueradeVerdict::Suspicious { expected, actual } => {
                    masquerade_alerts += 1;
                    paused += 1;
                    if let Some(ref interception) = interception_ref {
                        enqueue_process_masquerade_interception(
                            interception,
                            ctx,
                            proc_info.pid,
                            &proc_info.name,
                            &actual,
                            &expected,
                        );
                    }
                    continue;
                }
                MasqueradeVerdict::NotApplicable
                | MasqueradeVerdict::Clean
                | MasqueradeVerdict::Unknown => {}
            }

            if path_policy.should_skip_by_path_only(&proc_info.path) {
                signed += 1;
                continue;
            }

            let process_scan_key = proc_info.scan_key.clone();
            let process_target =
                inspect_startup_target_with_scan_key(&proc_info.path, process_scan_key.clone());
            let process_path_scannable = process_target.is_scannable();
            let process_signature_verdict = if process_path_scannable {
                let signature_start = Instant::now();
                let verdict = startup_signature_cache
                    .verify_file_for_target_async(
                        trust.clone(),
                        &proc_info.path,
                        &process_target,
                        signature_verify_timeout,
                    )
                    .await;
                performance.signature_verification_ms = performance
                    .signature_verification_ms
                    .saturating_add(elapsed_ms(signature_start));
                performance.process_signature_verification_ms = performance
                    .process_signature_verification_ms
                    .saturating_add(elapsed_ms(signature_start));
                if verdict.timed_out {
                    signature_timeouts += 1;
                    process_signature_timeouts += 1;
                    unknown_processes += 1;
                }
                Some(verdict)
            } else {
                None
            };
            let process_is_trusted = process_signature_verdict
                .as_ref()
                .is_some_and(|verdict| verdict.trusted);
            let process_hash_decision = if process_path_scannable && !process_is_trusted {
                let decision = path_policy.hash_after_path_miss_cached(
                    &proc_info.path,
                    process_target.signature_cache_key.as_deref(),
                );
                if decision.skip_scan {
                    signed += 1;
                    continue;
                }
                decision
            } else {
                HashAfterPathMissDecision::default()
            };

            if should_defer_startup_process_module_checks(
                &process_masquerade_verdict,
                process_path_scannable,
                process_is_trusted,
            ) {
                unknown_processes += 1;
                deferred_process_module_checks.push(StartupDeferredProcessModuleCheck {
                    pid: proc_info.pid,
                    process_name: proc_info.name.clone(),
                    process_path: proc_info.path.clone(),
                    process_scan_key: process_scan_key.clone(),
                    process_path_scannable,
                    process_is_trusted,
                    process_target,
                });
                continue;
            }

            let module_enumeration_start = Instant::now();
            let module_info = match enumerate_process_module_info_with_timeout(
                proc_info.pid,
                module_enumeration_timeout,
            )
            .await
            {
                Ok(modules) => Some(modules),
                Err(err) => {
                    module_enumeration_failures += 1;
                    unknown_modules += 1;
                    if module_enumeration_error_is_timeout(&err) {
                        module_enumeration_timeouts += 1;
                    }
                    let error_summary =
                        format!("PID={}, path={}: {}", proc_info.pid, proc_info.path, err);
                    if module_enumeration_error_is_access_denied(&err) {
                        module_enumeration_access_denied += 1;
                        if first_access_denied_module_enumeration_failure.is_none() {
                            first_access_denied_module_enumeration_failure = Some(error_summary);
                        }
                    } else if first_unexpected_module_enumeration_failure.is_none() {
                        first_unexpected_module_enumeration_failure = Some(error_summary);
                    }
                    None
                }
            };
            performance.module_enumeration_ms = performance
                .module_enumeration_ms
                .saturating_add(elapsed_ms(module_enumeration_start));
            let module_targets = module_info
                .as_ref()
                .map(|modules| prepare_startup_module_targets(modules));
            if let Some(targets) = module_targets.as_ref() {
                for module in targets {
                    unique_module_paths.insert(module.scan_key.clone());
                }
            }
            let image_integrity_start = Instant::now();
            let image_integrity = detect_process_image_integrity_from_modules(
                proc_info.pid,
                &proc_info.path,
                module_info.as_ref(),
            );
            performance.image_integrity_ms = performance
                .image_integrity_ms
                .saturating_add(elapsed_ms(image_integrity_start));
            let process_image_suspicious =
                image_integrity.status == ProcessImageIntegrityStatus::Suspicious;
            let process_image_clean = image_integrity.status == ProcessImageIntegrityStatus::Clean;
            match &image_integrity {
                ProcessImageIntegrityResult {
                    status: ProcessImageIntegrityStatus::Suspicious,
                    reason,
                    main_module_path,
                } => {
                    image_integrity_alerts += 1;
                    if let Some(ref interception) = interception_ref {
                        if enqueue_process_image_integrity_interception(
                            interception,
                            ctx,
                            proc_info.pid,
                            "startup_snapshot",
                            &proc_info.path,
                            main_module_path.as_deref(),
                            reason,
                            "high",
                        )
                        .is_enqueued()
                        {
                            paused += 1;
                        }
                    }
                }
                ProcessImageIntegrityResult {
                    status: ProcessImageIntegrityStatus::Unknown,
                    reason,
                    main_module_path,
                } => {
                    if process_path_scannable {
                        unknown_processes += 1;
                    }
                    if startup_snapshot_debug_logging_enabled() {
                        eprintln!(
                            "[StartupSnapshot] Process image integrity unknown PID={}, path={}, mainModule={:?}: {}",
                            proc_info.pid, proc_info.path, main_module_path, reason
                        );
                    }
                }
                ProcessImageIntegrityResult {
                    status: ProcessImageIntegrityStatus::Clean,
                    ..
                } => {}
            }

            let module_chain_integrity =
                detect_module_chain_anomalies(proc_info.pid, module_info.as_ref());
            let module_chain_clean =
                module_chain_integrity.status == ProcessImageIntegrityStatus::Clean;
            match &module_chain_integrity {
                ProcessImageIntegrityResult {
                    status: ProcessImageIntegrityStatus::Suspicious,
                    reason,
                    main_module_path,
                } => {
                    image_integrity_alerts += 1;
                    if let Some(ref interception) = interception_ref {
                        if enqueue_module_chain_anomaly_interception(
                            interception,
                            ctx,
                            proc_info.pid,
                            "startup_snapshot",
                            &proc_info.path,
                            main_module_path.as_deref(),
                            reason,
                        )
                        .is_enqueued()
                        {
                            paused += 1;
                        }
                    }
                }
                ProcessImageIntegrityResult {
                    status: ProcessImageIntegrityStatus::Unknown,
                    reason,
                    main_module_path,
                } => {
                    if process_path_scannable {
                        unknown_processes += 1;
                    }
                    if startup_snapshot_debug_logging_enabled() {
                        eprintln!(
                            "[StartupSnapshot] Module chain integrity unknown PID={}, path={}, sample={:?}: {}",
                            proc_info.pid, proc_info.path, main_module_path, reason
                        );
                    }
                }
                ProcessImageIntegrityResult {
                    status: ProcessImageIntegrityStatus::Clean,
                    ..
                } => {}
            }

            if should_schedule_process_revocation_check(
                &proc_info.name,
                &proc_info.path,
                process_path_scannable,
                process_is_trusted,
                process_image_clean,
            ) {
                revocation_targets.push(RevocationCheckTarget {
                    pid: proc_info.pid,
                    process_name: proc_info.name.clone(),
                    path: proc_info.path.clone(),
                    path_scan_key: process_scan_key.clone(),
                    write_time: process_target.write_time_epoch_ms,
                    critical: true,
                });
            }

            if !process_path_scannable {
                skipped_unscannable_processes += 1;
                unknown_processes += 1;
            } else if process_is_trusted && process_image_clean && module_chain_clean {
                skipped_trusted_processes += 1;
                signed += 1;
            } else {
                let target_scan_start = Instant::now();
                match scan_startup_target(
                    &engine,
                    &cache,
                    interception_ref.as_ref(),
                    ctx,
                    proc_info.pid,
                    &proc_info.name,
                    "process",
                    &proc_info.path,
                    &process_target.scan_key,
                    process_target.signature_cache_key.as_deref(),
                    process_hash_decision.sha256_hex.as_deref(),
                    None,
                    &path_policy,
                    true,
                    &mut startup_scan_results,
                    target_scan_timeout,
                )
                .await
                {
                    StartupScanOutcome::Malicious { cache_hit } => {
                        malicious_processes += 1;
                        paused += 1;
                        if cache_hit {
                            cache_hits += 1;
                            performance.target_scan_cache_hits =
                                performance.target_scan_cache_hits.saturating_add(1);
                        } else {
                            performance.target_scan_cache_misses =
                                performance.target_scan_cache_misses.saturating_add(1);
                        }
                    }
                    StartupScanOutcome::Clean { cache_hit } => {
                        if cache_hit {
                            cache_hits += 1;
                            performance.target_scan_cache_hits =
                                performance.target_scan_cache_hits.saturating_add(1);
                        } else {
                            performance.target_scan_cache_misses =
                                performance.target_scan_cache_misses.saturating_add(1);
                        }
                    }
                    StartupScanOutcome::Skipped => {}
                    StartupScanOutcome::Failed { error, cache_hit } => {
                        if cache_hit {
                            performance.target_scan_cache_hits =
                                performance.target_scan_cache_hits.saturating_add(1);
                        } else {
                            performance.target_scan_cache_misses =
                                performance.target_scan_cache_misses.saturating_add(1);
                        }
                        scan_failures += 1;
                        if first_scan_failure.is_none() {
                            first_scan_failure = Some(error);
                        }
                    }
                }
                performance.target_scan_ms = performance
                    .target_scan_ms
                    .saturating_add(elapsed_ms(target_scan_start));
                performance.process_target_scan_ms = performance
                    .process_target_scan_ms
                    .saturating_add(elapsed_ms(target_scan_start));

                if process_signature_verdict
                    .as_ref()
                    .is_some_and(should_count_unsigned_signature)
                {
                    unsigned += 1;
                }

                // 普通未签名是弱证据，只统计和保留 Unknown 语义，不自动挂起进程。
                // Strong findings such as malware, masquerade, revocation, or image integrity issues
                // are enqueued through their dedicated paths.
                if process_signature_verdict.as_ref().is_some_and(|verdict| {
                    should_enqueue_unsigned_signature(verdict, process_image_suspicious)
                }) {
                    paused += 1;
                }
            }

            if let Some(module_targets) = module_targets {
                let mut modules_requiring_signature = Vec::new();
                for module in module_targets {
                    let module_path = module.path;
                    if !slow_warning_logged && start_time.elapsed() >= slow_warn {
                        slow_warning_logged = true;
                        eprintln!(
                            "[StartupSnapshot] Slow scan warning while scanning modules after {}/{} processes ({}ms threshold); continuing to finish trust baseline",
                            i + 1,
                            processes.len(),
                            options.slow_warn_ms
                        );
                    }

                    scanned_modules += 1;
                    if startup_module_is_process_image(&module.scan_key, &process_scan_key) {
                        continue;
                    }
                    if path_policy.should_skip_by_path_only(&module_path) {
                        continue;
                    }

                    let module_target =
                        inspect_startup_target_with_scan_key(&module_path, module.scan_key.clone());
                    if module_target.skip_reason.is_some() {
                        skipped_unscannable_modules += 1;
                        unknown_modules += 1;
                        continue;
                    }
                    modules_requiring_signature.push(StartupModuleSignatureTarget {
                        pid: proc_info.pid,
                        process_name: proc_info.name.clone(),
                        process_path: proc_info.path.clone(),
                        path: module_path,
                        scan_key: module.scan_key,
                        target: module_target,
                    });
                }
                all_modules_requiring_signature.extend(modules_requiring_signature);
            }

            // 每10个进程更新一次进度 / Update progress every 10 processes
            if (i + 1) % 10 == 0 || i == processes.len() - 1 {
                if !ctx.is_exiting() {
                    let _ = ctx.emit_event(
                        "snapshot-progress",
                        serde_json::json!({
                            "stage": "scanning",
                            "total": total,
                            "current": (i + 1) as u32,
                        }),
                    );
                }
                eprintln!(
                    "[StartupSnapshot] Progress: {}/{} processes, {} module references, {} unique module paths, {} unique scanned paths, {} scan cache hits, {} signature cache hits, {} signature cache misses, {} malicious targets, {} skipped unscannable targets",
                    i + 1,
                    processes.len(),
                    scanned_modules,
                    unique_module_paths.len(),
                    startup_scan_results.len(),
                    cache_hits,
                    startup_signature_cache.hits,
                    startup_signature_cache.misses,
                    malicious_processes + malicious_modules,
                    skipped_unscannable_processes + skipped_unscannable_modules
                );
            }
        }
        performance.process_loop_ms = elapsed_ms(process_loop_start);

        let scan_cache_flush_start = Instant::now();
        if let Err(err) = cache.flush_pending() {
            eprintln!("[StartupSnapshot] Failed to persist scan cache: {}", err);
        }
        performance.scan_cache_flush_ms = elapsed_ms(scan_cache_flush_start);
        performance.module_references = scanned_modules;
        performance.unique_module_paths = unique_module_paths.len() as u32;
        performance.unique_scan_paths = startup_scan_results.len() as u32;
        performance.signature_cache_hits = startup_signature_cache.hits;
        performance.signature_cache_misses = startup_signature_cache.misses;
        performance.process_signature_timeouts = process_signature_timeouts;
        performance.module_signature_timeouts = module_signature_timeouts;
        performance.module_enumeration_timeouts = module_enumeration_timeouts;
        performance.signature_coalesced_waiters = startup_signature_cache.coalesced_waiters;
        performance.signature_cache_uncacheable = startup_signature_cache.uncacheable;
        performance.revocation_targets_scheduled = revocation_targets.len() as u32;
        performance.baseline_duration_ms = start_time.elapsed().as_millis() as u64;

        let deep_scan_pending_processes = deferred_process_module_checks.len() as u32;
        let deep_scan_pending_modules = all_modules_requiring_signature.len() as u32;
        if deep_scan_pending_modules > 0 {
            unknown_modules = unknown_modules.saturating_add(deep_scan_pending_modules);
        }
        let deep_scan_completed =
            deep_scan_pending_processes == 0 && deep_scan_pending_modules == 0;

        if skipped_unscannable_processes > 0
            || skipped_unscannable_modules > 0
            || skipped_trusted_processes > 0
            || skipped_trusted_modules > 0
            || unsigned_module_alerts > 0
            || image_integrity_alerts > 0
            || masquerade_alerts > 0
            || unknown_processes > 0
            || unknown_modules > 0
            || signature_timeouts > 0
            || scan_failures > 0
            || module_enumeration_failures > 0
            || slow_warning_logged
        {
            let module_enumeration_other_failures = module_enumeration_failures
                .saturating_sub(module_enumeration_access_denied)
                .saturating_sub(module_enumeration_timeouts);
            eprintln!(
                "[StartupSnapshot] Summary: {} unscannable process paths skipped, {} unscannable module paths skipped, {} trusted process paths skipped, {} trusted module paths skipped, {} unsigned module alerts, {} image integrity alerts, {} masquerade alerts, {} unknown processes, {} unknown modules, {} signature timeouts ({} process, {} module), {} scan failures, {} module enumeration failures ({} access denied, {} timeout, {} other), slowWarningLogged={}",
                skipped_unscannable_processes,
                skipped_unscannable_modules,
                skipped_trusted_processes,
                skipped_trusted_modules,
                unsigned_module_alerts,
                image_integrity_alerts,
                masquerade_alerts,
                unknown_processes,
                unknown_modules,
                signature_timeouts,
                process_signature_timeouts,
                module_signature_timeouts,
                scan_failures,
                module_enumeration_failures,
                module_enumeration_access_denied,
                module_enumeration_timeouts,
                module_enumeration_other_failures,
                slow_warning_logged
            );
            if let Some(error) = first_scan_failure {
                eprintln!("[StartupSnapshot] First scan failure: {}", error);
            }
            if let Some(error) = first_access_denied_module_enumeration_failure {
                eprintln!(
                    "[StartupSnapshot] First access-denied module enumeration failure: {}",
                    error
                );
            }
            if let Some(error) = first_unexpected_module_enumeration_failure {
                eprintln!(
                    "[StartupSnapshot] First unexpected module enumeration failure: {}",
                    error
                );
            }
        }

        eprintln!(
            "[StartupSnapshot] Performance: baseline={}ms, deepScanPendingModules={}, processEnumeration={}ms, pathPolicy={}ms, processLoop={}ms, moduleEnumeration={}ms, imageIntegrity={}ms, signatureVerification={}ms (process={}ms, module={}ms), signatureConcurrency={}, targetScan={}ms (process={}ms, module={}ms), scanCacheFlush={}ms, moduleRefs={}, uniqueModules={}, uniqueScanPaths={}, signatureCacheHits={}, signatureCacheMisses={}, signatureTimeouts={} (process={}, module={}), moduleEnumerationTimeouts={}, signatureCoalescedWaiters={}, signatureCacheUncacheable={}, targetScanCacheHits={}, targetScanCacheMisses={}, revocationTargets={}",
            performance.baseline_duration_ms,
            deep_scan_pending_modules,
            performance.process_enumeration_ms,
            performance.path_policy_load_ms,
            performance.process_loop_ms,
            performance.module_enumeration_ms,
            performance.image_integrity_ms,
            performance.signature_verification_ms,
            performance.process_signature_verification_ms,
            performance.module_signature_verification_ms,
            performance.signature_verify_concurrency,
            performance.target_scan_ms,
            performance.process_target_scan_ms,
            performance.module_target_scan_ms,
            performance.scan_cache_flush_ms,
            performance.module_references,
            performance.unique_module_paths,
            performance.unique_scan_paths,
            performance.signature_cache_hits,
            performance.signature_cache_misses,
            signature_timeouts,
            performance.process_signature_timeouts,
            performance.module_signature_timeouts,
            performance.module_enumeration_timeouts,
            performance.signature_coalesced_waiters,
            performance.signature_cache_uncacheable,
            performance.target_scan_cache_hits,
            performance.target_scan_cache_misses,
            performance.revocation_targets_scheduled
        );

        let result = SnapshotResult {
            baseline_complete: true,
            deep_scan_completed,
            deep_scan_pending_modules,
            deep_scan_pending_processes,
            total_processes: total,
            signed_processes: signed,
            unsigned_processes: unsigned,
            paused_processes: paused,
            scanned_modules,
            malicious_processes,
            malicious_modules,
            image_integrity_alerts,
            unsigned_module_alerts,
            masquerade_alerts,
            revocation_alerts,
            revocation_unknown_critical,
            unknown_processes,
            unknown_modules,
            module_enumeration_failures,
            module_enumeration_access_denied,
            cache_hits,
            performance,
            duration_ms: start_time.elapsed().as_millis() as u64,
        };

        // 保存结果 / Save result
        *self.last_result.lock().unwrap_or_else(|e| e.into_inner()) = Some(result.clone());

        // 通知前端完成 / Notify frontend of completion
        if !ctx.is_exiting() {
            let _ = ctx.emit_event("snapshot-result", result.clone());
        }

        // 尝试显示第一个拦截弹窗 / Try to show first interception modal
        if let Some(ref interception) = interception_ref {
            interception.try_show_next(ctx);
        }

        if !deep_scan_completed {
            spawn_startup_module_deep_checks(StartupModuleDeepCheckContext {
                trust: trust.clone(),
                engine: engine.clone(),
                cache: cache.clone(),
                last_result: self.last_result.clone(),
                active_run_id: self.revocation_run_id.clone(),
                run_id: revocation_run_id,
                interception: interception_ref.clone(),
                ctx: ctx.clone(),
                targets: all_modules_requiring_signature,
                deferred_processes: deferred_process_module_checks,
                path_policy,
                startup_signature_cache,
                startup_scan_results,
                module_signature_verify_timeout,
                module_enumeration_timeout,
                signature_verify_concurrency,
                target_scan_timeout,
                baseline_start_time: start_time,
                pending_modules: deep_scan_pending_modules,
                pending_processes: deep_scan_pending_processes,
            });
        }

        spawn_startup_revocation_checks(
            trust,
            self.last_result.clone(),
            self.revocation_run_id.clone(),
            revocation_run_id,
            interception_ref,
            ctx.clone(),
            revocation_targets,
            revocation_check_timeout,
            revocation_check_concurrency,
        );

        Ok(result)
    }

    /// 函数名称：get_last_result
    /// 函数作用：获取最后一次快照扫描结果。
    /// Purpose: Gets the last snapshot scan result.
    /// Called by: commands::snapshot::get_snapshot_result
    pub fn get_last_result(&self) -> Option<SnapshotResult> {
        self.last_result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// 进程基本信息 / Process basic info
enum StartupScanOutcome {
    Clean { cache_hit: bool },
    Malicious { cache_hit: bool },
    Skipped,
    Failed { error: String, cache_hit: bool },
}

impl StartupScanOutcome {
    fn started_scan(&self) -> bool {
        matches!(
            self,
            StartupScanOutcome::Clean { cache_hit: false }
                | StartupScanOutcome::Malicious { cache_hit: false }
                | StartupScanOutcome::Failed {
                    cache_hit: false,
                    ..
                }
        )
    }
}

#[derive(Debug, Clone)]
enum StartupScanCachedOutcome {
    Completed(CachedScanResult),
    Failed(String),
}

#[derive(Debug, Clone)]
struct TimedSignatureVerdict {
    trusted: bool,
    #[allow(dead_code)]
    status: i32,
    timed_out: bool,
}

#[derive(Debug, Clone)]
struct StartupTargetSnapshot {
    skip_reason: Option<&'static str>,
    scan_key: String,
    signature_cache_key: Option<String>,
    write_time_epoch_ms: Option<i64>,
}

impl StartupTargetSnapshot {
    fn is_scannable(&self) -> bool {
        self.skip_reason.is_none()
    }
}

#[derive(Debug, Clone)]
struct StartupModuleSignatureTarget {
    pid: u32,
    process_name: String,
    process_path: String,
    path: String,
    scan_key: String,
    target: StartupTargetSnapshot,
}

#[derive(Debug, Clone)]
struct StartupModuleSignatureResult {
    pid: u32,
    process_name: String,
    process_path: String,
    path: String,
    scan_key: String,
    signature_cache_key: Option<String>,
    verdict: TimedSignatureVerdict,
}

struct StartupModuleSignatureWaiter {
    order: usize,
    pid: u32,
    process_name: String,
    process_path: String,
    path: String,
    scan_key: String,
    signature_cache_key: Option<String>,
}

#[derive(Debug, Clone)]
struct StartupDeferredProcessModuleCheck {
    pid: u32,
    process_name: String,
    process_path: String,
    process_scan_key: String,
    process_path_scannable: bool,
    process_is_trusted: bool,
    process_target: StartupTargetSnapshot,
}

struct StartupModuleSignatureJob {
    path: String,
    cache_key: String,
    cacheable: bool,
}

struct StartupModuleSignatureCompleted {
    cache_key: String,
    cacheable: bool,
    verdict: TimedSignatureVerdict,
}

#[derive(Default)]
struct StartupSignatureCache {
    entries: HashMap<String, TimedSignatureVerdict>,
    hits: u32,
    misses: u32,
    coalesced_waiters: u32,
    uncacheable: u32,
}

struct StartupModuleDeepCheckContext {
    trust: Arc<TrustService>,
    engine: Arc<EngineService>,
    cache: Arc<ScanResultCacheService>,
    last_result: Arc<Mutex<Option<SnapshotResult>>>,
    active_run_id: Arc<AtomicU64>,
    run_id: u64,
    interception: Option<Arc<InterceptionService>>,
    ctx: SnapshotContext,
    targets: Vec<StartupModuleSignatureTarget>,
    deferred_processes: Vec<StartupDeferredProcessModuleCheck>,
    path_policy: PathPolicySnapshot,
    startup_signature_cache: StartupSignatureCache,
    startup_scan_results: HashMap<String, StartupScanCachedOutcome>,
    module_signature_verify_timeout: Duration,
    module_enumeration_timeout: Duration,
    signature_verify_concurrency: usize,
    target_scan_timeout: Duration,
    baseline_start_time: Instant,
    pending_modules: u32,
    pending_processes: u32,
}

impl StartupSignatureCache {
    /// 函数作用：同一轮启动快照内复用相同文件版本的签名结论，减少重复 DLL 签名验证。
    /// 安全边界：缓存键包含规范化路径、高精度修改时间和文件大小；无法读取文件版本信息时不缓存，避免文件替换后复用旧结论。
    async fn verify_file_for_target_async(
        &mut self,
        trust: Arc<TrustService>,
        file_path: &str,
        target: &StartupTargetSnapshot,
        timeout: Duration,
    ) -> TimedSignatureVerdict {
        let cache_key = target.signature_cache_key.clone();
        if let Some(key) = cache_key.as_ref() {
            if let Some(verdict) = self.entries.get(key) {
                self.hits = self.hits.saturating_add(1);
                return verdict.clone();
            }
        } else {
            self.uncacheable = self.uncacheable.saturating_add(1);
        }

        self.misses = self.misses.saturating_add(1);
        let verdict = verify_file_with_timeout_async(trust, file_path.to_string(), timeout).await;
        if let Some(key) = cache_key {
            self.entries.insert(key, verdict.clone());
        }
        verdict
    }

    /// 函数作用：同一轮启动快照内并发验证一批模块签名，减少多文件串行等待。
    /// 安全边界：每个目标仍然走同样的文件版本键缓存与超时逻辑；只是把独立文件的签名验证并行执行，不跳过任何验证。
    async fn verify_module_targets_concurrent(
        &mut self,
        trust: Arc<TrustService>,
        targets: Vec<StartupModuleSignatureTarget>,
        timeout: Duration,
        concurrency: usize,
    ) -> Vec<StartupModuleSignatureResult> {
        let max_concurrency = concurrency.max(1);
        let mut ordered_results: Vec<(usize, StartupModuleSignatureResult)> =
            Vec::with_capacity(targets.len());
        let mut pending = VecDeque::new();
        let mut waiting_by_cache_key: HashMap<String, Vec<StartupModuleSignatureWaiter>> =
            HashMap::new();

        for (order, target) in targets.into_iter().enumerate() {
            let cache_key = target.target.signature_cache_key.clone();
            if let Some(key) = cache_key.as_ref() {
                if let Some(verdict) = self.entries.get(key) {
                    self.hits = self.hits.saturating_add(1);
                    ordered_results.push((
                        order,
                        StartupModuleSignatureResult {
                            pid: target.pid,
                            process_name: target.process_name,
                            process_path: target.process_path,
                            path: target.path,
                            scan_key: target.scan_key,
                            signature_cache_key: Some(key.clone()),
                            verdict: verdict.clone(),
                        },
                    ));
                    continue;
                }

                let waiter = StartupModuleSignatureWaiter {
                    order,
                    pid: target.pid,
                    process_name: target.process_name,
                    process_path: target.process_path,
                    path: target.path.clone(),
                    scan_key: target.scan_key,
                    signature_cache_key: Some(key.clone()),
                };
                if let Some(waiters) = waiting_by_cache_key.get_mut(key) {
                    self.coalesced_waiters = self.coalesced_waiters.saturating_add(1);
                    waiters.push(waiter);
                    continue;
                }

                self.misses = self.misses.saturating_add(1);
                waiting_by_cache_key.insert(key.clone(), vec![waiter]);
                pending.push_back(StartupModuleSignatureJob {
                    path: target.path,
                    cache_key: key.clone(),
                    cacheable: true,
                });
            } else {
                self.uncacheable = self.uncacheable.saturating_add(1);
                self.misses = self.misses.saturating_add(1);
                let cache_key = format!("uncacheable|{}", order);
                waiting_by_cache_key.insert(
                    cache_key.clone(),
                    vec![StartupModuleSignatureWaiter {
                        order,
                        pid: target.pid,
                        process_name: target.process_name,
                        process_path: target.process_path,
                        path: target.path.clone(),
                        scan_key: target.scan_key,
                        signature_cache_key: None,
                    }],
                );
                pending.push_back(StartupModuleSignatureJob {
                    path: target.path,
                    cache_key,
                    cacheable: false,
                });
            }
        }

        let mut join_set = tokio::task::JoinSet::new();

        loop {
            while join_set.len() < max_concurrency {
                let Some(job) = pending.pop_front() else {
                    break;
                };
                let trust = trust.clone();
                join_set.spawn(async move {
                    let path_for_verify = job.path.clone();
                    let verdict =
                        verify_file_with_timeout_async(trust, path_for_verify, timeout).await;
                    StartupModuleSignatureCompleted {
                        cache_key: job.cache_key,
                        cacheable: job.cacheable,
                        verdict,
                    }
                });
            }

            let Some(joined) = join_set.join_next().await else {
                break;
            };

            match joined {
                Ok(completed) => {
                    if completed.cacheable {
                        self.entries
                            .insert(completed.cache_key.clone(), completed.verdict.clone());
                    }
                    if let Some(waiters) = waiting_by_cache_key.remove(&completed.cache_key) {
                        for waiter in waiters {
                            ordered_results.push((
                                waiter.order,
                                StartupModuleSignatureResult {
                                    pid: waiter.pid,
                                    process_name: waiter.process_name,
                                    process_path: waiter.process_path,
                                    path: waiter.path,
                                    scan_key: waiter.scan_key,
                                    signature_cache_key: waiter.signature_cache_key,
                                    verdict: completed.verdict.clone(),
                                },
                            ));
                        }
                    }
                }
                Err(_) => {}
            }
        }

        ordered_results.sort_by_key(|(order, _)| *order);
        ordered_results
            .into_iter()
            .map(|(_, result)| result)
            .collect()
    }

    #[cfg(test)]
    fn insert_for_test(
        &mut self,
        file_path: &str,
        verdict: TimedSignatureVerdict,
    ) -> Option<String> {
        let key = startup_signature_cache_key(file_path)?;
        self.entries.insert(key.clone(), verdict);
        Some(key)
    }

    #[cfg(test)]
    fn lookup_for_test(&self, file_path: &str) -> Option<TimedSignatureVerdict> {
        let key = startup_signature_cache_key(file_path)?;
        self.entries.get(&key).cloned()
    }
}

fn spawn_startup_module_deep_checks(context: StartupModuleDeepCheckContext) {
    tauri::async_runtime::spawn(async move {
        let StartupModuleDeepCheckContext {
            trust,
            engine,
            cache,
            last_result,
            active_run_id,
            run_id,
            interception,
            ctx,
            targets,
            deferred_processes,
            path_policy,
            mut startup_signature_cache,
            mut startup_scan_results,
            module_signature_verify_timeout,
            module_enumeration_timeout,
            signature_verify_concurrency,
            target_scan_timeout,
            baseline_start_time,
            pending_modules,
            pending_processes,
        } = context;

        let mut targets = targets;
        let deferred_process_start = Instant::now();
        let mut deferred_processes_checked: u32 = 0;
        let mut deferred_processes_clean: u32 = 0;
        let mut deferred_process_unknown_delta: u32 = 0;
        let mut deferred_module_enumeration_failures: u32 = 0;
        let mut deferred_module_enumeration_access_denied: u32 = 0;
        let mut deferred_module_enumeration_timeouts: u32 = 0;
        let mut deferred_module_target_unknown_delta: u32 = 0;
        let mut deferred_scanned_modules: u32 = 0;
        let mut deferred_unique_module_paths: HashSet<String> = HashSet::new();
        let mut image_integrity_alerts_delta: u32 = 0;
        let mut malicious_processes_delta: u32 = 0;
        let mut paused_processes_delta: u32 = 0;
        let mut scan_failures_delta: u32 = 0;
        let mut first_deferred_scan_failure: Option<String> = None;
        let mut process_target_scan_elapsed_ms: u64 = 0;
        let mut process_target_scan_cache_hits: u32 = 0;
        let mut process_target_scan_cache_misses: u32 = 0;

        for deferred in deferred_processes {
            deferred_processes_checked = deferred_processes_checked.saturating_add(1);
            let module_enumeration_start = Instant::now();
            let module_info = match enumerate_process_module_info_with_timeout(
                deferred.pid,
                module_enumeration_timeout,
            )
            .await
            {
                Ok(modules) => Some(modules),
                Err(err) => {
                    deferred_module_enumeration_failures =
                        deferred_module_enumeration_failures.saturating_add(1);
                    deferred_module_target_unknown_delta =
                        deferred_module_target_unknown_delta.saturating_add(1);
                    if module_enumeration_error_is_timeout(&err) {
                        deferred_module_enumeration_timeouts =
                            deferred_module_enumeration_timeouts.saturating_add(1);
                    }
                    if module_enumeration_error_is_access_denied(&err) {
                        deferred_module_enumeration_access_denied =
                            deferred_module_enumeration_access_denied.saturating_add(1);
                    }
                    None
                }
            };

            let module_targets = module_info
                .as_ref()
                .map(|modules| prepare_startup_module_targets(modules));
            if let Some(items) = module_targets.as_ref() {
                for module in items {
                    deferred_unique_module_paths.insert(module.scan_key.clone());
                }
            }

            let image_integrity_start = Instant::now();
            let image_integrity = detect_process_image_integrity_from_modules(
                deferred.pid,
                &deferred.process_path,
                module_info.as_ref(),
            );
            let image_integrity_elapsed = elapsed_ms(image_integrity_start);
            let process_image_clean = image_integrity.status == ProcessImageIntegrityStatus::Clean;
            match &image_integrity {
                ProcessImageIntegrityResult {
                    status: ProcessImageIntegrityStatus::Suspicious,
                    reason,
                    main_module_path,
                } => {
                    image_integrity_alerts_delta = image_integrity_alerts_delta.saturating_add(1);
                    if let Some(ref interception) = interception {
                        if enqueue_process_image_integrity_interception(
                            interception,
                            &ctx,
                            deferred.pid,
                            "startup_snapshot_deep",
                            &deferred.process_path,
                            main_module_path.as_deref(),
                            reason,
                            "high",
                        )
                        .is_enqueued()
                        {
                            paused_processes_delta = paused_processes_delta.saturating_add(1);
                        }
                    }
                }
                ProcessImageIntegrityResult {
                    status: ProcessImageIntegrityStatus::Unknown,
                    reason,
                    main_module_path,
                } => {
                    if deferred.process_path_scannable {
                        deferred_process_unknown_delta =
                            deferred_process_unknown_delta.saturating_add(1);
                    }
                    if startup_snapshot_debug_logging_enabled() {
                        eprintln!(
                            "[StartupSnapshot] Deferred process image integrity unknown PID={}, path={}, mainModule={:?}: {}",
                            deferred.pid, deferred.process_path, main_module_path, reason
                        );
                    }
                }
                ProcessImageIntegrityResult {
                    status: ProcessImageIntegrityStatus::Clean,
                    ..
                } => {
                    deferred_processes_clean = deferred_processes_clean.saturating_add(1);
                }
            }

            let module_chain_integrity =
                detect_module_chain_anomalies(deferred.pid, module_info.as_ref());
            let module_chain_clean =
                module_chain_integrity.status == ProcessImageIntegrityStatus::Clean;
            match &module_chain_integrity {
                ProcessImageIntegrityResult {
                    status: ProcessImageIntegrityStatus::Suspicious,
                    reason,
                    main_module_path,
                } => {
                    image_integrity_alerts_delta = image_integrity_alerts_delta.saturating_add(1);
                    if let Some(ref interception) = interception {
                        if enqueue_module_chain_anomaly_interception(
                            interception,
                            &ctx,
                            deferred.pid,
                            "startup_snapshot_deep",
                            &deferred.process_path,
                            main_module_path.as_deref(),
                            reason,
                        )
                        .is_enqueued()
                        {
                            paused_processes_delta = paused_processes_delta.saturating_add(1);
                        }
                    }
                }
                ProcessImageIntegrityResult {
                    status: ProcessImageIntegrityStatus::Unknown,
                    reason,
                    main_module_path,
                } => {
                    if deferred.process_path_scannable {
                        deferred_process_unknown_delta =
                            deferred_process_unknown_delta.saturating_add(1);
                    }
                    if startup_snapshot_debug_logging_enabled() {
                        eprintln!(
                            "[StartupSnapshot] Deferred module chain integrity unknown PID={}, path={}, sample={:?}: {}",
                            deferred.pid, deferred.process_path, main_module_path, reason
                        );
                    }
                }
                ProcessImageIntegrityResult {
                    status: ProcessImageIntegrityStatus::Clean,
                    ..
                } => {}
            }

            if deferred.process_path_scannable
                && (!deferred.process_is_trusted || !process_image_clean || !module_chain_clean)
            {
                let process_hash_decision = path_policy.hash_after_path_miss_cached(
                    &deferred.process_path,
                    deferred.process_target.signature_cache_key.as_deref(),
                );
                if !process_hash_decision.skip_scan {
                    let target_scan_start = Instant::now();
                    match scan_startup_target(
                        &engine,
                        &cache,
                        interception.as_ref(),
                        &ctx,
                        deferred.pid,
                        &deferred.process_name,
                        "process",
                        &deferred.process_path,
                        &deferred.process_target.scan_key,
                        deferred.process_target.signature_cache_key.as_deref(),
                        process_hash_decision.sha256_hex.as_deref(),
                        None,
                        &path_policy,
                        true,
                        &mut startup_scan_results,
                        target_scan_timeout,
                    )
                    .await
                    {
                        StartupScanOutcome::Malicious { cache_hit } => {
                            malicious_processes_delta = malicious_processes_delta.saturating_add(1);
                            paused_processes_delta = paused_processes_delta.saturating_add(1);
                            if cache_hit {
                                process_target_scan_cache_hits =
                                    process_target_scan_cache_hits.saturating_add(1);
                            } else {
                                process_target_scan_cache_misses =
                                    process_target_scan_cache_misses.saturating_add(1);
                            }
                        }
                        StartupScanOutcome::Clean { cache_hit } => {
                            if cache_hit {
                                process_target_scan_cache_hits =
                                    process_target_scan_cache_hits.saturating_add(1);
                            } else {
                                process_target_scan_cache_misses =
                                    process_target_scan_cache_misses.saturating_add(1);
                            }
                        }
                        StartupScanOutcome::Skipped => {}
                        StartupScanOutcome::Failed { error, cache_hit } => {
                            scan_failures_delta = scan_failures_delta.saturating_add(1);
                            if cache_hit {
                                process_target_scan_cache_hits =
                                    process_target_scan_cache_hits.saturating_add(1);
                            } else {
                                process_target_scan_cache_misses =
                                    process_target_scan_cache_misses.saturating_add(1);
                            }
                            if first_deferred_scan_failure.is_none() {
                                first_deferred_scan_failure = Some(error);
                            }
                        }
                    }
                    process_target_scan_elapsed_ms = process_target_scan_elapsed_ms
                        .saturating_add(elapsed_ms(target_scan_start));
                }
            }

            if let Some(module_targets) = module_targets {
                for module in module_targets {
                    deferred_scanned_modules = deferred_scanned_modules.saturating_add(1);
                    if startup_module_is_process_image(&module.scan_key, &deferred.process_scan_key)
                    {
                        continue;
                    }
                    if path_policy.should_skip_by_path_only(&module.path) {
                        continue;
                    }
                    let module_target =
                        inspect_startup_target_with_scan_key(&module.path, module.scan_key.clone());
                    if module_target.skip_reason.is_some() {
                        deferred_module_target_unknown_delta =
                            deferred_module_target_unknown_delta.saturating_add(1);
                        continue;
                    }
                    targets.push(StartupModuleSignatureTarget {
                        pid: deferred.pid,
                        process_name: deferred.process_name.clone(),
                        process_path: deferred.process_path.clone(),
                        path: module.path,
                        scan_key: module.scan_key,
                        target: module_target,
                    });
                }
            }

            let mut guard = last_result.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(result) = guard.as_mut() {
                result.performance.module_enumeration_ms = result
                    .performance
                    .module_enumeration_ms
                    .saturating_add(elapsed_ms(module_enumeration_start));
                result.performance.image_integrity_ms = result
                    .performance
                    .image_integrity_ms
                    .saturating_add(image_integrity_elapsed);
            }
        }

        let module_signature_start = Instant::now();
        let module_signature_target_count = targets.len();
        if startup_snapshot_debug_logging_enabled() {
            eprintln!(
                "[StartupSnapshot] Module signature batch start: {} targets, timeout={}ms",
                module_signature_target_count,
                module_signature_verify_timeout.as_millis()
            );
        }
        let verified_modules = startup_signature_cache
            .verify_module_targets_concurrent(
                trust.clone(),
                targets,
                module_signature_verify_timeout,
                signature_verify_concurrency,
            )
            .await;
        let signature_elapsed = elapsed_ms(module_signature_start);
        if startup_snapshot_debug_logging_enabled() {
            eprintln!(
                "[StartupSnapshot] Module signature batch done: {} targets, {} verified, {} cache hits, {} cache misses, {} waiters coalesced",
                module_signature_target_count,
                verified_modules.len(),
                startup_signature_cache.hits,
                startup_signature_cache.misses,
                startup_signature_cache.coalesced_waiters
            );
        }

        let module_scan_batch_start = Instant::now();
        let mut module_scan_batch_count: u32 = 0;
        let mut module_scan_started: u32 = 0;
        let module_scan_total = verified_modules.len();
        let mut module_scan_last_progress = Instant::now();
        let mut malicious_modules: u32 = 0;
        let mut unsigned_module_alerts: u32 = 0;
        let mut unknown_modules_delta: u32 = 0;
        let mut cache_hits: u32 = 0;
        let mut target_scan_cache_hits: u32 = 0;
        let mut target_scan_cache_misses: u32 = 0;
        let mut module_signature_timeouts: u32 = 0;
        let mut first_scan_failure: Option<String> = None;
        let mut module_target_scan_elapsed_ms: u64 = 0;
        let deep_scan_start = Instant::now();

        if startup_snapshot_debug_logging_enabled() {
            eprintln!(
                "[StartupSnapshot] Module scan batch start: {} verified modules",
                module_scan_total
            );
        }
        for module_result in verified_modules {
            module_scan_batch_count += 1;
            if startup_snapshot_debug_logging_enabled()
                && (module_scan_batch_count == 1
                    || module_scan_batch_count % 250 == 0
                    || module_scan_last_progress.elapsed() >= Duration::from_secs(30))
            {
                module_scan_last_progress = Instant::now();
                eprintln!(
                    "[StartupSnapshot] Module scan batch progress: {}/{} verified modules, {} scans started, {} cache hits, {} cache misses, {}ms elapsed",
                    module_scan_batch_count,
                    module_scan_total,
                    module_scan_started,
                    target_scan_cache_hits,
                    target_scan_cache_misses,
                    elapsed_ms(module_scan_batch_start)
                );
            }

            let module_pid = module_result.pid;
            let module_process_name = module_result.process_name;
            let module_process_path = module_result.process_path;
            let module_path = module_result.path;
            let module_scan_key = module_result.scan_key;
            let module_signature_cache_key = module_result.signature_cache_key;
            let module_verdict = module_result.verdict;
            let module_signature_timed_out = module_verdict.timed_out;
            if module_verdict.timed_out {
                module_signature_timeouts += 1;
            }
            match module_verdict.trusted {
                true => {
                    continue;
                }
                false => {
                    let module_signature_untrusted =
                        should_count_unsigned_signature(&module_verdict);
                    let mut module_should_remain_unknown = module_signature_timed_out;
                    let module_hash_decision = path_policy.hash_after_path_miss_cached(
                        &module_path,
                        module_signature_cache_key.as_deref(),
                    );
                    if module_hash_decision.skip_scan {
                        if module_should_remain_unknown {
                            unknown_modules_delta = unknown_modules_delta.saturating_add(1);
                        }
                        continue;
                    }
                    let target_scan_start = Instant::now();
                    let scan_outcome = scan_startup_target(
                        &engine,
                        &cache,
                        interception.as_ref(),
                        &ctx,
                        module_pid,
                        &module_process_name,
                        "module",
                        &module_path,
                        &module_scan_key,
                        module_signature_cache_key.as_deref(),
                        module_hash_decision.sha256_hex.as_deref(),
                        Some(&module_process_path),
                        &path_policy,
                        true,
                        &mut startup_scan_results,
                        target_scan_timeout,
                    )
                    .await;
                    if scan_outcome.started_scan() {
                        module_scan_started += 1;
                    }
                    let mut module_scan_was_malicious = false;
                    let mut module_scan_confirmed_clean = false;
                    match scan_outcome {
                        StartupScanOutcome::Malicious { cache_hit } => {
                            module_scan_was_malicious = true;
                            malicious_modules += 1;
                            if cache_hit {
                                cache_hits += 1;
                                target_scan_cache_hits += 1;
                            } else {
                                target_scan_cache_misses += 1;
                            }
                        }
                        StartupScanOutcome::Clean { cache_hit } => {
                            module_scan_confirmed_clean = true;
                            if cache_hit {
                                cache_hits += 1;
                                target_scan_cache_hits += 1;
                            } else {
                                target_scan_cache_misses += 1;
                            }
                        }
                        StartupScanOutcome::Skipped => {}
                        StartupScanOutcome::Failed { error, cache_hit } => {
                            if cache_hit {
                                cache_hits += 1;
                                target_scan_cache_hits += 1;
                            } else {
                                target_scan_cache_misses += 1;
                            }
                            if first_scan_failure.is_none() {
                                first_scan_failure = Some(error);
                            }
                            module_should_remain_unknown = true;
                        }
                    }
                    module_target_scan_elapsed_ms =
                        module_target_scan_elapsed_ms.saturating_add(elapsed_ms(target_scan_start));
                    if module_signature_untrusted && !module_scan_was_malicious {
                        module_should_remain_unknown = true;
                        if startup_snapshot_debug_logging_enabled() {
                            eprintln!(
                                "[StartupSnapshot] Unsigned module observed without malware verdict PID={}, process={}, module={}, scanClean={}",
                                module_pid, module_process_name, module_path, module_scan_confirmed_clean
                            );
                        }
                    }
                    if module_signature_untrusted && !module_scan_was_malicious {
                        unsigned_module_alerts = unsigned_module_alerts.saturating_add(1);
                        if startup_snapshot_debug_logging_enabled() {
                            eprintln!(
                                "[StartupSnapshot] Unsigned module kept as alert-only PID={}, process={}, module={}, scanClean={}",
                                module_pid, module_process_name, module_path, module_scan_confirmed_clean
                            );
                        }
                    }
                    if module_should_remain_unknown {
                        unknown_modules_delta = unknown_modules_delta.saturating_add(1);
                    }
                }
            }
        }
        if startup_snapshot_debug_logging_enabled() {
            eprintln!(
                "[StartupSnapshot] Module scan batch done: {} verified modules, {} scans started, {}ms",
                module_scan_batch_count,
                module_scan_started,
                elapsed_ms(module_scan_batch_start)
            );
        }

        if active_run_id.load(Ordering::Relaxed) != run_id {
            eprintln!(
                "[StartupSnapshot] Dropping stale deep scan result for run {}",
                run_id
            );
            return;
        }

        let scan_cache_flush_start = Instant::now();
        if let Err(err) = cache.flush_pending() {
            eprintln!("[StartupSnapshot] Failed to persist scan cache: {}", err);
        }
        let scan_cache_flush_elapsed = elapsed_ms(scan_cache_flush_start);
        let deep_scan_elapsed = elapsed_ms(deep_scan_start);
        let deferred_process_elapsed = elapsed_ms(deferred_process_start);
        let total_elapsed = elapsed_ms(baseline_start_time);
        let updated = {
            let mut guard = last_result.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(result) = guard.as_mut() {
                result.deep_scan_completed = true;
                result.deep_scan_pending_modules = 0;
                result.deep_scan_pending_processes = 0;
                result.signed_processes = result
                    .signed_processes
                    .saturating_add(deferred_processes_clean);
                result.paused_processes = result
                    .paused_processes
                    .saturating_add(paused_processes_delta);
                result.malicious_processes = result
                    .malicious_processes
                    .saturating_add(malicious_processes_delta);
                result.image_integrity_alerts = result
                    .image_integrity_alerts
                    .saturating_add(image_integrity_alerts_delta);
                result.unknown_processes = result
                    .unknown_processes
                    .saturating_sub(pending_processes)
                    .saturating_add(deferred_process_unknown_delta);
                result.unknown_modules = result
                    .unknown_modules
                    .saturating_sub(pending_modules)
                    .saturating_add(deferred_module_target_unknown_delta)
                    .saturating_add(unknown_modules_delta);
                result.scanned_modules = result
                    .scanned_modules
                    .saturating_add(deferred_scanned_modules);
                result.module_enumeration_failures = result
                    .module_enumeration_failures
                    .saturating_add(deferred_module_enumeration_failures);
                result.module_enumeration_access_denied = result
                    .module_enumeration_access_denied
                    .saturating_add(deferred_module_enumeration_access_denied);
                result.malicious_modules =
                    result.malicious_modules.saturating_add(malicious_modules);
                result.unsigned_module_alerts = result
                    .unsigned_module_alerts
                    .saturating_add(unsigned_module_alerts);
                result.cache_hits = result
                    .cache_hits
                    .saturating_add(cache_hits)
                    .saturating_add(process_target_scan_cache_hits);
                result.performance.signature_verification_ms = result
                    .performance
                    .signature_verification_ms
                    .saturating_add(signature_elapsed);
                result.performance.module_signature_verification_ms = result
                    .performance
                    .module_signature_verification_ms
                    .saturating_add(signature_elapsed);
                result.performance.target_scan_ms = result
                    .performance
                    .target_scan_ms
                    .saturating_add(module_target_scan_elapsed_ms)
                    .saturating_add(process_target_scan_elapsed_ms);
                result.performance.process_target_scan_ms = result
                    .performance
                    .process_target_scan_ms
                    .saturating_add(process_target_scan_elapsed_ms);
                result.performance.module_target_scan_ms = result
                    .performance
                    .module_target_scan_ms
                    .saturating_add(module_target_scan_elapsed_ms);
                result.performance.scan_cache_flush_ms = result
                    .performance
                    .scan_cache_flush_ms
                    .saturating_add(scan_cache_flush_elapsed);
                result.performance.signature_cache_hits = startup_signature_cache.hits;
                result.performance.signature_cache_misses = startup_signature_cache.misses;
                result.performance.signature_coalesced_waiters =
                    startup_signature_cache.coalesced_waiters;
                result.performance.signature_cache_uncacheable =
                    startup_signature_cache.uncacheable;
                result.performance.module_signature_timeouts = result
                    .performance
                    .module_signature_timeouts
                    .saturating_add(module_signature_timeouts);
                result.performance.module_references = result
                    .performance
                    .module_references
                    .saturating_add(deferred_scanned_modules);
                result.performance.unique_module_paths = result
                    .performance
                    .unique_module_paths
                    .saturating_add(deferred_unique_module_paths.len() as u32);
                result.performance.unique_scan_paths = startup_scan_results.len() as u32;
                result.performance.module_enumeration_timeouts = result
                    .performance
                    .module_enumeration_timeouts
                    .saturating_add(deferred_module_enumeration_timeouts);
                result.performance.target_scan_cache_hits = result
                    .performance
                    .target_scan_cache_hits
                    .saturating_add(target_scan_cache_hits)
                    .saturating_add(process_target_scan_cache_hits);
                result.performance.target_scan_cache_misses = result
                    .performance
                    .target_scan_cache_misses
                    .saturating_add(target_scan_cache_misses)
                    .saturating_add(process_target_scan_cache_misses);
                result.performance.deep_scan_duration_ms = deep_scan_elapsed;
                result.duration_ms = total_elapsed;
                Some(result.clone())
            } else {
                None
            }
        };

        if let Some(error) = first_deferred_scan_failure {
            eprintln!(
                "[StartupSnapshot] First deferred process scan failure: {}",
                error
            );
        }
        if let Some(error) = first_scan_failure {
            eprintln!(
                "[StartupSnapshot] First deep module scan failure: {}",
                error
            );
        }
        eprintln!(
            "[StartupSnapshot] Deep checks done: {} deferred processes, {} deferred clean, {} modules, {} malicious modules, {} unsigned module alerts, {} still unknown modules, {} process scan failures, {} module scans started, {} cache hits, {} cache misses, {}ms deferred process phase, {}ms background, {}ms total",
            deferred_processes_checked,
            deferred_processes_clean,
            module_scan_batch_count,
            malicious_modules,
            unsigned_module_alerts,
            unknown_modules_delta.saturating_add(deferred_module_target_unknown_delta),
            scan_failures_delta,
            module_scan_started,
            target_scan_cache_hits + process_target_scan_cache_hits,
            target_scan_cache_misses + process_target_scan_cache_misses,
            deferred_process_elapsed,
            deep_scan_elapsed,
            total_elapsed
        );

        if let Some(result) = updated {
            if !ctx.is_exiting() {
                let _ = ctx.emit_event("snapshot-result", result.clone());
            }
        }

        if let Some(interception) = interception.as_ref() {
            interception.try_show_next(&ctx);
        }
    });
}

fn should_count_unsigned_signature(verdict: &TimedSignatureVerdict) -> bool {
    !verdict.trusted && !verdict.timed_out
}

fn should_enqueue_unsigned_signature(
    _verdict: &TimedSignatureVerdict,
    _image_suspicious: bool,
) -> bool {
    // 未签名只说明“身份不明”，不是可以冻结进程的强证据。
    // 恶意扫描命中、证书吊销、伪装路径或映像完整性异常会走各自的强证据入队路径。
    false
}

/// 函数作用：判断某个进程的模块枚举和主映像完整性检查是否可以后移到后台深度阶段。
/// 安全边界：只有非关键系统进程、主路径可扫描、主文件签名已真实可信时才后移；Unknown、超时、未签名和关键进程仍留在启动基线内。
fn should_defer_startup_process_module_checks(
    masquerade_verdict: &MasqueradeVerdict,
    process_path_scannable: bool,
    process_is_trusted: bool,
) -> bool {
    matches!(masquerade_verdict, MasqueradeVerdict::NotApplicable)
        && process_path_scannable
        && process_is_trusted
}

fn startup_module_signature_verify_timeout(
    base_timeout: Duration,
    target_scan_timeout: Duration,
) -> Duration {
    base_timeout
        .saturating_mul(STARTUP_MODULE_SIGNATURE_TIMEOUT_MULTIPLIER)
        .min(target_scan_timeout)
        .max(base_timeout)
}

/// 函数作用：把启动签名验证并发配置解析成实际运行值。
/// 业务含义：配置为 0 时使用本机逻辑处理器数量，让高配机器自动开更多“签名验证窗口”。
/// 安全边界：这里只影响同时验证多少个文件，不改变签名可信条件；读取失败时回到旧的保守并发值。
fn resolve_startup_signature_verify_concurrency(configured: usize) -> usize {
    if configured > 0 {
        return configured;
    }

    std::thread::available_parallelism()
        .map(|parallelism| parallelism.get().max(1))
        .unwrap_or(FALLBACK_STARTUP_SIGNATURE_VERIFY_CONCURRENCY)
}

#[derive(Debug, Clone)]
struct RevocationCheckTarget {
    pid: u32,
    process_name: String,
    path: String,
    path_scan_key: String,
    write_time: Option<i64>,
    critical: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RevocationCheckVerdict {
    Trusted,
    Revoked { status: i32 },
    Unknown { status: i32 },
}

#[derive(Debug)]
enum RevocationCheckOutcome {
    Trusted,
    Revoked {
        target: RevocationCheckTarget,
        status: i32,
    },
    Unknown {
        target: RevocationCheckTarget,
        status: i32,
    },
    ImageChanged {
        target: RevocationCheckTarget,
        current_path: Option<String>,
        current_write_time: Option<i64>,
    },
    TaskFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MasqueradeVerdict {
    NotApplicable,
    Clean,
    Unknown,
    Suspicious {
        expected: Vec<String>,
        actual: String,
    },
}

struct CriticalProcessRule {
    name: &'static str,
    expected_dirs: &'static [&'static str],
}

const CRITICAL_PROCESS_RULES: &[CriticalProcessRule] = &[
    CriticalProcessRule {
        name: "svchost.exe",
        expected_dirs: &["%SystemRoot%\\System32\\", "%SystemRoot%\\SysWOW64\\"],
    },
    CriticalProcessRule {
        name: "csrss.exe",
        expected_dirs: &["%SystemRoot%\\System32\\"],
    },
    CriticalProcessRule {
        name: "lsass.exe",
        expected_dirs: &["%SystemRoot%\\System32\\"],
    },
    CriticalProcessRule {
        name: "winlogon.exe",
        expected_dirs: &["%SystemRoot%\\System32\\"],
    },
    CriticalProcessRule {
        name: "services.exe",
        expected_dirs: &["%SystemRoot%\\System32\\"],
    },
    CriticalProcessRule {
        name: "smss.exe",
        expected_dirs: &["%SystemRoot%\\System32\\"],
    },
    CriticalProcessRule {
        name: "wininit.exe",
        expected_dirs: &["%SystemRoot%\\System32\\"],
    },
    CriticalProcessRule {
        name: "explorer.exe",
        expected_dirs: &["%SystemRoot%\\"],
    },
];

fn detect_process_masquerade(process_name: &str, process_path: &str) -> MasqueradeVerdict {
    let normalized_name = process_name.trim().to_ascii_lowercase();
    let Some(rule) = CRITICAL_PROCESS_RULES
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(&normalized_name))
    else {
        return MasqueradeVerdict::NotApplicable;
    };

    let expected_dirs = expanded_expected_dirs(rule);
    let expected_paths: Vec<String> = expected_dirs
        .iter()
        .map(|dir| format!("{}{}", dir, rule.name))
        .collect();
    let actual = normalize_security_path(process_path);
    if !security_path_is_absolute(&actual) {
        return MasqueradeVerdict::Unknown;
    }

    let actual_file_name = security_file_name(&actual);
    let actual_parent = security_parent_dir(&actual);

    let path_matches = actual_file_name
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case(rule.name))
        && actual_parent
            .as_deref()
            .is_some_and(|parent| expected_dirs.iter().any(|expected| parent == expected));

    if path_matches {
        MasqueradeVerdict::Clean
    } else {
        MasqueradeVerdict::Suspicious {
            expected: expected_paths,
            actual,
        }
    }
}

fn should_schedule_process_revocation_check(
    process_name: &str,
    process_path: &str,
    process_path_scannable: bool,
    process_is_trusted: bool,
    process_image_clean: bool,
) -> bool {
    process_path_scannable
        && process_is_trusted
        && process_image_clean
        && matches!(
            detect_process_masquerade(process_name, process_path),
            MasqueradeVerdict::Clean
        )
}

fn classify_revocation_verdict(
    verdict: Result<SignatureVerdict, String>,
) -> RevocationCheckVerdict {
    match verdict {
        Ok(verdict) if verdict.trusted => RevocationCheckVerdict::Trusted,
        Ok(verdict) if is_certificate_revoked_status(verdict.status) => {
            RevocationCheckVerdict::Revoked {
                status: verdict.status,
            }
        }
        Ok(verdict) => RevocationCheckVerdict::Unknown {
            status: verdict.status,
        },
        Err(_) => RevocationCheckVerdict::Unknown { status: -1 },
    }
}

fn is_certificate_revoked_status(status: i32) -> bool {
    let status = status as u32;
    status == CERT_E_REVOKED || status == CRYPT_E_REVOKED
}

fn validate_revocation_target_unchanged(
    target: &RevocationCheckTarget,
) -> Result<(), RevocationCheckOutcome> {
    let current_path = query_process_image_path(target.pid);
    let path_matches = current_path
        .as_deref()
        .is_some_and(|path| startup_scan_key(path) == target.path_scan_key.as_str());
    let current_write_time = current_path.as_deref().and_then(file_write_time_epoch_ms);
    let write_time_matches = target.write_time.is_some()
        && current_write_time.is_some()
        && current_write_time == target.write_time;

    if path_matches && write_time_matches {
        Ok(())
    } else {
        Err(RevocationCheckOutcome::ImageChanged {
            target: target.clone(),
            current_path,
            current_write_time,
        })
    }
}

async fn check_revocation_target(
    trust: Arc<TrustService>,
    target: RevocationCheckTarget,
    timeout: Duration,
    semaphore: Arc<tokio::sync::Semaphore>,
) -> RevocationCheckOutcome {
    if let Err(outcome) = validate_revocation_target_unchanged(&target) {
        return outcome;
    }

    let path = target.path.clone();
    let verdict = match tokio::time::timeout(timeout, async move {
        let Ok(permit) = semaphore.acquire_owned().await else {
            return RevocationCheckVerdict::Unknown { status: -1 };
        };
        match tokio::task::spawn_blocking(move || {
            let _permit = permit;
            trust.verify_file_with_revocation(&path)
        })
        .await
        {
            Ok(result) => classify_revocation_verdict(result),
            Err(_) => RevocationCheckVerdict::Unknown { status: -1 },
        }
    })
    .await
    {
        Ok(verdict) => verdict,
        Err(_) => RevocationCheckVerdict::Unknown { status: -1 },
    };

    match verdict {
        RevocationCheckVerdict::Trusted => RevocationCheckOutcome::Trusted,
        RevocationCheckVerdict::Revoked { status } => {
            RevocationCheckOutcome::Revoked { target, status }
        }
        RevocationCheckVerdict::Unknown { status } => {
            RevocationCheckOutcome::Unknown { target, status }
        }
    }
}

fn expanded_expected_dirs(rule: &CriticalProcessRule) -> Vec<String> {
    let system_root = system_root_for_security_paths();
    rule.expected_dirs
        .iter()
        .map(|dir| dir.replace("%SystemRoot%", &system_root))
        .map(|dir| normalize_security_dir(&dir))
        .collect()
}

fn system_root_for_security_paths() -> String {
    std::env::var("SystemRoot")
        .or_else(|_| std::env::var("WINDIR"))
        .unwrap_or_else(|_| "C:\\Windows".to_string())
        .trim_end_matches(['\\', '/'])
        .to_string()
}

fn normalize_security_path(path: &str) -> String {
    let trimmed = path.trim();
    let without_prefix = trimmed
        .strip_prefix(r"\\?\")
        .or_else(|| trimmed.strip_prefix(r"\??\"))
        .unwrap_or(trimmed);
    without_prefix.replace('/', "\\").to_ascii_lowercase()
}

fn security_path_is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}

fn normalize_security_dir(path: &str) -> String {
    let mut normalized = normalize_security_path(path);
    while normalized.ends_with('\\') {
        normalized.pop();
    }
    normalized.push('\\');
    normalized
}

fn security_file_name(path: &str) -> Option<String> {
    path.rsplit('\\')
        .next()
        .filter(|name| !name.is_empty())
        .map(|name| name.to_string())
}

fn security_parent_dir(path: &str) -> Option<String> {
    let index = path.rfind('\\')?;
    Some(normalize_security_dir(&path[..index]))
}

fn file_write_time_epoch_ms(file_path: &str) -> Option<i64> {
    let modified = std::fs::metadata(file_path).ok()?.modified().ok()?;
    let duration = modified.duration_since(UNIX_EPOCH).ok()?;
    Some(duration.as_millis() as i64)
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

/// 函数作用：在 Tokio 阻塞线程池中限时执行签名验证，供启动快照进程和模块签名批处理使用。
/// 安全边界：超时、任务失败或验证错误仍返回不可信/Unknown；不会把未完成验证的目标加入可信基线。
async fn verify_file_with_timeout_async(
    trust: Arc<TrustService>,
    file_path: String,
    timeout: Duration,
) -> TimedSignatureVerdict {
    match tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || trust.verify_file(&file_path)),
    )
    .await
    {
        Ok(Ok(Ok(verdict))) => TimedSignatureVerdict {
            trusted: verdict.trusted,
            status: verdict.status,
            timed_out: false,
        },
        Ok(Ok(Err(_))) | Ok(Err(_)) => TimedSignatureVerdict {
            trusted: false,
            status: -1,
            timed_out: false,
        },
        Err(_) => TimedSignatureVerdict {
            trusted: false,
            status: -1,
            timed_out: true,
        },
    }
}

/// 函数作用：在 Tokio 阻塞线程池中限时枚举进程模块，避免单个卡住的 PID 拖慢整轮启动快照。
/// 安全边界：超时或任务失败都返回错误，调用方会计入模块 Unknown；不会把未枚举模块的进程加入可信基线。
async fn enumerate_process_module_info_with_timeout(
    pid: u32,
    timeout: Duration,
) -> Result<Vec<ProcessModuleInfo>, String> {
    match tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || enumerate_process_module_info(pid)),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => Err(format!("module enumeration task failed: {}", err)),
        Err(_) => Err(format!(
            "module enumeration timed out after {}ms",
            timeout.as_millis()
        )),
    }
}

fn spawn_startup_revocation_checks(
    trust: Arc<TrustService>,
    last_result: Arc<Mutex<Option<SnapshotResult>>>,
    active_run_id: Arc<AtomicU64>,
    run_id: u64,
    interception: Option<Arc<InterceptionService>>,
    ctx: SnapshotContext,
    targets: Vec<RevocationCheckTarget>,
    timeout: Duration,
    concurrency: usize,
) {
    if targets.is_empty() {
        return;
    }

    tauri::async_runtime::spawn(async move {
        let mut revoked = Vec::new();
        let mut image_changed = Vec::new();
        let mut unknown_critical: u32 = 0;
        let mut join_set = tokio::task::JoinSet::new();
        let mut target_iter = targets.into_iter();
        let max_concurrency = concurrency.max(1);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrency));

        loop {
            while join_set.len() < max_concurrency {
                let Some(target) = target_iter.next() else {
                    break;
                };
                join_set.spawn(check_revocation_target(
                    trust.clone(),
                    target,
                    timeout,
                    semaphore.clone(),
                ));
            }

            let Some(joined) = join_set.join_next().await else {
                break;
            };

            let outcome = match joined {
                Ok(outcome) => outcome,
                Err(_) => RevocationCheckOutcome::TaskFailed,
            };

            match outcome {
                RevocationCheckOutcome::Trusted => {}
                RevocationCheckOutcome::Revoked { target, status } => {
                    eprintln!(
                        "[StartupSnapshot] Certificate revocation confirmed PID={}, path={}, status=0x{:08X}",
                        target.pid,
                        target.path,
                        status as u32
                    );
                    revoked.push((target, status));
                }
                RevocationCheckOutcome::Unknown { target, status } => {
                    if target.critical {
                        unknown_critical += 1;
                    }
                    eprintln!(
                        "[StartupSnapshot] Certificate revocation unknown PID={}, path={}, status=0x{:08X}",
                        target.pid,
                        target.path,
                        status as u32
                    );
                }
                RevocationCheckOutcome::ImageChanged {
                    target,
                    current_path,
                    current_write_time,
                } => {
                    eprintln!(
                        "[StartupSnapshot] Revocation target changed before check PID={}, originalPath={}, currentPath={:?}, originalWriteTime={:?}, currentWriteTime={:?}",
                        target.pid,
                        target.path,
                        current_path,
                        target.write_time,
                        current_write_time
                    );
                    image_changed.push((target, current_path, current_write_time));
                }
                RevocationCheckOutcome::TaskFailed => {
                    unknown_critical += 1;
                    eprintln!("[StartupSnapshot] Certificate revocation task failed");
                }
            }
        }

        if active_run_id.load(Ordering::Relaxed) != run_id {
            eprintln!(
                "[StartupSnapshot] Dropping stale revocation result for run {}",
                run_id
            );
            return;
        }

        if let Some(interception) = interception.as_ref() {
            for (target, status) in &revoked {
                enqueue_certificate_revocation_interception(
                    interception,
                    &ctx,
                    target.pid,
                    &target.process_name,
                    &target.path,
                    *status,
                );
            }
            for (target, current_path, current_write_time) in &image_changed {
                enqueue_revocation_target_changed_interception(
                    interception,
                    &ctx,
                    target,
                    current_path.as_deref(),
                    *current_write_time,
                );
            }
        }

        let updated = {
            let mut guard = last_result.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(result) = guard.as_mut() {
                result.revocation_alerts = result
                    .revocation_alerts
                    .saturating_add(revoked.len() as u32);
                result.revocation_unknown_critical = result
                    .revocation_unknown_critical
                    .saturating_add(unknown_critical)
                    .saturating_add(image_changed.len() as u32);
                Some(result.clone())
            } else {
                None
            }
        };

        if let Some(result) = updated {
            if !ctx.is_exiting() {
                let _ = ctx.emit_event("snapshot-result", result.clone());
            }
        }

        if let Some(interception) = interception.as_ref() {
            interception.try_show_next(&ctx);
        }
    });
}

/// 函数名称：scan_startup_target
/// 函数作用：启动快照中扫描进程文件或加载模块，复用持久化扫描缓存，并在恶意结果时入拦截队列。
/// Function name: scan_startup_target
/// Purpose: Scans a process file or loaded module during startup snapshot, reuses in-memory and persistent scan cache, and enqueues malware results.
/// 调用方：SnapshotService::take_startup_snapshot。
/// Called by: SnapshotService::take_startup_snapshot.
/// 被调用方：PathPolicySnapshot::should_skip_security_scan、ScanResultCacheService::scan_or_get_cached_deferred、InterceptionService。
/// Calls: PathPolicySnapshot::should_skip_security_scan, ScanResultCacheService::scan_or_get_cached_deferred, InterceptionService.
/// 副作用：可能更新延迟扫描缓存并推送 process-intercepted 事件。
/// Side effects: May update deferred scan cache and emit process-intercepted events.
async fn scan_startup_target(
    engine: &Arc<EngineService>,
    cache: &Arc<ScanResultCacheService>,
    interception: Option<&Arc<InterceptionService>>,
    ctx: &SnapshotContext,
    pid: u32,
    process_name: &str,
    target_type: &str,
    target_path: &str,
    _target_scan_key: &str,
    target_version_key: Option<&str>,
    precomputed_sha256_hex: Option<&str>,
    process_path: Option<&str>,
    path_policy: &PathPolicySnapshot,
    policy_already_checked: bool,
    startup_scan_results: &mut HashMap<String, StartupScanCachedOutcome>,
    target_scan_timeout: Duration,
) -> StartupScanOutcome {
    let target_scan_start = Instant::now();
    let debug_logging = startup_snapshot_debug_logging_enabled();
    if !policy_already_checked && path_policy.should_skip_security_scan_cached(target_path, None) {
        if debug_logging {
            eprintln!(
                "[StartupSnapshot] Target scan detail: targetType={}, PID={}, path={}, outcome=skipped, source=path-policy, elapsedMs={}, versionKeyAvailable={}",
                target_type,
                pid,
                target_path,
                elapsed_ms(target_scan_start),
                target_version_key.is_some()
            );
        }
        return StartupScanOutcome::Skipped;
    }

    let startup_cache_key = target_version_key.map(startup_scan_cache_key);
    let cached_result = startup_cache_key
        .as_ref()
        .and_then(|key| startup_scan_results.get(key))
        .cloned();
    let snapshot_cache_hit = cached_result.is_some();

    let scan_result: Result<CachedScanResult, (String, bool)> = match cached_result {
        Some(StartupScanCachedOutcome::Completed(mut result)) => {
            result.cache_hit = true;
            Ok(result)
        }
        Some(StartupScanCachedOutcome::Failed(error)) => Err((error, true)),
        None => match tokio::time::timeout(
            target_scan_timeout,
            cache.scan_or_get_cached_deferred_with_hash(
                engine,
                target_path,
                precomputed_sha256_hex.filter(|_| target_version_key.is_some()),
            ),
        )
        .await
        {
            Err(_) => {
                let error = format!("scan timed out after {}ms", target_scan_timeout.as_millis());
                if let Some(key) = startup_cache_key.as_ref() {
                    startup_scan_results
                        .insert(key.clone(), StartupScanCachedOutcome::Failed(error.clone()));
                }
                Err((error, false))
            }
            Ok(Ok(result)) => {
                if let Some(key) = startup_cache_key.as_ref() {
                    startup_scan_results.insert(
                        key.clone(),
                        StartupScanCachedOutcome::Completed(result.clone()),
                    );
                }
                Ok(result)
            }
            Ok(Err(err)) => {
                if let Some(key) = startup_cache_key.as_ref() {
                    startup_scan_results
                        .insert(key.clone(), StartupScanCachedOutcome::Failed(err.clone()));
                }
                Err((err, false))
            }
        },
    };
    match scan_result {
        Ok(scan_result) => {
            let is_malware = scan_result_is_malware(&scan_result.raw_result);
            let elapsed = elapsed_ms(target_scan_start);
            if should_log_startup_target_scan_detail(
                debug_logging,
                elapsed,
                snapshot_cache_hit,
                scan_result.cache_hit,
                is_malware,
            ) {
                eprintln!(
                    "[StartupSnapshot] Target scan detail: targetType={}, PID={}, path={}, outcome={}, source={}, elapsedMs={}, cacheHit={}, versionKeyAvailable={}, hashPrefix={}",
                    target_type,
                    pid,
                    target_path,
                    if is_malware { "malicious" } else { "clean" },
                    startup_target_scan_source(snapshot_cache_hit, scan_result.cache_hit),
                    elapsed,
                    scan_result.cache_hit,
                    target_version_key.is_some(),
                    short_hash_prefix(&scan_result.hash_hex)
                );
            }
            if is_malware {
                eprintln!(
                    "[StartupSnapshot] MALWARE DETECTED targetType={}, PID={}, path={}, confidence={}, cacheHit={}",
                    target_type,
                    pid,
                    target_path,
                    scan_confidence(&scan_result.raw_result),
                    scan_result.cache_hit
                );
                if let Some(interception) = interception {
                    enqueue_startup_scan_interception(
                        interception,
                        ctx,
                        pid,
                        process_name,
                        target_type,
                        target_path,
                        process_path,
                        &scan_result,
                    );
                }
                StartupScanOutcome::Malicious {
                    cache_hit: scan_result.cache_hit,
                }
            } else {
                StartupScanOutcome::Clean {
                    cache_hit: scan_result.cache_hit,
                }
            }
        }
        Err((err, cache_hit)) => {
            let elapsed = elapsed_ms(target_scan_start);
            let error = format!(
                "targetType={}, PID={}, path={}: {}",
                target_type, pid, target_path, err
            );
            if debug_logging {
                eprintln!(
                    "[StartupSnapshot] Target scan detail: targetType={}, PID={}, path={}, outcome=failed, source={}, elapsedMs={}, cacheHit={}, versionKeyAvailable={}, error={}",
                    target_type,
                    pid,
                    target_path,
                    if cache_hit { "snapshot-cache" } else { "miss-or-timeout" },
                    elapsed,
                    cache_hit,
                    target_version_key.is_some(),
                    err
                );
                eprintln!("[StartupSnapshot] Scan failed for {}", error);
            }
            StartupScanOutcome::Failed { error, cache_hit }
        }
    }
}

fn startup_scan_cache_key(target_version_key: &str) -> String {
    format!("target-scan|{}", target_version_key)
}

fn should_log_startup_target_scan_detail(
    debug_logging: bool,
    elapsed_ms: u64,
    snapshot_cache_hit: bool,
    cache_hit: bool,
    is_malware: bool,
) -> bool {
    debug_logging && (is_malware || !snapshot_cache_hit && !cache_hit || elapsed_ms >= 500)
}

fn startup_target_scan_source(snapshot_cache_hit: bool, cache_hit: bool) -> &'static str {
    match (snapshot_cache_hit, cache_hit) {
        (true, _) => "snapshot-cache",
        (false, true) => "persistent-cache",
        (false, false) => "engine",
    }
}

fn short_hash_prefix(hash_hex: &str) -> &str {
    let prefix_len = hash_hex.len().min(12);
    &hash_hex[..prefix_len]
}

/// 函数名称：startup_target_skip_reason
/// 函数作用：判断启动快照目标是否不是可直接打开的完整文件路径，避免对进程名或不存在文件执行必然失败的 SHA-256 扫描。
/// Purpose: Determines whether a startup snapshot target is not an openable full file path, avoiding guaranteed SHA-256 failures for process names or missing files.
/// 调用方：SnapshotService::take_startup_snapshot。
/// Called by: SnapshotService::take_startup_snapshot.
/// 被调用方：Path::is_absolute、std::fs::metadata。
/// Calls: Path::is_absolute, std::fs::metadata.
/// 中文关键词：启动快照，不可扫描路径，进程名，性能优化，刷屏控制
/// English keywords: startup snapshot, unscannable path, process name, performance optimization, log spam control
#[cfg(test)]
fn inspect_startup_target(path: &str) -> StartupTargetSnapshot {
    let scan_key = startup_scan_key(path);
    inspect_startup_target_with_scan_key(path, scan_key)
}

fn inspect_startup_target_with_scan_key(path: &str, scan_key: String) -> StartupTargetSnapshot {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return StartupTargetSnapshot {
            skip_reason: Some("empty path"),
            scan_key,
            signature_cache_key: None,
            write_time_epoch_ms: None,
        };
    }

    let fs_path = trimmed
        .strip_prefix(r"\\?\")
        .or_else(|| trimmed.strip_prefix(r"\??\"))
        .unwrap_or(trimmed);

    if !Path::new(fs_path).is_absolute() {
        return StartupTargetSnapshot {
            skip_reason: Some("not an absolute file path"),
            scan_key,
            signature_cache_key: None,
            write_time_epoch_ms: None,
        };
    }

    let Ok(metadata) = std::fs::metadata(fs_path) else {
        return StartupTargetSnapshot {
            skip_reason: Some("missing or inaccessible file"),
            scan_key,
            signature_cache_key: None,
            write_time_epoch_ms: None,
        };
    };

    if !metadata.is_file() {
        return StartupTargetSnapshot {
            skip_reason: Some("not a regular file"),
            scan_key,
            signature_cache_key: None,
            write_time_epoch_ms: None,
        };
    }

    let modified_duration = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok());
    let signature_cache_key = modified_duration.as_ref().map(|duration| {
        format!(
            "{}|modified_ns={}|len={}",
            scan_key,
            duration.as_nanos(),
            metadata.len()
        )
    });
    let write_time_epoch_ms = modified_duration.map(|duration| duration.as_millis() as i64);

    StartupTargetSnapshot {
        skip_reason: None,
        scan_key,
        signature_cache_key,
        write_time_epoch_ms,
    }
}

#[cfg(test)]
fn startup_target_skip_reason(path: &str) -> Option<&'static str> {
    inspect_startup_target(path).skip_reason
}

#[cfg(test)]
fn startup_signature_cache_key(path: &str) -> Option<String> {
    inspect_startup_target(path).signature_cache_key
}

/// 函数名称：module_enumeration_error_is_access_denied
/// 函数作用：识别 Windows 拒绝访问导致的模块枚举失败，便于摘要日志把系统保护边界和其他异常分开。
/// Purpose: Identifies access-denied module enumeration failures so startup summaries can separate normal Windows protection boundaries from other errors.
/// 调用方：SnapshotService::take_startup_snapshot。
/// Called by: SnapshotService::take_startup_snapshot.
/// 中文关键词：启动快照，模块枚举，拒绝访问，系统保护进程，日志分流
/// English keywords: startup snapshot, module enumeration, access denied, protected process, log classification
fn module_enumeration_error_is_access_denied(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("0x80070005")
        || lower.contains("access is denied")
        || lower.contains("permission denied")
        || error.contains("拒绝访问")
}

/// 函数作用：识别启动快照模块枚举超时，便于性能统计区分“等太久”和“权限拒绝”。
/// 安全边界：仅用于统计分类；超时仍按 Unknown 处理，不进入可信基线。
fn module_enumeration_error_is_timeout(error: &str) -> bool {
    error
        .to_ascii_lowercase()
        .contains("module enumeration timed out")
}

/// 函数名称：startup_snapshot_debug_logging_enabled
/// 函数作用：读取 ANXIN_STARTUP_SNAPSHOT_DEBUG，控制启动快照逐项失败明细日志。
/// Purpose: Reads ANXIN_STARTUP_SNAPSHOT_DEBUG to control per-target startup snapshot failure detail logs.
/// 调用方：scan_startup_target。
/// Called by: scan_startup_target.
/// 中文关键词：启动快照，调试日志，环境变量
/// English keywords: startup snapshot, debug logging, environment variable
fn startup_snapshot_debug_logging_enabled() -> bool {
    std::env::var("ANXIN_STARTUP_SNAPSHOT_DEBUG")
        .map(|value| {
            let normalized = value.trim();
            normalized == "1" || normalized.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

/// 函数名称：startup_scan_key
/// 函数作用：规整启动快照本轮去重键，避免同一路径大小写或斜杠差异导致重复扫描。
/// Purpose: Normalizes the per-snapshot dedupe key so case and slash differences do not trigger duplicate scans for the same path.
/// 调用方：scan_startup_target。
/// Called by: scan_startup_target.
/// 中文关键词：启动快照，路径去重，性能优化
/// English keywords: startup snapshot, path dedupe, performance optimization
fn startup_scan_key(path: &str) -> String {
    let mut normalized: String = path
        .trim()
        .chars()
        .map(|ch| {
            if ch == '/' {
                '\\'
            } else if ch.is_ascii_uppercase() {
                ch.to_ascii_lowercase()
            } else {
                ch
            }
        })
        .collect();
    if normalized.starts_with("\\\\?\\") {
        normalized = normalized[4..].to_string();
    }
    if normalized.starts_with("\\??\\") {
        normalized = normalized[4..].to_string();
    }
    normalized
}

/// 函数作用：去掉同一进程模块列表中的重复路径，保留首次出现的原始路径用于后续完整性检测和日志。
/// 安全边界：只在同一次模块枚举结果内部去重，不跨进程、不跨时间复用，文件变化仍由签名缓存键重新校验。
#[derive(Debug, Clone, PartialEq, Eq)]
struct StartupModuleTarget {
    path: String,
    scan_key: String,
}

/// 函数作用：去掉同一进程模块列表中的重复路径，并保留已经算好的规范化 key，供统计和主映像重复项判断复用。
/// 安全边界：key 只用于本轮去重、计数和“是否等于主映像”判断，不替代签名、路径策略或恶意扫描。
fn prepare_startup_module_targets(modules: &[ProcessModuleInfo]) -> Vec<StartupModuleTarget> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut deduplicated = Vec::with_capacity(modules.len());
    for module in modules {
        let scan_key = startup_scan_key(&module.path);
        if seen.insert(scan_key.clone()) {
            deduplicated.push(StartupModuleTarget {
                path: module.path.clone(),
                scan_key,
            });
        }
    }
    deduplicated
}

#[cfg(test)]
fn prepare_startup_module_paths(paths: Vec<String>) -> Vec<StartupModuleTarget> {
    let modules: Vec<ProcessModuleInfo> = paths
        .into_iter()
        .map(|path| ProcessModuleInfo {
            path,
            base_address: 0,
            image_size: 0,
        })
        .collect();
    prepare_startup_module_targets(&modules)
}

fn startup_module_is_process_image(module_scan_key: &str, process_scan_key: &str) -> bool {
    module_scan_key == process_scan_key
}

fn enqueue_startup_scan_interception(
    interception: &Arc<InterceptionService>,
    ctx: &SnapshotContext,
    pid: u32,
    process_name: &str,
    target_type: &str,
    target_path: &str,
    process_path: Option<&str>,
    scan_result: &CachedScanResult,
) {
    if ctx.is_exiting() {
        return;
    }

    let entry_process_name = if process_name.is_empty() {
        process_path
            .or(Some(target_path))
            .and_then(file_name_from_path)
            .unwrap_or_else(|| format!("PID {}", pid))
    } else {
        process_name.to_string()
    };
    let payload = serde_json::json!({
        "source": "startup_snapshot",
        "targetType": target_type,
        "targetPath": target_path,
        "processPath": process_path,
        "sha256": scan_result.hash_hex,
        "cacheHit": scan_result.cache_hit,
        "rawResult": scan_result.raw_result,
    });

    let entry = InterceptionEntry {
        pid,
        process_name: entry_process_name,
        file_path: target_path.to_string(),
        risk_level: "high".to_string(),
        threat_type: scan_threat_type(&scan_result.raw_result)
            .or_else(|| Some(format!("malware_{}", target_type))),
        reason: format!(
            "启动扫描发现{}存在恶意特征：{}",
            if target_type == "module" {
                "进程加载模块"
            } else {
                "进程文件"
            },
            target_path
        ),
        payload: Some(payload.to_string()),
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
    };
    interception.enqueue(entry);
    interception.try_show_next(ctx);
}

fn enqueue_process_masquerade_interception(
    interception: &Arc<InterceptionService>,
    ctx: &SnapshotContext,
    pid: u32,
    process_name: &str,
    actual_path: &str,
    expected_paths: &[String],
) {
    if ctx.is_exiting() {
        return;
    }

    let entry = build_process_masquerade_entry(pid, process_name, actual_path, expected_paths);
    interception.enqueue(entry);
    interception.try_show_next(ctx);
}

fn build_process_masquerade_entry(
    pid: u32,
    process_name: &str,
    actual_path: &str,
    expected_paths: &[String],
) -> InterceptionEntry {
    let payload = serde_json::json!({
        "source": "startup_snapshot",
        "targetType": "process",
        "targetPath": actual_path,
        "reasonCode": "masquerade_path_mismatch",
        "expectedPaths": expected_paths,
        "actualPath": actual_path,
    });

    InterceptionEntry {
        pid,
        process_name: if process_name.is_empty() {
            format!("PID {}", pid)
        } else {
            process_name.to_string()
        },
        file_path: actual_path.to_string(),
        risk_level: "high".to_string(),
        threat_type: Some("process_masquerade".to_string()),
        reason: format!(
            "系统关键进程路径不符合预期：{}，预期位置：{}",
            actual_path,
            expected_paths.join(", ")
        ),
        payload: Some(payload.to_string()),
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
    }
}

fn enqueue_certificate_revocation_interception(
    interception: &Arc<InterceptionService>,
    ctx: &SnapshotContext,
    pid: u32,
    process_name: &str,
    target_path: &str,
    status: i32,
) {
    if ctx.is_exiting() {
        return;
    }

    let entry = build_certificate_revocation_entry(pid, process_name, target_path, status);
    interception.enqueue(entry);
    interception.try_show_next(ctx);
}

fn enqueue_revocation_target_changed_interception(
    interception: &Arc<InterceptionService>,
    ctx: &SnapshotContext,
    target: &RevocationCheckTarget,
    current_path: Option<&str>,
    current_write_time: Option<i64>,
) {
    if ctx.is_exiting() {
        return;
    }

    let entry = build_revocation_target_changed_entry(target, current_path, current_write_time);
    interception.enqueue(entry);
    interception.try_show_next(ctx);
}

fn build_certificate_revocation_entry(
    pid: u32,
    process_name: &str,
    target_path: &str,
    status: i32,
) -> InterceptionEntry {
    let payload = serde_json::json!({
        "source": "startup_snapshot",
        "targetType": "process",
        "targetPath": target_path,
        "reasonCode": "certificate_revoked",
        "signatureStatus": status,
    });

    InterceptionEntry {
        pid,
        process_name: if process_name.is_empty() {
            format!("PID {}", pid)
        } else {
            process_name.to_string()
        },
        file_path: target_path.to_string(),
        risk_level: "high".to_string(),
        threat_type: Some("certificate_revoked".to_string()),
        reason: "certificate_revoked".to_string(),
        payload: Some(payload.to_string()),
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
    }
}

fn build_revocation_target_changed_entry(
    target: &RevocationCheckTarget,
    current_path: Option<&str>,
    current_write_time: Option<i64>,
) -> InterceptionEntry {
    let payload = serde_json::json!({
        "source": "startup_snapshot",
        "targetType": "process",
        "targetPath": target.path,
        "reasonCode": "revocation_target_changed",
        "originalPath": target.path,
        "currentPath": current_path,
        "originalWriteTime": target.write_time,
        "currentWriteTime": current_write_time,
    });

    InterceptionEntry {
        pid: target.pid,
        process_name: if target.process_name.is_empty() {
            format!("PID {}", target.pid)
        } else {
            target.process_name.clone()
        },
        file_path: current_path.unwrap_or(&target.path).to_string(),
        risk_level: "high".to_string(),
        threat_type: Some("revocation_target_changed".to_string()),
        reason: "revocation_target_changed".to_string(),
        payload: Some(payload.to_string()),
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
    }
}

#[derive(Debug, Clone)]
struct ProcInfo {
    pid: u32,
    name: String,
    path: String,
    scan_key: String,
}

/// 枚举所有运行进程 / Enumerate all running processes
fn enumerate_all_processes() -> Result<Vec<ProcInfo>, String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let mut result = Vec::new();

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| format!("创建进程快照失败: {}", e))?;

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe {
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                let exe_name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len())],
                );

                // 获取进程完整路径 / Get process full path
                let path = if pid > 0 && pid != std::process::id() {
                    match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                        Ok(handle) => {
                            let mut buf: Vec<u16> = vec![0u16; 520];
                            let mut len = buf.len() as u32;
                            let pwstr = windows::core::PWSTR(buf.as_mut_ptr());
                            let image_path = match QueryFullProcessImageNameW(
                                handle,
                                PROCESS_NAME_FORMAT(0), // PROCESS_NAME_WIN32
                                pwstr,
                                &mut len,
                            ) {
                                Ok(()) => {
                                    let s = String::from_utf16_lossy(&buf[..len as usize]);
                                    s
                                }
                                Err(_) => exe_name.clone(),
                            };
                            CloseHandle(handle).ok();
                            image_path
                        }
                        Err(_) => exe_name.clone(),
                    }
                } else {
                    exe_name.clone()
                };

                result.push(ProcInfo {
                    pid,
                    name: exe_name,
                    scan_key: startup_scan_key(&path),
                    path,
                });

                if !Process32NextW(snapshot, &mut entry).is_ok() {
                    break;
                }
            }
        }
        CloseHandle(snapshot).ok();
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{
        build_certificate_revocation_entry, build_process_masquerade_entry,
        build_revocation_target_changed_entry, classify_revocation_verdict,
        detect_process_masquerade, inspect_startup_target_with_scan_key,
        is_certificate_revoked_status, module_enumeration_error_is_access_denied,
        prepare_startup_module_paths, resolve_startup_signature_verify_concurrency,
        should_count_unsigned_signature, should_defer_startup_process_module_checks,
        should_enqueue_unsigned_signature, should_schedule_process_revocation_check,
        startup_module_is_process_image, startup_module_signature_verify_timeout,
        startup_scan_cache_key, startup_scan_key, startup_signature_cache_key,
        startup_target_scan_source, startup_target_skip_reason, system_root_for_security_paths,
        MasqueradeVerdict, RevocationCheckTarget, RevocationCheckVerdict,
        StartupModuleSignatureTarget, StartupScanOutcome, StartupSignatureCache,
        StartupTargetSnapshot, TimedSignatureVerdict, CERT_E_REVOKED, CRYPT_E_REVOKED,
        FALLBACK_STARTUP_SIGNATURE_VERIFY_CONCURRENCY,
    };
    use crate::services::trust_service::SignatureVerdict;
    use serde_json::Value;
    use std::sync::Arc;
    use std::time::Duration;

    fn module_signature_target_for_test(
        path: String,
        scan_key: String,
        target: StartupTargetSnapshot,
    ) -> StartupModuleSignatureTarget {
        StartupModuleSignatureTarget {
            pid: 42,
            process_name: "test-process.exe".to_string(),
            process_path: r"C:\Test\test-process.exe".to_string(),
            path,
            scan_key,
            target,
        }
    }

    #[test]
    fn startup_scan_key_normalizes_prefix_slashes_and_case() {
        assert_eq!(
            startup_scan_key(r"\\?\C:/Windows/System32/KERNEL32.DLL"),
            r"c:\windows\system32\kernel32.dll"
        );
        assert_eq!(
            startup_scan_key(r"\??\C:\Windows\System32\kernel32.dll"),
            r"c:\windows\system32\kernel32.dll"
        );
    }

    #[test]
    fn prepare_startup_module_paths_preserves_first_path_and_precomputed_key() {
        let paths = vec![
            r"C:\Windows\System32\KERNEL32.DLL".to_string(),
            r"c:/windows/system32/kernel32.dll".to_string(),
            r"C:\Windows\System32\USER32.dll".to_string(),
            r"\\?\C:\Windows\System32\user32.DLL".to_string(),
        ];

        let deduplicated = prepare_startup_module_paths(paths);

        assert_eq!(
            deduplicated
                .iter()
                .map(|target| target.path.as_str())
                .collect::<Vec<_>>(),
            vec![
                r"C:\Windows\System32\KERNEL32.DLL",
                r"C:\Windows\System32\USER32.dll",
            ]
        );
        assert_eq!(
            deduplicated
                .iter()
                .map(|target| target.scan_key.as_str())
                .collect::<Vec<_>>(),
            vec![
                r"c:\windows\system32\kernel32.dll",
                r"c:\windows\system32\user32.dll",
            ]
        );
    }

    #[test]
    fn startup_module_is_process_image_only_matches_same_precomputed_key() {
        let process_scan_key = startup_scan_key(r"c:/program files/app/app.exe");
        let matching_module_key = startup_scan_key(r"\\?\C:\Program Files\App\APP.EXE");
        let sibling_module_key = startup_scan_key(r"C:\Program Files\App\helper.exe");
        let different_directory_key = startup_scan_key(r"C:\Users\Public\app.exe");

        assert!(startup_module_is_process_image(
            &matching_module_key,
            &process_scan_key
        ));
        assert!(!startup_module_is_process_image(
            &sibling_module_key,
            &process_scan_key
        ));
        assert!(!startup_module_is_process_image(
            &different_directory_key,
            &process_scan_key
        ));
    }

    #[test]
    fn only_noncritical_trusted_processes_defer_module_checks() {
        assert!(should_defer_startup_process_module_checks(
            &MasqueradeVerdict::NotApplicable,
            true,
            true,
        ));
        assert!(!should_defer_startup_process_module_checks(
            &MasqueradeVerdict::Clean,
            true,
            true,
        ));
        assert!(!should_defer_startup_process_module_checks(
            &MasqueradeVerdict::NotApplicable,
            false,
            true,
        ));
        assert!(!should_defer_startup_process_module_checks(
            &MasqueradeVerdict::NotApplicable,
            true,
            false,
        ));
        assert!(!should_defer_startup_process_module_checks(
            &MasqueradeVerdict::Unknown,
            true,
            true,
        ));
        assert!(!should_defer_startup_process_module_checks(
            &MasqueradeVerdict::Suspicious {
                expected: vec![r"C:\Windows\System32\lsass.exe".to_string()],
                actual: r"C:\Users\Public\lsass.exe".to_string(),
            },
            true,
            true,
        ));
    }

    #[test]
    fn startup_signature_cache_key_includes_file_version_info() {
        let temp_path = std::env::temp_dir().join(format!(
            "anxin_snapshot_signature_cache_{}.tmp",
            std::process::id()
        ));
        std::fs::write(&temp_path, b"first version").expect("write first temp file");
        let temp_path = temp_path.to_string_lossy().to_string();

        let first_key = startup_signature_cache_key(&temp_path).expect("first signature cache key");
        assert!(first_key.contains("|modified_ns="));
        assert!(first_key.contains("|len="));

        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&temp_path, b"second version").expect("write second temp file");
        let second_key =
            startup_signature_cache_key(&temp_path).expect("second signature cache key");

        assert_ne!(first_key, second_key);
        std::fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn startup_scan_cache_key_wraps_file_version_key() {
        let version_key = r"c:\program files\app\module.dll|modified_ns=123|len=456";

        assert_eq!(
            startup_scan_cache_key(version_key),
            r"target-scan|c:\program files\app\module.dll|modified_ns=123|len=456"
        );
    }

    #[test]
    fn startup_scan_outcome_started_scan_ignores_cached_outcomes() {
        assert!(StartupScanOutcome::Clean { cache_hit: false }.started_scan());
        assert!(StartupScanOutcome::Malicious { cache_hit: false }.started_scan());
        assert!(StartupScanOutcome::Failed {
            error: "timeout".to_string(),
            cache_hit: false,
        }
        .started_scan());

        assert!(!StartupScanOutcome::Clean { cache_hit: true }.started_scan());
        assert!(!StartupScanOutcome::Failed {
            error: "timeout".to_string(),
            cache_hit: true,
        }
        .started_scan());
        assert!(!StartupScanOutcome::Skipped.started_scan());
    }

    #[test]
    fn startup_target_scan_source_labels_cache_layers() {
        assert_eq!(startup_target_scan_source(true, false), "snapshot-cache");
        assert_eq!(startup_target_scan_source(true, true), "snapshot-cache");
        assert_eq!(startup_target_scan_source(false, true), "persistent-cache");
        assert_eq!(startup_target_scan_source(false, false), "engine");
    }

    #[test]
    fn startup_target_scan_detail_logs_only_debug_signal_cases() {
        assert!(!super::should_log_startup_target_scan_detail(
            false, 10_000, false, false, true
        ));
        assert!(super::should_log_startup_target_scan_detail(
            true, 10, false, false, false
        ));
        assert!(super::should_log_startup_target_scan_detail(
            true, 10, true, false, true
        ));
        assert!(!super::should_log_startup_target_scan_detail(
            true, 10, true, true, false
        ));
        assert!(super::should_log_startup_target_scan_detail(
            true, 500, true, true, false
        ));
    }

    #[test]
    fn startup_target_scan_hash_prefix_is_bounded() {
        assert_eq!(super::short_hash_prefix("abc"), "abc");
        assert_eq!(super::short_hash_prefix("1234567890abcdef"), "1234567890ab");
    }

    #[test]
    fn module_signature_timeout_extends_base_without_exceeding_scan_timeout() {
        assert_eq!(
            startup_module_signature_verify_timeout(
                Duration::from_millis(1_000),
                Duration::from_millis(10_000)
            ),
            Duration::from_millis(3_000)
        );
        assert_eq!(
            startup_module_signature_verify_timeout(
                Duration::from_millis(5_000),
                Duration::from_millis(10_000)
            ),
            Duration::from_millis(10_000)
        );
        assert_eq!(
            startup_module_signature_verify_timeout(
                Duration::from_millis(5_000),
                Duration::from_millis(1_000)
            ),
            Duration::from_millis(5_000)
        );
    }

    #[test]
    fn startup_signature_verify_concurrency_auto_uses_logical_processors() {
        let expected = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get().max(1))
            .unwrap_or(FALLBACK_STARTUP_SIGNATURE_VERIFY_CONCURRENCY);

        assert_eq!(resolve_startup_signature_verify_concurrency(0), expected);
    }

    #[test]
    fn startup_signature_verify_concurrency_keeps_explicit_limit() {
        assert_eq!(resolve_startup_signature_verify_concurrency(3), 3);
    }

    #[test]
    fn inspect_startup_target_reuses_precomputed_scan_key() {
        let temp_path = std::env::temp_dir().join(format!(
            "anxin_snapshot_precomputed_scan_key_{}.tmp",
            std::process::id()
        ));
        std::fs::write(&temp_path, b"scan key version").expect("write temp file");
        let temp_path = temp_path.to_string_lossy().to_string();
        let precomputed_key = startup_scan_key(&temp_path);

        let target = inspect_startup_target_with_scan_key(&temp_path, precomputed_key.clone());

        assert_eq!(target.scan_key, precomputed_key);
        assert!(target.skip_reason.is_none());
        assert!(target.signature_cache_key.is_some());
        std::fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn startup_signature_cache_reuses_only_same_file_version() {
        let temp_path = std::env::temp_dir().join(format!(
            "anxin_snapshot_signature_cache_lookup_{}.tmp",
            std::process::id()
        ));
        std::fs::write(&temp_path, b"trusted version").expect("write trusted temp file");
        let temp_path = temp_path.to_string_lossy().to_string();
        let mut cache = StartupSignatureCache::default();
        let verdict = TimedSignatureVerdict {
            trusted: true,
            status: 0,
            timed_out: false,
        };

        cache
            .insert_for_test(&temp_path, verdict)
            .expect("insert signature cache");
        assert!(cache
            .lookup_for_test(&temp_path)
            .is_some_and(|cached| cached.trusted));

        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&temp_path, b"changed version").expect("rewrite temp file");

        assert!(cache.lookup_for_test(&temp_path).is_none());
        std::fs::remove_file(&temp_path).ok();
    }

    #[tokio::test]
    async fn concurrent_module_signature_verification_reuses_version_cache() {
        let temp_path = std::env::temp_dir().join(format!(
            "anxin_snapshot_concurrent_signature_cache_{}.tmp",
            std::process::id()
        ));
        std::fs::write(&temp_path, b"cached module version").expect("write temp file");
        let temp_path = temp_path.to_string_lossy().to_string();
        let scan_key = startup_scan_key(&temp_path);
        let target = inspect_startup_target_with_scan_key(&temp_path, scan_key.clone());
        let mut cache = StartupSignatureCache::default();
        let cached_verdict = TimedSignatureVerdict {
            trusted: true,
            status: 0,
            timed_out: false,
        };
        cache
            .insert_for_test(&temp_path, cached_verdict)
            .expect("insert signature cache");

        let results = cache
            .verify_module_targets_concurrent(
                Arc::new(crate::services::trust_service::TrustService::new()),
                vec![module_signature_target_for_test(
                    temp_path.clone(),
                    scan_key,
                    target,
                )],
                Duration::from_millis(1),
                4,
            )
            .await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pid, 42);
        assert_eq!(results[0].process_name, "test-process.exe");
        assert!(results[0].verdict.trusted);
        assert_eq!(cache.hits, 1);
        assert_eq!(cache.misses, 0);
        std::fs::remove_file(&temp_path).ok();
    }

    #[tokio::test]
    async fn concurrent_module_signature_verification_coalesces_same_file_version() {
        let temp_path = std::env::temp_dir().join(format!(
            "anxin_snapshot_coalesced_signature_cache_{}.tmp",
            std::process::id()
        ));
        std::fs::write(&temp_path, b"same module version").expect("write temp file");
        let temp_path = temp_path.to_string_lossy().to_string();
        let scan_key = startup_scan_key(&temp_path);
        let target = inspect_startup_target_with_scan_key(&temp_path, scan_key.clone());
        let mut cache = StartupSignatureCache::default();

        let results = cache
            .verify_module_targets_concurrent(
                Arc::new(crate::services::trust_service::TrustService::new()),
                vec![
                    module_signature_target_for_test(
                        temp_path.clone(),
                        "second-order-key".to_string(),
                        target.clone(),
                    ),
                    module_signature_target_for_test(temp_path.clone(), scan_key.clone(), target),
                ],
                Duration::from_millis(1),
                4,
            )
            .await;

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].scan_key, "second-order-key");
        assert_eq!(results[1].scan_key, scan_key);
        assert_eq!(results[0].pid, 42);
        assert_eq!(results[1].pid, 42);
        assert_eq!(results[0].process_name, "test-process.exe");
        assert_eq!(results[1].process_name, "test-process.exe");
        assert_eq!(cache.misses, 1);
        assert_eq!(cache.coalesced_waiters, 1);
        assert_eq!(cache.hits, 0);
        std::fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn startup_target_skip_reason_rejects_process_name_without_full_path() {
        assert_eq!(
            startup_target_skip_reason("svchost.exe"),
            Some("not an absolute file path")
        );
    }

    #[test]
    fn startup_target_skip_reason_accepts_existing_file_path() {
        let temp_path = std::env::temp_dir().join(format!(
            "anxin_snapshot_scannable_{}.tmp",
            std::process::id()
        ));
        std::fs::write(&temp_path, b"snapshot test").expect("write temp snapshot test file");

        assert_eq!(
            startup_target_skip_reason(temp_path.to_string_lossy().as_ref()),
            None
        );

        std::fs::remove_file(&temp_path).ok();
    }

    #[test]
    fn module_enumeration_access_denied_errors_are_classified_separately() {
        assert!(module_enumeration_error_is_access_denied(
            "创建模块快照失败: 拒绝访问。 (0x80070005)"
        ));
        assert!(module_enumeration_error_is_access_denied(
            "failed to create module snapshot: Access is denied. (0x80070005)"
        ));
        assert!(!module_enumeration_error_is_access_denied(
            "failed to create module snapshot: invalid parameter"
        ));
    }

    #[test]
    fn process_masquerade_accepts_expected_system32_path() {
        let root = system_root_for_security_paths();
        let path = format!(r"\\?\{}\System32\SVCHOST.EXE", root);

        assert_eq!(
            detect_process_masquerade("svchost.exe", &path),
            MasqueradeVerdict::Clean
        );
    }

    #[test]
    fn process_masquerade_rejects_critical_process_outside_expected_dir() {
        let verdict = detect_process_masquerade("lsass.exe", r"C:\Users\Public\lsass.exe");

        match verdict {
            MasqueradeVerdict::Suspicious { expected, actual } => {
                assert!(expected
                    .iter()
                    .any(|path| path.ends_with(r"\system32\lsass.exe")));
                assert_eq!(actual, r"c:\users\public\lsass.exe");
            }
            other => panic!("expected suspicious masquerade verdict, got {:?}", other),
        }
    }

    #[test]
    fn process_masquerade_treats_missing_full_path_as_unknown() {
        assert_eq!(
            detect_process_masquerade("svchost.exe", "svchost.exe"),
            MasqueradeVerdict::Unknown
        );
    }

    #[test]
    fn signature_timeout_is_unknown_not_unsigned_interception() {
        let timed_out = TimedSignatureVerdict {
            trusted: false,
            status: -1,
            timed_out: true,
        };
        let untrusted = TimedSignatureVerdict {
            trusted: false,
            status: 0x800B0100u32 as i32,
            timed_out: false,
        };

        assert!(!should_count_unsigned_signature(&timed_out));
        assert!(!should_enqueue_unsigned_signature(&timed_out, false));
        assert!(should_count_unsigned_signature(&untrusted));
        assert!(!should_enqueue_unsigned_signature(&untrusted, false));
        assert!(!should_enqueue_unsigned_signature(&untrusted, true));
    }

    #[test]
    fn process_masquerade_entry_uses_existing_interception_shape() {
        let expected = vec![r"c:\windows\system32\lsass.exe".to_string()];
        let entry = build_process_masquerade_entry(
            4242,
            "lsass.exe",
            r"c:\users\public\lsass.exe",
            &expected,
        );
        let payload: Value =
            serde_json::from_str(entry.payload.as_deref().expect("payload")).expect("json payload");

        assert_eq!(entry.pid, 4242);
        assert_eq!(entry.risk_level, "high");
        assert_eq!(entry.threat_type.as_deref(), Some("process_masquerade"));
        assert_eq!(payload["source"], "startup_snapshot");
        assert_eq!(payload["reasonCode"], "masquerade_path_mismatch");
        assert_eq!(payload["actualPath"], r"c:\users\public\lsass.exe");
    }

    #[test]
    fn process_masquerade_ignores_non_critical_process_names() {
        assert_eq!(
            detect_process_masquerade("notepad.exe", r"C:\Temp\notepad.exe"),
            MasqueradeVerdict::NotApplicable
        );
    }

    #[test]
    fn process_revocation_check_only_schedules_trusted_clean_critical_processes() {
        let root = system_root_for_security_paths();
        let path = format!(r"{}\System32\services.exe", root);

        assert!(should_schedule_process_revocation_check(
            "services.exe",
            &path,
            true,
            true,
            true
        ));
        assert!(!should_schedule_process_revocation_check(
            "notepad.exe",
            r"C:\Windows\System32\notepad.exe",
            true,
            true,
            true
        ));
        assert!(!should_schedule_process_revocation_check(
            "services.exe",
            &path,
            true,
            false,
            true
        ));
        assert!(!should_schedule_process_revocation_check(
            "services.exe",
            &path,
            true,
            true,
            false
        ));
    }

    #[test]
    fn certificate_revocation_statuses_are_classified_without_overblocking_unknowns() {
        assert!(is_certificate_revoked_status(CERT_E_REVOKED as i32));
        assert!(is_certificate_revoked_status(CRYPT_E_REVOKED as i32));
        assert!(!is_certificate_revoked_status(0x800B0101u32 as i32));

        assert_eq!(
            classify_revocation_verdict(Ok(SignatureVerdict {
                trusted: true,
                status: 0,
            })),
            RevocationCheckVerdict::Trusted
        );
        assert_eq!(
            classify_revocation_verdict(Ok(SignatureVerdict {
                trusted: false,
                status: CERT_E_REVOKED as i32,
            })),
            RevocationCheckVerdict::Revoked {
                status: CERT_E_REVOKED as i32,
            }
        );
        assert_eq!(
            classify_revocation_verdict(Ok(SignatureVerdict {
                trusted: false,
                status: 0x800B0101u32 as i32,
            })),
            RevocationCheckVerdict::Unknown {
                status: 0x800B0101u32 as i32,
            }
        );
    }

    #[test]
    fn certificate_revocation_entry_uses_existing_interception_shape() {
        let entry = build_certificate_revocation_entry(
            900,
            "services.exe",
            r"c:\windows\system32\services.exe",
            CERT_E_REVOKED as i32,
        );
        let payload: Value =
            serde_json::from_str(entry.payload.as_deref().expect("payload")).expect("json payload");

        assert_eq!(entry.pid, 900);
        assert_eq!(entry.risk_level, "high");
        assert_eq!(entry.threat_type.as_deref(), Some("certificate_revoked"));
        assert_eq!(entry.reason, "certificate_revoked");
        assert_eq!(payload["source"], "startup_snapshot");
        assert_eq!(payload["reasonCode"], "certificate_revoked");
        assert_eq!(payload["signatureStatus"], CERT_E_REVOKED as i32);
    }

    #[test]
    fn revocation_target_changed_entry_uses_existing_interception_shape() {
        let target = RevocationCheckTarget {
            pid: 901,
            process_name: "services.exe".to_string(),
            path: r"c:\windows\system32\services.exe".to_string(),
            path_scan_key: startup_scan_key(r"c:\windows\system32\services.exe"),
            write_time: Some(1000),
            critical: true,
        };
        let entry = build_revocation_target_changed_entry(
            &target,
            Some(r"c:\users\public\services.exe"),
            Some(2000),
        );
        let payload: Value =
            serde_json::from_str(entry.payload.as_deref().expect("payload")).expect("json payload");

        assert_eq!(entry.pid, 901);
        assert_eq!(entry.risk_level, "high");
        assert_eq!(
            entry.threat_type.as_deref(),
            Some("revocation_target_changed")
        );
        assert_eq!(entry.reason, "revocation_target_changed");
        assert_eq!(payload["source"], "startup_snapshot");
        assert_eq!(payload["reasonCode"], "revocation_target_changed");
        assert_eq!(payload["originalPath"], r"c:\windows\system32\services.exe");
        assert_eq!(payload["currentPath"], r"c:\users\public\services.exe");
        assert_eq!(payload["originalWriteTime"], 1000);
        assert_eq!(payload["currentWriteTime"], 2000);
    }
}
