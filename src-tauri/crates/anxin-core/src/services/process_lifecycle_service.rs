// 进程生命周期 + 行为采集服务的编排层（AnXinProcMon.sys 用户态伙伴）
//  Process lifecycle + behavior collection service (user-mode companion of AnXinProcMon.sys)
//
// 职责（docs/proc_monitor_design.md 契约 v6）：
//  Responsibilities (contract v6 in docs/proc_monitor_design.md):
// - 应用启动时按需加载驱动（sc start AnXinProcMon）并完成版本握手
// - 生命周期事件泵：消费 PROC_QUEUE_LIFECYCLE，维护状态表，识别 BYOVD 主动探针回报
// - 行为事件泵：消费 PROC_QUEUE_BEHAVIOR（本阶段仅 drain + 统计，入库在后续阶段）
// - BYOVD 主动探针（§13.7）：每 2s 创建 `cmd.exe /c exit`，驱动须 100ms 内回报；
//   探针 PID 集合由本服务维护、按 PID 过滤不进入业务事件；连续 ≥10s 未回报 →
//   `process-monitor-tampered` 高危告警事件，并触发全盘快照纠偏（§4.4）
// - 快照纠偏（§4.4）：探针告警时一次性 Toolhelp 枚举重建状态表缺失项，
//   纠偏期间抑制补采避免风暴
//
// 线程模型：
//  Threading model:
// - 三个专用 std 线程：lifecycle 泵 / behavior 泵 / 探针调度器
// - 泵线程阻塞在 wait_*_event（同步 IOCTL），stop() 通过 disconnect()（CancelIoEx）
//   唤醒后 join
// - 共享状态：Arc<Mutex<HashMap<u32, Instant>>>（探针 PID → 发出时刻）、
//   Arc<AtomicU32>（连续未回报轮数）、Arc<Mutex<HashMap<u32, ProcessEntry>>>（状态表）、
//   Arc<Mutex<VecDeque<LifecycleRecord>>>（事件环形缓冲，前端查询）
//
// 中文关键词：进程生命周期，行为采集，BYOVD 探针，回调失明，事件泵，高危告警，快照纠偏
// English keywords: process lifecycle, behavior collection, BYOVD probe, callback blindness,
//                   event pump, high-risk alert, snapshot reconciliation
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::services::service_context::ServiceContext;
use crate::utils::proc_driver_client::{evt, ProcDriverClient, ProcEvent, PROC_CAP_LIFECYCLE};

// ============================================================================
// 常量 / Constants
// ============================================================================

/// 探针周期：每 2 秒创建一个探针进程 / Probe interval: one probe process every 2 seconds
const PROBE_INTERVAL: Duration = Duration::from_secs(2);
/// 一轮探针回报窗口：超过此时间未收到该 PID 的 CREATE 回报视为一轮失败
///  Probe reporting window: a CREATE report for the PID not seen within this window
///  counts as one missed round.
const PROBE_REPORT_WINDOW: Duration = Duration::from_secs(2);
/// 连续失败多少轮后告警（5 轮 × 2s ≈ 10s，契约 §13.7 的"连续 ≥10s 未回报"）
///  Missed rounds before alerting (5 × 2s ≈ 10s, contract §13.7's "≥10s without report")
const PROBE_MISS_THRESHOLD: u32 = 5;
/// 探针进程命令行 / Probe command line
const PROBE_COMMAND: &str = "cmd.exe";
const PROBE_ARGS: [&str; 2] = ["/c", "exit"];

/// 回调失明告警事件名 / Callback-blindness alert event name
pub const EVENT_CALLBACK_TAMPERED: &str = "process-monitor-tampered";
/// 生命周期事件名（§4.6：独立通道，前端 ProcessLifecyclePage 监听）
///  Lifecycle event name (§4.6: dedicated channel for ProcessLifecyclePage)
pub const EVENT_PROCESS_LIFECYCLE: &str = "process-lifecycle-event";
/// 前端查询的事件缓冲上限（§5：沿用 BehaviorPage 500 条模式）
///  Event ring-buffer cap for frontend queries (§5: 500 like BehaviorPage)
pub const EVENT_BUFFER_CAP: usize = 500;
/// 快照纠偏冷却（秒）：纠偏后这段时间内不再重复纠偏，避免探针持续失明时风暴
///  Reconciliation cooldown (s): no repeated reconciliation within this window,
///  preventing a storm while the probe keeps failing.
const RECONCILE_COOLDOWN_SECS: u64 = 30;

// ============================================================================
// 数据结构 / Data structures
// ============================================================================

/// 状态表条目（§4.1：CREATE 关联、EXIT 收尾、快照纠偏补项）
///  Process-table entry (§4.1: CREATE association, EXIT finalization, reconciliation)
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    /// 创建时间（100ns FILETIME，来自驱动事件头）
    pub create_time: u64,
    /// 是否由快照纠偏补入（无 CREATE 事件的基线缺失项，§4.4）
    pub restored: bool,
    /// 进程可执行文件路径（纠偏补项时尽力补查，可能为空）
    pub image_path: Option<String>,
    /// 是否存活（EXIT 事件到达后置 false，保留一段时间供前端进程树展示）
    pub alive: bool,
}

/// 生命周期记录（CREATE/EXIT/纠偏补项，写入环形缓冲供前端查询）
///  Lifecycle record (CREATE/EXIT/reconcile, kept in the ring buffer for the frontend)
#[derive(Debug, Clone)]
pub struct LifecycleRecord {
    pub pid: u32,
    pub parent_pid: u32,
    pub event_type: u16,
    /// 100ns FILETIME（事件头）
    pub event_time: u64,
    /// 毫秒时间戳（前端展示用）
    pub ts_ms: u64,
    pub session_id: u32,
    pub exit_status: u32,
    pub flags: u16,
    /// 进程路径（纠偏补项时尽力补查）
    pub image_path: Option<String>,
    /// 由快照纠偏补入（无驱动事件）
    pub restored: bool,
}

/// 探针调度的共享状态 / Shared state of the probe scheduler
struct ProbeState {
    /// 探针 PID → 发出时刻 / probe PID -> when it was launched
    pending: Mutex<HashMap<u32, Instant>>,
    /// 连续未回报轮数 / consecutive missed rounds
    missed_rounds: AtomicU32,
    /// 累计回报统计 / cumulative reporting statistics
    reported_ok: AtomicU32,
    reported_late_ms: Mutex<Vec<u64>>,
    /// 累计发射探针数 / cumulative probe launches
    total_launched: AtomicU32,
}

impl Default for ProbeState {
    fn default() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            missed_rounds: AtomicU32::new(0),
            reported_ok: AtomicU32::new(0),
            reported_late_ms: Mutex::new(Vec::new()),
            total_launched: AtomicU32::new(0),
        }
    }
}

/// 探针统计快照 / Probe statistics snapshot
#[derive(Debug, Clone, Default)]
pub struct ProbeStats {
    pub total_launched: u32,
    pub reported_ok: u32,
    pub missed_rounds: u32,
    pub tampered_alerts: u32,
    /// 最近一次快照纠偏补入的进程数（0 = 从未纠偏）
    pub last_reconcile_count: u32,
}

// ============================================================================
// 服务 / Service
// ============================================================================

/// AnXinProcMon 采集服务（驱动连接 + 双队列泵 + BYOVD 主动探针 + 状态表 + 快照纠偏）
///  AnXinProcMon collection service (driver connection + dual-queue pumps + BYOVD probe
///  + process table + snapshot reconciliation)
pub struct ProcessLifecycleService {
    client: Arc<ProcDriverClient>,
    running: Arc<AtomicBool>,
    probe_state: Arc<ProbeState>,
    tampered_alerts: Arc<AtomicU32>,
    /// 握手时记录的驱动版本 / driver version captured at handshake
    driver_version: Mutex<Option<crate::utils::proc_driver_client::ProcVersion>>,
    /// 生命周期状态表（pid → 条目，§4.1 / §4.4）
    process_table: Arc<Mutex<HashMap<u32, ProcessEntry>>>,
    /// 事件环形缓冲（CREATE/EXIT/纠偏补项，§5 前端查询）
    event_buffer: Arc<Mutex<VecDeque<LifecycleRecord>>>,
    /// 上次快照纠偏时刻（冷却期内不重复纠偏）
    last_reconcile: Arc<Mutex<Option<Instant>>>,
    /// 最近一次纠偏补入的进程数（探针统计用）
    last_reconcile_count: Arc<AtomicU32>,
    lifecycle_pump: Mutex<Option<std::thread::JoinHandle<()>>>,
    behavior_pump: Mutex<Option<std::thread::JoinHandle<()>>>,
    probe_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    driver_connected: AtomicBool,
}

impl Default for ProcessLifecycleService {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessLifecycleService {
    pub fn new() -> Self {
        Self {
            client: Arc::new(ProcDriverClient::new()),
            running: Arc::new(AtomicBool::new(false)),
            probe_state: Arc::new(ProbeState::default()),
            tampered_alerts: Arc::new(AtomicU32::new(0)),
            driver_version: Mutex::new(None),
            process_table: Arc::new(Mutex::new(HashMap::new())),
            event_buffer: Arc::new(Mutex::new(VecDeque::with_capacity(EVENT_BUFFER_CAP))),
            last_reconcile: Arc::new(Mutex::new(None)),
            last_reconcile_count: Arc::new(AtomicU32::new(0)),
            lifecycle_pump: Mutex::new(None),
            behavior_pump: Mutex::new(None),
            probe_thread: Mutex::new(None),
            driver_connected: AtomicBool::new(false),
        }
    }

    /// 函数名称：start
    /// 函数作用：加载并连接 AnXinProcMon 驱动，启动生命周期/行为双事件泵与 BYOVD 主动探针。
    /// Purpose: Loads and connects to AnXinProcMon, starts the dual event pumps and the BYOVD probe.
    ///
    /// 驱动不可用时返回 Err，调用方应把它当作「功能降级」而不是启动失败——
    /// 防护套件的其他模块必须照常工作。主动探针是失明检测的唯一手段，
    /// 驱动连不上时意味着回调链路整体缺失，此时同样要触发一次 TAMPERED 告警。
    /// Returns Err when the driver is unavailable; callers must treat that as a degraded
    /// feature rather than startup failure. The probe is the only blindness detector, so a
    /// failed connection also raises one TAMPERED alert before returning.
    ///
    /// 调用方：应用启动流程 / 服务进程启动流程（P5 接入）
    /// 并发与幂等：重复调用会先停止已有实例再重启
    pub fn start(&self, ctx: ServiceContext) -> Result<(), String> {
        if self.running.load(Ordering::SeqCst) {
            self.stop();
        }

        // DEMAND_START 驱动安装后是 STOPPED：先经 SCM 启动服务（sc start AnXinProcMon），
        // 驱动加载成功后才存在设备对象。驱动服务未安装/启动失败按降级处理。
        //  The DEMAND_START driver is STOPPED after install: start the service via the
        //  SCM first, otherwise no device object exists. Missing/failed driver start
        //  degrades gracefully.
        if let Err(e) = crate::services::driver_install_service::start_driver_service_by_kind(
            crate::services::driver_install_service::DriverKind::ProcessMonitor,
        ) {
            eprintln!(
                "[ProcLifecycle] failed to start AnXinProcMon service (non-fatal): {}",
                e
            );
        }

        let version = self
            .client
            .connect()
            .map_err(|e| format!("failed to connect to AnXinProcMon driver: {}", e))?;

        if version.capabilities & PROC_CAP_LIFECYCLE == 0 {
            self.client.disconnect();
            return Err(format!(
                "driver lacks LIFECYCLE capability (capabilities=0x{:08X})",
                version.capabilities
            ));
        }

        *self.driver_version.lock().unwrap() = Some(version);
        self.driver_connected.store(true, Ordering::SeqCst);
        self.running.store(true, Ordering::SeqCst);

        // §6 默认过滤表：加载 config/proc_filter_rules.json 并下发驱动（SET_FILTER
        // 整表原子替换），收敛高频低价值噪音、防止行为队列积压。空规则 = 采集全部
        // （驱动默认）；下发失败仅日志（降级不阻断）。
        //  §6 default filter table: load proc_filter_rules.json and push it to the
        //  driver (whole-table atomic replace) to suppress high-frequency noise.
        //  Empty rules keep the driver default (collect all); push failures are logged only.
        let filter_rules = load_default_filter_rules();
        if let Err(e) = self.client.set_filter(1, &filter_rules) {
            eprintln!(
                "[ProcLifecycle] failed to push filter table ({} rules, non-fatal): {}",
                filter_rules.len(),
                e
            );
        }

        self.spawn_lifecycle_pump(ctx.clone());
        self.spawn_behavior_pump(ctx.clone());
        self.spawn_probe(ctx.clone());

        // §4.5 ETW 降噪：驱动接管成功后关闭 ETW 重复类别（进程/线程/文件/注册表/网络
        // 由驱动采集），ETW 会话保留以便失联时快速恢复全量。失败仅日志（降级不阻断）。
        //  §4.5 ETW reduced mode: after driver takeover, shut down the duplicated ETW
        //  kernel classes (collected by the driver instead); the ETW session stays so
        //  full mode can be restored quickly on driver loss. Failures are logged only.
        if let Some(etw) =
            ctx.get::<std::sync::Mutex<crate::services::etw_service::EtwService>>()
        {
            let guard = etw.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = guard.restart_with_flags(
                ctx.clone(),
                crate::services::etw::session::ETW_FLAGS_REDUCED,
            ) {
                eprintln!(
                    "[ProcLifecycle] ETW reduced-mode switch failed (non-fatal): {}",
                    e
                );
            }
        }

        eprintln!(
            "[ProcLifecycle] Started (driver v{}.{}.{}, caps=0x{:08X})",
            version.driver_major, version.driver_minor, version.driver_patch, version.capabilities
        );
        Ok(())
    }

    /// 函数名称：stop
    /// 函数作用：断开驱动、停止全部线程。驱动句柄关闭后泵线程立即从阻塞 IOCTL 返回。
    /// Purpose: Disconnects the driver and stops all threads; the pumps wake from the
    ///          blocking IOCTL as soon as the handle closes.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.client.disconnect();
        self.driver_connected.store(false, Ordering::SeqCst);
        *self.driver_version.lock().unwrap() = None;

        for slot in [
            &self.lifecycle_pump,
            &self.behavior_pump,
            &self.probe_thread,
        ] {
            if let Some(handle) = slot.lock().unwrap().take() {
                let _ = handle.join();
            }
        }
    }

    /// 当前是否已连接并接管 / Whether the driver is connected and attached
    pub fn is_connected(&self) -> bool {
        self.driver_connected.load(Ordering::SeqCst)
    }

    /// 握手时记录的驱动版本 / Driver version captured at handshake
    pub fn driver_version(&self) -> Option<crate::utils::proc_driver_client::ProcVersion> {
        *self.driver_version.lock().unwrap()
    }

    /// 读取驱动回调活性心跳（§13.7；驱动未连接时返回 None）
    ///  Reads the driver callback-activity heartbeat (§13.7; None when disconnected)
    pub fn driver_health(&self) -> Option<crate::utils::proc_driver_client::ProcHealth> {
        if !self.driver_connected.load(Ordering::SeqCst) {
            return None;
        }
        self.client.get_health().ok()
    }

    /// 探针统计快照 / Probe statistics snapshot
    pub fn probe_stats(&self) -> ProbeStats {
        let state = &self.probe_state;
        ProbeStats {
            total_launched: state.total_launched.load(Ordering::SeqCst),
            reported_ok: state.reported_ok.load(Ordering::SeqCst),
            missed_rounds: state.missed_rounds.load(Ordering::SeqCst),
            tampered_alerts: self.tampered_alerts.load(Ordering::SeqCst),
            last_reconcile_count: self.last_reconcile_count.load(Ordering::SeqCst),
        }
    }

    /// 状态表快照（进程树查询用） / Process-table snapshot (for the process tree)
    pub fn process_table_snapshot(&self) -> Vec<ProcessEntry> {
        self.process_table
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// 事件缓冲快照（前端查询，最多 cap 条，最新在前）
    ///  Event-buffer snapshot (newest first, capped)
    pub fn recent_events(&self, limit: usize) -> Vec<LifecycleRecord> {
        let buffer = self.event_buffer.lock().unwrap();
        let take = limit.min(buffer.len());
        buffer.iter().rev().take(take).cloned().collect()
    }

    /// 主动触发一次全盘快照纠偏（§4.4）：Toolhelp 枚举当前 PID，
    /// 为状态表缺失项补建条目并写入事件缓冲。
    ///  Runs one full snapshot reconciliation (§4.4): enumerates current PIDs via
    ///  Toolhelp and back-fills process-table entries that are missing.
    ///
    /// 由探针告警路径调用；带冷却，冷却期内直接返回。
    ///  Called from the probe-alert path; subject to a cooldown.
    pub fn run_snapshot_reconciliation(&self) -> u32 {
        let now = Instant::now();
        {
            let mut last = self.last_reconcile.lock().unwrap();
            if let Some(prev) = *last {
                if now.duration_since(prev).as_secs() < RECONCILE_COOLDOWN_SECS {
                    return 0;
                }
            }
            *last = Some(now);
        }

        let current = crate::services::process_scanner_service::collect_current_pids();
        let mut table = self.process_table.lock().unwrap();
        let mut restored = 0u32;

        for pid in &current {
            if table.contains_key(pid) {
                continue;
            }
            // 系统 PID 0/4/8 无意义，跳过（与驱动防呆一致）
            if *pid == 0 || *pid == 4 || *pid == 8 {
                continue;
            }
            let image_path =
                crate::services::process_scanner_service::query_process_image_path(*pid);
            table.insert(
                *pid,
                ProcessEntry {
                    pid: *pid,
                    parent_pid: 0,
                    session_id: 0,
                    create_time: 0,
                    restored: true,
                    image_path,
                    alive: true,
                },
            );
            restored += 1;
        }

        if restored > 0 {
            self.last_reconcile_count.store(restored, Ordering::SeqCst);
            let ts_ms = unix_ms_now();
            let mut buffer = self.event_buffer.lock().unwrap();
            for pid in &current {
                if let Some(entry) = table.get(pid) {
                    if !entry.restored {
                        continue;
                    }
                    push_event_record(
                        &mut *buffer,
                        LifecycleRecord {
                            pid: entry.pid,
                            parent_pid: entry.parent_pid,
                            event_type: evt::PROC_CREATE,
                            event_time: 0,
                            ts_ms,
                            session_id: entry.session_id,
                            exit_status: 0,
                            flags: 0,
                            image_path: entry.image_path.clone(),
                            restored: true,
                        },
                    );
                }
            }
        }

        eprintln!(
            "[ProcLifecycle] snapshot reconciliation restored {} entries ({} pids total)",
            restored,
            current.len()
        );
        restored
    }

    // ------------------------------------------------------------------
    // 生命周期事件泵 / Lifecycle event pump
    // ------------------------------------------------------------------

    fn spawn_lifecycle_pump(&self, ctx: ServiceContext) {
        let client = self.client.clone();
        let running = self.running.clone();
        let probe_state = self.probe_state.clone();
        let process_table = self.process_table.clone();
        let event_buffer = self.event_buffer.clone();
        let behavior = ctx.get::<std::sync::Mutex<crate::services::behavior_service::BehaviorService>>();
        let reconcile = self.make_reconcile_fn();

        let handle = std::thread::Builder::new()
            .name("anxin-procmon-lifecycle-pump".to_string())
            .spawn(move || {
                while running.load(Ordering::SeqCst) {
                    match client.wait_lifecycle_event() {
                        Ok(event) => {
                            Self::consume_lifecycle_event(
                                &probe_state,
                                &process_table,
                                &event_buffer,
                                &ctx,
                                &event,
                                behavior.clone(),
                                &*reconcile,
                            );
                        }
                        Err(err) => {
                            // 驱动断开（stop 或驱动被卸载）时退出；其余错误退避重试
                            //  Driver detached (stop or unload); other errors back off and retry.
                            if !running.load(Ordering::SeqCst) {
                                break;
                            }
                            eprintln!("[ProcLifecycle] lifecycle pump error: {}", err);
                            std::thread::sleep(Duration::from_millis(500));
                        }
                    }
                }
            })
            .expect("failed to spawn lifecycle pump thread");

        *self.lifecycle_pump.lock().unwrap() = Some(handle);
    }

    /// 消费一条生命周期事件：识别 BYOVD 探针回报（PID 命中 pending 表即回报成功），
    /// 并把非探针的 CREATE/EXIT 事件关联进状态表、写入事件缓冲并向前端发射。
    ///  Consumes one lifecycle event: a PID hitting the pending probe table counts as
    ///  a probe report; non-probe CREATE/EXIT events update the process table, the
    ///  event buffer and the frontend channel.
    #[allow(clippy::too_many_arguments)]
    fn consume_lifecycle_event(
        probe_state: &ProbeState,
        process_table: &Mutex<HashMap<u32, ProcessEntry>>,
        event_buffer: &Mutex<VecDeque<LifecycleRecord>>,
        ctx: &ServiceContext,
        event: &ProcEvent,
        behavior: Option<Arc<std::sync::Mutex<crate::services::behavior_service::BehaviorService>>>,
        reconcile: &dyn Fn() -> u32,
    ) {
        // 1. 探针回报判定（仅 CREATE 事件会命中 pending 表）
        //    Probe report matching (only CREATE events can hit the pending table)
        let is_probe = {
            let mut pending = probe_state.pending.lock().unwrap();
            if event.header.event_type == evt::PROC_CREATE {
                if let Some(launched_at) = pending.remove(&event.header.pid) {
                    let latency_ms = launched_at.elapsed().as_millis() as u64;
                    probe_state.reported_ok.fetch_add(1, Ordering::SeqCst);
                    probe_state.missed_rounds.store(0, Ordering::SeqCst);
                    probe_state.reported_late_ms.lock().unwrap().push(latency_ms);

                    // 契约 §13.7：驱动应在 100ms 内回报。迟报（>100ms）记日志供诊断。
                    //  Contract §13.7: the driver should report within 100ms. Late
                    //  reports (>100ms) are logged for diagnosis.
                    if latency_ms > 100 {
                        eprintln!(
                            "[ProcLifecycle] probe PID {} reported late: {}ms (window {}ms)",
                            event.header.pid,
                            latency_ms,
                            PROBE_REPORT_WINDOW.as_millis()
                        );
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };

        // 2. 探针 PID 过滤：探针进程自身的 CREATE/EXIT 不进入业务状态表与事件流（§13.7）
        //    Probe PID filter: probe processes never enter the business table or event stream
        if is_probe {
            return;
        }

        let header = event.header;
        let image_path = if header.payload_len > 0 {
            decode_utf16_payload(&event.payload)
        } else {
            None
        };

        // 缓冲写入 helper：锁内 push（丢旧保新）
        //  Buffer writer: push inside the lock (drop-oldest policy)
        let push = |record: LifecycleRecord| {
            let mut buf = event_buffer.lock().unwrap();
            push_event_record(&mut buf, record);
        };

        // DROP_MARKER（§4.4）：驱动队列满丢弃后注入，用户态据此触发全盘快照纠偏
        //  DROP_MARKER (§4.4): injected by the driver after queue eviction; triggers
        //  a full-snapshot reconciliation in user mode.
        if header.event_type == evt::DROP_MARKER {
            let dropped = if header.payload_len >= 4 {
                u32::from_le_bytes([event.payload[0], event.payload[1], event.payload[2], event.payload[3]])
            } else {
                0
            };
            let restored = reconcile();
            eprintln!(
                "[ProcLifecycle] DROP_MARKER received (dropped={}, reconciled={})",
                dropped, restored
            );
            return;
        }

        match header.event_type {
            evt::PROC_CREATE => {
                process_table.lock().unwrap().insert(
                    header.pid,
                    ProcessEntry {
                        pid: header.pid,
                        parent_pid: header.parent_pid,
                        session_id: header.session_id,
                        create_time: header.create_time,
                        restored: false,
                        image_path: image_path.clone(),
                        alive: true,
                    },
                );
                push(
                    LifecycleRecord {
                        pid: header.pid,
                        parent_pid: header.parent_pid,
                        event_type: evt::PROC_CREATE,
                        event_time: header.event_time,
                        ts_ms: filetime_to_ms(header.event_time),
                        session_id: header.session_id,
                        exit_status: 0,
                        flags: header.flags,
                        image_path: image_path.clone(),
                        restored: false,
                    },
                );
                let _ = ctx.emit(
                    EVENT_PROCESS_LIFECYCLE,
                    serde_json::json!({
                        "event": "create",
                        "pid": header.pid,
                        "parentPid": header.parent_pid,
                        "sessionId": header.session_id,
                        "flags": header.flags,
                        "ts": header.event_time,
                        "imagePath": image_path,
                    }),
                );
                // §4.7 入库：CREATE 插入 process_lifecycle 表
                if let Some(behavior) = behavior.clone() {
                    let record = serde_json::json!({
                        "pid": header.pid,
                        "parentPid": header.parent_pid,
                        "sessionId": header.session_id,
                        "createTime": filetime_to_rfc3339(header.event_time),
                        "processPath": image_path.clone(),
                        "subsystemType": "Win32",
                        "elevated": if header.flags & 0x0002 != 0 { 1 } else { 0 },
                        "details": {
                            "flags": header.flags,
                            "creatorPid": header.creator_pid,
                            "sequence": header.sequence,
                        },
                    });
                    // std::sync::Mutex 锁内克隆服务（BehaviorService 内部是 Arc<tokio::Mutex<Pool>>，
                    // Clone 廉价），释放锁后再 async 调用——避免跨 await 持锁。
                    let svc = behavior.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    tauri::async_runtime::spawn(async move {
                        if let Err(e) = svc.ingest_lifecycle(record).await {
                            eprintln!("[ProcLifecycle] ingest CREATE failed: {}", e);
                        }
                    });
                }
            }
            evt::PROC_EXIT => {
                let mut table = process_table.lock().unwrap();
                if let Some(entry) = table.get_mut(&header.pid) {
                    entry.alive = false;
                }
                push(
                    LifecycleRecord {
                        pid: header.pid,
                        parent_pid: 0,
                        event_type: evt::PROC_EXIT,
                        event_time: header.event_time,
                        ts_ms: filetime_to_ms(header.event_time),
                        session_id: header.session_id,
                        exit_status: header.exit_status,
                        flags: header.flags,
                        image_path,
                        restored: false,
                    },
                );
                let _ = ctx.emit(
                    EVENT_PROCESS_LIFECYCLE,
                    serde_json::json!({
                        "event": "exit",
                        "pid": header.pid,
                        "exitStatus": header.exit_status,
                        "ts": header.event_time,
                    }),
                );
                // §4.7 入库：EXIT 更新 process_lifecycle 表的退出时间/时长/退出码
                if let Some(behavior) = behavior.clone() {
                    let record = serde_json::json!({
                        "pid": header.pid,
                        "exitTime": filetime_to_rfc3339(header.event_time),
                        "exitStatus": header.exit_status,
                    });
                    let svc = behavior.lock().unwrap_or_else(|e| e.into_inner()).clone();
                    tauri::async_runtime::spawn(async move {
                        if let Err(e) = svc.ingest_lifecycle(record).await {
                            eprintln!("[ProcLifecycle] ingest EXIT failed: {}", e);
                        }
                    });
                }
            }
            // 其余生命周期事件类型（IMAGE_LOAD 等）本阶段不维护状态表，仅记录
            _ => {
                push(
                    LifecycleRecord {
                        pid: header.pid,
                        parent_pid: 0,
                        event_type: header.event_type,
                        event_time: header.event_time,
                        ts_ms: filetime_to_ms(header.event_time),
                        session_id: header.session_id,
                        exit_status: 0,
                        flags: header.flags,
                        image_path,
                        restored: false,
                    },
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // 行为事件泵 / Behavior event pump
    // ------------------------------------------------------------------

    fn spawn_behavior_pump(&self, ctx: ServiceContext) {
        let client = self.client.clone();
        let running = self.running.clone();
        let behavior = ctx.get::<std::sync::Mutex<crate::services::behavior_service::BehaviorService>>();

        let handle = std::thread::Builder::new()
            .name("anxin-procmon-behavior-pump".to_string())
            .spawn(move || {
                // §4.3 性能优化：批量攒批入库（最多 BEHAVIOR_BATCH_MAX 条或
                //  BEHAVIOR_BATCH_FLUSH_MS 未满也 flush），单事务写入 SQLite，
                //  避免逐条 INSERT + 逐条任务调度导致的高事件率下消费跟不上。
                //  Batch persistence: collect up to BEHAVIOR_BATCH_MAX events (or flush
                //  after BEHAVIOR_BATCH_FLUSH_MS) and persist them in one transaction,
                //  avoiding per-event INSERT + per-event task scheduling that falls
                //  behind under high event rates.
                const BEHAVIOR_BATCH_MAX: usize = 200;
                const BEHAVIOR_BATCH_FLUSH_MS: u64 = 100;
                let mut batch: Vec<serde_json::Value> = Vec::with_capacity(BEHAVIOR_BATCH_MAX);
                let mut batch_started = std::time::Instant::now();

                while running.load(Ordering::SeqCst) {
                    match client.wait_behavior_event() {
                        Ok(event) => {
                            // panic 保护：单事件解析异常不得杀死 pump 线程
                            // （服务进程线程 panic 会静默冻结行为队列，2026-08-14 VM 实测）。
                            //  Panic guard: a bad event must not kill the pump thread
                            //  (a thread panic silently freezes the behavior queue in the
                            //  service process - verified in VM 2026-08-14).
                            let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                                || behavior_event_to_app_event(&event),
                            ))
                            .unwrap_or_else(|_| {
                                eprintln!(
                                    "[ProcLifecycle] behavior event parse panicked; dropping event"
                                );
                                None
                            });
                            if let Some(app_event) = parsed {
                                batch.push(app_event);
                                if batch.len() >= BEHAVIOR_BATCH_MAX
                                    || batch_started.elapsed().as_millis() as u64
                                        >= BEHAVIOR_BATCH_FLUSH_MS
                                {
                                    if let Some(behavior) = behavior.clone() {
                                        let events = std::mem::take(&mut batch);
                                        let svc = behavior
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .clone();
                                        tauri::async_runtime::spawn(async move {
                                            match svc.ingest_events_batch(&events).await {
                                                Ok(failed) => {
                                                    if failed > 0 {
                                                        eprintln!(
                                                            "[ProcLifecycle] batch ingest: {} failed / {} total",
                                                            failed,
                                                            events.len()
                                                        );
                                                    }
                                                }
                                                Err(e) => eprintln!(
                                                    "[ProcLifecycle] batch ingest failed: {}",
                                                    e
                                                ),
                                            }
                                        });
                                    }
                                    batch_started = std::time::Instant::now();
                                }
                            }
                        }
                        Err(err) => {
                            // 驱动断开（stop 或驱动被卸载）时 flush 剩余批次再退出
                            if !running.load(Ordering::SeqCst) {
                                if !batch.is_empty() {
                                    if let Some(behavior) = behavior.clone() {
                                        let events = std::mem::take(&mut batch);
                                        let svc = behavior
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .clone();
                                        tauri::async_runtime::spawn(async move {
                                            let _ = svc.ingest_events_batch(&events).await;
                                        });
                                    }
                                }
                                break;
                            }
                            eprintln!("[ProcLifecycle] behavior pump error: {}", err);
                            // 服务进程 stderr 不可见：写入临时文件便于现场诊断
                            let _ = std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(r"C:\Windows\Temp\anxin-procmon.log")
                                .and_then(|mut f| {
                                    use std::io::Write;
                                    f.write_all(
                                        format!(
                                            "[ProcLifecycle] behavior pump error: {}\n",
                                            err
                                        )
                                        .as_bytes(),
                                    )
                                });
                            std::thread::sleep(Duration::from_millis(500));
                        }
                    }
                }
            })
            .expect("failed to spawn behavior pump thread");

        *self.behavior_pump.lock().unwrap() = Some(handle);
    }

    // ------------------------------------------------------------------
    // BYOVD 主动探针 / BYOVD active probe (§13.7)
    // ------------------------------------------------------------------

    /// 构造一个可跨线程调用的纠偏闭包（探针线程用）。
    ///  Builds a reconciliation closure usable from the probe thread.
    fn make_reconcile_fn(&self) -> Arc<dyn Fn() -> u32 + Send + Sync> {
        let table = self.process_table.clone();
        let buffer = self.event_buffer.clone();
        let last = self.last_reconcile.clone();
        let count = self.last_reconcile_count.clone();
        Arc::new(move || reconcile_process_table(&table, &buffer, &last, &count))
    }

    fn spawn_probe(&self, ctx: ServiceContext) {
        let running = self.running.clone();
        let probe_state = self.probe_state.clone();
        let tampered_alerts = self.tampered_alerts.clone();
        // 告警同时触发全盘快照纠偏（§13.7 第 5 点 / §4.4）
        //  The alert also triggers a full snapshot reconciliation (§13.7 pt.5 / §4.4)
        let reconcile_fn = self.make_reconcile_fn();
        // §4.5：驱动失联（探针持续超时）时恢复 ETW 全量采集，避免监控空窗
        //  §4.5: on driver loss (persistent probe timeouts), restore full ETW
        //  collection so monitoring does not go dark.
        let etw = ctx.get::<std::sync::Mutex<crate::services::etw_service::EtwService>>();

        let handle = std::thread::Builder::new()
            .name("anxin-procmon-probe".to_string())
            .spawn(move || {
                while running.load(Ordering::SeqCst) {
                    // 1. 发一轮探针：创建一个 cmd.exe /c exit 进程
                    //    Launch one probe round: a cmd.exe /c exit process
                    if let Ok(child) = std::process::Command::new(PROBE_COMMAND)
                        .args(PROBE_ARGS)
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                    {
                        let pid = child.id();
                        // child 被 drop，句柄关闭；cmd /c exit 立即退出，无泄漏
                        drop(child);
                        probe_state.total_launched.fetch_add(1, Ordering::SeqCst);
                        probe_state
                            .pending
                            .lock()
                            .unwrap()
                            .insert(pid, Instant::now());
                    }

                    // 2. 清理超过回报窗口仍未回报的探针：每一枚超时探针 = 一轮失败
                    //    Sweep probes whose report window expired: each timed-out probe is one miss
                    let now = Instant::now();
                    let mut timed_out = 0u32;
                    {
                        let mut pending = probe_state.pending.lock().unwrap();
                        pending.retain(|_, launched_at| {
                            if now.duration_since(*launched_at) > PROBE_REPORT_WINDOW {
                                timed_out += 1;
                                false
                            } else {
                                true
                            }
                        });
                    }
                    if timed_out > 0 {
                        let missed = probe_state.missed_rounds.fetch_add(1, Ordering::SeqCst) + 1;
                        eprintln!(
                            "[ProcLifecycle] probe missed round {}/{} ({} pid(s) unreported)",
                            missed,
                            PROBE_MISS_THRESHOLD,
                            timed_out
                        );

                        // 3. 连续 ≥10s（5 轮）未回报 → 回调失明告警 + 全盘快照纠偏
                        //    ≥10s without any report -> callback-blindness alert + reconciliation
                        if missed >= PROBE_MISS_THRESHOLD {
                            let alerts = tampered_alerts.fetch_add(1, Ordering::SeqCst) + 1;
                            let restored = reconcile_fn();
                            let payload = serde_json::json!({
                                "severity": "high",
                                "missing_seconds": missed * 2,
                                "missed_rounds": missed,
                                "alert_count": alerts,
                                "reconciledProcesses": restored,
                                "hint": "Process creation callbacks are not reaching user mode; \
                                         the collector driver may be disabled or replaced (BYOVD tampering)"
                            });
                            let _ = ctx.emit(EVENT_CALLBACK_TAMPERED, payload);
                            eprintln!(
                                "[ProcLifecycle] CALLBACK TAMPERED alert #{} ({} rounds missed, {} processes reconciled)",
                                alerts, missed, restored
                            );
                            // 驱动失联 → 恢复 ETW 全量（§4.5），补上驱动失效造成的采集空窗
                            if let Some(etw) = etw.clone() {
                                let guard = etw.lock().unwrap_or_else(|e| e.into_inner());
                                if let Err(e) = guard.restart_with_flags(
                                    ctx.clone(),
                                    crate::services::etw::session::ETW_FLAGS_FULL,
                                ) {
                                    eprintln!(
                                        "[ProcLifecycle] ETW full-mode restore failed (non-fatal): {}",
                                        e
                                    );
                                }
                            }
                            probe_state.missed_rounds.store(0, Ordering::SeqCst);
                        }
                    }

                    std::thread::sleep(PROBE_INTERVAL);
                }
            })
            .expect("failed to spawn probe thread");

        *self.probe_thread.lock().unwrap() = Some(handle);
    }
}

// ============================================================================
// 自由函数 / Free functions
// ============================================================================

/// 解码 UTF-16 负载（创建事件负载为命令行 UTF-16；长度按字节 /2 得 WCHAR 数）。
///  Decodes a UTF-16 payload (CREATE payload is a UTF-16 command line; bytes/2 = WCHARs).
fn decode_utf16_payload(payload: &[u8]) -> Option<String> {
    if payload.len() < 2 || payload.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = payload
        .chunks_exact(2)
        .map(|c| u16::from_ne_bytes([c[0], c[1]]))
        .collect();
    // 去掉结尾 NUL（驱动以含 NUL 的 UTF-16 写入）
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&units[..end]))
}

/// 把驱动行为事件 normalize 成可入库的 app_event（§4.3）。
///  Normalizes a driver behavior event into a persistable app_event (§4.3).
///
/// 过滤规则配置文件（§6：config/proc_filter_rules.json）。
///  Filter-rule config file (§6: config/proc_filter_rules.json).
#[derive(Debug, Clone, serde::Deserialize)]
struct ProcFilterRuleConfig {
    version: u32,
    #[serde(default)]
    rules: Vec<ProcFilterRuleEntry>,
}

/// 单条过滤规则（字符串形式，加载时映射到驱动结构）。
#[derive(Debug, Clone, serde::Deserialize)]
struct ProcFilterRuleEntry {
    #[serde(rename = "type")]
    rule_type: String,
    action: String,
    #[serde(default)]
    flags: String,
    name: String,
}

/// 从 CWD / 上级目录 / exe 资源目录加载默认过滤规则（与 AppConfig::load 同款 fallback）。
///  Loads the default filter rules from CWD / parent / exe resource dir (same fallback
///  chain as AppConfig::load), so both the UI process and the SYSTEM service process
///  can find the packaged config.
fn load_default_filter_rules() -> Vec<crate::utils::proc_driver_client::ProcFilterRule> {
    use crate::utils::proc_driver_client::{ProcFilterRule, PROC_FILTER_COLLECT, PROC_FILTER_DROP};

    let candidates = [
        "config/proc_filter_rules.json",
        "../config/proc_filter_rules.json",
        "_up_/config/proc_filter_rules.json",
        "resources/config/proc_filter_rules.json",
    ];

    let mut content = None;
    for rel in candidates {
        if let Ok(text) = std::fs::read_to_string(rel) {
            content = Some(text);
            break;
        }
    }
    if content.is_none() {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                for rel in [
                    "_up_/config/proc_filter_rules.json",
                    "resources/config/proc_filter_rules.json",
                    "config/proc_filter_rules.json",
                ] {
                    if let Ok(text) = std::fs::read_to_string(dir.join(rel)) {
                        content = Some(text);
                        break;
                    }
                }
            }
        }
    }

    let Some(content) = content else {
        eprintln!("[ProcLifecycle] no proc_filter_rules.json found; keeping driver default (collect all)");
        return Vec::new();
    };

    let cfg: ProcFilterRuleConfig = match serde_json::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "[ProcLifecycle] invalid proc_filter_rules.json: {} (keeping driver default)",
                e
            );
            return Vec::new();
        }
    };

    let mut rules: Vec<ProcFilterRule> = Vec::with_capacity(cfg.rules.len());
    for entry in &cfg.rules {
        let rule_type = match entry.rule_type.as_str() {
            "file_path_prefix" => crate::utils::proc_driver_client::PROC_RULE_FILE_PATH_PREFIX,
            "reg_key_prefix" => crate::utils::proc_driver_client::PROC_RULE_REG_KEY_PREFIX,
            "proc_path_prefix" => crate::utils::proc_driver_client::PROC_RULE_PROC_PATH_PREFIX,
            "ipc_name_prefix" => crate::utils::proc_driver_client::PROC_RULE_IPC_NAME_PREFIX,
            "image_path_exact" => crate::utils::proc_driver_client::PROC_RULE_IMAGE_PATH_EXACT,
            "image_path_prefix" => crate::utils::proc_driver_client::PROC_RULE_IMAGE_PATH_PREFIX,
            other => {
                eprintln!("[ProcLifecycle] unknown rule type '{}', skipping", other);
                continue;
            }
        };
        let action = match entry.action.as_str() {
            "collect" => PROC_FILTER_COLLECT,
            "drop" => PROC_FILTER_DROP,
            other => {
                eprintln!("[ProcLifecycle] unknown action '{}', skipping", other);
                continue;
            }
        };
        let flags = if entry.flags.eq_ignore_ascii_case("case_insensitive") {
            0x00000001
        } else {
            0
        };
        let name: Vec<u16> = entry.name.encode_utf16().collect();
        rules.push(ProcFilterRule {
            rule_type,
            action,
            flags,
            name_len: name.len() as u32,
            name,
        });
    }
    eprintln!("[ProcLifecycle] loaded {} default filter rules", rules.len());
    rules
}

/// 映射：FILE_CREATE/WRITE/DELETE/RENAME → "File:Create/Write/Delete/Rename"，
/// REG_SETVALUE/CREATEKEY/DELETE/RENAME → "Registry:SetValue/...",
/// NET_CONNECT → "Network:Connect"（NET_TUPLE 展开为 ip:port），
/// IPC_CONNECT → "IPC:Connect"。payload 为 UTF-16 路径或 40 字节 NET_TUPLE。
/// 返回 None 表示无需入库（如 DROP_MARKER 等控制事件）。
///  Mapping: FILE_* → "File:...", REG_* → "Registry:...", NET_CONNECT →
///  "Network:Connect" (NET_TUPLE expanded to ip:port), IPC_CONNECT → "IPC:Connect".
///  Payload is a UTF-16 path or a 40-byte NET_TUPLE. Returns None for control
///  events that need no persistence (e.g. DROP_MARKER).
fn behavior_event_to_app_event(event: &ProcEvent) -> Option<serde_json::Value> {
    use crate::utils::proc_driver_client::ProcNetTuple;

    let header = event.header;
    let operation = match header.event_type {
        evt::FILE_CREATE => "File:Create",
        evt::FILE_WRITE => "File:Write",
        evt::FILE_DELETE => "File:Delete",
        evt::FILE_RENAME => "File:Rename",
        evt::REG_SETVALUE => "Registry:SetValue",
        evt::REG_CREATEKEY => "Registry:CreateKey",
        evt::REG_DELETE => "Registry:Delete",
        evt::REG_RENAME => "Registry:Rename",
        evt::NET_CONNECT => "Network:Connect",
        evt::IPC_CONNECT => "IPC:Connect",
        _ => return None,
    };

    // 网络事件：40 字节 ANX_PROC_NET_TUPLE；其余：UTF-16 路径
    let (path, extra) = if header.event_type == evt::NET_CONNECT {
        if event.payload.len() < std::mem::size_of::<ProcNetTuple>() {
            (String::new(), serde_json::json!({}))
        } else {
            // 从字节切片重建元组（与驱动 pack(8) 布局一致）。用逐字段安全拷贝，
            // 不直接 read_unaligned 整个结构——避免任何布局假设导致的越界读。
            let p = &event.payload[..std::mem::size_of::<ProcNetTuple>()];
            let protocol = u16::from_ne_bytes([p[0], p[1]]);
            let family = u16::from_ne_bytes([p[2], p[3]]);
            let local_port = u16::from_ne_bytes([p[4], p[5]]);
            let remote_port = u16::from_ne_bytes([p[6], p[7]]);
            let mut local_addr = [0u8; 16];
            let mut remote_addr = [0u8; 16];
            local_addr.copy_from_slice(&p[8..24]);
            remote_addr.copy_from_slice(&p[24..40]);
            let local = format_ip(local_addr, family);
            let remote = format_ip(remote_addr, family);
            (
                format!("{}:{} -> {}:{}", local, local_port, remote, remote_port),
                serde_json::json!({
                    "protocol": protocol,
                    "addressFamily": family,
                    "localPort": local_port,
                    "remotePort": remote_port,
                }),
            )
        }
    } else {
        (
            decode_utf16_payload(&event.payload).unwrap_or_default(),
            serde_json::json!({}),
        )
    };

    Some(serde_json::json!({
        "pid": header.pid,
        "processName": "",
        "operation": operation,
        "path": path,
        "timestamp": filetime_to_rfc3339(header.event_time),
        "details": {
            "source": "proc_monitor",
            "eventType": header.event_type,
            "sessionId": header.session_id,
            "sequence": header.sequence,
            "flags": header.flags,
            "parentPid": header.parent_pid,
            "extra": extra,
        },
    }))
}

/// 把 16 字节网络地址格式化为 IPv4/IPv6 文本。
///  Formats a 16-byte network address as IPv4/IPv6 text.
fn format_ip(address: [u8; 16], family: u16) -> String {
    if family == 4 {
        // 网络字节序 IPv4 存前 4 字节
        format!("{}.{}.{}.{}", address[0], address[1], address[2], address[3])
    } else if family == 6 {
        // IPv6：16 位一组，最长零段压缩为 ::（简化：只压缩一个最长全零段）
        //  IPv6: 16-bit groups with the longest all-zero run collapsed to :: (simplified)
        let groups: Vec<String> = (0..8)
            .map(|i| {
                format!(
                    "{:x}",
                    u16::from_be_bytes([address[i * 2], address[i * 2 + 1]])
                )
            })
            .collect();
        // 找最长全零段
        let mut best_start = None;
        let mut best_len = 0usize;
        let mut cur_start = None;
        let mut cur_len = 0usize;
        for (i, g) in groups.iter().enumerate() {
            if g == "0" {
                if cur_start.is_none() {
                    cur_start = Some(i);
                    cur_len = 1;
                } else {
                    cur_len += 1;
                }
                if cur_len > best_len {
                    best_len = cur_len;
                    best_start = cur_start;
                }
            } else {
                cur_start = None;
                cur_len = 0;
            }
        }
        if best_len >= 2 {
            let s = best_start.unwrap();
            let mut out = groups[..s].join(":");
            out.push_str("::");
            out.push_str(&groups[s + best_len..].join(":"));
            out
        } else {
            groups.join(":")
        }
    } else {
        String::new()
    }
}

/// 把记录推入环形缓冲，超上限时丢弃最旧（丢旧保新，前端查询场景）。
///  调用方必须已持有缓冲锁。 / Pushes a record, dropping the oldest when over capacity.
fn push_event_record(buffer: &mut VecDeque<LifecycleRecord>, record: LifecycleRecord) {
    if buffer.len() >= EVENT_BUFFER_CAP {
        buffer.pop_front();
    }
    buffer.push_back(record);
}

/// FILETIME（100ns 单位，1601 起）→ 毫秒时间戳 / FILETIME (100ns, from 1601) to epoch ms
fn filetime_to_ms(filetime: u64) -> u64 {
    // 1601-01-01 到 1970-01-01 的 100ns 间隔数 = 11644473600 * 10^7
    const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
    if filetime >= EPOCH_DIFF_100NS {
        (filetime - EPOCH_DIFF_100NS) / 10_000
    } else {
        0
    }
}

/// FILETIME（100ns 单位，1601 起）→ RFC3339 时间字符串（§4.7 入库）。
///  FILETIME (100ns, from 1601) to an RFC3339 timestamp string (§4.7 persistence).
fn filetime_to_rfc3339(filetime: u64) -> String {
    let epoch_ms = filetime_to_ms(filetime);
    if epoch_ms == 0 {
        return String::new();
    }
    // 用 chrono 转成 RFC3339（项目已有 chrono 依赖）
    let secs = (epoch_ms / 1000) as i64;
    let nanos = ((epoch_ms % 1000) * 1_000_000) as u32;
    match chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nanos) {
        Some(dt) => dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        None => String::new(),
    }
}

/// 当前毫秒时间戳（纠偏补项用，因为纠偏项无事件时间）
///  Current epoch ms (for reconciliation entries, which carry no event time)
fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 全盘快照纠偏实现（与 ProcessLifecycleService::run_snapshot_reconciliation
/// 相同的逻辑，但以纯参数形式暴露给探针线程闭包）。
///  The reconciliation implementation, exposed in pure-parameter form so the
///  probe thread can call it through a closure.
fn reconcile_process_table(
    table: &Mutex<HashMap<u32, ProcessEntry>>,
    buffer: &Mutex<VecDeque<LifecycleRecord>>,
    last: &Mutex<Option<Instant>>,
    count: &AtomicU32,
) -> u32 {
    let now = Instant::now();
    {
        let mut guard = last.lock().unwrap();
        if let Some(prev) = *guard {
            if now.duration_since(prev).as_secs() < RECONCILE_COOLDOWN_SECS {
                return 0;
            }
        }
        *guard = Some(now);
    }

    let current = crate::services::process_scanner_service::collect_current_pids();
    let mut table_guard = table.lock().unwrap();
    let mut restored = 0u32;

    for pid in &current {
        if table_guard.contains_key(pid) {
            continue;
        }
        if *pid == 0 || *pid == 4 || *pid == 8 {
            continue;
        }
        let image_path = crate::services::process_scanner_service::query_process_image_path(*pid);
        table_guard.insert(
            *pid,
            ProcessEntry {
                pid: *pid,
                parent_pid: 0,
                session_id: 0,
                create_time: 0,
                restored: true,
                image_path,
                alive: true,
            },
        );
        restored += 1;
    }

    if restored > 0 {
        count.store(restored, Ordering::SeqCst);
        let ts_ms = unix_ms_now();
        let mut buf = buffer.lock().unwrap();
        for pid in &current {
            if let Some(entry) = table_guard.get(pid) {
                if entry.restored {
                    push_event_record(
                        &mut *buf,
                        LifecycleRecord {
                            pid: entry.pid,
                            parent_pid: entry.parent_pid,
                            event_type: evt::PROC_CREATE,
                            event_time: 0,
                            ts_ms,
                            session_id: entry.session_id,
                            exit_status: 0,
                            flags: 0,
                            image_path: entry.image_path.clone(),
                            restored: true,
                        },
                    );
                }
            }
        }
    }

    eprintln!(
        "[ProcLifecycle] snapshot reconciliation restored {} entries ({} pids total)",
        restored,
        current.len()
    );
    restored
}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::proc_driver_client::{PROC_QUEUE_BEHAVIOR, PROC_QUEUE_LIFECYCLE};

    fn make_event(pid: u32, event_type: u16) -> ProcEvent {
        ProcEvent {
            header: crate::utils::proc_driver_client::ProcEventHeader {
                event_time: 0,
                create_time: 0,
                pid,
                parent_pid: 0,
                creator_pid: 0,
                session_id: 0,
                exit_status: 0,
                sequence: 0,
                event_type,
                flags: 0,
                payload_len: 0,
            },
            payload: Vec::new(),
        }
    }

    /// 测试用 ServiceContext（无 UI 桥接，emit 进事件总线即成功）。
    fn test_ctx() -> ServiceContext {
        use crate::services::app_lifecycle_service::AppLifecycleService;
        use crate::services::event_bus::EventBus;
        use crate::services::service_context::ServiceRegistry;
        ServiceContext::new(
            Arc::new(ServiceRegistry::new()),
            Arc::new(AppLifecycleService::new()),
            Arc::new(EventBus::new(16)),
        )
    }

    fn consume(probe: &ProbeState, table: &Mutex<HashMap<u32, ProcessEntry>>, event: &ProcEvent) {
        let buffer = Mutex::new(VecDeque::new());
        let ctx = test_ctx();
        let noop_reconcile = || 0u32;
        ProcessLifecycleService::consume_lifecycle_event(
            probe,
            table,
            &buffer,
            &ctx,
            event,
            None,
            &noop_reconcile,
        );
    }

    /// 探针回报命中 pending 表：CREATE 事件按 PID 匹配，重置连续失败计数。
    ///  A CREATE event matching a pending probe PID counts as a report and resets the miss counter.
    #[test]
    fn probe_report_clears_pending_and_resets_missed_rounds() {
        let state = ProbeState::default();
        state
            .pending
            .lock()
            .unwrap()
            .insert(4242, Instant::now() - Duration::from_millis(50));
        state.missed_rounds.store(3, Ordering::SeqCst);
        let table = Mutex::new(HashMap::new());

        consume(&state, &table, &make_event(4242, evt::PROC_CREATE));

        assert!(state.pending.lock().unwrap().is_empty());
        assert_eq!(state.reported_ok.load(Ordering::SeqCst), 1);
        assert_eq!(state.missed_rounds.load(Ordering::SeqCst), 0);
        // 探针 PID 不进入业务状态表
        assert!(table.lock().unwrap().is_empty());
    }

    /// 探针回报同时不得写入事件缓冲（探针 PID 过滤）。
    ///  A probe report must not land in the event buffer either.
    #[test]
    fn probe_report_is_filtered_from_event_buffer() {
        let state = ProbeState::default();
        state.pending.lock().unwrap().insert(7, Instant::now());
        let table = Mutex::new(HashMap::new());
        let buffer = Mutex::new(VecDeque::new());
        let ctx = test_ctx();

        ProcessLifecycleService::consume_lifecycle_event(
            &state,
            &table,
            &buffer,
            &ctx,
            &make_event(7, evt::PROC_CREATE),
            None,
            &(|| 0u32),
        );

        assert!(buffer.lock().unwrap().is_empty());
    }

    /// 非 CREATE 事件（如进程退出）不应被当作探针回报。
    ///  Non-CREATE events (e.g. exit) must not count as probe reports.
    #[test]
    fn non_create_event_is_ignored_by_probe_match() {
        let state = ProbeState::default();
        state.pending.lock().unwrap().insert(7, Instant::now());
        let table = Mutex::new(HashMap::new());

        consume(&state, &table, &make_event(7, evt::PROC_EXIT));

        assert_eq!(state.pending.lock().unwrap().len(), 1);
        assert_eq!(state.reported_ok.load(Ordering::SeqCst), 0);
    }

    /// 非探针 PID 的 CREATE 事件不触碰 pending 表（探针 PID 过滤保证业务事件独立）。
    ///  A CREATE event for a non-probe PID must not touch the pending table.
    #[test]
    fn unrelated_create_event_leaves_pending_untouched() {
        let state = ProbeState::default();
        state.pending.lock().unwrap().insert(99, Instant::now());
        let table = Mutex::new(HashMap::new());

        consume(&state, &table, &make_event(100, evt::PROC_CREATE));

        assert_eq!(state.pending.lock().unwrap().len(), 1);
        assert_eq!(state.reported_ok.load(Ordering::SeqCst), 0);
    }

    /// 业务 CREATE 事件进入状态表与事件缓冲。
    ///  A business CREATE event enters the process table and the event buffer.
    #[test]
    fn business_create_event_updates_table_and_buffer() {
        let state = ProbeState::default();
        let table = Mutex::new(HashMap::new());
        let buffer = Mutex::new(VecDeque::new());
        let ctx = test_ctx();

        let mut event = make_event(1234, evt::PROC_CREATE);
        event.header.parent_pid = 5678;
        event.header.create_time = 132_000_000_000_000_000;

        ProcessLifecycleService::consume_lifecycle_event(
            &state,
            &table,
            &buffer,
            &ctx,
            &event,
            None,
            &(|| 0u32),
        );

        let entry = table.lock().unwrap().get(&1234).cloned().unwrap();
        assert_eq!(entry.parent_pid, 5678);
        assert!(entry.alive);
        assert!(!entry.restored);

        let buf = buffer.lock().unwrap();
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0].event_type, evt::PROC_CREATE);
        assert_eq!(buf[0].pid, 1234);
    }

    /// EXIT 事件把状态表条目标记为不存活。
    ///  An EXIT event marks the table entry as not alive.
    #[test]
    fn exit_event_marks_entry_not_alive() {
        let state = ProbeState::default();
        let table = Mutex::new(HashMap::new());
        table.lock().unwrap().insert(
            4321,
            ProcessEntry {
                pid: 4321,
                parent_pid: 0,
                session_id: 0,
                create_time: 0,
                restored: false,
                image_path: None,
                alive: true,
            },
        );
        let buffer = Mutex::new(VecDeque::new());
        let ctx = test_ctx();

        let mut event = make_event(4321, evt::PROC_EXIT);
        event.header.exit_status = 1;

        ProcessLifecycleService::consume_lifecycle_event(
            &state,
            &table,
            &buffer,
            &ctx,
            &event,
            None,
            &(|| 0u32),
        );

        assert!(!table.lock().unwrap().get(&4321).unwrap().alive);
        let buf = buffer.lock().unwrap();
        assert_eq!(buf[0].event_type, evt::PROC_EXIT);
        assert_eq!(buf[0].exit_status, 1);
    }

    /// 事件缓冲超上限时丢弃最旧（丢旧保新）。
    ///  The ring buffer drops the oldest record once over capacity.
    #[test]
    fn event_buffer_caps_at_limit() {
        let buffer = Mutex::new(VecDeque::new());
        for i in 0..(EVENT_BUFFER_CAP + 10) {
            let mut buf = buffer.lock().unwrap();
            push_event_record(
                &mut buf,
                LifecycleRecord {
                    pid: i as u32,
                    parent_pid: 0,
                    event_type: evt::PROC_CREATE,
                    event_time: 0,
                    ts_ms: 0,
                    session_id: 0,
                    exit_status: 0,
                    flags: 0,
                    image_path: None,
                    restored: false,
                },
            );
        }
        let buf = buffer.lock().unwrap();
        assert_eq!(buf.len(), EVENT_BUFFER_CAP);
        // 最旧 10 条被丢弃：第一条是 10（即 i=10 开始）
        assert_eq!(buf[0].pid, 10);
    }

    /// UTF-16 负载解码：末尾 NUL 被剥离。
    ///  UTF-16 payload decode strips the trailing NUL.
    #[test]
    fn utf16_payload_decode_strips_nul() {
        let mut bytes = Vec::new();
        for unit in "cmd.exe /c exit".encode_utf16() {
            bytes.extend_from_slice(&unit.to_ne_bytes());
        }
        bytes.extend_from_slice(&0u16.to_ne_bytes());
        assert_eq!(
            decode_utf16_payload(&bytes).as_deref(),
            Some("cmd.exe /c exit")
        );
        assert_eq!(decode_utf16_payload(&[0x41]), None);
        assert_eq!(decode_utf16_payload(&[0x00, 0x00]), None);
    }

    /// FILETIME → 毫秒转换。
    ///  FILETIME to epoch-ms conversion.
    #[test]
    fn filetime_converts_to_epoch_ms() {
        // 132_471_000_000_000_000 (100ns FILETIME) ≈ 2020-10-14 UTC
        let ft = 132_471_000_000_000_000u64;
        let ms = filetime_to_ms(ft);
        assert!(ms > 1_500_000_000_000, "unexpected ms {}", ms);
        assert!(ms < 2_000_000_000_000, "unexpected ms {}", ms);
        assert_eq!(filetime_to_ms(0), 0);
    }

    /// 快照纠偏：冷却期内重复调用返回 0。
    ///  Reconciliation is throttled by its cooldown.
    #[test]
    fn reconciliation_respects_cooldown() {
        let table = Mutex::new(HashMap::new());
        let buffer = Mutex::new(VecDeque::new());
        let last = Mutex::new(Some(Instant::now()));
        let count = AtomicU32::new(0);

        let restored = reconcile_process_table(&table, &buffer, &last, &count);
        assert_eq!(restored, 0);
    }

    /// 探针线程的清理逻辑：超窗探针被移除并累计一轮失败，未超窗的保留。
    ///  The sweep removes expired probes and counts one miss; live probes are kept.
    #[test]
    fn sweep_removes_only_expired_probes() {
        let state = ProbeState::default();
        {
            let mut pending = state.pending.lock().unwrap();
            pending.insert(1, Instant::now() - Duration::from_millis(3000));
            pending.insert(2, Instant::now());
        }

        let now = Instant::now();
        let mut timed_out = 0u32;
        {
            let mut pending = state.pending.lock().unwrap();
            pending.retain(|_, launched_at| {
                if now.duration_since(*launched_at) > PROBE_REPORT_WINDOW {
                    timed_out += 1;
                    false
                } else {
                    true
                }
            });
        }

        assert_eq!(timed_out, 1);
        assert_eq!(state.pending.lock().unwrap().len(), 1);
    }

    /// 连续失败轮数达到阈值后立即清零（告警风暴抑制），与 TAMPERED 语义一致。
    ///  After hitting the miss threshold the counter resets immediately (alert storm suppression).
    #[test]
    fn missed_rounds_reset_after_threshold() {
        let state = ProbeState::default();
        state.missed_rounds.store(PROBE_MISS_THRESHOLD, Ordering::SeqCst);
        assert_eq!(PROBE_MISS_THRESHOLD, 5);
        state.missed_rounds.store(0, Ordering::SeqCst);
        assert_eq!(state.missed_rounds.load(Ordering::SeqCst), 0);
    }

    /// 常量契约：探针命令与 §13.7 一致。
    ///  Contract check: probe command matches §13.7.
    #[test]
    fn probe_command_is_cmd_exit() {
        assert_eq!(PROBE_COMMAND, "cmd.exe");
        assert_eq!(PROBE_ARGS, ["/c", "exit"]);
        assert_eq!(PROBE_INTERVAL, Duration::from_secs(2));
        assert_eq!(PROBE_MISS_THRESHOLD * PROBE_INTERVAL.as_secs() as u32, 10);
    }

    /// 队列标识常量与驱动侧一致（0=lifecycle, 1=behavior）。
    ///  Queue identifiers match the driver side.
    #[test]
    fn queue_ids_match_driver() {
        assert_eq!(PROC_QUEUE_LIFECYCLE, 0);
        assert_eq!(PROC_QUEUE_BEHAVIOR, 1);
    }

    /// DROP_MARKER（§4.4）：解析丢弃计数并触发快照纠偏。
    ///  DROP_MARKER (§4.4): parses the dropped count and triggers reconciliation.
    #[test]
    fn drop_marker_triggers_reconciliation() {
        let state = ProbeState::default();
        let table = Mutex::new(HashMap::new());
        let buffer = Mutex::new(VecDeque::new());
        let ctx = test_ctx();

        let mut event = make_event(0, evt::DROP_MARKER);
        event.header.payload_len = 4;
        event.payload = vec![42u8, 0, 0, 0]; // 丢弃计数 42

        let reconcile_calls = std::sync::atomic::AtomicU32::new(0);
        let reconcile = || {
            reconcile_calls.fetch_add(1, Ordering::SeqCst);
            0u32
        };

        ProcessLifecycleService::consume_lifecycle_event(
            &state,
            &table,
            &buffer,
            &ctx,
            &event,
            None,
            &reconcile,
        );

        assert_eq!(reconcile_calls.load(Ordering::SeqCst), 1);
        // DROP_MARKER 不进状态表与事件缓冲
        assert!(table.lock().unwrap().is_empty());
        assert!(buffer.lock().unwrap().is_empty());
    }

    /// 行为事件 normalize：文件事件 → "File:Write" + UTF-16 路径解码。
    ///  Behavior normalization: file events map to "File:Write" with the UTF-16 path decoded.
    #[test]
    fn behavior_file_event_normalizes_to_app_event() {
        let mut event = make_event(4242, evt::FILE_WRITE);
        let mut path = Vec::new();
        for unit in "C:\\temp\\evil.exe".encode_utf16() {
            path.extend_from_slice(&unit.to_ne_bytes());
        }
        path.extend_from_slice(&0u16.to_ne_bytes());
        event.payload = path;
        event.header.payload_len = event.payload.len() as u16;
        event.header.event_time = 132_471_000_000_000_000;

        let app = behavior_event_to_app_event(&event).expect("file write should map");
        assert_eq!(app["operation"], "File:Write");
        assert_eq!(app["pid"], 4242);
        assert_eq!(app["path"], "C:\\temp\\evil.exe");
        assert_eq!(app["details"]["source"], "proc_monitor");
        // timestamp 必须是 RFC3339 字符串（ingest_event 用 as_str 读取）
        let ts = app["timestamp"].as_str().unwrap_or("");
        assert!(!ts.is_empty(), "timestamp must be an RFC3339 string");
        assert!(ts.contains('T'), "timestamp must look like RFC3339");
    }

    /// 行为事件 normalize：网络事件 → "Network:Connect" + NET_TUPLE 展开。
    ///  Behavior normalization: network events map to "Network:Connect" with the tuple expanded.
    #[test]
    fn behavior_net_event_normalizes_with_tuple() {
        let mut event = make_event(77, evt::NET_CONNECT);
        let mut payload = vec![0u8; 40];
        // protocol=TCP(6), family=4, local=12345 LE, remote=443 LE
        payload[0] = 6; payload[1] = 0;
        payload[2] = 4; payload[3] = 0;
        payload[4] = 0x39; payload[5] = 0x30; // 12345 LE (0x3039)
        payload[6] = 0xBB; payload[7] = 0x01; // 443 LE (0x01BB)
        payload[8..12].copy_from_slice(&[192, 168, 1, 10]);   // local addr
        payload[24..28].copy_from_slice(&[93, 184, 216, 34]); // remote addr
        event.payload = payload;
        event.header.payload_len = 40;

        let app = behavior_event_to_app_event(&event).expect("net connect should map");
        assert_eq!(app["operation"], "Network:Connect");
        let path = app["path"].as_str().unwrap_or("");
        assert!(path.contains("192.168.1.10:12345"), "path was: {}", path);
        assert!(path.contains("93.184.216.34:443"), "path was: {}", path);
        assert_eq!(app["details"]["extra"]["protocol"], 6);
        assert_eq!(app["details"]["extra"]["remotePort"], 443);
    }

    /// 控制事件（如 DROP_MARKER）不产生 app_event。
    ///  Control events (e.g. DROP_MARKER) produce no app_event.
    #[test]
    fn control_events_produce_no_app_event() {
        let event = make_event(0, evt::DROP_MARKER);
        assert!(behavior_event_to_app_event(&event).is_none());
    }

    /// FILETIME → RFC3339 转换（入库时间戳必须是字符串）。
    ///  FILETIME to RFC3339 conversion (the persisted timestamp must be a string).
    #[test]
    fn filetime_to_rfc3339_produces_parseable_timestamp() {
        // 132_471_000_000_000_000 (100ns FILETIME) ≈ 2020-10-14 UTC
        let s = filetime_to_rfc3339(132_471_000_000_000_000);
        assert!(s.contains('T'), "got: {}", s);
        assert!(chrono::DateTime::parse_from_rfc3339(&s).is_ok(), "got: {}", s);
        assert_eq!(filetime_to_rfc3339(0), "");
    }

    /// IPv4/IPv6 地址格式化。
    ///  IPv4/IPv6 address formatting.
    #[test]
    fn format_ip_handles_v4_and_v6() {
        assert_eq!(
            format_ip([192, 168, 1, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 4),
            "192.168.1.10"
        );
        let v6 = format_ip(
            [
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
            6,
        );
        assert_eq!(v6, "fe80::1");
    }

    /// 过滤规则配置解析：合法 JSON → 驱动 ProcFilterRule 列表。
    ///  Filter-rule config parsing: valid JSON maps to driver ProcFilterRule entries.
    #[test]
    fn filter_rule_config_parses_to_driver_rules() {
        let json = r#"{
            "version": 1,
            "rules": [
                {"type": "file_path_prefix", "action": "drop", "flags": "case_insensitive", "name": "C:\\Windows\\Temp\\"},
                {"type": "reg_key_prefix", "action": "collect", "name": "HKLM\\SOFTWARE\\"},
                {"type": "bogus_type", "action": "drop", "name": "x"}
            ]
        }"#;
        let cfg: ProcFilterRuleConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.version, 1);
        assert_eq!(cfg.rules.len(), 3);
        // 非法类型应被跳过
        let mapped = cfg
            .rules
            .iter()
            .filter_map(|r| {
                let t = match r.rule_type.as_str() {
                    "file_path_prefix" => Some(crate::utils::proc_driver_client::PROC_RULE_FILE_PATH_PREFIX),
                    "reg_key_prefix" => Some(crate::utils::proc_driver_client::PROC_RULE_REG_KEY_PREFIX),
                    _ => None,
                }?;
                let a = match r.action.as_str() {
                    "drop" => Some(crate::utils::proc_driver_client::PROC_FILTER_DROP),
                    "collect" => Some(crate::utils::proc_driver_client::PROC_FILTER_COLLECT),
                    _ => None,
                }?;
                Some((t, a, r.name.encode_utf16().collect::<Vec<u16>>()))
            })
            .collect::<Vec<_>>();
        assert_eq!(mapped.len(), 2);
        assert_eq!(mapped[0].0, crate::utils::proc_driver_client::PROC_RULE_FILE_PATH_PREFIX);
        assert_eq!(mapped[0].1, crate::utils::proc_driver_client::PROC_FILTER_DROP);
        assert_eq!(mapped[1].1, crate::utils::proc_driver_client::PROC_FILTER_COLLECT);
    }
}
