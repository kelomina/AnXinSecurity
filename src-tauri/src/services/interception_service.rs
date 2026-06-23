// 拦截队列管理器 — 管理被暂停进程的拦截队列和用户决策
// Interception queue manager — manages the interception queue for paused processes and user decisions
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Runtime};

use crate::services::app_lifecycle_service::app_is_exiting;
use crate::services::interception_diagnostics_service::append_interception_diagnostic;
use crate::services::interception_recovery_service::{
    clear_interception_suspensions, record_interception_suspension, remove_interception_suspension,
    retain_interception_suspensions,
};
use crate::services::interception_window_service::{
    hide_interception_window, show_interception_window,
};
use crate::services::process_control_service::query_process_identity;
use crate::services::process_control_service::{resume_process_by_pid, suspend_process_by_pid};

pub trait InterceptionProcessControl: Send + Sync {
    fn suspend_process(&self, pid: u32) -> Result<bool, String>;
    fn resume_process(&self, pid: u32) -> Result<bool, String>;
}

pub struct WindowsInterceptionProcessControl;

impl InterceptionProcessControl for WindowsInterceptionProcessControl {
    fn suspend_process(&self, pid: u32) -> Result<bool, String> {
        suspend_process_by_pid(pid)
    }

    fn resume_process(&self, pid: u32) -> Result<bool, String> {
        resume_process_by_pid(pid)
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub struct NoopInterceptionProcessControl;

impl InterceptionProcessControl for NoopInterceptionProcessControl {
    fn suspend_process(&self, _pid: u32) -> Result<bool, String> {
        Ok(true)
    }

    fn resume_process(&self, _pid: u32) -> Result<bool, String> {
        Ok(true)
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub struct FailingInterceptionProcessControl;

impl InterceptionProcessControl for FailingInterceptionProcessControl {
    fn suspend_process(&self, _pid: u32) -> Result<bool, String> {
        Err("test suspend failure".to_string())
    }

    fn resume_process(&self, _pid: u32) -> Result<bool, String> {
        Ok(true)
    }
}

/// 拦截队列中的条目 / Interception queue entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptionEntry {
    /// 进程 PID / Process PID
    pub pid: u32,
    /// 进程名称 / Process name
    #[serde(rename = "processName")]
    pub process_name: String,
    /// 进程路径 / Process path
    #[serde(rename = "filePath")]
    pub file_path: String,
    /// 风险等级 / Risk level
    #[serde(rename = "riskLevel")]
    pub risk_level: String,
    /// 威胁类型 / Threat type
    #[serde(rename = "threatType", skip_serializing_if = "Option::is_none")]
    pub threat_type: Option<String>,
    /// 检测原因 / Detection reason
    pub reason: String,
    /// 风险负载（JSON） / Risk payload (JSON)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// 入队时间戳（毫秒） / Enqueue timestamp (ms)
    pub timestamp: u64,
}

/// 拦截决策 / Interception decision
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterceptionDecision {
    /// 允许 / Allow
    #[serde(rename = "allow")]
    Allow,
    /// 阻止 / Block
    #[serde(rename = "block")]
    Block,
}

/// 拦截入队结果 / Interception enqueue result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptionEnqueueResult {
    /// 已成功进入队列 / Successfully queued
    Enqueued,
    /// 未入队，且没有执行回滚动作 / Rejected without rollback
    Rejected,
    /// 未入队，但已经恢复了本次挂起 / Rejected and rolled back this suspension
    RejectedAfterRollback,
}

impl InterceptionEnqueueResult {
    pub fn is_enqueued(self) -> bool {
        matches!(self, Self::Enqueued)
    }

    pub fn rollback_performed(self) -> bool {
        matches!(self, Self::RejectedAfterRollback)
    }
}

/// 拦截队列管理器 — 核心安全组件
/// Interception queue manager — core security component
///
/// 负责：
/// - 维护被暂停进程的拦截队列
/// - 状态机管理（等待中 → 已弹窗 → 已处理）
/// - 用户决策记录（放行/阻止）
/// - 向独立拦截窗口推送 process-intercepted 事件
///
/// Responsible for:
/// - Maintaining interception queue for paused processes
/// - State machine management (waiting → shown → handled)
/// - Recording user decisions (allow/block)
/// - Pushing process-intercepted events to the independent interception window
pub struct InterceptionService {
    /// 拦截队列 / Interception queue
    queue: Arc<Mutex<Vec<InterceptionEntry>>>,
    /// PID → 决策映射 / PID → decision mapping
    decisions: Arc<Mutex<HashMap<u32, InterceptionDecision>>>,
    /// 当前正在弹窗展示的 PID，防止展示期间同 PID 再次入队 / PID currently shown in modal, used for deduplication while shown.
    currently_showing_pid: Arc<Mutex<Option<u32>>>,
    /// 当前是否正在展示弹窗 / Whether currently showing a modal
    showing: Arc<Mutex<bool>>,
    /// 最近一次展示弹窗的条目（用于前端拉取） / Last shown entry for frontend pull
    last_shown_entry: Arc<Mutex<Option<InterceptionEntry>>>,
    /// 已被拦截服务挂起的 PID / PIDs suspended by the interception service
    suspended_pids: Arc<Mutex<Vec<u32>>>,
    /// 本次应用运行期间临时允许的目标路径 / Temporarily allowed target paths for this app session
    temporary_allowlist: Arc<Mutex<Vec<String>>>,
    /// PID → 当前展示或排队条目快照，供按钮命令恢复路径、临时允许和挂起状态。
    /// PID → entry snapshot for commands to recover target path, temporary allow and suspension state.
    active_entries: Arc<Mutex<HashMap<u32, InterceptionEntry>>>,
    /// 是否需要把挂起进程记录到恢复台账 / Whether to persist suspended processes for crash recovery
    persist_suspensions: bool,
    /// 进程控制适配器，生产环境调用 Windows API，测试环境可使用 no-op。
    /// Process-control adapter: Windows API in production, no-op in tests.
    process_control: Arc<dyn InterceptionProcessControl>,
}

impl InterceptionService {
    /// 函数名称：new
    /// 函数作用：创建 InterceptionService 实例。
    /// Purpose: Creates an InterceptionService instance.
    /// Called by: main.rs setup()
    /// 中文关键词：拦截管理器，初始化，拦截队列
    /// English keywords: interception manager, initialization, interception queue
    pub fn new() -> Self {
        Self::new_with_process_control_internal(Arc::new(WindowsInterceptionProcessControl), true)
    }

    #[allow(dead_code)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new_for_tests() -> Self {
        Self::new_with_process_control_internal(Arc::new(NoopInterceptionProcessControl), false)
    }

    #[allow(dead_code)]
    pub fn new_with_process_control(process_control: Arc<dyn InterceptionProcessControl>) -> Self {
        Self::new_with_process_control_internal(process_control, false)
    }

    fn new_with_process_control_internal(
        process_control: Arc<dyn InterceptionProcessControl>,
        persist_suspensions: bool,
    ) -> Self {
        Self {
            queue: Arc::new(Mutex::new(Vec::new())),
            decisions: Arc::new(Mutex::new(HashMap::new())),
            currently_showing_pid: Arc::new(Mutex::new(None)),
            showing: Arc::new(Mutex::new(false)),
            last_shown_entry: Arc::new(Mutex::new(None)),
            suspended_pids: Arc::new(Mutex::new(Vec::new())),
            temporary_allowlist: Arc::new(Mutex::new(Vec::new())),
            active_entries: Arc::new(Mutex::new(HashMap::new())),
            persist_suspensions,
            process_control,
        }
    }

    /// 函数名称：enqueue
    /// 函数作用：将可疑进程加入拦截队列；实时链路会先挂起目标，再补身份台账和前端弹窗。
    /// Purpose: Enqueues a suspicious process; realtime paths suspend first, then fill recovery ledger/UI.
    /// Called by: risk_service.rs on risk analysis, snapshot_service.rs on startup snapshot
    /// 副作用：通过 Tauri Events 向独立拦截窗口推送 process-intercepted
    /// 并发安全：使用 Mutex 保护队列
    /// 中文关键词：入队拦截，暂停进程，弹窗推送
    /// English keywords: enqueue interception, paused process, modal push
    pub fn enqueue(&self, entry: InterceptionEntry) -> InterceptionEnqueueResult {
        self.enqueue_internal(entry, true, "suspend-before-enqueue")
    }

    /// 函数名称：enqueue_pre_suspended
    /// 函数作用：将已经由前置防护链路挂起的进程加入拦截队列，不再重复调用 NtSuspendProcess。
    /// Function name: enqueue_pre_suspended
    /// Purpose: Enqueues a process that has already been suspended by an upstream protection hook.
    ///
    /// 典型调用方是 APIHook：它在 CreateRemoteThread 真正创建远程线程前先挂起目标进程，
    /// 然后把目标 PID 交给拦截窗口等待用户 Allow/Block。这里必须避免再次挂起，
    /// 否则用户点击“允许运行”只恢复一次，目标进程可能仍残留一层挂起计数。
    pub fn enqueue_pre_suspended(&self, entry: InterceptionEntry) -> InterceptionEnqueueResult {
        self.enqueue_internal(entry, false, "pre-suspended-by-upstream-hook")
    }

    fn enqueue_internal(
        &self,
        entry: InterceptionEntry,
        should_suspend: bool,
        enqueue_mode: &str,
    ) -> InterceptionEnqueueResult {
        if self.is_temporarily_allowed(&entry.file_path) {
            append_interception_diagnostic(
                "interception_queue_reject",
                serde_json::json!({
                    "reason": "temporary_allowlist",
                    "pid": entry.pid,
                    "processName": entry.process_name,
                    "mode": enqueue_mode,
                }),
            );
            eprintln!(
                "[InterceptionService] Skipping temporarily allowed path for PID {}: {}",
                entry.pid, entry.file_path
            );
            return InterceptionEnqueueResult::Rejected;
        }

        let currently_showing_pid = *self
            .currently_showing_pid
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        // 防止重复 / Prevent duplicates
        if queue.iter().any(|e| e.pid == entry.pid) || currently_showing_pid == Some(entry.pid) {
            append_interception_diagnostic(
                "interception_queue_reject",
                serde_json::json!({
                    "reason": "duplicate_or_currently_showing",
                    "pid": entry.pid,
                    "processName": entry.process_name,
                    "mode": enqueue_mode,
                    "queueLen": queue.len(),
                    "currentlyShowingPid": currently_showing_pid,
                }),
            );
            eprintln!(
                "[InterceptionService] PID {} already queued or showing, skipping",
                entry.pid
            );
            return InterceptionEnqueueResult::Rejected;
        }

        if should_suspend {
            // 实时 ETW/文件监控命中时，目标进程可能只留出很短的处置窗口。
            // 这里先执行最关键的 NtSuspendProcess，再补 PID 身份和恢复台账；
            // 如果后续台账写入失败，再恢复目标进程回滚，避免留下不可恢复的挂起状态。
            // Realtime ETW/file events can leave only a tiny response window.
            // Suspend first, then record identity/ledger; roll back on ledger failure.
            if let Err(err) = self.process_control.suspend_process(entry.pid) {
                append_interception_diagnostic(
                    "interception_suspend_failed",
                    serde_json::json!({
                        "pid": entry.pid,
                        "processName": entry.process_name,
                        "mode": enqueue_mode,
                        "error": err,
                    }),
                );
                eprintln!(
                    "[InterceptionService] Failed to suspend PID {} before enqueue: {}",
                    entry.pid, err
                );
                return InterceptionEnqueueResult::Rejected;
            }
        } else {
            append_interception_diagnostic(
                "interception_pre_suspended_entry",
                serde_json::json!({
                    "pid": entry.pid,
                    "processName": entry.process_name,
                    "mode": enqueue_mode,
                }),
            );
            eprintln!(
                "[InterceptionService] PID {} enters queue as pre-suspended ({})",
                entry.pid, enqueue_mode
            );
        }

        if self.persist_suspensions {
            match query_process_identity(entry.pid) {
                Ok(identity) => {
                    if let Err(err) = record_interception_suspension(&entry, &identity) {
                        append_interception_diagnostic(
                            "interception_ledger_failed",
                            serde_json::json!({
                                "pid": entry.pid,
                                "processName": entry.process_name,
                                "mode": enqueue_mode,
                                "error": err,
                            }),
                        );
                        eprintln!(
                            "[InterceptionService] Failed to persist PID {} suspension ledger: {}",
                            entry.pid, err
                        );
                        if let Err(resume_err) = self.process_control.resume_process(entry.pid) {
                            eprintln!(
                                "[InterceptionService] Failed to roll back PID {} after ledger write failure: {}",
                                entry.pid, resume_err
                            );
                        }
                        return InterceptionEnqueueResult::RejectedAfterRollback;
                    }
                }
                Err(err) => {
                    append_interception_diagnostic(
                        "interception_identity_failed",
                        serde_json::json!({
                            "pid": entry.pid,
                            "processName": entry.process_name,
                            "mode": enqueue_mode,
                            "error": err,
                        }),
                    );
                    eprintln!(
                        "[InterceptionService] Failed to capture PID {} identity after suspend: {}",
                        entry.pid, err
                    );
                    if let Err(resume_err) = self.process_control.resume_process(entry.pid) {
                        eprintln!(
                            "[InterceptionService] Failed to roll back PID {} after identity failure: {}",
                            entry.pid, resume_err
                        );
                    }
                    return InterceptionEnqueueResult::RejectedAfterRollback;
                }
            }
        }

        self.remember_suspended_pid(entry.pid);

        eprintln!(
            "[InterceptionService] Enqueuing PID {} ({}) - mode: {}, risk: {}, threat: {}, path: {}",
            entry.pid,
            entry.process_name,
            enqueue_mode,
            entry.risk_level,
            entry.threat_type.as_deref().unwrap_or("unknown"),
            entry.file_path
        );
        self.active_entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(entry.pid, entry.clone());
        let queue_len_before_push = queue.len();
        let priority = interception_entry_priority(&entry);
        let insert_front = should_insert_interception_at_front(&entry);
        append_interception_diagnostic(
            "interception_queue_push",
            serde_json::json!({
                "pid": entry.pid,
                "processName": entry.process_name,
                "riskLevel": entry.risk_level,
                "threatType": entry.threat_type,
                "mode": enqueue_mode,
                "queueLenBefore": queue_len_before_push,
                "queueLenAfter": queue_len_before_push + 1,
                "priority": priority,
                "insertFront": insert_front,
                "filePath": entry.file_path,
            }),
        );
        if insert_front {
            queue.insert(0, entry);
        } else {
            queue.push(entry);
        }
        InterceptionEnqueueResult::Enqueued
    }

    /// 函数名称：try_show_next
    /// 函数作用：尝试弹出下一个拦截弹窗（若当前无弹窗且队列非空）。
    /// Purpose: Tries to show the next interception modal (if no modal is showing and queue is not empty).
    /// Called by: enqueue() 后自动调用, 或前端处理完上一个弹窗后调用
    /// 参数 app_handle: Tauri 应用句柄，兼容真实运行时与测试运行时 / Tauri app handle for production and test runtimes
    /// Returns: 弹窗数据，若队列为空或无弹窗则为 None
    /// 中文关键词：弹窗展示，下一个拦截，弹窗状态
    /// English keywords: show modal, next interception, modal state
    pub fn try_show_next<R: Runtime>(
        &self,
        app_handle: &AppHandle<R>,
    ) -> Option<InterceptionEntry> {
        if app_is_exiting(app_handle) {
            append_interception_diagnostic(
                "try_show_next_skipped",
                serde_json::json!({
                    "reason": "app_exiting",
                }),
            );
            return None;
        }

        let mut showing = self.showing.lock().unwrap_or_else(|e| e.into_inner());
        if *showing {
            let current_entry = self
                .last_shown_entry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let preemptive_entry = {
                let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(current) = current_entry.as_ref() {
                    if let Some(position) = queue
                        .iter()
                        .position(|candidate| should_preempt_current_interception(current, candidate))
                    {
                        let candidate = queue.remove(position);
                        if !queue.iter().any(|entry| entry.pid == current.pid) {
                            queue.insert(0, current.clone());
                        }
                        append_interception_diagnostic(
                            "try_show_next_preempting",
                            serde_json::json!({
                                "currentPid": current.pid,
                                "currentProcessName": current.process_name,
                                "currentThreatType": current.threat_type,
                                "currentPriority": interception_entry_priority(current),
                                "nextPid": candidate.pid,
                                "nextProcessName": candidate.process_name,
                                "nextThreatType": candidate.threat_type,
                                "nextPriority": interception_entry_priority(&candidate),
                                "queueLenAfterRequeue": queue.len(),
                            }),
                        );
                        Some(candidate)
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some(entry) = preemptive_entry {
                *self
                    .currently_showing_pid
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(entry.pid);
                *self
                    .last_shown_entry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(entry.clone());
                self.active_entries
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(entry.pid, entry.clone());
                return self.show_entry(app_handle, entry);
            }

            append_interception_diagnostic(
                "try_show_next_skipped",
                serde_json::json!({
                    "reason": "already_showing",
                    "currentlyShowingPid": *self
                        .currently_showing_pid
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()),
                    "queueLen": self.queue.lock().unwrap_or_else(|e| e.into_inner()).len(),
                }),
            );
            return None;
        }

        let entry = {
            let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
            if queue.is_empty() {
                return None;
            }
            append_interception_diagnostic(
                "try_show_next_entry",
                serde_json::json!({
                    "queueLenBefore": queue.len(),
                    "nextPid": queue.first().map(|entry| entry.pid),
                    "nextProcessName": queue.first().map(|entry| entry.process_name.clone()),
                    "nextThreatType": queue.first().and_then(|entry| entry.threat_type.clone()),
                }),
            );
            queue.remove(0)
        };
        *showing = true;
        *self
            .currently_showing_pid
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(entry.pid);
        // 保存当前展示条目供前端拉取 / Save shown entry for frontend pull
        *self
            .last_shown_entry
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(entry.clone());
        self.active_entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(entry.pid, entry.clone());

        self.show_entry(app_handle, entry)
    }

    fn show_entry<R: Runtime>(
        &self,
        app_handle: &AppHandle<R>,
        entry: InterceptionEntry,
    ) -> Option<InterceptionEntry> {
        if let Err(err) = show_interception_window(app_handle) {
            append_interception_diagnostic(
                "show_interception_window_error_from_service",
                serde_json::json!({
                    "pid": entry.pid,
                    "processName": entry.process_name,
                    "error": err,
                }),
            );
            eprintln!(
                "[InterceptionService] Failed to show interception window: {}",
                err
            );
        } else {
            append_interception_diagnostic(
                "show_interception_window_ok_from_service",
                serde_json::json!({
                    "pid": entry.pid,
                    "processName": entry.process_name,
                }),
            );
        }

        // 向独立拦截窗口推送拦截事件 / Push interception event to the independent interception window
        let payload = serde_json::json!({
            "title": format!("进程行为拦截 - {}", entry.process_name),
            "message": format!(
                "检测到可疑行为：{}\n进程：{} (PID: {})\n风险等级：{}",
                entry.reason, entry.process_name, entry.pid, entry.risk_level
            ),
            "processName": entry.process_name,
            "pid": entry.pid,
            "riskLevel": entry.risk_level,
            "filePath": entry.file_path,
            "payload": entry.payload,
        });

        if let Err(err) = app_handle.emit_to("interception", "process-intercepted", payload) {
            append_interception_diagnostic(
                "emit_interception_event_error",
                serde_json::json!({
                    "pid": entry.pid,
                    "processName": entry.process_name,
                    "error": err.to_string(),
                }),
            );
            eprintln!(
                "[InterceptionService] Failed to emit interception event to independent window: {}",
                err
            );
        } else {
            append_interception_diagnostic(
                "emit_interception_event_ok",
                serde_json::json!({
                    "pid": entry.pid,
                    "processName": entry.process_name,
                }),
            );
        }

        Some(entry)
    }

    /// 函数名称：mark_decision
    /// 函数作用：记录用户对指定 PID 的拦截决策（放行或阻止）。
    /// Purpose: Records user's interception decision (allow or block) for the specified PID.
    /// Called by: commands::interception::handle_interception
    /// 副作用：向前端推送 process-interception-result 事件
    /// 并发安全：使用 Mutex 保护决策映射
    /// 中文关键词：拦截决策，放行，阻止，用户决策
    /// English keywords: interception decision, allow, block, user decision
    pub fn mark_decision(&self, pid: u32, decision: InterceptionDecision) {
        let mut decisions = self.decisions.lock().unwrap_or_else(|e| e.into_inner());
        decisions.insert(pid, decision);
        eprintln!("[InterceptionService] PID {} decision: {:?}", pid, decision);

        // 清除当前弹窗状态 / Clear current showing state
        let mut showing = self.showing.lock().unwrap_or_else(|e| e.into_inner());
        *showing = false;
        *self
            .currently_showing_pid
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .last_shown_entry
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;

        // 从队列中移除该 PID 的条目（如果还在队列中）/ Remove this PID's entry from queue (if still there)
        let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        queue.retain(|e| e.pid != pid);
        self.forget_suspended_pid(pid);
        self.active_entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&pid);
        if self.persist_suspensions {
            if let Err(err) = remove_interception_suspension(pid) {
                eprintln!(
                    "[InterceptionService] Failed to remove PID {} from suspension ledger: {}",
                    pid, err
                );
            }
        }
    }

    /// 函数名称：mark_decision_with_window
    /// 函数作用：记录用户决策，并隐藏独立拦截窗口。
    /// Purpose: Records the user's decision and hides the independent interception window.
    pub fn mark_decision_with_window<R: Runtime>(
        &self,
        pid: u32,
        decision: InterceptionDecision,
        app_handle: &AppHandle<R>,
    ) {
        self.mark_decision(pid, decision);
        hide_interception_window(app_handle);
    }

    /// 函数名称：get_paused_pids
    /// 函数作用：获取当前队列中所有暂停进程的 PID 列表。
    /// Purpose: Gets a list of all paused process PIDs currently in the queue.
    /// Called by: commands::interception::get_interception_queue
    /// 中文关键词：暂停进程列表，PID列表，拦截队列查询
    /// English keywords: paused process list, PID list, interception queue query
    pub fn get_paused_pids(&self) -> Vec<u32> {
        self.suspended_pids
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 函数名称：clear_all
    /// 函数作用：清空所有拦截队列和决策记录。
    /// Purpose: Clears all interception queues and decision records.
    /// Called by: commands::interception::clear_interception_queue
    /// 中文关键词：清空队列，重置拦截
    /// English keywords: clear queue, reset interception
    pub fn clear_all(&self) {
        let suspended_pids = self.get_paused_pids();
        let mut failed_resume_pids = Vec::new();
        for pid in suspended_pids {
            if let Err(err) = self.process_control.resume_process(pid) {
                eprintln!(
                    "[InterceptionService] Failed to resume PID {} during clear_all: {}",
                    pid, err
                );
                failed_resume_pids.push(pid);
            }
        }

        self.queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|entry| failed_resume_pids.contains(&entry.pid));
        self.decisions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|pid, _| failed_resume_pids.contains(pid));
        let mut active_entries = self
            .active_entries
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        active_entries.retain(|pid, _| failed_resume_pids.contains(pid));
        let retained_current_entry = failed_resume_pids
            .first()
            .and_then(|pid| active_entries.get(pid))
            .cloned();
        drop(active_entries);
        *self
            .currently_showing_pid
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = failed_resume_pids.first().copied();
        *self.showing.lock().unwrap_or_else(|e| e.into_inner()) = !failed_resume_pids.is_empty();
        *self
            .last_shown_entry
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = retained_current_entry;
        self.suspended_pids
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|pid| failed_resume_pids.contains(pid));
        self.temporary_allowlist
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();

        if self.persist_suspensions {
            let ledger_result = if failed_resume_pids.is_empty() {
                clear_interception_suspensions()
            } else {
                retain_interception_suspensions(&failed_resume_pids)
            };
            if let Err(err) = ledger_result {
                eprintln!(
                    "[InterceptionService] Failed to update suspension ledger during clear_all: {}",
                    err
                );
            }
        }
    }

    /// 函数名称：peek_current
    /// 函数作用：若当前正在展示弹窗（showing=true），返回该条目的克隆；否则返回 None。
    /// Purpose: Returns a clone of the currently shown entry if showing=true; otherwise None.
    /// Called by: commands::interception::peek_current_interception
    /// 中文关键词：当前拦截，弹窗条目，前端拉取
    /// English keywords: current interception, modal entry, frontend pull
    pub fn peek_current(&self) -> Option<InterceptionEntry> {
        let showing = self.showing.lock().unwrap_or_else(|e| e.into_inner());
        if !*showing {
            return None;
        }
        let showing_pid = self
            .currently_showing_pid
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let pid = (*showing_pid)?;
        // 当前展示的条目已从 queue 中移除，需从 last_shown 获取
        let last_shown = self
            .last_shown_entry
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        last_shown.as_ref().filter(|e| e.pid == pid).cloned()
    }

    /// 函数名称：get_queue_size
    /// 函数作用：获取当前拦截队列大小。
    /// Purpose: Gets the current interception queue size.
    /// Called by: commands::interception::get_interception_status
    /// 中文关键词：队列大小，队列状态
    /// English keywords: queue size, queue status
    pub fn get_queue_size(&self) -> usize {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// 函数名称：get_temporary_allowlist_size
    /// 函数作用：获取当前临时白名单数量。
    /// Function name: get_temporary_allowlist_size
    /// Purpose: Gets the current temporary allowlist size.
    pub fn get_temporary_allowlist_size(&self) -> usize {
        self.temporary_allowlist_len()
    }

    /// 函数名称：entry_for_pid
    /// 函数作用：返回指定 PID 当前拦截条目快照，供命令层执行允许/阻止时读取路径。
    /// Function name: entry_for_pid
    /// Purpose: Returns the current interception entry snapshot for command allow/block handling.
    pub fn entry_for_pid(&self, pid: u32) -> Option<InterceptionEntry> {
        self.active_entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&pid)
            .cloned()
    }

    /// 函数名称：mark_allowed_temporarily
    /// 函数作用：将当前拦截目标加入本次运行期间的内存临时白名单。
    /// Function name: mark_allowed_temporarily
    /// Purpose: Adds the current interception target to an in-memory temporary allowlist for this app session.
    pub fn mark_allowed_temporarily(&self, entry: &InterceptionEntry) {
        let normalized = normalize_temporary_allow_path(&entry.file_path);
        if normalized.is_empty() {
            return;
        }

        let mut temporary_allowlist = self
            .temporary_allowlist
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !temporary_allowlist.contains(&normalized) {
            temporary_allowlist.push(normalized);
        }
    }

    /// 函数名称：remove_temporary_allow
    /// 函数作用：允许恢复失败时回滚刚加入的临时白名单。
    /// Function name: remove_temporary_allow
    /// Purpose: Rolls back a temporary allow entry when process resume fails.
    pub fn remove_temporary_allow(&self, entry: &InterceptionEntry) {
        let normalized = normalize_temporary_allow_path(&entry.file_path);
        if normalized.is_empty() {
            return;
        }

        self.temporary_allowlist
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|allowed_path| allowed_path != &normalized);
    }

    /// 函数名称：complete_allow
    /// 函数作用：允许决策完成后清理挂起状态和当前条目快照。
    /// Function name: complete_allow
    /// Purpose: Clears suspension bookkeeping and active entry snapshot after Allow has resumed successfully.
    pub fn complete_allow(&self, pid: u32) {
        self.forget_suspended_pid(pid);
        self.active_entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&pid);
    }

    /// 函数名称：temporary_allowlist_len
    /// 函数作用：返回当前临时白名单条目数，供状态接口和测试观测。
    /// Function name: temporary_allowlist_len
    /// Purpose: Returns current temporary allowlist size for status reporting and tests.
    pub fn temporary_allowlist_len(&self) -> usize {
        self.temporary_allowlist
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    fn remember_suspended_pid(&self, pid: u32) {
        let mut suspended_pids = self
            .suspended_pids
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !suspended_pids.contains(&pid) {
            suspended_pids.push(pid);
        }
    }

    fn forget_suspended_pid(&self, pid: u32) {
        self.suspended_pids
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|paused_pid| *paused_pid != pid);
    }

    fn is_temporarily_allowed(&self, path: &str) -> bool {
        let normalized = normalize_temporary_allow_path(path);
        if normalized.is_empty() {
            return false;
        }

        self.temporary_allowlist
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&normalized)
    }
}

fn normalize_temporary_allow_path(path: &str) -> String {
    let mut normalized: String = path
        .trim()
        .chars()
        .map(|ch| {
            if ch == '/' {
                '\\'
            } else {
                ch.to_ascii_lowercase()
            }
        })
        .collect();
    if normalized.starts_with("\\\\?\\") {
        normalized = normalized[4..].to_string();
    }
    if normalized.starts_with("\\??\\") {
        normalized = normalized[4..].to_string();
    }
    while normalized.ends_with('\\') && normalized.len() > 3 {
        normalized.pop();
    }
    normalized
}

fn interception_entry_priority(entry: &InterceptionEntry) -> u8 {
    match entry.threat_type.as_deref() {
        Some("remote_thread_injection_target") => 100,
        Some("trusted_process_unsigned_image_load") => 80,
        Some("module_chain_unlinked_image") => 70,
        Some("malicious_file_event") => 65,
        Some("unsigned_process") => 20,
        _ => match entry.risk_level.to_ascii_lowercase().as_str() {
            "critical" => 60,
            "high" => 50,
            "medium" => 30,
            "low" => 10,
            _ => 0,
        },
    }
}

fn should_insert_interception_at_front(entry: &InterceptionEntry) -> bool {
    interception_entry_priority(entry) >= 70
}

fn should_preempt_current_interception(
    current: &InterceptionEntry,
    candidate: &InterceptionEntry,
) -> bool {
    let current_priority = interception_entry_priority(current);
    let candidate_priority = interception_entry_priority(candidate);
    candidate_priority >= 70 && candidate_priority > current_priority
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_service_initializes_empty() {
        let service = InterceptionService::new_for_tests();
        assert_eq!(service.get_queue_size(), 0);
        assert_eq!(service.get_paused_pids().len(), 0);
    }

    #[test]
    fn enqueue_adds_entry_to_queue() {
        let service = InterceptionService::new_for_tests();
        let entry = InterceptionEntry {
            pid: 123,
            process_name: "test.exe".to_string(),
            file_path: "C:\\test.exe".to_string(),
            risk_level: "high".to_string(),
            threat_type: Some("malware".to_string()),
            reason: "Test reason".to_string(),
            payload: None,
            timestamp: 1234567890,
        };

        service.enqueue(entry);
        assert_eq!(service.get_queue_size(), 1);
        assert!(service.get_paused_pids().contains(&123));
    }

    #[test]
    fn enqueue_pre_suspended_adds_entry_without_calling_suspend_again() {
        let service = InterceptionService::new_with_process_control(Arc::new(
            FailingInterceptionProcessControl,
        ));
        let entry = InterceptionEntry {
            pid: 321,
            process_name: "pre_suspended.exe".to_string(),
            file_path: "C:\\pre_suspended.exe".to_string(),
            risk_level: "high".to_string(),
            threat_type: Some("remote_thread_injection_target".to_string()),
            reason: "APIHook pre-suspended target".to_string(),
            payload: Some(r#"{"targetSuspendedByHook":true}"#.to_string()),
            timestamp: 1234567890,
        };

        let normal_result = service.enqueue(entry.clone());
        assert!(
            !normal_result.is_enqueued(),
            "normal enqueue must fail when the process-control layer cannot suspend"
        );
        assert_eq!(service.get_queue_size(), 0);

        let pre_suspended_result = service.enqueue_pre_suspended(entry);
        assert!(
            pre_suspended_result.is_enqueued(),
            "pre-suspended enqueue must not call NtSuspendProcess again"
        );
        assert_eq!(service.get_queue_size(), 1);
        assert_eq!(service.get_paused_pids(), vec![321]);
    }

    #[test]
    fn enqueue_prevents_duplicate_pids() {
        let service = InterceptionService::new_for_tests();
        let entry = InterceptionEntry {
            pid: 123,
            process_name: "test.exe".to_string(),
            file_path: "C:\\test.exe".to_string(),
            risk_level: "high".to_string(),
            threat_type: Some("malware".to_string()),
            reason: "Test reason".to_string(),
            payload: None,
            timestamp: 1234567890,
        };

        service.enqueue(entry.clone());
        service.enqueue(entry);

        assert_eq!(service.get_queue_size(), 1);
    }

    #[test]
    fn mark_decision_records_and_clears_entry() {
        let service = InterceptionService::new_for_tests();
        let entry = InterceptionEntry {
            pid: 123,
            process_name: "test.exe".to_string(),
            file_path: "C:\\test.exe".to_string(),
            risk_level: "high".to_string(),
            threat_type: Some("malware".to_string()),
            reason: "Test reason".to_string(),
            payload: None,
            timestamp: 1234567890,
        };

        service.enqueue(entry);
        service.mark_decision(123, InterceptionDecision::Allow);

        assert_eq!(service.get_queue_size(), 0);
        assert!(service.get_paused_pids().is_empty());
    }

    #[test]
    fn allow_decision_can_add_temporary_allow_and_skip_future_enqueue() {
        let service = InterceptionService::new_for_tests();
        let entry = InterceptionEntry {
            pid: 123,
            process_name: "allowed.exe".to_string(),
            file_path: "C:/Temp/Allowed.exe".to_string(),
            risk_level: "medium".to_string(),
            threat_type: Some("suspicious".to_string()),
            reason: "Test reason".to_string(),
            payload: None,
            timestamp: 1234567890,
        };

        service.enqueue(entry.clone());
        assert_eq!(service.get_queue_size(), 1);
        assert_eq!(service.get_paused_pids(), vec![123]);

        service.mark_allowed_temporarily(&entry);
        service.mark_decision(123, InterceptionDecision::Allow);
        assert_eq!(service.get_temporary_allowlist_size(), 1);
        assert!(service.get_paused_pids().is_empty());

        let mut next_entry = entry.clone();
        next_entry.pid = 456;
        next_entry.file_path = "c:\\temp\\allowed.exe\\".to_string();
        service.enqueue(next_entry);

        assert_eq!(
            service.get_queue_size(),
            0,
            "temporary allowlist should skip the same normalized path in this app session"
        );
    }

    #[test]
    fn clear_all_clears_queue_and_decisions() {
        let service = InterceptionService::new_for_tests();

        let entry1 = InterceptionEntry {
            pid: 123,
            process_name: "test1.exe".to_string(),
            file_path: "C:\\test1.exe".to_string(),
            risk_level: "high".to_string(),
            threat_type: Some("malware".to_string()),
            reason: "Test reason 1".to_string(),
            payload: None,
            timestamp: 1234567890,
        };
        let entry2 = InterceptionEntry {
            pid: 456,
            process_name: "test2.exe".to_string(),
            file_path: "C:\\test2.exe".to_string(),
            risk_level: "medium".to_string(),
            threat_type: Some("suspicious".to_string()),
            reason: "Test reason 2".to_string(),
            payload: None,
            timestamp: 1234567891,
        };

        service.enqueue(entry1);
        service.enqueue(entry2);
        service.clear_all();

        assert_eq!(service.get_queue_size(), 0);
        assert_eq!(service.get_paused_pids().len(), 0);
    }

    #[test]
    fn try_show_next_returns_entry_when_available() {
        let service = InterceptionService::new_for_tests();
        let entry = InterceptionEntry {
            pid: 123,
            process_name: "test.exe".to_string(),
            file_path: "C:\\test.exe".to_string(),
            risk_level: "high".to_string(),
            threat_type: Some("malware".to_string()),
            reason: "Test reason".to_string(),
            payload: None,
            timestamp: 1234567890,
        };

        service.enqueue(entry.clone());
        let dummy_app = tauri::test::mock_app();
        let shown = service.try_show_next(&dummy_app.handle());

        assert!(shown.is_some());
        assert_eq!(shown.unwrap().pid, 123);
    }

    #[test]
    fn try_show_next_blocks_when_showing_is_true() {
        let service = InterceptionService::new_for_tests();
        let entry1 = InterceptionEntry {
            pid: 100,
            process_name: "first.exe".to_string(),
            file_path: "C:\\first.exe".to_string(),
            risk_level: "high".to_string(),
            threat_type: Some("malware".to_string()),
            reason: "First threat".to_string(),
            payload: None,
            timestamp: 1000,
        };
        let entry2 = InterceptionEntry {
            pid: 200,
            process_name: "second.exe".to_string(),
            file_path: "C:\\second.exe".to_string(),
            risk_level: "medium".to_string(),
            threat_type: Some("suspicious".to_string()),
            reason: "Second threat".to_string(),
            payload: None,
            timestamp: 2000,
        };

        service.enqueue(entry1);
        service.enqueue(entry2);

        let dummy_app = tauri::test::mock_app();
        let first = service.try_show_next(&dummy_app.handle());
        assert!(first.is_some());
        assert_eq!(first.unwrap().pid, 100);

        let second = service.try_show_next(&dummy_app.handle());
        assert!(
            second.is_none(),
            "try_show_next should return None while showing is true"
        );
    }

    #[test]
    fn remote_thread_injection_preempts_lower_priority_modal() {
        let service = InterceptionService::new_for_tests();
        let unsigned_entry = InterceptionEntry {
            pid: 160452,
            process_name: "esbuild.exe".to_string(),
            file_path: "E:\\Project\\HTML\\AnXinSecurity\\node_modules\\@esbuild\\win32-x64\\esbuild.exe".to_string(),
            risk_level: "medium".to_string(),
            threat_type: Some("unsigned_process".to_string()),
            reason: "Unsigned process during startup snapshot".to_string(),
            payload: None,
            timestamp: 1000,
        };
        let injection_entry = InterceptionEntry {
            pid: 158968,
            process_name: "regedit.exe".to_string(),
            file_path: "C:\\Windows\\regedit.exe".to_string(),
            risk_level: "high".to_string(),
            threat_type: Some("remote_thread_injection_target".to_string()),
            reason: "APIHook blocked remote thread injection".to_string(),
            payload: Some(r#"{"source":"api_hook_process_injection_chain"}"#.to_string()),
            timestamp: 2000,
        };

        service.enqueue(unsigned_entry);
        let dummy_app = tauri::test::mock_app();
        let first = service.try_show_next(&dummy_app.handle());
        assert_eq!(first.as_ref().map(|entry| entry.pid), Some(160452));
        assert_eq!(service.peek_current().map(|entry| entry.pid), Some(160452));

        service.enqueue_pre_suspended(injection_entry);
        let preempted = service.try_show_next(&dummy_app.handle());

        assert_eq!(preempted.as_ref().map(|entry| entry.pid), Some(158968));
        assert_eq!(service.peek_current().map(|entry| entry.pid), Some(158968));
        assert_eq!(
            service.get_queue_size(),
            1,
            "lower-priority unsigned process should be returned to the queue"
        );
    }

    #[test]
    fn enqueue_prevents_duplicate_pid_while_modal_is_showing() {
        let service = InterceptionService::new_for_tests();
        let entry = InterceptionEntry {
            pid: 250,
            process_name: "shown.exe".to_string(),
            file_path: "C:\\shown.exe".to_string(),
            risk_level: "medium".to_string(),
            threat_type: Some("unsigned_module".to_string()),
            reason: "First shown threat".to_string(),
            payload: None,
            timestamp: 2500,
        };

        service.enqueue(entry.clone());
        let dummy_app = tauri::test::mock_app();
        let shown = service.try_show_next(&dummy_app.handle());
        assert!(shown.is_some());
        assert_eq!(service.get_queue_size(), 0);

        let mut duplicate = entry;
        duplicate.reason = "Second module from same process".to_string();
        service.enqueue(duplicate);

        assert_eq!(
            service.get_queue_size(),
            0,
            "same PID should not re-enter queue while its modal is already showing"
        );
    }

    #[test]
    fn mark_decision_resets_showing_flag() {
        let service = InterceptionService::new_for_tests();
        let entry = InterceptionEntry {
            pid: 300,
            process_name: "test.exe".to_string(),
            file_path: "C:\\test.exe".to_string(),
            risk_level: "high".to_string(),
            threat_type: Some("malware".to_string()),
            reason: "Test reason".to_string(),
            payload: None,
            timestamp: 3000,
        };

        service.enqueue(entry);
        let dummy_app = tauri::test::mock_app();
        let _ = service.try_show_next(&dummy_app.handle());

        service.mark_decision(300, InterceptionDecision::Allow);

        let next_entry = InterceptionEntry {
            pid: 400,
            process_name: "next.exe".to_string(),
            file_path: "C:\\next.exe".to_string(),
            risk_level: "medium".to_string(),
            threat_type: None,
            reason: "Next threat".to_string(),
            payload: None,
            timestamp: 4000,
        };
        service.enqueue(next_entry);

        let next = service.try_show_next(&dummy_app.handle());
        assert!(
            next.is_some(),
            "mark_decision should reset showing flag, allowing next modal"
        );
        assert_eq!(next.unwrap().pid, 400);
    }

    #[test]
    fn decisions_rotate_through_multiple_interceptions_in_fifo_order() {
        let service = InterceptionService::new_for_tests();
        for pid in [1000, 2000, 3000] {
            service.enqueue(InterceptionEntry {
                pid,
                process_name: format!("queued_{pid}.exe"),
                file_path: format!("C:\\queued_{pid}.exe"),
                risk_level: "high".to_string(),
                threat_type: Some("startup_snapshot".to_string()),
                reason: format!("Queued threat {pid}"),
                payload: None,
                timestamp: pid as u64,
            });
        }

        let dummy_app = tauri::test::mock_app();
        let first = service.try_show_next(&dummy_app.handle());
        assert_eq!(first.as_ref().map(|entry| entry.pid), Some(1000));
        assert_eq!(service.peek_current().map(|entry| entry.pid), Some(1000));
        assert_eq!(service.get_queue_size(), 2);

        service.mark_decision(1000, InterceptionDecision::Allow);
        let second = service.try_show_next(&dummy_app.handle());
        assert_eq!(second.as_ref().map(|entry| entry.pid), Some(2000));
        assert_eq!(service.peek_current().map(|entry| entry.pid), Some(2000));
        assert_eq!(service.get_queue_size(), 1);

        service.mark_decision(2000, InterceptionDecision::Block);
        let third = service.try_show_next(&dummy_app.handle());
        assert_eq!(third.as_ref().map(|entry| entry.pid), Some(3000));
        assert_eq!(service.peek_current().map(|entry| entry.pid), Some(3000));
        assert_eq!(service.get_queue_size(), 0);

        service.mark_decision(3000, InterceptionDecision::Allow);
        assert!(service.try_show_next(&dummy_app.handle()).is_none());
        assert!(service.peek_current().is_none());
    }

    #[test]
    fn try_show_next_returns_none_when_queue_empty() {
        let service = InterceptionService::new_for_tests();
        let dummy_app = tauri::test::mock_app();
        let result = service.try_show_next(&dummy_app.handle());
        assert!(result.is_none());
    }

    #[test]
    fn mark_decision_removes_entry_from_queue_if_still_present() {
        let service = InterceptionService::new_for_tests();
        let entry = InterceptionEntry {
            pid: 500,
            process_name: "queued.exe".to_string(),
            file_path: "C:\\queued.exe".to_string(),
            risk_level: "high".to_string(),
            threat_type: Some("trojan".to_string()),
            reason: "Queued threat".to_string(),
            payload: None,
            timestamp: 5000,
        };

        service.enqueue(entry);
        assert_eq!(service.get_queue_size(), 1);

        service.mark_decision(500, InterceptionDecision::Block);

        assert_eq!(service.get_queue_size(), 0);
        assert!(!service.get_paused_pids().contains(&500));
    }

    #[test]
    fn concurrent_enqueue_and_mark_decision_safe() {
        let service = Arc::new(InterceptionService::new_for_tests());
        let mut handles = vec![];

        for i in 0..10u32 {
            let svc = service.clone();
            let handle = std::thread::spawn(move || {
                let entry = InterceptionEntry {
                    pid: i,
                    process_name: format!("process_{}.exe", i),
                    file_path: format!("C:\\process_{}.exe", i),
                    risk_level: "medium".to_string(),
                    threat_type: None,
                    reason: format!("Thread {}", i),
                    payload: None,
                    timestamp: i as u64 * 1000,
                };
                svc.enqueue(entry);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("thread should complete");
        }

        assert_eq!(service.get_queue_size(), 10);
    }

    #[test]
    fn interception_entry_serialization_round_trip() {
        let entry = InterceptionEntry {
            pid: 9999,
            process_name: "malware.exe".to_string(),
            file_path: r"C:\Malware\malware.exe".to_string(),
            risk_level: "high".to_string(),
            threat_type: Some("ransomware".to_string()),
            reason: "Detected ransomware activity".to_string(),
            payload: Some(r#"{"rule":"RANSOMWARE_001"}"#.to_string()),
            timestamp: 1234567890123,
        };

        let json = serde_json::to_string(&entry).expect("serialization should succeed");
        let parsed: InterceptionEntry =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(parsed.pid, entry.pid);
        assert_eq!(parsed.process_name, entry.process_name);
        assert_eq!(parsed.file_path, entry.file_path);
        assert_eq!(parsed.risk_level, entry.risk_level);
        assert_eq!(parsed.threat_type, entry.threat_type);
        assert_eq!(parsed.reason, entry.reason);
        assert_eq!(parsed.payload, entry.payload);
        assert_eq!(parsed.timestamp, entry.timestamp);
    }

    #[test]
    fn interception_decision_serialization() {
        assert_eq!(
            serde_json::to_string(&InterceptionDecision::Allow).unwrap(),
            r#""allow""#
        );
        assert_eq!(
            serde_json::to_string(&InterceptionDecision::Block).unwrap(),
            r#""block""#
        );

        let allow: InterceptionDecision = serde_json::from_str(r#""allow""#).unwrap();
        assert_eq!(allow, InterceptionDecision::Allow);

        let block: InterceptionDecision = serde_json::from_str(r#""block""#).unwrap();
        assert_eq!(block, InterceptionDecision::Block);
    }
}
