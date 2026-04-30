// 拦截队列管理器 — 管理被暂停进程的拦截队列和用户决策
// Interception queue manager — manages the interception queue for paused processes and user decisions
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

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

/// 拦截队列管理器 — 核心安全组件
/// Interception queue manager — core security component
///
/// 负责：
/// - 维护被暂停进程的拦截队列
/// - 状态机管理（等待中 → 已弹窗 → 已处理）
/// - 用户决策记录（放行/阻止）
/// - 向前端推送 process-intercepted 事件
///
/// Responsible for:
/// - Maintaining interception queue for paused processes
/// - State machine management (waiting → shown → handled)
/// - Recording user decisions (allow/block)
/// - Pushing process-intercepted events to frontend
pub struct InterceptionService {
    /// 拦截队列 / Interception queue
    queue: Arc<Mutex<Vec<InterceptionEntry>>>,
    /// PID → 决策映射 / PID → decision mapping
    decisions: Arc<Mutex<HashMap<u32, InterceptionDecision>>>,
    /// 当前是否正在展示弹窗 / Whether currently showing a modal
    showing: Arc<Mutex<bool>>,
}

impl InterceptionService {
    /// 函数名称：new
    /// 函数作用：创建 InterceptionService 实例。
    /// Purpose: Creates an InterceptionService instance.
    /// Called by: main.rs setup()
    /// 中文关键词：拦截管理器，初始化，拦截队列
    /// English keywords: interception manager, initialization, interception queue
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(Vec::new())),
            decisions: Arc::new(Mutex::new(HashMap::new())),
            showing: Arc::new(Mutex::new(false)),
        }
    }

    /// 函数名称：enqueue
    /// 函数作用：将暂停的进程加入拦截队列，若未在弹窗则自动推送前端。
    /// Purpose: Enqueues a paused process into the interception queue, auto-pushes to frontend if no modal is showing.
    /// Called by: risk_service.rs on risk analysis, snapshot_service.rs on startup snapshot
    /// 副作用：通过 Tauri Events 向 emit("process-intercepted") 推送前端弹窗
    /// 并发安全：使用 Mutex 保护队列
    /// 中文关键词：入队拦截，暂停进程，弹窗推送
    /// English keywords: enqueue interception, paused process, modal push
    pub fn enqueue(&self, entry: InterceptionEntry) {
        let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        // 防止重复 / Prevent duplicates
        if queue.iter().any(|e| e.pid == entry.pid) {
            eprintln!("[InterceptionService] PID {} already in queue, skipping", entry.pid);
            return;
        }
        eprintln!(
            "[InterceptionService] Enqueuing PID {} ({}) - risk: {}",
            entry.pid, entry.process_name, entry.risk_level
        );
        queue.push(entry);
    }

    /// 函数名称：try_show_next
    /// 函数作用：尝试弹出下一个拦截弹窗（若当前无弹窗且队列非空）。
    /// Purpose: Tries to show the next interception modal (if no modal is showing and queue is not empty).
    /// Called by: enqueue() 后自动调用, 或前端处理完上一个弹窗后调用
    /// Returns: 弹窗数据，若队列为空或无弹窗则为 None
    /// 中文关键词：弹窗展示，下一个拦截，弹窗状态
    /// English keywords: show modal, next interception, modal state
    pub fn try_show_next(&self, app_handle: &AppHandle) -> Option<InterceptionEntry> {
        let mut showing = self.showing.lock().unwrap_or_else(|e| e.into_inner());
        if *showing {
            return None;
        }

        let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        if queue.is_empty() {
            return None;
        }

        let entry = queue.remove(0);
        *showing = true;

        // 向前端推送拦截事件 / Push interception event to frontend
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

        let _ = app_handle.emit("process-intercepted", payload);

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
        eprintln!(
            "[InterceptionService] PID {} decision: {:?}",
            pid, decision
        );

        // 清除当前弹窗状态 / Clear current showing state
        let mut showing = self.showing.lock().unwrap_or_else(|e| e.into_inner());
        *showing = false;

        // 从队列中移除该 PID 的条目（如果还在队列中）/ Remove this PID's entry from queue (if still there)
        let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        queue.retain(|e| e.pid != pid);
    }

    /// 函数名称：get_paused_pids
    /// 函数作用：获取当前队列中所有暂停进程的 PID 列表。
    /// Purpose: Gets a list of all paused process PIDs currently in the queue.
    /// Called by: commands::interception::get_interception_queue
    /// 中文关键词：暂停进程列表，PID列表，拦截队列查询
    /// English keywords: paused process list, PID list, interception queue query
    pub fn get_paused_pids(&self) -> Vec<u32> {
        let queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        queue.iter().map(|e| e.pid).collect()
    }

    /// 函数名称：clear_all
    /// 函数作用：清空所有拦截队列和决策记录。
    /// Purpose: Clears all interception queues and decision records.
    /// Called by: commands::interception::clear_interception_queue
    /// 中文关键词：清空队列，重置拦截
    /// English keywords: clear queue, reset interception
    pub fn clear_all(&self) {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.decisions.lock().unwrap_or_else(|e| e.into_inner()).clear();
        *self.showing.lock().unwrap_or_else(|e| e.into_inner()) = false;
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

}
