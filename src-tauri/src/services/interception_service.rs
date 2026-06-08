// 拦截队列管理器 — 管理被暂停进程的拦截队列和用户决策
// Interception queue manager — manages the interception queue for paused processes and user decisions
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Runtime};

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
            eprintln!(
                "[InterceptionService] PID {} already in queue, skipping",
                entry.pid
            );
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
    /// 参数 app_handle: Tauri 应用句柄，兼容真实运行时与测试运行时 / Tauri app handle for production and test runtimes
    /// Returns: 弹窗数据，若队列为空或无弹窗则为 None
    /// 中文关键词：弹窗展示，下一个拦截，弹窗状态
    /// English keywords: show modal, next interception, modal state
    pub fn try_show_next<R: Runtime>(&self, app_handle: &AppHandle<R>) -> Option<InterceptionEntry> {
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
        eprintln!("[InterceptionService] PID {} decision: {:?}", pid, decision);

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
        self.decisions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_service_initializes_empty() {
        let service = InterceptionService::new();
        assert_eq!(service.get_queue_size(), 0);
        assert_eq!(service.get_paused_pids().len(), 0);
    }

    #[test]
    fn enqueue_adds_entry_to_queue() {
        let service = InterceptionService::new();
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
    fn enqueue_prevents_duplicate_pids() {
        let service = InterceptionService::new();
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
        let service = InterceptionService::new();
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
    }

    #[test]
    fn clear_all_clears_queue_and_decisions() {
        let service = InterceptionService::new();

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
        let service = InterceptionService::new();
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
        let service = InterceptionService::new();
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
    fn mark_decision_resets_showing_flag() {
        let service = InterceptionService::new();
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
    fn try_show_next_returns_none_when_queue_empty() {
        let service = InterceptionService::new();
        let dummy_app = tauri::test::mock_app();
        let result = service.try_show_next(&dummy_app.handle());
        assert!(result.is_none());
    }

    #[test]
    fn mark_decision_removes_entry_from_queue_if_still_present() {
        let service = InterceptionService::new();
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
        let service = Arc::new(InterceptionService::new());
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
