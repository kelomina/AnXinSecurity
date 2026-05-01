/// ETW 监控服务 — 控制 ETW 会话生命周期，轮询事件并分发到行为数据库、风险分析和前端
/// ETW monitoring service — controls ETW session lifecycle, polls events and dispatches to behavior DB, risk analysis, and frontend
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tauri::{AppHandle, Emitter, Manager};

use super::etw::session::EtwSession;
use crate::commands::logs;

pub struct EtwService {
    session: Arc<Mutex<Option<EtwSession>>>,
    tx: broadcast::Sender<String>,
    running: Arc<std::sync::atomic::AtomicBool>,
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
        }))
    }

    /// 函数名称：start
    /// 函数作用：创建 ETW 会话、启用内核提供者、启动后台事件轮询和数据分发任务。
    /// Purpose: Creates ETW session, enables kernel providers, starts background event polling and data dispatch.
    /// 事件分发链路: ETW事件 → 日志缓冲区 + 行为数据库 + 风险分析 → 拦截队列 → 前端弹窗
    /// Event dispatch chain: ETW events → log buffer + behavior DB + risk analysis → interception queue → frontend modal
    /// Called by: main.rs start_etw_monitoring
    /// 中文关键词：启动ETW，事件监控，风险管线，拦截管线
    /// English keywords: start ETW, event monitoring, risk pipeline, interception pipeline
    pub fn start(&self, app_handle: AppHandle) -> Result<(), String> {
        // 创建 ETW Session（内部自动清理已存在的同名 Session）
        let mut session = EtwSession::new("AnXinETWSession")?;

        // 如果 session_handle 为 0（无管理员权限），跳过启用提供者和轮询
        // If session_handle is 0 (no admin), skip enabling providers and polling
        if session.session_handle != 0 {
            session.start(
                0x00000000, 0x00000001,
                0x00000000, 0x00000010,
                0x00000000, 0x00000100,
                0x00000000, 0x00001000,
                1, 0, 0, 65536,
            )?;
        } else {
            eprintln!("[EtwService] ETW skipped (no admin)");
        }

        let tx = self.tx.clone();
        let running = self.running.clone();
        let session_arc = self.session.clone();

        *self.session.lock().map_err(|e| e.to_string())? = Some(session);
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);

        let app_handle_clone = app_handle.clone();
        tokio::spawn(async move {
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                let events = {
                    let guard = session_arc.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(ref sess) = *guard {
                        sess.poll_events()
                    } else {
                        break;
                    }
                };

                for json_str in events {
                    let _ = tx.send(json_str.clone());

                    // 追加到日志缓冲区 / Append to log buffer
                    logs::append_log(json_str.clone());

                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        // 推送到前端 / Emit to frontend
                        let _ = app_handle_clone.emit("etw-event", val.clone());

                        // 风险分析 — 对匹配的威胁事件进行
                        // Risk analysis — for matched threat events
                        // 风险分析管线会自动写入行为数据库+推送拦截队列
                        // Risk analysis pipeline auto-writes behavior DB + pushes interception queue
                        if val.get("matched").and_then(|v| v.as_bool()).unwrap_or(false)
                            || val.get("threatType").is_some()
                        {
                            let val_risk = val.clone();
                            let app_handle_risk = app_handle_clone.clone();
                            tokio::spawn(async move {
                                if let (Some(risk_state), Some(trust_state)) = (
                                    app_handle_risk.try_state::<crate::services::risk_service::RiskService>(),
                                    app_handle_risk.try_state::<crate::services::trust_service::TrustService>(),
                                ) {
                                    let risk_event = crate::services::risk_service::RiskEvent {
                                        pid: val_risk.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                                        process_name: val_risk.get("processName").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
                                        file_path: val_risk.get("path").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        threat_type: val_risk.get("threatType").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                                        threat_name: val_risk.get("threatName").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        severity: val_risk.get("severity").and_then(|v| v.as_u64()).unwrap_or(30) as u32,
                                        rule_id: val_risk.get("ruleId").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                        description: val_risk.get("description").and_then(|v| v.as_str()).unwrap_or("ETW rule matched").to_string(),
                                        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
                                    };
                                    let _ = risk_state.analyze_event(risk_event, Some(&trust_state), None, &app_handle_risk).await;
                                }
                            });
                        }
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
        let mut guard = self.session.lock().map_err(|e| e.to_string())?;
        if let Some(ref mut session) = *guard {
            session.stop(2500)?;
        }
        *guard = None;
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// 函数名称：resume
    /// 函数作用：恢复 ETW 监控。
    /// Purpose: Resumes ETW monitoring.
    /// Called by: commands::behavior::resume_etw
    /// 中文关键词：恢复ETW，重启监控
    /// English keywords: resume ETW, restart monitoring
    pub fn resume(&self, app_handle: AppHandle) -> Result<(), String> {
        self.start(app_handle)
    }

}
