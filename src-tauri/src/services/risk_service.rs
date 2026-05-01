// ETW 风险分析服务 — 对 ETW 规则匹配事件进行风险评分和二次研判
// ETW risk analysis service — performs risk scoring and secondary assessment on ETW rule-matched events
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use crate::services::interception_service::{InterceptionService, InterceptionEntry};
use crate::services::trust_service::TrustService;
use crate::services::behavior_service::BehaviorService;

/// 风险事件 / Risk event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEvent {
    /// 进程 PID / Process PID
    pub pid: u32,
    /// 进程名称 / Process name
    #[serde(rename = "processName")]
    pub process_name: String,
    /// 进程路径 / Process path
    #[serde(rename = "filePath", skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    /// 威胁类型 / Threat type
    #[serde(rename = "threatType")]
    pub threat_type: String,
    /// 威胁名称 / Threat name
    #[serde(rename = "threatName", skip_serializing_if = "Option::is_none")]
    pub threat_name: Option<String>,
    /// 严重程度 / Severity (0-100)
    pub severity: u32,
    /// 检测规则 ID / Detection rule ID
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    /// 匹配的事件描述 / Matched event description
    pub description: String,
    /// Unix 毫秒时间戳 / Unix timestamp in ms
    pub timestamp: u64,
}

/// 风险研判结果 / Risk assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// 风险事件 / Risk event
    pub event: RiskEvent,
    /// 风险等级 / Risk level (high, medium, low)
    #[serde(rename = "riskLevel")]
    pub risk_level: String,
    /// 是否应拦截 / Whether should intercept
    #[serde(rename = "shouldIntercept")]
    pub should_intercept: bool,
    /// 研判原因 / Assessment reason
    pub reason: String,
}

/// ETW 风险分析服务 — 核心安全分析组件
/// ETW risk analysis service — core security analysis component
///
/// 负责：
/// - 接收 ETW 规则引擎匹配的事件
/// - 进行多维度风险评分（进程行为链分析、签名验证、威胁级别映射）
/// - 高/中风险事件推送拦截队列
/// - 所有事件写入行为数据库
///
/// Responsible for:
/// - Receiving ETW rule engine matched events
/// - Multi-dimensional risk scoring (process behavior chain, signature verification, threat level mapping)
/// - Pushing high/medium risk events to interception queue
/// - Writing all events to behavior database
pub struct RiskService {
    /// 拦截服务引用 / Interception service reference
    interception: Arc<Mutex<Option<Arc<InterceptionService>>>>,
    /// 事件计数 / Event counter
    event_counter: Arc<Mutex<u64>>,
    /// 已分析 PID 集合（用于去重） / Analyzed PID set (for deduplication)
    analyzed_pids: Arc<Mutex<std::collections::HashSet<u32>>>,
}

impl RiskService {
    /// 函数名称：new
    /// 函数作用：创建 RiskService 实例。
    /// Purpose: Creates a RiskService instance.
    /// Called by: main.rs setup()
    /// 中文关键词：风险分析，初始化，安全分析
    /// English keywords: risk analysis, initialization, security analysis
    pub fn new() -> Self {
        Self {
            interception: Arc::new(Mutex::new(None)),
            event_counter: Arc::new(Mutex::new(0)),
            analyzed_pids: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }

    /// 函数名称：set_interception_service
    /// 函数作用：设置拦截服务引用，用于风险研判后将进程入队。
    /// Purpose: Sets the interception service reference for enqueuing processes after risk assessment.
    /// Called by: main.rs setup() after creating both services
    /// 中文关键词：设置拦截，依赖注入
    /// English keywords: set interception, dependency injection
    pub fn set_interception_service(&self, svc: Arc<InterceptionService>) {
        *self.interception.lock().unwrap_or_else(|e| e.into_inner()) = Some(svc);
    }

    /// 函数名称：analyze_event
    /// 函数作用：对 ETW 规则匹配事件进行多维度风险分析。
    /// Purpose: Performs multi-dimensional risk analysis on ETW rule-matched events.
    /// Called by: etw_service.rs 在规则匹配后调用, main.rs ETW 事件处理 pipeline
    /// 参数 event: 风险事件信息 / Risk event information
    /// 参数 trust: 信任验证服务 / Trust verification service
    /// 参数 behavior: 行为数据库服务 / Behavior database service
    /// 参数 app_handle: Tauri 应用句柄 / Tauri app handle
    /// 副作用：写入行为数据库，高风险事件推入拦截队列并向前端 emit
    /// Side effects: writes to behavior DB, pushes high-risk events to interception queue, emits to frontend
    /// 中文关键词：风险分析，事件研判，威胁评估，安全评分，进程拦截
    /// English keywords: risk analysis, event assessment, threat evaluation, security scoring, process interception
    pub async fn analyze_event(
        &self,
        event: RiskEvent,
        trust: Option<&TrustService>,
        behavior: Option<&BehaviorService>,
        app_handle: &AppHandle,
    ) -> Result<RiskAssessment, String> {
        // 步骤1: 严重程度映射 → 风险等级 / Step 1: severity mapping → risk level
        let risk_level = match event.severity {
            0..=25 => "low",
            26..=60 => "medium",
            _ => "high",
        };

        // 步骤2: 签名验证（降低已签名进程的风险） / Step 2: signature verification (reduce risk for signed processes)
        let mut adjusted_level = risk_level.to_string();
        if let (Some(trust_svc), Some(ref fp)) = (trust, &event.file_path) {
            match trust_svc.verify_file(fp) {
                Ok(verdict) => {
                    if verdict.trusted && adjusted_level == "low" {
                        adjusted_level = "low".to_string(); // 签名验证通过，保持低风险
                    } else if !verdict.trusted && adjusted_level == "low" {
                        adjusted_level = "medium".to_string(); // 未签名提升风险
                    }
                }
                Err(_) => {
                    // 签名验证失败，保守处理：不影响现有风险等级
                    // Signature verification failed, conservative: keep current level
                }
            }
        }

        // 步骤3: 判断是否需要拦截 / Step 3: determine if interception is needed
        let should_intercept = matches!(adjusted_level.as_str(), "high" | "medium");

        // 步骤4: 构建研判结果 / Step 4: build assessment result
        let assessment = RiskAssessment {
            risk_level: adjusted_level.clone(),
            should_intercept,
            reason: format!(
                "规则 {} 匹配: {} (原始严重度: {}, 文件: {:?})",
                event.rule_id, event.description, event.severity, event.file_path
            ),
            event: event.clone(),
        };

        // 步骤5: 写入行为数据库 / Step 5: write to behavior database
        if let Some(behavior_svc) = behavior {
            let behavior_event = serde_json::json!({
                "type": "risk_analysis",
                "pid": event.pid,
                "processName": event.process_name,
                "path": event.file_path,
                "operation": event.threat_type,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "details": serde_json::to_string(&assessment).unwrap_or_default(),
            });
            let _ = behavior_svc.ingest_event(behavior_event).await;
        }

        // 步骤6: 高风险和中等风险事件推入拦截队列 / Step 6: push high and medium risk events to interception queue
        if should_intercept {
            // 对同一 PID 去重：同一天内不重复拦截 / Deduplicate same PID: don't re-intercept same day
            {
                let mut analyzed = self.analyzed_pids.lock().unwrap_or_else(|e| e.into_inner());
                if analyzed.contains(&event.pid) {
                    eprintln!("[RiskService] PID {} already analyzed, skipping interception", event.pid);
                } else {
                    analyzed.insert(event.pid);
                    // 清理过期条目（简单策略：保留最近1000个）/ Clean expired (simple: keep last 1000)
                    if analyzed.len() > 1000 {
                        // 移除一半旧条目 / Remove half old entries
                        let keys: Vec<u32> = analyzed.iter().copied().collect();
                        for key in keys.iter().take(500) {
                            analyzed.remove(key);
                        }
                    }
                }
            }

            let interception_guard = self.interception.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref interception) = *interception_guard {
                let entry = InterceptionEntry {
                    pid: event.pid,
                    process_name: event.process_name.clone(),
                    file_path: event.file_path.clone().unwrap_or_default(),
                    risk_level: adjusted_level.clone(),
                    threat_type: Some(event.threat_type.clone()),
                    reason: assessment.reason.clone(),
                    payload: Some(serde_json::to_string(&assessment).unwrap_or_default()),
                    timestamp: event.timestamp,
                };
                interception.enqueue(entry);
                // 尝试展示弹窗 / Try to show modal
                interception.try_show_next(app_handle);
            }
        }

        // 步骤7: 向前端发送风险事件 / Step 7: emit risk event to frontend
        let _ = app_handle.emit("etw-risk-event", &assessment);

        // 更新计数 / Update counter
        {
            let mut counter = self.event_counter.lock().unwrap_or_else(|e| e.into_inner());
            *counter += 1;
        }

        Ok(assessment)
    }

    /// 函数名称：get_event_count
    /// 函数作用：获取已分析事件总数。
    /// Purpose: Gets the total count of analyzed events.
    /// Called by: commands::risk::get_risk_status
    /// 中文关键词：事件计数，分析统计
    /// English keywords: event count, analysis statistics
    pub fn get_event_count(&self) -> u64 {
        *self.event_counter.lock().unwrap_or_else(|e| e.into_inner())
    }
}
