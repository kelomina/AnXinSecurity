// ETW 风险分析服务 — 对 ETW 规则匹配事件进行风险评分和二次研判
// ETW risk analysis service — performs risk scoring and secondary assessment on ETW rule-matched events
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Runtime};

use crate::services::app_lifecycle_service::app_is_exiting;
use crate::services::behavior_service::BehaviorService;
use crate::services::interception_service::{InterceptionEntry, InterceptionService};
use crate::services::trust_service::TrustService;

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
    /// 参数 app_handle: Tauri 应用句柄，兼容真实运行时与测试运行时 / Tauri app handle for production and test runtimes
    /// 副作用：写入行为数据库，高风险事件推入拦截队列并向前端 emit
    /// Side effects: writes to behavior DB, pushes high-risk events to interception queue, emits to frontend
    /// 中文关键词：风险分析，事件研判，威胁评估，安全评分，进程拦截
    /// English keywords: risk analysis, event assessment, threat evaluation, security scoring, process interception
    pub async fn analyze_event<R: Runtime>(
        &self,
        event: RiskEvent,
        trust: Option<&TrustService>,
        behavior: Option<&BehaviorService>,
        app_handle: &AppHandle<R>,
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

        // 步骤3: 判断是否需要自动拦截 / Step 3: determine if automatic interception is needed.
        //
        // 自动挂起是安全产品的“急刹车”，只能用于强证据。普通未签名、单个
        // APIHook 观察事件或孤立远程线程入口都只适合记录、告警和补证；否则会把
        // WebView、Node、浏览器扩展宿主等正常进程一起暂停，造成主页卡死。
        let should_intercept = should_auto_intercept_event(
            adjusted_level.as_str(),
            &event.rule_id,
            &event.threat_type,
        );

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

        // 步骤6: 强证据事件推入拦截队列 / Step 6: push strong-evidence events to interception queue
        if should_intercept && !app_is_exiting(app_handle) {
            // 对同一 PID 去重：同一天内不重复拦截 / Deduplicate same PID: don't re-intercept same day
            let should_enqueue = {
                let mut analyzed = self.analyzed_pids.lock().unwrap_or_else(|e| e.into_inner());
                if analyzed.contains(&event.pid) {
                    eprintln!(
                        "[RiskService] PID {} already analyzed, skipping interception",
                        event.pid
                    );
                    false
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
                    true
                }
            };
            if !should_enqueue {
                if !app_is_exiting(app_handle) {
                    let _ = app_handle.emit("etw-risk-event", &assessment);
                }
                let mut counter = self.event_counter.lock().unwrap_or_else(|e| e.into_inner());
                *counter += 1;
                return Ok(assessment);
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
        if !app_is_exiting(app_handle) {
            let _ = app_handle.emit("etw-risk-event", &assessment);
        }

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

fn is_observation_only_rule(rule_id: &str) -> bool {
    matches!(rule_id, "remote_thread_start_outside_image")
}

fn should_auto_intercept_event(risk_level: &str, rule_id: &str, threat_type: &str) -> bool {
    if risk_level != "high" {
        return false;
    }
    if is_observation_only_rule(rule_id) || is_observation_only_threat_type(threat_type) {
        return false;
    }
    true
}

fn is_observation_only_threat_type(threat_type: &str) -> bool {
    matches!(
        threat_type,
        "unsigned_process" | "unsigned_module" | "api_hook_process_activity"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::interception_service::InterceptionDecision;
    use std::sync::Arc;

    #[test]
    fn new_service_initializes_with_empty_state() {
        let service = RiskService::new();
        assert_eq!(service.get_event_count(), 0);
    }

    #[test]
    fn severity_maps_to_correct_risk_level() {
        let event_low = RiskEvent {
            pid: 123,
            process_name: "test.exe".to_string(),
            file_path: None,
            threat_type: "low_risk".to_string(),
            threat_name: None,
            severity: 20,
            rule_id: "RULE_001".to_string(),
            description: "Low severity event".to_string(),
            timestamp: 1234567890,
        };

        let event_medium = RiskEvent {
            severity: 50,
            ..event_low.clone()
        };

        let event_high = RiskEvent {
            severity: 80,
            ..event_low.clone()
        };

        let service = RiskService::new();
        let dummy_app = tauri::test::mock_app();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let result_low = service
                .analyze_event(event_low, None, None, &dummy_app.handle())
                .await
                .unwrap();
            assert_eq!(result_low.risk_level, "low");

            let result_medium = service
                .analyze_event(event_medium, None, None, &dummy_app.handle())
                .await
                .unwrap();
            assert_eq!(result_medium.risk_level, "medium");

            let result_high = service
                .analyze_event(event_high, None, None, &dummy_app.handle())
                .await
                .unwrap();
            assert_eq!(result_high.risk_level, "high");
        });
    }

    #[test]
    fn should_intercept_only_for_high_strong_evidence() {
        let event_low = RiskEvent {
            pid: 123,
            process_name: "test.exe".to_string(),
            file_path: None,
            threat_type: "low_risk".to_string(),
            threat_name: None,
            severity: 20,
            rule_id: "RULE_001".to_string(),
            description: "Low severity event".to_string(),
            timestamp: 1234567890,
        };

        let event_medium = RiskEvent {
            severity: 50,
            ..event_low.clone()
        };

        let event_high = RiskEvent {
            severity: 80,
            ..event_low.clone()
        };

        let service = RiskService::new();
        let dummy_app = tauri::test::mock_app();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let result_low = service
                .analyze_event(event_low, None, None, &dummy_app.handle())
                .await
                .unwrap();
            assert!(!result_low.should_intercept);

            let result_medium = service
                .analyze_event(event_medium, None, None, &dummy_app.handle())
                .await
                .unwrap();
            assert_eq!(result_medium.risk_level, "medium");
            assert!(
                !result_medium.should_intercept,
                "medium-risk events should alert and be recorded, not automatically suspend processes"
            );

            let result_high = service
                .analyze_event(event_high, None, None, &dummy_app.handle())
                .await
                .unwrap();
            assert!(result_high.should_intercept);
        });
    }

    #[test]
    fn unsigned_and_single_hook_activity_are_observation_only() {
        assert!(!should_auto_intercept_event(
            "high",
            "startup_unsigned_process",
            "unsigned_process"
        ));
        assert!(!should_auto_intercept_event(
            "high",
            "startup_unsigned_module",
            "unsigned_module"
        ));
        assert!(!should_auto_intercept_event(
            "high",
            "API_HOOK_PROCESS_ACTIVITY",
            "api_hook_process_activity"
        ));
        assert!(should_auto_intercept_event(
            "high",
            "trusted_process_unsigned_image_load",
            "trusted_process_unsigned_image_load"
        ));
    }

    #[test]
    fn medium_risk_event_does_not_enqueue_interception() {
        let service = RiskService::new();
        let interception = Arc::new(InterceptionService::new_for_tests());
        service.set_interception_service(interception.clone());
        let event = RiskEvent {
            pid: 51001,
            process_name: "normal-tool.exe".to_string(),
            file_path: Some(r"C:\Tools\normal-tool.exe".to_string()),
            threat_type: "unsigned_process".to_string(),
            threat_name: None,
            severity: 50,
            rule_id: "startup_unsigned_process".to_string(),
            description: "unsigned but not malicious".to_string(),
            timestamp: 1234567890,
        };

        let dummy_app = tauri::test::mock_app();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let result = service
                .analyze_event(event, None, None, &dummy_app.handle())
                .await
                .unwrap();
            assert_eq!(result.risk_level, "medium");
            assert!(!result.should_intercept);
            assert!(interception.get_paused_pids().is_empty());
        });
    }

    #[test]
    fn high_risk_duplicate_pid_is_not_requeued_after_decision() {
        let service = RiskService::new();
        let interception = Arc::new(InterceptionService::new_for_tests());
        service.set_interception_service(interception.clone());
        let event = RiskEvent {
            pid: 51002,
            process_name: "strong-evidence.exe".to_string(),
            file_path: Some(r"C:\Tools\strong-evidence.exe".to_string()),
            threat_type: "trusted_process_unsigned_image_load".to_string(),
            threat_name: None,
            severity: 90,
            rule_id: "trusted_process_unsigned_image_load".to_string(),
            description: "strong evidence".to_string(),
            timestamp: 1234567890,
        };

        let dummy_app = tauri::test::mock_app();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let first = service
                .analyze_event(event.clone(), None, None, &dummy_app.handle())
                .await
                .unwrap();
            assert!(first.should_intercept);
            assert_eq!(interception.get_paused_pids(), vec![51002]);

            interception.mark_decision(51002, InterceptionDecision::Block);
            assert!(interception.get_paused_pids().is_empty());

            let second = service
                .analyze_event(event, None, None, &dummy_app.handle())
                .await
                .unwrap();
            assert!(second.should_intercept);
            assert!(
                interception.get_paused_pids().is_empty(),
                "deduplicated PID should not be requeued after the first risk-service interception"
            );
        });
    }

    #[test]
    fn remote_thread_start_rule_is_observation_only_not_auto_intercept() {
        let service = RiskService::new();
        let event = RiskEvent {
            pid: 43210,
            process_name: "cmd.exe".to_string(),
            file_path: Some(r"C:\Windows\System32\cmd.exe".to_string()),
            threat_type: "可疑远程线程入口".to_string(),
            threat_name: None,
            severity: 75,
            rule_id: "remote_thread_start_outside_image".to_string(),
            description: "thread start outside image".to_string(),
            timestamp: 1234567890,
        };

        let dummy_app = tauri::test::mock_app();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let result = service
                .analyze_event(event, None, None, &dummy_app.handle())
                .await
                .unwrap();

            assert_eq!(result.risk_level, "high");
            assert!(
                !result.should_intercept,
                "isolated remote-thread entry evidence should alert and trigger follow-up scanning, not auto-suspend"
            );
        });
    }

    #[test]
    fn analyze_event_increments_counter() {
        let service = RiskService::new();
        let event = RiskEvent {
            pid: 123,
            process_name: "test.exe".to_string(),
            file_path: None,
            threat_type: "test".to_string(),
            threat_name: None,
            severity: 50,
            rule_id: "RULE_001".to_string(),
            description: "Test event".to_string(),
            timestamp: 1234567890,
        };

        let dummy_app = tauri::test::mock_app();
        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async {
            assert_eq!(service.get_event_count(), 0);
            let _ = service
                .analyze_event(event.clone(), None, None, &dummy_app.handle())
                .await;
            assert_eq!(service.get_event_count(), 1);
            let _ = service
                .analyze_event(event, None, None, &dummy_app.handle())
                .await;
            assert_eq!(service.get_event_count(), 2);
        });
    }

    #[test]
    fn set_interception_service_sets_correctly() {
        let service = RiskService::new();
        let interception = Arc::new(InterceptionService::new_for_tests());
        service.set_interception_service(interception.clone());
    }
}
