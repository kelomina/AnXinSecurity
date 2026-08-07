// ETW 风险分析服务 — 对 ETW 规则匹配事件进行风险评分和二次研判
// ETW risk analysis service — performs risk scoring and secondary assessment on ETW rule-matched events
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use crate::services::behavior_service::BehaviorService;
use crate::services::interception_service::{InterceptionEntry, InterceptionService};
use crate::services::process_control_service::is_windows_control_chain_process;
use crate::services::service_context::AppContext;
use crate::services::trust_service::TrustService;

/// 风险事件 / Risk event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEvent {
    /// 进程 PID / Process PID
    pub pid: u32,
    /// 进程名称 / Process name
    #[serde(rename = "processName")]
    pub process_name: String,
    /// 事件关联文件路径 / Event-related file path
    #[serde(rename = "filePath", skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    /// 进程可执行文件路径 / Process executable path
    #[serde(
        rename = "processPath",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub process_path: Option<String>,
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
    /// 规则建议动作：`block` 才允许自动挂起，其余（`alert` / `monitor`）只告警。
    /// 缺省视为不阻断——旧事件与无法判定的来源一律走告警路径。
    /// Rule-recommended action: only `block` permits an automatic suspend; anything else
    /// (`alert` / `monitor`) alerts only. Absent means "do not block".
    #[serde(
        rename = "recommendAction",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub recommend_action: Option<String>,
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
    /// 参数 ctx: 应用上下文，兼容 Tauri 运行时与 ServiceContext / App context for both Tauri runtime and ServiceContext
    /// 副作用：写入行为数据库，高风险事件推入拦截队列并向前端 emit
    /// Side effects: writes to behavior DB, pushes high-risk events to interception queue, emits to frontend
    /// 中文关键词：风险分析，事件研判，威胁评估，安全评分，进程拦截
    /// English keywords: risk analysis, event assessment, threat evaluation, security scoring, process interception
    pub async fn analyze_event<C: AppContext>(
        &self,
        event: RiskEvent,
        trust: Option<&TrustService>,
        behavior: Option<&BehaviorService>,
        ctx: &C,
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
        let should_intercept =
            should_auto_intercept_event(
                adjusted_level.as_str(),
                &event.rule_id,
                &event.threat_type,
                &event.process_name,
                event.process_path.as_deref(),
                event.recommend_action.as_deref(),
            ) && !is_auto_intercept_exempt(&event.rule_id, event.process_path.as_deref(), trust);

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
        if should_intercept && !ctx.is_exiting() {
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
                if !ctx.is_exiting() {
                    let _ = ctx.emit_event("etw-risk-event", assessment.clone());
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
                interception.try_show_next(ctx);
            }
        }

        // 步骤7: 向前端发送风险事件 / Step 7: emit risk event to frontend
        if !ctx.is_exiting() {
            let _ = ctx.emit_event("etw-risk-event", assessment.clone());
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

/// 判断自动挂起是否被豁免（发起进程可信 / 在用户排除目录内）。
///  Decides whether the automatic suspend is exempted (trusted or user-excluded originator).
///
/// 判定对象是**发起操作的进程映像**，不是事件目标路径——事件目标往往是刚被写出的
/// 临时文件，对它验签毫无意义。
///  Judged against the **originating process image**, not the event target path: the target
/// is usually a temp file that was just written, so verifying it proves nothing.
///
/// 边界取舍：
///  Boundary decisions:
/// - `process_path` 为 None → **不豁免**。无法识别来源就不能成为绕过通道，
///   否则攻击者只需让路径查询失败即可免疫拦截。
///   Unknown originator is NOT exempt, otherwise failing the path lookup becomes a bypass.
/// - 验签报错 → **不豁免**。验证失败不等于可信。
///   A verification error is NOT trust.
///
/// 中文关键词：拦截豁免，签名白名单，排除目录，发起进程
/// English keywords: interception exemption, signature allowlist, exclusions, originating process
/// 签名豁免对哪些规则**不适用**。
///  Rules for which the signature exemption does NOT apply.
///
/// `trusted_process_unsigned_image_load` 的成立前提就是「宿主进程已签名可信、却加载了未签名模块」，
/// 用宿主签名去豁免它等于把规则本身注销掉。
///  `trusted_process_unsigned_image_load` exists precisely because a *signed, trusted* host
/// loaded an unsigned module; exempting it on host signature would cancel the rule itself.
fn signature_exemption_applies(rule_id: &str) -> bool {
    !matches!(rule_id, "trusted_process_unsigned_image_load")
}

fn is_auto_intercept_exempt(
    rule_id: &str,
    process_path: Option<&str>,
    trust: Option<&TrustService>,
) -> bool {
    let Some(path) = process_path.filter(|p| !p.trim().is_empty()) else {
        return false;
    };

    // 门控 A：用户配置的排除目录 / Gate A: user-configured exclusions
    match crate::services::path_policy_service::is_excluded_path(path) {
        Ok(true) => {
            eprintln!(
                "[RiskService] Auto-intercept exempt: {} is in user exclusions",
                path
            );
            return true;
        }
        Ok(false) => {}
        Err(err) => {
            // 读排除表失败不能变成绕过通道，按未排除处理
            //  A failed exclusion lookup must not become a bypass; treat as not excluded
            eprintln!(
                "[RiskService] Exclusion lookup failed for {}: {} (treated as not excluded)",
                path, err
            );
        }
    }

    // 门控 B：发起进程映像的数字签名 / Gate B: signature of the originating process image
    if !signature_exemption_applies(rule_id) {
        return false;
    }
    if let Some(trust_svc) = trust {
        match trust_svc.verify_file(path) {
            Ok(verdict) if verdict.trusted => {
                eprintln!(
                    "[RiskService] Auto-intercept exempt: {} is digitally signed and trusted",
                    path
                );
                return true;
            }
            Ok(_) => {}
            Err(err) => {
                eprintln!(
                    "[RiskService] Signature check failed for {}: {} (not treated as trusted)",
                    path, err
                );
            }
        }
    }

    false
}

fn should_auto_intercept_event(
    risk_level: &str,
    rule_id: &str,
    threat_type: &str,
    process_name: &str,
    process_path: Option<&str>,
    recommend_action: Option<&str>,
) -> bool {
    // 规则必须**显式**建议阻断才允许自动挂起。
    // 此前是否挂起完全由 severity 隐式决定，导致 recommendAction=alert 的规则
    // 也会冻结进程；现在该字段真正参与决策。
    //  A rule must explicitly recommend blocking before anything is suspended.
    //  Suspension used to be driven implicitly by severity alone, so even
    //  recommendAction=alert rules froze processes. The field now actually decides.
    if !matches!(recommend_action, Some("block")) {
        return false;
    }
    if risk_level != "high" {
        return false;
    }
    if is_observation_only_rule(rule_id) || is_observation_only_threat_type(threat_type) {
        return false;
    }
    if should_skip_auto_intercept_for_control_chain(
        rule_id,
        threat_type,
        process_name,
        process_path,
    ) {
        return false;
    }
    true
}

fn should_skip_auto_intercept_for_control_chain(
    rule_id: &str,
    threat_type: &str,
    process_name: &str,
    process_path: Option<&str>,
) -> bool {
    if rule_id != "trusted_process_unsigned_image_load"
        && threat_type != "trusted_process_unsigned_image_load"
    {
        return false;
    }
    let Some(process_path) = process_path.map(str::trim).filter(|path| !path.is_empty()) else {
        return false;
    };
    is_windows_control_chain_process(process_name, Some(process_path))
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
            process_path: None,
            recommend_action: None,
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
            process_path: None,
            // 规则显式建议阻断，因此本用例检验的是 severity 门控本身
            //  The rule explicitly recommends blocking, so this case exercises the severity gate
            recommend_action: Some("block".to_string()),
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
            "unsigned_process",
            "test.exe",
            Some(r"C:\Tools\test.exe"),
            Some("block")
        ));
        assert!(!should_auto_intercept_event(
            "high",
            "startup_unsigned_module",
            "unsigned_module",
            "test.exe",
            Some(r"C:\Tools\test.exe"),
            Some("block")
        ));
        assert!(!should_auto_intercept_event(
            "high",
            "API_HOOK_PROCESS_ACTIVITY",
            "api_hook_process_activity",
            "test.exe",
            Some(r"C:\Tools\test.exe"),
            Some("block")
        ));
        assert!(should_auto_intercept_event(
            "high",
            "trusted_process_unsigned_image_load",
            "trusted_process_unsigned_image_load",
            "notepad.exe",
            Some(r"C:\Windows\System32\notepad.exe"),
            Some("block")
        ));
    }

    /// recommendAction 不是 "block" 时，即使 severity 再高也不得自动挂起。
    /// 修复前是否挂起完全由 severity 隐式决定，导致 alert 规则也会冻结进程。
    /// A non-"block" recommendAction must never auto-suspend, no matter how high the severity.
    #[test]
    fn non_block_recommend_action_never_auto_intercepts() {
        for action in [None, Some("alert"), Some("monitor"), Some("BLOCK")] {
            assert!(
                !should_auto_intercept_event(
                    "high",
                    "trusted_process_unsigned_image_load",
                    "trusted_process_unsigned_image_load",
                    "notepad.exe",
                    Some(r"C:\Windows\System32\notepad.exe"),
                    action,
                ),
                "recommendAction={:?} 不应触发自动挂起",
                action
            );
        }
    }

    /// 高危事件走完整链路时，recommendAction=alert 只告警不入队。
    /// A high-severity event with recommendAction=alert alerts without enqueuing.
    #[test]
    fn alert_action_high_severity_does_not_enqueue() {
        let service = RiskService::new();
        let interception = Arc::new(InterceptionService::new_for_tests());
        service.set_interception_service(interception.clone());
        let event = RiskEvent {
            pid: 51004,
            process_name: "probe.exe".to_string(),
            file_path: Some(r"C:\Temp\probe.dll".to_string()),
            process_path: Some(r"C:\Tools\probe.exe".to_string()),
            recommend_action: Some("alert".to_string()),
            threat_type: "trusted_process_unsigned_image_load".to_string(),
            threat_name: None,
            severity: 90,
            rule_id: "trusted_process_unsigned_image_load".to_string(),
            description: "alert-only rule".to_string(),
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
                "recommendAction=alert 的规则只应告警，不得挂起进程"
            );
            assert!(interception.get_paused_pids().is_empty());
        });
    }

    /// 无法确定发起进程映像时不得豁免——否则让路径查询失败就成了绕过手段。
    /// An unknown originator must not be exempt, else failing the lookup becomes a bypass.
    #[test]
    fn unknown_originator_is_not_exempt_from_auto_intercept() {
        assert!(!is_auto_intercept_exempt("any_rule", None, None));
        assert!(!is_auto_intercept_exempt("any_rule", Some("   "), None));
    }

    /// 「可信宿主加载未签名模块」不得被签名白名单反噬。
    /// 该规则的前提就是宿主已签名可信，若用宿主签名豁免它，全链路唯一的强证据拦截会被注销。
    /// The trusted-host-loads-unsigned-module rule must not be cancelled by the signature
    /// allowlist: host trust is the rule's own premise, and it is the only strong-evidence
    /// interception in the pipeline.
    #[test]
    fn strong_evidence_rule_is_not_cancelled_by_signature_allowlist() {
        assert!(!signature_exemption_applies(
            "trusted_process_unsigned_image_load"
        ));
        assert!(signature_exemption_applies("temp_dropper_create"));

        // 该规则配 block 时必须能通过策略门控（豁免检查另行覆盖）
        //  With recommendAction=block the rule must pass the policy gate
        assert!(should_auto_intercept_event(
            "high",
            "trusted_process_unsigned_image_load",
            "trusted_process_unsigned_image_load",
            "notepad.exe",
            Some(r"C:\Windows\System32\notepad.exe"),
            Some("block"),
        ));
    }

    #[test]
    fn trusted_image_load_control_chain_is_not_auto_intercepted() {
        let service = RiskService::new();
        let interception = Arc::new(InterceptionService::new_for_tests());
        service.set_interception_service(interception.clone());
        let event = RiskEvent {
            pid: 51003,
            process_name: "powershell.exe".to_string(),
            file_path: Some(r"C:\Temp\unsigned-module.dll".to_string()),
            process_path: Some(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            ),
            // 规则建议阻断，因此本用例检验的是控制链进程豁免本身
            //  The rule recommends blocking, so this case exercises the control-chain exemption
            recommend_action: Some("block".to_string()),
            threat_type: "trusted_process_unsigned_image_load".to_string(),
            threat_name: None,
            severity: 90,
            rule_id: "trusted_process_unsigned_image_load".to_string(),
            description: "PowerShell Direct control process loaded unsigned image".to_string(),
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
            assert!(!result.should_intercept);
            assert!(interception.get_paused_pids().is_empty());
        });
    }

    #[test]
    fn trusted_image_load_masqueraded_control_name_still_auto_intercepts() {
        assert!(should_auto_intercept_event(
            "high",
            "trusted_process_unsigned_image_load",
            "trusted_process_unsigned_image_load",
            "powershell.exe",
            Some(r"C:\Temp\powershell.exe"),
            Some("block")
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
            process_path: Some(r"C:\Tools\normal-tool.exe".to_string()),
            // 规则建议阻断，因此本用例检验的是 severity 门控本身
            //  The rule recommends blocking, so this case exercises the severity gate
            recommend_action: Some("block".to_string()),
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
            process_path: Some(r"C:\Tools\strong-evidence.exe".to_string()),
            recommend_action: Some("block".to_string()),
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
            process_path: Some(r"C:\Windows\System32\cmd.exe".to_string()),
            threat_type: "可疑远程线程入口".to_string(),
            threat_name: None,
            severity: 75,
            // 规则建议阻断，因此本用例检验的是 observation-only 规则豁免本身
            //  The rule recommends blocking, so this case exercises the observation-only exemption
            recommend_action: Some("block".to_string()),
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
            process_path: None,
            recommend_action: None,
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
