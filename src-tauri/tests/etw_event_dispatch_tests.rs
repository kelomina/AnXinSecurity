// ETW 事件分发集成测试 — 验证威胁事件识别、分类和数据流
// ETW event dispatch integration tests — verify threat event identification, classification, and data flow
//
// 测试策略：验证威胁事件识别逻辑（matched / threatType 字段判断），
// 并使用 InterceptionService 验证事件→拦截队列的映射。
// 由于 AppHandle 类型约束，不在外部测试中调用 analyze_event()。
//
// 中文关键词：事件分发，威胁识别，ETW事件，matched字段，事件流向
// English keywords: event dispatch, threat identification, ETW event, matched field, event flow

use std::sync::Arc;
use serde_json::json;
use anxin_security::services::risk_service::RiskService;
use anxin_security::services::interception_service::{InterceptionService, InterceptionEntry};

mod common;

// ================================================================
// 威胁识别测试 / Threat identification tests
// ================================================================

#[test]
fn test_matched_true_event_identified_as_threat() {
    let event = common::make_threat_event(3001, "ransomware_x", 85, "ransomware");
    assert!(common::is_threat_event(&event));
}

#[test]
fn test_normal_process_event_not_identified_as_threat() {
    let event = common::make_normal_event(3002, "notepad", "Process", "Start");
    assert!(!common::is_threat_event(&event));
}

#[test]
fn test_threat_type_field_alone_triggers_identification() {
    let event = json!({
        "pid": 4001,
        "processName": "trojan.exe",
        "threatType": "trojan",
        "severity": 72,
        "matched": false,
    });
    assert!(common::is_threat_event(&event));
}

#[test]
fn test_matched_true_alone_triggers_identification() {
    let event = json!({
        "pid": 4002,
        "processName": "suspicious.exe",
        "matched": true,
        "severity": 55,
    });
    assert!(common::is_threat_event(&event));
}

#[test]
fn test_neither_matched_nor_threat_type_not_threat() {
    let event = json!({
        "pid": 4003,
        "processName": "clean.exe",
        "severity": 30,
    });
    assert!(!common::is_threat_event(&event));
}

#[test]
fn test_empty_json_not_threat() {
    assert!(!common::is_threat_event(&json!({})));
}

// ================================================================
// 事件→拦截队列 映射测试 / Event → Interception queue mapping
// ================================================================

#[test]
fn test_event_data_maps_to_interception_entry_correctly() {
    // 模拟 ETW 威胁事件 → InterceptionEntry 的数据转换
    // Simulate ETW threat event → InterceptionEntry data transformation
    let threat_json = common::make_threat_event(5001, "trojan_horse", 88, "trojan");

    let pid = threat_json["pid"].as_u64().unwrap() as u32;
    let process_name = threat_json["processName"].as_str().unwrap();
    let threat_type = threat_json["threatType"].as_str().unwrap();
    let severity = threat_json["severity"].as_u64().unwrap() as u32;

    let entry = InterceptionEntry {
        pid,
        process_name: process_name.to_string(),
        file_path: threat_json["path"].as_str().unwrap_or("").to_string(),
        risk_level: match severity { 0..=25 => "low", 26..=60 => "medium", _ => "high" }.to_string(),
        threat_type: Some(threat_type.to_string()),
        reason: format!("规则 RULE_{} 匹配: {}", threat_type, threat_json["description"].as_str().unwrap_or("")),
        payload: Some(threat_json.to_string()),
        timestamp: 1000000,
    };

    assert_eq!(entry.pid, 5001);
    assert_eq!(entry.process_name, "trojan_horse");
    assert_eq!(entry.risk_level, "high");
    assert_eq!(entry.threat_type.unwrap(), "trojan");
}

#[test]
fn test_many_threat_events_all_identified_correctly() {
    let threat_events = vec![
        common::make_threat_event(6001, "malware_a", 70, "malware"),
        common::make_threat_event(6002, "ransom_b", 45, "ransomware"),
        common::make_threat_event(6003, "spyware_c", 62, "spyware"),
    ];

    for event in &threat_events {
        assert!(common::is_threat_event(event), "威胁事件应被正确识别");
    }
}

#[test]
fn test_mixed_events_threats_separated_from_normals() {
    let threats: Vec<_> = (0..5).map(|i| common::make_threat_event(7000 + i, &format!("threat_{}", i), 50, "malware")).collect();
    let normals: Vec<_> = (0..3).map(|i| common::make_normal_event(8000 + i, &format!("normal_{}", i), "Process", "Start")).collect();

    let threat_count = threats.iter().filter(|e| common::is_threat_event(e)).count();
    let normal_count = normals.iter().filter(|e| !common::is_threat_event(e)).count();

    assert_eq!(threat_count, 5);
    assert_eq!(normal_count, 3);
}

// ================================================================
// 服务连线集成 / Service wiring integration
// ================================================================

#[test]
fn test_services_wired_enqueue_flow_works() {
    let risk = RiskService::new();
    let inter = Arc::new(InterceptionService::new());
    risk.set_interception_service(inter.clone());

    // 模拟 ETW 事件匹配后入队（这是 analyze_event 内部流程的简化版本）
    // Simulate post-ETW match enqueue (simplified version of analyze_event flow)
    let threat = common::make_threat_event(9001, "wired_malware", 78, "trojan");
    assert!(common::is_threat_event(&threat));

    // 在真实管线中，这部分由 RiskService::analyze_event 完成
    // In real pipeline, this is done by RiskService::analyze_event
    let entry = InterceptionEntry {
        pid: threat["pid"].as_u64().unwrap() as u32,
        process_name: threat["processName"].as_str().unwrap().to_string(),
        file_path: threat["path"].as_str().unwrap().to_string(),
        risk_level: "high".to_string(),
        threat_type: Some(threat["threatType"].as_str().unwrap().to_string()),
        reason: "Simulated pipeline".to_string(),
        payload: Some(threat.to_string()),
        timestamp: 2000000,
    };

    inter.enqueue(entry);
    assert_eq!(inter.get_queue_size(), 1);
    assert_eq!(inter.get_paused_pids(), vec![9001]);
    assert_eq!(risk.get_event_count(), 0, "仅直接入队不影响 RiskService 计数");
}

#[test]
fn test_reverse_risk_level_from_severity_consistent() {
    // 验证从 ETW 事件的 severity 字段推导 risk_level 的一致性
    // Verifies consistency of risk_level derivation from ETW event severity field
    let test_cases = vec![
        (0, "low"), (15, "low"), (25, "low"),
        (26, "medium"), (45, "medium"), (60, "medium"),
        (61, "high"), (80, "high"), (100, "high"),
    ];

    for (severity, expected_level) in test_cases {
        let event = common::make_threat_event(10000 + severity, "test", severity, "test");
        let actual_severity = event["severity"].as_u64().unwrap() as u32;
        let actual_level = match actual_severity {
            0..=25 => "low",
            26..=60 => "medium",
            _ => "high",
        };
        assert_eq!(
            actual_level, expected_level,
            "severity={} 应映射到 risk_level={}",
            severity, expected_level
        );
    }
}
