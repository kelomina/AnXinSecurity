use std::sync::Arc;
use anxin_security::services::risk_service::{RiskService, RiskEvent, RiskAssessment};
use anxin_security::services::interception_service::{InterceptionService, InterceptionEntry, InterceptionDecision};

mod common;

#[test]
fn test_risk_service_initially_has_zero_count() {
    let risk = RiskService::new();
    assert_eq!(risk.get_event_count(), 0);
}

#[test]
fn test_interception_service_initially_empty() {
    let inter = InterceptionService::new();
    assert_eq!(inter.get_queue_size(), 0);
    assert!(inter.get_paused_pids().is_empty());
}

#[test]
fn test_services_can_be_wired_together() {
    let risk = RiskService::new();
    let inter = Arc::new(InterceptionService::new());
    risk.set_interception_service(inter);
    assert_eq!(risk.get_event_count(), 0);
}

#[test]
fn test_wired_interception_enqueue_visible_to_both() {
    let risk = RiskService::new();
    let inter = Arc::new(InterceptionService::new());
    risk.set_interception_service(inter.clone());

    let entry = InterceptionEntry {
        pid: 7000,
        process_name: "test_wired.exe".to_string(),
        file_path: "C:\\test_wired.exe".to_string(),
        risk_level: "high".to_string(),
        threat_type: Some("trojan".to_string()),
        reason: "Wired test".to_string(),
        payload: None,
        timestamp: 1000,
    };
    inter.enqueue(entry);

    assert_eq!(inter.get_queue_size(), 1);
    assert_eq!(inter.get_paused_pids(), vec![7000]);
}

#[test]
fn test_enqueue_then_decide_completes_flow() {
    let inter = InterceptionService::new();

    let entry = InterceptionEntry {
        pid: 8001,
        process_name: "flow_test.exe".to_string(),
        file_path: "C:\\flow_test.exe".to_string(),
        risk_level: "high".to_string(),
        threat_type: Some("malware".to_string()),
        reason: "Flow test".to_string(),
        payload: None,
        timestamp: 2000,
    };
    inter.enqueue(entry);
    assert_eq!(inter.get_queue_size(), 1);

    inter.mark_decision(8001, InterceptionDecision::Block);
    assert_eq!(inter.get_queue_size(), 0);
}

#[test]
fn test_multiple_processes_decision_ordering() {
    let inter = InterceptionService::new();

    for pid in &[100, 200, 300] {
        inter.enqueue(InterceptionEntry {
            pid: *pid,
            process_name: format!("proc_{}.exe", pid),
            file_path: format!("C:\\proc_{}.exe", pid),
            risk_level: "medium".to_string(),
            threat_type: Some("test".to_string()),
            reason: "Multi lifecycle".to_string(),
            payload: None,
            timestamp: 3000,
        });
    }
    assert_eq!(inter.get_queue_size(), 3);

    inter.mark_decision(100, InterceptionDecision::Allow);
    assert_eq!(inter.get_queue_size(), 2);
    assert_eq!(inter.get_paused_pids(), vec![200, 300]);

    inter.mark_decision(200, InterceptionDecision::Block);
    assert_eq!(inter.get_queue_size(), 1);
    assert_eq!(inter.get_paused_pids(), vec![300]);

    inter.mark_decision(300, InterceptionDecision::Allow);
    assert_eq!(inter.get_queue_size(), 0);
    assert!(inter.get_paused_pids().is_empty());
}

#[test]
fn test_risk_event_fields_accessible() {
    let event = RiskEvent {
        pid: 9001,
        process_name: "struct_test.exe".to_string(),
        file_path: Some("C:\\struct_test.exe".to_string()),
        threat_type: "spyware".to_string(),
        threat_name: Some("TestSpy".to_string()),
        severity: 72,
        rule_id: "RULE_001".to_string(),
        description: "Test event structure".to_string(),
        timestamp: 9999,
    };

    assert_eq!(event.pid, 9001);
    assert_eq!(event.severity, 72);
    assert_eq!(event.threat_type, "spyware");
    assert!(event.file_path.is_some());
    assert_eq!(event.file_path.unwrap(), "C:\\struct_test.exe");
}

#[test]
fn test_risk_event_json_serialization() {
    let event = RiskEvent {
        pid: 9002,
        process_name: "json_test.exe".to_string(),
        file_path: Some("C:\\json_test.exe".to_string()),
        threat_type: "ransomware".to_string(),
        threat_name: None,
        severity: 95,
        rule_id: "RULE_002".to_string(),
        description: "JSON test".to_string(),
        timestamp: 10000,
    };

    let json_str = serde_json::to_string(&event).expect("\u5e8f\u5217\u5316\u5e94\u6210\u529f");
    let parsed: RiskEvent = serde_json::from_str(&json_str).expect("\u53cd\u5e8f\u5217\u5316\u5e94\u6210\u529f");
    assert_eq!(parsed.pid, event.pid);
    assert_eq!(parsed.severity, event.severity);
    assert_eq!(parsed.threat_type, event.threat_type);
    assert_eq!(parsed.process_name, event.process_name);
}

#[test]
fn test_risk_service_counter_starts_at_zero() {
    let risk = RiskService::new();
    assert_eq!(risk.get_event_count(), 0);
}

#[test]
fn test_risk_service_counter_independent_of_interception() {
    let risk = RiskService::new();
    let inter = Arc::new(InterceptionService::new());
    risk.set_interception_service(inter);
    assert_eq!(risk.get_event_count(), 0);
}

#[test]
fn test_clear_all_on_wired_services() {
    let risk = RiskService::new();
    let inter = Arc::new(InterceptionService::new());
    risk.set_interception_service(inter.clone());

    for pid in 1..=5u32 {
        inter.enqueue(InterceptionEntry {
            pid,
            process_name: format!("cleanup_{}.exe", pid),
            file_path: format!("C:\\cleanup_{}.exe", pid),
            risk_level: "medium".to_string(),
            threat_type: Some("test".to_string()),
            reason: "Cleanup".to_string(),
            payload: None,
            timestamp: 5000,
        });
    }

    assert_eq!(inter.get_queue_size(), 5);

    inter.mark_decision(1, InterceptionDecision::Block);
    assert_eq!(inter.get_queue_size(), 4);

    inter.clear_all();
    assert_eq!(inter.get_queue_size(), 0);
    assert!(inter.get_paused_pids().is_empty());
}
