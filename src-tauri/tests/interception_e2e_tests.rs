use std::sync::Arc;
use anxin_security::services::risk_service::RiskService;
use anxin_security::services::interception_service::{
    InterceptionService, InterceptionEntry, InterceptionDecision,
};

mod common;

fn make_entry(pid: u32, name: &str, risk_level: &str, severity: u32) -> InterceptionEntry {
    InterceptionEntry {
        pid,
        process_name: name.to_string(),
        file_path: format!("C:\\test\\{}.exe", name),
        risk_level: risk_level.to_string(),
        threat_type: Some(match severity {
            0..=25 => "adware",
            26..=60 => "trojan",
            _ => "ransomware",
        }.to_string()),
        reason: format!("\u{98ce}\u{9669}\u{4e8b}\u{4ef6}: {} (\u{4e25}\u{91cd}\u{5ea6}: {})", name, severity),
        payload: Some(serde_json::json!({
            "severity": severity,
            "ruleId": format!("E2E_RULE_{}", severity),
        }).to_string()),
        timestamp: 1000 + pid as u64,
    }
}

#[test]
fn test_e2e_single_process_lifecycle() {
    let inter = InterceptionService::new();

    let entry = make_entry(5001, "ransom.exe", "high", 90);
    inter.enqueue(entry);
    assert_eq!(inter.get_queue_size(), 1);
    assert_eq!(inter.get_paused_pids(), vec![5001]);

    inter.mark_decision(5001, InterceptionDecision::Block);
    assert_eq!(inter.get_queue_size(), 0);

    let entry2 = make_entry(5001, "ransom.exe", "high", 90);
    inter.enqueue(entry2);
    assert_eq!(inter.get_queue_size(), 1);
}

#[test]
fn test_e2e_single_process_allow_then_re_enqueue() {
    let inter = InterceptionService::new();

    inter.enqueue(make_entry(6001, "suspicious.exe", "medium", 50));
    assert_eq!(inter.get_queue_size(), 1);

    inter.mark_decision(6001, InterceptionDecision::Allow);
    assert_eq!(inter.get_queue_size(), 0);

    inter.enqueue(make_entry(6001, "suspicious.exe", "medium", 50));
    assert_eq!(inter.get_queue_size(), 1);
}

#[test]
fn test_e2e_multi_process_fifo_order() {
    let inter = InterceptionService::new();

    inter.enqueue(make_entry(100, "proc_a.exe", "low", 10));
    inter.enqueue(make_entry(200, "proc_b.exe", "medium", 50));
    inter.enqueue(make_entry(300, "proc_c.exe", "high", 90));

    assert_eq!(inter.get_paused_pids(), vec![100, 200, 300]);

    inter.mark_decision(100, InterceptionDecision::Allow);
    assert_eq!(inter.get_paused_pids(), vec![200, 300]);

    inter.mark_decision(200, InterceptionDecision::Block);
    assert_eq!(inter.get_paused_pids(), vec![300]);

    inter.mark_decision(300, InterceptionDecision::Allow);
    assert_eq!(inter.get_queue_size(), 0);
    assert!(inter.get_paused_pids().is_empty());
}

#[test]
fn test_e2e_duplicate_prevention() {
    let inter = InterceptionService::new();

    inter.enqueue(make_entry(7001, "dup.exe", "high", 80));
    inter.enqueue(make_entry(7001, "dup.exe", "high", 80));
    assert_eq!(inter.get_queue_size(), 1);

    inter.mark_decision(7001, InterceptionDecision::Block);
    assert_eq!(inter.get_queue_size(), 0);

    inter.enqueue(make_entry(7001, "dup.exe", "high", 80));
    assert_eq!(inter.get_queue_size(), 1);
}

#[test]
fn test_e2e_clear_all() {
    let inter = InterceptionService::new();

    inter.enqueue(make_entry(8001, "a.exe", "low", 10));
    inter.enqueue(make_entry(8002, "b.exe", "medium", 50));
    inter.enqueue(make_entry(8003, "c.exe", "high", 90));

    inter.clear_all();
    assert_eq!(inter.get_queue_size(), 0);
    assert!(inter.get_paused_pids().is_empty());
}

#[test]
fn test_e2e_mixed_decisions() {
    let inter = InterceptionService::new();

    inter.enqueue(make_entry(100, "allow.exe", "low", 10));
    inter.enqueue(make_entry(200, "block.exe", "high", 90));
    inter.enqueue(make_entry(300, "allow2.exe", "medium", 50));

    inter.mark_decision(200, InterceptionDecision::Block);
    assert_eq!(inter.get_paused_pids(), vec![100, 300]);
    assert_eq!(inter.get_queue_size(), 2);

    inter.mark_decision(100, InterceptionDecision::Allow);
    assert_eq!(inter.get_paused_pids(), vec![300]);

    inter.mark_decision(300, InterceptionDecision::Allow);
    assert!(inter.get_paused_pids().is_empty());
}

#[test]
fn test_risk_service_initially_has_zero_count() {
    let risk = RiskService::new();
    assert_eq!(risk.get_event_count(), 0);
}

#[test]
fn test_risk_service_and_interaction_wired() {
    let risk = RiskService::new();
    let inter = Arc::new(InterceptionService::new());
    risk.set_interception_service(inter.clone());

    let entry = make_entry(9001, "wired.exe", "high", 70);
    inter.enqueue(entry);
    assert_eq!(inter.get_queue_size(), 1);
    assert_eq!(inter.get_paused_pids(), vec![9001]);
}
