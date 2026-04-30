use anxin_security::services::interception_service::{
    InterceptionService, InterceptionEntry, InterceptionDecision,
};

mod common;

fn make_entry(pid: u32, name: &str, risk_level: &str) -> InterceptionEntry {
    InterceptionEntry {
        pid,
        process_name: name.to_string(),
        file_path: format!("C:\\test\\{}.exe", name),
        risk_level: risk_level.to_string(),
        threat_type: Some("test_threat".to_string()),
        reason: "Test reason".to_string(),
        payload: None,
        timestamp: 1000,
    }
}

#[test]
fn test_new_service_has_empty_queue() {
    let svc = InterceptionService::new();
    assert_eq!(svc.get_queue_size(), 0);
    assert!(svc.get_paused_pids().is_empty());
}

#[test]
fn test_enqueue_adds_to_queue() {
    let svc = InterceptionService::new();
    svc.enqueue(make_entry(100, "malware_a", "high"));
    assert_eq!(svc.get_queue_size(), 1);
    assert_eq!(svc.get_paused_pids(), vec![100]);
}

#[test]
fn test_enqueue_multiple_different_pids() {
    let svc = InterceptionService::new();
    svc.enqueue(make_entry(100, "a", "high"));
    svc.enqueue(make_entry(200, "b", "medium"));
    svc.enqueue(make_entry(300, "c", "low"));
    assert_eq!(svc.get_queue_size(), 3);
    assert_eq!(svc.get_paused_pids(), vec![100, 200, 300]);
}

#[test]
fn test_enqueue_prevents_duplicate_pids() {
    let svc = InterceptionService::new();
    svc.enqueue(make_entry(100, "malware_a", "high"));
    svc.enqueue(make_entry(100, "malware_a_v2", "high"));
    assert_eq!(svc.get_queue_size(), 1);
}

#[test]
fn test_enqueue_same_pid_same_name_duplicate() {
    let svc = InterceptionService::new();
    let entry = make_entry(999, "trojan_x", "high");
    svc.enqueue(entry.clone());
    svc.enqueue(entry);
    assert_eq!(svc.get_queue_size(), 1);
}

#[test]
fn test_mark_decision_removes_pid_from_queue() {
    let svc = InterceptionService::new();
    svc.enqueue(make_entry(100, "a", "high"));
    svc.enqueue(make_entry(200, "b", "medium"));
    assert_eq!(svc.get_queue_size(), 2);

    svc.mark_decision(100, InterceptionDecision::Allow);
    assert_eq!(svc.get_queue_size(), 1);
    assert_eq!(svc.get_paused_pids(), vec![200]);
}

#[test]
fn test_mark_decision_clears_queue_pid_not_shown() {
    let svc = InterceptionService::new();
    svc.enqueue(make_entry(100, "a", "high"));
    svc.enqueue(make_entry(200, "b", "medium"));
    assert_eq!(svc.get_queue_size(), 2);

    svc.mark_decision(200, InterceptionDecision::Allow);
    assert_eq!(svc.get_queue_size(), 1);
    assert_eq!(svc.get_paused_pids(), vec![100]);
}

#[test]
fn test_clear_all_resets_everything() {
    let svc = InterceptionService::new();
    svc.enqueue(make_entry(100, "a", "high"));
    svc.enqueue(make_entry(200, "b", "medium"));
    assert_eq!(svc.get_queue_size(), 2);

    svc.clear_all();
    assert_eq!(svc.get_queue_size(), 0);
    assert!(svc.get_paused_pids().is_empty());
}

#[test]
fn test_enqueue_zero_pid() {
    let svc = InterceptionService::new();
    svc.enqueue(make_entry(0, "system", "high"));
    assert_eq!(svc.get_queue_size(), 1);
    assert_eq!(svc.get_paused_pids(), vec![0]);
}

#[test]
fn test_mark_decision_on_empty_service_no_panic() {
    let svc = InterceptionService::new();
    svc.mark_decision(100, InterceptionDecision::Allow);
    assert_eq!(svc.get_queue_size(), 0);
}
