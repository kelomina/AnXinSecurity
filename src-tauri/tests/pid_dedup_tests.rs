// PID 去重逻辑测试 — 验证同一 PID 不会重复触发拦截
// PID deduplication logic tests — verify same PID does not trigger repeated interception
//
// 中文关键词：PID去重，重复拦截，去重测试，幂等性
// English keywords: PID dedup, repeated interception, dedup test, idempotency
use anxin_security::services::interception_service::{
    InterceptionService, InterceptionEntry,
};

mod common;

fn make_entry(pid: u32) -> InterceptionEntry {
    InterceptionEntry {
        pid,
        process_name: format!("process_{}", pid),
        file_path: format!("C:\\test\\process_{}.exe", pid),
        risk_level: "high".to_string(),
        threat_type: Some("malware".to_string()),
        reason: "Test reason".to_string(),
        payload: None,
        timestamp: 1000,
    }
}

// ================================================================
// PID去重核心测试 / PID dedup core tests
// ================================================================

#[test]
fn test_same_pid_different_entries_only_enqueues_once() {
    let svc = InterceptionService::new();
    svc.enqueue(make_entry(42));
    svc.enqueue(make_entry(42));  // 相同 PID
    svc.enqueue(make_entry(42));  // 再次相同 PID
    assert_eq!(svc.get_queue_size(), 1, "同 PID 多次入队应只保留一个");
}

#[test]
fn test_different_pids_each_enqueue_once() {
    let svc = InterceptionService::new();
    for pid in 1..=10u32 {
        svc.enqueue(make_entry(pid));
    }
    assert_eq!(svc.get_queue_size(), 10);
}

#[test]
fn test_interleaved_pid_enqueue_still_dedup() {
    let svc = InterceptionService::new();
    svc.enqueue(make_entry(1));
    svc.enqueue(make_entry(2));
    svc.enqueue(make_entry(1));  // 重复
    svc.enqueue(make_entry(3));
    svc.enqueue(make_entry(2));  // 重复
    assert_eq!(svc.get_queue_size(), 3, "交错重复入队后应去重");
    assert_eq!(svc.get_paused_pids(), vec![1, 2, 3]);
}

#[test]
fn test_dedup_applies_to_high_medium_low_all_levels() {
    let svc = InterceptionService::new();

    let mut e1 = make_entry(100);
    e1.risk_level = "high".to_string();
    svc.enqueue(e1);

    let mut e2 = make_entry(100);  // 同 PID，不同风险等级
    e2.risk_level = "medium".to_string();
    svc.enqueue(e2);

    let mut e3 = make_entry(100);
    e3.risk_level = "low".to_string();
    svc.enqueue(e3);

    assert_eq!(svc.get_queue_size(), 1, "同 PID 无论风险等级如何均应去重");
}

#[test]
fn test_pid_dedup_across_clear_and_re_enqueue() {
    let svc = InterceptionService::new();
    svc.enqueue(make_entry(500));
    assert_eq!(svc.get_queue_size(), 1);

    svc.clear_all();
    assert_eq!(svc.get_queue_size(), 0);

    // 清除后相同 PID 可以再次入队
    svc.enqueue(make_entry(500));
    assert_eq!(svc.get_queue_size(), 1, "clear_all 后同 PID 可重新入队");
}

// ================================================================
// 批量去重压力测试 / Batch dedup stress test
// ================================================================

#[test]
fn test_many_duplicate_pids_still_works() {
    let svc = InterceptionService::new();
    // 同 PID 入队 100 次 / Enqueue same PID 100 times
    for _ in 0..100 {
        svc.enqueue(make_entry(42));
    }
    assert_eq!(svc.get_queue_size(), 1);
}

#[test]
fn test_many_unique_pids_no_issue() {
    let svc = InterceptionService::new();
    // 1000 个不同 PID / 1000 different PIDs
    for pid in 0..1000u32 {
        svc.enqueue(make_entry(pid));
    }
    assert_eq!(svc.get_queue_size(), 1000);
    // 验证顺序 / Verify order
    let pids = svc.get_paused_pids();
    assert_eq!(pids.len(), 1000);
    assert_eq!(pids[0], 0);
    assert_eq!(pids[999], 999);
}
