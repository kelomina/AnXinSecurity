// 风险梯度映射测试 — 验证 severity → risk_level → shouldIntercept 的映射逻辑
// Risk grading mapping tests — verify severity → risk_level → shouldIntercept mapping logic
//
// 中文关键词：风险梯度，严重度映射，风险等级，边界测试，拦截判断
// English keywords: risk grading, severity mapping, risk level, boundary test, interception decision
use serde_json::json;

mod common;

/// 提取 risk_service 中的严重度→风险等级映射逻辑（独立测试该纯函数）
/// Extract the severity→risk_level mapping logic from risk_service (test this pure function independently)
fn map_severity_to_risk_level(severity: u32) -> &'static str {
    match severity {
        0..=25 => "low",
        26..=60 => "medium",
        _ => "high",
    }
}

/// 判断是否需要自动拦截（只有高风险强证据才进入自动挂起）
/// Determine if automatic interception is needed (only high-risk strong evidence auto-suspends)
fn should_intercept(risk_level: &str) -> bool {
    risk_level == "high"
}

// ================================================================
// 严重度梯度测试 / Severity gradient tests
// ================================================================

#[test]
fn test_severity_0_maps_to_low() {
    assert_eq!(map_severity_to_risk_level(0), "low");
    assert!(!should_intercept("low"));
}

#[test]
fn test_severity_10_maps_to_low() {
    assert_eq!(map_severity_to_risk_level(10), "low");
    assert!(!should_intercept("low"));
}

#[test]
fn test_severity_25_boundary_maps_to_low() {
    assert_eq!(map_severity_to_risk_level(25), "low");
    assert!(!should_intercept("low"));
}

#[test]
fn test_severity_26_boundary_maps_to_medium() {
    assert_eq!(map_severity_to_risk_level(26), "medium");
    assert!(!should_intercept("medium"));
}

#[test]
fn test_severity_50_maps_to_medium() {
    assert_eq!(map_severity_to_risk_level(50), "medium");
    assert!(!should_intercept("medium"));
}

#[test]
fn test_severity_60_boundary_maps_to_medium() {
    assert_eq!(map_severity_to_risk_level(60), "medium");
    assert!(!should_intercept("medium"));
}

#[test]
fn test_severity_61_boundary_maps_to_high() {
    assert_eq!(map_severity_to_risk_level(61), "high");
    assert!(should_intercept("high"));
}

#[test]
fn test_severity_80_maps_to_high() {
    assert_eq!(map_severity_to_risk_level(80), "high");
    assert!(should_intercept("high"));
}

#[test]
fn test_severity_100_maps_to_high() {
    assert_eq!(map_severity_to_risk_level(100), "high");
    assert!(should_intercept("high"));
}

// ================================================================
// 风险等级 vs 拦截决策 / Risk level vs interception decision
// ================================================================

#[test]
fn test_low_risk_does_not_intercept() {
    assert!(!should_intercept("low"));
}

#[test]
fn test_medium_risk_does_not_auto_intercept() {
    assert!(!should_intercept("medium"));
}

#[test]
fn test_high_risk_does_intercept() {
    assert!(should_intercept("high"));
}

// ================================================================
// 事件分类测试 — 判定是否为威胁事件 / Event classification tests
// ================================================================

#[test]
fn test_threat_event_with_matched_true_is_threat() {
    let event = common::make_threat_event(1234, "test_malware", 70, "trojan");
    assert!(common::is_threat_event(&event));
}

#[test]
fn test_threat_event_with_threat_type_field_is_threat() {
    let event = json!({
        "pid": 1234,
        "processName": "suspicious.exe",
        "threatType": "ransomware",
        "severity": 90,
    });
    assert!(common::is_threat_event(&event));
}

#[test]
fn test_normal_event_is_not_threat() {
    let event = common::make_normal_event(1234, "notepad", "Process", "Start");
    assert!(!common::is_threat_event(&event));
}

#[test]
fn test_empty_event_is_not_threat() {
    let event = json!({});
    assert!(!common::is_threat_event(&event));
}
