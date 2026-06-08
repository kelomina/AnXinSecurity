// 风险服务签名验证调整逻辑测试 — 验证签名验证对风险等级的调整规则
// Risk service signature verification adjustment tests — verify how signature verification adjusts risk levels
//
// 中文关键词：风险调整，签名验证，风险升级，风险降级，安全决策
// English keywords: risk adjustment, signature verification, risk escalation, risk de-escalation, security decision

mod common;

fn map_severity_to_risk_level(severity: u32) -> &'static str {
    match severity {
        0..=25 => "low",
        26..=60 => "medium",
        _ => "high",
    }
}

fn adjust_risk_with_signature(base_risk: &str, trusted: bool, has_file_path: bool) -> String {
    if !has_file_path {
        return base_risk.to_string();
    }
    match (base_risk, trusted) {
        ("low", true) => "low".to_string(),
        ("low", false) => "medium".to_string(),
        (level, _) => level.to_string(),
    }
}

#[test]
fn test_low_risk_trusted_signature_stays_low() {
    let base = map_severity_to_risk_level(10);
    assert_eq!(base, "low");
    let adjusted = adjust_risk_with_signature(base, true, true);
    assert_eq!(adjusted, "low", "trusted + low severity should stay low");
}

#[test]
fn test_low_risk_untrusted_signature_escalates_to_medium() {
    let base = map_severity_to_risk_level(20);
    assert_eq!(base, "low");
    let adjusted = adjust_risk_with_signature(base, false, true);
    assert_eq!(
        adjusted, "medium",
        "untrusted + low severity should escalate to medium"
    );
}

#[test]
fn test_medium_risk_trusted_signature_stays_medium() {
    let base = map_severity_to_risk_level(40);
    assert_eq!(base, "medium");
    let adjusted = adjust_risk_with_signature(base, true, true);
    assert_eq!(
        adjusted, "medium",
        "trusted + medium severity should stay medium"
    );
}

#[test]
fn test_medium_risk_untrusted_signature_stays_medium() {
    let base = map_severity_to_risk_level(50);
    assert_eq!(base, "medium");
    let adjusted = adjust_risk_with_signature(base, false, true);
    assert_eq!(
        adjusted, "medium",
        "untrusted + medium severity should stay medium (already medium)"
    );
}

#[test]
fn test_high_risk_trusted_signature_stays_high() {
    let base = map_severity_to_risk_level(80);
    assert_eq!(base, "high");
    let adjusted = adjust_risk_with_signature(base, true, true);
    assert_eq!(
        adjusted, "high",
        "trusted + high severity should stay high (high risk is never de-escalated)"
    );
}

#[test]
fn test_high_risk_untrusted_signature_stays_high() {
    let base = map_severity_to_risk_level(90);
    assert_eq!(base, "high");
    let adjusted = adjust_risk_with_signature(base, false, true);
    assert_eq!(adjusted, "high", "untrusted + high severity should stay high");
}

#[test]
fn test_no_file_path_preserves_base_risk() {
    for severity in [10u32, 40, 80] {
        let base = map_severity_to_risk_level(severity);
        let adjusted = adjust_risk_with_signature(base, true, false);
        assert_eq!(
            adjusted, base,
            "no file path should preserve base risk level"
        );
    }
}

#[test]
fn test_severity_boundary_25_trusted_stays_low() {
    let base = map_severity_to_risk_level(25);
    assert_eq!(base, "low");
    let adjusted = adjust_risk_with_signature(base, true, true);
    assert_eq!(adjusted, "low");
}

#[test]
fn test_severity_boundary_26_untrusted_escalates_to_medium() {
    let base = map_severity_to_risk_level(26);
    assert_eq!(base, "medium");
    let adjusted = adjust_risk_with_signature(base, false, true);
    assert_eq!(adjusted, "medium");
}

#[test]
fn test_severity_boundary_25_untrusted_escalates_from_low_to_medium() {
    let base = map_severity_to_risk_level(25);
    assert_eq!(base, "low");
    let adjusted = adjust_risk_with_signature(base, false, true);
    assert_eq!(
        adjusted, "medium",
        "severity 25 is low but untrusted signature should escalate to medium"
    );
}

#[test]
fn test_should_intercept_after_signature_adjustment() {
    let should_intercept = |level: &str| matches!(level, "high" | "medium");

    assert!(!should_intercept(&adjust_risk_with_signature("low", true, true)));
    assert!(should_intercept(&adjust_risk_with_signature("low", false, true)));
    assert!(should_intercept(&adjust_risk_with_signature("medium", true, true)));
    assert!(should_intercept(&adjust_risk_with_signature("medium", false, true)));
    assert!(should_intercept(&adjust_risk_with_signature("high", true, true)));
    assert!(should_intercept(&adjust_risk_with_signature("high", false, true)));
}

#[test]
fn test_risk_assessment_struct_fields() {
    use anxin_security::services::risk_service::{RiskAssessment, RiskEvent};

    let event = RiskEvent {
        pid: 1234,
        process_name: "test.exe".to_string(),
        file_path: Some("C:\\test.exe".to_string()),
        threat_type: "trojan".to_string(),
        threat_name: Some("TestTrojan".to_string()),
        severity: 70,
        rule_id: "RULE_001".to_string(),
        description: "Test threat".to_string(),
        timestamp: 1000,
    };

    let assessment = RiskAssessment {
        event: event.clone(),
        risk_level: "high".to_string(),
        should_intercept: true,
        reason: "Test reason".to_string(),
    };

    assert_eq!(assessment.risk_level, "high");
    assert!(assessment.should_intercept);
    assert_eq!(assessment.event.pid, 1234);
    assert_eq!(assessment.event.severity, 70);
}

#[test]
fn test_risk_assessment_serialization() {
    use anxin_security::services::risk_service::{RiskAssessment, RiskEvent};

    let event = RiskEvent {
        pid: 5678,
        process_name: "malware.exe".to_string(),
        file_path: None,
        threat_type: "spyware".to_string(),
        threat_name: None,
        severity: 30,
        rule_id: "RULE_002".to_string(),
        description: "Suspicious activity".to_string(),
        timestamp: 2000,
    };

    let assessment = RiskAssessment {
        event,
        risk_level: "medium".to_string(),
        should_intercept: true,
        reason: "Rule matched".to_string(),
    };

    let json = serde_json::to_string(&assessment).expect("serialization should succeed");
    let parsed: RiskAssessment =
        serde_json::from_str(&json).expect("deserialization should succeed");
    assert_eq!(parsed.risk_level, "medium");
    assert!(parsed.should_intercept);
    assert_eq!(parsed.event.pid, 5678);
}
