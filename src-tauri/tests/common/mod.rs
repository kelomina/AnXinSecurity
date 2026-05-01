// 共享测试辅助函数 / Shared test helper functions
// 用于构造测试数据，仿照 ETW 规则匹配产生的威胁事件格式
// Used to construct test data, mimicking threat event format from ETW rule matching
use serde_json::json;

/// 构造一个包含威胁识别字段的 ETW 事件 JSON
/// Construct an ETW event JSON containing threat identification fields
///
/// 中文关键词：测试工厂，事件构造，mock事件，威胁测试数据
/// English keywords: test factory, event construction, mock event, threat test data
pub fn make_threat_event(pid: u32, process_name: &str, severity: u32, threat_type: &str) -> serde_json::Value {
    json!({
        "type": "threat",
        "timestamp": "2026-05-01T00:00:00Z",
        "pid": pid,
        "provider": "Process",
        "operation": "Start",
        "processName": process_name,
        "path": format!("C:\\malware\\{}.exe", process_name),
        "matched": true,
        "threatType": threat_type,
        "severity": severity,
        "ruleId": format!("RULE_{}", threat_type),
        "description": format!("检测到可疑行为: {}", threat_type),
    })
}

/// 构造一个无威胁标记的普通 ETW 事件 JSON
/// Construct a normal ETW event JSON without threat flags
pub fn make_normal_event(pid: u32, process_name: &str, provider: &str, operation: &str) -> serde_json::Value {
    json!({
        "type": provider,
        "timestamp": "2026-05-01T00:00:00Z",
        "pid": pid,
        "provider": provider,
        "operation": operation,
        "processName": process_name,
        "path": format!("C:\\windows\\system32\\{}.exe", process_name),
    })
}

/// 判断是否为威胁事件（需触发风险分析）/ Check if an event should trigger risk analysis
pub fn is_threat_event(event: &serde_json::Value) -> bool {
    event
        .get("matched")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || event.get("threatType").is_some()
}
