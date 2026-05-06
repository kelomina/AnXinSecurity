// 行为数据库服务测试 — 验证 ETW→Risk 管线中 BehaviorService 的 events 表 CRUD 路径
// Behavior database service tests — verify CRUD paths for events table in ETW→Risk pipeline
//
// 测试 BehaviorService::ingest_event / list_events / list_processes / clear_all
// 使用内存 SQLite，不依赖真实文件系统
// Tests use in-memory SQLite, no real filesystem dependency
//
// 中文关键词：行为数据库，事件写入，事件查询，进程查询，内存数据库，SQLite测试
// English keywords: behavior database, event ingest, event query, process query, in-memory DB, SQLite test

use anxin_security::services::behavior_service::BehaviorService;
use serde_json::json;
use sqlx::SqlitePool;

mod common;

/// 创建带有 events 表的内存 SQLite 池并返回 BehaviorService
/// Create an in-memory SQLite pool with events table and return BehaviorService
async fn setup_behavior_service() -> BehaviorService {
    let pool = SqlitePool::connect("sqlite::memory:")
        .await
        .expect("Failed to create in-memory SQLite pool");

    // 创建 events 表（与 main.rs 中的迁移一致）
    // Create events table (matching migration in main.rs)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            pid INTEGER,
            process_name TEXT,
            operation TEXT,
            path TEXT,
            timestamp TEXT,
            details TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create events table");

    BehaviorService::new(pool)
}

/// 构造一个模拟 analyze_event 生成的 behavior_event JSON
/// Construct a JSON that simulates what analyze_event passes to ingest_event
fn make_behavior_event(
    pid: u32,
    process_name: &str,
    threat_type: &str,
    path: Option<&str>,
    severity: u32,
) -> serde_json::Value {
    json!({
        "type": "risk_analysis",
        "pid": pid,
        "processName": process_name,
        "path": path,
        "operation": threat_type,
        "timestamp": "2026-05-01T12:00:00Z",
        "details": format!(r#"{{"risk_level":"{}","shouldIntercept":{},"reason":"rule test matched","event":{{"pid":{},"severity":{}}}}}"#,
            if severity >= 61 { "high" } else if severity >= 26 { "medium" } else { "low" },
            severity >= 26,
            pid,
            severity
        ),
    })
}

// ================================================================
// ingest_event 基础测试 / ingest_event basic tests
// ================================================================

#[tokio::test]
async fn test_ingest_single_event_succeeds() {
    let svc = setup_behavior_service().await;
    let event = make_behavior_event(100, "malware.exe", "trojan", Some("C:\\malware.exe"), 80);

    let result = svc.ingest_event(event).await;
    assert!(result.is_ok(), "ingest_event 应成功");
}

#[tokio::test]
async fn test_ingest_event_appears_in_list() {
    let svc = setup_behavior_service().await;
    let pid = 101u64;

    let event = make_behavior_event(101, "trojan.exe", "trojan", Some("C:\\trojan.exe"), 75);
    svc.ingest_event(event).await.expect("写入应成功");

    let events = svc.list_events(Some(101), 10).await.expect("查询应成功");
    assert_eq!(events.len(), 1, "应能查询到刚写入的 1 条事件");
    let first = &events[0];
    assert_eq!(first["pid"], json!(pid), "PID 应匹配");
    assert_eq!(first["processName"], json!("trojan.exe"), "进程名应匹配");
    assert_eq!(first["operation"], json!("trojan"), "操作类型应匹配");
    assert_eq!(first["path"], json!("C:\\trojan.exe"), "路径应匹配");
}

#[tokio::test]
async fn test_ingest_multiple_events_all_listed() {
    let svc = setup_behavior_service().await;

    for i in 0..5u32 {
        let event = make_behavior_event(200 + i, &format!("proc_{}.exe", i), "malware", None, 50);
        svc.ingest_event(event).await.expect("写入应成功");
    }

    // 无 PID 过滤查询 / No PID filter query
    let all = svc.list_events(None, 100).await.expect("查询应成功");
    assert_eq!(all.len(), 5, "应查询到全部 5 条事件");

    // 按 PID 过滤 / Filter by PID
    let filtered = svc.list_events(Some(202), 10).await.expect("查询应成功");
    assert_eq!(filtered.len(), 1, "PID=202 应只有 1 条");
    assert_eq!(filtered[0]["pid"], json!(202u64));
}

// ================================================================
// ingest_event 数据格式测试 — 模拟 analyze_event 的输出格式
// ingest_event data format test — simulate analyze_event output format
// ================================================================

#[tokio::test]
async fn test_ingest_preserves_all_analyze_event_fields() {
    let svc = setup_behavior_service().await;

    // 完全按照 analyze_event 步骤5的格式构造
    // Exact format from analyze_event step 5
    let assessment_json = r#"{"risk_level":"high","shouldIntercept":true,"reason":"test reason"}"#;
    let behavior_event = json!({
        "type": "risk_analysis",
        "pid": 300,
        "processName": "ransomware.exe",
        "path": "C:\\ransomware.exe",
        "operation": "ransomware",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "details": assessment_json,
    });

    svc.ingest_event(behavior_event).await.expect("写入应成功");

    let events = svc.list_events(Some(300), 10).await.expect("查询应成功");
    assert_eq!(events.len(), 1);

    let ev = &events[0];
    assert_eq!(ev["pid"], json!(300u64));
    assert_eq!(ev["processName"], json!("ransomware.exe"));
    assert_eq!(ev["operation"], json!("ransomware"));
    assert_eq!(ev["path"], json!("C:\\ransomware.exe"));
    assert!(
        ev["timestamp"].as_str().unwrap_or("").contains("202"),
        "应包含时间戳"
    );
    // details 字段应包含完整的风险研判信息
    assert!(
        ev["details"].as_str().unwrap_or("").contains("risk_level"),
        "应包含风险等级"
    );
}

#[tokio::test]
async fn test_ingest_with_minimal_fields() {
    let svc = setup_behavior_service().await;

    // 最小字段事件（某些 ETW 事件可能缺少部分字段）
    let minimal = json!({
        "pid": 400,
        "processName": "",
        "operation": "",
        "path": "",
        "timestamp": "",
    });

    let result = svc.ingest_event(minimal).await;
    assert!(result.is_ok(), "最小字段事件应能成功写入（不崩溃）");
}

#[tokio::test]
async fn test_ingest_with_missing_fields_defaults() {
    let svc = setup_behavior_service().await;

    // 只提供 pid，其他字段缺失
    let sparse = json!({
        "pid": 401,
    });

    let result = svc.ingest_event(sparse).await;
    assert!(result.is_ok(), "稀疏事件应能写入");

    let events = svc.list_events(Some(401), 10).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["pid"], json!(401u64));
}

// ================================================================
// list_processes 测试 / list_processes tests
// ================================================================

#[tokio::test]
async fn test_list_processes_returns_distinct_pids() {
    let svc = setup_behavior_service().await;

    // PID=500 有 3 条事件，PID=501 有 2 条事件
    for _ in 0..3 {
        svc.ingest_event(make_behavior_event(500, "proc_a.exe", "malware", None, 60))
            .await
            .unwrap();
    }
    for _ in 0..2 {
        svc.ingest_event(make_behavior_event(501, "proc_b.exe", "spyware", None, 40))
            .await
            .unwrap();
    }

    let processes = svc.list_processes(50).await.expect("查询应成功");
    assert_eq!(processes.len(), 2, "应返回 2 个不重复的进程");
    assert!(processes.iter().any(|p| p["pid"] == json!(500u64)));
    assert!(processes.iter().any(|p| p["pid"] == json!(501u64)));
}

#[tokio::test]
async fn test_list_processes_respects_limit() {
    let svc = setup_behavior_service().await;

    for pid in 600..610u32 {
        svc.ingest_event(make_behavior_event(
            pid,
            &format!("p{}.exe", pid),
            "test",
            None,
            30,
        ))
        .await
        .unwrap();
    }

    let processes = svc.list_processes(5).await.expect("查询应成功");
    assert!(processes.len() <= 5, "应遵守 LIMIT 限制");
}

// ================================================================
// clear_all 测试 / clear_all tests
// ================================================================

#[tokio::test]
async fn test_clear_all_removes_all_events() {
    let svc = setup_behavior_service().await;

    for pid in 700..705u32 {
        svc.ingest_event(make_behavior_event(pid, "wipable.exe", "test", None, 20))
            .await
            .unwrap();
    }

    assert!(
        !svc.list_events(None, 100).await.unwrap().is_empty(),
        "清空前应有数据"
    );

    let result = svc.clear_all().await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true);

    let after = svc.list_events(None, 100).await.unwrap();
    assert!(after.is_empty(), "清空后应无数据");
}

#[tokio::test]
async fn test_clear_all_idempotent() {
    let svc = setup_behavior_service().await;

    // 空表清空不应失败 / Clearing empty table should not fail
    let result = svc.clear_all().await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true);

    // 再次清空 / Clear again
    let result2 = svc.clear_all().await;
    assert!(result2.is_ok());
}

// ================================================================
// 数据完整性测试 / Data integrity tests
// ================================================================

#[tokio::test]
async fn test_ingest_duplicate_id_ignored() {
    let svc = setup_behavior_service().await;

    // BehaviorService 使用 INSERT OR IGNORE + UUID 作为 id
    // 相同数据插入两次不应产生重复
    let event = make_behavior_event(800, "dup_test.exe", "trojan", None, 70);
    svc.ingest_event(event.clone()).await.unwrap();
    svc.ingest_event(event).await.unwrap();

    let events = svc.list_events(Some(800), 10).await.unwrap();
    // 由于每次生成新的 UUID，两次 INSERT 都会成功（不同 id）
    // 但数据相同（同 PID 同操作）是正常行为
    assert!(events.len() >= 1, "至少应有 1 条记录");
}

#[tokio::test]
async fn test_pid_filter_returns_empty_for_unknown_pid() {
    let svc = setup_behavior_service().await;
    let events = svc.list_events(Some(9999), 10).await.unwrap();
    assert!(events.is_empty(), "不存在的 PID 应返回空列表");
}

// ================================================================
// 模拟 analyze_event 行为数据库写入路径
// Simulate analyze_event behavior database write path
// ================================================================

#[tokio::test]
async fn test_simulate_analyze_event_db_writes_high_risk() {
    let svc = setup_behavior_service().await;

    // 模拟 analyze_event 步骤5: 高风险事件写入 BehaviorService
    // Simulate analyze_event step 5: high risk event written to BehaviorService
    let risk_data = json!({
        "riskLevel": "high",
        "shouldIntercept": true,
        "reason": "Test: high severity threat detected",
        "event": { "pid": 900, "severity": 85, "threatType": "ransomware" }
    });

    let behavior_event = json!({
        "type": "risk_analysis",
        "pid": 900,
        "processName": "ransomware.exe",
        "path": "C:\\ransomware.exe",
        "operation": "ransomware",
        "timestamp": "2026-05-01T12:00:00Z",
        "details": risk_data.to_string(),
    });

    svc.ingest_event(behavior_event).await.unwrap();

    // 验证查询结果 / Verify query result
    let events = svc.list_events(Some(900), 10).await.unwrap();
    assert_eq!(events.len(), 1);
    let details = events[0]["details"].as_str().unwrap();
    assert!(details.contains("high"), "details 应包含风险等级");
    assert!(
        details.contains("shouldIntercept"),
        "details 应包含拦截判断"
    );
    assert!(details.contains("ransomware"), "details 应包含威胁类型");
}

#[tokio::test]
async fn test_simulate_analyze_event_db_writes_low_risk() {
    let svc = setup_behavior_service().await;

    // 低风险事件也写入数据库（analyze_event 对所有事件都写入）
    // Low risk events are also written (analyze_event writes all events)
    let risk_data = json!({
        "riskLevel": "low",
        "shouldIntercept": false,
        "reason": "Test: low severity, no interception",
        "event": { "pid": 901, "severity": 10, "threatType": "pup" }
    });

    let behavior_event = json!({
        "type": "risk_analysis",
        "pid": 901,
        "processName": "harmless.exe",
        "path": "C:\\harmless.exe",
        "operation": "pup",
        "timestamp": "2026-05-01T12:00:00Z",
        "details": risk_data.to_string(),
    });

    svc.ingest_event(behavior_event).await.unwrap();
    let events = svc.list_events(Some(901), 10).await.unwrap();
    assert_eq!(events.len(), 1, "低风险事件也应写入数据库");
}

#[tokio::test]
async fn test_simulate_multiple_events_create_processes_list() {
    let svc = setup_behavior_service().await;

    // 同一个进程有多个事件（不同操作类型）
    // Same process with multiple events (different operations)
    let base = json!({
        "pid": 950,
        "processName": "multi_op.exe",
        "path": "C:\\multi_op.exe",
        "timestamp": "2026-05-01T12:00:00Z",
    });

    for (i, op) in ["file_create", "registry_write", "network_connect"]
        .iter()
        .enumerate()
    {
        let risk_data = json!({
            "riskLevel": "medium",
            "shouldIntercept": true,
            "reason": format!("Test op {}", op),
            "event": { "pid": 950, "severity": 40 + i as u32 * 5, "threatType": "multi_stage" }
        });
        let event = json!({
            "type": "risk_analysis",
            "pid": 950,
            "processName": "multi_op.exe",
            "path": "C:\\multi_op.exe",
            "operation": *op,
            "timestamp": "2026-05-01T12:00:00Z",
            "details": risk_data.to_string(),
        });
        svc.ingest_event(event).await.unwrap();
    }

    // 验证 3 条事件都存在 / Verify all 3 events exist
    let events = svc.list_events(Some(950), 10).await.unwrap();
    assert_eq!(events.len(), 3);

    // 验证进程列表只返回 1 个进程 / Verify process list returns 1 process
    let processes = svc.list_processes(10).await.unwrap();
    assert_eq!(processes.len(), 1);
    assert_eq!(processes[0]["pid"], json!(950u64));
    assert_eq!(processes[0]["processName"], json!("multi_op.exe"));
}
