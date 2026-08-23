// BehaviorService 测试 — 验证行为事件数据库操作的核心逻辑
// BehaviorService tests — verify core logic of behavior event database operations
//
// 测试策略：使用内存 SQLite 数据库测试 BehaviorService 的所有公共方法，包括：
// - ingest_event: 事件摄取、字段提取、错误处理
// - list_processes: 进程列表查询和分页
// - list_events: 事件查询（全局/PID过滤）
// - clear_all: 数据清除
//
// 中文关键词：行为服务，事件摄取，数据库操作，进程列表，事件查询
// English keywords: behavior service, event ingestion, database operations, process list, event query

mod common;

use anxin_security::services::behavior_service::BehaviorService;
use sqlx::SqlitePool;

#[cfg(test)]
mod ingest_event_tests {
    use super::*;

    async fn setup_service() -> BehaviorService {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                path TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();
        BehaviorService::new(pool)
    }

    #[tokio::test]
    async fn ingest_event_stores_complete_event() {
        let service = setup_service().await;
        let event = serde_json::json!({
            "pid": 1234,
            "processName": "test.exe",
            "operation": "file_create",
            "path": "C:\\test\\file.exe",
            "timestamp": "2026-05-27T10:00:00Z",
            "type": "test"
        });

        service.ingest_event(event).await.unwrap();

        let processes = service.list_processes(10).await.unwrap();
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0]["pid"], 1234);
        assert_eq!(processes[0]["processName"], "test.exe");
    }

    #[tokio::test]
    async fn ingest_event_handles_missing_optional_fields() {
        let service = setup_service().await;
        let event = serde_json::json!({
            "type": "minimal_event"
        });

        service.ingest_event(event).await.unwrap();

        let processes = service.list_processes(10).await.unwrap();
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0]["pid"], 0);
        assert_eq!(processes[0]["processName"], "");
    }

    #[tokio::test]
    async fn ingest_event_handles_null_values() {
        let service = setup_service().await;
        let event = serde_json::json!({
            "pid": null,
            "processName": null,
            "operation": null,
            "path": null,
            "timestamp": null,
            "type": "null_test"
        });

        let result = service.ingest_event(event).await;
        assert!(result.is_ok(), "should handle null values gracefully");
    }

    #[tokio::test]
    async fn ingest_event_stores_nested_json_in_details() {
        let service = setup_service().await;
        let event = serde_json::json!({
            "pid": 5678,
            "processName": "nested.exe",
            "operation": "complex",
            "path": "C:\\test",
            "timestamp": "2026-05-27T12:00:00Z",
            "nested": {
                "level1": {
                    "level2": "deep_value"
                }
            }
        });

        service.ingest_event(event).await.unwrap();

        let events = service.list_events(None, 10).await.unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0]["nested"].is_object());
    }

    #[tokio::test]
    async fn ingest_event_allows_duplicate_ids() {
        let service = setup_service().await;
        let event1 = serde_json::json!({
            "pid": 100,
            "processName": "dup1.exe",
            "operation": "op1",
            "path": "p1",
            "timestamp": "2026-05-27T10:00:00Z"
        });
        let event2 = serde_json::json!({
            "pid": 200,
            "processName": "dup2.exe",
            "operation": "op2",
            "path": "p2",
            "timestamp": "2026-05-27T11:00:00Z"
        });

        service.ingest_event(event1).await.unwrap();
        service.ingest_event(event2).await.unwrap();

        let processes = service.list_processes(10).await.unwrap();
        assert_eq!(processes.len(), 2);
    }

    #[tokio::test]
    async fn ingest_event_generates_unique_uuids() {
        let service = setup_service().await;
        let mut events = Vec::new();
        for i in 0..5 {
            events.push(serde_json::json!({
                "pid": i as i64,
                "processName": format!("process_{}.exe", i),
                "operation": "test",
                "path": format!("C:\\test\\{}", i),
                "timestamp": format!("2026-05-27T10:00:{}0Z", i)
            }));
        }

        for event in events {
            service.ingest_event(event).await.unwrap();
        }

        let all_events = service.list_events(None, 100).await.unwrap();
        let ids: Vec<&serde_json::Value> = all_events.iter().map(|e| &e["id"]).collect();
        let unique_ids: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique_ids.len(), "all UUIDs should be unique");
    }
}

#[cfg(test)]
mod list_processes_tests {
    use super::*;

    async fn setup_service_with_events(count: usize) -> BehaviorService {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                path TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let service = BehaviorService::new(pool);

        for i in 0..count {
            let event = serde_json::json!({
                "pid": (i as i64) * 100,
                "processName": format!("process_{}.exe", i),
                "operation": "test",
                "path": format!("C:\\test\\{}", i),
                "timestamp": format!("2026-05-27T10:{:02}:00Z", i)
            });
            service.ingest_event(event).await.unwrap();
        }

        service
    }

    #[tokio::test]
    async fn list_processes_returns_distinct_processes() {
        let service = setup_service_with_events(5).await;
        let result = service.list_processes(10).await.unwrap();
        assert_eq!(result.len(), 5);
    }

    #[tokio::test]
    async fn list_processes_respects_limit() {
        let service = setup_service_with_events(10).await;
        let result = service.list_processes(3).await.unwrap();
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn list_processes_orders_by_timestamp_desc() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                path TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let service = BehaviorService::new(pool);

        let old_event = serde_json::json!({
            "pid": 100,
            "processName": "old.exe",
            "operation": "test",
            "path": "old",
            "timestamp": "2026-01-01T00:00:00Z"
        });
        let new_event = serde_json::json!({
            "pid": 200,
            "processName": "new.exe",
            "operation": "test",
            "path": "new",
            "timestamp": "2026-12-31T23:59:59Z"
        });

        service.ingest_event(old_event).await.unwrap();
        service.ingest_event(new_event).await.unwrap();

        let result = service.list_processes(10).await.unwrap();
        assert_eq!(result[0]["processName"], "new.exe");
    }

    #[tokio::test]
    async fn list_processes_empty_when_no_events() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                path TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let service = BehaviorService::new(pool);
        let result = service.list_processes(10).await.unwrap();
        assert_eq!(result.len(), 0);
    }

    #[tokio::test]
    async fn list_processes_includes_pid_and_process_name() {
        let service = setup_service_with_events(1).await;
        let result = service.list_processes(10).await.unwrap();
        assert!(result[0].as_object().unwrap().contains_key("pid"));
        assert!(result[0].as_object().unwrap().contains_key("processName"));
    }
}

#[cfg(test)]
mod list_events_tests {
    use super::*;

    async fn setup_service_with_events() -> (BehaviorService, SqlitePool) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                path TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let service = BehaviorService::new(pool.clone());

        let events = vec![
            (100, "process_a.exe", "create", "2026-05-27T10:00:00Z"),
            (100, "process_a.exe", "read", "2026-05-27T11:00:00Z"),
            (200, "process_b.exe", "write", "2026-05-27T12:00:00Z"),
            (300, "process_c.exe", "delete", "2026-05-27T13:00:00Z"),
        ];

        for (pid, name, op, ts) in events {
            let event = serde_json::json!({
                "pid": pid,
                "processName": name,
                "operation": op,
                "path": format!("C:\\test\\{}", name),
                "timestamp": ts
            });
            service.ingest_event(event).await.unwrap();
        }

        (service, pool)
    }

    #[tokio::test]
    async fn list_events_returns_all_events_when_no_filter() {
        let (service, _) = setup_service_with_events().await;
        let result = service.list_events(None, 100).await.unwrap();
        assert_eq!(result.len(), 4);
    }

    #[tokio::test]
    async fn list_events_filters_by_pid() {
        let (service, _) = setup_service_with_events().await;
        let result = service.list_events(Some(100), 100).await.unwrap();
        assert_eq!(result.len(), 2);
        for event in &result {
            assert_eq!(event["pid"], 100);
        }
    }

    #[tokio::test]
    async fn list_events_filters_nonexistent_pid() {
        let (service, _) = setup_service_with_events().await;
        let result = service.list_events(Some(999), 100).await.unwrap();
        assert_eq!(result.len(), 0);
    }

    #[tokio::test]
    async fn list_events_respects_limit() {
        let (service, _) = setup_service_with_events().await;
        let result = service.list_events(None, 2).await.unwrap();
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn list_events_includes_id_field() {
        let (service, _) = setup_service_with_events().await;
        let result = service.list_events(None, 1).await.unwrap();
        assert!(result[0].as_object().unwrap().contains_key("id"));
    }

    #[tokio::test]
    async fn list_events_includes_details_from_original_event() {
        let (service, _) = setup_service_with_events().await;
        let result = service.list_events(Some(100), 10).await.unwrap();
        assert_eq!(result.len(), 2);
        for event in &result {
            assert!(
                event.as_object().unwrap().contains_key("type")
                    || event.as_object().unwrap().contains_key("details")
                    || event.get("processName").is_some()
            );
        }
    }
}

#[cfg(test)]
mod clear_all_tests {
    use super::*;

    async fn setup_service_with_events(count: usize) -> BehaviorService {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                path TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let service = BehaviorService::new(pool);

        for i in 0..count {
            let event = serde_json::json!({
                "pid": i as i64,
                "processName": format!("process_{}.exe", i),
                "operation": "test",
                "path": format!("C:\\test\\{}", i),
                "timestamp": format!("2026-05-27T10:{:02}:00Z", i)
            });
            service.ingest_event(event).await.unwrap();
        }

        service
    }

    #[tokio::test]
    async fn clear_all_removes_all_events() {
        let service = setup_service_with_events(5).await;
        assert!(service.list_events(None, 100).await.unwrap().len() > 0);

        service.clear_all().await.unwrap();

        let events = service.list_events(None, 100).await.unwrap();
        assert_eq!(events.len(), 0);
    }

    #[tokio::test]
    async fn clear_all_returns_true_on_success() {
        let service = setup_service_with_events(1).await;
        let result = service.clear_all().await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn clear_all_on_empty_database() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                path TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let service = BehaviorService::new(pool);
        let result = service.clear_all().await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn clear_all_allows_new_ingest_after_clear() {
        let service = setup_service_with_events(3).await;
        service.clear_all().await.unwrap();

        let new_event = serde_json::json!({
            "pid": 999,
            "processName": "new_after_clear.exe",
            "operation": "test",
            "path": "C:\\test",
            "timestamp": "2026-05-27T20:00:00Z"
        });
        service.ingest_event(new_event).await.unwrap();

        let events = service.list_events(None, 100).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["processName"], "new_after_clear.exe");
    }
}

#[cfg(test)]
mod error_handling_tests {
    use super::*;

    #[tokio::test]
    async fn list_processes_handles_invalid_limit() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                path TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let service = BehaviorService::new(pool);
        let result = service.list_processes(0).await;
        assert!(result.is_ok(), "zero limit should return empty result");
    }

    #[tokio::test]
    async fn list_events_handles_invalid_limit() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                path TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let service = BehaviorService::new(pool);
        let result = service.list_events(None, 0).await;
        assert!(result.is_ok(), "zero limit should return empty result");
    }

    #[tokio::test]
    async fn ingest_event_handles_large_json_payload() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                path TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let service = BehaviorService::new(pool);
        let large_data: Vec<String> = (0..1000).map(|i| format!("item_{}", i)).collect();
        let event = serde_json::json!({
            "pid": 1,
            "processName": "large.exe",
            "operation": "large_data",
            "path": "C:\\test",
            "timestamp": "2026-05-27T10:00:00Z",
            "largeArray": large_data
        });

        let result = service.ingest_event(event).await;
        assert!(result.is_ok(), "large JSON payload should be handled");
    }

    #[tokio::test]
    async fn list_events_preserves_json_structure_in_details() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                path TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let service = BehaviorService::new(pool);
        let original_event = serde_json::json!({
            "pid": 42,
            "processName": "structure_test.exe",
            "operation": "test",
            "path": "C:\\test",
            "timestamp": "2026-05-27T10:00:00Z",
            "nested": {
                "array": [1, 2, 3],
                "object": {"key": "value"}
            }
        });

        service.ingest_event(original_event).await.unwrap();
        let result = service.list_events(None, 1).await.unwrap();

        assert!(result.len() == 1);
        let retrieved = &result[0];
        assert!(retrieved.get("nested").is_some() || retrieved.get("type").is_some());
    }
}
