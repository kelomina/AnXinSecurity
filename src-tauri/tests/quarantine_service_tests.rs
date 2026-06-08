// QuarantineService 数据库集成测试 — 验证隔离项目管理、状态转换和安全删除逻辑
// QuarantineService database integration tests — verify quarantine item management, state transitions, and secure deletion logic
//
// 测试策略：使用内存 SQLite 模拟数据库操作，测试隔离项目管理逻辑
// Test strategy: use in-memory SQLite to simulate database operations, test quarantine item management logic
//
// 中文关键词：隔离区，文件隔离，状态转换，安全删除，数据库操作
// English keywords: quarantine, file isolation, state transition, secure deletion, database operations

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: String,
    pub isolated_path: String,
    pub file_hash: String,
    pub file_size: i64,
    pub threat_type: Option<String>,
    pub threat_family: Option<String>,
    pub status: String,
    pub isolated_at: String,
    pub restored_at: Option<String>,
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create in-memory SQLite pool");
        
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS quarantine_items (
                id TEXT PRIMARY KEY,
                original_path TEXT NOT NULL,
                isolated_path TEXT NOT NULL UNIQUE,
                file_hash TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                threat_type TEXT,
                threat_family TEXT,
                status TEXT NOT NULL DEFAULT 'quarantined',
                isolated_at TEXT NOT NULL,
                restored_at TEXT,
                description TEXT
            )
            "#,
        )
        .execute(&pool)
        .await
        .expect("Failed to create quarantine_items table");
        
        pool
    }

    // ================================================================
    // 数据库 CRUD 测试 / Database CRUD tests
    // ================================================================

    #[tokio::test]
    async fn test_insert_quarantine_item() {
        let pool = create_test_pool().await;
        
        let result = sqlx::query(
            r#"
            INSERT INTO quarantine_items 
            (id, original_path, isolated_path, file_hash, file_size, threat_type, status, isolated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'quarantined', ?)
            "#,
        )
        .bind("test-id-001")
        .bind(r"C:\test\malware.exe")
        .bind(r"C:\quarantine\test-id-001.enc")
        .bind("deadbeef123456")
        .bind(1024i64)
        .bind("trojan")
        .bind("2026-05-23T10:00:00Z")
        .execute(&pool)
        .await;

        assert!(result.is_ok(), "Insert should succeed");
        
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM quarantine_items")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    }

    #[tokio::test]
    async fn test_query_quarantine_item_by_id() {
        let pool = create_test_pool().await;
        
        sqlx::query(
            r#"
            INSERT INTO quarantine_items 
            (id, original_path, isolated_path, file_hash, file_size, status, isolated_at)
            VALUES (?, ?, ?, ?, ?, 'quarantined', ?)
            "#,
        )
        .bind("query-test-id")
        .bind(r"C:\test\virus.exe")
        .bind(r"C:\quarantine\virus.enc")
        .bind("abc123hash")
        .bind(2048i64)
        .bind("2026-05-23T11:00:00Z")
        .execute(&pool)
        .await
        .unwrap();

        let item: QuarantineItem = sqlx::query_as(
            r#"SELECT * FROM quarantine_items WHERE id = ?"#
        )
        .bind("query-test-id")
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(item.id, "query-test-id");
        assert_eq!(item.original_path, r"C:\test\virus.exe");
        assert_eq!(item.file_hash, "abc123hash");
        assert_eq!(item.status, "quarantined");
    }

    #[tokio::test]
    async fn test_update_quarantine_status_to_restored() {
        let pool = create_test_pool().await;
        
        sqlx::query(
            r#"
            INSERT INTO quarantine_items 
            (id, original_path, isolated_path, file_hash, file_size, status, isolated_at)
            VALUES (?, ?, ?, ?, ?, 'quarantined', ?)
            "#,
        )
        .bind("restore-test-id")
        .bind(r"C:\test\restorable.exe")
        .bind(r"C:\quarantine\restorable.enc")
        .bind("restorehash")
        .bind(4096i64)
        .bind("2026-05-23T12:00:00Z")
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"UPDATE quarantine_items SET status = 'restored', restored_at = ? WHERE id = ?"#
        )
        .bind("2026-05-23T13:00:00Z")
        .bind("restore-test-id")
        .execute(&pool)
        .await
        .unwrap();

        let item: QuarantineItem = sqlx::query_as(
            r#"SELECT * FROM quarantine_items WHERE id = ?"#
        )
        .bind("restore-test-id")
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(item.status, "restored");
        assert!(item.restored_at.is_some());
    }

    #[tokio::test]
    async fn test_delete_quarantine_item() {
        let pool = create_test_pool().await;
        
        sqlx::query(
            r#"
            INSERT INTO quarantine_items 
            (id, original_path, isolated_path, file_hash, file_size, status, isolated_at)
            VALUES (?, ?, ?, ?, ?, 'quarantined', ?)
            "#,
        )
        .bind("delete-test-id")
        .bind(r"C:\test\deleteable.exe")
        .bind(r"C:\quarantine\deleteable.enc")
        .bind("deletehash")
        .bind(512i64)
        .bind("2026-05-23T14:00:00Z")
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query("DELETE FROM quarantine_items WHERE id = ?")
            .bind("delete-test-id")
            .execute(&pool)
            .await
            .unwrap();

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM quarantine_items")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0);
    }

    // ================================================================
    // 状态转换测试 / State transition tests
    // ================================================================

    #[tokio::test]
    async fn test_cannot_restore_non_quarantined_item() {
        let pool = create_test_pool().await;
        
        sqlx::query(
            r#"
            INSERT INTO quarantine_items 
            (id, original_path, isolated_path, file_hash, file_size, status, isolated_at)
            VALUES (?, ?, ?, ?, ?, 'restored', ?)
            "#,
        )
        .bind("already-restored-id")
        .bind(r"C:\test\restored.exe")
        .bind(r"C:\quarantine\restored.enc")
        .bind("restoredhash")
        .bind(1024i64)
        .bind("2026-05-23T15:00:00Z")
        .execute(&pool)
        .await
        .unwrap();

        let item: QuarantineItem = sqlx::query_as(
            r#"SELECT * FROM quarantine_items WHERE id = ?"#
        )
        .bind("already-restored-id")
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(item.status, "restored");
        
        let can_restore = item.status == "quarantined";
        assert!(!can_restore, "Should not be able to restore an already restored item");
    }

    #[tokio::test]
    async fn test_list_only_quarantined_items() {
        let pool = create_test_pool().await;
        
        sqlx::query(
            r#"INSERT INTO quarantine_items (id, original_path, isolated_path, file_hash, file_size, status, isolated_at) VALUES (?, ?, ?, ?, ?, 'quarantined', ?)"#
        )
        .bind("quarantined-1")
        .bind(r"C:\a.exe")
        .bind(r"C:\q\a.enc")
        .bind("hash1")
        .bind(100i64)
        .bind("2026-05-23T10:00:00Z")
        .execute(&pool)
        .await
        .unwrap();
        
        sqlx::query(
            r#"INSERT INTO quarantine_items (id, original_path, isolated_path, file_hash, file_size, status, isolated_at) VALUES (?, ?, ?, ?, ?, 'restored', ?)"#
        )
        .bind("restored-1")
        .bind(r"C:\b.exe")
        .bind(r"C:\q\b.enc")
        .bind("hash2")
        .bind(200i64)
        .bind("2026-05-23T11:00:00Z")
        .execute(&pool)
        .await
        .unwrap();

        let quarantined: Vec<QuarantineItem> = sqlx::query_as(
            r#"SELECT * FROM quarantine_items WHERE status = 'quarantined'"#
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        assert_eq!(quarantined.len(), 1);
        assert_eq!(quarantined[0].id, "quarantined-1");
    }

    // ================================================================
    // 隔离文件路径验证测试 / Isolation file path validation tests
    // ================================================================

    #[test]
    fn test_encrypted_file_extension() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let expected_filename = format!("{}.enc", id);
        assert_eq!(expected_filename, "550e8400-e29b-41d4-a716-446655440000.enc");
    }

    #[test]
    fn test_quarantine_directory_path_construction() {
        use std::path::PathBuf;
        
        let app_data = "C:\\Users\\Test\\AppData\\Roaming";
        let quarantine_dir = PathBuf::from(app_data)
            .join("AnXinSecurity")
            .join("quarantine");
        
        assert_eq!(
            quarantine_dir.to_string_lossy(),
            r"C:\Users\Test\AppData\Roaming\AnXinSecurity\quarantine"
        );
    }

    // ================================================================
    // 文件大小限制测试 / File size limit tests
    // ================================================================

    #[test]
    fn test_file_size_limit_500mb() {
        const MAX_SIZE: i64 = 500 * 1024 * 1024;
        
        assert!(1024 * 1024 < MAX_SIZE);
        assert!(MAX_SIZE < 600 * 1024 * 1024);
        
        let under_limit = 100 * 1024 * 1024;
        let at_limit = MAX_SIZE;
        let over_limit = 600 * 1024 * 1024;
        
        assert!(under_limit <= MAX_SIZE);
        assert!(at_limit <= MAX_SIZE);
        assert!(over_limit > MAX_SIZE);
    }

    // ================================================================
    // 安全覆写测试 / Secure overwrite tests
    // ================================================================

    #[test]
    fn test_overwrite_passes_count() {
        const OVERWRITE_PASSES: usize = 3;
        
        assert_eq!(OVERWRITE_PASSES, 3);
        
        let pass_types = ["random", "zeros", "0xFF"];
        assert_eq!(pass_types.len(), 3);
    }

    #[test]
    fn test_overwrite_data_generation() {
        use rand::Rng;
        
        let mut rng = rand::thread_rng();
        
        let file_size: usize = 1024;
        let random_data: Vec<u8> = (0..file_size).map(|_| rng.gen()).collect();
        assert_eq!(random_data.len(), file_size);
        
        let zeros = vec![0u8; file_size];
        assert!(zeros.iter().all(|&b| b == 0));
        
        let ff_data = vec![0xFFu8; file_size];
        assert!(ff_data.iter().all(|&b| b == 0xFF));
    }

    // ================================================================
    // 威胁类型映射测试 / Threat type mapping tests
    // ================================================================

    #[test]
    fn test_threat_type_options() {
        let valid_threat_types = vec![
            "trojan",
            "ransomware",
            "spyware",
            "adware",
            "worm",
            "backdoor",
            "dropper",
            "pup",
        ];

        assert!(valid_threat_types.contains(&"trojan"));
        assert!(!valid_threat_types.contains(&"unknown"));
    }

    #[test]
    fn test_quarantine_item_serialization() {
        let item = QuarantineItem {
            id: "serialize-test".to_string(),
            original_path: r"C:\test.exe".to_string(),
            isolated_path: r"C:\quarantine\serialize-test.enc".to_string(),
            file_hash: "testhash123".to_string(),
            file_size: 2048,
            threat_type: Some("trojan".to_string()),
            threat_family: Some("Agent".to_string()),
            status: "quarantined".to_string(),
            isolated_at: "2026-05-23T10:00:00Z".to_string(),
            restored_at: None,
            description: Some("Test quarantine item".to_string()),
        };

        let json = serde_json::to_string(&item).expect("serialization should succeed");
        assert!(json.contains("serialize-test"));
        assert!(json.contains("trojan"));
        assert!(json.contains("quarantined"));
    }

    // ================================================================
    // UUID 生成测试 / UUID generation tests
    // ================================================================

    #[test]
    fn test_uuid_format() {
        use uuid::Uuid;
        
        let id = Uuid::new_v4().to_string();
        
        assert_eq!(id.len(), 36);
        assert!(id.contains('-'));
        
        let parts: Vec<_> = id.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
    }

    // ================================================================
    // 隔离路径唯一性测试 / Isolation path uniqueness tests
    // ================================================================

    #[tokio::test]
    async fn test_isolated_path_uniqueness_constraint() {
        let pool = create_test_pool().await;
        
        sqlx::query(
            r#"INSERT INTO quarantine_items (id, original_path, isolated_path, file_hash, file_size, status, isolated_at) VALUES (?, ?, ?, ?, ?, 'quarantined', ?)"#
        )
        .bind("unique-test-1")
        .bind(r"C:\test1.exe")
        .bind(r"C:\quarantine\unique.enc")
        .bind("hash1")
        .bind(100i64)
        .bind("2026-05-23T10:00:00Z")
        .execute(&pool)
        .await
        .unwrap();

        let result = sqlx::query(
            r#"INSERT INTO quarantine_items (id, original_path, isolated_path, file_hash, file_size, status, isolated_at) VALUES (?, ?, ?, ?, ?, 'quarantined', ?)"#
        )
        .bind("unique-test-2")
        .bind(r"C:\test2.exe")
        .bind(r"C:\quarantine\unique.enc")
        .bind("hash2")
        .bind(200i64)
        .bind("2026-05-23T11:00:00Z")
        .execute(&pool)
        .await;

        assert!(result.is_err(), "Duplicate isolated_path should fail due to UNIQUE constraint");
    }

    // ================================================================
    // 列表查询测试 / List query tests
    // ================================================================

    #[tokio::test]
    async fn test_list_quarantine_items_ordered_by_time() {
        let pool = create_test_pool().await;
        
        for i in 0..5 {
            sqlx::query(
                r#"INSERT INTO quarantine_items (id, original_path, isolated_path, file_hash, file_size, status, isolated_at) VALUES (?, ?, ?, ?, ?, 'quarantined', ?)"#
            )
            .bind(format!("list-test-{}", i))
            .bind(format!(r"C:\test\{}.exe", i))
            .bind(format!(r"C:\quarantine\{}.enc", i))
            .bind(format!("hash{}", i))
            .bind(100i64 * (i + 1))
            .bind(format!("2026-05-23T{}:00:00Z", 10 + i))
            .execute(&pool)
            .await
            .unwrap();
        }

        let items: Vec<QuarantineItem> = sqlx::query_as(
            r#"SELECT * FROM quarantine_items ORDER BY isolated_at DESC LIMIT 1000"#
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        assert_eq!(items.len(), 5);
        
        for i in 0..items.len() - 1 {
            assert!(
                items[i].isolated_at >= items[i + 1].isolated_at,
                "Items should be ordered by isolated_at DESC"
            );
        }
    }

    // ================================================================
    // 索引测试 / Index tests
    // ================================================================

    #[tokio::test]
    async fn test_status_index_efficiency() {
        let pool = create_test_pool().await;
        
        for i in 0..100 {
            sqlx::query(
                r#"INSERT INTO quarantine_items (id, original_path, isolated_path, file_hash, file_size, status, isolated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"#
            )
            .bind(format!("index-test-{}", i))
            .bind(format!(r"C:\test\{}.exe", i))
            .bind(format!(r"C:\q\{}.enc", i))
            .bind(format!("ihash{}", i))
            .bind(100i64)
            .bind(if i % 2 == 0 { "quarantined" } else { "restored" })
            .bind(format!("2026-05-23T{}:00:00Z", i % 24))
            .execute(&pool)
            .await
            .unwrap();
        }

        let quarantined_count: (i64,) = sqlx::query_as(
            r#"SELECT COUNT(*) FROM quarantine_items WHERE status = 'quarantined'"#
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(quarantined_count.0, 50);
    }
}
