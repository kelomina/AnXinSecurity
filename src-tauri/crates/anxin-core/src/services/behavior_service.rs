use sqlx::{Row, SqlitePool};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct BehaviorService {
    pool: Arc<Mutex<SqlitePool>>,
}

impl BehaviorService {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool: Arc::new(Mutex::new(pool)),
        }
    }

    /// 建 process_lifecycle 表（§4.7，幂等）。
    ///  Creates the process_lifecycle table (§4.7, idempotent).
    ///
    /// 调用方：main.rs background_init 与 windows_service.rs 的建库流程，
    /// 两条路径共用同一个 APPDATA 行为库文件，缺一即服务模式查询报 no such table。
    /// Called by: main.rs background_init and windows_service.rs database setup;
    /// both paths share one APPDATA behavior DB, so missing either one breaks
    /// service-mode queries.
    pub async fn initialize_lifecycle_table(pool: &SqlitePool) -> Result<(), String> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS process_lifecycle (
                id TEXT PRIMARY KEY,
                pid INTEGER,
                create_time TEXT,
                exit_time TEXT,
                duration_ms INTEGER,
                parent_pid INTEGER,
                session_id INTEGER,
                process_path TEXT,
                command_line TEXT,
                cwd TEXT,
                user_sid TEXT,
                elevated INTEGER,
                file_hash TEXT,
                signature_status TEXT,
                exit_status INTEGER,
                is_orphan INTEGER,
                subsystem_type TEXT,
                details TEXT
            )
            "#,
        )
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_process_lifecycle_pid ON process_lifecycle(pid)",
        )
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_process_lifecycle_create_time ON process_lifecycle(create_time)",
        )
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;
        // events 表由调用方在建库流程中创建（可能在 initialize 之前或之后）；
        // 索引创建失败只降级（不影响表本身），不阻断初始化。
        //  The events table is created by the caller during DB setup (before or after
        //  this call); a failed index creation degrades only (the table itself is fine).
        let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            .execute(pool)
            .await;
        Ok(())
    }

    pub async fn ingest_event(&self, event: serde_json::Value) -> Result<(), String> {
        let pool = self.pool.lock().await;

        // 假设事件结构包含 pid, event_type, timestamp, details 等字段
        let id = uuid::Uuid::new_v4().to_string();
        let pid = event.get("pid").and_then(|v| v.as_i64()).unwrap_or(0);
        let process_name = event
            .get("processName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let operation = event
            .get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let path = event
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let timestamp = event
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let details = serde_json::to_string(&event).unwrap_or_default();

        sqlx::query(
            "INSERT OR IGNORE INTO events (id, pid, process_name, operation, path, timestamp, details) VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(id)
        .bind(pid)
        .bind(process_name)
        .bind(operation)
        .bind(path)
        .bind(timestamp)
        .bind(details)
        .execute(&*pool)
        .await
        .map_err(|e| e.to_string())?;

        Ok(())
    }

    /// 批量写入行为事件（§4.3 性能优化：行为事件量大时避免逐条 INSERT +
    /// 逐条任务调度，攒批后单事务写入，SQLite 吞吐提升一个数量级）。
    ///  Batch-ingests behavior events: for high event rates this avoids per-event
    ///  INSERT + per-event task scheduling; a single transaction per batch raises
    ///  SQLite throughput by an order of magnitude.
    ///
    /// 空批次直接返回 Ok。任一事件失败不会中断整批（逐条继续），
    /// 返回失败条数供调用方观测（不丢整批）。
    ///  An empty batch returns Ok immediately. A failing event does not abort the
    ///  rest of the batch; the failed count is returned for observability.
    pub async fn ingest_events_batch(
        &self,
        events: &[serde_json::Value],
    ) -> Result<usize, String> {
        if events.is_empty() {
            return Ok(0);
        }
        let pool = self.pool.lock().await;

        let mut tx = pool
            .begin()
            .await
            .map_err(|e| format!("failed to begin transaction: {}", e))?;

        let mut failed = 0usize;
        for event in events {
            let id = uuid::Uuid::new_v4().to_string();
            let pid = event.get("pid").and_then(|v| v.as_i64()).unwrap_or(0);
            let process_name = event
                .get("processName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let operation = event
                .get("operation")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let path = event
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let timestamp = event
                .get("timestamp")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let details = serde_json::to_string(event).unwrap_or_default();

            let result = sqlx::query(
                "INSERT OR IGNORE INTO events (id, pid, process_name, operation, path, timestamp, details) VALUES (?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(id)
            .bind(pid)
            .bind(process_name)
            .bind(operation)
            .bind(path)
            .bind(timestamp)
            .bind(details)
            .execute(&mut *tx)
            .await;

            if let Err(e) = result {
                failed += 1;
                if failed <= 3 {
                    eprintln!("[Behavior] batch ingest event failed: {}", e);
                }
            }
        }

        tx.commit()
            .await
            .map_err(|e| format!("failed to commit batch: {}", e))?;

        Ok(failed)
    }

    /// 写入一条进程生命周期记录（§4.7 process_lifecycle 表）。
    ///  Writes one process lifecycle record (§4.7 process_lifecycle table).
    ///
    /// 语义：CREATE 事件插入一行；EXIT 事件按 pid 更新同一行的
    /// exit_time / duration_ms / exit_status。事件载荷由 ProcessLifecycleService
    /// 构造，字段与表结构一一对应（缺失字段按 NULL 处理）。
    /// Semantics: a CREATE event inserts a row; an EXIT event updates the same
    /// row by pid (exit_time / duration_ms / exit_status). The payload is built
    /// by ProcessLifecycleService with one field per table column (missing fields
    /// are stored as NULL).
    ///
    /// 中文关键词：进程生命周期，入库，CREATE/EXIT 关联
    /// English keywords: process lifecycle, persistence, CREATE/EXIT pairing
    pub async fn ingest_lifecycle(&self, record: serde_json::Value) -> Result<(), String> {
        let pool = self.pool.lock().await;
        let id = uuid::Uuid::new_v4().to_string();
        let pid = record.get("pid").and_then(|v| v.as_i64()).unwrap_or(0);
        let exit_time = record.get("exitTime").and_then(|v| v.as_str());
        let duration_ms = record.get("durationMs").and_then(|v| v.as_i64());
        let exit_status = record.get("exitStatus").and_then(|v| v.as_i64());

        if exit_time.is_some() || duration_ms.is_some() || exit_status.is_some() {
            // EXIT 更新：按 pid 更新退出时间/时长/退出码（CREATE 必须已存在）
            sqlx::query(
                "UPDATE process_lifecycle SET exit_time = COALESCE(?, exit_time), \
                 duration_ms = COALESCE(?, duration_ms), exit_status = COALESCE(?, exit_status) \
                 WHERE pid = ? AND exit_time IS NULL",
            )
            .bind(exit_time)
            .bind(duration_ms)
            .bind(exit_status)
            .bind(pid)
            .execute(&*pool)
            .await
            .map_err(|e| e.to_string())?;
            return Ok(());
        }

        // CREATE 插入
        let parent_pid = record.get("parentPid").and_then(|v| v.as_i64());
        let session_id = record.get("sessionId").and_then(|v| v.as_i64());
        let process_path = record.get("processPath").and_then(|v| v.as_str());
        let command_line = record.get("commandLine").and_then(|v| v.as_str());
        let subsystem_type = record.get("subsystemType").and_then(|v| v.as_str());
        let elevated = record.get("elevated").and_then(|v| v.as_i64());
        let create_time = record.get("createTime").and_then(|v| v.as_str());
        let details = serde_json::to_string(&record).unwrap_or_default();

        sqlx::query(
            "INSERT OR IGNORE INTO process_lifecycle \
             (id, pid, create_time, parent_pid, session_id, process_path, command_line, \
              subsystem_type, elevated, details) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(pid)
        .bind(create_time)
        .bind(parent_pid)
        .bind(session_id)
        .bind(process_path)
        .bind(command_line)
        .bind(subsystem_type)
        .bind(elevated)
        .bind(details)
        .execute(&*pool)
        .await
        .map_err(|e| e.to_string())?;

        Ok(())
    }

    /// 查询进程生命周期记录（§4.7）。
    ///  Queries process lifecycle records (§4.7).
    pub async fn list_lifecycle(&self, limit: u64) -> Result<Vec<serde_json::Value>, String> {
        let pool = self.pool.lock().await;
        let rows = sqlx::query(
            "SELECT * FROM process_lifecycle ORDER BY create_time DESC LIMIT ?",
        )
        .bind(limit as i64)
        .fetch_all(&*pool)
        .await
        .map_err(|e| e.to_string())?;

        let result: Vec<serde_json::Value> = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "pid": row.try_get::<i64, _>("pid").unwrap_or(0),
                    "createTime": row.try_get::<String, _>("create_time").unwrap_or_default(),
                    "exitTime": row.try_get::<Option<String>, _>("exit_time").ok().flatten().unwrap_or_default(),
                    "durationMs": row.try_get::<Option<i64>, _>("duration_ms").ok().flatten().unwrap_or(0),
                    "parentPid": row.try_get::<Option<i64>, _>("parent_pid").ok().flatten().unwrap_or(0),
                    "sessionId": row.try_get::<Option<i64>, _>("session_id").ok().flatten().unwrap_or(0),
                    "processPath": row.try_get::<Option<String>, _>("process_path").ok().flatten().unwrap_or_default(),
                    "commandLine": row.try_get::<Option<String>, _>("command_line").ok().flatten().unwrap_or_default(),
                    "subsystemType": row.try_get::<Option<String>, _>("subsystem_type").ok().flatten().unwrap_or("Unknown".to_string()),
                    "elevated": row.try_get::<Option<i64>, _>("elevated").ok().flatten().unwrap_or(0),
                    "exitStatus": row.try_get::<Option<i64>, _>("exit_status").ok().flatten().unwrap_or(0),
                })
            })
            .collect();

        Ok(result)
    }

    pub async fn list_processes(&self, limit: u64) -> Result<Vec<serde_json::Value>, String> {
        let pool = self.pool.lock().await;

        let rows = sqlx::query(
            "SELECT DISTINCT pid, process_name FROM events ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(limit as i64)
        .fetch_all(&*pool)
        .await
        .map_err(|e| e.to_string())?;

        let result: Vec<serde_json::Value> = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "pid": row.get::<i64, _>("pid"),
                    "processName": row.get::<String, _>("process_name"),
                })
            })
            .collect();

        Ok(result)
    }

    pub async fn list_events(
        &self,
        pid: Option<u64>,
        limit: u64,
    ) -> Result<Vec<serde_json::Value>, String> {
        let pool = self.pool.lock().await;

        let rows = if let Some(p) = pid {
            sqlx::query("SELECT * FROM events WHERE pid = ? ORDER BY timestamp DESC LIMIT ?")
                .bind(p as i64)
                .bind(limit as i64)
                .fetch_all(&*pool)
                .await
                .map_err(|e| e.to_string())?
        } else {
            sqlx::query("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?")
                .bind(limit as i64)
                .fetch_all(&*pool)
                .await
                .map_err(|e| e.to_string())?
        };

        let result: Vec<serde_json::Value> = rows
            .iter()
            .map(|row| {
                let details: String = row.get("details");
                let mut event: serde_json::Value =
                    serde_json::from_str(&details).unwrap_or(serde_json::json!({}));
                event["id"] = serde_json::Value::String(row.get::<String, _>("id"));
                event
            })
            .collect();

        Ok(result)
    }

    pub async fn clear_all(&self) -> Result<bool, String> {
        let pool = self.pool.lock().await;

        sqlx::query("DELETE FROM events")
            .execute(&*pool)
            .await
            .map_err(|e| e.to_string())?;

        Ok(true)
    }

    /// 按保留期清理行为事件（防 DB 无限占盘）。
    ///  Prunes behavior events older than the retention window (caps DB growth).
    ///
    /// `before_rfc3339` 是清理边界（RFC3339 字符串）：`timestamp < before` 的
    /// events 行与 `create_time < before` 的 process_lifecycle 行被删除。
    /// 返回 (删除的 events 行数, 删除的 lifecycle 行数)。
    ///  Before-boundary RFC3339: rows with `timestamp < before` (events) and
    ///  `create_time < before` (process_lifecycle) are removed. Returns the
    ///  (events_deleted, lifecycle_deleted) counts.
    pub async fn prune_older_than(&self, before_rfc3339: &str) -> Result<(u64, u64), String> {
        let pool = self.pool.lock().await;

        let events_deleted = sqlx::query("DELETE FROM events WHERE timestamp < ?")
            .bind(before_rfc3339)
            .execute(&*pool)
            .await
            .map_err(|e| e.to_string())?
            .rows_affected();

        let lifecycle_deleted = sqlx::query("DELETE FROM process_lifecycle WHERE create_time < ?")
            .bind(before_rfc3339)
            .execute(&*pool)
            .await
            .map_err(|e| e.to_string())?
            .rows_affected();

        if events_deleted > 0 || lifecycle_deleted > 0 {
            eprintln!(
                "[Behavior] pruned {} events / {} lifecycle rows (before {})",
                events_deleted, lifecycle_deleted, before_rfc3339
            );
        }

        Ok((events_deleted, lifecycle_deleted))
    }

    /// 当前行为库文件大小（字节，逻辑页 × 页大小）。
    ///  Current behavior-DB size in bytes (page_count × page_size).
    pub async fn db_size_bytes(&self) -> Result<u64, String> {
        let pool = self.pool.lock().await;
        let page_count: i64 = sqlx::query_scalar("PRAGMA page_count")
            .fetch_one(&*pool)
            .await
            .map_err(|e| e.to_string())?;
        let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
            .fetch_one(&*pool)
            .await
            .map_err(|e| e.to_string())?;
        Ok((page_count.max(0) as u64).saturating_mul(page_size.max(0) as u64))
    }

    /// 按文件大小上限清理（防事件量大的用户一天刷爆占盘）。
    ///  Prunes by a file-size cap: when the DB exceeds `max_bytes`, the oldest
    ///  rows are deleted (and the file VACUUMed) until size drops below ~90%.
    ///
    /// 策略：保留期内数据也删——容量上限优先于保留窗口（1GB 封顶是硬约束）。
    /// 循环推进时间边界（每次删掉剩余时间跨度最早的 25%），最多 8 轮；
    /// 最后 VACUUM 回收文件空洞。返回 (删除的 events, lifecycle, 最终大小)。
    ///  Policy: the size cap overrides the retention window (1GiB is a hard bound).
    ///  The boundary is pushed forward iteratively (25% of the remaining span per
    ///  round, at most 8 rounds), then VACUUM reclaims the file. Returns
    ///  (events_deleted, lifecycle_deleted, final_size_bytes).
    pub async fn prune_by_size_limit(&self, max_bytes: u64) -> Result<(u64, u64, u64), String> {
        if max_bytes == 0 {
            return Err("max_db_bytes must be > 0".to_string());
        }

        let mut events_total = 0u64;
        let mut lifecycle_total = 0u64;

        // 先做保留期清理（通常已由定时任务做过，这里兜底）
        let now = chrono::Utc::now();
        let retention_before = now - chrono::Duration::days(7);
        let (e, l) = self
            .prune_older_than(
                &retention_before.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            )
            .await?;
        events_total += e;
        lifecycle_total += l;

        // 容量超限时逐轮推进时间边界删除最老数据
        for _ in 0..8 {
            let size = self.db_size_bytes().await?;
            if size <= max_bytes * 9 / 10 {
                break;
            }
            let (e, l, progressed) = self.prune_oldest_quarter().await?;
            events_total += e;
            lifecycle_total += l;
            if !progressed {
                break; // 无可删数据，停止
            }
        }

        // VACUUM 回收文件空洞（删除行不自动缩小文件）
        //  VACUUM reclaims the file (row deletes do not shrink it by themselves).
        {
            let pool = self.pool.lock().await;
            sqlx::query("VACUUM")
                .execute(&*pool)
                .await
                .map_err(|e| e.to_string())?;
        }

        let final_size = self.db_size_bytes().await?;
        if events_total > 0 || lifecycle_total > 0 {
            eprintln!(
                "[Behavior] size-limit prune: {} events / {} lifecycle deleted, db {} -> {} bytes (cap {})",
                events_total, lifecycle_total, final_size, final_size, max_bytes
            );
        }
        Ok((events_total, lifecycle_total, final_size))
    }

    /// 删除剩余数据中时间跨度最早 25% 的行（按 timestamp/create_time 排序取最小值推进）。
    ///  Deletes the oldest quarter of the remaining time span.
    async fn prune_oldest_quarter(&self) -> Result<(u64, u64, bool), String> {
        let pool = self.pool.lock().await;

        // 找出当前时间范围（字符串比较在统一 RFC3339 格式下等价于时间序）
        let min_ts: Option<String> = sqlx::query_scalar("SELECT MIN(timestamp) FROM events")
            .fetch_optional(&*pool)
            .await
            .map_err(|e| e.to_string())?;
        let max_ts: Option<String> = sqlx::query_scalar("SELECT MAX(timestamp) FROM events")
            .fetch_optional(&*pool)
            .await
            .map_err(|e| e.to_string())?;

        let (Some(min), Some(max)) = (min_ts, max_ts) else {
            return Ok((0, 0, false));
        };
        if min >= max {
            return Ok((0, 0, false));
        }

        // 解析 RFC3339 → 时间戳毫秒，推进 25% 跨度
        let parse = |s: &str| -> Option<i64> {
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.timestamp_millis())
        };
        let (Some(min_ms), Some(max_ms)) = (parse(&min), parse(&max)) else {
            return Ok((0, 0, false));
        };
        let span = (max_ms - min_ms) / 4;
        if span <= 0 {
            return Ok((0, 0, false));
        }
        let boundary_ms = min_ms + span;
        let boundary = match chrono::DateTime::from_timestamp_millis(boundary_ms) {
            Some(dt) => dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            None => return Ok((0, 0, false)),
        };

        let events_deleted = sqlx::query("DELETE FROM events WHERE timestamp <= ?")
            .bind(&boundary)
            .execute(&*pool)
            .await
            .map_err(|e| e.to_string())?
            .rows_affected();
        let lifecycle_deleted = sqlx::query("DELETE FROM process_lifecycle WHERE create_time <= ?")
            .bind(&boundary)
            .execute(&*pool)
            .await
            .map_err(|e| e.to_string())?
            .rows_affected();

        Ok((events_deleted, lifecycle_deleted, events_deleted + lifecycle_deleted > 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 建内存库 + process_lifecycle/events 表（与生产建库路径一致）。
    /// 注意：SQLite `:memory:` 每个连接独立，必须限单连接保证建表/读写同库。
    async fn test_pool() -> SqlitePool {
        use sqlx::sqlite::SqliteConnectOptions;
        let opts = SqliteConnectOptions::new()
            .filename(":memory:")
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        // 与生产建库顺序一致：先 events 表，再 lifecycle 表（含索引）
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS events (\
             id TEXT PRIMARY KEY, pid INTEGER, process_name TEXT, operation TEXT, \
             path TEXT, timestamp TEXT, details TEXT)",
        )
        .execute(&pool)
        .await
        .unwrap();
        BehaviorService::initialize_lifecycle_table(&pool)
            .await
            .unwrap();
        pool
    }

    /// §4.7：CREATE 插入 → EXIT 更新同一行。
    #[tokio::test]
    async fn ingest_lifecycle_create_then_exit_pairs_by_pid() {
        let pool = test_pool().await;
        let svc = BehaviorService::new(pool);

        svc.ingest_lifecycle(serde_json::json!({
            "pid": 4242,
            "parentPid": 1,
            "sessionId": 2,
            "createTime": "2026-08-14T10:00:00.000Z",
            "processPath": "C:\\Windows\\System32\\cmd.exe",
            "subsystemType": "Win32",
            "elevated": 0,
        }))
        .await
        .expect("create insert should succeed");

        svc.ingest_lifecycle(serde_json::json!({
            "pid": 4242,
            "exitTime": "2026-08-14T10:00:01.000Z",
            "exitStatus": 0,
        }))
        .await
        .expect("exit update should succeed");

        let rows = svc.list_lifecycle(10).await.unwrap();
        assert_eq!(rows.len(), 1, "one row per pid");
        let row = &rows[0];
        assert_eq!(row["pid"], 4242);
        assert_eq!(row["processPath"], "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(row["subsystemType"], "Win32");
        assert!(
            !row["exitTime"].as_str().unwrap_or("").is_empty(),
            "exit update must fill exit_time"
        );
        assert_eq!(row["exitStatus"], 0);
    }

    /// §4.7：EXIT 到达时 CREATE 尚未插入（队列乱序）不报错，也不产生孤儿行。
    #[tokio::test]
    async fn ingest_lifecycle_exit_without_create_is_noop() {
        let pool = test_pool().await;
        let svc = BehaviorService::new(pool);

        svc.ingest_lifecycle(serde_json::json!({
            "pid": 9999,
            "exitTime": "2026-08-14T10:00:01.000Z",
            "exitStatus": 1,
        }))
        .await
        .expect("exit without create should be a no-op, not an error");

        let rows = svc.list_lifecycle(10).await.unwrap();
        assert!(rows.is_empty(), "no row for unpaired exit");
    }

    /// §4.7：event ingest 仍工作（行为事件表）。
    #[tokio::test]
    async fn ingest_event_writes_events_table() {
        let pool = test_pool().await;
        let svc = BehaviorService::new(pool);

        svc.ingest_event(serde_json::json!({
            "pid": 123,
            "processName": "x.exe",
            "operation": "File:Write",
            "path": "C:\\t.txt",
            "timestamp": "2026-08-14T10:00:00.000Z",
        }))
        .await
        .expect("event ingest should succeed");

        let events = svc.list_events(None, 10).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["pid"], 123);
    }

    /// §4.3 性能优化：批量入库单事务写入多条，空批次为 no-op。
    #[tokio::test]
    async fn ingest_events_batch_writes_all_in_one_transaction() {
        let pool = test_pool().await;
        let svc = BehaviorService::new(pool);

        let events: Vec<serde_json::Value> = (0..50)
            .map(|i| {
                serde_json::json!({
                    "pid": 1000 + i,
                    "processName": format!("p{}.exe", i),
                    "operation": "File:Create",
                    "path": format!("C:\\tmp\\f{}.tmp", i),
                    "timestamp": "2026-08-14T10:00:00.000Z",
                })
            })
            .collect();

        let failed = svc
            .ingest_events_batch(&events)
            .await
            .expect("batch ingest should succeed");
        assert_eq!(failed, 0);

        let listed = svc.list_events(None, 100).await.unwrap();
        assert_eq!(listed.len(), 50);
    }

    /// 空批次直接返回，不触碰数据库。
    #[tokio::test]
    async fn ingest_events_batch_empty_is_noop() {
        let pool = test_pool().await;
        let svc = BehaviorService::new(pool);
        let failed = svc
            .ingest_events_batch(&[])
            .await
            .expect("empty batch should be a no-op");
        assert_eq!(failed, 0);
        let listed = svc.list_events(None, 10).await.unwrap();
        assert!(listed.is_empty());
    }

    /// 保留期清理：早于边界的 events/lifecycle 行被删除，新行保留。
    #[tokio::test]
    async fn prune_removes_only_rows_older_than_boundary() {
        let pool = test_pool().await;
        let svc = BehaviorService::new(pool);

        // 两条事件：7 天前 和 1 天前
        svc.ingest_event(serde_json::json!({
            "pid": 1, "operation": "File:Create", "path": "old",
            "timestamp": "2026-08-01T00:00:00.000Z",
        }))
        .await
        .unwrap();
        svc.ingest_event(serde_json::json!({
            "pid": 2, "operation": "File:Create", "path": "new",
            "timestamp": "2026-08-13T00:00:00.000Z",
        }))
        .await
        .unwrap();

        // 一条 lifecycle：7 天前创建
        svc.ingest_lifecycle(serde_json::json!({
            "pid": 3,
            "createTime": "2026-08-01T00:00:00.000Z",
            "processPath": "old.exe",
        }))
        .await
        .unwrap();

        // 边界 2026-08-07：删除 8 月 1 日的
        let (e, l) = svc
            .prune_older_than("2026-08-07T00:00:00.000Z")
            .await
            .unwrap();
        assert_eq!(e, 1, "old event should be pruned");
        assert_eq!(l, 1, "old lifecycle row should be pruned");

        let events = svc.list_events(None, 10).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["pid"], 2);

        let life = svc.list_lifecycle(10).await.unwrap();
        assert!(life.is_empty(), "old lifecycle row gone");
    }

    /// db_size_bytes 返回正数（内存库也可查询）。
    #[tokio::test]
    async fn db_size_bytes_returns_positive() {
        let pool = test_pool().await;
        let svc = BehaviorService::new(pool);
        let size = svc.db_size_bytes().await.unwrap();
        assert!(size > 0, "db size should be positive, got {}", size);
    }

    /// 容量清理：极小的 max_bytes 会删除最老数据并缩小 DB。
    #[tokio::test]
    async fn prune_by_size_limit_deletes_oldest_rows() {
        let pool = test_pool().await;
        let svc = BehaviorService::new(pool);

        // 写入 30 条不同时间戳的事件（从 5 天前到今天）
        for i in 0..30 {
            let day = 5 - (i / 6) as i64; // 0..5 天前
            let ts = format!("2026-08-{:02}T10:00:00.{:03}Z", 14 - day, i);
            svc.ingest_event(serde_json::json!({
                "pid": 1000 + i, "operation": "File:Create",
                "path": format!("f{}.tmp", i), "timestamp": ts,
            }))
            .await
            .unwrap();
        }

        // 用 1 字节上限强制清理（会删到无可删为止；VACUUM 在内存库上同样生效）
        let (e, _, final_size) = svc.prune_by_size_limit(1).await.unwrap();
        assert!(e > 0, "size-limit prune should delete rows, got {}", e);
        assert_eq!(final_size, svc.db_size_bytes().await.unwrap());
        let remaining = svc.list_events(None, 100).await.unwrap();
        assert!(remaining.len() < 30, "most rows should be pruned, left {}", remaining.len());
    }
}
