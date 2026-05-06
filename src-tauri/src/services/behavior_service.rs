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
}
