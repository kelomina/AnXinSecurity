// 隔离区服务 - 处理文件隔离、恢复和删除
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;
use chrono::Utc;
use crate::utils::crypto::{encrypt_data, decrypt_data};
use sha2::{Sha256, Digest};
use rand::Rng;

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

pub struct QuarantineService;

impl QuarantineService {
    pub fn new() -> Self {
        Self
    }

    /// 初始化数据库表
    pub async fn initialize_database(&self, pool: &SqlitePool) -> Result<(), String> {
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
            "#
        )
        .execute(pool)
        .await
        .map_err(|e| format!("Failed to create quarantine table: {}", e))?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_items(status)
            "#
        )
        .execute(pool)
        .await
        .map_err(|e| format!("Failed to create index: {}", e))?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_quarantine_isolated_at ON quarantine_items(isolated_at DESC)
            "#
        )
        .execute(pool)
        .await
        .map_err(|e| format!("Failed to create index: {}", e))?;

        Ok(())
    }

    /// 获取隔离目录路径
    fn get_quarantine_directory() -> PathBuf {
        // 使用应用数据目录下的 quarantine 文件夹
        let app_data = std::env::var("APPDATA")
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(app_data).join("AnXinSecurity").join("quarantine")
    }

    /// 计算文件 SHA-256 哈希
    fn calculate_file_hash(file_path: &PathBuf) -> Result<String, String> {
        let data = fs::read(file_path)
            .map_err(|e| format!("Failed to read file for hashing: {}", e))?;
        
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();
        
        Ok(format!("{:x}", result))
    }

    /// 函数名称：get_encryption_key
    /// 函数作用：
    ///   获取文件加密密钥。优先从环境变量 ANXIN_SECURITY_QUARANTINE_KEY 读取 32 位 hex 字符串，
    ///   若未设置则回退到开发用硬编码密钥（仅适用于非生产环境）。
    /// Purpose:
    ///   Returns the encryption key for file quarantine. Prefers environment variable
    ///   ANXIN_SECURITY_QUARANTINE_KEY (32-char hex string), falls back to dev hardcoded key.
    /// 调用方：isolate_file, restore_file
    /// Called by: isolate_file, restore_file
    /// 安全风险/Security risk: 回退密钥硬编码/fallback key is hardcoded — 不安全/not secure
    ///   生产环境必须设置 ANXIN_SECURITY_QUARANTINE_KEY 环境变量（32位十六进制）。
    ///   Production MUST set ANXIN_SECURITY_QUARANTINE_KEY env var (32 hex chars).
    /// 中文关键词：加密密钥，环境变量，隔离区，AES，密钥管理
    /// English keywords: encryption key, environment variable, quarantine, AES, key management
    fn get_encryption_key() -> [u8; 16] {
        if let Ok(hex_key) = std::env::var("ANXIN_SECURITY_QUARANTINE_KEY") {
            if hex_key.len() == 32 {
                if let Ok(key) = <[u8; 16]>::try_from(
                    (0..16)
                        .map(|i| u8::from_str_radix(&hex_key[i * 2..i * 2 + 2], 16))
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap_or_default()
                ) {
                    return key;
                }
            }
            eprintln!("[QuarantineService] ANXIN_SECURITY_QUARANTINE_KEY 格式无效，需要32位hex字符串，使用回退密钥");
        }
        // 安全警告: 回退密钥仅用于开发/演示 — 生产环境请设置环境变量
        // Security warning: fallback key for dev/demo only — set env var in production
        eprintln!("[QuarantineService] WARNING: 使用硬编码回退加密密钥，生产环境请设置 ANXIN_SECURITY_QUARANTINE_KEY 环境变量");
        *b"AnXinSecurityKey"
    }

    /// 隔离文件：加密并移动到隔离区
    pub async fn isolate_file(
        &self,
        pool: &SqlitePool,
        file_path: &str,
        threat_type: Option<&str>,
    ) -> Result<QuarantineItem, String> {
        let original_path = PathBuf::from(file_path);
        
        // 验证文件存在
        if !original_path.exists() {
            return Err(format!("File not found: {}", file_path));
        }
        
        // 检查文件大小（限制 500MB）
        let metadata = fs::metadata(&original_path)
            .map_err(|e| format!("Failed to get file metadata: {}", e))?;
        let file_size = metadata.len() as i64;
        
        if file_size > 500 * 1024 * 1024 {
            return Err("File size exceeds 500MB limit".to_string());
        }
        
        // 计算文件哈希
        let file_hash = Self::calculate_file_hash(&original_path)?;
        
        // 读取文件内容
        let file_data = fs::read(&original_path)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        
        // 加密文件
        let encryption_key = Self::get_encryption_key();
        let encrypted_data = encrypt_data(&file_data, &encryption_key)?;
        
        // 生成唯一的隔离文件名
        let id = Uuid::new_v4().to_string();
        let isolated_filename = format!("{}.enc", id);
        
        // 确保隔离目录存在
        let quarantine_dir = Self::get_quarantine_directory();
        fs::create_dir_all(&quarantine_dir)
            .map_err(|e| format!("Failed to create quarantine directory: {}", e))?;
        
        // 写入加密文件到隔离区
        let isolated_path = quarantine_dir.join(&isolated_filename);
        fs::write(&isolated_path, &encrypted_data)
            .map_err(|e| format!("Failed to write encrypted file: {}", e))?;
        
        // 安全删除原文件（简单删除，生产环境应多次覆写）
        fs::remove_file(&original_path)
            .map_err(|e| format!("Failed to remove original file: {}", e))?;
        
        // 记录到数据库
        let now = Utc::now().to_rfc3339();
        let isolated_path_str = isolated_path.to_string_lossy().to_string();
        
        sqlx::query(
            r#"
            INSERT INTO quarantine_items 
            (id, original_path, isolated_path, file_hash, file_size, threat_type, status, isolated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'quarantined', ?)
            "#
        )
        .bind(&id)
        .bind(file_path)
        .bind(&isolated_path_str)
        .bind(&file_hash)
        .bind(file_size as i64)
        .bind(threat_type)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| format!("Failed to save quarantine record: {}", e))?;
        
        Ok(QuarantineItem {
            id,
            original_path: file_path.to_string(),
            isolated_path: isolated_path_str,
            file_hash,
            file_size,
            threat_type: threat_type.map(|s| s.to_string()),
            threat_family: None,
            status: "quarantined".to_string(),
            isolated_at: now,
            restored_at: None,
            description: None,
        })
    }

    /// 恢复文件：解密并恢复到原位置
    pub async fn restore_file(&self, pool: &SqlitePool, id: &str) -> Result<bool, String> {
        // 查询隔离记录
        let record: Option<(String, String, String, i64, String)> = sqlx::query_as(
            r#"
            SELECT id, original_path, isolated_path, file_size, status
            FROM quarantine_items
            WHERE id = ?
            "#
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("Failed to query quarantine record: {}", e))?;
        
        let (record_id, original_path, isolated_path, _file_size, status) = 
            record.ok_or_else(|| format!("Quarantine record not found: {}", id))?;
        
        // 检查状态
        if status != "quarantined" {
            return Err(format!("File is not in quarantined state: {}", status));
        }
        
        // 读取加密文件
        let encrypted_data = fs::read(&isolated_path)
            .map_err(|e| format!("Failed to read encrypted file: {}", e))?;
        
        // 解密文件
        let encryption_key = Self::get_encryption_key();
        let decrypted_data = decrypt_data(&encrypted_data, &encryption_key)?;
        
        // 确保原文件的父目录存在
        let original_path_buf = PathBuf::from(&original_path);
        if let Some(parent) = original_path_buf.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create parent directory: {}", e))?;
        }
        
        // 写入解密后的文件到原位置
        fs::write(&original_path_buf, &decrypted_data)
            .map_err(|e| format!("Failed to write restored file: {}", e))?;
        
        // 更新数据库状态
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            r#"
            UPDATE quarantine_items
            SET status = 'restored', restored_at = ?
            WHERE id = ?
            "#
        )
        .bind(&now)
        .bind(&record_id)
        .execute(pool)
        .await
        .map_err(|e| format!("Failed to update quarantine status: {}", e))?;
        
        // 可选：删除隔离区的加密文件（保留以便审计）
        // fs::remove_file(&isolated_path).ok();
        
        Ok(true)
    }

    /// 函数名称：delete_quarantine
    /// 函数作用：
    ///   安全擦除并永久删除隔离区中的文件。执行三次覆写（随机数据→0x00→0xFF）后删除物理文件，
    ///   并从数据库中移除记录。此操作不可撤销。
    /// Purpose:
    ///   Securely wipes and permanently deletes a quarantined file.
    ///   Performs three-pass overwrite (random → zeros → 0xFF) before physical deletion,
    ///   then removes the database record. This operation is irreversible.
    /// 调用方：commands::quarantine::delete_quarantine
    /// Called by: commands::quarantine::delete_quarantine
    /// 中文关键词：安全擦除，覆写，删除，隔离区，不可逆，随机覆写，全零覆写
    /// English keywords: secure wipe, overwrite, delete, quarantine, irreversible, random overwrite, zero overwrite
    pub async fn delete_quarantine(&self, pool: &SqlitePool, id: &str) -> Result<bool, String> {
        // 查询隔离记录
        let record: Option<(String, String)> = sqlx::query_as(
            r#"
            SELECT id, isolated_path
            FROM quarantine_items
            WHERE id = ?
            "#
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("Failed to query quarantine record: {}", e))?;
        
        let (record_id, isolated_path) = 
            record.ok_or_else(|| format!("Quarantine record not found: {}", id))?;
        
        // 三次覆写：随机数据、0x00、0xFF
        if PathBuf::from(&isolated_path).exists() {
            let file_size = fs::metadata(&isolated_path)
                .map_err(|e| format!("Failed to get file metadata: {}", e))?
                .len() as usize;

            // 第一次覆写：随机数据
            let mut rng = rand::thread_rng();
            let random_data: Vec<u8> = (0..file_size).map(|_| rng.gen()).collect();
            fs::write(&isolated_path, &random_data)
                .map_err(|e| format!("Failed to overwrite file with random data: {}", e))?;

            // 第二次覆写：全零 (0x00)
            let zero_data = vec![0u8; file_size];
            fs::write(&isolated_path, &zero_data)
                .map_err(|e| format!("Failed to overwrite file with zeros: {}", e))?;

            // 第三次覆写：全一 (0xFF)
            let ff_data = vec![0xFFu8; file_size];
            fs::write(&isolated_path, &ff_data)
                .map_err(|e| format!("Failed to overwrite file with 0xFF: {}", e))?;
            
            // 删除文件
            fs::remove_file(&isolated_path)
                .map_err(|e| format!("Failed to delete quarantined file: {}", e))?;
        }
        
        // 从数据库中删除记录
        sqlx::query(
            r#"
            DELETE FROM quarantine_items
            WHERE id = ?
            "#
        )
        .bind(&record_id)
        .execute(pool)
        .await
        .map_err(|e| format!("Failed to delete quarantine record: {}", e))?;
        
        Ok(true)
    }

    /// 列出所有隔离项目
    pub async fn list_quarantine_items(&self, pool: &SqlitePool) -> Result<Vec<QuarantineItem>, String> {
        let items: Vec<QuarantineItem> = sqlx::query_as(
            r#"
            SELECT id, original_path, isolated_path, file_hash, file_size,
                   threat_type, threat_family, status, isolated_at, restored_at, description
            FROM quarantine_items
            ORDER BY isolated_at DESC
            LIMIT 1000
            "#
        )
        .fetch_all(pool)
        .await
        .map_err(|e| format!("Failed to query quarantine items: {}", e))?;
        
        Ok(items)
    }
}
