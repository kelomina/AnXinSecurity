// 隔离区服务 - 处理文件隔离、恢复和删除
use crate::utils::crypto::{
    decrypt_data, encrypt_data, protect_data_with_dpapi, unprotect_data_with_dpapi,
};
use chrono::Utc;
use rand::Rng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

const QUARANTINE_KEY_FILE_NAME: &str = "quarantine_key.bin";
const QUARANTINE_KEY_ENTROPY: &[u8] = b"AnXinSecurity.QuarantineKey.v1";

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
            "#,
        )
        .execute(pool)
        .await
        .map_err(|e| format!("Failed to create quarantine table: {}", e))?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_items(status)
            "#,
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
        let app_data = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(app_data)
            .join("AnXinSecurity")
            .join("quarantine")
    }

    /// 函数名称：get_runtime_directory
    /// 函数作用：获取隔离区运行时密钥目录，默认位于 APPDATA 下。
    /// Purpose: Gets the quarantine runtime key directory, defaulting to APPDATA.
    /// 调用方：quarantine_key_path。
    /// Called by: quarantine_key_path.
    /// 中文关键词：隔离区密钥，APPDATA，运行时目录
    /// English keywords: quarantine key, APPDATA, runtime directory
    fn get_runtime_directory() -> PathBuf {
        std::env::var("APPDATA")
            .map(|app_data| {
                PathBuf::from(app_data)
                    .join("AnXinSecurity")
                    .join("runtime")
            })
            .unwrap_or_else(|_| PathBuf::from("data").join("runtime"))
    }

    /// 函数名称：quarantine_key_path
    /// 函数作用：返回 DPAPI 加密后的隔离区 AES 密钥文件路径。
    /// Purpose: Returns the file path for the DPAPI-protected quarantine AES key.
    /// 调用方：load_or_create_dpapi_encryption_key。
    /// Called by: load_or_create_dpapi_encryption_key.
    /// 中文关键词：隔离区密钥，DPAPI，密钥文件
    /// English keywords: quarantine key, DPAPI, key file
    fn quarantine_key_path() -> PathBuf {
        Self::get_runtime_directory().join(QUARANTINE_KEY_FILE_NAME)
    }

    /// 计算文件 SHA-256 哈希
    fn calculate_file_hash(file_path: &PathBuf) -> Result<String, String> {
        let data =
            fs::read(file_path).map_err(|e| format!("Failed to read file for hashing: {}", e))?;

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();

        Ok(format!("{:x}", result))
    }

    /// 函数名称：get_encryption_key
    /// 函数作用：
    ///   获取文件加密密钥。优先从环境变量 ANXIN_SECURITY_QUARANTINE_KEY 读取 32 位 hex 字符串，
    ///   若未设置则读取或创建 DPAPI 保护的本机运行时密钥。
    /// Purpose:
    ///   Returns the encryption key for file quarantine. Prefers environment variable
    ///   ANXIN_SECURITY_QUARANTINE_KEY (32-char hex string), otherwise reads or creates a DPAPI-protected local runtime key.
    /// 调用方：isolate_file, restore_file
    /// Called by: isolate_file, restore_file
    /// 错误处理：环境变量格式错误或 DPAPI 密钥文件不可读时返回 String，不使用内置静态密钥。
    /// Error handling: Invalid env var or unreadable DPAPI key file returns String; no built-in static key is used.
    /// 中文关键词：加密密钥，环境变量，隔离区，AES，密钥管理，DPAPI
    /// English keywords: encryption key, environment variable, quarantine, AES, key management, DPAPI
    fn get_encryption_key() -> Result<[u8; 16], String> {
        if let Ok(hex_key) = std::env::var("ANXIN_SECURITY_QUARANTINE_KEY") {
            if hex_key.len() == 32 {
                let parsed_result: Result<Vec<u8>, _> = (0..16)
                    .map(|i| u8::from_str_radix(&hex_key[i * 2..i * 2 + 2], 16))
                    .collect();
                if let Ok(bytes) = parsed_result {
                    if let Ok(key) = <[u8; 16]>::try_from(bytes) {
                        return Ok(key);
                    }
                }
            }
            return Err(
                "ANXIN_SECURITY_QUARANTINE_KEY 格式无效，需要 32 位 hex 字符串".to_string(),
            );
        }

        Self::load_or_create_dpapi_encryption_key()
    }

    /// 函数名称：load_or_create_dpapi_encryption_key
    /// 函数作用：读取 DPAPI 保护的隔离区 AES 密钥；不存在时生成随机密钥并保存。
    /// Purpose: Reads the DPAPI-protected quarantine AES key, generating and saving a random key when missing.
    /// 调用方：get_encryption_key。
    /// Called by: get_encryption_key.
    /// 被调用方：protect_data_with_dpapi，unprotect_data_with_dpapi。
    /// Calls: protect_data_with_dpapi, unprotect_data_with_dpapi.
    /// 返回值说明：返回 16 字节 AES-128 密钥。
    /// Returns: 16-byte AES-128 key.
    /// 中文关键词：隔离区密钥，DPAPI，随机密钥，APPDATA
    /// English keywords: quarantine key, DPAPI, random key, APPDATA
    fn load_or_create_dpapi_encryption_key() -> Result<[u8; 16], String> {
        let key_path = Self::quarantine_key_path();
        if key_path.exists() {
            let encrypted_key =
                fs::read(&key_path).map_err(|err| format!("Failed to read key file: {}", err))?;
            let key_bytes = unprotect_data_with_dpapi(&encrypted_key, QUARANTINE_KEY_ENTROPY)?;
            return <[u8; 16]>::try_from(key_bytes)
                .map_err(|_| "DPAPI quarantine key must be 16 bytes".to_string());
        }

        let mut key = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key);
        let encrypted_key = protect_data_with_dpapi(&key, QUARANTINE_KEY_ENTROPY)?;

        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("Failed to create quarantine key directory: {}", err))?;
        }
        fs::write(&key_path, encrypted_key)
            .map_err(|err| format!("Failed to write quarantine key file: {}", err))?;

        Ok(key)
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
        let file_data =
            fs::read(&original_path).map_err(|e| format!("Failed to read file: {}", e))?;

        // 加密文件
        let encryption_key = Self::get_encryption_key()?;
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
            "#,
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
        let encryption_key = Self::get_encryption_key()?;
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
            "#,
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
            "#,
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
            "#,
        )
        .bind(&record_id)
        .execute(pool)
        .await
        .map_err(|e| format!("Failed to delete quarantine record: {}", e))?;

        Ok(true)
    }

    /// 列出所有隔离项目
    pub async fn list_quarantine_items(
        &self,
        pool: &SqlitePool,
    ) -> Result<Vec<QuarantineItem>, String> {
        let items: Vec<QuarantineItem> = sqlx::query_as(
            r#"
            SELECT id, original_path, isolated_path, file_hash, file_size,
                   threat_type, threat_family, status, isolated_at, restored_at, description
            FROM quarantine_items
            ORDER BY isolated_at DESC
            LIMIT 1000
            "#,
        )
        .fetch_all(pool)
        .await
        .map_err(|e| format!("Failed to query quarantine items: {}", e))?;

        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct QuarantineKeyEnvGuard {
        _lock: MutexGuard<'static, ()>,
        original: Option<String>,
    }

    impl QuarantineKeyEnvGuard {
        fn set(value: &str) -> Self {
            let lock = ENV_LOCK.lock().expect("env lock should not be poisoned");
            let original = std::env::var("ANXIN_SECURITY_QUARANTINE_KEY").ok();
            std::env::set_var("ANXIN_SECURITY_QUARANTINE_KEY", value);
            Self {
                _lock: lock,
                original,
            }
        }
    }

    impl Drop for QuarantineKeyEnvGuard {
        fn drop(&mut self) {
            if let Some(val) = &self.original {
                std::env::set_var("ANXIN_SECURITY_QUARANTINE_KEY", val);
            } else {
                std::env::remove_var("ANXIN_SECURITY_QUARANTINE_KEY");
            }
        }
    }

    #[test]
    fn get_encryption_key_returns_16_bytes() {
        let _env_guard =
            QuarantineKeyEnvGuard::set("00112233445566778899aabbccddeeff");
        let key = QuarantineService::get_encryption_key().expect("valid env key should load");
        assert_eq!(key.len(), 16, "encryption key must be 16 bytes for AES-128");
    }

    #[test]
    fn get_encryption_key_with_valid_env_var() {
        let _env_guard =
            QuarantineKeyEnvGuard::set("00112233445566778899aabbccddeeff");
        let key = QuarantineService::get_encryption_key().expect("valid env key should load");
        assert_eq!(key[0], 0x00);
        assert_eq!(key[1], 0x11);
        assert_eq!(key[15], 0xff);
    }

    #[test]
    fn get_encryption_key_with_short_env_var_returns_error() {
        let _env_guard = QuarantineKeyEnvGuard::set("tooshort");
        let result = QuarantineService::get_encryption_key();
        assert!(result.is_err(), "short env var must not use a built-in static key");
    }

    #[test]
    fn get_encryption_key_with_invalid_hex_env_var_returns_error() {
        let _env_guard =
            QuarantineKeyEnvGuard::set("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        let result = QuarantineService::get_encryption_key();
        assert!(result.is_err(), "invalid env var must not use a built-in static key");
    }

    #[test]
    fn quarantine_key_path_uses_runtime_key_file() {
        let key_path = QuarantineService::quarantine_key_path();
        assert_eq!(
            key_path.file_name().and_then(|name| name.to_str()),
            Some(QUARANTINE_KEY_FILE_NAME)
        );
        assert!(
            key_path.to_string_lossy().contains("runtime"),
            "quarantine key should be stored in runtime data directory"
        );
    }

    #[test]
    fn quarantine_item_default_status_is_quarantined() {
        let item = QuarantineItem {
            id: "test-id".to_string(),
            original_path: "C:\\test.exe".to_string(),
            isolated_path: "C:\\quarantine\\test.enc".to_string(),
            file_hash: "abc123".to_string(),
            file_size: 1024,
            threat_type: Some("trojan".to_string()),
            threat_family: None,
            status: "quarantined".to_string(),
            isolated_at: "2026-01-01T00:00:00Z".to_string(),
            restored_at: None,
            description: None,
        };
        assert_eq!(item.status, "quarantined");
        assert_eq!(item.file_size, 1024);
        assert!(item.threat_type.is_some());
        assert!(item.restored_at.is_none());
    }

    #[test]
    fn quarantine_item_serialization_round_trip() {
        let item = QuarantineItem {
            id: "uuid-1234".to_string(),
            original_path: "C:\\malware\\test.exe".to_string(),
            isolated_path: "C:\\quarantine\\uuid-1234.enc".to_string(),
            file_hash: "deadbeef".to_string(),
            file_size: 2048,
            threat_type: Some("ransomware".to_string()),
            threat_family: Some("WannaCry".to_string()),
            status: "quarantined".to_string(),
            isolated_at: "2026-05-01T12:00:00Z".to_string(),
            restored_at: None,
            description: Some("Test quarantine item".to_string()),
        };
        let json = serde_json::to_string(&item).expect("serialization should succeed");
        let parsed: QuarantineItem =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(parsed.id, item.id);
        assert_eq!(parsed.original_path, item.original_path);
        assert_eq!(parsed.file_hash, item.file_hash);
        assert_eq!(parsed.status, item.status);
    }
}
