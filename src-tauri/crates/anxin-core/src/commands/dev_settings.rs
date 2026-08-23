// 开发者设置命令 — 密码保护的加密配置管理
// Developer settings commands — password-protected encrypted configuration management
use crate::utils::crypto::{decrypt_data, encrypt_data};
use std::sync::{Arc, Mutex};

/// 加密的开发者设置数据 / Encrypted developer settings data
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct DevSettings {
    /// 密码哈希 / Password hash (SHA-256)
    pub password_hash: String,
    /// AES-128-GCM 加密的载荷 / AES-128-GCM encrypted payload
    pub payload: String,
    /// 更新时间戳 / Update timestamp
    #[serde(rename = "updatedAt")]
    pub updated_at: u64,
}

/// 函数名称：dev_settings_unlock
/// 函数作用：使用密码验证并解密开发者设置数据。
/// Purpose: Verifies password and decrypts developer settings data.
/// 参数 password: 解锁密码 / Unlock password
/// 参数 config: 应用配置状态 / App config state
/// Returns: 解密后的 JSON 数据 / Decrypted JSON data
/// 错误处理：密码错误返回错误
/// 调用方：前端 SettingsPage 开发者设置选项卡
/// Called by: Frontend SettingsPage dev settings tab
/// 中文关键词：开发者设置，解锁，密码验证，解密配置
/// English keywords: developer settings, unlock, password verification, decrypt config
#[tauri::command]
pub async fn dev_settings_unlock(
    password: String,
    _config: tauri::State<'_, Arc<Mutex<crate::models::config::AppConfig>>>,
) -> Result<serde_json::Value, String> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = format!("{:x}", hasher.finalize());

    // 从配置文件读取加密的开发者设置 / Read encrypted dev settings from config
    // devSettings 通过 config/app.json 独立读取（不在 AppConfig 结构体中）
    let dev_config = read_dev_settings_file()?;

    if dev_config.password_hash != hash {
        return Err("密码错误".to_string());
    }

    // 解密载荷 / Decrypt payload
    let payload_bytes =
        hex::decode(&dev_config.payload).map_err(|e| format!("解码载荷失败: {}", e))?;
    let decrypted = decrypt_data(&payload_bytes, password.as_bytes())?;
    let value: serde_json::Value =
        serde_json::from_slice(&decrypted).map_err(|e| format!("解析设置失败: {}", e))?;

    Ok(value)
}

/// 函数名称：dev_settings_save
/// 函数作用：使用密码加密并保存开发者设置数据。
/// Purpose: Encrypts and saves developer settings data with password.
/// 参数 password: 加密密码 / Encryption password
/// 参数 data: 要保存的 JSON 数据 / JSON data to save
/// 副作用：写入 config/app.json 的 devSettings 字段
/// 调用方：前端 SettingsPage 开发者设置选项卡
/// Called by: Frontend SettingsPage dev settings tab
/// 中文关键词：保存设置，加密配置，开发者设置保存
/// English keywords: save settings, encrypt config, developer settings save
#[tauri::command]
pub async fn dev_settings_save(password: String, data: serde_json::Value) -> Result<bool, String> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = format!("{:x}", hasher.finalize());

    let plaintext = serde_json::to_string(&data).map_err(|e| format!("序列化设置失败: {}", e))?;
    let encrypted = encrypt_data(plaintext.as_bytes(), password.as_bytes())?;
    let payload = hex::encode(&encrypted);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let new_dev_settings = serde_json::json!({
        "salt": &hash[..32],
        "payload": {
            "iv": "",
            "authTag": "",
            "data": payload,
        },
        "updatedAt": now,
        "passwordHash": hash,
    });

    // 写入配置文件的 devSettings 字段 / Write devSettings field to config file
    save_dev_settings_to_file(&new_dev_settings)?;

    Ok(true)
}

fn read_dev_settings_file() -> Result<DevSettings, String> {
    let path = std::path::PathBuf::from("config/app.json");
    let content = std::fs::read_to_string(&path).map_err(|e| format!("读取配置文件失败: {}", e))?;
    let config: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("解析配置文件失败: {}", e))?;

    let dev = config
        .get("devSettings")
        .ok_or("配置文件中未找到 devSettings")?;

    let password_hash = dev
        .get("salt")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let payload = dev
        .get("payload")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let updated_at = dev.get("updatedAt").and_then(|v| v.as_u64()).unwrap_or(0);

    Ok(DevSettings {
        password_hash,
        payload,
        updated_at,
    })
}

fn save_dev_settings_to_file(dev_settings: &serde_json::Value) -> Result<(), String> {
    let path = std::path::PathBuf::from("config/app.json");
    let content = std::fs::read_to_string(&path).map_err(|e| format!("读取配置文件失败: {}", e))?;
    let mut config: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("解析配置文件失败: {}", e))?;

    config["devSettings"] = dev_settings.clone();

    let json_str =
        serde_json::to_string_pretty(&config).map_err(|e| format!("序列化配置失败: {}", e))?;
    std::fs::write(&path, json_str).map_err(|e| format!("写入配置文件失败: {}", e))?;

    Ok(())
}
