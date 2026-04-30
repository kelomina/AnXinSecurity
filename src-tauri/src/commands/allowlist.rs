// 启动允许列表管理命令
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::State;
use crate::models::config::AppConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistEntry {
    pub path: String,
    pub hash: Option<String>, // 文件哈希值（可选，用于验证）
    pub description: Option<String>,
    pub created_at: String,
}

/// 获取启动允许列表
#[tauri::command]
pub async fn list_allowlist(state: State<'_, Arc<Mutex<AppConfig>>>) -> Result<Vec<AllowlistEntry>, String> {
    let config = state.lock().map_err(|e| e.to_string())?;
    
    let allowlist = config.startup_allowlist.clone().unwrap_or_default();
    
    Ok(allowlist)
}

/// 添加到启动允许列表
#[tauri::command]
pub async fn add_to_allowlist(
    state: State<'_, Arc<Mutex<AppConfig>>>,
    path: String,
    description: Option<String>,
) -> Result<bool, String> {
    let mut config = state.lock().map_err(|e| e.to_string())?;
    
    // 验证路径是否存在
    let path_buf = PathBuf::from(&path);
    if !path_buf.exists() {
        return Err(format!("路径不存在: {}", path));
    }
    
    // 检查是否已存在
    let mut allowlist = config.startup_allowlist.clone().unwrap_or_default();
    if allowlist.iter().any(|e| e.path == path) {
        return Err("该程序已在允许列表中".to_string());
    }
    
    // 计算文件哈希（可选）
    let hash = calculate_file_hash(&path_buf).ok();
    
    let entry = AllowlistEntry {
        path,
        hash,
        description,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    
    allowlist.push(entry);
    config.startup_allowlist = Some(allowlist);
    
    // 保存配置
    config.save().map_err(|e| e.to_string())?;
    
    Ok(true)
}

/// 从启动允许列表移除
#[tauri::command]
pub async fn remove_from_allowlist(
    state: State<'_, Arc<Mutex<AppConfig>>>,
    path: String,
) -> Result<bool, String> {
    let mut config = state.lock().map_err(|e| e.to_string())?;
    
    let mut allowlist = config.startup_allowlist.clone().unwrap_or_default();
    let original_len = allowlist.len();
    
    allowlist.retain(|e| e.path != path);
    
    if allowlist.len() == original_len {
        return Err("允许列表项不存在".to_string());
    }
    
    config.startup_allowlist = Some(allowlist);
    config.save().map_err(|e| e.to_string())?;
    
    Ok(true)
}

/// 批量添加到允许列表
#[tauri::command]
pub async fn add_to_allowlist_batch(
    state: State<'_, Arc<Mutex<AppConfig>>>,
    entries: Vec<AllowlistEntry>,
) -> Result<usize, String> {
    let mut config = state.lock().map_err(|e| e.to_string())?;
    
    let mut allowlist = config.startup_allowlist.clone().unwrap_or_default();
    let mut added_count = 0;
    
    for entry in entries {
        if !allowlist.iter().any(|e| e.path == entry.path) {
            allowlist.push(entry);
            added_count += 1;
        }
    }
    
    config.startup_allowlist = Some(allowlist);
    config.save().map_err(|e| e.to_string())?;
    
    Ok(added_count)
}

/// 计算文件 SHA256 哈希
fn calculate_file_hash(path: &PathBuf) -> Result<String, String> {
    use sha2::Digest;
    use std::fs::File;
    use std::io::Read;
    
    let mut file = File::open(path).map_err(|e| format!("无法打开文件: {}", e))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|e| format!("读取文件失败: {}", e))?;
    
    let mut hasher = sha2::Sha256::new();
    hasher.update(&buffer);
    let result = hasher.finalize();
    
    Ok(format!("{:x}", result))
}
