// 排除列表管理命令 - 完整实现
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::State;
use crate::models::config::AppConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionEntry {
    pub path: String,
    pub entry_type: String, // "file" | "directory" | "process"
    pub description: Option<String>,
    pub created_at: String,
}

/// 获取排除项列表
#[tauri::command]
pub async fn list_exclusions(state: State<'_, Arc<Mutex<AppConfig>>>) -> Result<Vec<ExclusionEntry>, String> {
    let config = state.lock().map_err(|e| e.to_string())?;
    
    // 从配置中读取排除项，如果不存在则返回空列表
    let exclusions = config.exclusions.clone().unwrap_or_default();
    
    Ok(exclusions)
}

/// 添加排除项
#[tauri::command]
pub async fn add_exclusion(
    state: State<'_, Arc<Mutex<AppConfig>>>,
    path: String,
    entry_type: String,
    description: Option<String>,
) -> Result<bool, String> {
    let mut config = state.lock().map_err(|e| e.to_string())?;
    
    // 验证路径是否存在
    let path_buf = PathBuf::from(&path);
    if !path_buf.exists() {
        return Err(format!("路径不存在: {}", path));
    }
    
    // 检查是否已存在
    let mut exclusions = config.exclusions.clone().unwrap_or_default();
    if exclusions.iter().any(|e| e.path == path) {
        return Err("排除项已存在".to_string());
    }
    
    // 创建新的排除项
    let entry = ExclusionEntry {
        path,
        entry_type,
        description,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    
    exclusions.push(entry);
    config.exclusions = Some(exclusions);
    
    // 保存配置
    config.save().map_err(|e| e.to_string())?;
    
    Ok(true)
}

/// 移除排除项
#[tauri::command]
pub async fn remove_exclusion(
    state: State<'_, Arc<Mutex<AppConfig>>>,
    path: String,
) -> Result<bool, String> {
    let mut config = state.lock().map_err(|e| e.to_string())?;
    
    let mut exclusions = config.exclusions.clone().unwrap_or_default();
    let original_len = exclusions.len();
    
    exclusions.retain(|e| e.path != path);
    
    if exclusions.len() == original_len {
        return Err("排除项不存在".to_string());
    }
    
    config.exclusions = Some(exclusions);
    config.save().map_err(|e| e.to_string())?;
    
    Ok(true)
}

/// 批量添加排除项（用于目录扫描）
#[tauri::command]
pub async fn add_exclusions_batch(
    state: State<'_, Arc<Mutex<AppConfig>>>,
    entries: Vec<ExclusionEntry>,
) -> Result<usize, String> {
    let mut config = state.lock().map_err(|e| e.to_string())?;
    
    let mut exclusions = config.exclusions.clone().unwrap_or_default();
    let mut added_count = 0;
    
    for entry in entries {
        if !exclusions.iter().any(|e| e.path == entry.path) {
            exclusions.push(entry);
            added_count += 1;
        }
    }
    
    config.exclusions = Some(exclusions);
    config.save().map_err(|e| e.to_string())?;
    
    Ok(added_count)
}
