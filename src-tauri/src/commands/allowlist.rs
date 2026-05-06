use crate::services::path_policy_service::{
    load_allowlist_entries, AllowlistEntry, ALLOWLIST_RUNTIME_FILE,
};
use crate::services::runtime_list_store::save_runtime_list;
use std::path::PathBuf;

/// 获取启动允许列表
#[tauri::command]
pub async fn list_allowlist() -> Result<Vec<AllowlistEntry>, String> {
    load_allowlist()
}

/// 添加到启动允许列表
#[tauri::command]
pub async fn add_to_allowlist(path: String, description: Option<String>) -> Result<bool, String> {
    // 验证路径是否存在
    let path_buf = PathBuf::from(&path);
    if !path_buf.exists() {
        return Err(format!("路径不存在: {}", path));
    }

    // 检查是否已存在
    let mut allowlist = load_allowlist()?;
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
    save_allowlist(&allowlist)?;

    // 保存配置

    Ok(true)
}

/// 从启动允许列表移除
#[tauri::command]
pub async fn remove_from_allowlist(path: String) -> Result<bool, String> {
    let mut allowlist = load_allowlist()?;
    let original_len = allowlist.len();

    allowlist.retain(|e| e.path != path);

    if allowlist.len() == original_len {
        return Err("允许列表项不存在".to_string());
    }

    save_allowlist(&allowlist)?;

    Ok(true)
}

/// 批量添加到允许列表
#[tauri::command]
pub async fn add_to_allowlist_batch(entries: Vec<AllowlistEntry>) -> Result<usize, String> {
    let mut allowlist = load_allowlist()?;
    let mut added_count = 0;

    for entry in entries {
        if !allowlist.iter().any(|e| e.path == entry.path) {
            allowlist.push(entry);
            added_count += 1;
        }
    }

    save_allowlist(&allowlist)?;

    Ok(added_count)
}

/// 计算文件 SHA256 哈希
fn calculate_file_hash(path: &PathBuf) -> Result<String, String> {
    use sha2::Digest;
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path).map_err(|e| format!("无法打开文件: {}", e))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| format!("读取文件失败: {}", e))?;

    let mut hasher = sha2::Sha256::new();
    hasher.update(&buffer);
    let result = hasher.finalize();

    Ok(format!("{:x}", result))
}

fn load_allowlist() -> Result<Vec<AllowlistEntry>, String> {
    load_allowlist_entries()
}

fn save_allowlist(entries: &[AllowlistEntry]) -> Result<(), String> {
    save_runtime_list(ALLOWLIST_RUNTIME_FILE, entries)
}
