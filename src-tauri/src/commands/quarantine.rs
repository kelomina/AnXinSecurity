// 隔离区管理命令 - 完整实现
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tauri::State;
use crate::services::quarantine_service::QuarantineService;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItemResponse {
    pub id: String,
    pub original_path: String,
    pub file_hash: String,
    pub file_size: u64,
    pub threat_type: Option<String>,
    pub threat_family: Option<String>,
    pub status: String,
    pub isolated_at: String,
    pub restored_at: Option<String>,
}

/// 列出隔离区项目
#[tauri::command]
pub async fn list_quarantine(
    pool: State<'_, SqlitePool>,
) -> Result<Vec<QuarantineItemResponse>, String> {
    let service = QuarantineService::new();
    let items = service.list_quarantine_items(&pool).await?;
    
    Ok(items.into_iter().map(|item| QuarantineItemResponse {
        id: item.id,
        original_path: item.original_path,
        file_hash: item.file_hash,
        file_size: item.file_size,
        threat_type: item.threat_type,
        threat_family: item.threat_family,
        status: item.status,
        isolated_at: item.isolated_at,
        restored_at: item.restored_at,
    }).collect())
}

/// 隔离文件
#[tauri::command]
pub async fn isolate_file(
    pool: State<'_, SqlitePool>,
    file_path: String,
    threat_type: Option<String>,
) -> Result<QuarantineItemResponse, String> {
    let service = QuarantineService::new();
    let item = service.isolate_file(&pool, &file_path, threat_type.as_deref()).await?;
    
    Ok(QuarantineItemResponse {
        id: item.id,
        original_path: item.original_path,
        file_hash: item.file_hash,
        file_size: item.file_size,
        threat_type: item.threat_type,
        threat_family: item.threat_family,
        status: item.status,
        isolated_at: item.isolated_at,
        restored_at: item.restored_at,
    })
}

/// 恢复文件
#[tauri::command]
pub async fn restore_file(
    pool: State<'_, SqlitePool>,
    id: String,
) -> Result<bool, String> {
    let service = QuarantineService::new();
    let success = service.restore_file(&pool, &id).await?;
    
    // TODO: 触发前端事件通知
    // if success {
    //     app_handle.emit("quarantine-restored", &id).ok();
    // }
    
    Ok(success)
}

/// 删除隔离文件
#[tauri::command]
pub async fn delete_quarantine(
    pool: State<'_, SqlitePool>,
    id: String,
) -> Result<bool, String> {
    let service = QuarantineService::new();
    let success = service.delete_quarantine(&pool, &id).await?;
    
    // TODO: 触发前端事件通知
    // if success {
    //     app_handle.emit("quarantine-deleted", &id).ok();
    // }
    
    Ok(success)
}
