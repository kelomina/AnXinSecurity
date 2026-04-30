// 隔离区管理命令 - 完整实现
//  Quarantine management commands — full implementation
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tauri::{AppHandle, Emitter, State};
use crate::services::quarantine_service::QuarantineService;

/// 隔离区项目响应结构体
/// Quarantine item response DTO — returned to the frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItemResponse {
    pub id: String,
    pub original_path: String,
    pub file_hash: String,
    pub file_size: i64,
    pub threat_type: Option<String>,
    pub threat_family: Option<String>,
    pub status: String,
    pub isolated_at: String,
    pub restored_at: Option<String>,
}

/// 函数名称：list_quarantine
/// 函数作用：列出隔离区中的所有文件记录，返回 QuarantineItemResponse 列表。
/// Purpose: Lists all quarantined file records, returning Vec<QuarantineItemResponse>.
/// 调用方：前端 API `listQuarantine()` → useQuarantineStore.loadItems()
/// Called by: Frontend API listQuarantine() → useQuarantineStore.loadItems()
/// 中文关键词：隔离区，列表，文件列表，威胁文件，隔离记录
/// English keywords: quarantine, list, file list, threat file, quarantine record
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

/// 函数名称：isolate_file
/// 函数作用：将指定文件隔离，加密后存储在隔离区，并从原位置删除。
/// Purpose: Isolates a file by encrypting and storing it in the quarantine directory, then removing the original.
/// 调用方：前端 API `isolateFile()` → ScanPage 威胁列表操作
/// Called by: Frontend API isolateFile() → ScanPage threat list actions
/// 副作用：加密文件写入隔离区，原文件被删除，数据库记录创建，向前端发送 quarantine-updated 事件
/// Side effects: Writes encrypted file, deletes original file, creates DB record, emits "quarantine-updated" event
/// 中文关键词：隔离，文件隔离，加密，安全隔离，威胁处理
/// English keywords: isolate, file isolation, encrypt, quarantine, threat handling
#[tauri::command]
pub async fn isolate_file(
    app_handle: AppHandle,
    pool: State<'_, SqlitePool>,
    file_path: String,
    threat_type: Option<String>,
) -> Result<QuarantineItemResponse, String> {
    let service = QuarantineService::new();
    let item = service.isolate_file(&pool, &file_path, threat_type.as_deref()).await?;
    
    // 通知前端隔离区已更新
    let _ = app_handle.emit("quarantine-updated", &item.id);
    
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

/// 函数名称：restore_file
/// 函数作用：将隔离区中的文件解密并恢复到原始位置。
/// Purpose: Decrypts and restores a quarantined file to its original location.
/// 调用方：前端 API `restoreFile()` → QuarantinePage 恢复按钮
/// Called by: Frontend API restoreFile() → QuarantinePage restore button
/// 副作用：解密文件写入原位置，数据库状态更新，向前端发送 quarantine-updated 事件
/// Side effects: Writes decrypted file, updates DB status, emits "quarantine-updated" event
/// 中文关键词：恢复，文件恢复，解密，隔离区恢复
/// English keywords: restore, file restore, decrypt, quarantine restore
#[tauri::command]
pub async fn restore_file(
    app_handle: AppHandle,
    pool: State<'_, SqlitePool>,
    id: String,
) -> Result<bool, String> {
    let service = QuarantineService::new();
    let success = service.restore_file(&pool, &id).await?;
    
    // 通知前端隔离区已更新
    if success {
        let _ = app_handle.emit("quarantine-updated", &id);
    }
    
    Ok(success)
}

/// 函数名称：delete_quarantine
/// 函数作用：安全擦除并永久删除隔离区文件。此操作不可逆。
/// Purpose: Securely wipes and permanently deletes a quarantined file. This operation is irreversible.
/// 调用方：前端 API `deleteQuarantine()` → QuarantinePage 删除按钮
/// Called by: Frontend API deleteQuarantine() → QuarantinePage delete button
/// 副作用：三次覆写物理文件后删除，数据库记录删除，向前端发送 quarantine-updated 事件
/// Side effects: Three-pass overwrite then delete physical file, remove DB record, emit "quarantine-updated" event
/// 中文关键词：删除，安全擦除，永久删除，覆写，不可逆
/// English keywords: delete, secure wipe, permanent delete, overwrite, irreversible
#[tauri::command]
pub async fn delete_quarantine(
    app_handle: AppHandle,
    pool: State<'_, SqlitePool>,
    id: String,
) -> Result<bool, String> {
    let service = QuarantineService::new();
    let success = service.delete_quarantine(&pool, &id).await?;
    
    // 通知前端隔离区已更新
    if success {
        let _ = app_handle.emit("quarantine-updated", &id);
    }
    
    Ok(success)
}
