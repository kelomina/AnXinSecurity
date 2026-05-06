// 日志命令 — 实时 ETW 日志流和历史日志查询
// Log commands — real-time ETW log stream and historical log query
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};

/// 内存日志缓冲区 / In-memory log buffer
/// 存储最近的事件日志供前端查询 / Stores recent event logs for frontend queries
static LOG_BUFFER: Lazy<Arc<Mutex<Vec<String>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Vec::with_capacity(LOG_CAPACITY))));

/// 日志缓冲区最大容量 / Log buffer max capacity
const LOG_CAPACITY: usize = 500;

/// 获取日志缓冲区 / Get log buffer
fn get_log_buffer() -> Arc<Mutex<Vec<String>>> {
    LOG_BUFFER.clone()
}

/// 追加日志条目到缓冲区 / Append log entry to buffer
pub fn append_log(entry: String) {
    if let Ok(mut buf) = LOG_BUFFER.lock() {
        if buf.len() >= LOG_CAPACITY {
            buf.remove(0); // 移除最旧条目 / Remove oldest entry
        }
        buf.push(entry);
    }
}

/// 函数名称：get_recent_logs
/// 函数作用：获取最近的 ETW 事件日志。
/// Purpose: Gets the most recent ETW event logs.
/// Returns: 最近 500 条日志 / Last 500 log entries
/// 调用方：前端概览页日志面板
/// Called by: Frontend overview page log panel
/// 中文关键词：日志查询，事件日志，历史日志
/// English keywords: log query, event logs, historical logs
#[tauri::command]
pub async fn get_recent_logs() -> Result<Vec<String>, String> {
    let buffer = get_log_buffer();
    let buf = buffer.lock().map_err(|e| e.to_string())?;
    Ok(buf.clone())
}

/// 函数名称：clear_logs
/// 函数作用：清空本地日志缓冲区。
/// Purpose: Clears the local log buffer.
/// 调用方：前端日志面板清除按钮
/// Called by: Frontend log panel clear button
/// 中文关键词：清空日志，清除日志
/// English keywords: clear logs, wipe logs
#[tauri::command]
pub async fn clear_logs() -> Result<bool, String> {
    let buffer = get_log_buffer();
    let mut buf = buffer.lock().map_err(|e| e.to_string())?;
    buf.clear();
    Ok(true)
}

/// 函数名称：get_log_status
/// 函数作用：获取 ETW 日志服务状态（是否运行、缓冲区大小）。
/// Purpose: Gets ETW log service status (running state, buffer size).
/// 调用方：前端概览页
/// Called by: Frontend overview page
/// 中文关键词：日志状态，缓冲区大小
/// English keywords: log status, buffer size
#[tauri::command]
pub async fn get_log_status() -> Result<serde_json::Value, String> {
    let buffer = get_log_buffer();
    let buf = buffer.lock().map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "bufferSize": buf.len(),
        "maxCapacity": LOG_CAPACITY,
    }))
}
