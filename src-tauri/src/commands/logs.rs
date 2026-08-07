// 日志命令 — 实时 ETW 日志流和历史日志查询
// Log commands — real-time ETW log stream and historical log query
use crate::services::service_context::AppContext;
use once_cell::sync::Lazy;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// 内存日志缓冲区 / In-memory log buffer
/// 存储最近的事件日志供前端查询 / Stores recent event logs for frontend queries
static LOG_BUFFER: Lazy<Arc<Mutex<VecDeque<String>>>> =
    Lazy::new(|| Arc::new(Mutex::new(VecDeque::with_capacity(LOG_CAPACITY))));

/// 日志缓冲区最大容量 / Log buffer max capacity
const LOG_CAPACITY: usize = 500;

/// 获取日志缓冲区 / Get log buffer
fn get_log_buffer() -> Arc<Mutex<VecDeque<String>>> {
    LOG_BUFFER.clone()
}

/// 追加日志条目到缓冲区 / Append log entry to buffer
pub fn append_log(entry: String) {
    if let Ok(mut buf) = LOG_BUFFER.lock() {
        append_log_entry(&mut buf, entry);
    }
}

fn append_log_entry(buffer: &mut VecDeque<String>, entry: String) {
    if buffer.len() >= LOG_CAPACITY {
        buffer.pop_front();
    }
    buffer.push_back(entry);
}

/// 函数名称：event_pid
/// 函数作用：从统一事件 JSON 中提取明确存在的 PID，兼容顶层 pid 和嵌套 event.pid。
/// Purpose: Extracts an explicit PID from unified event JSON, supporting top-level pid and nested event.pid.
/// 中文关键词：日志过滤，PID提取，系统噪音
/// English keywords: log filter, PID extraction, system noise
#[allow(dead_code)]
fn event_pid(value: &serde_json::Value) -> Option<u64> {
    value
        .get("pid")
        .or_else(|| value.get("event").and_then(|event| event.get("pid")))
        .and_then(|pid| pid.as_u64())
}

#[allow(dead_code)]
const INVALID_WINDOWS_PID_U32_MAX: u64 = u32::MAX as u64;

/// 函数名称：should_drop_system_log_event
/// 函数作用：判断事件是否来自系统或无效 PID，避免系统空闲/内核进程噪音进入实时日志。
/// Purpose: Returns whether an event belongs to system/invalid PIDs and should be excluded from realtime logs.
/// 中文关键词：PID过滤，实时日志，后端兜底
/// English keywords: PID filter, realtime log, backend guard
#[allow(dead_code)]
fn should_drop_system_log_event(value: &serde_json::Value) -> bool {
    match event_pid(value) {
        Some(0 | 4) => true,
        Some(pid) => pid == INVALID_WINDOWS_PID_U32_MAX,
        None => false,
    }
}

/// 追加日志条目并推送给前端 / Append log entry and emit it to frontend listeners
///
/// 泛型化到 `AppContext` 而不是绑死 `tauri::AppHandle`：
/// ETW / 文件 Hook 等防护组件在服务化后只持有 `ServiceContext`，
/// 而 `AppHandle` 同样实现了 `AppContext`，因此两种进程共用这一个实现。
///  Generic over `AppContext` instead of `tauri::AppHandle`: after the service split, protection
///  components such as ETW and the file hook only hold a `ServiceContext`, while `AppHandle` also
///  implements `AppContext`, so both processes share this single implementation.
pub fn append_log_and_emit<C: AppContext>(ctx: &C, entry: String) {
    append_log(entry.clone());
    if !ctx.is_exiting() {
        let _ = ctx.emit_event("log-event", entry);
    }
}

/// 函数名称：append_event_log_and_emit
/// 函数作用：写入已解析的统一事件日志，并在写入前过滤系统/无效 PID 噪音。
/// Purpose: Appends a parsed unified event log and filters system/invalid PID noise before writing.
/// 调用方：ETW 服务、文件 Hook 服务。
/// Called by: ETW service and file hook service.
/// 返回值说明：写入并推送返回 true；过滤或序列化失败返回 false。
/// Returns: true when appended/emitted; false when filtered or serialization failed.
/// 中文关键词：结构化日志，实时日志，PID过滤，性能保护
/// English keywords: structured log, realtime log, PID filter, performance guard
pub fn append_event_log_and_emit<C: AppContext>(ctx: &C, event: &serde_json::Value) -> bool {
    if should_drop_system_log_event(event) {
        return false;
    }

    match serde_json::to_string(event) {
        Ok(entry) => {
            append_log_and_emit(ctx, entry);
            true
        }
        Err(_) => false,
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
    Ok(buf.iter().cloned().collect())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn should_drop_system_log_event_filters_top_level_and_nested_pid_zero_four() {
        assert!(should_drop_system_log_event(&json!({
            "pid": 0,
            "provider": "Unknown"
        })));
        assert!(should_drop_system_log_event(&json!({
            "event": {
                "pid": 4,
                "provider": "Network"
            }
        })));
        assert!(should_drop_system_log_event(&json!({
            "pid": 4_294_967_295_u64,
            "provider": "Unknown"
        })));
        assert!(should_drop_system_log_event(&json!({
            "event": {
                "pid": 4_294_967_295_u64,
                "provider": "Unknown"
            }
        })));
    }

    #[test]
    fn should_drop_system_log_event_keeps_normal_and_missing_pid() {
        assert!(!should_drop_system_log_event(&json!({
            "pid": 47216,
            "provider": "Network"
        })));
        assert!(!should_drop_system_log_event(&json!({
            "provider": "Unknown"
        })));
    }

    #[test]
    fn append_log_entry_evicts_oldest_when_capacity_is_reached() {
        let mut buffer = VecDeque::with_capacity(LOG_CAPACITY);

        for index in 0..LOG_CAPACITY {
            append_log_entry(&mut buffer, format!("entry-{index}"));
        }

        append_log_entry(&mut buffer, "entry-new".to_string());

        assert_eq!(buffer.len(), LOG_CAPACITY);
        assert_eq!(buffer.front().map(|value| value.as_str()), Some("entry-1"));
        assert_eq!(buffer.back().map(|value| value.as_str()), Some("entry-new"));
    }
}
