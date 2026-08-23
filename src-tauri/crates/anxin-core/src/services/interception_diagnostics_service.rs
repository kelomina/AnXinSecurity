//! 拦截链路诊断日志。
//!
//! 这里故意不复用 stderr / 前端实时日志：ETW 高频事件刷屏时，人工很难看清
//! APIHook → 拦截队列 → 独立窗口展示到底卡在哪一级。该模块把关键节点按
//! JSONL 追加写入 `%APPDATA%\AnXinSecurity\runtime\interception_diagnostics.jsonl`，
//! 每行都是一个独立 JSON，便于 `Get-Content -Tail` 或脚本过滤。

use crate::services::runtime_list_store::runtime_file_path;
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

const INTERCEPTION_DIAGNOSTICS_FILE: &str = "interception_diagnostics.jsonl";
static DIAGNOSTIC_WRITE_LOCK: Mutex<()> = Mutex::new(());

/// 函数名称：append_interception_diagnostic
/// 函数作用：向独立 JSONL 文件追加一条拦截链路诊断记录。
/// Purpose: Appends one interception-pipeline diagnostic record to a dedicated JSONL file.
///
/// 这类诊断是“黑匣子记录”，只用于定位 Hook 事件是否进入 Rust、是否成功入队、
/// `try_show_next()` 是否被调用、独立拦截窗口是否 show 成功。写入失败不应影响
/// 安全主链路，因此本函数吞掉 I/O 错误，避免诊断功能反过来阻塞拦截。
pub fn append_interception_diagnostic(stage: &str, payload: Value) {
    let _guard = DIAGNOSTIC_WRITE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = runtime_file_path(INTERCEPTION_DIAGNOSTICS_FILE);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let record = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "stage": stage,
        "payload": payload,
    });
    let Ok(line) = serde_json::to_string(&record) else {
        return;
    };

    let _ = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| writeln!(file, "{}", line));
}

#[cfg(test)]
mod tests {
    #[test]
    fn interception_diagnostic_record_is_json_line() {
        let record = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "stage": "try_show_next_entry",
            "payload": {
                "pid": 6200,
                "processName": "regedit.exe"
            }
        });

        let line = serde_json::to_string(&record).expect("diagnostic record should serialize");
        let parsed: serde_json::Value =
            serde_json::from_str(&line).expect("diagnostic line should be valid JSON");

        assert_eq!(parsed["stage"], "try_show_next_entry");
        assert_eq!(parsed["payload"]["pid"], 6200);
        assert_eq!(parsed["payload"]["processName"], "regedit.exe");
    }
}
