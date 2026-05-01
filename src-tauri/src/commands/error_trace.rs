// 错误追踪命令 — 前端错误上报到主进程日志
// Error trace commands — frontend error reporting to main process logs
use std::fs;
use std::path::PathBuf;
use std::io::Write;

/// 函数名称：report_error
/// 函数作用：将前端错误堆栈记录到本地日志文件。
/// Purpose: Records frontend error stack traces to a local log file.
/// 参数 error: 错误堆栈信息 / Error stack info
/// 参数 source: 错误来源（如 "renderer", "interception"）/ Error source
/// 副作用：写入 logs/error_trace.log
/// Side effect: Writes to logs/error_trace.log
/// 调用方：前端 ErrorBoundary 捕获错误后调用
/// Called by: Frontend ErrorBoundary after catching an error
/// 中文关键词：错误追踪，错误上报，错误日志，堆栈记录
/// English keywords: error trace, error reporting, error log, stack recording
#[tauri::command]
pub async fn report_error(
    error: String,
    source: Option<String>,
) -> Result<bool, String> {
    let source_str = source.unwrap_or_else(|| "renderer".to_string());
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();

    let log_line = format!(
        "[{}] [{}] {}\n",
        timestamp, source_str, error.replace('\n', " | ")
    );

    // 确保 logs 目录存在 / Ensure logs directory exists
    let logs_dir = PathBuf::from("logs");
    if !logs_dir.exists() {
        fs::create_dir_all(&logs_dir)
            .map_err(|e| format!("创建日志目录失败: {}", e))?;
    }

    let log_path = logs_dir.join("error_trace.log");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| format!("打开错误日志文件失败: {}", e))?;

    file.write_all(log_line.as_bytes())
        .map_err(|e| format!("写入错误日志失败: {}", e))?;

    Ok(true)
}

/// 函数名称：get_error_logs
/// 函数作用：获取最近的错误日志记录。
/// Purpose: Gets the most recent error log records.
/// Returns: 最近 100 条错误日志 / Last 100 error log lines
/// 调用方：前端调试页面
/// Called by: Frontend debug page
/// 中文关键词：错误日志读取，日志查询
/// English keywords: error log reading, log query
#[tauri::command]
pub async fn get_error_logs() -> Result<Vec<String>, String> {
    let log_path = PathBuf::from("logs/error_trace.log");
    if !log_path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(&log_path)
        .map_err(|e| format!("读取错误日志失败: {}", e))?;
    let lines: Vec<String> = content.lines()
        .rev()
        .take(100)
        .map(|s| s.to_string())
        .collect();
    Ok(lines)
}
