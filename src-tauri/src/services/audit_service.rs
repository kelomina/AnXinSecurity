// 安全审计日志服务 — 记录所有 IPC 连接、提权、关键操作事件
//  Security audit log service - records all IPC connection, elevation, critical operation events
//
// 职责：
//  Responsibilities:
// - 记录连接建立/拒绝、提权请求/确认/过期、关键操作执行/拒绝
// - JSONL 格式按天滚动
// - 路径和 SID 脱敏，禁止记录密钥/Token 明文
//
// 安全说明：
//  Security notes:
// - 审计日志本身是安全资产，写入失败不应阻断业务流程
// - 日志路径固定在 %APPDATA%\AnXinSecurity\audit\
//
// 中文关键词：审计日志，安全日志，JSONL，脱敏，提权审计
// English keywords: audit log, security log, JSONL, masking, elevation audit
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// 审计事件类型
///  Audit event types
#[derive(Debug, Clone)]
pub enum AuditEvent {
    /// IPC 连接建立
    IpcConnect {
        pid: u32,
        path: String,
        sid: String,
        session: u32,
        integrity: String,
        verdict: &'static str, // "ACCEPT" | "REJECT"
    },
    /// IPC 连接拒绝
    IpcConnectRejected { pid: u32, reason: &'static str },
    /// 提权请求
    ElevationRequested {
        pid: u32,
        request_id: String,
        ttl_ms: u64,
    },
    /// 提权确认
    ElevationConfirmed {
        pid: u32,
        helper_pid: u32,
        request_id: String,
    },
    /// 提权过期
    ElevationExpired { pid: u32, request_id: String },
    /// 关键操作执行
    ElevatedOpExecuted { pid: u32, method: String },
    /// 关键操作被拒绝
    ElevatedOpDenied {
        pid: u32,
        method: String,
        reason: &'static str,
    },
    /// 身份校验失败
    IdentityCheckFailed {
        pid: u32,
        method: String,
        reason: &'static str,
    },
}

/// 记录审计事件
///  Log audit event
///
/// 写入失败只打印 stderr，不返回错误（审计日志不应阻断业务）
///  Write failures only print to stderr, do not return errors
pub fn log(event: AuditEvent) {
    let timestamp = current_rfc3339();
    let svc_pid = std::process::id();
    let line = format_event(&timestamp, svc_pid, &event);

    let log_dir = resolve_audit_dir();
    let _ = std::fs::create_dir_all(&log_dir);
    let log_path = log_dir.join(format!("security_audit_{}.jsonl", current_date_compact()));

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
        if let Err(e) = writeln!(file, "{}", line) {
            eprintln!("[audit] Failed to write log: {}", e);
        }
    } else {
        eprintln!("[audit] Failed to open log file: {}", log_path.display());
    }
}

/// 格式化事件为 JSONL 行
///  Format event as JSONL line
fn format_event(timestamp: &str, svc_pid: u32, event: &AuditEvent) -> String {
    match event {
        AuditEvent::IpcConnect {
            pid,
            path,
            sid,
            session,
            integrity,
            verdict,
        } => {
            format!(
                r#"{{"ts":"{}","svc_pid":{},"event":"IPC_CONNECT","pid":{},"path":"{}","sid":"{}","session":{},"integrity":"{}","verdict":"{}"}}"#,
                timestamp,
                svc_pid,
                pid,
                mask_path(path),
                mask_sid(sid),
                session,
                integrity,
                verdict
            )
        }
        AuditEvent::IpcConnectRejected { pid, reason } => {
            format!(
                r#"{{"ts":"{}","svc_pid":{},"event":"IPC_CONNECT_REJECTED","pid":{},"reason":"{}"}}"#,
                timestamp, svc_pid, pid, reason
            )
        }
        AuditEvent::ElevationRequested {
            pid,
            request_id,
            ttl_ms,
        } => {
            format!(
                r#"{{"ts":"{}","svc_pid":{},"event":"ELEVATION_REQUESTED","pid":{},"request_id":"{}","ttl_ms":{}}}"#,
                timestamp, svc_pid, pid, request_id, ttl_ms
            )
        }
        AuditEvent::ElevationConfirmed {
            pid,
            helper_pid,
            request_id,
        } => {
            format!(
                r#"{{"ts":"{}","svc_pid":{},"event":"ELEVATION_CONFIRMED","pid":{},"helper_pid":{},"request_id":"{}"}}"#,
                timestamp, svc_pid, pid, helper_pid, request_id
            )
        }
        AuditEvent::ElevationExpired { pid, request_id } => {
            format!(
                r#"{{"ts":"{}","svc_pid":{},"event":"ELEVATION_EXPIRED","pid":{},"request_id":"{}"}}"#,
                timestamp, svc_pid, pid, request_id
            )
        }
        AuditEvent::ElevatedOpExecuted { pid, method } => {
            format!(
                r#"{{"ts":"{}","svc_pid":{},"event":"ELEVATED_OP_EXECUTED","pid":{},"method":"{}"}}"#,
                timestamp, svc_pid, pid, method
            )
        }
        AuditEvent::ElevatedOpDenied {
            pid,
            method,
            reason,
        } => {
            format!(
                r#"{{"ts":"{}","svc_pid":{},"event":"ELEVATED_OP_DENIED","pid":{},"method":"{}","reason":"{}"}}"#,
                timestamp, svc_pid, pid, method, reason
            )
        }
        AuditEvent::IdentityCheckFailed {
            pid,
            method,
            reason,
        } => {
            format!(
                r#"{{"ts":"{}","svc_pid":{},"event":"IDENTITY_CHECK_FAILED","pid":{},"method":"{}","reason":"{}"}}"#,
                timestamp, svc_pid, pid, method, reason
            )
        }
    }
}

/// 路径脱敏：仅保留文件名 + 哈希前 8 位
///  Path masking: keep only filename + hash prefix 8 chars
fn mask_path(path: &str) -> String {
    let p = Path::new(path);
    let filename = p
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<unknown>");
    // 简单哈希（非加密强度，仅用于日志区分）
    let mut hash: u64 = 5381;
    for c in path.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(c as u64);
    }
    format!("{}_{:08x}", filename, hash & 0xFFFF_FFFF)
}

/// SID 脱敏：仅保留前 3 段 + 最后 1 段
///  SID masking: keep only first 3 segments + last 1 segment
fn mask_sid(sid: &str) -> String {
    let parts: Vec<&str> = sid.split('-').collect();
    if parts.len() >= 5 {
        format!("{}-***-{}", parts[..3].join("-"), parts.last().unwrap())
    } else {
        "***".to_string()
    }
}

/// 解析审计日志目录
///  Resolve audit log directory
fn resolve_audit_dir() -> PathBuf {
    std::env::var("APPDATA")
        .map(|p| PathBuf::from(p).join("AnXinSecurity").join("audit"))
        .unwrap_or_else(|_| PathBuf::from("logs/audit"))
}

fn current_rfc3339() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    format!("{}.{:03}Z", secs, millis)
}

fn current_date_compact() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = now / 86400;
    let (year, month, day) = days_to_ymd(days);
    format!("{:04}{:02}{:02}", year, month, day)
}

/// Unix 天数转年月日（简化算法，适用于 1970-2100）
///  Unix days to year-month-day (simplified, valid 1970-2100)
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    let mut remaining = days;
    let mut year = 1970u32;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }
    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u32;
    for &md in &month_days {
        let actual_days = if month == 2 && is_leap_year(year) {
            29
        } else {
            md
        };
        if remaining < actual_days {
            break;
        }
        remaining -= actual_days;
        month += 1;
    }
    (year, month, (remaining + 1) as u32)
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_path_returns_filename_and_hash() {
        let masked = mask_path("C:\\Program Files\\AnXinSecurity\\anxin-security.exe");
        assert!(masked.starts_with("anxin-security.exe_"));
        // 格式为 filename_8位十六进制，长度应为 19 + 8 = 27
        assert_eq!(masked.len(), "anxin-security.exe_".len() + 8);
    }

    #[test]
    fn mask_path_handles_unknown() {
        let masked = mask_path("");
        assert!(masked.starts_with("<unknown>_"));
    }

    #[test]
    fn mask_sid_masks_middle_parts() {
        let masked = mask_sid("S-1-5-21-123456789-987654321-1000");
        assert!(masked.starts_with("S-1-5-"));
        assert!(masked.ends_with("-1000"));
        assert!(masked.contains("***"));
    }

    #[test]
    fn mask_sid_handles_short_sid() {
        let masked = mask_sid("S-1-5");
        assert_eq!(masked, "***");
    }

    #[test]
    fn is_leap_year_correct() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2023));
    }

    #[test]
    fn days_to_ymd_correct_for_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_correct_for_2024() {
        // 2024-01-01 是 Unix 第 19723 天
        let (y, m, d) = days_to_ymd(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    #[test]
    fn resolve_audit_dir_uses_appdata() {
        let dir = resolve_audit_dir();
        // 应该以 audit 结尾
        assert!(dir.ends_with("audit"));
    }

    #[test]
    fn format_ipc_connect_event_contains_required_fields() {
        let event = AuditEvent::IpcConnect {
            pid: 1234,
            path: "C:\\anxin-security.exe".to_string(),
            sid: "S-1-5-21-123-1000".to_string(),
            session: 1,
            integrity: "medium".to_string(),
            verdict: "ACCEPT",
        };
        let line = format_event("2026-07-23T10:00:00Z", 9999, &event);
        assert!(line.contains("\"event\":\"IPC_CONNECT\""));
        assert!(line.contains("\"pid\":1234"));
        assert!(line.contains("\"verdict\":\"ACCEPT\""));
        // 脱敏检查
        assert!(!line.contains("C:\\anxin-security.exe"));
        assert!(line.contains("anxin-security.exe_"));
    }
}
