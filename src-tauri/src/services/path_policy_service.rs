use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::Path;

use crate::services::runtime_list_store::load_runtime_list;

pub const ALLOWLIST_RUNTIME_FILE: &str = "startup_allowlist.json";
pub const ALLOWLIST_LEGACY_FIELD: &str = "startupAllowlist";
pub const EXCLUSIONS_RUNTIME_FILE: &str = "exclusions.json";
pub const EXCLUSIONS_LEGACY_FIELD: &str = "exclusions";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistEntry {
    pub path: String,
    pub hash: Option<String>,
    pub description: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionEntry {
    pub path: String,
    pub entry_type: String,
    pub description: Option<String>,
    pub created_at: String,
}

/// 函数名称：load_allowlist_entries
/// 函数作用：从运行时允许列表读取当前可信路径，供设置页命令、扫描入口和监控服务共享。
/// Function name: load_allowlist_entries
/// Purpose: Loads trusted paths from the runtime allowlist for settings commands, scan entry points, and monitoring services.
/// 调用方：commands::allowlist、is_allowed_path、should_skip_security_scan。
/// Called by: commands::allowlist, is_allowed_path, should_skip_security_scan.
/// 被调用方：runtime_list_store::load_runtime_list。
/// Calls: runtime_list_store::load_runtime_list.
/// 参数说明：无参数。
/// Parameters: No parameters.
/// 返回值说明：成功返回允许列表；运行时文件损坏时返回 String 错误。
/// Returns: Allowlist entries on success; String error when the runtime file is damaged.
/// 内部关键变量：无。
/// Internal variables: None.
/// 接入方式：仅用于运行时策略读取；不要从业务路径直接读取 config/app.json 可变字段。
/// Integration: Use for runtime policy reads; business paths should not read mutable config/app.json fields directly.
/// 错误处理：向上返回运行时列表读取错误。
/// Error handling: Propagates runtime list read errors.
/// 副作用：首次迁移旧字段时底层可能写 APPDATA runtime 文件。
/// Side effects: The underlying migration may write APPDATA runtime files on first legacy read.
/// 事务边界：无 Unit of Work；无数据库事务。
/// Transaction boundary: No Unit of Work and no database transaction.
/// 并发与幂等：读取可重复；并发写入一致性由 runtime_list_store 边界承担。
/// Concurrency and idempotency: Repeatable reads; concurrent write consistency is bounded by runtime_list_store.
/// 中文关键词：允许列表，信任列表，运行时策略，扫描生效，监控生效，APPDATA，路径策略，启动允许，配置拆分，实时读取
/// English keywords: allowlist, trust list, runtime policy, scan effective, monitor effective, APPDATA, path policy, startup allow, config split, live read
pub fn load_allowlist_entries() -> Result<Vec<AllowlistEntry>, String> {
    load_runtime_list(ALLOWLIST_RUNTIME_FILE, ALLOWLIST_LEGACY_FIELD)
}

/// 函数名称：load_exclusion_entries
/// 函数作用：从运行时排除项读取当前排除路径，供设置页命令、扫描入口和监控服务共享。
/// Function name: load_exclusion_entries
/// Purpose: Loads excluded paths from runtime exclusions for settings commands, scan entry points, and monitoring services.
/// 调用方：commands::exclusions、is_excluded_path、should_skip_security_scan。
/// Called by: commands::exclusions, is_excluded_path, should_skip_security_scan.
/// 被调用方：runtime_list_store::load_runtime_list。
/// Calls: runtime_list_store::load_runtime_list.
/// 参数说明：无参数。
/// Parameters: No parameters.
/// 返回值说明：成功返回排除项；运行时文件损坏时返回 String 错误。
/// Returns: Exclusion entries on success; String error when the runtime file is damaged.
/// 内部关键变量：无。
/// Internal variables: None.
/// 接入方式：扫描和监控路径判断必须通过本函数间接读取排除项。
/// Integration: Scan and monitor path checks should read exclusions through this function.
/// 错误处理：向上返回运行时列表读取错误。
/// Error handling: Propagates runtime list read errors.
/// 副作用：首次迁移旧字段时底层可能写 APPDATA runtime 文件。
/// Side effects: The underlying migration may write APPDATA runtime files on first legacy read.
/// 事务边界：无 Unit of Work；无数据库事务。
/// Transaction boundary: No Unit of Work and no database transaction.
/// 并发与幂等：读取可重复；并发写入一致性由 runtime_list_store 边界承担。
/// Concurrency and idempotency: Repeatable reads; concurrent write consistency is bounded by runtime_list_store.
/// 中文关键词：排除项，运行时策略，扫描排除，监控排除，APPDATA，路径策略，配置拆分，实时读取，目录匹配，文件匹配
/// English keywords: exclusions, runtime policy, scan exclusion, monitor exclusion, APPDATA, path policy, config split, live read, directory match, file match
pub fn load_exclusion_entries() -> Result<Vec<ExclusionEntry>, String> {
    load_runtime_list(EXCLUSIONS_RUNTIME_FILE, EXCLUSIONS_LEGACY_FIELD)
}

/// 函数名称：should_skip_security_scan
/// 函数作用：判断给定路径是否因排除项或允许列表而应跳过扫描/监控处置。
/// Function name: should_skip_security_scan
/// Purpose: Determines whether a path should be skipped by scan or monitor handling because it matches exclusions or the allowlist.
/// 调用方：commands::scanner::scan_file、commands::scanner::scan_batch、process_scanner_service、file_monitor_service、process_monitor_service、snapshot_service。
/// Called by: commands::scanner::scan_file, commands::scanner::scan_batch, process_scanner_service, file_monitor_service, process_monitor_service, snapshot_service.
/// 被调用方：is_excluded_path、is_allowed_path。
/// Calls: is_excluded_path, is_allowed_path.
/// 参数说明：path 为待检查的文件或进程路径，不可为空。
/// Parameters: path is the file or process path to check and must not be empty.
/// 返回值说明：Result<bool, String>；true 表示应跳过，false 表示继续扫描/监控。
/// Returns: Result<bool, String>; true means skip, false means continue scanning or monitoring.
/// 内部关键变量：excluded 表示排除项命中结果。
/// Internal variables: excluded stores exclusion match result.
/// 接入方式：业务入口在调用扫描引擎、签名拦截或注入前调用。
/// Integration: Business entry points call this before invoking scan engines, signature interception, or injection.
/// 错误处理：运行时列表读取错误向上返回；调用方决定记录日志或返回前端。
/// Error handling: Runtime list read errors propagate; callers decide whether to log or return to frontend.
/// 副作用：允许列表哈希匹配时可能读取文件计算 SHA-256。
/// Side effects: Allowlist hash matching may read the file to compute SHA-256.
/// 事务边界：无 Unit of Work；无数据库事务。
/// Transaction boundary: No Unit of Work and no database transaction.
/// 并发与幂等：同一列表和文件内容下结果稳定；列表变化后下一次调用即可生效。
/// Concurrency and idempotency: Stable for the same lists and file content; list changes take effect on the next call.
/// 中文关键词：跳过扫描，跳过监控，排除项生效，允许列表生效，扫描策略，进程策略，文件策略，实时保护，路径匹配，哈希匹配
/// English keywords: skip scan, skip monitor, exclusion effective, allowlist effective, scan policy, process policy, file policy, realtime protection, path match, hash match
pub fn should_skip_security_scan(path: &str) -> Result<bool, String> {
    if is_excluded_path(path)? {
        return Ok(true);
    }
    is_allowed_path(path)
}

/// 函数名称：is_excluded_path
/// 函数作用：判断路径是否命中运行时排除项，支持文件精确匹配、目录前缀匹配和进程名匹配。
/// Function name: is_excluded_path
/// Purpose: Checks whether a path matches runtime exclusions, supporting exact file, directory prefix, and process-name matching.
/// 调用方：should_skip_security_scan。
/// Called by: should_skip_security_scan.
/// 被调用方：load_exclusion_entries、matches_exclusion、normalize_path、file_name_lower。
/// Calls: load_exclusion_entries, matches_exclusion, normalize_path, file_name_lower.
/// 参数说明：path 为待检查路径。
/// Parameters: path is the path to check.
/// 返回值说明：命中排除项返回 true，否则 false。
/// Returns: true on exclusion hit, otherwise false.
/// 内部关键变量：normalized_path 为标准化路径；file_name 为小写文件名。
/// Internal variables: normalized_path is the canonical path; file_name is lowercase basename.
/// 接入方式：由 should_skip_security_scan 调用。
/// Integration: Called by should_skip_security_scan.
/// 错误处理：运行时列表读取错误向上返回。
/// Error handling: Propagates runtime list read errors.
/// 副作用：无直接写入；可能触发旧配置迁移读取。
/// Side effects: No direct writes; may trigger legacy migration reads.
/// 事务边界：无 Unit of Work。
/// Transaction boundary: No Unit of Work.
/// 并发与幂等：列表不变时结果稳定。
/// Concurrency and idempotency: Stable when the list does not change.
/// 中文关键词：排除匹配，目录排除，文件排除，进程排除，路径标准化，扫描跳过，监控跳过，运行时排除，设置页，实时生效
/// English keywords: exclusion match, directory exclusion, file exclusion, process exclusion, path normalization, scan skip, monitor skip, runtime exclusion, settings page, live effect
pub fn is_excluded_path(path: &str) -> Result<bool, String> {
    let normalized_path = normalize_path(path);
    let file_name = file_name_lower(path);
    let exclusions = load_exclusion_entries()?;
    Ok(exclusions
        .iter()
        .any(|entry| matches_exclusion(entry, &normalized_path, file_name.as_deref())))
}

/// 函数名称：is_allowed_path
/// 函数作用：判断路径是否命中运行时允许列表，支持路径精确匹配和 SHA-256 哈希匹配。
/// Function name: is_allowed_path
/// Purpose: Checks whether a path matches the runtime allowlist by exact path or SHA-256 hash.
/// 调用方：should_skip_security_scan。
/// Called by: should_skip_security_scan.
/// 被调用方：load_allowlist_entries、normalize_path、sha256_hex_of_file。
/// Calls: load_allowlist_entries, normalize_path, sha256_hex_of_file.
/// 参数说明：path 为待检查路径。
/// Parameters: path is the path to check.
/// 返回值说明：命中允许列表返回 true，否则 false。
/// Returns: true on allowlist hit, otherwise false.
/// 内部关键变量：normalized_path 为标准化路径；file_hash 缓存当前文件哈希。
/// Internal variables: normalized_path is the canonical path; file_hash caches the current file hash.
/// 接入方式：由 should_skip_security_scan 调用。
/// Integration: Called by should_skip_security_scan.
/// 错误处理：运行时列表读取错误向上返回；哈希计算失败仅导致哈希匹配不可用，不阻断路径匹配。
/// Error handling: Runtime list read errors propagate; hash failures only disable hash matching.
/// 副作用：可能读取目标文件计算 SHA-256。
/// Side effects: May read the target file to compute SHA-256.
/// 事务边界：无 Unit of Work。
/// Transaction boundary: No Unit of Work.
/// 并发与幂等：列表和文件内容不变时结果稳定。
/// Concurrency and idempotency: Stable when the list and file content do not change.
/// 中文关键词：允许匹配，信任匹配，哈希匹配，路径匹配，启动允许列表，扫描跳过，监控跳过，运行时允许，设置页，实时生效
/// English keywords: allow match, trust match, hash match, path match, startup allowlist, scan skip, monitor skip, runtime allow, settings page, live effect
pub fn is_allowed_path(path: &str) -> Result<bool, String> {
    let normalized_path = normalize_path(path);
    let allowlist = load_allowlist_entries()?;
    let mut file_hash: Option<String> = None;

    for entry in allowlist {
        if normalize_path(&entry.path) == normalized_path {
            return Ok(true);
        }

        let Some(entry_hash) = entry.hash.as_deref().filter(|value| !value.is_empty()) else {
            continue;
        };

        if file_hash.is_none() {
            file_hash = sha256_hex_of_file(path).ok();
        }

        if file_hash
            .as_deref()
            .is_some_and(|current_hash| current_hash.eq_ignore_ascii_case(entry_hash))
        {
            return Ok(true);
        }
    }

    Ok(false)
}

fn matches_exclusion(
    entry: &ExclusionEntry,
    normalized_path: &str,
    file_name: Option<&str>,
) -> bool {
    let excluded_path = normalize_path(&entry.path);
    match entry.entry_type.as_str() {
        "directory" => is_under_directory(normalized_path, &excluded_path),
        "process" => {
            let excluded_file_name = file_name_lower(&entry.path);
            normalized_path == excluded_path
                || file_name.is_some_and(|name| name == entry.path.to_ascii_lowercase())
                || file_name.is_some_and(|name| excluded_file_name.as_deref() == Some(name))
        }
        _ => normalized_path == excluded_path,
    }
}

fn is_under_directory(path: &str, directory: &str) -> bool {
    path == directory || path.starts_with(&format!("{}\\", directory))
}

fn normalize_path(path: &str) -> String {
    let mut normalized: String = path
        .trim()
        .chars()
        .map(|ch| {
            if ch == '/' {
                '\\'
            } else {
                ch.to_ascii_lowercase()
            }
        })
        .collect();
    if normalized.starts_with("\\\\?\\") {
        normalized = normalized[4..].to_string();
    }
    if normalized.starts_with("\\??\\") {
        normalized = normalized[4..].to_string();
    }
    while normalized.ends_with('\\') && normalized.len() > 3 {
        normalized.pop();
    }
    normalized
}

fn file_name_lower(path: &str) -> Option<String> {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_ascii_lowercase())
}

fn sha256_hex_of_file(path: &str) -> Result<String, String> {
    let bytes = std::fs::read(path)
        .map_err(|err| format!("Failed to read file for allowlist hash: {}", err))?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_exclusion_matches_children_only() {
        let entry = ExclusionEntry {
            path: r"C:\Safe\Folder".to_string(),
            entry_type: "directory".to_string(),
            description: None,
            created_at: "2026-05-03T00:00:00Z".to_string(),
        };

        assert!(matches_exclusion(
            &entry,
            &normalize_path(r"C:\Safe\Folder\app.exe"),
            Some("app.exe")
        ));
        assert!(matches_exclusion(
            &entry,
            &normalize_path(r"C:\Safe\Folder"),
            None
        ));
        assert!(!matches_exclusion(
            &entry,
            &normalize_path(r"C:\Safe\Folder2\app.exe"),
            Some("app.exe")
        ));
    }

    #[test]
    fn file_exclusion_requires_exact_normalized_path() {
        let entry = ExclusionEntry {
            path: r"C:/Safe/App.exe".to_string(),
            entry_type: "file".to_string(),
            description: None,
            created_at: "2026-05-03T00:00:00Z".to_string(),
        };

        assert!(matches_exclusion(
            &entry,
            &normalize_path(r"c:\safe\app.exe"),
            Some("app.exe")
        ));
        assert!(!matches_exclusion(
            &entry,
            &normalize_path(r"c:\safe\app.exe.bak"),
            Some("app.exe.bak")
        ));
    }
}
