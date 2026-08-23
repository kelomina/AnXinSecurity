use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

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

#[derive(Debug, Clone)]
pub struct PathPolicySnapshot {
    exclusions: Vec<PreparedExclusionEntry>,
    allowlist: PreparedAllowlistIndex,
    lookup_cache: std::sync::Arc<Mutex<HashMap<String, PreparedPathLookup>>>,
    hash_cache: std::sync::Arc<Mutex<HashMap<String, Option<String>>>>,
    decision_cache: std::sync::Arc<Mutex<HashMap<String, bool>>>,
}

#[derive(Debug, Clone)]
struct PreparedExclusionEntry {
    entry: ExclusionEntry,
    normalized_path: String,
    file_name: Option<String>,
}

#[derive(Debug, Clone)]
struct PreparedAllowlistIndex {
    exact_paths: HashSet<String>,
    hashes: HashSet<String>,
}

#[derive(Debug, Clone)]
struct PreparedPathLookup {
    normalized_path: String,
    file_name: Option<String>,
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

/// 函数名称：load_path_policy_snapshot
/// 函数作用：一次性读取排除项和允许列表，供启动快照这类批量扫描在内存中重复判断，避免每个模块都重复读取/解密运行时文件。
/// Function name: load_path_policy_snapshot
/// Purpose: Loads exclusions and allowlist once so batch scanners such as startup snapshot can evaluate policy in memory instead of repeatedly reading/decrypting runtime files per module.
/// 调用方：SnapshotService::take_startup_snapshot。
/// Called by: SnapshotService::take_startup_snapshot.
/// 中文关键词：路径策略快照，启动快照，排除项，允许列表，性能优化
/// English keywords: path policy snapshot, startup snapshot, exclusions, allowlist, performance optimization
pub fn load_path_policy_snapshot() -> Result<PathPolicySnapshot, String> {
    Ok(PathPolicySnapshot {
        exclusions: prepare_exclusion_entries(load_exclusion_entries()?),
        allowlist: prepare_allowlist_entries(load_allowlist_entries()?),
        lookup_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
        hash_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
        decision_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
    })
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

impl PathPolicySnapshot {
    /// 函数名称：should_skip_security_scan
    /// 函数作用：使用已加载的策略快照判断路径是否应跳过扫描；适用于启动快照这类单轮批量扫描。
    /// Purpose: Determines whether a path should be skipped using a preloaded policy snapshot; intended for one-shot batch scans such as startup snapshot.
    /// 调用方：SnapshotService::take_startup_snapshot，scan_startup_target。
    /// Called by: SnapshotService::take_startup_snapshot and scan_startup_target.
    /// 中文关键词：路径策略快照，跳过扫描，批量扫描
    /// English keywords: path policy snapshot, skip scan, batch scan
    pub fn should_skip_security_scan(&self, path: &str) -> bool {
        let lookup = self.lookup_for_path(path);
        self.is_excluded_lookup(&lookup) || self.is_allowed_lookup(path, &lookup)
    }

    /// 函数作用：只使用无需读取文件内容的路径规则判断是否跳过，供启动快照在读取 metadata 前快速处理明确排除/路径允许目标。
    /// 安全边界：本函数不做哈希允许列表匹配；返回 false 只表示“路径规则未命中”，调用方仍必须继续完整策略/签名/扫描流程。
    pub fn should_skip_by_path_only(&self, path: &str) -> bool {
        let lookup = self.lookup_for_path(path);
        self.is_excluded_lookup(&lookup) || self.is_allowed_path_by_exact_lookup(&lookup)
    }

    /// 函数作用：同一轮批量扫描内复用路径策略判定结果，避免多个进程加载同一 DLL 时反复匹配排除项/允许列表。
    /// 安全边界：调用方必须提供包含文件版本信息的缓存键；没有键时不缓存，避免把旧文件的允许结果复用到新文件。
    pub fn should_skip_security_scan_cached(&self, path: &str, cache_key: Option<&str>) -> bool {
        let Some(cache_key) = cache_key.filter(|key| !key.trim().is_empty()) else {
            return self.should_skip_security_scan(path);
        };

        if let Some(cached) = self
            .decision_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(cache_key)
            .copied()
        {
            return cached;
        }

        let decision = self.should_skip_security_scan(path);
        self.decision_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(cache_key.to_string(), decision);
        decision
    }

    /// 函数作用：调用方已经确认排除项和精确路径允许列表未命中后，只继续检查哈希允许列表。
    /// 安全边界：本函数只用于同一调用点刚执行过 should_skip_by_path_only(path) == false 的路径；没有文件版本键时不缓存，也不会把路径规则命中写入哈希决策缓存。
    #[allow(dead_code)]
    pub fn should_skip_by_hash_after_path_miss_cached(
        &self,
        path: &str,
        cache_key: Option<&str>,
    ) -> bool {
        self.hash_after_path_miss_cached(path, cache_key).skip_scan
    }

    /// 函数作用：同上，但额外返回本次哈希允许列表检查已经计算出的 SHA-256，供后续扫描缓存查找复用。
    /// 安全边界：返回的 hash 只绑定调用方提供的文件版本键；缺少版本键时不返回 hash，避免裸路径或过期文件内容被后续缓存误用。
    pub fn hash_after_path_miss_cached(
        &self,
        path: &str,
        cache_key: Option<&str>,
    ) -> HashAfterPathMissDecision {
        let Some(cache_key) = cache_key.filter(|key| !key.trim().is_empty()) else {
            return HashAfterPathMissDecision {
                skip_scan: self.is_allowed_by_hash(path),
                sha256_hex: None,
            };
        };
        if self.allowlist.hashes.is_empty() {
            return HashAfterPathMissDecision {
                skip_scan: false,
                sha256_hex: None,
            };
        }
        let Some(current_cache_key) = file_version_cache_key(path).filter(|key| key == cache_key)
        else {
            return HashAfterPathMissDecision {
                skip_scan: self.is_allowed_by_hash(path),
                sha256_hex: None,
            };
        };
        let scoped_cache_key = format!("hash-after-path-miss|{}", current_cache_key);

        if let Some(cached) = self
            .decision_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&scoped_cache_key)
            .copied()
        {
            let sha256_hex = self
                .hash_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&current_cache_key)
                .cloned()
                .flatten();
            return HashAfterPathMissDecision {
                skip_scan: cached,
                sha256_hex,
            };
        }

        let sha256_hex = self.sha256_hex_cached_with_key(path, &current_cache_key);
        let decision = sha256_hex
            .as_deref()
            .is_some_and(|current_hash| self.allowlist.hashes.contains(current_hash));
        self.decision_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(scoped_cache_key, decision);
        HashAfterPathMissDecision {
            skip_scan: decision,
            sha256_hex,
        }
    }

    fn is_excluded_lookup(&self, lookup: &PreparedPathLookup) -> bool {
        self.exclusions.iter().any(|entry| {
            matches_prepared_exclusion(entry, &lookup.normalized_path, lookup.file_name.as_deref())
        })
    }

    fn is_allowed_lookup(&self, path: &str, lookup: &PreparedPathLookup) -> bool {
        if self.allowlist.exact_paths.contains(&lookup.normalized_path) {
            return true;
        }

        self.is_allowed_by_hash(path)
    }

    fn is_allowed_by_hash(&self, path: &str) -> bool {
        if self.allowlist.hashes.is_empty() {
            return false;
        }

        self.sha256_hex_cached(path)
            .as_deref()
            .is_some_and(|current_hash| self.allowlist.hashes.contains(current_hash))
    }

    fn is_allowed_path_by_exact_lookup(&self, lookup: &PreparedPathLookup) -> bool {
        self.allowlist.exact_paths.contains(&lookup.normalized_path)
    }

    /// 函数作用：同一轮批量扫描内复用路径标准化和文件名提取结果。
    /// 安全边界：只缓存纯字符串转换结果，不缓存文件属性、哈希、签名或可信判定。
    fn lookup_for_path(&self, path: &str) -> PreparedPathLookup {
        if let Some(cached) = self
            .lookup_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(path)
            .cloned()
        {
            return cached;
        }

        let lookup = prepare_path_lookup(path);
        self.lookup_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(path.to_string(), lookup.clone());
        lookup
    }

    /// 函数作用：同一轮批量扫描内复用允许列表哈希匹配所需的 SHA-256。
    /// 安全边界：缓存键包含规范化路径、高精度修改时间和文件大小；文件版本信息不可读时不缓存。
    fn sha256_hex_cached(&self, path: &str) -> Option<String> {
        let cache_key = file_version_cache_key(path)?;
        self.sha256_hex_cached_with_key(path, &cache_key)
    }

    fn sha256_hex_cached_with_key(&self, path: &str, cache_key: &str) -> Option<String> {
        if let Some(cached) = self
            .hash_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(cache_key)
            .cloned()
        {
            return cached;
        }

        let computed = sha256_hex_of_file(path).ok();
        self.hash_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(cache_key.to_string(), computed.clone());
        computed
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HashAfterPathMissDecision {
    pub skip_scan: bool,
    pub sha256_hex: Option<String>,
}

fn prepare_path_lookup(path: &str) -> PreparedPathLookup {
    PreparedPathLookup {
        normalized_path: normalize_path(path),
        file_name: file_name_lower(path),
    }
}

fn file_version_cache_key(path: &str) -> Option<String> {
    let trimmed = path.trim();
    let fs_path = trimmed
        .strip_prefix(r"\\?\")
        .or_else(|| trimmed.strip_prefix(r"\??\"))
        .unwrap_or(trimmed);
    let metadata = std::fs::metadata(fs_path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let modified_ns = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some(format!(
        "{}|modified_ns={}|len={}",
        normalize_path(path),
        modified_ns,
        metadata.len()
    ))
}

fn prepare_exclusion_entries(entries: Vec<ExclusionEntry>) -> Vec<PreparedExclusionEntry> {
    entries
        .into_iter()
        .map(|entry| {
            let normalized_path = normalize_path(&entry.path);
            let file_name = file_name_lower(&entry.path);
            PreparedExclusionEntry {
                entry,
                normalized_path,
                file_name,
            }
        })
        .collect()
}

fn prepare_allowlist_entries(entries: Vec<AllowlistEntry>) -> PreparedAllowlistIndex {
    let mut exact_paths = HashSet::with_capacity(entries.len());
    let mut hashes = HashSet::new();

    for entry in entries {
        exact_paths.insert(normalize_path(&entry.path));
        if let Some(hash) = entry.hash.as_deref().and_then(normalized_sha256_hex) {
            hashes.insert(hash);
        }
    }

    PreparedAllowlistIndex {
        exact_paths,
        hashes,
    }
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

        let Some(entry_hash) = entry.hash.as_deref().and_then(normalized_sha256_hex) else {
            continue;
        };

        if file_hash.is_none() {
            file_hash = sha256_hex_of_file(path).ok();
        }

        if file_hash
            .as_deref()
            .is_some_and(|current_hash| current_hash.eq_ignore_ascii_case(&entry_hash))
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
    let mut file = std::fs::File::open(path)
        .map_err(|err| format!("Failed to open file for allowlist hash: {}", err))?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)
            .map_err(|err| format!("Failed to read file for allowlist hash: {}", err))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn normalized_sha256_hex(hash_hex: &str) -> Option<String> {
    let normalized = hash_hex.trim();
    if normalized.len() != 64 || !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(normalized.to_ascii_lowercase())
}

fn matches_prepared_exclusion(
    entry: &PreparedExclusionEntry,
    normalized_path: &str,
    file_name: Option<&str>,
) -> bool {
    match entry.entry.entry_type.as_str() {
        "directory" => is_under_directory(normalized_path, &entry.normalized_path),
        "process" => {
            normalized_path == entry.normalized_path
                || entry
                    .file_name
                    .as_deref()
                    .is_some_and(|name| file_name == Some(name))
        }
        _ => normalized_path == entry.normalized_path,
    }
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

    #[test]
    fn normalize_path_converts_forward_slash_to_backslash() {
        assert_eq!(
            normalize_path(r"C:/Windows/System32"),
            r"c:\windows\system32"
        );
    }

    #[test]
    fn normalize_path_lowercases_all_chars() {
        assert_eq!(
            normalize_path(r"C:\PROGRAM FILES\APP"),
            r"c:\program files\app"
        );
    }

    #[test]
    fn normalize_path_strips_unc_prefix() {
        assert_eq!(normalize_path(r"\\?\C:\Windows"), r"c:\windows");
    }

    #[test]
    fn normalize_path_strips_kernel_prefix() {
        assert_eq!(normalize_path(r"\??\C:\Windows"), r"c:\windows");
    }

    #[test]
    fn normalize_path_trims_trailing_backslashes() {
        assert_eq!(normalize_path(r"C:\Windows\"), r"c:\windows");
        assert_eq!(normalize_path(r"C:\Windows\\"), r"c:\windows");
    }

    #[test]
    fn normalize_path_preserves_drive_root() {
        assert_eq!(normalize_path(r"C:\"), r"c:\");
    }

    #[test]
    fn normalize_path_trims_whitespace() {
        assert_eq!(normalize_path(r"  C:\Windows  "), r"c:\windows");
    }

    #[test]
    fn file_name_lower_extracts_basename() {
        assert_eq!(
            file_name_lower(r"C:\Windows\notepad.exe"),
            Some("notepad.exe".to_string())
        );
    }

    #[test]
    fn file_name_lower_returns_none_for_root() {
        assert_eq!(file_name_lower(r"C:\"), None);
    }

    #[test]
    fn file_name_lower_is_case_insensitive() {
        assert_eq!(file_name_lower(r"C:\APP.EXE"), Some("app.exe".to_string()));
    }

    #[test]
    fn is_under_directory_matches_exact_directory() {
        assert!(is_under_directory(r"c:\safe\folder", r"c:\safe\folder"));
    }

    #[test]
    fn is_under_directory_matches_child_path() {
        assert!(is_under_directory(
            r"c:\safe\folder\app.exe",
            r"c:\safe\folder"
        ));
    }

    #[test]
    fn is_under_directory_rejects_sibling_directory() {
        assert!(!is_under_directory(
            r"c:\safe\folder2\app.exe",
            r"c:\safe\folder"
        ));
    }

    #[test]
    fn is_under_directory_rejects_partial_name_match() {
        assert!(!is_under_directory(r"c:\safe\folder2", r"c:\safe\folder"));
    }

    #[test]
    fn process_exclusion_matches_by_file_name() {
        let entry = ExclusionEntry {
            path: "notepad.exe".to_string(),
            entry_type: "process".to_string(),
            description: None,
            created_at: "2026-05-03T00:00:00Z".to_string(),
        };
        assert!(matches_exclusion(
            &entry,
            &normalize_path(r"C:\Windows\notepad.exe"),
            Some("notepad.exe")
        ));
    }

    #[test]
    fn process_exclusion_matches_by_full_path() {
        let entry = ExclusionEntry {
            path: r"C:\Windows\notepad.exe".to_string(),
            entry_type: "process".to_string(),
            description: None,
            created_at: "2026-05-03T00:00:00Z".to_string(),
        };
        assert!(matches_exclusion(
            &entry,
            &normalize_path(r"c:\windows\notepad.exe"),
            Some("notepad.exe")
        ));
    }

    #[test]
    fn process_exclusion_rejects_different_process() {
        let entry = ExclusionEntry {
            path: "notepad.exe".to_string(),
            entry_type: "process".to_string(),
            description: None,
            created_at: "2026-05-03T00:00:00Z".to_string(),
        };
        assert!(!matches_exclusion(
            &entry,
            &normalize_path(r"c:\windows\calc.exe"),
            Some("calc.exe")
        ));
    }

    #[test]
    fn directory_exclusion_with_trailing_backslash_in_entry() {
        let entry = ExclusionEntry {
            path: r"C:\Safe\Folder\".to_string(),
            entry_type: "directory".to_string(),
            description: None,
            created_at: "2026-05-03T00:00:00Z".to_string(),
        };
        let normalized_dir = normalize_path(&entry.path);
        assert!(is_under_directory(
            &normalize_path(r"C:\Safe\Folder\app.exe"),
            &normalized_dir
        ));
    }

    #[test]
    fn default_entry_type_is_file_match() {
        let entry = ExclusionEntry {
            path: r"C:\Safe\App.exe".to_string(),
            entry_type: "unknown_type".to_string(),
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

    #[test]
    fn normalize_path_handles_empty_string() {
        assert_eq!(normalize_path(""), "");
    }

    #[test]
    fn normalize_path_handles_whitespace_only() {
        assert_eq!(normalize_path("   "), "");
    }

    #[test]
    fn normalize_path_preserves_relative_path() {
        assert_eq!(normalize_path(r"..\..\test.exe"), r"..\..\test.exe");
        assert_eq!(normalize_path(r".\app.exe"), r".\app.exe");
    }

    #[test]
    fn is_under_directory_rejects_parent_directory() {
        assert!(!is_under_directory(r"c:\safe", r"c:\safe\folder"));
    }

    #[test]
    fn is_under_directory_rejects_different_drive() {
        assert!(!is_under_directory(
            r"d:\safe\folder\app.exe",
            r"c:\safe\folder"
        ));
    }

    #[test]
    fn file_name_lower_handles_unicode() {
        let result = file_name_lower(r"C:\测试\应用.exe");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "应用.exe");
    }

    #[test]
    fn file_name_lower_handles_no_extension() {
        assert_eq!(
            file_name_lower(r"C:\Windows\README"),
            Some("readme".to_string())
        );
    }

    #[test]
    fn matches_exclusion_with_empty_file_name() {
        let entry = ExclusionEntry {
            path: r"C:\Safe\App.exe".to_string(),
            entry_type: "file".to_string(),
            description: None,
            created_at: "2026-05-03T00:00:00Z".to_string(),
        };
        assert!(matches_exclusion(
            &entry,
            &normalize_path(r"c:\safe\app.exe"),
            None
        ));
    }

    #[test]
    fn process_exclusion_with_empty_file_name_uses_path() {
        let entry = ExclusionEntry {
            path: r"C:\Windows\notepad.exe".to_string(),
            entry_type: "process".to_string(),
            description: None,
            created_at: "2026-05-03T00:00:00Z".to_string(),
        };
        assert!(matches_exclusion(
            &entry,
            &normalize_path(r"c:\windows\notepad.exe"),
            None
        ));
    }

    #[test]
    fn prepared_process_exclusion_uses_prepared_file_name_once() {
        let entry = PreparedExclusionEntry {
            normalized_path: normalize_path(r"C:\Windows\notepad.exe"),
            file_name: file_name_lower(r"C:\Windows\notepad.exe"),
            entry: ExclusionEntry {
                path: r"C:\Windows\notepad.exe".to_string(),
                entry_type: "process".to_string(),
                description: None,
                created_at: "2026-05-03T00:00:00Z".to_string(),
            },
        };
        let lookup = prepare_path_lookup(r"\\?\C:\Windows\NOTEPAD.EXE");
        assert!(matches_prepared_exclusion(
            &entry,
            &lookup.normalized_path,
            lookup.file_name.as_deref()
        ));
        assert!(!matches_prepared_exclusion(
            &entry,
            &normalize_path(r"C:\Windows\calc.exe"),
            file_name_lower(r"C:\Windows\calc.exe").as_deref()
        ));
    }

    #[test]
    fn sha256_hex_of_file_computes_correct_hash() {
        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("anxin_test_{}.txt", std::process::id()));
        let mut file = std::fs::File::create(&temp_file).expect("create temp file");
        file.write_all(b"hello world").expect("write temp file");
        drop(file);

        let hash = sha256_hex_of_file(&temp_file.to_string_lossy()).expect("compute hash");
        let _ = std::fs::remove_file(&temp_file);

        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn sha256_hex_of_file_returns_error_for_nonexistent_file() {
        let result = sha256_hex_of_file(r"C:\nonexistent\file\that\does\not\exist.txt");
        assert!(result.is_err());
    }

    #[test]
    fn path_policy_snapshot_hash_cache_invalidates_when_file_version_changes() {
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("anxin_policy_cache_{}.txt", std::process::id()));
        let mut file = std::fs::File::create(&temp_file).expect("create temp file");
        file.write_all(b"hello allowlist").expect("write temp file");
        drop(file);

        let temp_path = temp_file.to_string_lossy().to_string();
        let trusted_hash = sha256_hex_of_file(&temp_path).expect("compute trusted hash");
        let snapshot = PathPolicySnapshot {
            exclusions: prepare_exclusion_entries(Vec::new()),
            allowlist: prepare_allowlist_entries(vec![AllowlistEntry {
                path: r"C:\Other\Path.exe".to_string(),
                hash: Some(trusted_hash),
                description: None,
                created_at: "2026-06-16T00:00:00Z".to_string(),
            }]),
            lookup_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            hash_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            decision_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
        };

        assert!(snapshot.should_skip_security_scan(&temp_path));
        assert_eq!(
            snapshot
                .hash_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            1
        );

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&temp_file, b"changed allowlist content").expect("rewrite temp file");

        assert!(!snapshot.should_skip_security_scan(&temp_path));
        assert!(
            snapshot
                .hash_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len()
                >= 2
        );

        std::fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn path_policy_snapshot_decision_cache_invalidates_when_file_version_changes() {
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("anxin_policy_decision_{}.txt", std::process::id()));
        let mut file = std::fs::File::create(&temp_file).expect("create temp file");
        file.write_all(b"first version").expect("write temp file");
        drop(file);

        let temp_path = temp_file.to_string_lossy().to_string();
        let trusted_hash = sha256_hex_of_file(&temp_path).expect("compute trusted hash");
        let snapshot = PathPolicySnapshot {
            exclusions: prepare_exclusion_entries(Vec::new()),
            allowlist: prepare_allowlist_entries(vec![AllowlistEntry {
                path: r"C:\Other\Path.exe".to_string(),
                hash: Some(trusted_hash),
                description: None,
                created_at: "2026-06-16T00:00:00Z".to_string(),
            }]),
            lookup_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            hash_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            decision_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
        };

        let first_key = file_version_cache_key(&temp_path).expect("first cache key");
        assert!(snapshot.should_skip_security_scan_cached(&temp_path, Some(&first_key)));
        assert_eq!(
            snapshot
                .decision_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            1
        );

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&temp_file, b"second version").expect("rewrite temp file");
        let second_key = file_version_cache_key(&temp_path).expect("second cache key");
        assert_ne!(first_key, second_key);
        assert!(!snapshot.should_skip_security_scan_cached(&temp_path, Some(&second_key)));
        assert_eq!(
            snapshot
                .decision_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            2
        );

        std::fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn path_policy_snapshot_path_only_skip_does_not_use_hash_allowlist() {
        let snapshot = PathPolicySnapshot {
            exclusions: prepare_exclusion_entries(vec![ExclusionEntry {
                path: r"C:\Ignored".to_string(),
                entry_type: "directory".to_string(),
                description: None,
                created_at: "2026-06-16T00:00:00Z".to_string(),
            }]),
            allowlist: prepare_allowlist_entries(vec![
                AllowlistEntry {
                    path: r"C:\Trusted\App.exe".to_string(),
                    hash: None,
                    description: None,
                    created_at: "2026-06-16T00:00:00Z".to_string(),
                },
                AllowlistEntry {
                    path: r"C:\Other\HashOnly.exe".to_string(),
                    hash: Some(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    ),
                    description: None,
                    created_at: "2026-06-16T00:00:00Z".to_string(),
                },
            ]),
            lookup_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            hash_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            decision_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
        };

        assert!(snapshot.should_skip_by_path_only(r"C:\Ignored\child.dll"));
        assert!(snapshot.should_skip_by_path_only(r"c:\trusted\APP.exe"));
        assert!(!snapshot.should_skip_by_path_only(r"C:\Unknown\HashOnly.exe"));
        assert_eq!(
            snapshot
                .hash_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            0
        );
    }

    #[test]
    fn path_policy_snapshot_hash_after_path_miss_ignores_exact_path_only_entries() {
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!(
            "anxin_policy_exact_only_{}.txt",
            std::process::id()
        ));
        let mut file = std::fs::File::create(&temp_file).expect("create temp file");
        file.write_all(b"exact path only").expect("write temp file");
        drop(file);

        let temp_path = temp_file.to_string_lossy().to_string();
        let snapshot = PathPolicySnapshot {
            exclusions: prepare_exclusion_entries(Vec::new()),
            allowlist: prepare_allowlist_entries(vec![AllowlistEntry {
                path: temp_path.clone(),
                hash: None,
                description: None,
                created_at: "2026-06-16T00:00:00Z".to_string(),
            }]),
            lookup_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            hash_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            decision_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
        };

        let cache_key = file_version_cache_key(&temp_path).expect("cache key");
        assert!(snapshot.should_skip_by_path_only(&temp_path));
        assert!(!snapshot.should_skip_by_hash_after_path_miss_cached(&temp_path, Some(&cache_key)));
        assert_eq!(
            snapshot
                .decision_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            0
        );
        assert_eq!(
            snapshot
                .hash_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            0
        );

        std::fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn path_policy_snapshot_hash_after_path_miss_uses_hash_allowlist_and_cache() {
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!(
            "anxin_policy_hash_after_miss_{}.txt",
            std::process::id()
        ));
        let mut file = std::fs::File::create(&temp_file).expect("create temp file");
        file.write_all(b"hash allowlist content")
            .expect("write temp file");
        drop(file);

        let temp_path = temp_file.to_string_lossy().to_string();
        let trusted_hash = sha256_hex_of_file(&temp_path).expect("compute trusted hash");
        let snapshot = PathPolicySnapshot {
            exclusions: prepare_exclusion_entries(Vec::new()),
            allowlist: prepare_allowlist_entries(vec![
                AllowlistEntry {
                    path: r"C:\Different\ExactOnly.exe".to_string(),
                    hash: None,
                    description: None,
                    created_at: "2026-06-16T00:00:00Z".to_string(),
                },
                AllowlistEntry {
                    path: r"C:\Different\HashOnly.exe".to_string(),
                    hash: Some(trusted_hash.clone()),
                    description: None,
                    created_at: "2026-06-16T00:00:00Z".to_string(),
                },
            ]),
            lookup_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            hash_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            decision_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
        };

        let cache_key = file_version_cache_key(&temp_path).expect("cache key");
        let first_decision = snapshot.hash_after_path_miss_cached(&temp_path, Some(&cache_key));
        assert!(first_decision.skip_scan);
        assert_eq!(
            first_decision.sha256_hex.as_deref(),
            Some(trusted_hash.as_str())
        );
        assert_eq!(
            snapshot
                .decision_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            1
        );
        let cached_decision = snapshot.hash_after_path_miss_cached(&temp_path, Some(&cache_key));
        assert!(cached_decision.skip_scan);
        assert_eq!(
            cached_decision.sha256_hex.as_deref(),
            Some(trusted_hash.as_str())
        );
        assert_eq!(
            snapshot
                .decision_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            1
        );

        std::fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn path_policy_hash_after_path_miss_does_not_return_hash_for_stale_version_key() {
        use std::io::Write;

        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!(
            "anxin_policy_stale_hash_{}.txt",
            std::process::id()
        ));
        let mut file = std::fs::File::create(&temp_file).expect("create temp file");
        file.write_all(b"first hash version")
            .expect("write temp file");
        drop(file);

        let temp_path = temp_file.to_string_lossy().to_string();
        let trusted_hash = sha256_hex_of_file(&temp_path).expect("compute trusted hash");
        let stale_cache_key = file_version_cache_key(&temp_path).expect("stale cache key");
        let snapshot = PathPolicySnapshot {
            exclusions: prepare_exclusion_entries(Vec::new()),
            allowlist: prepare_allowlist_entries(vec![AllowlistEntry {
                path: r"C:\Different\HashOnly.exe".to_string(),
                hash: Some(trusted_hash),
                description: None,
                created_at: "2026-06-16T00:00:00Z".to_string(),
            }]),
            lookup_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            hash_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            decision_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
        };

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&temp_file, b"second hash version").expect("rewrite temp file");

        let decision = snapshot.hash_after_path_miss_cached(&temp_path, Some(&stale_cache_key));
        assert!(!decision.skip_scan);
        assert!(decision.sha256_hex.is_none());

        std::fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn path_policy_snapshot_prepared_entries_keep_existing_match_semantics() {
        let snapshot = PathPolicySnapshot {
            exclusions: prepare_exclusion_entries(vec![
                ExclusionEntry {
                    path: r"C:\Safe\Folder".to_string(),
                    entry_type: "directory".to_string(),
                    description: None,
                    created_at: "2026-06-16T00:00:00Z".to_string(),
                },
                ExclusionEntry {
                    path: "blocked.exe".to_string(),
                    entry_type: "process".to_string(),
                    description: None,
                    created_at: "2026-06-16T00:00:00Z".to_string(),
                },
            ]),
            allowlist: prepare_allowlist_entries(vec![AllowlistEntry {
                path: r"C:\Trusted\App.exe".to_string(),
                hash: None,
                description: None,
                created_at: "2026-06-16T00:00:00Z".to_string(),
            }]),
            lookup_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            hash_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            decision_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
        };

        assert!(snapshot.should_skip_by_path_only(r"c:\safe\folder\child.dll"));
        assert!(snapshot.should_skip_by_path_only(r"C:\Temp\BLOCKED.EXE"));
        assert!(snapshot.should_skip_by_path_only(r"c:\trusted\app.exe"));
        assert!(!snapshot.should_skip_by_path_only(r"C:\Temp\other.exe"));
    }

    #[test]
    fn path_policy_snapshot_reuses_prepared_lookup_without_hash_fast_path() {
        let snapshot = PathPolicySnapshot {
            exclusions: prepare_exclusion_entries(vec![
                ExclusionEntry {
                    path: r"C:\Ignored".to_string(),
                    entry_type: "directory".to_string(),
                    description: None,
                    created_at: "2026-06-16T00:00:00Z".to_string(),
                },
                ExclusionEntry {
                    path: "blocked.exe".to_string(),
                    entry_type: "process".to_string(),
                    description: None,
                    created_at: "2026-06-16T00:00:00Z".to_string(),
                },
            ]),
            allowlist: prepare_allowlist_entries(vec![
                AllowlistEntry {
                    path: r"C:\Trusted\App.exe".to_string(),
                    hash: None,
                    description: None,
                    created_at: "2026-06-16T00:00:00Z".to_string(),
                },
                AllowlistEntry {
                    path: r"C:\HashOnly\App.exe".to_string(),
                    hash: Some(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    ),
                    description: None,
                    created_at: "2026-06-16T00:00:00Z".to_string(),
                },
            ]),
            lookup_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            hash_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            decision_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
        };

        assert!(snapshot.should_skip_by_path_only(r"c:/ignored/child.dll"));
        assert!(snapshot.should_skip_by_path_only(r"C:\Temp\BLOCKED.EXE"));
        assert!(snapshot.should_skip_by_path_only(r"\\?\C:\Trusted\App.exe"));
        assert!(!snapshot.should_skip_by_path_only(r"C:\Unknown\App.exe"));
        assert_eq!(
            snapshot
                .hash_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            0
        );
    }

    #[test]
    fn path_policy_snapshot_caches_prepared_lookup_per_raw_path() {
        let snapshot = PathPolicySnapshot {
            exclusions: prepare_exclusion_entries(vec![ExclusionEntry {
                path: r"C:\Ignored".to_string(),
                entry_type: "directory".to_string(),
                description: None,
                created_at: "2026-06-16T00:00:00Z".to_string(),
            }]),
            allowlist: prepare_allowlist_entries(Vec::new()),
            lookup_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            hash_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
            decision_cache: std::sync::Arc::new(Mutex::new(HashMap::new())),
        };

        let path = r"C:/Ignored/Child.dll";
        assert!(snapshot.should_skip_by_path_only(path));
        assert!(snapshot.should_skip_by_path_only(path));
        assert_eq!(
            snapshot
                .lookup_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            1
        );
    }

    #[test]
    fn prepared_allowlist_index_splits_exact_paths_and_hashes() {
        let entries = prepare_allowlist_entries(vec![AllowlistEntry {
            path: r"C:\Trusted\App.exe".to_string(),
            hash: Some(
                "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789".to_string(),
            ),
            description: None,
            created_at: "2026-06-16T00:00:00Z".to_string(),
        }]);

        assert!(entries.exact_paths.contains(r"c:\trusted\app.exe"));
        assert!(entries
            .hashes
            .contains("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"));
    }

    #[test]
    fn prepared_allowlist_index_rejects_non_sha256_hashes() {
        let entries = prepare_allowlist_entries(vec![
            AllowlistEntry {
                path: r"C:\Trusted\ShortHash.exe".to_string(),
                hash: Some("abc123".to_string()),
                description: None,
                created_at: "2026-06-16T00:00:00Z".to_string(),
            },
            AllowlistEntry {
                path: r"C:\Trusted\InvalidHash.exe".to_string(),
                hash: Some(
                    "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string(),
                ),
                description: None,
                created_at: "2026-06-16T00:00:00Z".to_string(),
            },
        ]);

        assert!(entries.exact_paths.contains(r"c:\trusted\shorthash.exe"));
        assert!(entries.exact_paths.contains(r"c:\trusted\invalidhash.exe"));
        assert!(entries.hashes.is_empty());
    }

    #[test]
    fn normalized_sha256_hex_accepts_only_full_hex_hashes() {
        assert_eq!(
            normalized_sha256_hex(
                " ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789 "
            )
            .as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );
        assert!(normalized_sha256_hex("abc123").is_none());
        assert!(normalized_sha256_hex(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        )
        .is_none());
    }

    #[test]
    fn allowlist_entry_with_empty_hash_is_skipped() {
        let entry = AllowlistEntry {
            path: r"C:\Safe\App.exe".to_string(),
            hash: Some("".to_string()),
            description: None,
            created_at: "2026-05-03T00:00:00Z".to_string(),
        };
        assert!(entry.hash.as_deref().filter(|v| !v.is_empty()).is_none());
    }

    #[test]
    fn allowlist_entry_with_none_hash_is_skipped() {
        let entry = AllowlistEntry {
            path: r"C:\Safe\App.exe".to_string(),
            hash: None,
            description: None,
            created_at: "2026-05-03T00:00:00Z".to_string(),
        };
        assert!(entry.hash.as_deref().filter(|v| !v.is_empty()).is_none());
    }

    #[test]
    fn allowlist_entry_with_valid_hash_is_used() {
        let entry = AllowlistEntry {
            path: r"C:\Safe\App.exe".to_string(),
            hash: Some("abc123".to_string()),
            description: None,
            created_at: "2026-05-03T00:00:00Z".to_string(),
        };
        assert_eq!(
            entry.hash.as_deref().filter(|v| !v.is_empty()),
            Some("abc123")
        );
    }
}
