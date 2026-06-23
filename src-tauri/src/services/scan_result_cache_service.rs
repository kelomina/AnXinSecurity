// 进程与模块扫描结果缓存服务 - 使用 APPDATA runtime DPAPI 文件缓存原始引擎结果。
// Process and module scan result cache service - caches raw engine results in an APPDATA runtime DPAPI file.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::services::engine_service::EngineService;
use crate::services::runtime_list_store::{
    load_runtime_list, runtime_file_path, save_runtime_list,
};

const SCAN_RESULT_CACHE_FILE: &str = "scan_results.json";
const SCAN_RESULT_CACHE_LEGACY_FIELD: &str = "__scanResultCache";
const DEFAULT_MAX_ENTRIES: usize = 4096;
const DEFAULT_TTL_MS: u64 = 3_600_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedScanCacheEntry {
    path: String,
    write_time: i64,
    hash_hex: String,
    raw_result: serde_json::Value,
    cached_at_ms: u64,
}

#[derive(Debug, Clone)]
struct ScanCacheEntry {
    path: String,
    write_time: i64,
    hash_hex: String,
    raw_result: serde_json::Value,
    cached_at_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CachedScanResult {
    pub raw_result: serde_json::Value,
    pub hash_hex: String,
    pub cache_hit: bool,
}

struct ScanResultCacheState {
    entries: HashMap<String, ScanCacheEntry>,
    lru: VecDeque<String>,
    max_entries: usize,
    ttl_ms: u64,
    dirty_entries: usize,
}

/// 函数名称：ScanResultCacheService
/// 函数作用：为进程本体和加载模块提供持久化原始引擎扫描结果缓存。
/// Purpose: Provides persistent raw engine scan result cache for process images and loaded modules.
/// 调用方：main.rs setup 初始化；ProcessScannerService 与 SnapshotService 调用 scan_or_get_cached。
/// Called by: main.rs setup; ProcessScannerService and SnapshotService call scan_or_get_cached.
/// 副作用：读取和写入 DPAPI 加密的 runtime/scan_results.json；不写 config/app.json。
/// Side effects: Reads and writes DPAPI-encrypted runtime/scan_results.json; does not write config/app.json.
pub struct ScanResultCacheService {
    state: Mutex<ScanResultCacheState>,
}

impl ScanResultCacheService {
    /// 函数名称：new
    /// 函数作用：创建扫描结果缓存服务并加载已有加密缓存。
    /// Purpose: Creates the scan result cache service and loads existing encrypted cache entries.
    /// 调用方：main.rs setup。
    /// Called by: main.rs setup.
    /// 错误处理：缓存文件缺失时使用空缓存；读取或解密失败时记录调试输出并使用空缓存，避免阻断安全扫描。
    /// Error handling: Missing cache uses an empty cache; read/decrypt failures are logged and do not block scanning.
    pub fn new() -> Self {
        let persisted = match load_runtime_list::<PersistedScanCacheEntry>(
            SCAN_RESULT_CACHE_FILE,
            SCAN_RESULT_CACHE_LEGACY_FIELD,
        ) {
            Ok(entries) => entries,
            Err(err) => {
                eprintln!("[ScanResultCache] Failed to load persistent cache: {}", err);
                quarantine_corrupt_scan_cache(&err);
                Vec::new()
            }
        };

        let mut entries = HashMap::new();
        let mut lru = VecDeque::new();
        for item in persisted {
            let key = item.hash_hex.clone();
            if key.is_empty() {
                continue;
            }
            lru.push_front(key.clone());
            entries.insert(
                key.clone(),
                ScanCacheEntry {
                    path: item.path,
                    write_time: item.write_time,
                    hash_hex: key,
                    raw_result: item.raw_result,
                    cached_at_ms: item.cached_at_ms,
                },
            );
        }

        Self {
            state: Mutex::new(ScanResultCacheState {
                entries,
                lru,
                max_entries: DEFAULT_MAX_ENTRIES,
                ttl_ms: DEFAULT_TTL_MS,
                dirty_entries: 0,
            }),
        }
    }

    /// 函数名称：scan_or_get_cached
    /// 函数作用：先按 SHA-256 与写入时间查找缓存；未命中时调用引擎扫描并持久化原始结果。
    /// Purpose: Looks up cache by SHA-256 and write time; scans with the engine and persists raw result on miss.
    /// 调用方：ProcessScannerService、SnapshotService。
    /// Called by: ProcessScannerService, SnapshotService.
    /// 参数说明：engine 为扫描引擎服务；file_path 为进程或模块路径。
    /// Parameters: engine is the scan engine service; file_path is a process image or module path.
    /// 返回值说明：返回原始引擎结果、SHA-256 和是否命中缓存。
    /// Returns: Raw engine result, SHA-256, and whether cache was hit.
    /// 错误处理：哈希计算或引擎扫描失败时返回错误；缓存持久化失败记录日志但不改变扫描结果。
    /// Error handling: Hash or engine scan failures return errors; persistence failures are logged without changing scan result.
    pub async fn scan_or_get_cached(
        &self,
        engine: &EngineService,
        file_path: &str,
    ) -> Result<CachedScanResult, String> {
        self.scan_or_get_cached_with_policy(engine, file_path, true, None)
            .await
    }

    /// 函数名称：scan_or_get_cached_deferred
    /// 函数作用：扫描或读取缓存，但把缓存持久化延迟到 flush_pending，避免启动快照期间每个模块都写一次 DPAPI 文件。
    /// Purpose: Scans or reads cache while deferring persistence until flush_pending to avoid one DPAPI file write per startup module.
    /// 调用方：SnapshotService::take_startup_snapshot。
    /// Called by: SnapshotService::take_startup_snapshot.
    /// 中文关键词：扫描缓存，延迟持久化，启动快照，性能优化
    /// English keywords: scan cache, deferred persistence, startup snapshot, performance optimization
    #[allow(dead_code)]
    pub async fn scan_or_get_cached_deferred(
        &self,
        engine: &EngineService,
        file_path: &str,
    ) -> Result<CachedScanResult, String> {
        self.scan_or_get_cached_with_policy(engine, file_path, false, None)
            .await
    }

    /// 函数名称：scan_or_get_cached_deferred_with_hash
    /// 函数作用：启动快照专用入口；当调用方已经在同一文件版本键下计算过 SHA-256 时，复用该 hash 查扫描缓存，避免同一文件被连续读取两遍。
    /// Purpose: Startup-snapshot entry point that reuses a SHA-256 already computed for the same file-version key, avoiding immediately reading the same file twice.
    /// 安全边界：调用方只能在文件版本键可用且刚完成哈希允许列表检查时传入 hash；缺少 hash 时回退到重新计算。
    /// Security boundary: Callers may pass a hash only when a file-version key is available and the hash was just computed for allowlist checking; missing hash falls back to recomputation.
    pub async fn scan_or_get_cached_deferred_with_hash(
        &self,
        engine: &EngineService,
        file_path: &str,
        precomputed_sha256_hex: Option<&str>,
    ) -> Result<CachedScanResult, String> {
        self.scan_or_get_cached_with_policy(engine, file_path, false, precomputed_sha256_hex)
            .await
    }

    /// 函数名称：flush_pending
    /// 函数作用：把延迟写入的扫描缓存一次性持久化。
    /// Purpose: Persists deferred scan cache updates in one batch.
    /// 调用方：SnapshotService::take_startup_snapshot。
    /// Called by: SnapshotService::take_startup_snapshot.
    /// 中文关键词：扫描缓存，批量写入，启动快照
    /// English keywords: scan cache, batch persist, startup snapshot
    pub fn flush_pending(&self) -> Result<(), String> {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        state.persist_if_dirty()
    }

    async fn scan_or_get_cached_with_policy(
        &self,
        engine: &EngineService,
        file_path: &str,
        persist_immediately: bool,
        precomputed_sha256_hex: Option<&str>,
    ) -> Result<CachedScanResult, String> {
        let debug_logging = scan_result_cache_debug_logging_enabled();
        let total_start = Instant::now();
        let write_time = file_write_time(file_path).unwrap_or(0);
        let hash_start = Instant::now();
        let normalized_precomputed_hash = precomputed_sha256_hex.and_then(normalized_sha256_hex);
        let hash_source = if normalized_precomputed_hash.is_some() {
            "precomputed"
        } else {
            "computed"
        };
        let hash_hex = match normalized_precomputed_hash {
            Some(hash) => hash,
            None => sha256_hex_of_file(file_path)?,
        };
        let hash_ms = elapsed_ms(hash_start);
        let now_ms = epoch_ms();

        {
            let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
            let ttl_ms = state.ttl_ms;
            if let Some(entry) = state.entries.get(&hash_hex) {
                let fresh = entry.write_time == write_time
                    && now_ms >= entry.cached_at_ms
                    && (now_ms - entry.cached_at_ms) <= ttl_ms;
                if fresh {
                    let raw_result = entry.raw_result.clone();
                    state.touch_lru(&hash_hex);
                    if debug_logging {
                        eprintln!(
                            "[ScanResultCache] Lookup detail: outcome=hit, path={}, hashMs={}, hashSource={}, totalMs={}, hashPrefix={}",
                            file_path,
                            hash_ms,
                            hash_source,
                            elapsed_ms(total_start),
                            short_hash_prefix(&hash_hex)
                        );
                    }
                    return Ok(CachedScanResult {
                        raw_result,
                        hash_hex,
                        cache_hit: true,
                    });
                }
            }
        }

        let engine_start = Instant::now();
        let raw_result = engine.scan_file_raw(file_path).await?;
        let engine_ms = elapsed_ms(engine_start);
        {
            let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
            state.upsert(ScanCacheEntry {
                path: normalize_path(file_path),
                write_time,
                hash_hex: hash_hex.clone(),
                raw_result: raw_result.clone(),
                cached_at_ms: now_ms,
            });
            state.evict_if_needed();
            if persist_immediately {
                if let Err(err) = state.persist_if_dirty() {
                    eprintln!("[ScanResultCache] Failed to persist cache: {}", err);
                }
            }
        }

        if debug_logging {
            eprintln!(
                "[ScanResultCache] Lookup detail: outcome=miss, path={}, hashMs={}, hashSource={}, engineMs={}, totalMs={}, persistImmediate={}, hashPrefix={}",
                file_path,
                hash_ms,
                hash_source,
                engine_ms,
                elapsed_ms(total_start),
                persist_immediately,
                short_hash_prefix(&hash_hex)
            );
        }
        Ok(CachedScanResult {
            raw_result,
            hash_hex,
            cache_hit: false,
        })
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn cached_entry_count_for_test(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .entries
            .len()
    }
}

fn quarantine_corrupt_scan_cache(load_error: &str) {
    let cache_path = runtime_file_path(SCAN_RESULT_CACHE_FILE);
    if !cache_path.exists() {
        return;
    }

    let quarantine_path = corrupt_cache_path(&cache_path);
    match std::fs::rename(&cache_path, &quarantine_path) {
        Ok(()) => {
            eprintln!(
                "[ScanResultCache] Corrupt persistent cache moved to {} after load failure: {}",
                quarantine_path.display(),
                load_error
            );
        }
        Err(err) => {
            eprintln!(
                "[ScanResultCache] Failed to move corrupt persistent cache {}: {}",
                cache_path.display(),
                err
            );
        }
    }
}

fn corrupt_cache_path(cache_path: &PathBuf) -> PathBuf {
    let timestamp = epoch_ms();
    let file_name = cache_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(SCAN_RESULT_CACHE_FILE);
    cache_path.with_file_name(format!("{}.corrupt.{}", file_name, timestamp))
}

impl ScanResultCacheState {
    fn touch_lru(&mut self, hash_hex: &str) {
        self.lru.retain(|item| item != hash_hex);
        self.lru.push_front(hash_hex.to_string());
    }

    fn upsert(&mut self, entry: ScanCacheEntry) {
        let hash_hex = entry.hash_hex.clone();
        self.entries.insert(hash_hex.clone(), entry);
        self.touch_lru(&hash_hex);
        self.dirty_entries += 1;
    }

    fn evict_if_needed(&mut self) {
        while self.entries.len() > self.max_entries {
            if let Some(hash_hex) = self.lru.pop_back() {
                self.entries.remove(&hash_hex);
            } else {
                break;
            }
        }
    }

    fn persist(&self) -> Result<(), String> {
        let entries: Vec<PersistedScanCacheEntry> = self
            .entries
            .values()
            .map(|entry| PersistedScanCacheEntry {
                path: entry.path.clone(),
                write_time: entry.write_time,
                hash_hex: entry.hash_hex.clone(),
                raw_result: entry.raw_result.clone(),
                cached_at_ms: entry.cached_at_ms,
            })
            .collect();
        save_runtime_list(SCAN_RESULT_CACHE_FILE, &entries)
    }

    fn persist_if_dirty(&mut self) -> Result<(), String> {
        if self.dirty_entries == 0 {
            return Ok(());
        }
        self.persist()?;
        self.dirty_entries = 0;
        Ok(())
    }
}

fn normalize_path(path: &str) -> String {
    let mut normalized: String = path
        .chars()
        .map(|ch| {
            if ch == '/' {
                '\\'
            } else if ch.is_ascii_uppercase() {
                ch.to_ascii_lowercase()
            } else {
                ch
            }
        })
        .collect();
    if normalized.starts_with("\\\\?\\") {
        normalized = normalized[4..].to_string();
    }
    if normalized.starts_with("\\??\\") {
        normalized = normalized[4..].to_string();
    }
    normalized
}

fn file_write_time(file_path: &str) -> Option<i64> {
    let modified = std::fs::metadata(file_path).ok()?.modified().ok()?;
    let duration = modified.duration_since(UNIX_EPOCH).ok()?;
    Some(duration.as_millis() as i64)
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

fn scan_result_cache_debug_logging_enabled() -> bool {
    std::env::var("ANXIN_SCAN_CACHE_DEBUG")
        .or_else(|_| std::env::var("ANXIN_STARTUP_SNAPSHOT_DEBUG"))
        .map(|value| scan_result_cache_debug_value_enabled(&value))
        .unwrap_or(false)
}

fn scan_result_cache_debug_value_enabled(value: &str) -> bool {
    let normalized = value.trim();
    normalized == "1" || normalized.eq_ignore_ascii_case("true")
}

fn short_hash_prefix(hash_hex: &str) -> &str {
    let prefix_len = hash_hex.len().min(12);
    &hash_hex[..prefix_len]
}

fn normalized_sha256_hex(hash_hex: &str) -> Option<String> {
    let normalized = hash_hex.trim();
    if normalized.len() != 64 || !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(normalized.to_ascii_lowercase())
}

fn sha256_hex_of_file(file_path: &str) -> Result<String, String> {
    let mut file =
        File::open(file_path).map_err(|err| format!("Failed to open file for SHA-256: {}", err))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| format!("Failed to read file for SHA-256: {}", err))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_removes_windows_prefix_and_lowercases() {
        assert_eq!(normalize_path(r"\\?\C:\Temp\App.EXE"), r"c:\temp\app.exe");
    }

    #[test]
    fn state_evicts_oldest_entry() {
        let mut state = ScanResultCacheState {
            entries: HashMap::new(),
            lru: VecDeque::new(),
            max_entries: 1,
            ttl_ms: DEFAULT_TTL_MS,
            dirty_entries: 0,
        };
        state.upsert(ScanCacheEntry {
            path: "a".to_string(),
            write_time: 1,
            hash_hex: "a".repeat(64),
            raw_result: serde_json::json!({"is_malware": false}),
            cached_at_ms: epoch_ms(),
        });
        state.upsert(ScanCacheEntry {
            path: "b".to_string(),
            write_time: 2,
            hash_hex: "b".repeat(64),
            raw_result: serde_json::json!({"is_malware": true}),
            cached_at_ms: epoch_ms(),
        });
        state.evict_if_needed();
        assert_eq!(state.entries.len(), 1);
        assert!(state.entries.contains_key(&"b".repeat(64)));
    }

    #[test]
    fn sha256_hex_of_file_reads_file_content() {
        let path = std::env::temp_dir().join(format!("anxin-cache-test-{}.bin", epoch_ms()));
        std::fs::write(&path, b"abc").expect("write temp file");
        let hash = sha256_hex_of_file(&path.to_string_lossy()).expect("hash temp file");
        let _ = std::fs::remove_file(path);
        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn scan_result_cache_debug_value_enabled_parses_supported_values() {
        assert!(scan_result_cache_debug_value_enabled("1"));
        assert!(scan_result_cache_debug_value_enabled("true"));
        assert!(scan_result_cache_debug_value_enabled(" TRUE "));
        assert!(!scan_result_cache_debug_value_enabled("0"));
        assert!(!scan_result_cache_debug_value_enabled("false"));
        assert!(!scan_result_cache_debug_value_enabled(""));
    }

    #[test]
    fn scan_result_cache_hash_prefix_is_bounded() {
        assert_eq!(short_hash_prefix("abc"), "abc");
        assert_eq!(short_hash_prefix("1234567890abcdef"), "1234567890ab");
    }

    #[test]
    fn normalized_sha256_hex_accepts_only_full_hex_hashes() {
        let upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
        assert_eq!(
            normalized_sha256_hex(upper).as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );
        assert!(normalized_sha256_hex("abc").is_none());
        assert!(normalized_sha256_hex(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        )
        .is_none());
    }
}
