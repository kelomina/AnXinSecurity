// 进程与模块扫描结果缓存服务 - 使用 APPDATA runtime DPAPI 文件缓存原始引擎结果。
// Process and module scan result cache service - caches raw engine results in an APPDATA runtime DPAPI file.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::Read;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::services::engine_service::EngineService;
use crate::services::runtime_list_store::{load_runtime_list, save_runtime_list};

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
        let write_time = file_write_time(file_path).unwrap_or(0);
        let hash_hex = sha256_hex_of_file(file_path)?;
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
                    return Ok(CachedScanResult {
                        raw_result,
                        hash_hex,
                        cache_hit: true,
                    });
                }
            }
        }

        let raw_result = engine.scan_file_raw(file_path).await?;
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
            if let Err(err) = state.persist() {
                eprintln!("[ScanResultCache] Failed to persist cache: {}", err);
            }
        }

        Ok(CachedScanResult {
            raw_result,
            hash_hex,
            cache_hit: false,
        })
    }

    #[cfg(test)]
    pub fn cached_entry_count_for_test(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .entries
            .len()
    }
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
}
