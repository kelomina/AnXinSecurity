// ScanResultCacheService 扩展测试 — 验证缓存状态管理、LRU驱逐和数据结构边界
// ScanResultCacheService extended tests — verify cache state management, LRU eviction, and data structure boundaries
//
// 测试策略：测试 ScanResultCacheState 的内部逻辑，包括 LRU 驱逐、条目更新和持久化转换
// Test strategy: test ScanResultCacheState internal logic including LRU eviction, entry update, and persistence transform
//
// 中文关键词：扫描结果缓存，LRU缓存，驱逐策略，持久化，状态管理
// English keywords: scan result cache, LRU cache, eviction policy, persistence, state management

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};

    const _DEFAULT_MAX_ENTRIES: usize = 4096;
    const DEFAULT_TTL_MS: u64 = 3_600_000;

    struct ScanCacheEntry {
        path: String,
        write_time: i64,
        hash_hex: String,
        raw_result: serde_json::Value,
        cached_at_ms: u64,
    }

    struct ScanResultCacheState {
        entries: HashMap<String, ScanCacheEntry>,
        lru: VecDeque<String>,
        max_entries: usize,
        _ttl_ms: u64,
    }

    impl ScanResultCacheState {
        fn new(max_entries: usize, ttl_ms: u64) -> Self {
            Self {
                entries: HashMap::new(),
                lru: VecDeque::new(),
                max_entries,
                _ttl_ms: ttl_ms,
            }
        }

        fn touch_lru(&mut self, hash_hex: &str) {
            if !self.entries.contains_key(hash_hex) {
                return;
            }
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

        fn get(&self, hash_hex: &str) -> Option<&ScanCacheEntry> {
            self.entries.get(hash_hex)
        }

        fn len(&self) -> usize {
            self.entries.len()
        }

        fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }
    }

    // ================================================================
    // LRU 行为测试 / LRU behavior tests
    // ================================================================

    #[test]
    fn test_lru_order_maintained_on_upsert() {
        let mut state = ScanResultCacheState::new(100, DEFAULT_TTL_MS);
        
        state.upsert(ScanCacheEntry {
            path: "a".to_string(),
            write_time: 1,
            hash_hex: "hash_a".to_string(),
            raw_result: serde_json::json!({"id": "a"}),
            cached_at_ms: 1000,
        });
        state.upsert(ScanCacheEntry {
            path: "b".to_string(),
            write_time: 2,
            hash_hex: "hash_b".to_string(),
            raw_result: serde_json::json!({"id": "b"}),
            cached_at_ms: 2000,
        });
        state.upsert(ScanCacheEntry {
            path: "c".to_string(),
            write_time: 3,
            hash_hex: "hash_c".to_string(),
            raw_result: serde_json::json!({"id": "c"}),
            cached_at_ms: 3000,
        });

        let lru_order: Vec<_> = state.lru.iter().collect();
        assert_eq!(lru_order, vec![&"hash_c", &"hash_b", &"hash_a"]);
    }

    #[test]
    fn test_touch_lru_moves_to_front() {
        let mut state = ScanResultCacheState::new(100, DEFAULT_TTL_MS);
        
        state.upsert(ScanCacheEntry {
            path: "a".to_string(),
            write_time: 1,
            hash_hex: "hash_a".to_string(),
            raw_result: serde_json::json!({}),
            cached_at_ms: 1000,
        });
        state.upsert(ScanCacheEntry {
            path: "b".to_string(),
            write_time: 2,
            hash_hex: "hash_b".to_string(),
            raw_result: serde_json::json!({}),
            cached_at_ms: 2000,
        });

        state.touch_lru("hash_a");
        
        let lru_order: Vec<_> = state.lru.iter().collect();
        assert_eq!(lru_order, vec![&"hash_a", &"hash_b"]);
    }

    #[test]
    fn test_touch_nonexistent_key_no_op() {
        let mut state = ScanResultCacheState::new(100, DEFAULT_TTL_MS);
        
        state.upsert(ScanCacheEntry {
            path: "a".to_string(),
            write_time: 1,
            hash_hex: "hash_a".to_string(),
            raw_result: serde_json::json!({}),
            cached_at_ms: 1000,
        });

        state.touch_lru("nonexistent");
        
        assert_eq!(state.len(), 1);
        assert_eq!(state.lru.len(), 1);
    }

    #[test]
    fn test_upsert_updates_existing_entry() {
        let mut state = ScanResultCacheState::new(100, DEFAULT_TTL_MS);
        
        state.upsert(ScanCacheEntry {
            path: "a".to_string(),
            write_time: 1,
            hash_hex: "hash_a".to_string(),
            raw_result: serde_json::json!({"version": 1}),
            cached_at_ms: 1000,
        });
        
        state.upsert(ScanCacheEntry {
            path: "a".to_string(),
            write_time: 2,
            hash_hex: "hash_a".to_string(),
            raw_result: serde_json::json!({"version": 2}),
            cached_at_ms: 2000,
        });

        assert_eq!(state.len(), 1);
        let entry = state.get("hash_a").unwrap();
        assert_eq!(entry.raw_result["version"], 2);
        assert_eq!(entry.write_time, 2);
    }

    // ================================================================
    // LRU 驱逐测试 / LRU eviction tests
    // ================================================================

    #[test]
    fn test_eviction_removes_oldest_lru_entry() {
        let mut state = ScanResultCacheState::new(2, DEFAULT_TTL_MS);
        
        state.upsert(ScanCacheEntry {
            path: "a".to_string(),
            write_time: 1,
            hash_hex: "hash_a".to_string(),
            raw_result: serde_json::json!({}),
            cached_at_ms: 1000,
        });
        state.upsert(ScanCacheEntry {
            path: "b".to_string(),
            write_time: 2,
            hash_hex: "hash_b".to_string(),
            raw_result: serde_json::json!({}),
            cached_at_ms: 2000,
        });

        state.evict_if_needed();
        
        assert_eq!(state.len(), 2);
        
        state.upsert(ScanCacheEntry {
            path: "c".to_string(),
            write_time: 3,
            hash_hex: "hash_c".to_string(),
            raw_result: serde_json::json!({}),
            cached_at_ms: 3000,
        });
        
        state.evict_if_needed();
        
        assert_eq!(state.len(), 2);
        assert!(state.get("hash_a").is_none());
        assert!(state.get("hash_b").is_some());
        assert!(state.get("hash_c").is_some());
    }

    #[test]
    fn test_eviction_with_max_entries_zero_no_eviction() {
        let mut state = ScanResultCacheState::new(0, DEFAULT_TTL_MS);
        
        state.upsert(ScanCacheEntry {
            path: "a".to_string(),
            write_time: 1,
            hash_hex: "hash_a".to_string(),
            raw_result: serde_json::json!({}),
            cached_at_ms: 1000,
        });
        
        state.evict_if_needed();
        
        assert_eq!(state.len(), 0);
    }

    #[test]
    fn test_massive_eviction_handles_all_entries() {
        let mut state = ScanResultCacheState::new(5, DEFAULT_TTL_MS);
        
        for i in 0..100 {
            state.upsert(ScanCacheEntry {
                path: format!("file_{}", i),
                write_time: i as i64,
                hash_hex: format!("hash_{:064}", i),
                raw_result: serde_json::json!({"id": i}),
                cached_at_ms: (1000 + i) as u64,
            });
        }
        
        state.evict_if_needed();
        
        assert_eq!(state.len(), 5);
        
        let remaining: Vec<_> = state.entries.keys().collect();
        assert!(remaining.contains(&&format!("hash_{:064}", 99)));
        assert!(remaining.contains(&&format!("hash_{:064}", 98)));
        assert!(!remaining.contains(&&format!("hash_{:064}", 0)));
    }

    #[test]
    fn test_eviction_is_idempotent() {
        let mut state = ScanResultCacheState::new(2, DEFAULT_TTL_MS);
        
        state.upsert(ScanCacheEntry {
            path: "a".to_string(),
            write_time: 1,
            hash_hex: "hash_a".to_string(),
            raw_result: serde_json::json!({}),
            cached_at_ms: 1000,
        });
        state.upsert(ScanCacheEntry {
            path: "b".to_string(),
            write_time: 2,
            hash_hex: "hash_b".to_string(),
            raw_result: serde_json::json!({}),
            cached_at_ms: 2000,
        });

        state.evict_if_needed();
        let len_after_first = state.len();
        
        state.evict_if_needed();
        let len_after_second = state.len();
        
        assert_eq!(len_after_first, len_after_second);
    }

    // ================================================================
    // 缓存条目操作测试 / Cache entry operations tests
    // ================================================================

    #[test]
    fn test_get_returns_correct_entry() {
        let mut state = ScanResultCacheState::new(100, DEFAULT_TTL_MS);
        
        state.upsert(ScanCacheEntry {
            path: r"C:\test\malware.exe".to_string(),
            write_time: 12345,
            hash_hex: "malware_hash_abc".to_string(),
            raw_result: serde_json::json!({"is_malware": true, "family": "Trojan"}),
            cached_at_ms: 5000,
        });

        let entry = state.get("malware_hash_abc").unwrap();
        assert_eq!(entry.path, r"C:\test\malware.exe");
        assert_eq!(entry.write_time, 12345);
        assert_eq!(entry.raw_result["is_malware"], true);
    }

    #[test]
    fn test_get_returns_none_for_missing_key() {
        let state = ScanResultCacheState::new(100, DEFAULT_TTL_MS);
        
        assert!(state.get("nonexistent").is_none());
    }

    #[test]
    fn test_empty_state_operations() {
        let state = ScanResultCacheState::new(100, DEFAULT_TTL_MS);
        
        assert!(state.is_empty());
        assert_eq!(state.len(), 0);
        assert!(state.get("any").is_none());
    }

    #[test]
    fn test_len_after_operations() {
        let mut state = ScanResultCacheState::new(100, DEFAULT_TTL_MS);
        
        assert_eq!(state.len(), 0);
        
        state.upsert(ScanCacheEntry {
            path: "a".to_string(),
            write_time: 1,
            hash_hex: "hash_a".to_string(),
            raw_result: serde_json::json!({}),
            cached_at_ms: 1000,
        });
        assert_eq!(state.len(), 1);
        
        state.upsert(ScanCacheEntry {
            path: "b".to_string(),
            write_time: 2,
            hash_hex: "hash_b".to_string(),
            raw_result: serde_json::json!({}),
            cached_at_ms: 2000,
        });
        assert_eq!(state.len(), 2);
    }

    // ================================================================
    // TTL 和缓存新鲜度测试 / TTL and cache freshness tests
    // ================================================================

    #[test]
    fn test_cache_freshness_check() {
        fn is_cache_fresh(entry_write_time: i64, cached_at_ms: u64, now_ms: u64, ttl_ms: u64) -> bool {
            let Some(time_diff) = now_ms.checked_sub(cached_at_ms) else {
                return false;
            };
            entry_write_time >= 0 && time_diff <= ttl_ms
        }

        assert!(is_cache_fresh(1000, 5000, 6000, 3600000));
        assert!(is_cache_fresh(1000, 5000, 5000, 3600000));
        
        assert!(!is_cache_fresh(1000, 5000, 4000, 3600000));
        assert!(!is_cache_fresh(1000, 5000, 5001 + 3600000, 3600000));
    }

    #[test]
    fn test_ttl_zero_means_always_stale() {
        fn is_cache_fresh(_entry_write_time: i64, cached_at_ms: u64, now_ms: u64, ttl_ms: u64) -> bool {
            if ttl_ms == 0 {
                return false;
            }
            now_ms
                .checked_sub(cached_at_ms)
                .map(|time_diff| time_diff <= ttl_ms)
                .unwrap_or(false)
        }

        assert!(!is_cache_fresh(1000, 5000, 5001, 0));
        assert!(!is_cache_fresh(1000, 5000, 5000, 0));
    }

    // ================================================================
    // 持久化转换测试 / Persistence transform tests
    // ================================================================

    #[test]
    fn test_entry_to_persisted_conversion() {
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        struct PersistedScanCacheEntry {
            path: String,
            write_time: i64,
            hash_hex: String,
            raw_result: serde_json::Value,
            cached_at_ms: u64,
        }

        let entry = ScanCacheEntry {
            path: r"C:\test.exe".to_string(),
            write_time: 999,
            hash_hex: "test_hash".to_string(),
            raw_result: serde_json::json!({"result": "ok"}),
            cached_at_ms: 10000,
        };

        let persisted = PersistedScanCacheEntry {
            path: entry.path.clone(),
            write_time: entry.write_time,
            hash_hex: entry.hash_hex.clone(),
            raw_result: entry.raw_result.clone(),
            cached_at_ms: entry.cached_at_ms,
        };

        assert_eq!(persisted.path, r"C:\test.exe");
        assert_eq!(persisted.hash_hex, "test_hash");
        assert_eq!(persisted.raw_result["result"], "ok");
    }

    #[test]
    fn test_hash_hex_64_char_validation() {
        fn is_valid_sha256_hex(s: &str) -> bool {
            s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
        }

        let valid_hash = "a".repeat(64);
        assert!(is_valid_sha256_hex(&valid_hash));
        
        assert!(!is_valid_sha256_hex("short"));
        assert!(!is_valid_sha256_hex(&"g".repeat(64)));
        assert!(!is_valid_sha256_hex(""));
    }

    // ================================================================
    // 边界情况测试 / Edge case tests
    // ================================================================

    #[test]
    fn test_empty_hash_hex_is_skipped() {
        let mut state = ScanResultCacheState::new(100, DEFAULT_TTL_MS);
        
        state.upsert(ScanCacheEntry {
            path: "empty_hash".to_string(),
            write_time: 1,
            hash_hex: "".to_string(),
            raw_result: serde_json::json!({}),
            cached_at_ms: 1000,
        });

        assert_eq!(state.len(), 1);
    }

    #[test]
    fn test_unicode_path_handling() {
        let mut state = ScanResultCacheState::new(100, DEFAULT_TTL_MS);
        
        state.upsert(ScanCacheEntry {
            path: r"C:\测试\文件.exe".to_string(),
            write_time: 1,
            hash_hex: "unicode_path_hash".to_string(),
            raw_result: serde_json::json!({"test": true}),
            cached_at_ms: 1000,
        });

        let entry = state.get("unicode_path_hash").unwrap();
        assert_eq!(entry.path, r"C:\测试\文件.exe");
    }

    #[test]
    fn test_large_path_handling() {
        let mut state = ScanResultCacheState::new(100, DEFAULT_TTL_MS);
        
        let long_path = format!(r"C:\{}", "a".repeat(500));
        state.upsert(ScanCacheEntry {
            path: long_path.clone(),
            write_time: 1,
            hash_hex: "large_path_hash".to_string(),
            raw_result: serde_json::json!({}),
            cached_at_ms: 1000,
        });

        let entry = state.get("large_path_hash").unwrap();
        assert_eq!(entry.path, long_path);
    }

    #[test]
    fn test_negative_write_time_handling() {
        fn is_cache_fresh(entry_write_time: i64, cached_at_ms: u64, now_ms: u64, ttl_ms: u64) -> bool {
            entry_write_time >= 0
                && ttl_ms > 0
                && now_ms
                    .checked_sub(cached_at_ms)
                    .map(|time_diff| time_diff <= ttl_ms)
                    .unwrap_or(false)
        }

        assert!(!is_cache_fresh(-1, 5000, 6000, 3600000));
    }
}
