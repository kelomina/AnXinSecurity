// TrustService 单元测试 — 验证缓存配置、签名判定结构和哈希校验
// TrustService unit tests — verify cache config, signature verdict struct, and hash validation
//
// 测试策略：由于签名验证和文件哈希计算依赖 Windows DLL (wintrust.dll, kernel32.dll)
// 和真实文件系统，采用分离测试：测试不依赖外部资源的状态管理和数据结构。
// Test strategy: Since signature verification and file hashing depend on Windows DLLs
// and real file system, use separation testing: test state management and data structures
// that don't depend on external resources.
//
// 中文关键词：信任服务，签名验证，缓存配置，SHA-256校验，LRU缓存，单元测试
// English keywords: trust service, signature verification, cache config, SHA-256 validation,
// LRU cache, unit test

use anxin_security::services::trust_service::{TrustService, SignatureVerdict, SignerInfo};

mod common;

// ================================================================
// TrustService 初始化测试 / TrustService initialization tests
// ================================================================

#[test]
fn test_new_service_created_successfully() {
    let svc = TrustService::new();
    // 验证服务可创建不 panic / Verify service can be created without panic
    drop(svc);
}

#[test]
fn test_multiple_instances_independent() {
    let svc1 = TrustService::new();
    let svc2 = TrustService::new();
    // 两个实例独立运行 / Both instances operate independently
    drop(svc1);
    drop(svc2);
}

// ================================================================
// set_cache_config 测试 / set_cache_config tests
// ================================================================

#[test]
fn test_set_cache_config_with_valid_values() {
    let svc = TrustService::new();
    // 设置有效配置 / Set valid config
    svc.set_cache_config(1024, 300_000);
    // 验证不 panic / Verify no panic
}

#[test]
fn test_set_cache_config_with_max_entries_zero() {
    let svc = TrustService::new();
    // max_entries=0 应回退到默认值 / max_entries=0 should fallback to default
    svc.set_cache_config(0, 300_000);
}

#[test]
fn test_set_cache_config_with_ttl_zero() {
    let svc = TrustService::new();
    // ttl_ms=0 应回退到默认值 / ttl_ms=0 should fallback to default
    svc.set_cache_config(512, 0);
}

#[test]
fn test_set_cache_config_with_both_zero() {
    let svc = TrustService::new();
    // 两个都为零，应回退到默认值 / Both zero, should fallback to defaults
    svc.set_cache_config(0, 0);
}

#[test]
fn test_set_cache_config_with_large_values() {
    let svc = TrustService::new();
    // 大数值不应 panic / Large values should not panic
    svc.set_cache_config(100_000, 86_400_000);
}

#[test]
fn test_set_cache_config_multiple_times() {
    let svc = TrustService::new();
    // 多次配置应正常 / Multiple configs should work
    svc.set_cache_config(100, 60_000);
    svc.set_cache_config(500, 120_000);
    svc.set_cache_config(2048, 600_000);
}

// ================================================================
// scan_cache_store 测试 / scan_cache_store tests
// ================================================================

#[test]
fn test_scan_cache_store_valid_sha256_hash() {
    let svc = TrustService::new();
    let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let result = svc.scan_cache_store(hash, 0);
    assert!(result.is_ok(), "有效的 SHA-256 哈希应存储成功");
}

#[test]
fn test_scan_cache_store_multiple_hashes() {
    let svc = TrustService::new();
    let hash_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let hash_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let hash_c = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    assert!(svc.scan_cache_store(hash_a, 0).is_ok());
    assert!(svc.scan_cache_store(hash_b, 1).is_ok());
    assert!(svc.scan_cache_store(hash_c, -1).is_ok());
}

#[test]
fn test_scan_cache_store_overwrite_existing() {
    let svc = TrustService::new();
    let hash = "1111111111111111111111111111111111111111111111111111111111111111";
    svc.scan_cache_store(hash, 0).unwrap();
    // 覆盖写入 / Overwrite
    let result = svc.scan_cache_store(hash, 5);
    assert!(result.is_ok(), "覆盖已有哈希应成功");
}

#[test]
fn test_scan_cache_store_invalid_hash_too_short() {
    let svc = TrustService::new();
    let result = svc.scan_cache_store("short", 0);
    assert!(result.is_err(), "过短的哈希应返回错误");
}

#[test]
fn test_scan_cache_store_invalid_hash_wrong_chars() {
    let svc = TrustService::new();
    let result = svc.scan_cache_store("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 0);
    // 包含非法 hex 字符 / Contains invalid hex chars
    assert!(result.is_err(), "包含非hex字符的哈希应返回错误");
}

#[test]
fn test_scan_cache_store_empty_hash() {
    let svc = TrustService::new();
    let result = svc.scan_cache_store("", 0);
    assert!(result.is_err(), "空哈希应返回错误");
}

// ================================================================
// SignatureVerdict 结构体测试 / SignatureVerdict struct tests
// ================================================================

#[test]
fn test_signature_verdict_trusted() {
    let v = SignatureVerdict { trusted: true, status: 0 };
    assert!(v.trusted);
    assert_eq!(v.status, 0);
}

#[test]
fn test_signature_verdict_untrusted() {
    let v = SignatureVerdict { trusted: false, status: -1 };
    assert!(!v.trusted);
    assert_eq!(v.status, -1);
}

#[test]
fn test_signature_verdict_various_statuses() {
    // 验证不同 WinVerifyTrust 状态码场景 / Verify various WinVerifyTrust status code scenarios
    let trusted = SignatureVerdict { trusted: true, status: 0 }; // TRUST_E_SUBJECT_NOT_TRUSTED? No, 0 = SUCCESS
    let revocation_ok = SignatureVerdict { trusted: true, status: 0 };
    let untrusted = SignatureVerdict { trusted: false, status: 0x80096004u32 as i32 }; // TRUST_E_SUBJECT_NOT_TRUSTED
    let expired = SignatureVerdict { trusted: false, status: 0x800B0101u32 as i32 }; // CERT_E_EXPIRED

    assert!(trusted.trusted);
    assert!(revocation_ok.trusted);
    assert!(!untrusted.trusted);
    assert!(!expired.trusted);
}

// ================================================================
// SignerInfo 结构体测试 / SignerInfo struct tests
// ================================================================

#[test]
fn test_signer_info_all_fields_present() {
    let info = SignerInfo {
        subject: Some("CN=Test Corp".to_string()),
        issuer: Some("CN=Test CA".to_string()),
        thumbprint: Some("ABCDEF1234567890".to_string()),
    };
    assert_eq!(info.subject.as_deref(), Some("CN=Test Corp"));
    assert_eq!(info.issuer.as_deref(), Some("CN=Test CA"));
    assert_eq!(info.thumbprint.as_deref(), Some("ABCDEF1234567890"));
}

#[test]
fn test_signer_info_all_fields_none() {
    let info = SignerInfo {
        subject: None,
        issuer: None,
        thumbprint: None,
    };
    // 验证 None 字段不 panic / Verify None fields don't panic
    assert!(info.subject.is_none());
    assert!(info.issuer.is_none());
    assert!(info.thumbprint.is_none());
}

#[test]
fn test_signer_info_partial_fields() {
    // 仅有部分字段的场景 / Partial fields scenario
    let info = SignerInfo {
        subject: Some("Unknown Publisher".to_string()),
        issuer: None,
        thumbprint: None,
    };
    assert!(info.subject.is_some());
    assert!(info.issuer.is_none());
    assert!(info.thumbprint.is_none());
}

// ================================================================
// 缓存行为模拟测试 / Cache behavior simulation tests
// ================================================================

#[test]
fn test_cache_eviction_with_small_limit() {
    let svc = TrustService::new();
    // 设置非常小的缓存限制 / Set very small cache limit
    svc.set_cache_config(3, 60_000);

    // 存储多个哈希，验证无 panic / Store multiple hashes, verify no panic
    for i in 0..10 {
        let hash = format!("{:064x}", i);
        let _ = svc.scan_cache_store(&hash, i as i32);
    }
}

#[test]
fn test_cache_handles_zero_ttl() {
    let svc = TrustService::new();
    svc.set_cache_config(10, 0); // TTL 为 0 回退到默认 / TTL 0 falls back to default
    // 存储和查询不 panic / Store and query without panic
    let hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    assert!(svc.scan_cache_store(hash, 0).is_ok());
}
