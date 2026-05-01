use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::sync::Mutex;
use std::time::Instant;
use std::fs::File;

use sha2::{Sha256, Digest};
use libloading::{Library, Symbol};

const DEFAULT_MAX_ENTRIES: usize = 4096;
const DEFAULT_TTL_MS: u64 = 600_000;
const DEFAULT_SCAN_VERDICT_TTL_MS: u64 = 3_600_000;

// CryptQueryObject 常量
const CERT_QUERY_OBJECT_FILE: u32 = 1;
const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED: u32 = 8;
const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED: u32 = 64;
const CERT_QUERY_FORMAT_FLAG_BINARY: u32 = 2;

// CertFindCertificateInStore 常量
const CERT_FIND_SUBJECT_CERT: u32 = 0x000B0000;
const X509_ASN_ENCODING: u32 = 1;
const PKCS_7_ASN_ENCODING: u32 = 0x00010000;

// CertGetNameStringW 常量
const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
const CERT_NAME_ISSUER_FLAG: u32 = 0x00000001;

// CryptMsgGetParam 常量
const CMSG_SIGNER_INFO_PARAM: u32 = 6;

// CertGetCertificateContextProperty 常量
const CERT_HASH_PROP_ID: u32 = 3;

// GetFileAttributesExW 常量
const GET_FILEEX_INFO_LEVELS_STANDARD: u32 = 0;

// GUID for WINTRUST_ACTION_GENERIC_VERIFY_V2 {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

pub const ACTION_VERIFY_V2: Guid = Guid {
    data1: 0x00AAC56B,
    data2: 0xCD44,
    data3: 0x11d0,
    data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};

// WinVerifyTrust 常量 (pub for process_monitor_service reuse)
pub const WTD_UI_NONE: u32 = 2;
pub const WTD_REVOKE_NONE: u32 = 0;
pub const WTD_CHOICE_FILE: u32 = 1;
pub const WTD_STATEACTION_VERIFY: u32 = 1;
pub const WTD_STATEACTION_CLOSE: u32 = 2;
pub const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x00000010;

#[repr(C)]
pub struct WinTrustFileInfo {
    pub cb_struct: u32,
    pub file_path: *const u16,
    pub h_file: isize,
    pub pg_known_subject: *const u8,
}

#[repr(C)]
pub struct WinTrustData {
    pub cb_struct: u32,
    pub policy_callback_data: *const u8,
    pub sip_client_data: *const u8,
    pub ui_choice: u32,
    pub revocation_checks: u32,
    pub union_choice: u32,
    pub union_data: *const WinTrustFileInfo,
    pub state_action: u32,
    pub h_wvt_state_data: isize,
    pub pwsz_url_reference: *const u16,
    pub prov_flags: u32,
    pub ui_context: u32,
    pub p_signature_settings: *const u8,
}

#[repr(C)]
struct CertInfo {
    version: u32,
    serial_number: [u8; 20], // CRYPT_INTEGER_BLOB
    signature_algorithm: [u8; 16], // CRYPT_ALGORITHM_IDENTIFIER
    issuer: [u8; 16], // CERT_NAME_BLOB
    not_before: [u32; 2], // FILETIME
    not_after: [u32; 2], // FILETIME
    subject: [u8; 16], // CERT_NAME_BLOB
    subject_public_key_info: [u8; 24], // CERT_PUBLIC_KEY_INFO
}

#[repr(C)]
struct CMSSignerInfo {
    version: u32,
    issuer: [u8; 16], // CERT_NAME_BLOB
    serial_number: [u8; 20], // CRYPT_INTEGER_BLOB
}

#[repr(C)]
struct Win32FileAttributeData {
    file_attributes: u32,
    creation_time: [u32; 2], // FILETIME
    last_access_time: [u32; 2], // FILETIME
    last_write_time: [u32; 2], // FILETIME
    file_size_high: u32,
    file_size_low: u32,
}

struct CacheEntry {
    status: i32,
    trusted: bool,
    write_time: i64,
    cached_at_ms: u64,
}

struct ScanHashEntry {
    write_time: i64,
    hash_hex: String,
}

struct ScanVerdictEntry {
    verdict: i32,
    cached_at_ms: u64,
}

struct InnerCache {
    entries: HashMap<String, CacheEntry>,
    lru: VecDeque<String>,
    max_entries: usize,
    ttl_ms: u64,
}

pub struct TrustService {
    cache: Mutex<InnerCache>,
    scan_cache: Mutex<ScanCacheInner>,
}

struct ScanCacheInner {
    path_to_hash: HashMap<String, ScanHashEntry>,
    hash_to_verdict: HashMap<String, ScanVerdictEntry>,
    ttl_ms: u64,
}

pub struct SignatureVerdict {
    pub trusted: bool,
    pub status: i32,
}

pub struct SignerInfo {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub thumbprint: Option<String>,
}

impl TrustService {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(InnerCache {
                entries: HashMap::new(),
                lru: VecDeque::new(),
                max_entries: DEFAULT_MAX_ENTRIES,
                ttl_ms: DEFAULT_TTL_MS,
            }),
            scan_cache: Mutex::new(ScanCacheInner {
                path_to_hash: HashMap::new(),
                hash_to_verdict: HashMap::new(),
                ttl_ms: DEFAULT_SCAN_VERDICT_TTL_MS,
            }),
        }
    }

    /// 函数名称：set_cache_config
    /// 函数作用：配置签名验证 LRU 缓存参数（最大条目数、TTL 毫秒）。
    /// Purpose: Configures signature verification LRU cache parameters (max entries, TTL ms).
    /// 调用方：commands::trust::set_trust_cache_config
    /// Called by: commands::trust::set_trust_cache_config
    /// 中文关键词：缓存配置，LRU缓存，签名缓存，TTL，缓存容量
    /// English keywords: cache config, LRU cache, signature cache, TTL, cache capacity
    pub fn set_cache_config(&self, max_entries: u32, ttl_ms: u32) {
        let mut cache = self.cache.lock().unwrap();
        cache.max_entries = if max_entries > 0 { max_entries as usize } else { DEFAULT_MAX_ENTRIES };
        cache.ttl_ms = if ttl_ms > 0 { ttl_ms as u64 } else { DEFAULT_TTL_MS };
        cache.evict_if_needed();
    }

    /// 函数名称：verify_file
    /// 函数作用：验证文件数字签名，返回是否受信及原始 WinVerifyTrust 状态码。带 LRU 缓存。
    /// Purpose: Verifies a file's digital signature, returns trusted status and raw WinVerifyTrust status code. LRU cached.
    /// 调用方：commands::trust::verify_file_signature, process_monitor_service
    /// Called by: commands::trust::verify_file_signature, process_monitor_service
    /// 中文关键词：数字签名验证，WinVerifyTrust，可信验证，签名校验
    /// English keywords: digital signature verification, WinVerifyTrust, trust verification, signature check
    pub fn verify_file(&self, file_path: &str) -> Result<SignatureVerdict, String> {
        let write_time = file_write_time(file_path).unwrap_or(0);
        let norm = normalize_path(file_path);
        let now_ms = monotonic_ms();

        // 先检查缓存
        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.entries.get(&norm) {
                let fresh = entry.write_time == write_time
                    && now_ms >= entry.cached_at_ms
                    && (now_ms - entry.cached_at_ms) <= cache.ttl_ms;
                if fresh {
                    // 克隆需要的数据，释放缓存锁
                    let trusted = entry.trusted;
                    let status = entry.status;
                    drop(cache); // 显式释放
                    // 重新获取锁以更新 LRU
                    let mut cache2 = self.cache.lock().unwrap();
                    cache2.touch_lru(&norm);
                    return Ok(SignatureVerdict { trusted, status });
                }
            }
        }

        let result = verify_file_no_cache(file_path);

        {
            let mut cache = self.cache.lock().unwrap();
            cache.upsert(norm, CacheEntry {
                status: result.status,
                trusted: result.trusted,
                write_time,
                cached_at_ms: now_ms,
            });
            cache.evict_if_needed();
        }

        Ok(result)
    }

    /// 函数名称：get_signer_info
    /// 函数作用：提取文件数字签名证书信息（主题、签发者、指纹）。
    /// Purpose: Extracts code signing certificate info (subject, issuer, thumbprint).
    /// 调用方：commands::trust::get_signer_info
    /// Called by: commands::trust::get_signer_info
    /// 中文关键词：证书信息，签名者，代码签名，证书指纹
    /// English keywords: certificate info, signer, code signing, cert thumbprint
    pub fn get_signer_info(&self, file_path: &str) -> Result<SignerInfo, String> {
        unsafe { get_signer_info_impl(file_path) }
    }

    /// 函数名称：compute_sha256
    /// 函数作用：计算文件 SHA-256 哈希值，返回十六进制小写字符串。
    /// Purpose: Computes file SHA-256 hash and returns lowercase hex string.
    /// 调用方：commands::trust::compute_file_sha256
    /// Called by: commands::trust::compute_file_sha256
    /// 中文关键词：SHA-256，文件哈希，哈希计算，完整性校验
    /// English keywords: SHA-256, file hash, hash computation, integrity check
    pub fn compute_sha256(&self, file_path: &str) -> Result<String, String> {
        sha256_hex_of_file(file_path)
    }

    /// 函数名称：scan_cache_lookup
    /// 函数作用：根据文件路径查找扫描判决缓存。
    /// Purpose: Looks up scan verdict cache by file path.
    /// 调用方：commands::trust::scan_cache_lookup
    /// Called by: commands::trust::scan_cache_lookup
    /// 中文关键词：扫描缓存，判决缓存，病毒扫描，缓存查找
    /// English keywords: scan cache, verdict cache, virus scan, cache lookup
    pub fn scan_cache_lookup(&self, file_path: &str) -> Result<Option<(i32, String)>, String> {
        let wt = file_write_time(file_path).unwrap_or(0);
        let key = normalize_path(file_path);
        let now_ms = monotonic_ms();

        let hash_hex = {
            let cache = self.scan_cache.lock().unwrap();
            cache.path_to_hash.get(&key)
                .filter(|e| e.write_time == wt && !e.hash_hex.is_empty())
                .map(|e| e.hash_hex.clone())
                .unwrap_or_default()
        };

        let hash_hex = if hash_hex.is_empty() {
            let h = sha256_hex_of_file(file_path)?;
            self.scan_cache.lock().unwrap().path_to_hash.insert(key, ScanHashEntry {
                write_time: wt,
                hash_hex: h.clone(),
            });
            h
        } else {
            hash_hex
        };

        let mut cache = self.scan_cache.lock().unwrap();
        if let Some(entry) = cache.hash_to_verdict.get(&hash_hex) {
            let fresh = now_ms >= entry.cached_at_ms
                && (now_ms - entry.cached_at_ms) <= cache.ttl_ms;
            if fresh {
                return Ok(Some((entry.verdict, hash_hex)));
            } else {
                cache.hash_to_verdict.remove(&hash_hex);
            }
        }
        Ok(None)
    }

    /// 函数名称：scan_cache_store
    /// 函数作用：存储扫描判决到缓存，以 SHA-256 为键。
    /// Purpose: Stores a scan verdict to cache, keyed by SHA-256 hash.
    /// 调用方：commands::trust::scan_cache_store
    /// Called by: commands::trust::scan_cache_store
    /// 中文关键词：扫描缓存存储，判决存储
    /// English keywords: scan cache store, verdict store
    pub fn scan_cache_store(&self, hash_hex: &str, verdict: i32) -> Result<(), String> {
        if !is_hex_lower_64(hash_hex) {
            return Err("Invalid SHA-256 hash format".to_string());
        }
        let now_ms = monotonic_ms();
        let mut cache = self.scan_cache.lock().unwrap();
        cache.hash_to_verdict.insert(hash_hex.to_string(), ScanVerdictEntry {
            verdict,
            cached_at_ms: now_ms,
        });
        Ok(())
    }
}

impl InnerCache {
    fn touch_lru(&mut self, key: &str) {
        self.lru.retain(|k| k != key);
        self.lru.push_front(key.to_string());
    }

    fn upsert(&mut self, key: String, entry: CacheEntry) {
        if let Some(existing) = self.entries.get_mut(&key) {
            existing.status = entry.status;
            existing.trusted = entry.trusted;
            existing.write_time = entry.write_time;
            existing.cached_at_ms = entry.cached_at_ms;
            self.touch_lru(&key);
        } else {
            self.lru.push_front(key.clone());
            self.entries.insert(key, entry);
        }
    }

    fn evict_if_needed(&mut self) {
        while self.entries.len() > self.max_entries {
            if let Some(back) = self.lru.pop_back() {
                self.entries.remove(&back);
            } else {
                break;
            }
        }
    }
}

/// 函数名称：normalize_path
/// 函数作用：规范化文件路径：转小写、正斜杠改反斜杠、去除 \\?\ 和 \??\ 前缀。
/// Purpose: Normalizes file path: lowercases, converts / to \, strips \\?\ and \??\ prefixes.
/// 被调用方：verify_file, scan_cache_lookup
/// Called by: verify_file, scan_cache_lookup
/// 中文关键词：路径规范化，标准化路径，小写路径，路径前缀，缓存键
/// English keywords: path normalization, canonical path, lowercase path, path prefix, cache key
fn normalize_path(s: &str) -> String {
    let mut out: String = s.chars().map(|c| {
        if c == '/' { '\\' }
        else if c.is_ascii_uppercase() { c.to_ascii_lowercase() }
        else { c }
    }).collect();
    if out.starts_with("\\\\?\\") {
        out = out[4..].to_string();
    }
    if out.starts_with("\\??\\") {
        out = out[4..].to_string();
    }
    out
}

/// 函数名称：to_wide
/// 函数作用：将 Rust 字符串转为宽字符 null 结尾数组，用于 Windows API 调用。
/// Purpose: Converts Rust string to null-terminated wide char array for Windows API.
/// 中文关键词：宽字符，UTF-16，Windows API，字符串转换
/// English keywords: wide char, UTF-16, Windows API, string conversion
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 函数名称：file_write_time
/// 函数作用：通过 GetFileAttributesExW 获取文件的最后写入时间（FILETIME 转为 i64）。
/// Purpose: Gets file last write time via GetFileAttributesExW (FILETIME to i64).
/// 被调用方：verify_file, scan_cache_lookup
/// Called by: verify_file, scan_cache_lookup
/// 中文关键词：文件时间，写入时间，GetFileAttributesExW，FILETIME，缓存失效
/// English keywords: file time, write time, GetFileAttributesExW, FILETIME, cache invalidation
fn file_write_time(file_path: &str) -> Option<i64> {
    let wide = to_wide(file_path);
    unsafe {
        let kernel32 = Library::new("kernel32.dll").ok()?;
        let get_attrs: Symbol<unsafe extern "system" fn(*const u16, u32, *mut Win32FileAttributeData) -> i32> =
            kernel32.get(b"GetFileAttributesExW").ok()?;

        let mut fad: Win32FileAttributeData = std::mem::zeroed();
        let ok = get_attrs(wide.as_ptr(), GET_FILEEX_INFO_LEVELS_STANDARD, &mut fad);
        if ok == 0 {
            return None;
        }
        // FILETIME is 2 u32s: low then high
        let ft: i64 = (fad.last_write_time[1] as i64) << 32 | (fad.last_write_time[0] as i64 as u32 as i64);
        Some(ft)
    }
}

/// 函数名称：monotonic_ms
/// 函数作用：返回自系统启动以来的单调时钟毫秒数，用于缓存 TTL 计算。
/// Purpose: Returns monotonic clock milliseconds since system boot, used for cache TTL.
fn monotonic_ms() -> u64 {
    Instant::now().elapsed().as_millis() as u64
}

/// 函数名称：verify_file_no_cache
/// 函数作用：调用 WinVerifyTrust 验证文件数字签名（不经过缓存）。
/// Purpose: Calls WinVerifyTrust to verify file digital signature (bypasses cache).
/// 被调用方：verify_file
/// Calls: WinVerifyTrust (wintrust.dll libloading)
/// 参数：file_path — 文件绝对路径
/// 返回值：SignatureVerdict（包含 trusted 状态和原始 WinVerifyTrust 状态码）
/// 错误处理：DLL 加载失败返回兼容的失败结果（status=-1, trusted=false）
/// Error handling: Returns compatible failure result on DLL load error
/// 副作用：调用 WinVerifyTrust (WTD_STATEACTION_CLOSE 清理状态)
/// 中文关键词：无缓存签名验证，WinVerifyTrust，原始API，直接调用
/// English keywords: uncached signature verify, WinVerifyTrust, raw API, direct call
fn verify_file_no_cache(file_path: &str) -> SignatureVerdict {
    let wide = to_wide(file_path);
    let status = unsafe {
        match Library::new("wintrust.dll") {
            Ok(wintrust) => match wintrust.get::<unsafe extern "system" fn(isize, *const Guid, *const WinTrustData) -> i32>(b"WinVerifyTrust") {
                Ok(verify) => {
                    let file_info = WinTrustFileInfo {
                        cb_struct: std::mem::size_of::<WinTrustFileInfo>() as u32,
                        file_path: wide.as_ptr(),
                        h_file: 0,
                        pg_known_subject: std::ptr::null(),
                    };

                    let mut data = WinTrustData {
                        cb_struct: std::mem::size_of::<WinTrustData>() as u32,
                        policy_callback_data: std::ptr::null(),
                        sip_client_data: std::ptr::null(),
                        ui_choice: WTD_UI_NONE,
                        revocation_checks: WTD_REVOKE_NONE,
                        union_choice: WTD_CHOICE_FILE,
                        union_data: &file_info,
                        state_action: WTD_STATEACTION_VERIFY,
                        h_wvt_state_data: 0,
                        pwsz_url_reference: std::ptr::null(),
                        prov_flags: WTD_CACHE_ONLY_URL_RETRIEVAL,
                        ui_context: 0,
                        p_signature_settings: std::ptr::null(),
                    };

                    let status = verify(0, &ACTION_VERIFY_V2, &data);
                    data.state_action = WTD_STATEACTION_CLOSE;
                    verify(0, &ACTION_VERIFY_V2, &data);
                    status
                }
                Err(_) => -1,
            },
            Err(_) => -1,
        }
    };

    SignatureVerdict {
        trusted: status == 0,
        status,
    }
}

unsafe fn get_signer_info_impl(file_path: &str) -> Result<SignerInfo, String> {
    let crypt32 = Library::new("crypt32.dll")
        .map_err(|e| format!("Failed to load crypt32.dll: {}", e))?;

    type CryptQueryObjectFn = unsafe extern "system" fn(
        u32, *const u16, u32, u32, u32, u32, *mut u32, *mut u32, *mut u32,
        *mut *mut std::ffi::c_void, *mut *mut std::ffi::c_void, *mut *mut std::ffi::c_void,
    ) -> i32;
    let crypt_query: Symbol<CryptQueryObjectFn> = crypt32.get(b"CryptQueryObject")
        .map_err(|e| format!("Failed to load CryptQueryObject: {}", e))?;

    type CryptMsgCloseFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> i32;
    let crypt_msg_close: Symbol<CryptMsgCloseFn> = crypt32.get(b"CryptMsgClose")
        .map_err(|e| format!("Failed to load CryptMsgClose: {}", e))?;

    type CertCloseStoreFn = unsafe extern "system" fn(*mut std::ffi::c_void, u32) -> i32;
    let cert_close_store: Symbol<CertCloseStoreFn> = crypt32.get(b"CertCloseStore")
        .map_err(|e| format!("Failed to load CertCloseStore: {}", e))?;

    type CryptMsgGetParamFn = unsafe extern "system" fn(
        *mut std::ffi::c_void, u32, u32, *mut std::ffi::c_void, *mut u32,
    ) -> i32;
    let crypt_msg_get_param: Symbol<CryptMsgGetParamFn> = crypt32.get(b"CryptMsgGetParam")
        .map_err(|e| format!("Failed to load CryptMsgGetParam: {}", e))?;

    type CertFindCertificateInStoreFn = unsafe extern "system" fn(
        *mut std::ffi::c_void, u32, u32, u32, *const std::ffi::c_void,
        *const std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    let cert_find: Symbol<CertFindCertificateInStoreFn> = crypt32.get(b"CertFindCertificateInStore")
        .map_err(|e| format!("Failed to load CertFindCertificateInStore: {}", e))?;

    type CertGetNameStringWFn = unsafe extern "system" fn(
        *const std::ffi::c_void, u32, u32, *const std::ffi::c_void, *mut u16, u32,
    ) -> u32;
    let cert_get_name: Symbol<CertGetNameStringWFn> = crypt32.get(b"CertGetNameStringW")
        .map_err(|e| format!("Failed to load CertGetNameStringW: {}", e))?;

    type CertFreeCertificateContextFn = unsafe extern "system" fn(*const std::ffi::c_void) -> i32;
    let cert_free: Symbol<CertFreeCertificateContextFn> = crypt32.get(b"CertFreeCertificateContext")
        .map_err(|e| format!("Failed to load CertFreeCertificateContext: {}", e))?;

    type CertGetCertificateContextPropertyFn = unsafe extern "system" fn(
        *const std::ffi::c_void, u32, *mut u8, *mut u32,
    ) -> i32;
    let cert_get_prop: Symbol<CertGetCertificateContextPropertyFn> = crypt32.get(b"CertGetCertificateContextProperty")
        .map_err(|e| format!("Failed to load CertGetCertificateContextProperty: {}", e))?;

    let wide = to_wide(file_path);
    let mut store: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut msg: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut enc: u32 = 0;
    let mut content: u32 = 0;
    let mut format: u32 = 0;

    let ok = crypt_query(
        CERT_QUERY_OBJECT_FILE,
        wide.as_ptr(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        std::mem::size_of::<u32>() as u32, // dwExpectedEncodingTypeIn
        &mut enc,
        &mut content,
        &mut format,
        &mut store,
        &mut msg,
        std::ptr::null_mut(),
    );

    if ok == 0 || store.is_null() || msg.is_null() {
        if !store.is_null() { cert_close_store(store, 0); }
        if !msg.is_null() { crypt_msg_close(msg); }
        return Err("File has no embedded signature".to_string());
    }

    let subject = cert_name_string_inner(
        store, msg, false,
        *crypt_msg_get_param, *cert_find, *cert_get_name, *cert_free,
    );
    let issuer = cert_name_string_inner(
        store, msg, true,
        *crypt_msg_get_param, *cert_find, *cert_get_name, *cert_free,
    );
    let thumbprint = cert_thumbprint_inner(
        store, msg,
        *crypt_msg_get_param, *cert_find, *cert_get_prop, *cert_free,
    );

    crypt_msg_close(msg);
    cert_close_store(store, 0);

    Ok(SignerInfo {
        subject,
        issuer,
        thumbprint,
    })
}

unsafe fn cert_name_string_inner(
    store: *mut std::ffi::c_void,
    msg: *mut std::ffi::c_void,
    is_issuer: bool,
    get_param: unsafe extern "system" fn(*mut std::ffi::c_void, u32, u32, *mut std::ffi::c_void, *mut u32) -> i32,
    find_cert: unsafe extern "system" fn(*mut std::ffi::c_void, u32, u32, u32, *const std::ffi::c_void, *const std::ffi::c_void) -> *mut std::ffi::c_void,
    get_name: unsafe extern "system" fn(*const std::ffi::c_void, u32, u32, *const std::ffi::c_void, *mut u16, u32) -> u32,
    free_cert: unsafe extern "system" fn(*const std::ffi::c_void) -> i32,
) -> Option<String> {
    let mut size: u32 = 0;
    let ok = get_param(msg, CMSG_SIGNER_INFO_PARAM, 0, std::ptr::null_mut(), &mut size);
    if ok == 0 || size == 0 {
        return None;
    }

    let mut buf: Vec<u8> = vec![0u8; size as usize];
    let ok = get_param(msg, CMSG_SIGNER_INFO_PARAM, 0, buf.as_mut_ptr() as _, &mut size);
    if ok == 0 {
        return None;
    }

    let si = &*(buf.as_ptr() as *const CMSSignerInfo);
    let ci = CertInfo {
        issuer: si.issuer,
        serial_number: si.serial_number,
        ..std::mem::zeroed()
    };

    let cert = find_cert(
        store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_CERT,
        &ci as *const CertInfo as *const std::ffi::c_void,
        std::ptr::null(),
    );
    if cert.is_null() {
        return None;
    }

    let flags = if is_issuer { CERT_NAME_ISSUER_FLAG } else { 0 };
    let mut name_buf: Vec<u16> = vec![0u16; 512];
    let got = get_name(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, std::ptr::null(), name_buf.as_mut_ptr(), 512);

    free_cert(cert);

    if got <= 1 {
        None
    } else {
        Some(String::from_utf16_lossy(&name_buf[..got as usize]))
    }
}

unsafe fn cert_thumbprint_inner(
    store: *mut std::ffi::c_void,
    msg: *mut std::ffi::c_void,
    get_param: unsafe extern "system" fn(*mut std::ffi::c_void, u32, u32, *mut std::ffi::c_void, *mut u32) -> i32,
    find_cert: unsafe extern "system" fn(*mut std::ffi::c_void, u32, u32, u32, *const std::ffi::c_void, *const std::ffi::c_void) -> *mut std::ffi::c_void,
    get_prop: unsafe extern "system" fn(*const std::ffi::c_void, u32, *mut u8, *mut u32) -> i32,
    free_cert: unsafe extern "system" fn(*const std::ffi::c_void) -> i32,
) -> Option<String> {
    let mut size: u32 = 0;
    let ok = get_param(msg, CMSG_SIGNER_INFO_PARAM, 0, std::ptr::null_mut(), &mut size);
    if ok == 0 || size == 0 {
        return None;
    }

    let mut buf: Vec<u8> = vec![0u8; size as usize];
    let ok = get_param(msg, CMSG_SIGNER_INFO_PARAM, 0, buf.as_mut_ptr() as _, &mut size);
    if ok == 0 {
        return None;
    }

    let si = &*(buf.as_ptr() as *const CMSSignerInfo);
    let ci = CertInfo {
        issuer: si.issuer,
        serial_number: si.serial_number,
        ..std::mem::zeroed()
    };

    let cert = find_cert(
        store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_CERT,
        &ci as *const CertInfo as *const std::ffi::c_void,
        std::ptr::null(),
    );
    if cert.is_null() {
        return None;
    }

    let mut hash: [u8; 64] = [0u8; 64];
    let mut hash_len: u32 = 64;
    let ok = get_prop(cert, CERT_HASH_PROP_ID, hash.as_mut_ptr(), &mut hash_len);

    free_cert(cert);

    if ok == 0 || hash_len == 0 {
        return None;
    }

    let hex: String = hash[..hash_len as usize].iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    Some(hex)
}

/// 函数名称：sha256_hex_of_file
/// 函数作用：使用 sha2 crate 分块读取文件并计算 SHA-256 哈希值，返回小写十六进制字符串。
/// Purpose: Reads file in chunks using sha2 crate, computes SHA-256 hash, returns lowercase hex string.
/// 被调用方：compute_sha256, scan_cache_lookup
/// Called by: compute_sha256, scan_cache_lookup
/// 返回值：Ok(hex_string) 或 Err(IO error)
/// 错误处理：文件打开/读取失败直接返回 Err
/// 副作用：读取文件内容（不修改）
/// 中文关键词：SHA-256，文件哈希，哈希计算，sha2，十六进制
/// English keywords: SHA-256, file hash, hash computation, sha2, hex
fn sha256_hex_of_file(file_path: &str) -> Result<String, String> {
    let mut file = File::open(file_path)
        .map_err(|e| format!("Failed to open file for SHA-256: {}", e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)
            .map_err(|e| format!("Failed to read file for SHA-256: {}", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// 函数名称：is_hex_lower_64
/// 函数作用：检查字符串是否为 64 字符的小写十六进制字符串（SHA-256 格式）。
/// Purpose: Checks if string is 64-char lowercase hex string (SHA-256 format).
fn is_hex_lower_64(s: &str) -> bool {
    if s.len() != 64 {
        return false;
    }
    s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}
