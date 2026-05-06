use crate::services::trust_service::TrustService;
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Serialize)]
pub struct VerifyFileResponse {
    pub trusted: bool,
    pub status: i32,
}

#[derive(Serialize)]
pub struct SignerInfoResponse {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub thumbprint: Option<String>,
}

#[derive(Serialize)]
pub struct ScanCacheLookupResponse {
    pub found: bool,
    pub verdict: i32,
    pub sha256: Option<String>,
}

#[derive(Deserialize)]
pub struct ScanCacheStoreRequest {
    pub hash_hex: String,
    pub verdict: i32,
}

/// 函数名称：verify_file_signature
/// 函数作用：验证文件数字签名，返回签名状态和信任结果。带 LRU 缓存。
/// Purpose: Verifies file digital signature, returns signature status and trust result. LRU cached.
/// 调用方：前端安全扫描页面
/// Called by: Frontend security scan page
/// 中文关键词：数字签名验证，WinVerifyTrust，文件签名，可信文件
/// English keywords: digital signature verification, WinVerifyTrust, file signature, trusted file
#[tauri::command]
pub async fn verify_file_signature(
    trust: State<'_, TrustService>,
    file_path: String,
) -> Result<VerifyFileResponse, String> {
    let verdict = trust.verify_file(&file_path)?;
    Ok(VerifyFileResponse {
        trusted: verdict.trusted,
        status: verdict.status,
    })
}

/// 函数名称：get_signer_info
/// 函数作用：提取文件代码签名证书信息（主题、签发者、指纹）。
/// Purpose: Extracts code signing certificate info (subject, issuer, thumbprint).
/// 调用方：前端安全分析页面
/// Called by: Frontend security analysis page
/// 中文关键词：证书信息，签名者信息，代码签名证书，证书指纹
/// English keywords: certificate info, signer info, code signing cert, cert thumbprint
#[tauri::command]
pub async fn get_signer_info(
    trust: State<'_, TrustService>,
    file_path: String,
) -> Result<SignerInfoResponse, String> {
    let info = trust.get_signer_info(&file_path)?;
    Ok(SignerInfoResponse {
        subject: info.subject,
        issuer: info.issuer,
        thumbprint: info.thumbprint,
    })
}

/// 函数名称：compute_file_sha256
/// 函数作用：计算文件 SHA-256 哈希值，返回十六进制小写字符串。
/// Purpose: Computes file SHA-256 hash and returns lowercase hex string.
/// 调用方：前端文件分析
/// Called by: Frontend file analysis
/// 中文关键词：SHA-256，文件哈希，散列计算
/// English keywords: SHA-256, file hash, hash computation
#[tauri::command]
pub async fn compute_file_sha256(
    trust: State<'_, TrustService>,
    file_path: String,
) -> Result<String, String> {
    trust.compute_sha256(&file_path)
}

/// 函数名称：scan_cache_lookup
/// 函数作用：查找扫描判决缓存，若命中则返回判决和 SHA-256。
/// Purpose: Looks up scan verdict cache, returns verdict and SHA-256 if hit.
/// 调用方：前端扫描结果缓存查询
/// Called by: Frontend scan result cache query
/// 中文关键词：扫描缓存查找，判决查找，病毒库缓存
/// English keywords: scan cache lookup, verdict lookup, virus database cache
#[tauri::command]
pub async fn scan_cache_lookup(
    trust: State<'_, TrustService>,
    file_path: String,
) -> Result<ScanCacheLookupResponse, String> {
    let result = trust.scan_cache_lookup(&file_path)?;
    match result {
        Some((verdict, sha256)) => Ok(ScanCacheLookupResponse {
            found: true,
            verdict,
            sha256: Some(sha256),
        }),
        None => Ok(ScanCacheLookupResponse {
            found: false,
            verdict: 0,
            sha256: None,
        }),
    }
}

/// 函数名称：scan_cache_store
/// 函数作用：存储扫描判决到缓存。
/// Purpose: Stores a scan verdict to cache.
/// 调用方：前端扫描完成后存储结果
/// Called by: Frontend after scan completion
/// 中文关键词：扫描缓存存储，判决存储
/// English keywords: scan cache store, verdict store
#[tauri::command]
pub async fn scan_cache_store(
    trust: State<'_, TrustService>,
    request: ScanCacheStoreRequest,
) -> Result<bool, String> {
    trust.scan_cache_store(&request.hash_hex, request.verdict)?;
    Ok(true)
}

/// 函数名称：set_trust_cache_config
/// 函数作用：配置签名验证缓存的参数（最大条目数和 TTL）。
/// Purpose: Configures signature verification cache parameters (max entries and TTL).
/// 调用方：前端设置页面
/// Called by: Frontend settings page
/// 中文关键词：缓存配置，签名缓存，TTL配置
/// English keywords: cache config, signature cache, TTL config
#[tauri::command]
pub async fn set_trust_cache_config(
    trust: State<'_, TrustService>,
    max_entries: u32,
    ttl_ms: u32,
) -> Result<bool, String> {
    trust.set_cache_config(max_entries, ttl_ms);
    Ok(true)
}
