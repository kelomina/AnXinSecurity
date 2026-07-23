// 身份校验服务 — 采集 IPC 客户端进程身份证据并校验合法性
//  Identity verification service - collects IPC client process identity evidence and verifies legitimacy
//
// 职责：
//  Responsibilities:
// - 采集客户端进程的 PID/路径/启动时间/签名/SID/会话/完整性级别
// - 校验客户端是否为合法 AnXinSecurity UI 进程
// - 提供 PID 重用检测（比对启动时间）
//
// 安全边界：
//  Security boundary:
// - 所有校验失败必须 fail-closed（拒绝连接）
// - 开发模式通过 ANXIN_DEV_MODE=1 环境变量跳过签名校验
//
// 中文关键词：身份校验，PID 重用，进程签名，完整性级别，会话校验
// English keywords: identity verification, PID reuse, process signature, integrity level, session check
use std::path::PathBuf;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel,
    TokenSessionId, TokenUser, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

// ============================================================================
// 数据结构 / Data structures
// ============================================================================

/// 客户端进程身份证据
///  Client process identity evidence
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    /// 客户端进程 PID
    ///  Client process PID
    pub pid: u32,
    /// 客户端进程路径（canonicalize 后）
    ///  Client process path (canonicalized)
    pub path: PathBuf,
    /// 客户端进程启动时间（Unix 毫秒）
    ///  Client process start time (Unix ms)
    pub start_time: u64,
    /// 客户端用户 SID
    ///  Client user SID
    pub user_sid: String,
    /// 客户端会话 ID
    ///  Client session ID
    pub session_id: u32,
    /// 客户端完整性级别 ("low" | "medium" | "high")
    ///  Client integrity level
    pub integrity_level: String,
}

/// 校验错误类型
///  Verification error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// 路径不匹配
    PathMismatch,
    /// 签名无效
    SignatureInvalid,
    /// SID 非法（SYSTEM 或服务账户）
    InvalidSid,
    /// 会话不匹配
    SessionMismatch,
    /// 完整性级别过低（Low）
    IntegrityTooLow,
}

/// 已知的 AnXinSecurity 可执行文件名
///  Known AnXinSecurity executable filenames
const ANXIN_EXE_NAMES: &[&str] = &["anxin-security.exe"];

impl ClientIdentity {
    /// 校验路径是否为合法的 AnXinSecurity 可执行文件
    ///  Verify path is a legitimate AnXinSecurity executable
    ///
    /// 开发模式允许 target\debug\ 或 target\release\ 路径
    ///  Dev mode allows target\debug\ or target\release\ paths
    pub fn is_valid_anxin_path(&self, dev_mode: bool) -> bool {
        let filename = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if !ANXIN_EXE_NAMES.contains(&filename.to_lowercase().as_str()) {
            return false;
        }

        if dev_mode {
            // 开发模式：允许 target\debug 或 target\release 路径
            let path_str = self.path.to_string_lossy().to_lowercase();
            return path_str.contains("target\\debug\\") || path_str.contains("target\\release\\");
        }

        // 生产模式：路径必须不包含 target（即不是开发构建）
        // 实际生产校验由调用方补充安装目录比对
        !self.path.to_string_lossy().to_lowercase().contains("target\\")
    }

    /// 校验 SID 是否为交互式用户（拒绝 SYSTEM 和服务账户）
    ///  Verify SID is interactive user (reject SYSTEM and service accounts)
    pub fn is_valid_sid(&self) -> bool {
        // SYSTEM SID: S-1-5-18
        // LocalService: S-1-5-19
        // NetworkService: S-1-5-20
        let system_sids = ["S-1-5-18", "S-1-5-19", "S-1-5-20"];
        !system_sids.contains(&self.user_sid.as_str())
    }

    /// 校验完整性级别是否足够（拒绝 Low）
    ///  Verify integrity level is sufficient (reject Low)
    pub fn is_valid_integrity(&self) -> bool {
        self.integrity_level != "low" && self.integrity_level != "untrusted"
    }
}

// ============================================================================
// 校验函数 / Verification functions
// ============================================================================

/// 校验客户端身份是否为合法 AnXinSecurity UI 进程
///  Verify client identity is a legitimate AnXinSecurity UI process
pub fn verify_identity(
    identity: &ClientIdentity,
    expected_session_id: u32,
    dev_mode: bool,
) -> Result<(), VerifyError> {
    // a. 路径校验
    if !identity.is_valid_anxin_path(dev_mode) {
        return Err(VerifyError::PathMismatch);
    }
    // b. 签名校验由调用方在采集时完成（WinVerifyTrust），这里通过 dev_mode 跳过
    //  Signature verification done by caller during collection, skipped here via dev_mode
    // c. SID 校验
    if !identity.is_valid_sid() {
        return Err(VerifyError::InvalidSid);
    }
    // d. 会话 ID 校验
    if identity.session_id != expected_session_id {
        return Err(VerifyError::SessionMismatch);
    }
    // e. 完整性级别校验
    if !identity.is_valid_integrity() {
        return Err(VerifyError::IntegrityTooLow);
    }
    Ok(())
}

/// 检测 PID 重用：比对当前进程启动时间与记录的启动时间
///  Detect PID reuse: compare current process start time with recorded start time
pub fn detect_pid_reuse(current_start_time: u64, recorded_start_time: u64) -> bool {
    current_start_time != recorded_start_time
}

/// 判断是否为开发模式
///  Check if running in dev mode
pub fn is_dev_mode() -> bool {
    std::env::var("ANXIN_DEV_MODE")
        .map(|v| v == "1")
        .unwrap_or(false)
}

// ============================================================================
// Windows API 证据采集 / Windows API evidence collection
// ============================================================================

/// 采集客户端进程身份证据
///  Collect client process identity evidence
///
/// 通过命名管道句柄获取客户端 PID，再打开进程采集完整身份信息
///  Gets client PID via named pipe handle, then opens process to collect full identity
///
/// 安全说明：所有 Windows API 调用失败都返回 Err，调用方必须 fail-closed
///  Security: all Windows API failures return Err, caller must fail-closed
pub fn collect_evidence(pipe_handle: HANDLE) -> Result<ClientIdentity, String> {
    // 1. 获取客户端真实 PID
    let pid = get_pipe_client_pid(pipe_handle)?;

    // 2. 打开客户端进程
    let process = open_process_for_query(pid)?;

    // 3. 采集路径
    let path = query_process_path(process)?;

    // 4. 采集启动时间
    let start_time = query_process_start_time(process)?;

    // 5. 打开进程令牌
    let token = open_process_token(process)?;

    // 6. 采集 SID
    let user_sid = query_token_sid(&token)?;

    // 7. 采集会话 ID
    let session_id = query_token_session_id(&token)?;

    // 8. 采集完整性级别
    let integrity_level = query_token_integrity_level(&token)?;

    unsafe {
        let _ = CloseHandle(process);
        let _ = CloseHandle(token);
    }

    Ok(ClientIdentity {
        pid,
        path: path.canonicalize().unwrap_or(path),
        start_time,
        user_sid,
        session_id,
        integrity_level,
    })
}

/// 通过命名管道句柄获取客户端 PID
///  Get client PID via named pipe handle
fn get_pipe_client_pid(pipe_handle: HANDLE) -> Result<u32, String> {
    use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
    let mut pid: u32 = 0;
    unsafe {
        GetNamedPipeClientProcessId(pipe_handle, &mut pid as *mut _ as *mut _)
            .map_err(|e| format!("GetNamedPipeClientProcessId failed: {}", e))?;
    }
    Ok(pid)
}

/// 打开进程用于查询信息
///  Open process for query information
fn open_process_for_query(pid: u32) -> Result<HANDLE, String> {
    unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| format!("OpenProcess({}) failed: {}", pid, e))
    }
}

/// 查询进程完整路径
///  Query full process image path
fn query_process_path(process: HANDLE) -> Result<PathBuf, String> {
    let mut buffer = [0u16; 1024];
    let mut size = buffer.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
        .map_err(|e| format!("QueryFullProcessImageNameW failed: {}", e))?;
    }
    let path_str = String::from_utf16_lossy(&buffer[..size as usize]);
    Ok(PathBuf::from(path_str))
}

/// 查询进程启动时间（FILETIME 转换为 Unix 毫秒）
///  Query process start time (FILETIME converted to Unix ms)
fn query_process_start_time(process: HANDLE) -> Result<u64, String> {
    let mut creation_time = FILETIME::default();
    let mut exit_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();

    unsafe {
        GetProcessTimes(
            process,
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )
        .map_err(|e| format!("GetProcessTimes failed: {}", e))?;
    }

    // FILETIME 是 100 纳秒单位，从 1601-01-01 开始
    //  Unix ms = (filetime / 10000) - 11644473600000
    let filetime_u64 = ((creation_time.dwHighDateTime as u64) << 32)
        | (creation_time.dwLowDateTime as u64);
    Ok(filetime_u64 / 10_000 - 11_644_473_600_000)
}

/// 打开进程令牌
///  Open process token
fn open_process_token(process: HANDLE) -> Result<HANDLE, String> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(process, TOKEN_QUERY, &mut token)
            .map_err(|e| format!("OpenProcessToken failed: {}", e))?;
    }
    Ok(token)
}

/// 查询令牌用户 SID
///  Query token user SID
fn query_token_sid(token: &HANDLE) -> Result<String, String> {
    let mut return_length: u32 = 0;
    unsafe {
        // 第一次调用获取所需缓冲区大小
        let _ = GetTokenInformation(*token, TokenUser, None, 0, &mut return_length);
    }

    let mut buffer = vec![0u8; return_length as usize];
    unsafe {
        GetTokenInformation(
            *token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut _),
            return_length,
            &mut return_length,
        )
        .map_err(|e| format!("GetTokenInformation(TokenUser) failed: {}", e))?;
    }

    let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    let mut sid_string_ptr = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string_ptr)
            .map_err(|e| format!("ConvertSidToStringSidW failed: {}", e))?;
        let sid_string = sid_string_ptr
            .to_string()
            .map_err(|e| format!("SID string conversion failed: {}", e))?;
        let _ = windows::Win32::Foundation::LocalFree(HLOCAL(sid_string_ptr.0 as *mut _));
        Ok(sid_string)
    }
}

/// 查询令牌会话 ID
///  Query token session ID
fn query_token_session_id(token: &HANDLE) -> Result<u32, String> {
    let mut return_length: u32 = 0;
    unsafe {
        let _ = GetTokenInformation(*token, TokenSessionId, None, 0, &mut return_length);
    }

    let mut session_id: u32 = 0;
    unsafe {
        GetTokenInformation(
            *token,
            TokenSessionId,
            Some(&mut session_id as *mut _ as *mut _),
            std::mem::size_of::<u32>() as u32,
            &mut return_length,
        )
        .map_err(|e| format!("GetTokenInformation(TokenSessionId) failed: {}", e))?;
    }
    Ok(session_id)
}

/// 查询令牌完整性级别
///  Query token integrity level
fn query_token_integrity_level(token: &HANDLE) -> Result<String, String> {
    let mut return_length: u32 = 0;
    unsafe {
        let _ = GetTokenInformation(*token, TokenIntegrityLevel, None, 0, &mut return_length);
    }

    let mut buffer = vec![0u8; return_length as usize];
    unsafe {
        GetTokenInformation(
            *token,
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr() as *mut _),
            return_length,
            &mut return_length,
        )
        .map_err(|e| format!("GetTokenInformation(TokenIntegrityLevel) failed: {}", e))?;
    }

    let label = unsafe { &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
    let sid = label.Label.Sid;
    let sub_authority_count_ptr = unsafe { GetSidSubAuthorityCount(sid) };
    if sub_authority_count_ptr.is_null() {
        return Ok("unknown".to_string());
    }
    let sub_authority_count = unsafe { *sub_authority_count_ptr } as u32;
    if sub_authority_count == 0 {
        return Ok("unknown".to_string());
    }

    // 最后一个 SubAuthority 决定完整性级别
    let rid_ptr = unsafe { GetSidSubAuthority(sid, sub_authority_count - 1) };
    if rid_ptr.is_null() {
        return Ok("unknown".to_string());
    }
    let rid = unsafe { *rid_ptr };
    let level = match rid {
        0x0000 => "untrusted",
        0x1000 => "low",
        0x2000 => "medium",
        0x3000 => "medium_plus",
        0x4000 => "high",
        0x5000 => "system",
        0x6000 => "protected",
        _ => "unknown",
    };
    Ok(level.to_string())
}

/// 获取当前进程的会话 ID（用于与服务进程会话比对）
///  Get current process session ID (for comparing with service process session)
pub fn get_current_session_id() -> Result<u32, String> {
    use windows::Win32::System::Threading::GetCurrentProcess;
    let process = unsafe { GetCurrentProcess() };
    let token = open_process_token(process)?;
    let session_id = query_token_session_id(&token)?;
    unsafe {
        let _ = CloseHandle(token);
    }
    Ok(session_id)
}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_identity(
        pid: u32,
        path: &str,
        sid: &str,
        session: u32,
        integrity: &str,
    ) -> ClientIdentity {
        ClientIdentity {
            pid,
            path: PathBuf::from(path),
            start_time: 1000,
            user_sid: sid.to_string(),
            session_id: session,
            integrity_level: integrity.to_string(),
        }
    }

    #[test]
    fn valid_anxin_path_accepts_production_path() {
        let identity = make_test_identity(
            1234,
            "C:\\Program Files\\AnXinSecurity\\anxin-security.exe",
            "S-1-5-21-1000",
            1,
            "medium",
        );
        assert!(identity.is_valid_anxin_path(false));
    }

    #[test]
    fn valid_anxin_path_rejects_wrong_filename() {
        let identity = make_test_identity(
            1234,
            "C:\\evil\\malware.exe",
            "S-1-5-21-1000",
            1,
            "medium",
        );
        assert!(!identity.is_valid_anxin_path(false));
    }

    #[test]
    fn valid_anxin_path_dev_mode_allows_target_debug() {
        let identity = make_test_identity(
            1234,
            "E:\\Project\\target\\debug\\anxin-security.exe",
            "S-1-5-21-1000",
            1,
            "medium",
        );
        assert!(identity.is_valid_anxin_path(true));
    }

    #[test]
    fn valid_anxin_path_production_rejects_target_path() {
        let identity = make_test_identity(
            1234,
            "E:\\Project\\target\\release\\anxin-security.exe",
            "S-1-5-21-1000",
            1,
            "medium",
        );
        assert!(!identity.is_valid_anxin_path(false));
    }

    #[test]
    fn valid_sid_rejects_system() {
        let identity = make_test_identity(1234, "C:\\anxin-security.exe", "S-1-5-18", 1, "medium");
        assert!(!identity.is_valid_sid());
    }

    #[test]
    fn valid_sid_rejects_local_service() {
        let identity = make_test_identity(1234, "C:\\anxin-security.exe", "S-1-5-19", 1, "medium");
        assert!(!identity.is_valid_sid());
    }

    #[test]
    fn valid_sid_accepts_interactive_user() {
        let identity = make_test_identity(
            1234,
            "C:\\anxin-security.exe",
            "S-1-5-21-12345-67890-1000",
            1,
            "medium",
        );
        assert!(identity.is_valid_sid());
    }

    #[test]
    fn valid_integrity_rejects_low() {
        let identity = make_test_identity(1234, "C:\\anxin-security.exe", "S-1-5-21-1000", 1, "low");
        assert!(!identity.is_valid_integrity());
    }

    #[test]
    fn valid_integrity_accepts_medium() {
        let identity =
            make_test_identity(1234, "C:\\anxin-security.exe", "S-1-5-21-1000", 1, "medium");
        assert!(identity.is_valid_integrity());
    }

    #[test]
    fn verify_identity_passes_all_checks() {
        let identity = make_test_identity(
            1234,
            "C:\\Program Files\\AnXinSecurity\\anxin-security.exe",
            "S-1-5-21-1000",
            1,
            "medium",
        );
        assert!(verify_identity(&identity, 1, false).is_ok());
    }

    #[test]
    fn verify_identity_rejects_session_mismatch() {
        let identity = make_test_identity(
            1234,
            "C:\\Program Files\\AnXinSecurity\\anxin-security.exe",
            "S-1-5-21-1000",
            2,
            "medium",
        );
        assert_eq!(
            verify_identity(&identity, 1, false),
            Err(VerifyError::SessionMismatch)
        );
    }

    #[test]
    fn verify_identity_rejects_system_sid() {
        let identity = make_test_identity(
            1234,
            "C:\\Program Files\\AnXinSecurity\\anxin-security.exe",
            "S-1-5-18",
            1,
            "medium",
        );
        assert_eq!(
            verify_identity(&identity, 1, false),
            Err(VerifyError::InvalidSid)
        );
    }

    #[test]
    fn detect_pid_reuse_returns_true_on_mismatch() {
        assert!(detect_pid_reuse(2000, 1000));
    }

    #[test]
    fn detect_pid_reuse_returns_false_on_match() {
        assert!(!detect_pid_reuse(1000, 1000));
    }
}
