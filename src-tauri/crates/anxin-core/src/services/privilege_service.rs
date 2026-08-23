// 权限检查服务
//  Privilege checking service
//
// 检测当前进程是否以管理员权限运行。
//  Detects whether the current process is running with administrator privileges.
//
// 中文关键词：管理员权限，UAC，令牌提升，权限检查
// English keywords: administrator privilege, UAC, token elevation, privilege check
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub struct PrivilegeService;

impl PrivilegeService {
    /// 检查当前进程是否以管理员权限运行（UAC 提升后的令牌）。
    ///  Checks if the current process is running with elevated (administrator) privileges.
    ///
    /// 返回 true 表示当前进程已提升权限，可以启动需要管理员的防护功能（ETW、进程监控、文件钩子）。
    /// Returns true if the process has elevated privileges.
    pub fn is_elevated() -> bool {
        unsafe { Self::check_token_elevation().unwrap_or(false) }
    }

    unsafe fn check_token_elevation() -> Result<bool, String> {
        let mut token_handle: HANDLE = zeroed();

        // 打开当前进程的令牌
        //  Open current process token
        let result = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle);
        if result.is_err() {
            return Err(format!("OpenProcessToken failed: {:?}", result));
        }

        // 确保 token 句柄最终被关闭
        //  Ensure token handle is closed
        let _guard = TokenHandleGuard(token_handle);

        // 查询令牌提升信息
        //  Query token elevation info
        let mut elevation: TOKEN_ELEVATION = zeroed();
        let mut return_length: u32 = 0;
        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        if result.is_err() {
            return Err(format!("GetTokenInformation failed: {:?}", result));
        }

        Ok(elevation.TokenIsElevated != 0)
    }
}

/// RAII 守卫，确保 token 句柄被正确关闭
///  RAII guard to ensure token handle is properly closed
struct TokenHandleGuard(HANDLE);

impl Drop for TokenHandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
