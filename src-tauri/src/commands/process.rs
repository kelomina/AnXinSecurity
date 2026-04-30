// 进程控制命令 - 完整实现
use windows::Win32::Foundation::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;

/// 保护进程白名单
const PROTECTED_PROCESSES: &[&str] = &[
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
];

/// 检查进程是否为受保护的系统进程
fn is_protected_process(pid: u32) -> Result<bool, String> {
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    }.map_err(|e| format!("Failed to create process snapshot: {}", e))?;

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe {
        if Process32FirstW(snapshot, &mut entry).as_bool() {
            loop {
                if entry.th32ProcessID == pid {
                    // 提取进程名
                    let exe_name = String::from_utf16_lossy(
                        &entry.szExeFile[..entry.szExeFile.iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len())]
                    ).to_lowercase();

                    let is_protected = PROTECTED_PROCESSES.iter()
                        .any(|&name| exe_name.contains(name));

                    CloseHandle(snapshot).ok();
                    return Ok(is_protected);
                }

                if !Process32NextW(snapshot, &mut entry).as_bool() {
                    break;
                }
            }
        }
        CloseHandle(snapshot).ok();
    }

    Err("Process not found".to_string())
}

/// 挂起进程
#[tauri::command]
pub async fn suspend_process(pid: u32) -> Result<bool, String> {
    // 检查是否为保护进程
    if is_protected_process(pid)? {
        return Err("无法操作受保护的系统进程".to_string());
    }

    // 防止操作自身
    if pid == std::process::id() {
        return Err("无法操作当前进程".to_string());
    }

    unsafe {
        let handle = OpenProcess(
            PROCESS_SUSPEND_RESUME,
            FALSE,
            pid
        ).map_err(|e| format!("Failed to open process (PID: {}): {}", pid, e))?;

        // 动态加载 ntdll.dll 获取 NtSuspendProcess
        let ntdll = std::ffi::CString::new("ntdll.dll").unwrap();
        let h_module = LoadLibraryA(ntdll.as_ptr())
            .map_err(|e| format!("Failed to load ntdll: {}", e))?;

        let proc_name = std::ffi::CString::new("NtSuspendProcess").unwrap();
        let nt_suspend_addr = GetProcAddress(h_module, proc_name.as_ptr())
            .ok_or("Failed to get NtSuspendProcess address")?;

        let nt_suspend: extern "system" fn(HANDLE) -> i32 = 
            std::mem::transmute(nt_suspend_addr);

        let result = nt_suspend(handle);

        CloseHandle(handle).ok();
        FreeLibrary(h_module).ok();

        if result == 0 {
            Ok(true)
        } else {
            Err(format!("NtSuspendProcess failed with status: {}", result))
        }
    }
}

/// 恢复进程
#[tauri::command]
pub async fn resume_process(pid: u32) -> Result<bool, String> {
    // 检查是否为保护进程
    if is_protected_process(pid)? {
        return Err("无法操作受保护的系统进程".to_string());
    }

    unsafe {
        let handle = OpenProcess(
            PROCESS_SUSPEND_RESUME,
            FALSE,
            pid
        ).map_err(|e| format!("Failed to open process (PID: {}): {}", pid, e))?;

        // 动态加载 ntdll.dll 获取 NtResumeProcess
        let ntdll = std::ffi::CString::new("ntdll.dll").unwrap();
        let h_module = LoadLibraryA(ntdll.as_ptr())
            .map_err(|e| format!("Failed to load ntdll: {}", e))?;

        let proc_name = std::ffi::CString::new("NtResumeProcess").unwrap();
        let nt_resume_addr = GetProcAddress(h_module, proc_name.as_ptr())
            .ok_or("Failed to get NtResumeProcess address")?;

        let nt_resume: extern "system" fn(HANDLE) -> i32 = 
            std::mem::transmute(nt_resume_addr);

        let result = nt_resume(handle);

        CloseHandle(handle).ok();
        FreeLibrary(h_module).ok();

        if result == 0 {
            Ok(true)
        } else {
            Err(format!("NtResumeProcess failed with status: {}", result))
        }
    }
}

/// 终止进程
#[tauri::command]
pub async fn terminate_process(pid: u32) -> Result<bool, String> {
    // 检查是否为保护进程
    if is_protected_process(pid)? {
        return Err("无法终止受保护的系统进程".to_string());
    }

    // 防止终止自身
    if pid == std::process::id() {
        return Err("无法终止当前进程".to_string());
    }

    unsafe {
        let handle = OpenProcess(
            PROCESS_TERMINATE,
            FALSE,
            pid
        ).map_err(|e| format!("Failed to open process (PID: {}): {}", pid, e))?;

        let result = TerminateProcess(handle, 1);

        CloseHandle(handle).ok();

        if result.as_bool() {
            Ok(true)
        } else {
            Err("TerminateProcess failed".to_string())
        }
    }
}
