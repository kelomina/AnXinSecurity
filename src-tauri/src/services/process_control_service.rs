// 进程控制服务 — 封装挂起、恢复和终止进程的 Windows API 调用。
// Process control service — wraps Windows API calls for process suspend, resume, and terminate.
use libloading::{Library, Symbol};
use windows::core::PWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Threading::*;

/// 保护进程白名单 / Protected process whitelist
const PROTECTED_PROCESSES: &[&str] = &[
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
];

/// 进程身份快照 / Process identity snapshot
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessIdentity {
    pub pid: u32,
    pub image_path: String,
    pub creation_time_100ns: u64,
}

fn filetime_to_u64(filetime: FILETIME) -> u64 {
    ((filetime.dwHighDateTime as u64) << 32) | filetime.dwLowDateTime as u64
}

/// 检查进程是否为受保护的系统进程 / Check if process is a protected system process
fn is_protected_process(pid: u32) -> Result<bool, String> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| format!("Failed to create process snapshot: {}", e))?;

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe {
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    let exe_name = String::from_utf16_lossy(
                        &entry.szExeFile[..entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len())],
                    )
                    .to_lowercase();

                    let is_protected = PROTECTED_PROCESSES
                        .iter()
                        .any(|&name| exe_name.contains(name));

                    CloseHandle(snapshot).ok();
                    return Ok(is_protected);
                }

                if !Process32NextW(snapshot, &mut entry).is_ok() {
                    break;
                }
            }
        }
        CloseHandle(snapshot).ok();
    }

    Err("Process not found".to_string())
}

/// 函数名称：current_process_ancestor_pids
/// 函数作用：读取当前 AnXinSecurity 进程的父/祖先进程 PID 链，用于阻止自动挂起自己的控制链。
/// Function name: current_process_ancestor_pids
/// Purpose: Reads the parent/ancestor PID chain of the current AnXinSecurity process so auto-suspend cannot freeze its own control chain.
pub(crate) fn current_process_ancestor_pids() -> Result<Vec<u32>, String> {
    process_ancestor_pids(std::process::id())
}

/// 函数名称：is_current_process_or_ancestor
/// 函数作用：判断目标 PID 是否为当前进程或其父/祖先进程。
/// Function name: is_current_process_or_ancestor
/// Purpose: Returns whether the target PID is the current process or one of its ancestors.
pub(crate) fn is_current_process_or_ancestor(pid: u32) -> bool {
    if pid == 0 || pid == u32::MAX {
        return false;
    }
    if pid == std::process::id() {
        return true;
    }
    current_process_ancestor_pids()
        .map(|ancestors| ancestors.contains(&pid))
        .unwrap_or(false)
}

fn process_ancestor_pids(root_pid: u32) -> Result<Vec<u32>, String> {
    if root_pid == 0 || root_pid == u32::MAX {
        return Ok(Vec::new());
    }

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| format!("Failed to create process snapshot: {}", e))?;

    let mut parent_by_pid = std::collections::HashMap::<u32, u32>::new();
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe {
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                parent_by_pid.insert(entry.th32ProcessID, entry.th32ParentProcessID);
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        CloseHandle(snapshot).ok();
    }

    let mut ancestors = Vec::new();
    let mut seen = std::collections::HashSet::<u32>::new();
    let mut cursor = root_pid;
    while let Some(parent) = parent_by_pid.get(&cursor).copied() {
        if parent == 0 || parent == u32::MAX || !seen.insert(parent) {
            break;
        }
        ancestors.push(parent);
        cursor = parent;
    }

    Ok(ancestors)
}

/// 函数名称：query_process_identity
/// 函数作用：读取指定 PID 的进程路径和创建时间，用于拦截恢复台账校验 PID 是否被复用。
/// Function name: query_process_identity
/// Purpose: Reads process path and creation time for PID reuse checks in the interception recovery ledger.
pub(crate) fn query_process_identity(pid: u32) -> Result<ProcessIdentity, String> {
    if pid == 0 {
        return Err("Invalid PID 0".to_string());
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)
            .map_err(|e| format!("Failed to open process for identity (PID: {}): {}", pid, e))?;

        let result = (|| {
            let mut creation_time = FILETIME::default();
            let mut exit_time = FILETIME::default();
            let mut kernel_time = FILETIME::default();
            let mut user_time = FILETIME::default();
            GetProcessTimes(
                handle,
                &mut creation_time,
                &mut exit_time,
                &mut kernel_time,
                &mut user_time,
            )
            .map_err(|e| format!("Failed to query process time (PID: {}): {}", pid, e))?;

            let mut size = 32768u32;
            let mut buffer = vec![0u16; size as usize];
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            )
            .map_err(|e| format!("Failed to query process path (PID: {}): {}", pid, e))?;

            let image_path = String::from_utf16_lossy(&buffer[..size as usize]);
            Ok(ProcessIdentity {
                pid,
                image_path,
                creation_time_100ns: filetime_to_u64(creation_time),
            })
        })();

        CloseHandle(handle).ok();
        result
    }
}

/// 函数名称：suspend_process_by_pid
/// 函数作用：挂起指定 PID 的进程，供拦截队列入队和前端命令复用。
/// Function name: suspend_process_by_pid
/// Purpose: Suspends the process identified by PID for interception enqueue and frontend commands.
pub(crate) fn suspend_process_by_pid(pid: u32) -> Result<bool, String> {
    if is_protected_process(pid)? {
        return Err("无法操作受保护的系统进程".to_string());
    }
    if pid == std::process::id() {
        return Err("无法操作当前进程".to_string());
    }
    if is_current_process_or_ancestor(pid) {
        return Err("无法自动挂起当前防护进程的父级控制链".to_string());
    }

    unsafe {
        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid)
            .map_err(|e| format!("Failed to open process (PID: {}): {}", pid, e))?;

        let result = call_nt_function("NtSuspendProcess", handle);

        CloseHandle(handle).ok();

        result
    }
}

/// 函数名称：resume_process_by_pid
/// 函数作用：恢复指定 PID 的进程，供“允许运行”取消拦截挂起。
/// Function name: resume_process_by_pid
/// Purpose: Resumes the process identified by PID so Allow can cancel interception suspension.
pub(crate) fn resume_process_by_pid(pid: u32) -> Result<bool, String> {
    if is_protected_process(pid)? {
        return Err("无法操作受保护的系统进程".to_string());
    }

    unsafe {
        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid)
            .map_err(|e| format!("Failed to open process (PID: {}): {}", pid, e))?;

        let result = call_nt_function("NtResumeProcess", handle);

        CloseHandle(handle).ok();

        result
    }
}

/// 函数名称：terminate_process_by_pid
/// 函数作用：终止指定 PID 的进程，供“阻止进程”结束已挂起的进程。
/// Function name: terminate_process_by_pid
/// Purpose: Terminates the process identified by PID so Block can end the suspended process.
pub(crate) fn terminate_process_by_pid(pid: u32) -> Result<bool, String> {
    if is_protected_process(pid)? {
        return Err("无法操作受保护的系统进程".to_string());
    }
    if pid == std::process::id() {
        return Err("无法操作当前进程".to_string());
    }
    if is_current_process_or_ancestor(pid) {
        return Err("无法终止当前防护进程的父级控制链".to_string());
    }

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid)
            .map_err(|e| format!("Failed to open process (PID: {}): {}", pid, e))?;

        let result = TerminateProcess(handle, 1);

        CloseHandle(handle).ok();

        if result.is_ok() {
            Ok(true)
        } else {
            Err("TerminateProcess failed".to_string())
        }
    }
}

/// 动态加载 ntdll.dll 并调用指定 NT 函数 / Dynamically load ntdll.dll and call named NT function
/// 使用 libloading 避免 windows-core 版本冲突 / Uses libloading to avoid windows-core version conflicts
unsafe fn call_nt_function(func_name: &str, handle: HANDLE) -> Result<bool, String> {
    let ntdll =
        Library::new("ntdll.dll").map_err(|e| format!("Failed to load ntdll.dll: {}", e))?;

    let func: Symbol<unsafe extern "system" fn(HANDLE) -> i32> = ntdll
        .get(func_name.as_bytes())
        .map_err(|e| format!("Failed to get {}: {}", func_name, e))?;

    let status = func(handle);

    // NT_SUCCESS(status) == 0
    if status == 0 {
        Ok(true)
    } else {
        Err(format!(
            "{} failed with status: 0x{:X}",
            func_name, status as u32
        ))
    }
}
