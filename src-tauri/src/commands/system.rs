// 系统信息命令 — CPU、进程列表等系统信息获取
// System info commands — CPU, process list, and other system information retrieval
use std::process::Command;

/// 函数名称：get_system_info
/// 函数作用：获取系统 CPU 和内存信息。
/// Purpose: Gets system CPU and memory information.
/// Returns: CPU 型号、核心数、架构等 / CPU model, core count, architecture, etc.
/// 调用方：前端概览页
/// Called by: Frontend overview page
/// 中文关键词：系统信息，CPU信息，内存信息，硬件信息
/// English keywords: system info, CPU info, memory info, hardware info
#[tauri::command]
pub fn get_system_info() -> Result<serde_json::Value, String> {
    let cpu_name = get_cpu_name();
    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    Ok(serde_json::json!({
        "cpuName": cpu_name,
        "cpuCores": cpu_cores,
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "hostname": std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string()),
    }))
}

/// 函数名称：get_running_processes
/// 函数作用：获取当前运行的所有进程列表。
/// Purpose: Gets a list of all currently running processes.
/// Returns: 进程名称和 PID 列表 / Process name and PID list
/// 调用方：前端行为分析页进程选择
/// Called by: Frontend behavior analysis page process selection
/// 中文关键词：进程列表，运行进程，任务管理器
/// English keywords: process list, running processes, task manager
#[tauri::command]
pub fn get_running_processes() -> Result<Vec<serde_json::Value>, String> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::Foundation::CloseHandle;

    let mut processes = Vec::new();
    let current_pid = std::process::id();

    let snapshot = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    }.map_err(|e| format!("创建进程快照失败: {}", e))?;

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    unsafe {
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                if pid > 0 && pid != current_pid {
                    let exe_name = String::from_utf16_lossy(
                        &entry.szExeFile[..entry.szExeFile.iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len())]
                    );
                    processes.push(serde_json::json!({
                        "pid": pid,
                        "name": exe_name,
                    }));
                }

                if !Process32NextW(snapshot, &mut entry).is_ok() {
                    break;
                }
            }
        }
        CloseHandle(snapshot).ok();
    }

    Ok(processes)
}

/// 获取 CPU 名称 / Get CPU name
fn get_cpu_name() -> String {
    // 通过 wmic 命令获取 / Get via wmic command
    if let Ok(output) = Command::new("wmic")
        .args(["cpu", "get", "name", "/format:value"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.to_lowercase().starts_with("name=") {
                let name = line[5..].trim().to_string();
                if !name.is_empty() {
                    return name;
                }
            }
        }
    }

    // 回退：通过环境变量 / Fallback: via environment variable
    std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| "Unknown CPU".to_string())
}
