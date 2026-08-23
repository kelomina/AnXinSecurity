// AnXinService — 完整后端防护服务进程（拆分后的 Server 角色）
//  AnXinService - full backend protection service process (the split-out Server role)
//
// 职责边界：
// - `--service`：以 Windows 服务运行（SCM 启动），启动全部防护组件与 IPC 服务端，
//   并在用户会话拉起 Tray 进程。
// - `--foreground`：前台模式运行同一套防护后端（无 SCM），供开发调试与 standalone
//   引导启动使用；Ctrl+C / IPC shutdown_service 触发优雅停止。
// - 本进程不创建任何窗口/托盘；驱动相关安装期 CLI 子命令保留在主 UI 程序中
//   （FileProtect 驱动按镜像名 anxin-security.exe 校验调用者，见 minifilter.c）。
//
// 中文关键词：服务进程，后端，SCM，前台模式，进程拆分
// English keywords: service process, backend, SCM, foreground mode, process split
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anxin_security::services::windows_service;

/// 函数名称：has_flag
/// 函数作用：判断命令行参数中是否存在指定开关。
/// Function name: has_flag
/// Purpose: Checks whether a given switch exists in the command line arguments.
fn has_flag(flag: &str) -> bool {
    std::env::args().any(|arg| arg == flag)
}

fn main() {
    // 服务模式：交给 SCM dispatcher（binPath 带 --service 由 SCM 启动时进入此分支）
    //  Service mode: hand over to the SCM dispatcher (entered when SCM starts binPath ... --service)
    if windows_service::is_service_mode() {
        if let Err(e) = windows_service::dispatch() {
            eprintln!("[Service] Fatal error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // 前台模式：同一套防护后端，无 SCM，Ctrl+C / shutdown_service 停止
    //  Foreground mode: same protection backend without SCM; stopped via Ctrl+C / shutdown_service
    if has_flag("--foreground") {
        eprintln!("[Service] Starting in foreground mode");
        if let Err(e) = windows_service::run_foreground() {
            eprintln!("[Service] Fatal error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    eprintln!("AnXinService: backend protection service binary");
    eprintln!("Usage:");
    eprintln!("  --service      run as a Windows service (invoked by SCM)");
    eprintln!("  --foreground   run the protection backend in foreground (debug/bootstrap)");
}
