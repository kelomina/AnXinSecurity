// 远程会话检测服务
//  Remote session detection service
//
// 检测当前是否运行在远程会话或远程控制软件中。
//  Detects whether the current process is running in a remote session or remote control software.
//
// 检测策略：
//  Detection strategy:
// 1. GetSystemMetrics(SM_REMOTESESSION) — 检测 RDP 会话
// 2. 枚举进程，匹配已知远程控制软件进程名 — 检测 TeamViewer/AnyDesk/ToDesk/Sunlogin 等
//
// 中文关键词：远程会话，远程控制，RDP，TeamViewer，AnyDesk
// English keywords: remote session, remote control, RDP, TeamViewer, AnyDesk
use std::mem::{size_of, zeroed};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Runtime};

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_REMOTESESSION};

/// 远程控制软件进程名清单（小写匹配）
///  Remote control software process name list (lowercase match)
const REMOTE_CONTROL_PROCESSES: &[&str] = &[
    // RDP
    "mstsc.exe",
    "rdpclip.exe",
    // TeamViewer
    "teamviewer.exe",
    "teamviewer_service.exe",
    "tvnetworktest.exe",
    // AnyDesk
    "anydesk.exe",
    // ToDesk
    "todesk.exe",
    "todesk_service.exe",
    // Sunlogin (向日葵)
    "sunloginclient.exe",
    "sunloginclientdaemon.exe",
    "oray_rundaemon.exe",
    // VNC
    "vncviewer.exe",
    "winvnc.exe",
    "vnserver.exe",
    "tvncviewer.exe",
    // NoMachine
    "nxplayer.exe",
    "nxserver.bin.exe",
    // Splashtop
    "splashtopstreamer.exe",
    "srserver.exe",
    // RemoteUtilities
    "rutserv.exe",
    "rufusvc.exe",
    // GoToAssist / GoToMeeting
    "g2mcomm.exe",
    "g2mstart.exe",
    // AeroAdmin
    "aeroadmin.exe",
    // Ammyy Admin
    "aav3.exe",
    // SupRemo
    "supremo.exe",
    // LiteManager
    "romserver.exe",
    "romviewer.exe",
];

/// 远程会话状态变更事件
///  Remote session status change event
#[derive(Debug, Clone, serde::Serialize)]
pub struct RemoteSessionState {
    pub is_remote: bool,
}

pub struct RemoteSessionService {
    is_remote: std::sync::Arc<std::sync::atomic::AtomicBool>,
    stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl RemoteSessionService {
    pub fn new() -> Self {
        Self {
            is_remote: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            stop_flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// 启动远程会话检测循环
    ///  Start remote session detection loop
    pub fn start<R: Runtime>(self: &std::sync::Arc<Self>, app_handle: AppHandle<R>) {
        let is_remote = self.is_remote.clone();
        let stop_flag = self.stop_flag.clone();

        tauri::async_runtime::spawn(async move {
            eprintln!("[RemoteSession] Detection service started");
            loop {
                if stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }

                let detected = Self::detect_remote_session();
                let was_remote = is_remote.swap(detected, std::sync::atomic::Ordering::SeqCst);

                if was_remote != detected {
                    eprintln!(
                        "[RemoteSession] Remote session state changed: {} -> {}",
                        was_remote, detected
                    );
                    let _ = app_handle.emit(
                        "remote-session-changed",
                        RemoteSessionState {
                            is_remote: detected,
                        },
                    );
                }

                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            eprintln!("[RemoteSession] Detection service stopped");
        });
    }

    /// 停止检测循环
    ///  Stop detection loop
    #[allow(dead_code)]
    pub fn stop(&self) {
        self.stop_flag
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// 当前是否处于远程会话
    ///  Whether currently in a remote session
    #[allow(dead_code)]
    pub fn is_remote(&self) -> bool {
        self.is_remote.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// 一次性检测：综合 RDP 会话标志 + 远程控制软件进程
    ///  One-shot detection: combines RDP session flag + remote control process check
    pub fn detect_remote_session() -> bool {
        Self::is_rdp_session() || Self::has_remote_control_process()
    }

    /// 通过 GetSystemMetrics(SM_REMOTESESSION) 检测 RDP 会话
    ///  Detect RDP session via GetSystemMetrics(SM_REMOTESESSION)
    fn is_rdp_session() -> bool {
        unsafe {
            let result = GetSystemMetrics(SM_REMOTESESSION);
            result != 0
        }
    }

    /// 枚举进程，检查是否有已知的远程控制软件在运行
    ///  Enumerate processes to check if any known remote control software is running
    fn has_remote_control_process() -> bool {
        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return false,
            };

            let _guard = SnapshotGuard(snapshot);

            let mut entry: PROCESSENTRY32W = zeroed();
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut entry).is_err() {
                return false;
            }

            loop {
                let exe_name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                );
                let exe_name_lower = exe_name.to_lowercase();

                if REMOTE_CONTROL_PROCESSES
                    .iter()
                    .any(|name| exe_name_lower == *name)
                {
                    return true;
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }

            false
        }
    }
}

/// RAII 守卫，确保 snapshot 句柄被正确关闭
///  RAII guard to ensure snapshot handle is properly closed
struct SnapshotGuard(windows::Win32::Foundation::HANDLE);

impl Drop for SnapshotGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
