use std::collections::{HashMap, HashSet};
use std::os::windows::process::CommandExt;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;

use libloading::{Library, Symbol};

/// 进程架构
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcArch {
    Unknown,
    X86,
    X64,
}

/// 注入任务
struct InjectTask {
    pid: u32,
    arch: ProcArch,
}

/// 进程监控服务状态
struct SharedState {
    watcher_thread: Option<thread::JoinHandle<()>>,
    injector_thread: Option<thread::JoinHandle<()>>,
    stop_flag: Arc<AtomicBool>,
    _inject_queue: mpsc::Sender<InjectTask>,
    new_pid_queue: Arc<Mutex<Vec<u32>>>,
    sign_cache: Arc<Mutex<HashMap<String, bool>>>,
}

pub struct ProcessMonitorService {
    state: Arc<Mutex<Option<SharedState>>>,
}

impl ProcessMonitorService {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
        }
    }

    /// 函数名称：start
    /// 函数作用：启动进程监控后台线程，轮询新进程并注入未签名进程。
    /// Purpose: Starts the process monitor background thread, polls new processes and injects unsigned ones.
    /// 调用方：commands::process::start_process_watcher
    /// Called by: commands::process::start_process_watcher
    /// 中文关键词：进程监控，启动监控，进程轮询，DLL注入
    /// English keywords: process monitor, start monitoring, process polling, DLL injection
    pub fn start(
        &self,
        injector_x64: &str,
        injector_x86: &str,
        dll_x64: &str,
        dll_x86: &str,
        interval_ms: u32,
    ) -> Result<bool, String> {
        let mut guard = self.state.lock().unwrap();
        if guard.is_some() {
            return Err("Process monitor is already running".to_string());
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let (inject_tx, inject_rx) = mpsc::channel::<InjectTask>();
        let new_pid_queue = Arc::new(Mutex::new(Vec::new()));
        let sign_cache = Arc::new(Mutex::new(HashMap::new()));

        let injector_x64 = injector_x64.to_string();
        let injector_x86 = injector_x86.to_string();
        let dll_x64 = dll_x64.to_string();
        let dll_x86 = dll_x86.to_string();
        let interval = std::cmp::max(interval_ms, 100);

        // 注入线程
        let inject_stop = stop_flag.clone();
        let injector_thread = thread::spawn(move || {
            while !inject_stop.load(Ordering::Relaxed) {
                match inject_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(task) => {
                        if task.arch != ProcArch::Unknown {
                            launch_injector(
                                task.pid,
                                task.arch,
                                &injector_x64,
                                &injector_x86,
                                &dll_x64,
                                &dll_x86,
                            );
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });

        // 监控线程
        let monitor_stop = stop_flag.clone();
        let monitor_inject_tx = inject_tx.clone();
        let monitor_new_pids = new_pid_queue.clone();
        let monitor_sign_cache = sign_cache.clone();

        let watcher_thread = thread::spawn(move || {
            let self_pid = std::process::id();
            let mut seen: HashSet<u32> = HashSet::new();
            let mut step = 0u32;

            while !monitor_stop.load(Ordering::Relaxed) {
                let current = collect_current_pids();
                for pid in &current {
                    if *pid <= 4 || *pid == self_pid {
                        continue;
                    }
                    if !seen.insert(*pid) {
                        continue;
                    }
                    // 通知新 PID
                    monitor_new_pids.lock().unwrap().push(*pid);

                    let image_path = match query_process_image_path(*pid) {
                        Some(p) => p,
                        None => continue,
                    };
                    if image_path.is_empty() {
                        continue;
                    }

                    // 检查签名缓存
                    let signed = {
                        let cache = monitor_sign_cache.lock().unwrap();
                        cache.get(&image_path).copied()
                    };
                    let signed = if let Some(s) = signed {
                        s
                    } else {
                        let s = verify_file_signed(&image_path);
                        monitor_sign_cache.lock().unwrap().insert(image_path.clone(), s);
                        s
                    };

                    if signed {
                        continue;
                    }

                    let arch = detect_process_arch(*pid);
                    if arch != ProcArch::Unknown {
                        let _ = monitor_inject_tx.send(InjectTask { pid: *pid, arch });
                    }
                }
                // 清理已退出的 PID
                seen.retain(|p| current.contains(p));

                // 分段睡眠以避免阻塞
                let sleep_chunk = 100u32;
                let chunks = interval / sleep_chunk;
                for _ in 0..chunks {
                    if monitor_stop.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(sleep_chunk as u64));
                }
                step = step.wrapping_add(1);
            }
        });

        *guard = Some(SharedState {
            watcher_thread: Some(watcher_thread),
            injector_thread: Some(injector_thread),
            stop_flag,
            _inject_queue: inject_tx,
            new_pid_queue,
            sign_cache,
        });

        Ok(true)
    }

    /// 函数名称：stop
    /// 函数作用：停止进程监控线程和注入线程。
    /// Purpose: Stops the process monitor and injector threads.
    /// 调用方：commands::process::stop_process_watcher
    /// Called by: commands::process::stop_process_watcher
    /// 中文关键词：停止监控，停止进程轮询
    /// English keywords: stop monitor, stop process polling
    pub fn stop(&self) -> Result<(), String> {
        let mut guard = self.state.lock().unwrap();
        if let Some(state) = guard.take() {
            state.stop_flag.store(true, Ordering::Relaxed);
            drop(guard); // 释放锁避免死锁

            // 等待线程结束
            if let Some(handle) = state.injector_thread {
                let _ = handle.join();
            }
            if let Some(handle) = state.watcher_thread {
                let _ = handle.join();
            }
        }
        Ok(())
    }

    /// 函数名称：set_signed_list
    /// 函数作用：预填签名缓存，将指定路径标记为已签名。
    /// Purpose: Pre-fills the signature cache, marking given paths as signed.
    /// 调用方：commands::process::set_signed_list
    /// Called by: commands::process::set_signed_list
    /// 中文关键词：签名列表，白名单，可信进程
    /// English keywords: signed list, whitelist, trusted process
    pub fn set_signed_list(&self, paths: &[String]) -> Result<u32, String> {
        let guard = self.state.lock().unwrap();
        if let Some(state) = &*guard {
            let mut cache = state.sign_cache.lock().unwrap();
            let added = paths.len() as u32;
            for p in paths {
                cache.insert(p.clone(), true);
            }
            Ok(added)
        } else {
            Ok(0)
        }
    }

    /// 函数名称：poll_new_pids
    /// 函数作用：轮询新发现的 PID 列表，取出后清空。
    /// Purpose: Polls the list of newly discovered PIDs, draining after reading.
    /// 调用方：commands::process::poll_new_pids
    /// Called by: commands::process::poll_new_pids
    /// 中文关键词：轮询新进程，新PID，进程发现
    /// English keywords: poll new processes, new PID, process discovery
    pub fn poll_new_pids(&self) -> Result<Vec<u32>, String> {
        let guard = self.state.lock().unwrap();
        if let Some(state) = &*guard {
            let mut pids = state.new_pid_queue.lock().unwrap();
            let result = pids.clone();
            pids.clear();
            Ok(result)
        } else {
            Ok(Vec::new())
        }
    }
}

/// 函数名称：to_wide
/// 函数作用：将 Rust 字符串转为 UTF-16 以 null 结尾的 Vec<u16>，用于 Windows API 调用。
/// Purpose: Converts Rust string to null-terminated UTF-16 Vec<u16> for Windows API calls.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 函数名称：collect_current_pids
/// 函数作用：通过 CreateToolhelp32Snapshot 收集系统当前所有进程 PID。
/// Purpose: Collects all current process PIDs via CreateToolhelp32Snapshot.
/// 被调用方：watcher_thread
/// Called by: watcher_thread
/// 中文关键词：进程枚举，当前进程，PID收集，ToolHelp，进程快照
/// English keywords: process enumeration, current processes, PID collection, ToolHelp, process snapshot
fn collect_current_pids() -> HashSet<u32> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::Foundation::*;

    let mut pids = HashSet::new();
    unsafe {
        if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    pids.insert(entry.th32ProcessID);
                    if !Process32NextW(snapshot, &mut entry).is_ok() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
    }
    pids
}

/// 函数名称：query_process_image_path
/// 函数作用：通过 OpenProcess + QueryFullProcessImageNameW 获取指定 PID 的可执行文件路径。
/// Purpose: Gets executable path for a PID via OpenProcess + QueryFullProcessImageNameW.
/// 被调用方：watcher_thread
/// Called by: watcher_thread
/// 中文关键词：进程路径，镜像路径，进程查询，OpenProcess
/// English keywords: process path, image path, process query, OpenProcess
fn query_process_image_path(pid: u32) -> Option<String> {
    use windows::Win32::System::Threading::*;
    use windows::Win32::Foundation::*;
    use windows::core::PWSTR;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf: Vec<u16> = vec![0u16; 4096];
        let mut size: u32 = 4096;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        );
        CloseHandle(handle).ok();
        if ok.is_ok() && size > 0 {
            Some(String::from_utf16_lossy(&buf[..size as usize]))
        } else {
            None
        }
    }
}

/// 函数名称：verify_file_signed
/// 函数作用：通过 WinVerifyTrust 检查文件是否有有效数字签名。失败时保守返回 false。
/// Purpose: Checks if file has valid digital signature via WinVerifyTrust. Returns false conservatively on failure.
/// 被调用方：watcher_thread
/// Calls: WinVerifyTrust (wintrust.dll libloading)
/// 返回值：true 表示已签名，false 表示未签名或验证失败
/// 错误处理：DLL/符号加载失败时输出诊断日志并返回 false
/// Error handling: Logs diagnostic on DLL/symbol load failure and returns false
/// 副作用：调用 WinVerifyTrust（WTD_STATEACTION_CLOSE 清理）
/// 中文关键词：签名检查，WinVerifyTrust，进程签名，文件签名
/// English keywords: signature check, WinVerifyTrust, process signature, file signature
fn verify_file_signed(file_path: &str) -> bool {
    let wide = to_wide(file_path);
    unsafe {
        let lib = match Library::new("wintrust.dll") {
            Ok(l) => l,
            Err(e) => {
                eprintln!("verify_file_signed: failed to load wintrust.dll: {}", e);
                return false;
            }
        };
        let verify: Symbol<unsafe extern "system" fn(isize, *const super::trust_service::Guid, *const super::trust_service::WinTrustData) -> i32> =
            match lib.get(b"WinVerifyTrust") {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("verify_file_signed: failed to load WinVerifyTrust: {}", e);
                    return false;
                }
            };

        let file_info = super::trust_service::WinTrustFileInfo {
            cb_struct: std::mem::size_of::<super::trust_service::WinTrustFileInfo>() as u32,
            file_path: wide.as_ptr(),
            h_file: 0,
            pg_known_subject: std::ptr::null(),
        };

        use super::trust_service::{
            WinTrustData, WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE,
            WTD_STATEACTION_VERIFY, WTD_STATEACTION_CLOSE, WTD_CACHE_ONLY_URL_RETRIEVAL,
            ACTION_VERIFY_V2,
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

        status == 0
    }
}

/// 函数名称：detect_process_arch
/// 函数作用：通过 IsWow64Process2 检测目标进程架构（x86 或 x64）。
/// Purpose: Detects target process architecture (x86 or x64) via IsWow64Process2.
/// 被调用方：watcher_thread
/// Called by: watcher_thread
/// 中文关键词：进程架构，IsWow64Process2，x86，x64，WOW64
/// English keywords: process arch, IsWow64Process2, x86, x64, WOW64
fn detect_process_arch(pid: u32) -> ProcArch {
    use windows::Win32::System::Threading::*;
    use windows::Win32::Foundation::*;

    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return ProcArch::Unknown,
        };

        let kernel32 = match Library::new("kernel32.dll") {
            Ok(l) => l,
            Err(_) => {
                CloseHandle(handle).ok();
                return ProcArch::Unknown;
            }
        };

        type FnIsWow64Process2 = unsafe extern "system" fn(HANDLE, *mut u16, *mut u16) -> i32;
        if let Ok(func) = kernel32.get::<FnIsWow64Process2>(b"IsWow64Process2") {
            let mut process_machine: u16 = 0;
            let mut native_machine: u16 = 0;
            if func(handle, &mut process_machine, &mut native_machine) != 0 {
                CloseHandle(handle).ok();
                if process_machine == 0 { // IMAGE_FILE_MACHINE_UNKNOWN
                    return if native_machine == 0x8664 { ProcArch::X64 } else { ProcArch::X86 };
                }
                return ProcArch::X86;
            }
        }

        CloseHandle(handle).ok();
    }
    ProcArch::Unknown
}

/// 函数名称：launch_injector
/// 函数作用：启动 file_hook_injector.exe 将 file_hook DLL 注入目标进程。最多等待 12 秒。
/// Purpose: Launches file_hook_injector.exe to inject file_hook DLL into target process. Waits up to 12s.
/// 被调用方：inject_thread
/// Called by: inject_thread
/// 参数：pid — 目标进程 PID；arch — 目标架构；injector_x64/x86 — 注入器路径；dll_x64/x86 — DLL 路径
/// 副作用：创建子进程，注入 DLL 到目标进程
/// Side effect: Creates child process, injects DLL into target process
/// 中文关键词：进程注入，CreateProcess，DLL注入，注入器，file_hook
/// English keywords: process injection, CreateProcess, DLL injection, injector, file_hook
fn launch_injector(
    pid: u32,
    arch: ProcArch,
    injector_x64: &str,
    injector_x86: &str,
    dll_x64: &str,
    dll_x86: &str,
) {
    let (injector, dll) = match arch {
        ProcArch::X64 => (injector_x64, dll_x64),
        ProcArch::X86 => (injector_x86, dll_x86),
        ProcArch::Unknown => return,
    };

    if injector.is_empty() || dll.is_empty() {
        return;
    }

    let result = std::process::Command::new(injector)
        .args(["--pid", &pid.to_string(), "--dll", dll])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn();

    if let Ok(mut child) = result {
        let start = std::time::Instant::now();
        let timeout = Duration::from_millis(12000);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if start.elapsed() > timeout {
                        let _ = child.kill();
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                Err(_) => {
                    let _ = child.kill();
                    break;
                }
            }
        }
    }
}
