use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

use crate::services::path_policy_service::should_skip_security_scan;
use libloading::Library;

const FILE_HOOK_INJECTOR_NAME: &str = "file_hook_injector.exe";
const FILE_HOOK_DETOURS_NAME: &str = "file_hook_detours.dll";
const FILE_HOOK_X64_DIR: &str = "win32-x64";
const FILE_HOOK_X86_DIR: &str = "win32-x86";
const FILE_HOOK_NATIVE_BIN_DIR: &str = "native/bin";
const FILE_HOOK_INJECTOR_SKIP_SELF_HOOK_ENV: &str = "ANXIN_FILE_HOOK_INJECTOR_SKIP_SELF_HOOK";
const PROCESS_MONITOR_STOP_JOIN_TIMEOUT_MS: u64 = 2_500;
const PROCESS_MONITOR_STOP_JOIN_POLL_MS: u64 = 25;

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

/// APIHook 注入器与 DLL 的最终解析路径。
/// Resolved file_hook injector and DLL paths used by APIHook injection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessHookResolvedPaths {
    pub injector_x64: PathBuf,
    pub injector_x86: PathBuf,
    pub dll_x64: PathBuf,
    pub dll_x86: PathBuf,
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

    /// 函数名称：start_with_resource_dir
    /// 函数作用：启动进程监控后台线程；启动前解析 APIHook 注入器和 DLL 默认路径，避免前端必须手填绝对路径。
    /// Function name: start_with_resource_dir
    /// Purpose: Starts the process monitor thread after resolving default APIHook injector and DLL paths so the frontend does not need absolute paths.
    /// 调用方：commands::process::start_process_watcher，commands::config::set_process_monitoring_enabled，main.rs 启动初始化。
    /// Called by: commands::process::start_process_watcher, commands::config::set_process_monitoring_enabled, main.rs setup.
    /// 被调用方：resolve_process_hook_paths，launch_injector，collect_current_pids，query_process_image_path，should_skip_security_scan，verify_file_signed，detect_process_arch。
    /// Calls: resolve_process_hook_paths, launch_injector, collect_current_pids, query_process_image_path, should_skip_security_scan, verify_file_signed, detect_process_arch.
    /// 参数说明：injector_x64/injector_x86/dll_x64/dll_x86 为空时使用默认候选路径；resource_dir 为 Tauri 打包资源目录；interval_ms 为轮询间隔。
    /// Parameters: injector_x64/injector_x86/dll_x64/dll_x86 use default candidates when empty; resource_dir is the Tauri bundle resource directory; interval_ms is the polling interval.
    /// 返回值说明：成功启动返回 true；已经启动时幂等返回 true；路径解析失败返回 String。
    /// Returns: true after successful start; true when already running; String error when path resolution fails.
    /// 错误处理：启动后台线程前校验四个文件是否存在；缺失时返回包含架构、文件名和候选路径的错误。
    /// Error handling: Validates all four files before starting background threads; missing files return errors with architecture, filename and checked paths.
    /// 中文关键词：进程监控，APIHook，默认路径，资源目录，开发目录，DLL注入，路径校验
    /// English keywords: process monitor, APIHook, default path, resource directory, development directory, DLL injection, path validation
    pub fn start_with_resource_dir(
        &self,
        injector_x64: &str,
        injector_x86: &str,
        dll_x64: &str,
        dll_x86: &str,
        interval_ms: u32,
        resource_dir: Option<&Path>,
    ) -> Result<bool, String> {
        let mut guard = self.state.lock().unwrap();
        if guard.is_some() {
            return Ok(true);
        }

        let resolved_paths =
            resolve_process_hook_paths(injector_x64, injector_x86, dll_x64, dll_x86, resource_dir)?;

        let stop_flag = Arc::new(AtomicBool::new(false));
        let (inject_tx, inject_rx) = mpsc::channel::<InjectTask>();
        let new_pid_queue = Arc::new(Mutex::new(Vec::new()));
        let sign_cache = Arc::new(Mutex::new(HashMap::new()));

        let injector_x64 = path_to_process_hook_string(&resolved_paths.injector_x64);
        let injector_x86 = path_to_process_hook_string(&resolved_paths.injector_x86);
        let dll_x64 = path_to_process_hook_string(&resolved_paths.dll_x64);
        let dll_x86 = path_to_process_hook_string(&resolved_paths.dll_x86);
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
                                &inject_stop,
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
            let mut seen = initial_seen_pids();

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

                    match should_skip_security_scan(&image_path) {
                        Ok(true) => {
                            eprintln!(
                                "[ProcessMonitor] Skipped by exclusions or allowlist: {}",
                                image_path
                            );
                            continue;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            eprintln!(
                                "[ProcessMonitor] Failed to load path policy for {}: {}",
                                image_path, e
                            );
                        }
                    }

                    // 检查签名缓存
                    let signed = {
                        let cache = monitor_sign_cache.lock().unwrap();
                        cache.get(&image_path).copied()
                    };
                    let signed = if let Some(s) = signed {
                        s
                    } else {
                        let s = super::trust_service::TrustService::new()
                            .verify_file(&image_path)
                            .map(|verdict| verdict.trusted)
                            .unwrap_or(false);
                        monitor_sign_cache
                            .lock()
                            .unwrap()
                            .insert(image_path.clone(), s);
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
    /// 函数作用：停止进程监控线程和注入线程，并用有限等待避免停止命令无限阻塞。
    /// Purpose: Stops the process monitor and injector threads with bounded waits so stop cannot block indefinitely.
    /// 调用方：commands::process::stop_process_watcher
    /// Called by: commands::process::stop_process_watcher
    /// 被调用方：wait_for_process_monitor_thread_stop。
    /// Calls: wait_for_process_monitor_thread_stop.
    /// 错误处理：线程 panic 或超时未退出时返回 String；超时线程句柄会放回状态中，便于后续重试停止。
    /// Error handling: Returns String for panicked or timed-out threads; timed-out handles are restored for later stop retry.
    /// 中文关键词：停止监控，停止进程轮询，有限等待，阻塞防护
    /// English keywords: stop monitor, stop process polling, bounded wait, blocking guard
    pub fn stop(&self) -> Result<(), String> {
        let mut guard = self.state.lock().unwrap();
        let Some(mut state) = guard.take() else {
            return Ok(());
        };

        state.stop_flag.store(true, Ordering::Relaxed);
        drop(guard); // 释放锁避免死锁

        let timeout = Duration::from_millis(PROCESS_MONITOR_STOP_JOIN_TIMEOUT_MS);
        let mut pending_threads = Vec::new();
        let mut errors = Vec::new();

        if let Some(handle) = state.injector_thread.take() {
            match wait_for_process_monitor_thread_stop(handle, timeout, "injector") {
                Ok(Some(handle)) => {
                    state.injector_thread = Some(handle);
                    pending_threads.push("injector");
                }
                Ok(None) => {}
                Err(err) => errors.push(err),
            }
        }
        if let Some(handle) = state.watcher_thread.take() {
            match wait_for_process_monitor_thread_stop(handle, timeout, "watcher") {
                Ok(Some(handle)) => {
                    state.watcher_thread = Some(handle);
                    pending_threads.push("watcher");
                }
                Ok(None) => {}
                Err(err) => errors.push(err),
            }
        }

        if !pending_threads.is_empty() {
            let mut guard = self.state.lock().unwrap();
            *guard = Some(state);
            let mut message = format!(
                "Process monitor did not stop within {} ms; still running thread(s): {}",
                PROCESS_MONITOR_STOP_JOIN_TIMEOUT_MS,
                pending_threads.join(", ")
            );
            if !errors.is_empty() {
                message.push_str("; ");
                message.push_str(&errors.join("; "));
            }
            return Err(message);
        }

        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        Ok(())
    }

    /// 函数名称：is_running
    /// 函数作用：读取 APIHook 进程监控 watcher 是否已有运行态线程。
    /// Function name: is_running
    /// Purpose: Reads whether the APIHook process monitor watcher currently has runtime threads.
    /// 调用方：commands::process::get_process_watcher_status。
    /// Called by: commands::process::get_process_watcher_status.
    /// 返回值说明：true 表示 watcher 已启动；false 表示未启动或已停止。
    /// Returns: true when the watcher is started; false when stopped.
    /// 中文关键词：进程监控状态，APIHook状态，运行态查询
    /// English keywords: process monitor status, APIHook status, runtime query
    pub fn is_running(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.is_some())
            .unwrap_or(false)
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

/// 函数名称：resolve_process_hook_paths
/// 函数作用：解析 APIHook 注入链路所需的 x64/x86 注入器与 DLL 路径；显式路径必须指向默认可信候选，空路径才按默认候选查找。
/// Function name: resolve_process_hook_paths
/// Purpose: Resolves x64/x86 injector and DLL paths needed by the APIHook injection path; explicit paths must resolve to trusted default candidates, empty paths fall back to defaults.
/// 调用方：ProcessMonitorService::start_with_resource_dir，process_monitor_service_tests。
/// Called by: ProcessMonitorService::start_with_resource_dir, process_monitor_service_tests.
/// 被调用方：resolve_process_hook_file。
/// Calls: resolve_process_hook_file.
/// 参数说明：四个字符串为前端兼容参数；非空时只作为“指定默认资源文件”的兼容入口，不能指向任意路径；resource_dir 为 Tauri 打包资源目录，可为空。
/// Parameters: the four strings are frontend-compatible parameters; non-empty values only select packaged/default resources and cannot point to arbitrary paths; resource_dir is optional.
/// 返回值说明：成功时返回四个已存在文件路径；失败时返回明确缺失文件和候选路径。
/// Returns: existing paths for all four files on success; explicit missing file and candidate paths on failure.
/// 错误处理：不会启动进程或注入 DLL，只做文件存在性检查并返回 String。
/// Error handling: Does not start processes or inject DLLs; only checks file existence and returns String errors.
/// 中文关键词：APIHook，默认路径，资源目录，开发目录，注入器，DLL，路径解析
/// English keywords: APIHook, default path, resource directory, development directory, injector, DLL, path resolution
pub fn resolve_process_hook_paths(
    injector_x64: &str,
    injector_x86: &str,
    dll_x64: &str,
    dll_x86: &str,
    resource_dir: Option<&Path>,
) -> Result<ProcessHookResolvedPaths, String> {
    Ok(ProcessHookResolvedPaths {
        injector_x64: resolve_process_hook_file(
            injector_x64,
            "x64 injector",
            FILE_HOOK_X64_DIR,
            FILE_HOOK_INJECTOR_NAME,
            resource_dir,
        )?,
        injector_x86: resolve_process_hook_file(
            injector_x86,
            "x86 injector",
            FILE_HOOK_X86_DIR,
            FILE_HOOK_INJECTOR_NAME,
            resource_dir,
        )?,
        dll_x64: resolve_process_hook_file(
            dll_x64,
            "x64 DLL",
            FILE_HOOK_X64_DIR,
            FILE_HOOK_DETOURS_NAME,
            resource_dir,
        )?,
        dll_x86: resolve_process_hook_file(
            dll_x86,
            "x86 DLL",
            FILE_HOOK_X86_DIR,
            FILE_HOOK_DETOURS_NAME,
            resource_dir,
        )?,
    })
}

/// 函数名称：process_hook_default_path_candidates
/// 函数作用：生成 APIHook 文件默认候选路径，顺序为开发目录 native/bin 优先，Tauri resource_dir 其次。
/// Function name: process_hook_default_path_candidates
/// Purpose: Builds default APIHook file candidates, preferring the development native/bin directory and then Tauri resource_dir.
/// 调用方：resolve_process_hook_file，process_monitor_service_tests。
/// Called by: resolve_process_hook_file, process_monitor_service_tests.
/// 参数说明：arch_dir 为 win32-x64 或 win32-x86；file_name 为 file_hook_injector.exe 或 file_hook_detours.dll；resource_dir 可为空。
/// Parameters: arch_dir is win32-x64 or win32-x86; file_name is file_hook_injector.exe or file_hook_detours.dll; resource_dir is optional.
/// 返回值说明：返回按优先级排序的候选路径，不检查文件是否存在。
/// Returns: ordered candidate paths without checking file existence.
/// 中文关键词：路径候选，开发目录，资源目录，APIHook，打包资源
/// English keywords: path candidates, development directory, resource directory, APIHook, bundled resource
pub fn process_hook_default_path_candidates(
    arch_dir: &str,
    file_name: &str,
    resource_dir: Option<&Path>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(project_root) = locate_process_hook_project_root() {
        candidates.push(
            project_root
                .join(FILE_HOOK_NATIVE_BIN_DIR)
                .join(arch_dir)
                .join(file_name),
        );
    }

    if let Some(resource_dir) = resource_dir {
        candidates.push(
            resource_dir
                .join(FILE_HOOK_NATIVE_BIN_DIR)
                .join(arch_dir)
                .join(file_name),
        );
        candidates.push(resource_dir.join(arch_dir).join(file_name));
    }

    candidates
}

/// 函数名称：resolve_process_hook_file
/// 函数作用：解析单个 APIHook 文件路径；前端传入非空路径时必须与默认可信候选归一化后相同，传空时按默认候选查找。
/// Function name: resolve_process_hook_file
/// Purpose: Resolves one APIHook file path; non-empty frontend paths must canonicalize to a trusted default candidate, empty paths use default candidates.
/// 调用方：resolve_process_hook_paths。
/// Called by: resolve_process_hook_paths.
/// 被调用方：process_hook_default_path_candidates，format_missing_process_hook_file_error。
/// Calls: process_hook_default_path_candidates, format_missing_process_hook_file_error.
/// 错误处理：缺失时返回包含角色、文件名和候选路径的 String。
/// Error handling: Missing files return String with role, filename and checked candidates.
/// 中文关键词：单文件解析，注入器路径，DLL路径，缺失错误
/// English keywords: single file resolution, injector path, DLL path, missing file error
fn resolve_process_hook_file(
    explicit_path: &str,
    role: &str,
    arch_dir: &str,
    file_name: &str,
    resource_dir: Option<&Path>,
) -> Result<PathBuf, String> {
    let candidates = process_hook_default_path_candidates(arch_dir, file_name, resource_dir);
    let trimmed_path = explicit_path.trim();
    if !trimmed_path.is_empty() {
        let explicit = PathBuf::from(trimmed_path);
        return resolve_explicit_process_hook_file(&explicit, role, file_name, &candidates);
    }

    candidates
        .iter()
        .find(|candidate| candidate.is_file())
        .cloned()
        .ok_or_else(|| format_missing_process_hook_file_error(role, file_name, &candidates))
}

fn resolve_explicit_process_hook_file(
    explicit: &Path,
    role: &str,
    file_name: &str,
    trusted_candidates: &[PathBuf],
) -> Result<PathBuf, String> {
    if explicit.file_name().and_then(|name| name.to_str()) != Some(file_name) {
        return Err(format_untrusted_process_hook_file_error(
            role,
            file_name,
            trusted_candidates,
        ));
    }

    let explicit_canonical = fs::canonicalize(explicit).map_err(|_| {
        format_missing_process_hook_file_error(role, file_name, &[explicit.to_path_buf()])
    })?;
    if !explicit_canonical.is_file() {
        return Err(format_missing_process_hook_file_error(
            role,
            file_name,
            &[explicit.to_path_buf()],
        ));
    }

    for candidate in trusted_candidates {
        if let Ok(candidate_canonical) = fs::canonicalize(candidate) {
            if candidate_canonical == explicit_canonical {
                return Ok(candidate_canonical);
            }
        }
    }

    Err(format_untrusted_process_hook_file_error(
        role,
        file_name,
        trusted_candidates,
    ))
}

/// 函数名称：locate_process_hook_project_root
/// 函数作用：从当前目录或 Cargo 清单目录推导项目根目录，用于开发模式下寻找 native/bin。
/// Function name: locate_process_hook_project_root
/// Purpose: Infers the project root from current_dir or Cargo manifest dir so development mode can find native/bin.
/// 调用方：process_hook_default_path_candidates。
/// Called by: process_hook_default_path_candidates.
/// 错误处理：当前目录不可读且编译期清单目录不可用时返回 None。
/// Error handling: Returns None when current_dir is unavailable and compile-time manifest dir cannot be used.
/// 中文关键词：项目根目录，开发模式，Cargo清单，路径推导
/// English keywords: project root, development mode, Cargo manifest, path inference
fn locate_process_hook_project_root() -> Option<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(current_dir) = std::env::current_dir() {
        roots.push(current_dir);
    }
    roots.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")));

    for root in roots {
        if let Some(project_root) = normalize_process_hook_project_root(&root) {
            return Some(project_root);
        }
    }
    None
}

/// 函数名称：normalize_process_hook_project_root
/// 函数作用：把 src-tauri 目录或项目内子目录规整到项目根目录。
/// Function name: normalize_process_hook_project_root
/// Purpose: Normalizes src-tauri or nested project directories to the project root.
/// 调用方：locate_process_hook_project_root。
/// Called by: locate_process_hook_project_root.
/// 中文关键词：路径规整，项目根目录，src-tauri，native目录
/// English keywords: path normalization, project root, src-tauri, native directory
fn normalize_process_hook_project_root(start: &Path) -> Option<PathBuf> {
    for ancestor in start.ancestors() {
        if ancestor.file_name().is_some_and(|name| name == "src-tauri") {
            return ancestor.parent().map(Path::to_path_buf);
        }
        if ancestor.join("src-tauri").is_dir() && ancestor.join("native").is_dir() {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

/// 函数名称：format_missing_process_hook_file_error
/// 函数作用：格式化 APIHook 文件缺失错误，带上角色、文件名和已检查候选路径。
/// Function name: format_missing_process_hook_file_error
/// Purpose: Formats an APIHook missing-file error with role, filename and checked candidates.
/// 调用方：resolve_process_hook_file。
/// Called by: resolve_process_hook_file.
/// 中文关键词：错误信息，缺失文件，候选路径，APIHook
/// English keywords: error message, missing file, candidate paths, APIHook
fn format_missing_process_hook_file_error(
    role: &str,
    file_name: &str,
    candidates: &[PathBuf],
) -> String {
    let checked_paths = if candidates.is_empty() {
        "no candidate paths were available".to_string()
    } else {
        candidates
            .iter()
            .map(|candidate| candidate.display().to_string())
            .collect::<Vec<_>>()
            .join("; ")
    };

    format!(
        "Missing APIHook {} file '{}'. Checked paths: {}",
        role, file_name, checked_paths
    )
}

fn format_untrusted_process_hook_file_error(
    role: &str,
    file_name: &str,
    candidates: &[PathBuf],
) -> String {
    let checked_paths = if candidates.is_empty() {
        "no trusted candidate paths were available".to_string()
    } else {
        candidates
            .iter()
            .map(|candidate| candidate.display().to_string())
            .collect::<Vec<_>>()
            .join("; ")
    };

    format!(
        "Rejected APIHook {} file '{}': explicit paths must resolve to a trusted packaged APIHook resource. Trusted paths: {}",
        role, file_name, checked_paths
    )
}

/// 函数名称：path_to_process_hook_string
/// 函数作用：将已解析 PathBuf 转为 Windows 命令行可用字符串。
/// Function name: path_to_process_hook_string
/// Purpose: Converts a resolved PathBuf to a Windows command-line string.
/// 调用方：ProcessMonitorService::start_with_resource_dir。
/// Called by: ProcessMonitorService::start_with_resource_dir.
/// 中文关键词：路径转换，命令行，注入器
/// English keywords: path conversion, command line, injector
fn path_to_process_hook_string(path: &Path) -> String {
    path.display().to_string()
}

/// 函数名称：wait_for_process_monitor_thread_stop
/// 函数作用：在限定时间内等待进程监控线程退出，避免 stop 路径无限 join。
/// Purpose: Waits for a process monitor thread to finish within a bounded timeout, avoiding indefinite joins on stop.
/// 调用方：ProcessMonitorService::stop，进程监控单元测试。
/// Called by: ProcessMonitorService::stop, process monitor unit tests.
/// 参数说明：handle 为后台线程句柄；timeout 为最大等待时间；thread_name 用于错误定位。
/// Parameters: handle is the background thread handle; timeout is the maximum wait; thread_name labels errors.
/// 返回值说明：线程结束返回 None；超时返回 Some(handle) 交还调用方保存。
/// Returns: None when the thread finished; Some(handle) on timeout so the caller can keep it.
/// 错误处理：线程 panic 转换为 String；超时不 panic、不无限等待。
/// Error handling: Converts thread panic to String; timeout does not panic or wait indefinitely.
/// 中文关键词：进程监控，线程等待，超时保护，阻塞防护
/// English keywords: process monitor, thread wait, timeout guard, blocking guard
fn wait_for_process_monitor_thread_stop(
    handle: thread::JoinHandle<()>,
    timeout: Duration,
    thread_name: &str,
) -> Result<Option<thread::JoinHandle<()>>, String> {
    let started_at = Instant::now();

    while started_at.elapsed() < timeout {
        if handle.is_finished() {
            handle.join().map_err(|_| {
                format!(
                    "Process monitor {} thread panicked during stop",
                    thread_name
                )
            })?;
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(PROCESS_MONITOR_STOP_JOIN_POLL_MS));
    }

    Ok(Some(handle))
}

/// 函数名称：collect_current_pids
/// 函数作用：通过 CreateToolhelp32Snapshot 收集系统当前所有进程 PID。
/// Purpose: Collects all current process PIDs via CreateToolhelp32Snapshot.
/// 被调用方：watcher_thread
/// Called by: watcher_thread
/// 中文关键词：进程枚举，当前进程，PID收集，ToolHelp，进程快照
/// English keywords: process enumeration, current processes, PID collection, ToolHelp, process snapshot
fn collect_current_pids() -> HashSet<u32> {
    use windows::Win32::Foundation::*;
    use windows::Win32::System::Diagnostics::ToolHelp::*;

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

/// 函数名称：initial_seen_pids
/// 函数作用：进程监控启动时把已有进程作为基线，避免刚启动就向全系统既有进程注入 Hook DLL。
/// Function name: initial_seen_pids
/// Purpose: Uses existing processes as the initial baseline so startup does not inject the hook DLL into every already-running process.
/// 调用方：watcher_thread。
/// Called by: watcher_thread.
/// 中文关键词：进程监控，启动基线，既有进程，减少误报
/// English keywords: process monitor, startup baseline, existing processes, false-positive reduction
fn initial_seen_pids() -> HashSet<u32> {
    collect_current_pids()
}

/// 函数名称：query_process_image_path
/// 函数作用：通过 OpenProcess + QueryFullProcessImageNameW 获取指定 PID 的可执行文件路径。
/// Purpose: Gets executable path for a PID via OpenProcess + QueryFullProcessImageNameW.
/// 被调用方：watcher_thread
/// Called by: watcher_thread
/// 中文关键词：进程路径，镜像路径，进程查询，OpenProcess
/// English keywords: process path, image path, process query, OpenProcess
fn query_process_image_path(pid: u32) -> Option<String> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::*;
    use windows::Win32::System::Threading::*;

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

/// 函数名称：detect_process_arch
/// 函数作用：通过 IsWow64Process2 检测目标进程架构（x86 或 x64）。
/// Purpose: Detects target process architecture (x86 or x64) via IsWow64Process2.
/// 被调用方：watcher_thread
/// Called by: watcher_thread
/// 中文关键词：进程架构，IsWow64Process2，x86，x64，WOW64
/// English keywords: process arch, IsWow64Process2, x86, x64, WOW64
fn detect_process_arch(pid: u32) -> ProcArch {
    use windows::Win32::Foundation::*;
    use windows::Win32::System::Threading::*;

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
                if process_machine == 0 {
                    // IMAGE_FILE_MACHINE_UNKNOWN
                    return if native_machine == 0x8664 {
                        ProcArch::X64
                    } else {
                        ProcArch::X86
                    };
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
    stop_flag: &Arc<AtomicBool>,
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
        .env(FILE_HOOK_INJECTOR_SKIP_SELF_HOOK_ENV, "1")
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn();

    if let Ok(mut child) = result {
        let start = std::time::Instant::now();
        let timeout = Duration::from_millis(12000);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if stop_flag.load(Ordering::Relaxed) {
                        let _ = child.kill();
                        break;
                    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_monitor_thread_wait_joins_finished_thread_without_timeout() {
        let handle = thread::spawn(|| {});

        let remaining_handle =
            wait_for_process_monitor_thread_stop(handle, Duration::from_millis(250), "unit")
                .expect("finished thread should join cleanly");

        assert!(
            remaining_handle.is_none(),
            "finished process monitor thread should not be retained"
        );
    }

    #[test]
    fn initial_seen_pids_uses_current_process_baseline() {
        let baseline = initial_seen_pids();

        assert!(
            baseline.contains(&std::process::id()),
            "startup baseline should include the current process and avoid treating existing PIDs as new"
        );
    }
}
