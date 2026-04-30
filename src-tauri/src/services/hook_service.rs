// 文件钩子服务 — 管理命名管道服务端，接收注入进程的实时文件操作事件
// File hook service — manages named pipe server, receives real-time file operation events from injected processes
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc;
use serde::{Deserialize, Serialize};
use libloading::{Library, Symbol};

/// 文件钩子事件 / File hook event
/// Received from injected file_hook_detours.dll via named pipe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHookEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub path: String,
    #[serde(rename = "targetPath", skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    pub pid: u32,
    #[serde(rename = "processName", skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    pub timestamp: u64,
}

/// 文件钩子服务 — 命名管道服务端
/// File hook service — named pipe server
///
/// 使用 libloading 动态调用 kernel32.dll 的命名管道 API，避免 windows-core 版本冲突。
/// Uses libloading to dynamically call kernel32.dll named pipe APIs, avoiding windows-core version conflicts.
pub struct HookService {
    tx: Arc<Mutex<Option<mpsc::UnboundedSender<FileHookEvent>>>>,
    running: Arc<AtomicBool>,
}

impl HookService {
    pub fn new() -> Self {
        Self {
            tx: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 函数名称：start
    /// 函数作用：启动命名管道服务端，开始接收文件操作事件。
    /// Purpose: Starts the named pipe server, begins receiving file operation events.
    /// Called by: main.rs setup() on app start, commands::hook::start_hook_service
    /// 中文关键词：启动管道，接收事件，文件钩子启动
    /// English keywords: start pipe, receive events, file hook start
    pub fn start(&self, pipe_name: &str) -> Result<mpsc::UnboundedReceiver<FileHookEvent>, String> {
        if self.running.load(Ordering::SeqCst) {
            return Err("Hook service is already running".to_string());
        }

        let (tx, rx) = mpsc::unbounded_channel::<FileHookEvent>();
        *self.tx.lock().map_err(|e| e.to_string())? = Some(tx);

        let running = self.running.clone();
        let full_pipe_name = format!(r"\\.\pipe\{}", pipe_name);
        self.running.store(true, Ordering::SeqCst);

        thread::spawn(move || {
            eprintln!("[HookService] Starting named pipe server: {}", full_pipe_name);
            while running.load(Ordering::SeqCst) {
                match serve_pipe_connection(&full_pipe_name) {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("[HookService] Pipe connection error: {}", e);
                    }
                }
                thread::sleep(Duration::from_millis(100));
            }
            eprintln!("[HookService] Named pipe server stopped");
        });

        Ok(rx)
    }

    pub fn stop(&self) -> Result<(), String> {
        self.running.store(false, Ordering::SeqCst);
        *self.tx.lock().map_err(|e| e.to_string())? = None;
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

}

/// 内部函数：通过 libloading 动态调用 kernel32.dll 的命名管道 API 处理单个连接
/// Internal: handle a single named pipe connection via libloading dynamic calls to kernel32.dll
fn serve_pipe_connection(pipe_name: &str) -> Result<Vec<FileHookEvent>, String> {
    // 动态加载 kernel32.dll / Dynamically load kernel32.dll
    let kernel32 = unsafe { 
        Library::new("kernel32.dll")
            .map_err(|e| format!("Failed to load kernel32.dll: {}", e))?
    };

    // CreateNamedPipeA
    type CreateNamedPipeFn = unsafe extern "system" fn(
        name: *const u8, open_mode: u32, pipe_mode: u32,
        max_instances: u32, out_buf_size: u32, in_buf_size: u32,
        default_timeout: u32, security_attrs: *const u8,
    ) -> isize;
    let create_pipe: Symbol<CreateNamedPipeFn> = unsafe { kernel32.get(b"CreateNamedPipeA") }
        .map_err(|e| format!("Failed to get CreateNamedPipeA: {}", e))?;

    // ConnectNamedPipe
    type ConnectNamedPipeFn = unsafe extern "system" fn(pipe: isize, overlapped: *const u8) -> i32;
    let connect_pipe: Symbol<ConnectNamedPipeFn> = unsafe { kernel32.get(b"ConnectNamedPipe") }
        .map_err(|e| format!("Failed to get ConnectNamedPipe: {}", e))?;

    // ReadFile
    type ReadFileFn = unsafe extern "system" fn(
        file: isize, buffer: *mut u8, bytes_to_read: u32,
        bytes_read: *mut u32, overlapped: *const u8,
    ) -> i32;
    let read_file: Symbol<ReadFileFn> = unsafe { kernel32.get(b"ReadFile") }
        .map_err(|e| format!("Failed to get ReadFile: {}", e))?;

    // CloseHandle
    type CloseHandleFn = unsafe extern "system" fn(handle: isize) -> i32;
    let close_handle: Symbol<CloseHandleFn> = unsafe { kernel32.get(b"CloseHandle") }
        .map_err(|e| format!("Failed to get CloseHandle: {}", e))?;

    // 管道模式常量 / Pipe mode constants
    const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
    const PIPE_TYPE_MESSAGE: u32 = 0x00000004;
    const PIPE_READMODE_MESSAGE: u32 = 0x00000002;
    const PIPE_WAIT: u32 = 0x00000000;
    const INVALID_HANDLE_VALUE: isize = -1;

    use std::ffi::CString;
    let pipe_name_c = CString::new(pipe_name)
        .map_err(|_| "Invalid pipe name".to_string())?;

    let pipe_handle = unsafe {
        create_pipe(
            pipe_name_c.as_ptr() as *const u8,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,      // max instances
            65536,  // out buffer
            65536,  // in buffer
            0,      // default timeout
            std::ptr::null(),  // default security
        )
    };

    if pipe_handle == INVALID_HANDLE_VALUE {
        return Err("Failed to create named pipe".to_string());
    }

    // 等待客户端连接 / Wait for client connection
    let connected = unsafe { connect_pipe(pipe_handle, std::ptr::null()) };
    if connected == 0 {
        unsafe { close_handle(pipe_handle); }
        return Ok(Vec::new());
    }

    let mut events: Vec<FileHookEvent> = Vec::new();
    let mut buffer = vec![0u8; 65536];

    // 读取消息 / Read messages
    loop {
        let mut bytes_read: u32 = 0;
        let result = unsafe {
            read_file(
                pipe_handle,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut bytes_read,
                std::ptr::null(),
            )
        };

        if result == 0 || bytes_read == 0 {
            break;
        }

        let msg = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
        for line in msg.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<FileHookEvent>(trimmed) {
                events.push(event);
            } else {
                eprintln!("[HookService] Failed to parse hook event: {}", trimmed);
            }
        }
    }

    unsafe { close_handle(pipe_handle); }
    Ok(events)
}
