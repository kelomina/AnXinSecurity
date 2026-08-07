// IPC 客户端 — 运行在 UI 进程中，连接到服务进程的命名管道
//  IPC client - runs in UI process, connects to service process's named pipe
//
// 职责：
//  Responsibilities:
// - 连接到服务进程的命名管道 \\.\pipe\AnXinSecurityIPC
// - 向服务进程发送请求（状态查询、拦截决策等）
// - 接收服务进程推送的事件（ETW 事件、拦截通知等），转发到 Tauri 事件系统
//
// 当 UI 进程启动时，先尝试连接 IPC 管道：
//  When UI process starts, first try to connect to IPC pipe:
// - 连接成功：说明服务进程已运行，UI 进程作为客户端连接，防护由服务进程提供
// - 连接失败：说明服务进程未运行，UI 进程自己启动防护组件（兼容模式）
//
// 自动重连由 IpcBridgeService 管理，不在此模块内实现
//  Auto reconnect is managed by IpcBridgeService, not implemented in this module
//
// 中文关键词：IPC 客户端，命名管道，客户端，UI 进程，前后端分离
// English keywords: IPC client, named pipe, client, UI process, frontend-backend separation
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::services::ipc_protocol::{IpcMessage, RequestId, IPC_PIPE_NAME};

// ============================================================================
// IPC 客户端 — 连接到服务进程
//  IPC client - connects to service process
// ============================================================================

/// IPC 客户端 — 连接到服务进程，发送请求，接收事件
///  IPC client - connects to service process, sends requests, receives events
///
/// 所有方法都是 `&self`，通过内部可变性支持并发访问和重连
///  All methods are `&self`, supporting concurrent access and reconnect via interior mutability
pub struct IpcClient {
    /// 是否已连接
    ///  Whether connected
    connected: Arc<AtomicBool>,
    /// 下一个请求 ID
    ///  Next request ID
    next_request_id: AtomicU64,
    /// 待处理的请求响应（request_id -> response sender）
    ///  Pending request responses (request_id -> response sender)
    pending_responses: Arc<Mutex<HashMap<RequestId, std::sync::mpsc::Sender<IpcMessage>>>>,
    /// 事件回调（event_name -> callback）
    ///  Event callbacks (event_name -> callback)
    event_callbacks: Arc<Mutex<HashMap<String, Box<dyn Fn(serde_json::Value) + Send + Sync>>>>,
    /// 写入端（用于向服务进程发送消息）
    ///  Write side (for sending messages to service process)
    writer: Arc<Mutex<Option<Box<dyn Write + Send>>>>,
    /// 读取线程句柄
    ///  Read thread handle
    read_thread: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
}

impl IpcClient {
    /// 创建新的 IPC 客户端
    ///  Create new IPC client
    pub fn new() -> Self {
        Self {
            connected: Arc::new(AtomicBool::new(false)),
            next_request_id: AtomicU64::new(1),
            pending_responses: Arc::new(Mutex::new(HashMap::new())),
            event_callbacks: Arc::new(Mutex::new(HashMap::new())),
            writer: Arc::new(Mutex::new(None)),
            read_thread: Arc::new(Mutex::new(None)),
        }
    }

    /// 尝试连接到服务进程的 IPC 管道
    ///  Try to connect to service process's IPC pipe
    ///
    /// 返回 true 表示连接成功，false 表示服务进程未运行
    ///  Returns true if connected, false if service process not running
    ///
    /// 此方法为 `&self`，可在重连场景中反复调用
    ///  This method is `&self`, can be called repeatedly in reconnect scenarios
    pub fn connect(&self) -> Result<bool, String> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows::Win32::Storage::FileSystem::CreateFileW;

        // 如果已经连接，直接返回成功
        //  If already connected, return success directly
        if self.connected.load(Ordering::SeqCst) {
            return Ok(true);
        }

        let pipe_name_wide: Vec<u16> = IPC_PIPE_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let pipe_handle = unsafe {
            CreateFileW(
                PCWSTR(pipe_name_wide.as_ptr()),
                windows::Win32::Storage::FileSystem::FILE_GENERIC_READ.0
                    | windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE.0,
                windows::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
                None,
                windows::Win32::Storage::FileSystem::OPEN_EXISTING,
                windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };

        let pipe_handle = match pipe_handle {
            Ok(h) => h,
            Err(_e) => {
                // ERROR_PIPE_BUSY (231) 或 ERROR_FILE_NOT_FOUND (2) 表示服务未运行
                //  ERROR_PIPE_BUSY (231) or ERROR_FILE_NOT_FOUND (2) means service not running
                return Ok(false);
            }
        };

        if pipe_handle == INVALID_HANDLE_VALUE {
            return Ok(false);
        }

        eprintln!("[IPC Client] Connected to service process");

        // 清理旧的读取线程（如果存在）
        //  Clean up old read thread if exists
        {
            let mut read_thread_guard = self.read_thread.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(old_thread) = read_thread_guard.take() {
                // 旧线程应该已经退出（因为 connected 之前被设为 false）
                //  Old thread should have exited (because connected was set to false before)
                let _ = old_thread.join();
            }
        }

        // 创建读写器
        //  Create reader and writer
        let (reader, writer) = ClientPipeConnection::new(pipe_handle);
        {
            let mut writer_guard = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            writer_guard.replace(Box::new(writer));
        }
        self.connected.store(true, Ordering::SeqCst);

        // 启动读取线程
        //  Start read thread
        let pending = self.pending_responses.clone();
        let callbacks = self.event_callbacks.clone();
        let connected = self.connected.clone();
        let writer_for_cleanup = self.writer.clone();

        let read_handle = thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            loop {
                if !connected.load(Ordering::SeqCst) {
                    break;
                }
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        eprintln!("[IPC Client] Service process disconnected");
                        connected.store(false, Ordering::SeqCst);
                        // 清理写入端，避免后续 request 卡在 writer 锁上
                        //  Clean up writer to prevent subsequent requests from blocking on writer lock
                        {
                            let mut writer_guard =
                                writer_for_cleanup.lock().unwrap_or_else(|e| e.into_inner());
                            *writer_guard = None;
                        }
                        break;
                    }
                    Ok(_) => {
                        if let Ok(msg) = IpcMessage::from_line(&line) {
                            match msg {
                                IpcMessage::Response { response } => {
                                    // 匹配待处理的请求
                                    //  Match pending request
                                    let pending_map =
                                        pending.lock().unwrap_or_else(|e| e.into_inner());
                                    if let Some(sender) = pending_map.get(&response.id) {
                                        let _ = sender.send(IpcMessage::Response { response });
                                    }
                                }
                                IpcMessage::Event { event } => {
                                    // 调用事件回调
                                    //  Call event callback
                                    let cb_map =
                                        callbacks.lock().unwrap_or_else(|e| e.into_inner());
                                    if let Some(callback) = cb_map.get(&event.event) {
                                        callback(event.data);
                                    }
                                }
                                IpcMessage::Request { .. } => {
                                    // 客户端不接收请求，忽略
                                    //  Client doesn't receive requests, ignore
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[IPC Client] Read error: {}", e);
                        connected.store(false, Ordering::SeqCst);
                        {
                            let mut writer_guard =
                                writer_for_cleanup.lock().unwrap_or_else(|e| e.into_inner());
                            *writer_guard = None;
                        }
                        break;
                    }
                }
            }
            eprintln!("[IPC Client] Read thread exiting");
        });

        // 保存读取线程句柄
        //  Save read thread handle
        {
            let mut read_thread_guard = self.read_thread.lock().unwrap_or_else(|e| e.into_inner());
            *read_thread_guard = Some(read_handle);
        }

        Ok(true)
    }

    /// 检查是否已连接到服务进程
    ///  Check if connected to service process
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// 发送请求并等待响应（阻塞，带超时）
    ///  Send request and wait for response (blocking, with timeout)
    pub fn request(
        &self,
        method: &str,
        params: serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, String> {
        if !self.is_connected() {
            return Err("Not connected to service process".to_string());
        }

        let id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let msg = IpcMessage::request(id, method, params);

        let (tx, rx) = std::sync::mpsc::channel::<IpcMessage>();
        {
            let mut pending = self
                .pending_responses
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            pending.insert(id, tx);
        }

        // 发送请求
        //  Send request
        let line = msg.to_line().map_err(|e| e.to_string())?;
        let line_with_newline = format!("{}\n", line);
        {
            let mut writer_guard = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref mut writer) = *writer_guard {
                writer
                    .write_all(line_with_newline.as_bytes())
                    .map_err(|e| format!("Failed to write request: {}", e))?;
                writer
                    .flush()
                    .map_err(|e| format!("Failed to flush request: {}", e))?;
            } else {
                // 写入端不存在（可能刚断开），清理待处理请求
                //  Writer not available (possibly just disconnected), clean up pending request
                let mut pending = self
                    .pending_responses
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                pending.remove(&id);
                return Err("Connection lost while sending request".to_string());
            }
        }

        // 等待响应（带超时）
        //  Wait for response (with timeout)
        match rx.recv_timeout(Duration::from_millis(timeout_ms)) {
            Ok(IpcMessage::Response { response }) => {
                // 清理待处理请求
                //  Clean up pending request
                let mut pending = self
                    .pending_responses
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                pending.remove(&id);

                if let Some(result) = response.result {
                    Ok(result)
                } else if let Some(error) = response.error {
                    Err(error)
                } else {
                    Err("Empty response".to_string())
                }
            }
            _ => {
                // 清理待处理请求
                //  Clean up pending request
                let mut pending = self
                    .pending_responses
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                pending.remove(&id);
                Err("Request timed out or channel closed".to_string())
            }
        }
    }

    /// 注册事件回调（当服务进程推送事件时调用）
    ///  Register event callback (called when service process pushes events)
    ///
    /// 回调在 IpcClient 内部持久存储，即使连接断开重连，回调仍然有效
    ///  Callbacks are stored persistently inside IpcClient; they remain valid across reconnects
    pub fn on_event<F>(&self, event: &str, callback: F)
    where
        F: Fn(serde_json::Value) + Send + Sync + 'static,
    {
        let mut callbacks = self
            .event_callbacks
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        callbacks.insert(event.to_string(), Box::new(callback));
    }

    /// 断开连接（不启动重连）
    ///  Disconnect (does not trigger reconnect)
    #[allow(dead_code)]
    pub fn disconnect(&self) {
        self.connected.store(false, Ordering::SeqCst);
        // 清理写入端
        //  Clean up writer
        {
            let mut writer_guard = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            *writer_guard = None;
        }
    }
}

impl Default for IpcClient {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 客户端管道连接
//  Client pipe connection
// ============================================================================

/// 客户端命名管道的读端
///  Client named pipe reader
struct ClientPipeReader {
    handle: windows::Win32::Foundation::HANDLE,
}

// HANDLE 包含 *mut c_void 不是 Send，但管道句柄在 Windows 上可以安全跨线程使用
//  HANDLE contains *mut c_void which is not Send, but pipe handles are safe to use across threads on Windows
unsafe impl Send for ClientPipeReader {}

impl std::io::Read for ClientPipeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use windows::Win32::Storage::FileSystem::ReadFile;
        let mut bytes_read: u32 = 0;
        let result = unsafe {
            ReadFile(
                self.handle,
                Some(buf),
                Some(&mut bytes_read as *mut u32),
                None,
            )
        };
        match result {
            Ok(_) => Ok(bytes_read as usize),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )),
        }
    }
}

/// 客户端命名管道的写端
///  Client named pipe writer
struct ClientPipeWriter {
    handle: windows::Win32::Foundation::HANDLE,
}

// HANDLE 包含 *mut c_void 不是 Send，但管道句柄在 Windows 上可以安全跨线程使用
//  HANDLE contains *mut c_void which is not Send, but pipe handles are safe to use across threads on Windows
unsafe impl Send for ClientPipeWriter {}

impl std::io::Write for ClientPipeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use windows::Win32::Storage::FileSystem::WriteFile;
        let mut bytes_written: u32 = 0;
        let result = unsafe {
            WriteFile(
                self.handle,
                Some(buf),
                Some(&mut bytes_written as *mut u32),
                None,
            )
        };
        match result {
            Ok(_) => Ok(bytes_written as usize),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        use windows::Win32::Storage::FileSystem::FlushFileBuffers;
        unsafe {
            FlushFileBuffers(self.handle)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        }
    }
}

/// 客户端命名管道连接
///  Client named pipe connection
struct ClientPipeConnection;

impl ClientPipeConnection {
    /// 从管道句柄创建读端和写端
    ///  Create reader and writer from pipe handle
    fn new(handle: windows::Win32::Foundation::HANDLE) -> (ClientPipeReader, ClientPipeWriter) {
        (ClientPipeReader { handle }, ClientPipeWriter { handle })
    }
}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_client_new_initializes_disconnected() {
        let client = IpcClient::new();
        assert!(!client.is_connected());
    }

    #[test]
    fn ipc_client_disconnect_sets_connected_false() {
        let client = IpcClient::new();
        client.connected.store(true, Ordering::SeqCst);
        client.disconnect();
        assert!(!client.is_connected());
    }

    #[test]
    fn ipc_client_request_not_connected_returns_error() {
        let client = IpcClient::new();
        let result = client.request("ping", serde_json::json!({}), 1000);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Not connected to service process".to_string()
        );
    }

    #[test]
    fn ipc_client_on_event_registers_callback() {
        let client = IpcClient::new();
        client.on_event("test-event", |_data| {
            // 回调内容
            //  Callback content
        });
        let callbacks = client
            .event_callbacks
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert!(callbacks.contains_key("test-event"));
    }

    #[test]
    fn ipc_client_connect_already_connected_returns_ok_true() {
        let client = IpcClient::new();
        client.connected.store(true, Ordering::SeqCst);
        let result = client.connect();
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
