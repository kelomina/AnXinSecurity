// IPC 服务器 — 命名管道服务端，运行在防护服务进程中
//  IPC server - named pipe server, runs in the protection service process
//
// 职责：
//  Responsibilities:
// - 监听命名管道 \\.\pipe\Global\AnXinSecurityIPC，接受 UI 进程连接
// - 接收 UI 进程的请求（状态查询、拦截决策等），分发给防护组件
// - 将防护组件产生的事件（ETW 事件、拦截通知等）推送给已连接的 UI 进程
//
// 通信协议见 ipc_protocol.rs，使用换行符分隔的 JSON 消息。
//  Communication protocol in ipc_protocol.rs, using newline-delimited JSON messages.
//
// 中文关键词：IPC 服务器，命名管道，服务端，事件推送，前后端分离
// English keywords: IPC server, named pipe, server, event push, frontend-backend separation
use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::services::ipc_protocol::{
    methods, InterceptionDecisionParams, InterceptionQueueItem, IpcMessage, ProtectionStatus,
    RequestId, IPC_PIPE_NAME,
};
use crate::services::service_context::ServiceContext;

// ============================================================================
// 客户端连接管理 — 跟踪所有已连接的 UI 进程
//  Client connection management - tracks all connected UI processes
// ============================================================================

/// 一个已连接的 UI 客户端
///  A connected UI client
struct IpcClient {
    /// 客户端唯一 ID
    ///  Client unique ID
    id: u64,
    /// 写入端（用于向客户端推送消息）
    ///  Write side (for pushing messages to client)
    writer: std::sync::Mutex<Box<dyn Write + Send>>,
}

/// 客户端连接池 — 管理所有活跃的 UI 进程连接
///  Client connection pool - manages all active UI process connections
struct ClientPool {
    clients: Mutex<HashMap<u64, Arc<IpcClient>>>,
    next_id: AtomicU64,
}

impl ClientPool {
    fn new() -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn add(&self, writer: Box<dyn Write + Send>) -> Arc<IpcClient> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let client = Arc::new(IpcClient {
            id,
            writer: std::sync::Mutex::new(writer),
        });
        self.clients
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, client.clone());
        client
    }

    fn remove(&self, id: u64) {
        self.clients
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
    }

    /// 向所有已连接的客户端广播消息
    ///  Broadcast a message to all connected clients
    fn broadcast(&self, message: &IpcMessage) {
        let line = match message.to_line() {
            Ok(line) => line,
            Err(e) => {
                eprintln!("[IPC] Failed to serialize broadcast message: {}", e);
                return;
            }
        };
        let line_with_newline = format!("{}\n", line);

        let clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        for (id, client) in clients.iter() {
            if let Ok(mut writer) = client.writer.lock() {
                if let Err(e) = writer.write_all(line_with_newline.as_bytes()) {
                    eprintln!("[IPC] Failed to write to client {}: {}", id, e);
                }
                let _ = writer.flush();
            }
        }
    }

    #[allow(dead_code)]
    fn client_count(&self) -> usize {
        self.clients.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

// ============================================================================
// 请求工作池 — 把请求执行与读循环线程解耦
//  Request worker pool - decouples request execution from the read-loop thread
// ============================================================================

/// 每个客户端连接的工作线程数量（有界并发，避免按请求 spawn 无限线程）。
///  Bounded worker count per client connection (bounds concurrency, avoids an
///  unbounded thread per request).
const IPC_WORKERS_PER_CLIENT: usize = 4;

/// 由固定数量 worker 并发消费的一个作业。
///  A queued request, executed concurrently by one of the bounded workers.
struct PendingRequest {
    id: RequestId,
    method: String,
    params: serde_json::Value,
}

/// 创建一个由固定数量 worker 并发消费的作业队列，返回作业发送端。
///  Creates a job queue consumed concurrently by a fixed number of workers,
///  returning the job sender.
///
/// `worker_factory` 在**发起线程**上被调用 `worker_count` 次，每次生成一个
/// 属于该 worker 的独立处理器（handler）。每个 worker 用自己那份处理器，
/// 因此多个 worker 能真正并发执行各自拿到的作业（长任务不会阻塞其他请求）。
///  `worker_factory` is invoked `worker_count` times on the spawning thread, each
///  time producing an independent handler for one worker. Each worker runs with its
///  own handler, so multiple workers genuinely execute their jobs concurrently
///  (a long task does not block other requests).
///
/// 并发关键：worker 拿到作业、释放接收端锁之后才执行 handler。
///  Concurrency key: a worker runs its handler only after claiming the job and
///  releasing the receiver lock.
fn spawn_worker_queue<J, F, H>(
    name: &str,
    worker_count: usize,
    worker_factory: F,
) -> std::sync::mpsc::Sender<J>
where
    J: Send + 'static,
    F: Fn() -> H,
    H: FnMut(J) + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel::<J>();
    let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
    for _ in 0..worker_count {
        let rx = rx.clone();
        let mut handle = worker_factory();
        if let Err(e) = thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                loop {
                    // 先取锁、阻塞取作业，随后 guard 随语句结束立即释放，
                    // 执行阶段不再持有接收端锁，从而支持多 worker 并发执行。
                    //  Concurrent execution relies on the guard dropping here,
                    //  before the job handler runs.
                    let job = match rx.lock().unwrap_or_else(|e| e.into_inner()).recv() {
                        Ok(job) => job,
                        // 发送端已丢弃（读循环结束/客户端断开），排空后退线程
                        //  Sender dropped (read loop ended / client disconnected); exit after draining
                        Err(_) => break,
                    };
                    handle(job);
                }
            })
        {
            eprintln!("[IPC] Failed to spawn worker '{}': {}", name, e);
        }
    }
    tx
}

// ============================================================================
// IPC 服务器 — 命名管道服务端
//  IPC server - named pipe server
// ============================================================================

/// IPC 服务器 — 在服务进程中运行，接受 UI 进程的连接
///  IPC server - runs in service process, accepts connections from UI process
pub struct IpcServer {
    /// 是否运行中
    ///  Whether running
    running: Arc<AtomicBool>,
    /// 客户端连接池
    ///  Client connection pool
    clients: Arc<ClientPool>,
    /// 服务上下文（防护组件的依赖注入容器）
    ///  Service context (dependency injection container for protection components)
    ctx: ServiceContext,
    /// 服务启动时间（Unix 毫秒）
    ///  Service start time (Unix ms)
    started_at: u64,
    /// Tokio runtime handle — 用于在同步 IPC 处理线程中调用 async 引擎方法
    ///  Tokio runtime handle - used to call async engine methods from sync IPC handler threads
    runtime_handle: tokio::runtime::Handle,
}

impl IpcServer {
    /// 创建 IPC 服务器
    ///  Create IPC server
    pub fn new(
        ctx: ServiceContext,
        started_at: u64,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            clients: Arc::new(ClientPool::new()),
            ctx,
            started_at,
            runtime_handle,
        }
    }

    /// 启动 IPC 服务器（阻塞当前线程，应在独立线程中调用）
    ///  Start IPC server (blocks current thread, should be called in a separate thread)
    pub fn start(&self) -> Result<(), String> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
        use windows::Win32::System::Pipes::CreateNamedPipeW;

        self.running.store(true, Ordering::SeqCst);
        eprintln!("[IPC] Server starting on pipe: {}", IPC_PIPE_NAME);

        // 创建安全描述符：允许 SYSTEM、Administrators 和交互式登录用户访问
        //  Create security descriptor: allow SYSTEM, Administrators, and interactive users
        //
        // 原来这里给的是 WD（Everyone）+ GENERIC_ALL。这条管道是 SYSTEM 托管的控制
        // 通道，上面挂着 handle_interception、clear_interception_queue、start_engine，
        // 以及本轮新增的 set_firewall_enabled / handle_network_decision —— 也就是说
        // 任何本地账户（含各类服务账户、网络登录、计划任务身份）都能连上来关掉防火墙、
        // 清空拦截队列或替恶意进程放行。
        //  This used to be WD (Everyone) with GENERIC_ALL. The pipe is a
        //  SYSTEM-hosted control channel carrying handle_interception,
        //  clear_interception_queue, start_engine and the newly added
        //  set_firewall_enabled / handle_network_decision — so any local account
        //  (service accounts, network logons, scheduled-task identities included)
        //  could connect and switch the firewall off, drain the interception queue,
        //  or allow a malicious process through.
        //
        // 改为 IU（Interactive Users）：UI 进程在交互式会话里运行，不论登录的是哪个
        // 用户都能连上，而非交互式的服务/网络登录身份被排除在外。
        //  IU (Interactive Users) instead: the UI runs in an interactive session so
        //  it still connects regardless of which user is logged on, while
        //  non-interactive service and network-logon identities are excluded.
        //
        // 注意这不足以挡住同一交互式会话里的恶意进程 —— 那需要
        // identity_verification_service 的调用方身份校验，而该模块目前声明了但没有接线。
        //  Note this does not stop a malicious process inside the same interactive
        //  session; that requires the caller verification in
        //  identity_verification_service, which is currently declared but unwired.
        let sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)";
        let mut sddl_wide: Vec<u16> = sddl.encode_utf16().collect();
        sddl_wide.push(0);

        let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_wide.as_ptr()),
                SDDL_REVISION_1,
                &mut security_descriptor,
                None,
            )
            .map_err(|e| format!("Failed to create pipe security descriptor: {}", e))?;
        }

        let security_attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security_descriptor.0 as *mut _,
            bInheritHandle: false.into(),
        };

        let pipe_name_wide: Vec<u16> = IPC_PIPE_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // 主循环：反复创建管道实例，等待客户端连接
        //  Main loop: repeatedly create pipe instances, wait for client connections
        while self.running.load(Ordering::SeqCst) {
            // 创建命名管道实例
            //  Create named pipe instance
            let pipe_handle: HANDLE = unsafe {
                CreateNamedPipeW(
                    PCWSTR(pipe_name_wide.as_ptr()),
                    windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX,
                    windows::Win32::System::Pipes::PIPE_TYPE_MESSAGE
                        | windows::Win32::System::Pipes::PIPE_WAIT,
                    windows::Win32::System::Pipes::PIPE_UNLIMITED_INSTANCES,
                    65536,
                    65536,
                    0,
                    Some(&security_attributes),
                )
            };

            if pipe_handle == INVALID_HANDLE_VALUE {
                eprintln!("[IPC] Failed to create named pipe instance, retrying in 1s...");
                thread::sleep(Duration::from_secs(1));
                continue;
            }

            // 等待客户端连接（阻塞）
            //  Wait for client connection (blocking)
            eprintln!("[IPC] Waiting for client connection...");
            let connected =
                unsafe { windows::Win32::System::Pipes::ConnectNamedPipe(pipe_handle, None) };

            if connected.is_err() {
                let err = unsafe { windows::Win32::Foundation::GetLastError() };
                eprintln!("[IPC] ConnectNamedPipe failed: {:?}", err);
                unsafe {
                    let _ = CloseHandle(pipe_handle);
                }
                continue;
            }

            eprintln!("[IPC] Client connected");

            // 为每个客户端连接创建处理线程
            //  Create handler thread for each client connection
            // HANDLE 不是 Send，转换为 isize 跨线程传递，在 handle_client 中转回 HANDLE
            //  HANDLE is not Send, convert to isize for cross-thread transfer, convert back to HANDLE in handle_client
            let ctx = self.ctx.clone();
            let clients = self.clients.clone();
            let started_at = self.started_at;
            let running = self.running.clone();
            let runtime_handle = self.runtime_handle.clone();
            let handle_as_isize = pipe_handle.0 as isize;

            thread::spawn(move || {
                let handle = windows::Win32::Foundation::HANDLE(handle_as_isize as *mut _);
                Self::handle_client(handle, ctx, clients, started_at, running, runtime_handle);
            });
        }

        // 清理安全描述符
        //  Clean up security descriptor
        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
                security_descriptor.0,
            ));
        }

        eprintln!("[IPC] Server stopped");
        Ok(())
    }

    /// 停止 IPC 服务器
    ///  Stop IPC server
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// 获取已连接客户端数量
    ///  Get connected client count
    #[allow(dead_code)]
    pub fn client_count(&self) -> usize {
        self.clients.client_count()
    }

    /// 向所有已连接的 UI 进程广播事件
    ///  Broadcast event to all connected UI processes
    pub fn broadcast_event(&self, event: &str, data: serde_json::Value) {
        let msg = IpcMessage::event(event, data);
        self.clients.broadcast(&msg);
    }

    /// 处理单个客户端连接
    ///  Handle a single client connection
    fn handle_client(
        pipe_handle: windows::Win32::Foundation::HANDLE,
        ctx: ServiceContext,
        clients: Arc<ClientPool>,
        started_at: u64,
        running: Arc<AtomicBool>,
        runtime_handle: tokio::runtime::Handle,
    ) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Storage::FileSystem::ReadFile;

        // VUL-035 收口：接受连接后、处理任何请求前，校验客户端进程身份。
        // SDDL 只挡非交互式身份；这一步挡住在同一交互式会话里冒充 UI 进程的
        // 恶意程序。校验失败一律 fail-closed：不注册到客户端池、不处理任何请求，
        // 直接关闭管道。
        //  VUL-035 closure: after accepting a connection and before processing any
        //  request, verify the client process identity. The SDDL only excludes
        //  non-interactive identities; this stops a malicious process in the same
        //  interactive session impersonating the UI. Any failed check is fail-closed:
        //  the client is not registered, no request is served, and the pipe is closed.
        match crate::services::identity_verification_service::verify_pipe_client(pipe_handle) {
            Ok(identity) => {
                eprintln!("[IPC] Client identity verified (PID {})", identity.pid);
                // 三进程拆分：GUI 进程（Main / Tray）通过身份校验即自动登记内核进程
                // 保护。Main 由 Tray 按需拉起，不能再依赖服务启动时的单次 launch 注册。
                // 注册失败不阻断通信——进程保护是纵深防御的一层，不是 IPC 的前置条件。
                //  Three-process split: any GUI process (Main / Tray) passing identity
                //  verification is automatically registered for kernel process
                //  protection. Main is spawned by Tray on demand, so we can no longer
                //  rely on the single launch-time registration. Registration failure
                //  never blocks IPC — process protection is one defence-in-depth layer,
                //  not a precondition for communication.
                crate::services::windows_service::register_ui_process_pid(identity.pid);
            }
            Err(err) => {
                eprintln!("[IPC] REJECTED client connection (identity check failed): {}", err);
                unsafe {
                    let _ = CloseHandle(pipe_handle);
                }
                return;
            }
        }

        // 创建管道读写器
        //  Create pipe reader/writer
        let (_reader, writer) = PipeConnection::new(pipe_handle);
        let client = clients.add(Box::new(writer));

        let client_id = client.id;
        eprintln!("[IPC] Client {} handler started", client_id);

        // 为这个客户端连接创建有界请求工作池。
        // 原先这里在唯一的读循环线程上同步执行每个请求；SCAN_BATCH/SCAN_FILE
        // 会把批量/单文件扫描 block_on 在这条线程上，scan 期间该线程既读不了
        // 新请求也答不了旧请求，导致 UI 状态刷新 broken-pipe、开关卡死、
        // CANCEL_SCAN 无法送达。改为读循环只负责读入与分派，长任务只占住
        // 自己的工作线程，GET_STATUS/开关/CANCEL_SCAN 能并发及时处理。
        //  Create a bounded request worker pool for this client connection. Requests
        //  used to run synchronously on the single read-loop thread; SCAN_BATCH /
        //  SCAN_FILE block_on'ed the whole scan there, so while a scan was running
        //  the thread could neither read new requests nor answer old ones — UI status
        //  refresh broke the pipe, toggles froze, and CANCEL_SCAN could not arrive.
        //  Now the read loop only reads and dispatches; a long task occupies only
        //  its own worker while GET_STATUS/toggles/CANCEL_SCAN run concurrently.
        let request_tx = Self::spawn_request_workers(
            client.clone(),
            ctx.clone(),
            started_at,
            runtime_handle.clone(),
        );

        // 读取循环：逐行读取客户端请求（只负责读入与分派，
        // 请求的执行交给上面的工作池并发处理）。
        //  Read loop: read client requests line by line (only reads and dispatches;
        //  execution is handed to the worker pool above).
        let mut line_buf = Vec::new();
        while running.load(Ordering::SeqCst) {
            let mut read_buf = [0u8; 4096];
            let mut bytes_read: u32 = 0;
            let result = unsafe {
                ReadFile(
                    pipe_handle,
                    Some(&mut read_buf),
                    Some(&mut bytes_read as *mut u32),
                    None,
                )
            };

            if result.is_err() || bytes_read == 0 {
                eprintln!("[IPC] Client {} disconnected", client_id);
                break;
            }

            // 将读取的数据追加到行缓冲区，按换行符分割
            //  Append read data to line buffer, split by newline
            line_buf.extend_from_slice(&read_buf[..bytes_read as usize]);

            while let Some(pos) = line_buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = line_buf.drain(..=pos).collect();
                let line_str = match String::from_utf8(line) {
                    Ok(s) => s,
                    Err(_) => {
                        eprintln!("[IPC] Client {} sent invalid UTF-8", client_id);
                        continue;
                    }
                };

                // 解析并处理请求
                //  Parse and handle request
                match IpcMessage::from_line(&line_str) {
                    Ok(IpcMessage::Request { request }) => {
                        // 入队到工作池，读循环立即返回继续读下一条。
                        // 原先在这里内联执行：SCAN_BATCH 在唯一读循环线程上
                        // block_on 整段扫描，期间该线程读不了新请求、答不了旧请求，
                        // 造成 UI 状态刷新 broken-pipe、开关卡死、CANCEL_SCAN 无法送达。
                        //  Enqueue to the worker pool so the read loop immediately returns
                        //  to reading the next request. Requests used to run inline here;
                        //  a SCAN_BATCH block_on'ing the whole scan on the single read-loop
                        //  thread left that thread unable to read or answer anything.
                        let job = PendingRequest {
                            id: request.id,
                            method: request.method,
                            params: request.params,
                        };
                        if let Err(e) = request_tx.send(job) {
                            eprintln!(
                                "[IPC] Failed to enqueue request: {} (channel closed: {})",
                                request.id, e
                            );
                        }
                    }
                    Ok(IpcMessage::Response { .. }) => {
                        // 服务端不接收响应消息，忽略
                        //  Server doesn't receive response messages, ignore
                    }
                    Ok(IpcMessage::Event { .. }) => {
                        // 服务端不接收事件消息，忽略
                        //  Server doesn't receive event messages, ignore
                    }
                    Err(e) => {
                        eprintln!("[IPC] Client {} sent invalid message: {}", client_id, e);
                    }
                }
            }
        }

        // 清理：移除客户端，关闭管道
        //  Cleanup: remove client, close pipe
        clients.remove(client_id);
        unsafe {
            let _ = CloseHandle(pipe_handle);
        }
        eprintln!("[IPC] Client {} handler stopped", client_id);
    }

    /// 为一个客户端连接创建有界请求工作池，返回请求发送端。
    ///  Creates the bounded request worker pool for one client connection.
    ///
    /// 每个 worker 通过工厂拿到自己独立的 handler 副本（各自持有 ctx 的克隆，
    /// 共享内部 Arc 状态），因此多个 worker 能并发执行各自拿到的请求。
    ///  Each worker obtains its own independent handler via the factory (each holds
    ///  a cloned `ctx` sharing the internal `Arc` state), so workers execute the
    ///  jobs they claim concurrently.
    fn spawn_request_workers(
        client: std::sync::Arc<IpcClient>,
        ctx: ServiceContext,
        started_at: u64,
        runtime_handle: tokio::runtime::Handle,
    ) -> std::sync::mpsc::Sender<PendingRequest> {
        spawn_worker_queue("ipc-request-worker", IPC_WORKERS_PER_CLIENT, {
            // 工厂：发起线程调用 worker_count 次，每次返回一个 worker 的 handler。
            //  Factory: called worker_count times on the spawning thread, returning
            //  one worker's handler each time.
            move || {
                let ctx = ctx.clone();
                let runtime_handle = runtime_handle.clone();
                let client = client.clone();
                move |job: PendingRequest| {
                    // 在 worker 线程上执行并写回响应；用 catch_unwind 兜住 panic，
                    // 单个 handler 异常不能饿死整条管道。
                    //  Execute on the worker and write back the response; catch_unwind
                    //  guards so a single panicking handler cannot starve the pipe.
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        Self::execute_request(job, &ctx, started_at, &runtime_handle, &client);
                    }));
                    if outcome.is_err() {
                        eprintln!("[IPC] A request worker panicked (client {})", client.id);
                    }
                }
            }
        })
    }

    /// 在 worker 线程上执行一个 IPC 请求，并把响应写回客户端。
    ///  Execute one queued IPC request on a worker thread and write back the response.
    ///
    /// 响应经线程安全的 `client.writer` 写回，客户端按 request id 匹配，天然支持乱序。
    ///  The response is written through the thread-safe `client.writer`; the client
    ///  matches by request id, so out-of-order responses are natively supported.
    fn execute_request(
        job: PendingRequest,
        ctx: &ServiceContext,
        started_at: u64,
        runtime_handle: &tokio::runtime::Handle,
        client: &std::sync::Arc<IpcClient>,
    ) {
        let response = Self::handle_request(
            &job.id,
            &job.method,
            &job.params,
            ctx,
            started_at,
            runtime_handle,
        );
        let response_line = match response.to_line() {
            Ok(line) => format!("{}\n", line),
            Err(e) => {
                eprintln!("[IPC] Failed to serialize response for {}: {}", job.id, e);
                return;
            }
        };
        if let Ok(mut writer) = client.writer.lock() {
            if let Err(e) = writer.write_all(response_line.as_bytes()) {
                eprintln!("[IPC] Failed to write response to client {}: {}", job.id, e);
            }
            if let Err(e) = writer.flush() {
                eprintln!("[IPC] Failed to flush response for {}: {}", job.id, e);
            }
        }
    }

    /// 处理 IPC 请求，返回响应消息
    ///  Handle IPC request, return response message
    fn handle_request(
        id: &RequestId,
        method: &str,
        params: &serde_json::Value,
        ctx: &ServiceContext,
        started_at: u64,
        runtime_handle: &tokio::runtime::Handle,
    ) -> IpcMessage {
        eprintln!("[IPC] Handling request: method={}, id={}", method, id);

        let result: Result<serde_json::Value, String> = match method {
            methods::PING => Ok(
                serde_json::json!({"pong": true, "timestamp": chrono::Utc::now().timestamp_millis()}),
            ),

            methods::SHUTDOWN_SERVICE => {
                // 优雅停止请求：先向所有客户端广播 service-exiting（Main 等其余 GUI
                // 进程据此自行退出），再置位停止标志并立即应答；真正的 IPC 停止、
                // 组件收尾与 runtime 关闭由持有 ProtectionRuntime 的服务主循环完成。
                //  Graceful stop request: first broadcast "service-exiting" to all clients
                //  (remaining GUI processes such as Main exit themselves), then set the stop
                //  flag and answer immediately; actual IPC teardown, component shutdown and
                //  runtime drop are done by the service main loop owning ProtectionRuntime.
                eprintln!("[IPC] shutdown_service requested");
                if let Some(server) = ctx.get::<IpcServer>() {
                    server.broadcast_event(
                        "service-exiting",
                        serde_json::json!({
                            "requestedAt": chrono::Utc::now().to_rfc3339(),
                        }),
                    );
                } else {
                    eprintln!("[IPC] shutdown_service: IpcServer not registered, cannot broadcast");
                }
                crate::services::windows_service::request_service_shutdown();
                Ok(serde_json::json!({"accepted": true}))
            }

            methods::GET_STATUS => {
                // 必须上报真实运行态而不是"是否注册过"。
                // 原实现用 .is_some()，而 build_service_context 无条件注册 EtwService，
                // 该字段因此恒为 true——即使 ETW 因权限或会话失败根本没跑起来。
                //  Must report the real runtime state, not "was it registered". The previous
                //  .is_some() was always true because build_service_context registers EtwService
                //  unconditionally, even when ETW never actually started.
                let (etw_running, etw_collecting) = ctx
                    .get::<std::sync::Mutex<crate::services::etw_service::EtwService>>()
                    .and_then(|state| {
                        state
                            .lock()
                            .ok()
                            .map(|etw| (etw.is_running(), etw.is_collecting()))
                    })
                    .unwrap_or((false, false));
                let status = ProtectionStatus {
                    etw_running,
                    etw_collecting,
                    file_hook_running: ctx
                        .get::<crate::services::hook_service::HookService>()
                        .map(|h| h.is_running())
                        .unwrap_or(false),
                    file_monitor_running: ctx
                        .get::<crate::services::file_monitor_service::FileMonitorService>()
                        .map(|m| m.is_running())
                        .unwrap_or(false),
                    process_monitor_running: ctx
                        .get::<crate::services::process_monitor_service::ProcessMonitorService>()
                        .map(|m| m.is_running())
                        .unwrap_or(false),
                    interception_queue_len: ctx
                        .get::<crate::services::interception_service::InterceptionService>()
                        .map(|s| s.get_paused_pids().len())
                        .unwrap_or(0),
                    engine_online: ctx
                        .get::<std::sync::Arc<crate::services::engine_service::EngineService>>()
                        .map(|e| e.is_loaded())
                        .unwrap_or(false),
                    started_at,
                };
                serde_json::to_value(status).map_err(|e| e.to_string())
            }

            methods::GET_INTERCEPTION_QUEUE => {
                let interception =
                    match ctx.get::<crate::services::interception_service::InterceptionService>() {
                        Some(s) => s,
                        None => {
                            return IpcMessage::response(
                                *id,
                                Err("InterceptionService not available".to_string()),
                            )
                        }
                    };
                // 原实现把 pid 之外的字段全部填空串，UI 拿到的队列除了 PID 之外
                // 什么都看不出来——既不知道是哪个程序，也不知道为什么被拦。
                // 这里改为从 InterceptionService 取回真实条目。
                //  The previous implementation blank-stubbed every field except pid, so
                //  the UI could see neither which program was held nor why. Real entries
                //  are pulled from InterceptionService now.
                let items: Vec<InterceptionQueueItem> = interception
                    .get_paused_pids()
                    .iter()
                    .map(|&pid| match interception.entry_for_pid(pid) {
                        Some(entry) => InterceptionQueueItem {
                            pid: entry.pid,
                            process_name: entry.process_name,
                            file_path: entry.file_path,
                            risk_level: entry.risk_level,
                            threat_type: entry.threat_type,
                            reason: entry.reason,
                            timestamp: entry.timestamp,
                        },
                        // 条目刚好在两次调用之间被裁决掉时保留 PID，
                        // 让调用方至少知道这个 PID 曾经在队列里
                        //  If the entry was decided between the two calls, keep the PID so
                        //  the caller still knows it was queued
                        None => InterceptionQueueItem {
                            pid,
                            process_name: String::new(),
                            file_path: String::new(),
                            risk_level: String::new(),
                            threat_type: None,
                            reason: String::new(),
                            timestamp: 0,
                        },
                    })
                    .collect();
                serde_json::to_value(items).map_err(|e| e.to_string())
            }

            methods::SET_BEHAVIOR_MONITORING => {
                let enabled = match params.get("enabled").and_then(|v| v.as_bool()) {
                    Some(value) => value,
                    None => {
                        return IpcMessage::response(
                            *id,
                            Err("Invalid params: expected { \"enabled\": bool }".to_string()),
                        )
                    }
                };
                let etw =
                    match ctx.get::<std::sync::Mutex<crate::services::etw_service::EtwService>>() {
                        Some(state) => state,
                        None => {
                            return IpcMessage::response(
                                *id,
                                Err("EtwService not available".to_string()),
                            )
                        }
                    };
                let etw = match etw.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let outcome = if enabled {
                    etw.resume(ctx.clone())
                } else {
                    etw.pause()
                };
                match outcome {
                    Ok(()) => {
                        eprintln!("[IPC] Behavior monitoring set to {} by UI process", enabled);
                        Ok(serde_json::json!({
                            "ok": true,
                            "enabled": enabled,
                            "running": etw.is_running(),
                            "collecting": etw.is_collecting(),
                        }))
                    }
                    Err(err) => Err(format!("Failed to toggle behavior monitoring: {}", err)),
                }
            }

            methods::SET_FILE_MONITORING => {
                let enabled = match params.get("enabled").and_then(|v| v.as_bool()) {
                    Some(value) => value,
                    None => {
                        return IpcMessage::response(
                            *id,
                            Err("Invalid params: expected { \"enabled\": bool }".to_string()),
                        )
                    }
                };
                let (file_monitor, engine, cache, interception) = match (
                    ctx.get::<crate::services::file_monitor_service::FileMonitorService>(),
                    ctx.get::<crate::services::engine_service::EngineService>(),
                    ctx.get::<crate::services::scan_result_cache_service::ScanResultCacheService>(),
                    ctx.get::<crate::services::interception_service::InterceptionService>(),
                ) {
                    (Some(fm), Some(eng), Some(cache), Some(ic)) => (fm, eng, cache, ic),
                    _ => {
                        return IpcMessage::response(
                            *id,
                            Err("File monitor dependencies not available".to_string()),
                        )
                    }
                };
                if enabled {
                    // 订阅 ETW 文件事件广播（依赖与启动路径一致）
                    //  Subscribe to the ETW file-event broadcast (same dependencies as startup path)
                    let etw_rx = match ctx
                        .get::<std::sync::Mutex<crate::services::etw_service::EtwService>>()
                    {
                        Some(etw_state) => match etw_state.lock() {
                            Ok(guard) => guard.subscribe(),
                            Err(poisoned) => poisoned.into_inner().subscribe(),
                        },
                        None => {
                            return IpcMessage::response(
                                *id,
                                Err("EtwService not available".to_string()),
                            )
                        }
                    };
                    file_monitor.start(engine, cache, interception, ctx.clone(), etw_rx);
                    eprintln!("[IPC] File monitoring enabled by UI process");
                } else {
                    file_monitor.stop();
                    eprintln!("[IPC] File monitoring disabled by UI process");
                }
                Ok(serde_json::json!({
                    "ok": true,
                    "enabled": enabled,
                    "running": file_monitor.is_running(),
                }))
            }

            methods::SET_PROCESS_MONITORING => {
                let enabled = match params.get("enabled").and_then(|v| v.as_bool()) {
                    Some(value) => value,
                    None => {
                        return IpcMessage::response(
                            *id,
                            Err("Invalid params: expected { \"enabled\": bool }".to_string()),
                        )
                    }
                };
                // 服务进程只能启动 APIHook watcher；ProcessScannerService 的 start()
                // 需要 Tauri AppHandle 弹出拦截窗口，服务模式不运行（架构限制）。
                //  The service process can only start the APIHook watcher; ProcessScannerService::start
                //  needs a Tauri AppHandle to show the interception modal, so it does not run in
                //  service mode (architecture limitation).
                let watcher = match ctx
                    .get::<crate::services::process_monitor_service::ProcessMonitorService>()
                {
                    Some(w) => w,
                    None => {
                        return IpcMessage::response(
                            *id,
                            Err("ProcessMonitorService not available".to_string()),
                        )
                    }
                };
                if enabled {
                    match watcher.start_with_resource_dir("", "", "", "", 2000, None) {
                        Ok(_) => {
                            eprintln!("[IPC] Process monitoring (APIHook) enabled by UI process")
                        }
                        Err(err) => {
                            return IpcMessage::response(
                                *id,
                                Err(format!("Failed to start process monitor: {}", err)),
                            )
                        }
                    }
                } else {
                    match watcher.stop() {
                        Ok(()) => {
                            eprintln!("[IPC] Process monitoring (APIHook) disabled by UI process")
                        }
                        Err(err) => {
                            return IpcMessage::response(
                                *id,
                                Err(format!("Failed to stop process monitor: {}", err)),
                            )
                        }
                    }
                }
                Ok(serde_json::json!({
                    "ok": true,
                    "enabled": enabled,
                    "running": watcher.is_running(),
                    // 新进程扫描在服务模式下不运行，如实上报给 UI 侧展示
                    "scannerInServiceMode": false,
                }))
            }

            methods::HANDLE_INTERCEPTION => {
                use crate::services::interception_service::InterceptionDecision;
                use crate::services::process_control_service::{
                    resume_process_by_pid, terminate_process_by_pid,
                };

                let interception =
                    match ctx.get::<crate::services::interception_service::InterceptionService>() {
                        Some(s) => s,
                        None => {
                            return IpcMessage::response(
                                *id,
                                Err("InterceptionService not available".to_string()),
                            )
                        }
                    };

                // InterceptionDecisionParams 的 decision 字段带 `alias = "action"`，
                // 因此 UI 实际发出的 {"pid":..,"action":".."} 现在能正确反序列化。
                //  The decision field of InterceptionDecisionParams carries
                //  `alias = "action"`, so the {"pid":..,"action":".."} the UI actually
                //  sends now deserializes correctly.
                let decision_params: InterceptionDecisionParams =
                    match serde_json::from_value(params.clone()) {
                        Ok(p) => p,
                        Err(e) => {
                            return IpcMessage::response(*id, Err(format!("Invalid params: {}", e)))
                        }
                    };

                let pid = decision_params.pid;

                let decision = match decision_params.decision.to_ascii_lowercase().as_str() {
                    "allow" => InterceptionDecision::Allow,
                    "block" => InterceptionDecision::Block,
                    other => {
                        return IpcMessage::response(
                            *id,
                            Err(format!("Unknown decision: {}", other)),
                        )
                    }
                };

                let Some(entry) = interception.entry_for_pid(pid) else {
                    return IpcMessage::response(
                        *id,
                        Err(format!("No pending interception found for PID {}", pid)),
                    );
                };

                // 这里必须真正恢复或终止进程。原实现只调 mark_decision_with_window，
                // 而它只做记账（清 showing、出队、删恢复台账）。后果是：
                // Allow 之后进程永远挂着，而且恢复台账已被删掉，重启也救不回来；
                // Block 之后恶意进程只是被挂起，仍然活着。
                //  The process must actually be resumed or terminated here. The previous
                //  implementation only called mark_decision_with_window, which merely
                //  bookkeeps (clears showing, dequeues, drops the recovery ledger entry).
                //  The consequences: after Allow the process stayed suspended forever with
                //  its ledger entry already deleted, so even a restart could not recover
                //  it; after Block the malicious process was merely suspended, still alive.
                //  流程与 commands/interception.rs 的独立模式分支保持一致。
                //  The flow mirrors the standalone branch in commands/interception.rs.
                match decision {
                    InterceptionDecision::Allow => {
                        interception.mark_allowed_temporarily(&entry);
                        if let Err(err) = resume_process_by_pid(pid) {
                            // 恢复失败要撤掉临时放行，否则这个路径会被静默加进白名单
                            //  Roll back the temporary allow, otherwise a failed resume
                            //  would silently whitelist the path anyway
                            interception.remove_temporary_allow(&entry);
                            return IpcMessage::response(*id, Err(err));
                        }
                        interception.mark_decision_with_window(pid, decision, ctx);
                        interception.complete_allow(pid);
                    }
                    InterceptionDecision::Block => {
                        if let Err(err) = terminate_process_by_pid(pid) {
                            return IpcMessage::response(*id, Err(err));
                        }
                        interception.mark_decision_with_window(pid, decision, ctx);
                    }
                }

                // 轮播下一条，否则队列里后面的拦截永远不会弹出来
                //  Rotate to the next entry, otherwise later interceptions never appear
                interception.try_show_next(ctx);

                Ok(serde_json::json!({"ok": true}))
            }

            methods::CLEAR_INTERCEPTION_QUEUE => {
                let interception =
                    match ctx.get::<crate::services::interception_service::InterceptionService>() {
                        Some(s) => s,
                        None => {
                            return IpcMessage::response(
                                *id,
                                Err("InterceptionService not available".to_string()),
                            )
                        }
                    };
                interception.clear_all();
                Ok(serde_json::json!({"ok": true}))
            }

            methods::GET_INTERCEPTION_STATUS => {
                let interception =
                    match ctx.get::<crate::services::interception_service::InterceptionService>() {
                        Some(s) => s,
                        None => {
                            return IpcMessage::response(
                                *id,
                                Err("InterceptionService not available".to_string()),
                            )
                        }
                    };
                let pids = interception.get_paused_pids();
                Ok(serde_json::json!({
                    "queue_length": pids.len(),
                    "paused_pids": pids,
                }))
            }

            methods::PEEK_CURRENT_INTERCEPTION => {
                let interception =
                    match ctx.get::<crate::services::interception_service::InterceptionService>() {
                        Some(s) => s,
                        None => {
                            return IpcMessage::response(
                                *id,
                                Err("InterceptionService not available".to_string()),
                            )
                        }
                    };
                match interception.peek_current() {
                    Some(entry) => serde_json::to_value(entry).map_err(|e| e.to_string()),
                    None => Ok(serde_json::Value::Null),
                }
            }

            // ===== 扫描引擎相关方法 / Scan engine methods =====
            // 这些方法在服务进程中执行，使用本地 EngineService，通过 IPC 返回结果给 UI 进程
            //  These methods execute in the service process using the local EngineService,
            //  returning results to the UI process via IPC
            methods::START_ENGINE => {
                let engine = match ctx
                    .get::<std::sync::Arc<crate::services::engine_service::EngineService>>()
                {
                    Some(s) => s,
                    None => {
                        return IpcMessage::response(
                            *id,
                            Err("EngineService not available".to_string()),
                        )
                    }
                };
                runtime_handle
                    .block_on(async move { engine.start_engine().await })
                    .map(|ok| serde_json::json!({"ok": ok}))
            }

            methods::STOP_ENGINE => {
                let engine = match ctx
                    .get::<std::sync::Arc<crate::services::engine_service::EngineService>>()
                {
                    Some(s) => s,
                    None => {
                        return IpcMessage::response(
                            *id,
                            Err("EngineService not available".to_string()),
                        )
                    }
                };
                runtime_handle
                    .block_on(async move { engine.stop_engine().await })
                    .map(|ok| serde_json::json!({"ok": ok}))
            }

            methods::SCANNER_HEALTH => {
                let engine = match ctx
                    .get::<std::sync::Arc<crate::services::engine_service::EngineService>>()
                {
                    Some(s) => s,
                    None => {
                        return IpcMessage::response(
                            *id,
                            Err("EngineService not available".to_string()),
                        )
                    }
                };
                runtime_handle.block_on(async move { engine.health_check().await })
            }

            methods::SCAN_FILE => {
                let file_path = match params.get("filePath").and_then(|v| v.as_str()) {
                    Some(p) => p.to_string(),
                    None => {
                        return IpcMessage::response(
                            *id,
                            Err("Missing filePath parameter".to_string()),
                        )
                    }
                };
                let options = params
                    .get("options")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let engine = match ctx
                    .get::<std::sync::Arc<crate::services::engine_service::EngineService>>()
                {
                    Some(s) => s,
                    None => {
                        return IpcMessage::response(
                            *id,
                            Err("EngineService not available".to_string()),
                        )
                    }
                };
                runtime_handle.block_on(async move {
                    engine.reset_cancel_flag();
                    // 路径策略检查在服务进程本地执行（基于 APPDATA 运行时文件）
                    //  Path policy check executes locally in service process (based on APPDATA runtime files)
                    if crate::services::path_policy_service::should_skip_security_scan(&file_path)?
                    {
                        return Ok(serde_json::json!({
                            "fileId": file_path,
                            "verdict": "clean",
                            "threatType": "",
                            "severity": 0,
                            "description": "Skipped by exclusions or allowlist",
                        }));
                    }
                    engine.scan_file(&file_path, options).await
                })
            }

            methods::SCAN_BATCH => {
                let file_paths: Vec<String> =
                    match params.get("filePaths").and_then(|v| v.as_array()) {
                        Some(arr) => arr
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect(),
                        None => {
                            return IpcMessage::response(
                                *id,
                                Err("Missing or invalid filePaths parameter".to_string()),
                            )
                        }
                    };
                let options = params
                    .get("options")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let engine = match ctx
                    .get::<std::sync::Arc<crate::services::engine_service::EngineService>>()
                {
                    Some(s) => s,
                    None => {
                        return IpcMessage::response(
                            *id,
                            Err("EngineService not available".to_string()),
                        )
                    }
                };
                runtime_handle.block_on(async move {
                    engine.reset_cancel_flag();
                    let mut results: Vec<serde_json::Value> = Vec::new();
                    for file_path in &file_paths {
                        // 检查取消标志
                        //  Check cancel flag
                        if engine.is_cancelled() {
                            return Ok(serde_json::json!({
                                "results": results,
                                "totalFiles": file_paths.len(),
                                "threatsFound": results.iter().filter(|r| r.get("verdict").and_then(|v| v.as_str()) == Some("malware")).count(),
                                "scannedFiles": results.len(),
                                "cancelled": true,
                            }));
                        }
                        // 路径策略检查
                        //  Path policy check
                        if crate::services::path_policy_service::should_skip_security_scan(file_path)? {
                            results.push(serde_json::json!({
                                "fileId": file_path,
                                "verdict": "clean",
                                "threatType": "",
                                "severity": 0,
                                "description": "Skipped by exclusions or allowlist",
                            }));
                        } else {
                            results.push(engine.scan_file(file_path, options.clone()).await?);
                        }
                    }
                    let threats_found = results
                        .iter()
                        .filter(|result| result.get("verdict").and_then(|value| value.as_str()) == Some("malware"))
                        .count();
                    Ok(serde_json::json!({
                        "results": results,
                        "totalFiles": file_paths.len(),
                        "threatsFound": threats_found,
                    }))
                })
            }

            methods::CANCEL_SCAN => {
                let engine = match ctx
                    .get::<std::sync::Arc<crate::services::engine_service::EngineService>>()
                {
                    Some(s) => s,
                    None => {
                        return IpcMessage::response(
                            *id,
                            Err("EngineService not available".to_string()),
                        )
                    }
                };
                runtime_handle
                    .block_on(async move { engine.cancel_scan().await })
                    .map(|ok| serde_json::json!({"ok": ok}))
            }

            // ------------------------------------------------------------
            // 网络防火墙 / Network firewall
            //
            // 驱动句柄只存在于服务进程，这些分支是 UI 唯一的操作入口。
            // FirewallService 未注册（驱动缺失或模块关闭）时统一返回错误，
            // 由 UI 侧降级展示，绝不静默返回成功。
            //  The driver handle lives only in the service process; these
            //  branches are the UI's sole entry point. When FirewallService is
            //  not registered (driver missing or module off) they return an
            //  error for the UI to degrade on — never a silent success.
            // ------------------------------------------------------------
            methods::GET_FIREWALL_STATUS
            | methods::HANDLE_NETWORK_DECISION
            | methods::GET_NETWORK_PENDING
            | methods::GET_NETWORK_EVENTS
            | methods::GET_NETWORK_STATS
            | methods::RELOAD_FIREWALL_RULES
            | methods::SET_FIREWALL_ENABLED
            | methods::SET_FIREWALL_MODE
            | methods::FLUSH_FIREWALL_CACHE => Self::handle_firewall_request(method, params, ctx),

            _ => Err(format!("Unknown method: {}", method)),
        };

        IpcMessage::response(*id, result)
    }

    /// 函数名称：handle_firewall_request
    /// 函数作用：处理全部网络防火墙相关的 IPC 方法。
    /// Purpose: Handles every network-firewall IPC method.
    ///
    /// 单独抽出来的原因：这些方法共用同一个前置条件（FirewallService 必须已注册），
    /// 与其在九个分支里各写一遍取服务和报错，不如集中一次。
    ///  Extracted because all of these share one precondition (FirewallService
    ///  must be registered); resolving the service and reporting its absence once
    ///  beats repeating it across nine branches.
    ///
    /// 调用方：handle_request 的防火墙分支
    /// Called by: the firewall arm of handle_request
    /// 返回值：成功为 JSON 结果；服务未注册或参数非法时返回 Err
    /// Returns: a JSON result, or Err when the service is missing or params are invalid
    /// 中文关键词：防火墙 IPC，参数校验，服务缺失
    /// English keywords: firewall IPC, parameter validation, missing service
    fn handle_firewall_request(
        method: &str,
        params: &serde_json::Value,
        ctx: &ServiceContext,
    ) -> Result<serde_json::Value, String> {
        use crate::services::firewall_service::{FirewallService, VerdictOutcome};

        let firewall = ctx.get::<FirewallService>().ok_or_else(|| {
            "FirewallService is not available (driver missing or module disabled)".to_string()
        })?;

        match method {
            methods::GET_FIREWALL_STATUS => serde_json::to_value(firewall.status())
                .map_err(|e| format!("failed to serialize firewall status: {}", e)),

            methods::GET_NETWORK_PENDING => serde_json::to_value(firewall.pending_connections())
                .map_err(|e| format!("failed to serialize the pending queue: {}", e)),

            methods::GET_NETWORK_EVENTS => {
                // 缺省 200 条：够界面首屏铺满，又不会让单次 IPC 消息过大。
                //  Default 200: enough to fill the first screen without making a
                //  single IPC message oversized.
                let limit = params
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(200)
                    .min(500) as usize;

                serde_json::to_value(firewall.recent_events(limit))
                    .map_err(|e| format!("failed to serialize network events: {}", e))
            }

            methods::GET_NETWORK_STATS => firewall.traffic_stats(),

            methods::RELOAD_FIREWALL_RULES => firewall
                .apply_rules()
                .map(|warnings| serde_json::json!({ "ok": true, "warnings": warnings })),

            methods::FLUSH_FIREWALL_CACHE => firewall
                .flush_cache()
                .map(|_| serde_json::json!({ "ok": true })),

            methods::HANDLE_NETWORK_DECISION => {
                let decision_id = params
                    .get("decisionId")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| "missing or invalid 'decisionId'".to_string())?;

                // 同时接受 action 与 decision 两个键名。项目里已经出现过一次
                // UI 发 "action"、服务端只认 "decision" 导致裁决全部静默失败的问题
                // （见 interception 链路），这里刻意两边都收。
                //  Both 'action' and 'decision' are accepted. This codebase has
                //  already been bitten once by the UI sending "action" while the
                //  server only read "decision", silently dropping every verdict
                //  (see the interception path), so both are honoured here.
                let action = params
                    .get("action")
                    .or_else(|| params.get("decision"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "missing or invalid 'action'".to_string())?;

                let allow = match action.to_ascii_lowercase().as_str() {
                    "allow" => true,
                    "block" => false,
                    other => return Err(format!("unknown action '{}'", other)),
                };

                let remember = params
                    .get("remember")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let remember_process = params
                    .get("rememberProcess")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let outcome = firewall.decide(decision_id, allow, remember, remember_process)?;

                Ok(serde_json::json!({
                    "ok": true,
                    "alreadyResolved": outcome == VerdictOutcome::AlreadyResolved,
                }))
            }

            methods::SET_FIREWALL_ENABLED => {
                let enabled = params
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .ok_or_else(|| "missing or invalid 'enabled'".to_string())?;

                let mut config = crate::models::config::AppConfig::load()
                    .map_err(|e| format!("failed to load app config: {}", e))?;
                config.network_firewall.enabled = enabled;

                // VUL-040 事务顺序：开启时必须先让驱动实际接受配置，成功后才落盘。
                // 先落盘会让「配置声称开启、驱动实际没拦」——用户以为受保护，实则裸奔。
                // 关闭总是安全：驱动不可用（未连接）时本就全放行，落盘 false 只是如实
                // 记录用户意图；若驱动在线则先下发放行再落盘。
                //  VUL-040 transaction order: enabling must be accepted by the driver
                //  before it is persisted. Persisting first leaves the config claiming
                //  the firewall is on while the driver blocks nothing — the user thinks
                //  they are protected when they are not. Disabling is always safe: with
                //  the driver unavailable (not connected) traffic is already permitted,
                //  so persisting false merely records the intent; if the driver is up,
                //  push the permit-first config, then persist.
                //
                // 服务模式下 `start_firewall`/`stop_firewall` 命令在 UI 侧直接返回成功
                // （防火墙生命周期归服务进程管），因此「开启」的完整启动必须在这里发生：
                // 若服务启动时因驱动缺失而降级、用户随后装好驱动，经 UI 开启开关时要
                // 真正连接驱动、下发规则、启动事件泵，失败则 fail-closed 不落盘。
                //  In service mode the UI-side start_firewall/stop_firewall commands
                //  return success directly (the service owns the firewall lifecycle),
                //  so the full "enable" startup must happen here: when the service
                //  degraded at startup because the driver was missing and the user then
                //  installs the driver, toggling on over the UI must really connect the
                //  driver, push rules and start the pump — and a failure is fail-closed
                //  (not persisted).
                if enabled && !firewall.is_running() {
                    firewall.start(ctx.clone(), &config.network_firewall)?;
                } else if enabled {
                    firewall.apply_config(&config.network_firewall)?;
                } else if firewall.is_driver_connected() {
                    firewall.apply_config(&config.network_firewall)?;
                }
                config
                    .save()
                    .map_err(|e| format!("failed to persist app config: {}", e))?;

                Ok(serde_json::json!({ "ok": true, "enabled": enabled }))
            }

            methods::SET_FIREWALL_MODE => {
                let mode = params
                    .get("mode")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "missing or invalid 'mode'".to_string())?
                    .to_ascii_lowercase();

                if !matches!(mode.as_str(), "silent" | "prompt" | "learn") {
                    return Err(format!("unknown firewall mode '{}'", mode));
                }

                let applied = mode.clone();
                Self::update_firewall_config(&firewall, move |config| {
                    config.mode = mode.clone();
                })?;

                Ok(serde_json::json!({ "ok": true, "mode": applied }))
            }

            _ => Err(format!("Unhandled firewall method: {}", method)),
        }
    }

    /// 函数名称：update_firewall_config
    /// 函数作用：读取 app.json、按闭包修改防火墙段、持久化并立即下发给驱动。
    /// Purpose: Loads app.json, mutates the firewall section, persists it and
    ///          pushes it to the driver immediately.
    ///
    /// 先持久化再下发。反过来的话，下发成功但写盘失败会让重启后的行为与用户
    /// 刚刚看到的不一致 —— 对防火墙来说这意味着用户以为开着、实际却没开。
    ///  Persist first, push second. The other order means a successful push with
    ///  a failed write leaves post-restart behaviour disagreeing with what the
    ///  user just saw — for a firewall that means believing it is on when it is not.
    ///
    /// 调用方：handle_firewall_request 的开关与模式分支
    /// Called by: the toggle and mode arms of handle_firewall_request
    /// 副作用：写 config/app.json，并向驱动下发新配置
    /// Side effects: writes config/app.json and pushes the new config to the driver
    /// 中文关键词：配置持久化，先落盘再生效，防火墙开关
    /// English keywords: config persistence, persist-then-apply, firewall toggle
    fn update_firewall_config<F>(
        firewall: &std::sync::Arc<crate::services::firewall_service::FirewallService>,
        mutate: F,
    ) -> Result<(), String>
    where
        F: FnOnce(&mut crate::models::config::NetworkFirewallConfig),
    {
        let mut config = crate::models::config::AppConfig::load()
            .map_err(|e| format!("failed to load app config: {}", e))?;

        mutate(&mut config.network_firewall);

        config
            .save()
            .map_err(|e| format!("failed to persist app config: {}", e))?;

        firewall.apply_config(&config.network_firewall)
    }
}

// ============================================================================
// PipeConnection — 封装命名管道的读写
//  PipeConnection - wraps named pipe read/write
// ============================================================================

/// 命名管道连接的读端和写端
///  Read and write sides of a named pipe connection
struct PipeReader {
    handle: windows::Win32::Foundation::HANDLE,
}

// HANDLE 包含 *mut c_void 不是 Send，但管道句柄在 Windows 上可以安全跨线程使用
//  HANDLE contains *mut c_void which is not Send, but pipe handles are safe to use across threads on Windows
unsafe impl Send for PipeReader {}

impl std::io::Read for PipeReader {
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

/// 命名管道连接的写端
///  Write side of a named pipe connection
struct PipeWriter {
    handle: windows::Win32::Foundation::HANDLE,
}

// HANDLE 包含 *mut c_void 不是 Send，但管道句柄在 Windows 上可以安全跨线程使用
//  HANDLE contains *mut c_void which is not Send, but pipe handles are safe to use across threads on Windows
unsafe impl Send for PipeWriter {}

impl std::io::Write for PipeWriter {
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

/// 命名管道连接
///  Named pipe connection
struct PipeConnection;

impl PipeConnection {
    /// 从管道句柄创建读端和写端
    ///  Create reader and writer from pipe handle
    fn new(handle: windows::Win32::Foundation::HANDLE) -> (PipeReader, PipeWriter) {
        (PipeReader { handle }, PipeWriter { handle })
    }
}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::spawn_worker_queue;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    /// 验证工作池的核心保证：一个长任务占住某个 worker 时，
    /// 新请求仍能被空闲 worker 并发执行（这是修复 broken-pipe/卡死的关键）。
    ///  Verifies the pool's core guarantee: while a long task occupies one worker,
    ///  a new request is still executed concurrently by a free worker — the key to
    ///  not breaking the pipe / freezing the UI during a scan.
    #[test]
    fn worker_queue_runs_long_and_short_jobs_concurrently() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        // 长任务已真正进入执行（正在 sleep）的信号，确保短任务在长任务进行中被派发
        let (long_started_tx, long_started_rx) = mpsc::channel::<()>();

        // 工厂需 move 一套 Arc 进闭包；原句柄在此保留，供断言使用
        let active_job = active.clone();
        let peak_job = peak.clone();
        let completed_job = completed.clone();
        let long_started_tx_job = long_started_tx.clone();
        let tx = spawn_worker_queue("test", 2, move || {
            let active = active_job.clone();
            let peak = peak_job.clone();
            let completed = completed_job.clone();
            let long_started_tx = long_started_tx_job.clone();
            move |job: u32| {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                if job == 0 {
                    let _ = long_started_tx.send(());
                    std::thread::sleep(Duration::from_millis(120));
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
                active.fetch_sub(1, Ordering::SeqCst);
                completed.fetch_add(1, Ordering::SeqCst);
            }
        });

        tx.send(0).unwrap();
        long_started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("long job should have started");
        // 长任务占住一个 worker 时派发短任务，应由空闲 worker 并发执行
        tx.send(1).unwrap();
        drop(tx);

        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(
            completed.load(Ordering::SeqCst),
            2,
            "both jobs must finish"
        );
        assert!(
            peak.load(Ordering::SeqCst) >= 2,
            "short job must run while long job is in progress"
        );
    }
}
