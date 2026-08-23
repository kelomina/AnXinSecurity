// IPC 桥接服务 — 运行在 UI 进程中，桥接服务进程与 Tauri 前端
//  IPC bridge service - runs in UI process, bridges service process and Tauri frontend
//
// 职责：
//  Responsibilities:
// - 启动时尝试连接服务进程的 IPC 管道
// - 订阅服务进程推送的事件，转发为 Tauri 事件（前端通过 listen 接收）
// - 提供请求转发能力，让 Tauri commands 通过 IPC 调用服务进程
// - 后台监控连接状态，断开时自动重连
//
// 设计原则：
//  Design principles:
// - 前端代码零改动：仍使用 listen('etw-event', ...) 等 Tauri 事件监听
// - 向后兼容：服务进程未运行时，UI 进程自己启动防护组件（由 main.rs 决定）
// - 自动重连：UI 崩溃重启或服务重启后，自动重新建立连接
//
// 中文关键词：IPC 桥接，事件转发，自动重连，前后端分离
// English keywords: IPC bridge, event forwarding, auto reconnect, frontend-backend separation
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tauri::{AppHandle, Emitter, Runtime};

use crate::services::ipc_client::IpcClient;
use crate::services::ipc_protocol::methods as ipc_methods;

/// 需要从服务进程转发到 Tauri 前端的事件名列表
///  List of event names to forward from service process to Tauri frontend
///
/// 这些事件名与前端 `listen()` 调用的事件名一致
///  These event names match the event names used by frontend `listen()` calls
const FORWARDED_EVENTS: &[&str] = &[
    "etw-event",
    "file-hook-event",
    "process-intercepted",
    "log-event",
    "behavior-event",
    // 见 windows_service::FORWARDABLE_EVENTS 的说明：真正发出的事件名是 "etw-risk-event"。
    //  See the note on windows_service::FORWARDABLE_EVENTS: the real event is "etw-risk-event".
    "etw-risk-event",
    "interception-decision",
    "file-monitor-event",
    "snapshot-progress",
    "snapshot-result",
    "scan-progress",
    "quarantine-updated",
    "remote-session-changed",
    "tray-exit-requested",
    "memory-mode-changed",
    // 网络防火墙 / network firewall
    "network-event",
    "network-intercepted",
    // 进程监控采集 / process monitor collector
    "process-lifecycle-event",
    "process-monitor-tampered",
    // 服务生命周期广播 / service lifecycle broadcast
    "service-exiting",
];

/// 重连间隔（毫秒）
///  Reconnect interval in milliseconds
const RECONNECT_INTERVAL_MS: u64 = 3000;

/// IPC 请求默认超时（毫秒）
///  Default IPC request timeout in milliseconds
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 5000;

/// IPC 桥接服务 — 封装 IpcClient，提供事件转发和自动重连
///  IPC bridge service - wraps IpcClient, provides event forwarding and auto reconnect
pub struct IpcBridgeService {
    /// 内部 IPC 客户端
    ///  Internal IPC client
    client: Arc<IpcClient>,
    /// 是否已启动（防止重复启动）
    ///  Whether started (prevent duplicate start)
    started: Arc<AtomicBool>,
    /// 是否已连接到服务进程
    ///  Whether connected to service process
    /// 此字段与 client.is_connected() 保持同步，供外部快速查询
    ///  This field stays in sync with client.is_connected() for fast external queries
    connected: Arc<AtomicBool>,
    /// 重连线程句柄
    ///  Reconnect thread handle
    reconnect_thread: Mutex<Option<thread::JoinHandle<()>>>,
}

impl IpcBridgeService {
    /// 创建新的 IPC 桥接服务
    ///  Create new IPC bridge service
    pub fn new() -> Self {
        Self {
            client: Arc::new(IpcClient::new()),
            started: Arc::new(AtomicBool::new(false)),
            connected: Arc::new(AtomicBool::new(false)),
            reconnect_thread: Mutex::new(None),
        }
    }

    /// 启动桥接服务 — 尝试连接服务进程，注册事件转发，启动重连监控
    ///  Start bridge service - try to connect to service process, register event forwarding, start reconnect monitor
    ///
    /// 返回 true 表示连接成功（服务进程已运行），false 表示服务进程未运行
    ///  Returns true if connected (service process running), false if service process not running
    pub fn start<R: Runtime>(&self, app_handle: &AppHandle<R>) -> Result<bool, String> {
        if self.started.swap(true, Ordering::SeqCst) {
            // 已经启动过，直接返回当前连接状态
            //  Already started, return current connection status
            return Ok(self.connected.load(Ordering::SeqCst));
        }

        // 注册事件转发 — 将服务进程推送的事件转发为 Tauri 事件
        //  Register event forwarding - forward service process events to Tauri events
        self.register_event_forwarding(app_handle);

        // 尝试首次连接
        //  Try first connection
        let connected = self.client.connect()?;
        self.connected.store(connected, Ordering::SeqCst);

        if connected {
            eprintln!(
                "[IPC Bridge] Connected to service process, events will be forwarded to frontend"
            );
        } else {
            eprintln!("[IPC Bridge] Service process not running, UI will run in standalone mode");
        }

        // 启动重连监控线程
        //  Start reconnect monitor thread
        self.start_reconnect_monitor(app_handle.clone());

        Ok(connected)
    }

    /// 检查是否已连接到服务进程
    ///  Check if connected to service process
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// 通过 IPC 发送请求到服务进程
    ///  Send request to service process via IPC
    ///
    /// 如果未连接，返回 Err；调用方可根据此结果决定是否回退到本地逻辑
    ///  Returns Err if not connected; caller can decide whether to fall back to local logic
    pub fn request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        if !self.is_connected() {
            return Err("IPC bridge not connected to service process".to_string());
        }
        self.client
            .request(method, params, DEFAULT_REQUEST_TIMEOUT_MS)
    }

    /// 注册事件转发 — 将服务进程推送的事件转发为 Tauri 事件
    ///  Register event forwarding - forward service process events to Tauri events
    ///
    /// 前端通过 `listen('etw-event', ...)` 等方式接收，无需修改前端代码
    ///  Frontend receives via `listen('etw-event', ...)` etc., no frontend changes needed
    fn register_event_forwarding<R: Runtime>(&self, app_handle: &AppHandle<R>) {
        for event_name in FORWARDED_EVENTS {
            let app_handle_clone = app_handle.clone();
            let event_name_owned = event_name.to_string();
            let connected_clone = self.connected.clone();

            self.client.on_event(event_name, move |data| {
                // 只有在连接状态下才转发（避免重连过程中的旧事件）
                //  Only forward when connected (avoid stale events during reconnect)
                if !connected_clone.load(Ordering::SeqCst) {
                    return;
                }

                // 将事件转发到 Tauri 前端
                //  Forward event to Tauri frontend
                // process-intercepted 事件需要定向到 interception 窗口
                //  process-intercepted event needs to be targeted to interception window
                if event_name_owned == "process-intercepted" {
                    if let Err(e) =
                        app_handle_clone.emit_to("interception", &event_name_owned, data)
                    {
                        eprintln!(
                            "[IPC Bridge] Failed to forward event '{}' to interception window: {}",
                            event_name_owned, e
                        );
                    }
                } else {
                    if let Err(e) = app_handle_clone.emit(&event_name_owned, data) {
                        eprintln!(
                            "[IPC Bridge] Failed to forward event '{}': {}",
                            event_name_owned, e
                        );
                    }
                }
            });
        }
    }

    /// 启动重连监控线程
    ///  Start reconnect monitor thread
    ///
    /// 线程定期检查连接状态，如果断开则尝试重新连接
    ///  Thread periodically checks connection status, reconnects if disconnected
    fn start_reconnect_monitor<R: Runtime>(&self, app_handle: AppHandle<R>) {
        let client = self.client.clone();
        let connected = self.connected.clone();
        let started = self.started.clone();

        let handle = match thread::Builder::new()
            .name("ipc-reconnect-monitor".to_string())
            .spawn(move || {
                eprintln!("[IPC Bridge] Reconnect monitor started");

                while started.load(Ordering::SeqCst) {
                    // 短暂休眠，避免空轮询
                    //  Short sleep to avoid busy-waiting
                    thread::sleep(Duration::from_millis(RECONNECT_INTERVAL_MS));

                    // 检查当前连接状态
                    //  Check current connection status
                    if client.is_connected() {
                        // 已连接，同步状态并继续等待
                        //  Connected, sync status and continue waiting
                        connected.store(true, Ordering::SeqCst);
                        continue;
                    }

                    // 未连接，尝试重连
                    //  Not connected, try to reconnect
                    eprintln!("[IPC Bridge] Connection lost, attempting reconnect...");
                    connected.store(false, Ordering::SeqCst);

                    match client.connect() {
                        Ok(true) => {
                            eprintln!("[IPC Bridge] Reconnected to service process");
                            connected.store(true, Ordering::SeqCst);
                            // 通知前端连接已恢复
                            //  Notify frontend that connection is restored
                            let _ = app_handle.emit(
                                "ipc-connection-status",
                                serde_json::json!({"connected": true}),
                            );
                        }
                        Ok(false) => {
                            // 服务仍未运行，继续等待
                            //  Service still not running, keep waiting
                        }
                        Err(e) => {
                            eprintln!("[IPC Bridge] Reconnect error: {}", e);
                        }
                    }
                }

                eprintln!("[IPC Bridge] Reconnect monitor exiting");
            }) {
            Ok(h) => h,
            Err(e) => {
                eprintln!(
                    "[IPC Bridge] Failed to spawn reconnect monitor thread: {}",
                    e
                );
                return;
            }
        };

        let mut guard = self
            .reconnect_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *guard = Some(handle);
    }

    /// 停止桥接服务
    ///  Stop bridge service
    #[allow(dead_code)]
    pub fn stop(&self) {
        self.started.store(false, Ordering::SeqCst);
        self.client.disconnect();
        self.connected.store(false, Ordering::SeqCst);
    }
}

impl Default for IpcBridgeService {
    fn default() -> Self {
        Self::new()
    }
}

/// IPC 桥接服务相关的 Tauri commands
///  Tauri commands related to IPC bridge service
pub mod commands {
    use super::*;
    use tauri::State;

    /// 检查 IPC 桥接是否已连接到服务进程
    ///  Check if IPC bridge is connected to service process
    #[tauri::command]
    pub fn is_ipc_connected(ipc_bridge: State<'_, Arc<IpcBridgeService>>) -> bool {
        ipc_bridge.is_connected()
    }

    /// 获取防护状态（通过 IPC 转发到服务进程）
    ///  Get protection status (forwarded to service process via IPC)
    ///
    /// 如果未连接 IPC，返回本地状态标识
    ///  If IPC not connected, returns local status identifier
    #[tauri::command]
    pub fn get_protection_status(
        ipc_bridge: State<'_, Arc<IpcBridgeService>>,
    ) -> Result<serde_json::Value, String> {
        if !ipc_bridge.is_connected() {
            // 未连接服务进程，返回降级状态
            //  Not connected to service process, return degraded status
            return Ok(serde_json::json!({
                "mode": "standalone",
                "service_running": false,
                "message": "Protection running in UI process (service not available)"
            }));
        }

        // 通过 IPC 查询服务进程的状态
        //  Query service process status via IPC
        ipc_bridge
            .request(ipc_methods::GET_STATUS, serde_json::json!({}))
            .map(|result| {
                serde_json::json!({
                    "mode": "service",
                    "service_running": true,
                    "details": result
                })
            })
            .map_err(|e| format!("Failed to query protection status: {}", e))
    }
}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_bridge_new_initializes_disconnected() {
        let bridge = IpcBridgeService::new();
        assert!(!bridge.is_connected());
        assert!(!bridge.started.load(Ordering::SeqCst));
    }

    #[test]
    fn forwarded_events_includes_key_events() {
        // 确保关键事件都在转发列表中
        //  Ensure key events are in the forward list
        assert!(FORWARDED_EVENTS.contains(&"etw-event"));
        assert!(FORWARDED_EVENTS.contains(&"process-intercepted"));
        assert!(FORWARDED_EVENTS.contains(&"file-hook-event"));
        assert!(FORWARDED_EVENTS.contains(&"log-event"));
        assert!(FORWARDED_EVENTS.contains(&"snapshot-progress"));
        assert!(FORWARDED_EVENTS.contains(&"snapshot-result"));
        // 前端 src/api/risk.ts 监听的是 etw-risk-event，而非曾经写在这里的死条目 risk-event
        //  The frontend (src/api/risk.ts) listens for etw-risk-event, not the dead "risk-event"
        assert!(FORWARDED_EVENTS.contains(&"etw-risk-event"));
        assert!(!FORWARDED_EVENTS.contains(&"risk-event"));
        // 进程监控采集事件（服务模式下 UI 依赖转发） / process monitor collector events
        assert!(FORWARDED_EVENTS.contains(&"process-lifecycle-event"));
        assert!(FORWARDED_EVENTS.contains(&"process-monitor-tampered"));
    }

    #[test]
    fn ipc_bridge_request_not_connected_returns_error() {
        let bridge = IpcBridgeService::new();
        let result = bridge.request("ping", serde_json::json!({}));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("not connected to service process"));
    }

    #[test]
    fn ipc_bridge_stop_sets_connected_false() {
        let bridge = IpcBridgeService::new();
        bridge.connected.store(true, Ordering::SeqCst);
        bridge.stop();
        assert!(!bridge.is_connected());
        assert!(!bridge.started.load(Ordering::SeqCst));
    }
}
