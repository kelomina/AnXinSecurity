// IPC 协议定义 — 服务进程与 UI 进程之间的通信协议
//  IPC protocol definition - communication protocol between service process and UI process
//
// 协议基于 JSON-RPC 风格，使用换行符分隔的 JSON 消息。
//  Protocol is JSON-RPC style, using newline-delimited JSON messages.
//
// 消息类型：
//  Message types:
// - Request: UI 进程 → 服务进程（查询状态、发送决策等）
// - Response: 服务进程 → UI 进程（请求的回复）
// - Event: 服务进程 → UI 进程（事件推送，如 ETW 事件、拦截通知）
//
// 中文关键词：IPC 协议，命名管道，服务通信，前后端分离
// English keywords: IPC protocol, named pipe, service communication, frontend-backend separation
use serde::{Deserialize, Serialize};

/// IPC 管道名称
///  IPC pipe name
pub const IPC_PIPE_NAME: &str = r"\\.\pipe\AnXinSecurityIPC";

/// 请求 ID 类型
///  Request ID type
pub type RequestId = u64;

// ============================================================================
// 请求消息 — UI 进程发送给服务进程
//  Request message - sent from UI process to service process
// ============================================================================

/// IPC 请求消息
///  IPC request message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    /// 请求 ID，用于匹配响应
    ///  Request ID for matching response
    pub id: RequestId,
    /// 请求方法名
    ///  Request method name
    pub method: String,
    /// 请求参数（JSON 值）
    ///  Request parameters (JSON value)
    #[serde(default)]
    pub params: serde_json::Value,
}

// ============================================================================
// 响应消息 — 服务进程回复 UI 进程
//  Response message - sent from service process to UI process
// ============================================================================

/// IPC 响应消息
///  IPC response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    /// 对应的请求 ID
    ///  Corresponding request ID
    pub id: RequestId,
    /// 响应结果（成功时）
    ///  Response result (on success)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// 错误信息（失败时）
    ///  Error message (on failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl IpcResponse {
    /// 创建成功响应
    ///  Create success response
    pub fn ok(id: RequestId, result: serde_json::Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    /// 创建错误响应
    ///  Create error response
    pub fn err(id: RequestId, error: String) -> Self {
        Self {
            id,
            result: None,
            error: Some(error),
        }
    }
}

// ============================================================================
// 事件消息 — 服务进程推送给 UI 进程
//  Event message - pushed from service process to UI process
// ============================================================================

/// IPC 事件推送消息
///  IPC event push message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcEvent {
    /// 事件名称（如 "etw-event", "process-intercepted", "log-event"）
    ///  Event name (e.g. "etw-event", "process-intercepted", "log-event")
    pub event: String,
    /// 事件数据（JSON 值）
    ///  Event data (JSON value)
    pub data: serde_json::Value,
}

// ============================================================================
// 消息封装 — 统一的 IPC 消息格式
//  Message envelope - unified IPC message format
// ============================================================================

/// IPC 消息（请求、响应或事件）
///  IPC message (request, response, or event)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum IpcMessage {
    /// 请求消息
    ///  Request message
    Request {
        #[serde(flatten)]
        request: IpcRequest,
    },
    /// 响应消息
    ///  Response message
    Response {
        #[serde(flatten)]
        response: IpcResponse,
    },
    /// 事件推送
    ///  Event push
    Event {
        #[serde(flatten)]
        event: IpcEvent,
    },
}

impl IpcMessage {
    /// 创建请求消息
    ///  Create request message
    pub fn request(id: RequestId, method: &str, params: serde_json::Value) -> Self {
        Self::Request {
            request: IpcRequest {
                id,
                method: method.to_string(),
                params,
            },
        }
    }

    /// 创建响应消息
    ///  Create response message
    pub fn response(id: RequestId, result: Result<serde_json::Value, String>) -> Self {
        Self::Response {
            response: match result {
                Ok(value) => IpcResponse::ok(id, value),
                Err(error) => IpcResponse::err(id, error),
            },
        }
    }

    /// 创建事件消息
    ///  Create event message
    pub fn event(event: &str, data: serde_json::Value) -> Self {
        Self::Event {
            event: IpcEvent {
                event: event.to_string(),
                data,
            },
        }
    }

    /// 序列化为 JSON 字符串（带换行符，用于管道传输）
    ///  Serialize to JSON string (with newline, for pipe transport)
    pub fn to_line(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| format!("Failed to serialize IPC message: {}", e))
    }

    /// 从 JSON 字符串反序列化
    ///  Deserialize from JSON string
    pub fn from_line(line: &str) -> Result<Self, String> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err("Empty line".to_string());
        }
        serde_json::from_str(trimmed)
            .map_err(|e| format!("Failed to deserialize IPC message: {}", e))
    }
}

// ============================================================================
// 支持的 IPC 方法名常量
//  Supported IPC method name constants
// ============================================================================

/// IPC 方法名常量
///  IPC method name constants
pub mod methods {
    /// 查询防护状态
    ///  Query protection status
    pub const GET_STATUS: &str = "get_status";

    /// 获取拦截队列
    ///  Get interception queue
    pub const GET_INTERCEPTION_QUEUE: &str = "get_interception_queue";

    /// 处理拦截决策（允许/阻止）
    ///  Handle interception decision (allow/block)
    pub const HANDLE_INTERCEPTION: &str = "handle_interception";

    /// 清空拦截队列
    ///  Clear interception queue
    pub const CLEAR_INTERCEPTION_QUEUE: &str = "clear_interception_queue";

    /// 获取拦截状态
    ///  Get interception status
    pub const GET_INTERCEPTION_STATUS: &str = "get_interception_status";

    /// 获取当前拦截条目
    ///  Peek current interception entry
    pub const PEEK_CURRENT_INTERCEPTION: &str = "peek_current_interception";

    /// 启动扫描引擎
    ///  Start scan engine
    pub const START_ENGINE: &str = "start_engine";

    /// 停止扫描引擎
    ///  Stop scan engine
    pub const STOP_ENGINE: &str = "stop_engine";

    /// 查询扫描引擎健康状态
    ///  Query scan engine health
    pub const SCANNER_HEALTH: &str = "scanner_health";

    /// 扫描单个文件
    ///  Scan a single file
    pub const SCAN_FILE: &str = "scan_file";

    /// 批量扫描多个文件
    ///  Scan multiple files in batch
    pub const SCAN_BATCH: &str = "scan_batch";

    /// 取消当前扫描
    ///  Cancel current scan
    pub const CANCEL_SCAN: &str = "cancel_scan";

    /// ping（连接测试）
    ///  Ping (connection test)
    pub const PING: &str = "ping";

    // ----------------------------------------------------------------
    // 提权通道绑定相关方法 / Elevation channel binding methods
    // ----------------------------------------------------------------

    /// UI → 服务: 请求提权
    ///  UI → service: request elevation
    pub const REQUEST_ELEVATION: &str = "request_elevation";

    /// helper → 服务: 确认提权
    ///  helper → service: confirm elevation
    pub const CONFIRM_ELEVATION: &str = "confirm_elevation";

    /// UI → 服务: 查询通道状态
    ///  UI → service: query channel status
    pub const GET_CHANNEL_STATUS: &str = "get_channel_status";

    /// UI → 服务: 主动撤销提权
    ///  UI → service: revoke elevation
    pub const REVOKE_ELEVATION: &str = "revoke_elevation";
}

// ============================================================================
// 请求/响应数据类型
//  Request/response data types
// ============================================================================

/// 防护状态响应
///  Protection status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionStatus {
    /// ETW 监控是否运行中
    ///  Whether ETW monitoring is running
    pub etw_running: bool,
    /// 文件钩子是否运行中
    ///  Whether file hook is running
    pub file_hook_running: bool,
    /// 文件监控是否运行中
    ///  Whether file monitor is running
    pub file_monitor_running: bool,
    /// 拦截队列长度
    ///  Interception queue length
    pub interception_queue_len: usize,
    /// 引擎是否在线
    ///  Whether engine is online
    pub engine_online: bool,
    /// 服务启动时间（Unix 毫秒）
    ///  Service start time (Unix ms)
    pub started_at: u64,
}

/// 拦截决策请求参数
///  Interception decision request parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptionDecisionParams {
    /// 进程 PID
    ///  Process PID
    pub pid: u32,
    /// 决策：allow 或 block
    ///  Decision: allow or block
    pub decision: String,
}

/// 拦截队列条目
///  Interception queue entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptionQueueItem {
    pub pid: u32,
    pub process_name: String,
    pub file_path: String,
    pub risk_level: String,
    pub threat_type: Option<String>,
    pub reason: String,
    pub timestamp: u64,
}

// ============================================================================
// 提权通道绑定相关数据类型 / Elevation channel binding data types
// ============================================================================

/// 通道状态响应（UI 查询自身通道的提权状态）
///  Channel status response (UI queries its own channel's elevation status)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelStatus {
    /// 当前通道是否已提权
    ///  Whether current channel is elevated
    pub elevated: bool,
    /// 提权到期时间（Unix 毫秒），未提权时为 None
    ///  Elevation expiry time (Unix ms), None when not elevated
    pub elevated_until: Option<u64>,
    /// UI 进程 PID
    ///  UI process PID
    pub ui_pid: u32,
    /// UI 进程路径
    ///  UI process path
    pub ui_path: String,
}

/// 提权请求参数（UI → 服务）
///  Elevation request parameters (UI → service)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevationRequestParams {
    /// UI 进程 PID
    ///  UI process PID
    pub ui_pid: u32,
    /// UI 进程路径
    ///  UI process path
    pub ui_path: String,
    /// UI 进程启动时间（Unix 毫秒），用于 PID 重用检测
    ///  UI process start time (Unix ms), for PID reuse detection
    pub ui_start_time: u64,
    /// 请求的 TTL（毫秒），由用户在设置中选择
    ///  Requested TTL (ms), chosen by user in settings
    pub requested_ttl_ms: u64,
}

/// 提权确认参数（helper → 服务）
///  Elevation confirm parameters (helper → service)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevationConfirmParams {
    /// 提权请求 ID（一次性，由服务颁发）
    ///  Elevation request ID (one-time, issued by service)
    pub request_id: String,
    /// helper 进程 PID
    ///  helper process PID
    pub helper_pid: u32,
    /// helper 进程路径
    ///  helper process path
    pub helper_path: String,
    /// helper 进程启动时间（Unix 毫秒）
    ///  helper process start time (Unix ms)
    pub helper_start_time: u64,
    /// helper 进程签名指纹（开发模式可为 None）
    ///  helper process signature fingerprint (None in dev mode)
    pub helper_signature: Option<String>,
    /// 父进程 PID（应为 UI 进程）
    ///  Parent process PID (should be UI process)
    pub parent_pid: u32,
    /// 父进程启动时间（用于 PID 重用检测）
    ///  Parent process start time (for PID reuse detection)
    pub parent_start_time: u64,
    /// UI 进程 PID（helper 启动时由命令行传入）
    ///  UI process PID (passed via command line when helper starts)
    pub ui_pid: u32,
}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serialize_deserialize() {
        let msg = IpcMessage::request(1, "get_status", serde_json::json!({}));
        let line = msg.to_line().unwrap();
        let parsed = IpcMessage::from_line(&line).unwrap();

        match parsed {
            IpcMessage::Request { request } => {
                assert_eq!(request.id, 1);
                assert_eq!(request.method, "get_status");
            }
            _ => panic!("Expected Request variant"),
        }
    }

    #[test]
    fn response_ok_serialize_deserialize() {
        let msg = IpcMessage::response(2, Ok(serde_json::json!({"running": true})));
        let line = msg.to_line().unwrap();
        let parsed = IpcMessage::from_line(&line).unwrap();

        match parsed {
            IpcMessage::Response { response } => {
                assert_eq!(response.id, 2);
                assert!(response.result.is_some());
                assert!(response.error.is_none());
            }
            _ => panic!("Expected Response variant"),
        }
    }

    #[test]
    fn response_err_serialize_deserialize() {
        let msg = IpcMessage::response(3, Err("service unavailable".to_string()));
        let line = msg.to_line().unwrap();
        let parsed = IpcMessage::from_line(&line).unwrap();

        match parsed {
            IpcMessage::Response { response } => {
                assert_eq!(response.id, 3);
                assert!(response.result.is_none());
                assert_eq!(response.error.as_deref(), Some("service unavailable"));
            }
            _ => panic!("Expected Response variant"),
        }
    }

    #[test]
    fn event_serialize_deserialize() {
        let msg = IpcMessage::event("etw-event", serde_json::json!({"pid": 1234}));
        let line = msg.to_line().unwrap();
        let parsed = IpcMessage::from_line(&line).unwrap();

        match parsed {
            IpcMessage::Event { event } => {
                assert_eq!(event.event, "etw-event");
                assert_eq!(event.data["pid"], 1234);
            }
            _ => panic!("Expected Event variant"),
        }
    }

    #[test]
    fn from_line_empty_returns_error() {
        assert!(IpcMessage::from_line("").is_err());
        assert!(IpcMessage::from_line("   \n  ").is_err());
    }

    #[test]
    fn from_line_invalid_json_returns_error() {
        assert!(IpcMessage::from_line("not json").is_err());
    }

    #[test]
    fn message_round_trip_with_newline() {
        let msg = IpcMessage::request(42, "ping", serde_json::json!({"msg": "hello"}));
        let mut line = msg.to_line().unwrap();
        line.push('\n');
        let parsed = IpcMessage::from_line(line.trim()).unwrap();

        match parsed {
            IpcMessage::Request { request } => {
                assert_eq!(request.id, 42);
                assert_eq!(request.method, "ping");
                assert_eq!(request.params["msg"], "hello");
            }
            _ => panic!("Expected Request variant"),
        }
    }
}
