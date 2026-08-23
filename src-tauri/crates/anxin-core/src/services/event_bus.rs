// 事件总线 — 基于 broadcast channel 的事件分发
//  Event bus - broadcast channel-based event distribution
//
// 目标：解耦防护组件对 app_handle.emit() 的直接依赖。
//  Goal: Decouple protection components from direct app_handle.emit() dependency.
//
// EventBus 提供按事件名订阅/发布的能力，payload 以 serde_json::Value 传递。
// 在 Tauri 主进程模式下，前端桥接层订阅事件总线并转发到 Tauri 事件系统；
// 在独立服务进程模式下，事件通过 IPC（命名管道/WebSocket）转发到 UI 进程。
//
// EventBus provides subscribe/publish by event name, with serde_json::Value payloads.
// In Tauri main process mode, the frontend bridge layer subscribes to the event bus
// and forwards to the Tauri event system; in standalone service process mode, events
// are forwarded via IPC (named pipe/WebSocket) to the UI process.
//
// 中文关键词：事件总线，事件分发，广播，前后端分离
// English keywords: event bus, event distribution, broadcast, frontend-backend separation
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::broadcast;

/// 事件 payload — 封装事件名和序列化后的 payload
///  Event payload - encapsulates event name and serialized payload
#[derive(Debug, Clone)]
pub struct EventPayload {
    /// 事件名称（如 "etw-event", "file-hook-event", "process-intercepted"）
    ///  Event name (e.g. "etw-event", "file-hook-event", "process-intercepted")
    pub event: String,
    /// 序列化后的 payload（JSON 值）
    ///  Serialized payload (JSON value)
    pub payload: serde_json::Value,
}

/// 事件总线 — 按事件名分组的广播通道集合
///  Event bus - collection of broadcast channels grouped by event name
pub struct EventBus {
    /// 每个事件名对应一个独立的 broadcast 通道
    ///  Each event name maps to an independent broadcast channel
    channels: Mutex<HashMap<String, broadcast::Sender<EventPayload>>>,
    /// 默认通道容量
    ///  Default channel capacity
    capacity: usize,
}

impl EventBus {
    /// 创建事件总线，指定默认通道容量
    ///  Create event bus with specified default channel capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            channels: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// 获取或创建指定事件的广播通道发送端
    ///  Get or create the broadcast channel sender for the specified event
    fn get_or_create_sender(&self, event: &str) -> broadcast::Sender<EventPayload> {
        let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        channels
            .entry(event.to_string())
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(self.capacity);
                tx
            })
            .clone()
    }

    /// 发射事件。订阅者通过 subscribe() 获取的 Receiver 接收。
    ///  Emit an event. Subscribers receive via the Receiver obtained from subscribe().
    ///
    /// 如果没有订阅者，事件会被静默丢弃（与 app_handle.emit 在前端未监听时行为一致）。
    ///  If there are no subscribers, the event is silently dropped (consistent with
    ///  app_handle.emit behavior when frontend is not listening).
    pub fn emit<S: serde::Serialize + Clone + Send + 'static>(
        &self,
        event: &str,
        payload: S,
    ) -> Result<(), String> {
        let sender = self.get_or_create_sender(event);
        let json_payload = serde_json::to_value(payload)
            .map_err(|e| format!("Failed to serialize event payload: {}", e))?;
        let event_payload = EventPayload {
            event: event.to_string(),
            payload: json_payload,
        };
        // send 失败表示没有订阅者，这是正常情况（与 emit 到无监听器一致）
        //  send failure means no subscribers, which is normal (same as emit to no listener)
        let _ = sender.send(event_payload);
        Ok(())
    }

    /// 订阅指定事件。返回的 Receiver 会收到该事件的所有后续发射。
    ///  Subscribe to the specified event. The returned Receiver will receive all
    ///  subsequent emissions of this event.
    ///
    /// 可以对同一事件多次订阅，每个订阅者独立接收。
    ///  Multiple subscriptions to the same event are allowed; each subscriber
    ///  receives independently.
    pub fn subscribe(&self, event: &str) -> broadcast::Receiver<EventPayload> {
        let sender = self.get_or_create_sender(event);
        sender.subscribe()
    }

    /// 获取已注册的事件名列表（用于调试/诊断）
    ///  Get list of registered event names (for debugging/diagnostics)
    #[allow(dead_code)]
    pub fn registered_events(&self) -> Vec<String> {
        let channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        channels.keys().cloned().collect()
    }
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.channels.lock().map(|c| c.len()).unwrap_or(0);
        f.debug_struct("EventBus")
            .field("event_count", &count)
            .field("capacity", &self.capacity)
            .finish()
    }
}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Debug, Clone, Serialize)]
    struct TestPayload {
        pid: u32,
        name: String,
    }

    #[tokio::test]
    async fn emit_and_receive() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe("test-event");

        let payload = TestPayload {
            pid: 1234,
            name: "test.exe".to_string(),
        };
        bus.emit("test-event", payload.clone()).unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.event, "test-event");
        assert_eq!(received.payload["pid"], 1234);
        assert_eq!(received.payload["name"], "test.exe");
    }

    #[tokio::test]
    async fn multiple_subscribers_independent() {
        let bus = EventBus::new(16);
        let mut rx1 = bus.subscribe("multi");
        let mut rx2 = bus.subscribe("multi");

        bus.emit("multi", "hello").unwrap();

        let r1 = rx1.recv().await.unwrap();
        let r2 = rx2.recv().await.unwrap();
        assert_eq!(r1.payload, "hello");
        assert_eq!(r2.payload, "hello");
    }

    #[tokio::test]
    async fn emit_without_subscribers_succeeds() {
        let bus = EventBus::new(16);
        // 没有订阅者时 emit 不应报错
        assert!(bus.emit("nobody-listening", "data").is_ok());
    }

    #[tokio::test]
    async fn different_events_isolated() {
        let bus = EventBus::new(16);
        let mut rx_a = bus.subscribe("event-a");
        let _rx_b = bus.subscribe("event-b");

        bus.emit("event-a", "a-payload").unwrap();
        // event-b 不应收到 event-a 的事件
        bus.emit("event-b", "b-payload").unwrap();

        let received = rx_a.recv().await.unwrap();
        assert_eq!(received.event, "event-a");
        assert_eq!(received.payload, "a-payload");
    }

    #[test]
    fn registered_events_list() {
        let bus = EventBus::new(16);
        let _ = bus.subscribe("alpha");
        let _ = bus.subscribe("beta");
        let mut names = bus.registered_events();
        names.sort();
        assert_eq!(names, vec!["alpha", "beta"]);
    }
}
