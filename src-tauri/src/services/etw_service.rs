use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tauri::{AppHandle, Emitter};
use crate::ffi::etw_bridge::{EtwBridge, EtwKeywords};
use crate::models::event::EtwEvent;

pub struct EtwService {
    bridge: Arc<Mutex<Option<EtwBridge>>>,
    tx: broadcast::Sender<EtwEvent>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl EtwService {
    pub fn new() -> Arc<Mutex<Self>> {
        let (tx, _) = broadcast::channel(1000);

        Arc::new(Mutex::new(Self {
            bridge: Arc::new(Mutex::new(None)),
            tx,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }))
    }

    pub fn start(&self, app_handle: AppHandle) -> Result<(), String> {
        let mut bridge = EtwBridge::new().map_err(|e: String| e)?;
        let keywords = EtwKeywords::default();

        bridge.start(keywords).map_err(|e: String| e)?;

        let tx = self.tx.clone();
        let running = self.running.clone();

        *self.bridge.lock().map_err(|e| e.to_string())? = Some(bridge);
        let bridge_arc = self.bridge.clone();
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);

        // 启动后台轮询任务
        let app_handle_clone = app_handle.clone();
        tokio::spawn(async move {
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                if let Ok(bridge_guard) = bridge_arc.lock() {
                    if let Some(ref bridge) = *bridge_guard {
                        match bridge.poll_events() {
                            Ok(events) => {
                                for event in events {
                                    let _ = tx.send(event.clone());

                                    // 发送到 Tauri 前端事件总线
                                    if let Some(payload) = event.to_json() {
                                        let _ = app_handle_clone.emit("etw-event", payload);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("ETW poll error: {}", e);
                                break;
                            }
                        }
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        });

        Ok(())
    }

    pub fn pause(&self) -> Result<(), String> {
        if let Ok(mut bridge_guard) = self.bridge.lock() {
            if let Some(ref mut bridge) = *bridge_guard {
                bridge.stop(2500).map_err(|e: String| e)?;
            }
        }
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    pub fn resume(&self, app_handle: AppHandle) -> Result<(), String> {
        self.start(app_handle)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EtwEvent> {
        self.tx.subscribe()
    }
}
