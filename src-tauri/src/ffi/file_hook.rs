// File Hook DLL 绑定
// 注意：file_hook_detours.dll 是通过注入方式工作的，不需要直接调用其导出函数
// 这个模块主要提供配置和状态管理功能

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileHookConfig {
    #[serde(rename = "pipeName")]
    pub pipe_name: String,
    #[serde(rename = "heartbeatIntervalMs")]
    pub heartbeat_interval_ms: u32,
    #[serde(rename = "heartbeatAckTimeoutMs")]
    pub heartbeat_ack_timeout_ms: u32,
}

impl Default for FileHookConfig {
    fn default() -> Self {
        Self {
            pipe_name: "\\\\.\\pipe\\anxin_security_filehook".to_string(),
            heartbeat_interval_ms: 10000,
            heartbeat_ack_timeout_ms: 1000,
        }
    }
}

pub struct FileHook {
    config: FileHookConfig,
}

impl FileHook {
    pub fn new() -> Self {
        Self {
            config: FileHookConfig::default(),
        }
    }

    pub fn with_config(config: FileHookConfig) -> Self {
        Self { config }
    }

    pub fn get_pipe_name(&self) -> &str {
        &self.config.pipe_name
    }
}
