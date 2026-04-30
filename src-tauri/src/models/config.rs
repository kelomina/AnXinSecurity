use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use crate::commands::exclusions::ExclusionEntry;
use crate::commands::allowlist::AllowlistEntry;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppConfig {
    pub brand: String,
    #[serde(rename = "themeColor")]
    pub theme_color: String,
    #[serde(rename = "defaultPage")]
    pub default_page: String,
    #[serde(rename = "minimizeToTray")]
    pub minimize_to_tray: bool,
    pub tray: TrayConfig,
    pub ui: UiConfig,
    pub scan: ScanConfig,
    pub scanner: ScannerConfig,
    #[serde(rename = "behaviorMonitoring")]
    pub behavior_monitoring: BehaviorConfig,
    #[serde(rename = "behaviorAnalyzer")]
    pub behavior_analyzer: BehaviorAnalyzerConfig,
    // 新增：扫描排除项列表
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclusions: Option<Vec<ExclusionEntry>>,
    // 新增：启动允许列表
    #[serde(rename = "startupAllowlist", skip_serializing_if = "Option::is_none")]
    pub startup_allowlist: Option<Vec<AllowlistEntry>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TrayConfig {
    #[serde(rename = "exitKeepScannerServicePrompt")]
    pub exit_keep_scanner_service_prompt: Option<bool>,
    #[serde(rename = "exitKeepScannerServiceDefault")]
    pub exit_keep_scanner_service_default: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UiConfig {
    pub animations: bool,
    #[serde(rename = "themeMode")]
    pub theme_mode: String,
    pub window: WindowConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WindowConfig {
    #[serde(rename = "minWidth")]
    pub min_width: u32,
    #[serde(rename = "minHeight")]
    pub min_height: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanConfig {
    #[serde(rename = "commonExtensionsOnly")]
    pub common_extensions_only: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScannerConfig {
    #[serde(rename = "timeoutMs")]
    pub timeout_ms: u64,
    #[serde(rename = "healthPollIntervalMs")]
    pub health_poll_interval_ms: u64,
    #[serde(rename = "maxFileSizeMB")]
    pub max_file_size_mb: u64,
    pub ipc: IpcConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IpcConfig {
    pub enabled: bool,
    pub prefer: bool,
    pub host: String,
    pub port: u16,
    #[serde(rename = "connectTimeoutMs")]
    pub connect_timeout_ms: u64,
    #[serde(rename = "timeoutMs")]
    pub timeout_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BehaviorConfig {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BehaviorAnalyzerConfig {
    pub enabled: bool,
    #[serde(rename = "flushIntervalMs")]
    pub flush_interval_ms: u64,
    pub sqlite: SqliteConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SqliteConfig {
    pub mode: String,
    pub directory: String,
    #[serde(rename = "fileName")]
    pub file_name: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            brand: "AnXin Security".to_string(),
            theme_color: "#4CA2FF".to_string(),
            default_page: "overview".to_string(),
            minimize_to_tray: true,
            tray: TrayConfig {
                exit_keep_scanner_service_prompt: Some(true),
                exit_keep_scanner_service_default: Some(true),
            },
            ui: UiConfig {
                animations: true,
                theme_mode: "system".to_string(),
                window: WindowConfig {
                    min_width: 800,
                    min_height: 600,
                },
            },
            scan: ScanConfig {
                common_extensions_only: false,
            },
            scanner: ScannerConfig {
                timeout_ms: 10000,
                health_poll_interval_ms: 30000,
                max_file_size_mb: 500,
                ipc: IpcConfig {
                    enabled: false,
                    prefer: false,
                    host: "127.0.0.1".to_string(),
                    port: 8765,
                    connect_timeout_ms: 500,
                    timeout_ms: 10000,
                },
            },
            behavior_monitoring: BehaviorConfig {
                enabled: true,
            },
            behavior_analyzer: BehaviorAnalyzerConfig {
                enabled: true,
                flush_interval_ms: 500,
                sqlite: SqliteConfig {
                    mode: "file".to_string(),
                    directory: "data/behavior".to_string(),
                    file_name: "anxin_etw_behavior.db".to_string(),
                },
            },
            // 新增字段默认值
            exclusions: Some(Vec::new()),
            startup_allowlist: Some(Vec::new()),
        }
    }
}

impl AppConfig {
    /// 函数名称：load
    /// 函数作用：从 config/app.json 加载配置。优先从 CWD 查找，未找到则尝试上级目录（适配 tauri dev 场景）。
    /// Purpose: Loads config from config/app.json. Tries CWD first, then parent dir (for tauri dev compat).
    /// 中文关键词：配置加载，路径解析，tauri dev，配置查找
    /// English keywords: config loading, path resolution, tauri dev, config lookup
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        Self::try_load_path("config/app.json")
            .or_else(|_| Self::try_load_path("../config/app.json"))
    }

    fn try_load_path(config_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let path = PathBuf::from(config_path);
        let content = fs::read_to_string(&path)?;
        let config: AppConfig = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = PathBuf::from("config/app.json");
        let content = serde_json::to_string_pretty(self)?;
        fs::write(config_path, content)?;
        Ok(())
    }
}
