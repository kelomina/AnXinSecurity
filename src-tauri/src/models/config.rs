use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

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
    #[serde(rename = "processMonitoring")]
    pub process_monitoring: ProcessMonitorConfig,
    #[serde(rename = "fileMonitoring")]
    pub file_monitoring: FileMonitorConfig,
    #[serde(rename = "behaviorAnalyzer")]
    pub behavior_analyzer: BehaviorAnalyzerConfig,
    // 新增：扫描排除项列表
    // 新增：启动允许列表
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
pub struct ProcessMonitorConfig {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileMonitorConfig {
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
            behavior_monitoring: BehaviorConfig { enabled: false },
            process_monitoring: ProcessMonitorConfig { enabled: true },
            file_monitoring: FileMonitorConfig { enabled: true },
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

    /// 函数名称：resolve_save_path
    /// 函数作用：解析配置保存路径，优先复用当前工作目录的 config/app.json，若不存在则复用上级目录配置。
    /// Purpose: Resolves the config save path, preferring CWD config/app.json and falling back to the parent config path.
    /// 调用方：AppConfig::save。
    /// Called by: AppConfig::save.
    /// 被调用方：PathBuf::from、PathBuf::exists。
    /// Calls: PathBuf::from, PathBuf::exists.
    /// 参数说明：无参数；依赖当前进程工作目录。
    /// Parameters: No parameters; depends on the current process working directory.
    /// 返回值说明：PathBuf，表示应该写入的 app.json 路径。
    /// Returns: PathBuf for the app.json file to write.
    /// 内部关键变量：local_path 为当前目录配置路径；parent_path 为 tauri dev 上级目录配置路径。
    /// Internal variables: local_path is the CWD config path; parent_path is the tauri dev parent config path.
    /// 接入方式：仅配置模型内部使用，避免调用方硬编码保存路径。
    /// Integration: Internal to the config model, avoiding hardcoded save paths in callers.
    /// 错误处理：本函数不返回错误；目录创建和写入错误由 save 处理。
    /// Error handling: Does not return errors; directory creation and write errors are handled by save.
    /// 副作用：无文件写入副作用，仅解析路径。
    /// Side effects: No file write side effects; resolves a path only.
    /// 事务边界：无 Unit of Work；无 commit/rollback。
    /// Transaction boundary: No Unit of Work; no commit/rollback.
    /// 并发与幂等：同一工作目录下重复调用结果稳定。
    /// Concurrency and idempotency: Stable for repeated calls in the same working directory.
    /// 中文关键词：配置保存，路径解析，config目录，tauri dev，上级目录，app.json，保存路径，工作目录，硬编码避免，配置文件
    /// English keywords: config save, path resolution, config directory, tauri dev, parent directory, app.json, save path, working directory, avoid hardcode, config file
    fn resolve_save_path() -> PathBuf {
        let local_path = PathBuf::from("config/app.json");
        if local_path.exists() {
            return local_path;
        }

        let parent_path = PathBuf::from("../config/app.json");
        if parent_path.exists() {
            return parent_path;
        }

        local_path
    }

    /// 函数名称：save
    /// 函数作用：保存当前应用配置到解析出的 config/app.json，并在写入前确保父目录存在，同时保留未建模配置字段。
    /// Purpose: Saves the current app config to the resolved config/app.json path, ensures its parent directory exists, and preserves unmodeled config fields.
    /// 调用方：config、tray、i18n、dev_settings 等主配置相关 Tauri commands；allowlist/exclusions 已迁移到 runtime_list_store。
    /// Called by: config, tray, i18n, dev_settings, and other main-config Tauri commands; allowlist/exclusions now use runtime_list_store.
    /// 被调用方：resolve_save_path、serde_json::to_value、serde_json::from_str、serde_json::to_string_pretty、fs::create_dir_all、fs::write。
    /// Calls: resolve_save_path, serde_json::to_value, serde_json::from_str, serde_json::to_string_pretty, fs::create_dir_all, fs::write.
    /// 参数说明：self 为当前配置对象。
    /// Parameters: self is the current config object.
    /// 返回值说明：成功返回 Ok(())；序列化、读取已有 JSON、建目录或写文件失败时返回错误。
    /// Returns: Ok(()) on success; serialization, existing JSON read, directory creation, or write failures return errors.
    /// 内部关键变量：config_path 为实际保存路径；existing_value 为原始 JSON；typed_value 为当前结构化配置；content 为格式化 JSON。
    /// Internal variables: config_path is the actual save path; existing_value is the original JSON; typed_value is the current structured config; content is formatted JSON.
    /// 接入方式：由应用层命令保存配置时调用，不应绕过本函数直接写配置文件。
    /// Integration: Called by application commands when persisting config; callers should not bypass it.
    /// 错误处理：已有配置读取或解析失败时退回只保存当前结构化配置；其他错误向上抛出给 Tauri command。
    /// Error handling: Falls back to saving the current structured config when existing config read/parse fails; other errors propagate to the Tauri command.
    /// 副作用：写入配置文件，可能创建 config 目录。
    /// Side effects: Writes the config file and may create the config directory.
    /// 事务边界：无 Unit of Work；单文件写入失败时原错误向上返回。
    /// Transaction boundary: No Unit of Work; single-file write failures are propagated.
    /// 并发与幂等：不是并发写安全；重复保存同一配置结果一致。
    /// Concurrency and idempotency: Not safe for concurrent writes; repeated saves of the same config are stable.
    /// 中文关键词：保存配置，创建目录，运行时拆分，剥离可变列表，os error 3，保留未知字段，config，app.json，错误传播，文件写入
    /// English keywords: save config, create directory, runtime split, strip mutable lists, os error 3, preserve unknown fields, config, app.json, error propagation, file write
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = Self::resolve_save_path();
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut existing_value = fs::read_to_string(&config_path)
            .ok()
            .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
            .unwrap_or_else(|| serde_json::json!({}));
        let typed_value = serde_json::to_value(self)?;

        if let (Some(existing_object), Some(typed_object)) =
            (existing_value.as_object_mut(), typed_value.as_object())
        {
            for (key, value) in typed_object {
                existing_object.insert(key.clone(), value.clone());
            }
            existing_object.remove("exclusions");
            existing_object.remove("startupAllowlist");
            existing_object.remove("startup_allowlist");
        } else {
            existing_value = typed_value;
        }

        let content = serde_json::to_string_pretty(&existing_value)?;
        fs::write(config_path, content)?;
        Ok(())
    }
}
