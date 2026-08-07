use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppConfig {
    pub brand: String,
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
    // 网络防火墙模块。用 default 兜底，旧版 app.json 缺少该键时仍能正常加载。
    //  Network firewall module. `default` keeps an older app.json without this
    //  key loadable.
    #[serde(rename = "networkFirewall", default)]
    pub network_firewall: NetworkFirewallConfig,
    // 元核防护（Hypervisor）模块。用 default 兜底，旧版 app.json 缺少该键时仍能正常加载。
    //  Hypervisor protection module. `default` keeps an older app.json without this
    //  key loadable. Fail-closed: defaults to disabled — must be explicitly turned on
    //  by the user after an environment check passes.
    #[serde(rename = "hypervisorProtection", default)]
    pub hypervisor_protection: HypervisorConfig,
    // locale 字段 — 界面语言设置 / Locale field for UI language
    #[serde(default = "default_locale")]
    pub locale: String,
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
    #[serde(
        rename = "startupSnapshotSlowWarnMs",
        default = "default_startup_snapshot_slow_warn_ms"
    )]
    pub startup_snapshot_slow_warn_ms: u64,
    #[serde(
        rename = "startupModuleEnumerationTimeoutMs",
        default = "default_startup_module_enumeration_timeout_ms"
    )]
    pub startup_module_enumeration_timeout_ms: u64,
    #[serde(
        rename = "startupSignatureVerifyTimeoutMs",
        default = "default_startup_signature_verify_timeout_ms"
    )]
    pub startup_signature_verify_timeout_ms: u64,
    #[serde(
        rename = "startupSignatureVerifyConcurrency",
        default = "default_startup_signature_verify_concurrency"
    )]
    pub startup_signature_verify_concurrency: usize,
    #[serde(
        rename = "startupRevocationCheckTimeoutMs",
        default = "default_startup_revocation_check_timeout_ms"
    )]
    pub startup_revocation_check_timeout_ms: u64,
    #[serde(
        rename = "startupRevocationCheckConcurrency",
        default = "default_startup_revocation_check_concurrency"
    )]
    pub startup_revocation_check_concurrency: usize,
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

/// 网络防火墙配置 / Network firewall configuration
///
/// 对应 config/app.json 的 `networkFirewall` 段，由 FirewallService 翻译成
/// AnXinNetFilter.sys 的运行配置。
///  Backs the `networkFirewall` section of config/app.json; FirewallService
///  translates it into the AnXinNetFilter.sys runtime configuration.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct NetworkFirewallConfig {
    /// 总开关。关闭时驱动全放行，等同于没装这个模块。
    ///  Master switch. When off the driver permits everything.
    pub enabled: bool,
    /// silent（只按规则）/ prompt（未知连接询问）/ learn（只观察）
    ///  silent (rules only) / prompt (ask on unknown) / learn (observe only)
    pub mode: String,
    /// 未命中任何规则时的出站默认动作：allow / block / prompt
    ///  Default outbound action when no rule matches: allow / block / prompt
    #[serde(rename = "defaultOutbound")]
    pub default_outbound: String,
    /// 未命中任何规则时的入站默认动作 / Default inbound action
    #[serde(rename = "defaultInbound")]
    pub default_inbound: String,
    /// 弹窗等待用户裁决的超时（毫秒）/ Prompt timeout in milliseconds
    #[serde(rename = "promptTimeoutMs")]
    pub prompt_timeout_ms: u32,
    /// 超时后采取的动作 / Action taken once the prompt times out
    #[serde(rename = "timeoutAction")]
    pub timeout_action: String,
    /// DNS 域名管控 / DNS domain filtering
    #[serde(rename = "dnsFiltering")]
    pub dns_filtering: bool,
    /// 数据流内容检查（TLS SNI / HTTP Host）/ Stream inspection (TLS SNI / HTTP Host)
    #[serde(rename = "contentInspection")]
    pub content_inspection: bool,
    /// 按进程限速 / Per-process rate limiting
    #[serde(rename = "rateLimiting")]
    pub rate_limiting: bool,
    /// 流量统计 / Traffic statistics
    #[serde(rename = "trafficStats")]
    pub traffic_stats: bool,
    /// 回环流量直接放行。默认开启，关闭会影响大量本机进程间通信。
    ///  Permit loopback outright. On by default; turning it off affects a great
    ///  deal of local inter-process communication.
    #[serde(rename = "allowLoopback")]
    pub allow_loopback: bool,
    /// 内核裁决缓存生存期（毫秒），0 表示不过期
    ///  Kernel verdict cache TTL in milliseconds; 0 means never expires
    #[serde(rename = "cacheTtlMs")]
    pub cache_ttl_ms: u32,
}

impl Default for NetworkFirewallConfig {
    /// 默认关闭且全放行。防火墙是会切断用户网络的功能，必须由用户显式启用，
    /// 绝不能因为升级到带这个模块的版本就默默开始拦截流量。
    ///  Disabled and fully permissive by default. A firewall can cut the user
    ///  off the network, so it must be enabled explicitly — upgrading to a build
    ///  that contains this module must never start blocking traffic on its own.
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "silent".to_string(),
            default_outbound: "allow".to_string(),
            default_inbound: "allow".to_string(),
            prompt_timeout_ms: 20_000,
            timeout_action: "allow".to_string(),
            dns_filtering: false,
            content_inspection: false,
            rate_limiting: false,
            traffic_stats: true,
            allow_loopback: true,
            cache_ttl_ms: 300_000,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BehaviorAnalyzerConfig {
    pub enabled: bool,
    #[serde(rename = "flushIntervalMs")]
    pub flush_interval_ms: u64,
    pub sqlite: SqliteConfig,
}

/// 元核防护（Hypervisor）配置。
///  Hypervisor protection configuration.
/// 该模块默认关闭（fail-closed）。用户必须在设置页手动开启，
/// 后端会先做环境检查（驱动已安装、CPU 支持虚拟化扩展）再加载驱动。
///  This module is disabled by default (fail-closed). The user must turn it on
///  manually in the settings page; the backend runs an environment check (driver
///  installed, CPU virtualization extensions available) before loading the driver.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HypervisorConfig {
    pub enabled: bool,
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
                startup_snapshot_slow_warn_ms: default_startup_snapshot_slow_warn_ms(),
                startup_module_enumeration_timeout_ms:
                    default_startup_module_enumeration_timeout_ms(),
                startup_signature_verify_timeout_ms: default_startup_signature_verify_timeout_ms(),
                startup_signature_verify_concurrency: default_startup_signature_verify_concurrency(
                ),
                startup_revocation_check_timeout_ms: default_startup_revocation_check_timeout_ms(),
                startup_revocation_check_concurrency: default_startup_revocation_check_concurrency(
                ),
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
            network_firewall: NetworkFirewallConfig::default(),
            hypervisor_protection: HypervisorConfig::default(),
            locale: "zh-CN".to_string(),
            // 新增字段默认值
        }
    }
}

fn default_startup_snapshot_slow_warn_ms() -> u64 {
    30_000
}

fn default_startup_module_enumeration_timeout_ms() -> u64 {
    1_000
}

fn default_startup_signature_verify_timeout_ms() -> u64 {
    1_000
}

fn default_startup_signature_verify_concurrency() -> usize {
    0
}

fn default_startup_revocation_check_timeout_ms() -> u64 {
    5_000
}

fn default_startup_revocation_check_concurrency() -> usize {
    4
}

fn default_locale() -> String {
    "zh-CN".to_string()
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

#[cfg(test)]
mod tests {
    use super::{AppConfig, NetworkFirewallConfig};

    #[test]
    fn scanner_revocation_options_default_when_missing_from_legacy_config() {
        let raw = r##"{
            "brand": "AnXin Security",
            "defaultPage": "overview",
            "minimizeToTray": true,
            "tray": {},
            "ui": {
                "animations": true,
                "themeMode": "system",
                "window": {
                    "minWidth": 800,
                    "minHeight": 600
                }
            },
            "scan": {
                "commonExtensionsOnly": false
            },
            "scanner": {
                "timeoutMs": 10000,
                "startupSnapshotSlowWarnMs": 30000,
                "startupSignatureVerifyTimeoutMs": 1000,
                "healthPollIntervalMs": 30000,
                "maxFileSizeMB": 500,
                "ipc": {
                    "enabled": false,
                    "prefer": false,
                    "host": "127.0.0.1",
                    "port": 8765,
                    "connectTimeoutMs": 500,
                    "timeoutMs": 10000
                }
            },
            "behaviorMonitoring": {
                "enabled": false
            },
            "processMonitoring": {
                "enabled": true
            },
            "fileMonitoring": {
                "enabled": true
            },
            "behaviorAnalyzer": {
                "enabled": true,
                "flushIntervalMs": 500,
                "sqlite": {
                    "mode": "file",
                    "directory": "data/behavior",
                    "fileName": "anxin_etw_behavior.db"
                }
            }
        }"##;

        let config: AppConfig = serde_json::from_str(raw).expect("legacy config");

        assert_eq!(config.scanner.startup_revocation_check_timeout_ms, 5_000);
        assert_eq!(config.scanner.startup_revocation_check_concurrency, 4);
        assert_eq!(config.scanner.startup_signature_verify_concurrency, 0);
        assert_eq!(config.scanner.startup_module_enumeration_timeout_ms, 1_000);
    }

    /// 网络防火墙的出厂配置必须是关闭且全放行。
    ///
    /// 防火墙会切断用户的网络。用户升级到带这个模块的版本时，不能因为安装了新版本
    /// 就开始拦截流量——那会在用户完全没有预期的情况下断网，而且断网之后连提示都
    /// 收不到。开启必须是一次显式的用户动作。
    ///  The network firewall must ship disabled and fully permissive. A firewall
    ///  can cut the user off the network, and merely upgrading to a build that
    ///  contains this module must not start blocking traffic: that would drop the
    ///  connection with no warning, and once dropped the user cannot even be told
    ///  why. Enabling it has to be an explicit user action.
    #[test]
    fn network_firewall_ships_disabled_and_permissive() {
        let config = NetworkFirewallConfig::default();

        assert!(!config.enabled, "the firewall must ship disabled");
        assert_eq!(config.mode, "silent");
        assert_eq!(
            config.default_outbound, "allow",
            "outbound must default to allow, never block"
        );
        assert_eq!(
            config.default_inbound, "allow",
            "inbound must default to allow, never block"
        );
        assert_eq!(
            config.timeout_action, "allow",
            "an unanswered prompt must resolve to allow, never block"
        );
        assert!(
            config.allow_loopback,
            "loopback carries local IPC and must be permitted by default"
        );
    }

    /// AppConfig 的整体默认值里也必须带上关闭的防火墙，
    /// 否则配置文件缺少 networkFirewall 段时会落到别的状态。
    ///  The overall AppConfig default must also carry a disabled firewall, so a
    ///  config file missing the networkFirewall section cannot land elsewhere.
    #[test]
    fn app_config_default_keeps_firewall_off() {
        assert!(!AppConfig::default().network_firewall.enabled);
    }
}
