// 扫描引擎服务 — 包装 NativeEngineService，对外提供异步扫描接口
// Scan engine service — wraps NativeEngineService, provides async scanning interface
//
// 原有的 TCP IPC 通信已被原生 DLL 直接加载取代。
// The original TCP IPC communication has been replaced by native DLL direct loading.

use crate::services::native_engine_service::NativeEngineService;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// 扫描引擎服务
/// Scan engine service
pub struct EngineService {
    native: Arc<Mutex<Option<Arc<NativeEngineService>>>>,
    engine_dll_path: String,
    engine_root_path: String,
    /// 取消标志 — 设置为 true 时，批量扫描在文件间中断 / Cancel flag — when true, batch scan stops between files
    cancel_flag: Arc<AtomicBool>,
}

impl EngineService {
    /// 函数名称：new
    /// 函数作用：创建 EngineService，延迟加载原生扫描引擎。引擎在后台异步加载，不阻塞主线程。
    /// Purpose: Creates EngineService with deferred engine loading. The engine loads asynchronously in the background without blocking the main thread.
    /// 调用方：main.rs setup
    /// Called by: main.rs setup
    /// 被调用方：spawn_background_load（内部异步加载）。
    /// Calls: spawn_background_load (internal async loading).
    /// 参数说明：engine_dll_path 为 axon_engine.dll 路径；engine_root_path 为 Engine/Axon 根目录。
    /// Parameters: engine_dll_path is axon_engine.dll path; engine_root_path is Engine/Axon root.
    /// 返回值说明：始终返回 EngineService（native 初始为 None），引擎在后台加载完成后自动填充。
    /// Returns: Always returns EngineService (native initially None); engine fills in after background load completes.
    /// 错误处理：路径为空时返回错误；后台加载失败只记录日志，不阻断应用启动。
    /// Error handling: Returns error on empty paths; background load failures are logged without blocking app startup.
    /// 中文关键词：引擎服务，延迟初始化，异步加载，不阻塞主线程
    /// English keywords: engine service, deferred init, async loading, non-blocking
    pub fn new(engine_dll_path: String, engine_root_path: String) -> Result<Self, String> {
        if engine_dll_path.trim().is_empty() || engine_root_path.trim().is_empty() {
            return Err("Engine DLL path and root path must not be empty".to_string());
        }
        Ok(Self {
            native: Arc::new(Mutex::new(None)),
            engine_dll_path,
            engine_root_path,
            cancel_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    /// 函数名称：spawn_background_load
    /// 函数作用：在后台异步加载原生引擎 DLL 和模型，加载完成后填充 native 字段。
    /// Purpose: Loads the native engine DLL and models asynchronously in the background, filling the native field when complete.
    /// 调用方：main.rs setup（在创建 EngineService 后立即调用）。
    /// Called by: main.rs setup (called immediately after creating EngineService).
    /// 被调用方：NativeEngineService::new。
    /// Calls: NativeEngineService::new.
    /// 中文关键词：后台加载，异步初始化，引擎加载
    /// English keywords: background load, async init, engine loading
    pub fn spawn_background_load(self: &Arc<Self>) {
        let dll_path = self.engine_dll_path.clone();
        let root_path = self.engine_root_path.clone();
        let native_arc = self.native.clone();
        tauri::async_runtime::spawn(async move {
            eprintln!("[EngineService] Background engine load started");
            let result = tokio::task::spawn_blocking(move || {
                NativeEngineService::new(&dll_path, &root_path).map(Arc::new)
            })
            .await;
            match result {
                Ok(Ok(engine)) => {
                    if let Ok(mut guard) = native_arc.lock() {
                        if guard.is_none() {
                            *guard = Some(engine);
                            eprintln!("[EngineService] Background engine load succeeded");
                        }
                    }
                }
                Ok(Err(e)) => {
                    eprintln!("[EngineService] Background engine load failed: {}", e);
                }
                Err(e) => {
                    eprintln!(
                        "[EngineService] Background engine load task panicked: {}",
                        e
                    );
                }
            }
        });
    }

    /// 函数名称：health_check
    /// 函数作用：检查引擎健康状态，在 blocking 线程中执行。
    /// Purpose: Checks engine health status, executed in a blocking thread.
    /// 调用方：commands::scanner::scanner_health
    /// Called by: commands::scanner::scanner_health
    /// 中文关键词：引擎健康，心跳，状态检查
    /// English keywords: engine health, heartbeat, status check
    pub async fn health_check(&self) -> Result<serde_json::Value, String> {
        let Some(native) = self.native()? else {
            return Ok(serde_json::json!({
                "status": "stopped",
                "engine": "axon_native"
            }));
        };
        tokio::task::spawn_blocking(move || native.health_check())
            .await
            .map_err(|e| format!("Health check task failed: {}", e))?
    }

    /// 函数名称：start_engine
    /// 函数作用：启动扫描引擎；若已启动则保持幂等并返回成功。
    /// Purpose: Starts the scan engine; if already running, keeps the call idempotent and succeeds.
    /// 调用方：commands::engine::start_engine。
    /// Called by: commands::engine::start_engine.
    /// 被调用方：NativeEngineService::new。
    /// Calls: NativeEngineService::new.
    /// 返回值说明：true 表示命令成功；启动失败返回 String。
    /// Returns: true when command succeeds; String error when startup fails.
    /// 错误处理：DLL 或模型加载失败时返回错误，不伪造启动成功。
    /// Error handling: Returns an error on DLL/model loading failure; does not fake success.
    /// 中文关键词：启动引擎，加载DLL，恢复扫描
    /// English keywords: start engine, load DLL, resume scan
    pub async fn start_engine(&self) -> Result<bool, String> {
        if self.native()?.is_some() {
            return Ok(true);
        }

        let dll_path = self.engine_dll_path.clone();
        let root_path = self.engine_root_path.clone();
        let native = tokio::task::spawn_blocking(move || {
            NativeEngineService::new(&dll_path, &root_path).map(Arc::new)
        })
        .await
        .map_err(|e| format!("Start engine task failed: {}", e))??;

        let mut guard = self.native.lock().map_err(|e| e.to_string())?;
        if guard.is_none() {
            *guard = Some(native);
        }
        self.cancel_flag.store(false, Ordering::SeqCst);
        Ok(true)
    }

    /// 函数名称：stop_engine
    /// 函数作用：停止扫描引擎并释放原生 DLL 句柄；已停止时保持幂等。
    /// Purpose: Stops the scan engine and releases the native DLL handle; remains idempotent when already stopped.
    /// 调用方：commands::engine::stop_engine。
    /// Called by: commands::engine::stop_engine.
    /// 被调用方：Option::take，NativeEngineService::drop。
    /// Calls: Option::take, NativeEngineService::drop.
    /// 返回值说明：true 表示命令成功。
    /// Returns: true when command succeeds.
    /// 错误处理：锁失败返回错误。
    /// Error handling: Returns an error when the engine state lock fails.
    /// 中文关键词：停止引擎，释放DLL，暂停扫描
    /// English keywords: stop engine, release DLL, pause scan
    pub async fn stop_engine(&self) -> Result<bool, String> {
        self.cancel_flag.store(true, Ordering::SeqCst);
        let mut guard = self.native.lock().map_err(|e| e.to_string())?;
        let _ = guard.take();
        Ok(true)
    }

    fn native(&self) -> Result<Option<Arc<NativeEngineService>>, String> {
        Ok(self.native.lock().map_err(|e| e.to_string())?.clone())
    }

    fn require_native(&self) -> Result<Arc<NativeEngineService>, String> {
        self.native()?
            .ok_or_else(|| "扫描引擎未启动，请先启动扫描引擎".to_string())
    }

    /// 函数名称：scan_file
    /// 函数作用：扫描单个文件，在 blocking 线程中执行 DLL 调用，并将结果转换为前端 ScanResult 格式。
    /// Purpose: Scans a single file, executes DLL call in blocking thread,
    ///          and converts the result to frontend ScanResult format.
    /// 调用方：commands::scanner::scan_file
    /// Called by: commands::scanner::scan_file
    /// 中文关键词：文件扫描，DLL扫描，单文件检测，结果转换
    /// English keywords: file scan, DLL scan, single file detection, result conversion
    pub async fn scan_file(
        &self,
        file_path: &str,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let result = self.scan_file_raw_with_options(file_path, options).await?;
        Ok(Self::convert_scan_result(result, file_path))
    }

    /// 函数名称：scan_file_raw
    /// 函数作用：扫描单个文件并返回原始 Axon 引擎 JSON，不转换为前端 ScanResult。
    /// Function name: scan_file_raw
    /// Purpose: Scans a single file and returns raw Axon engine JSON without converting it to frontend ScanResult.
    /// 调用方：scan_result_cache_service::scan_or_get_cached。
    /// Called by: scan_result_cache_service::scan_or_get_cached.
    /// 被调用方：scan_file_raw_with_options、NativeEngineService::scan_file。
    /// Calls: scan_file_raw_with_options, NativeEngineService::scan_file.
    /// 参数说明：file_path 为待扫描文件路径；不能为空；应先由调用方完成排除项/允许列表判断。
    /// Parameters: file_path is the file to scan; must not be empty; callers should apply exclusions/allowlist first.
    /// 返回值说明：返回原始 JSON，包含 is_malware、confidence、malware_family 等引擎字段。
    /// Returns: Raw JSON containing engine fields such as is_malware, confidence, and malware_family.
    /// 错误处理：blocking 任务失败或 DLL 扫描失败时返回 String 错误。
    /// Error handling: Returns String on blocking task or DLL scan failure.
    /// 副作用：调用原生扫描引擎；不写文件、不写数据库、不修改缓存。
    /// Side effects: Calls the native scan engine; does not write files, databases, or cache.
    /// 事务边界：无 Unit of Work；无数据库事务。
    /// Transaction boundary: No Unit of Work and no database transaction.
    /// 并发与幂等：同一文件内容和引擎模型不变时结果应稳定；并发由原生引擎句柄锁控制。
    /// Concurrency and idempotency: Stable for unchanged file content and engine model; native handle locking controls concurrency.
    /// 中文关键词：原始扫描结果，进程扫描，模块扫描，缓存扫描，引擎JSON，Axon，引擎调试，SHA缓存，进程模块，安全扫描
    /// English keywords: raw scan result, process scan, module scan, cached scan, engine JSON, Axon, engine debug, SHA cache, process module, security scan
    pub async fn scan_file_raw(&self, file_path: &str) -> Result<serde_json::Value, String> {
        self.scan_file_raw_with_options(file_path, serde_json::json!({}))
            .await
    }

    /// 函数名称：scan_file_raw_with_options
    /// 函数作用：使用指定扫描选项调用原生引擎并返回原始 JSON。
    ///   默认只记录恶意命中或错误结果；设置 ANXIN_ENGINE_DEBUG=1/true 时输出完整原始结果。
    /// Purpose: Calls the native engine with scan options and returns raw JSON.
    ///   By default only malware hits or error results are logged; ANXIN_ENGINE_DEBUG=1/true enables full raw-result logging.
    /// 调用方：scan_file、scan_file_raw。
    /// Called by: scan_file, scan_file_raw.
    /// 被调用方：NativeEngineService::scan_file。
    /// Calls: NativeEngineService::scan_file.
    async fn scan_file_raw_with_options(
        &self,
        file_path: &str,
        options: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let native = self.require_native()?;
        let fp = file_path.to_string();
        let fp_for_closure = fp.clone();
        let result =
            tokio::task::spawn_blocking(move || native.scan_file(&fp_for_closure, options))
                .await
                .map_err(|e| format!("Scan file task failed: {}", e))?
                .map_err(|e| format!("Scan file failed: {}", e))?;
        if Self::should_log_raw_scan_result(&result) {
            eprintln!("[EngineService] scan_file raw result: {}", result);
        }
        Ok(result)
    }

    /// 函数名称：convert_scan_result
    /// 函数作用：将 DLL 原始扫描结果 `{is_malware, confidence, malware_family: {family_name}, ...}`
    ///   转换为前端统一的 ScanResult 格式 `{fileId, verdict, threatType, severity, description}`。
    ///   判定以 is_malware 为准；confidence 是对当前结论的置信度，不单独把安全样本升级为 suspicious。
    ///   threatType 按优先级提取：
    ///     1. malware_family.family_name（引擎实际嵌套格式）
    ///     2. family_name（扁平格式）
    ///     3. threat_type / threatType / label（其他可能字段）
    /// Purpose: Converts raw DLL scan result `{is_malware, confidence, malware_family: {family_name}, ...}`
    ///   to the unified frontend ScanResult format `{fileId, verdict, threatType, severity, description}`.
    ///   The verdict follows is_malware; confidence is confidence in the current result and does not promote benign samples to suspicious.
    ///   threatType priority: malware_family.family_name → family_name → threat_type → threatType → label.
    /// 调用方：scan_file, scan_batch
    /// Called by: scan_file, scan_batch
    /// 被调用方：engine_debug_logging_enabled
    /// Calls: engine_debug_logging_enabled
    /// 中文关键词：结果转换，格式映射，ScanResult转换，恶意判定，威胁类型提取，嵌套字段，多字段回退
    /// English keywords: result conversion, format mapping, ScanResult conversion, malware verdict, threat type extraction, nested field, multi-field fallback
    fn convert_scan_result(raw: serde_json::Value, file_path: &str) -> serde_json::Value {
        let debug_logging = Self::engine_debug_logging_enabled();
        let is_malware = raw
            .get("is_malware")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let confidence = raw
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let has_err = raw.get("error").and_then(|v| v.as_str()).is_some();

        // 诊断：枚举原始结果中的所有字段
        // Diagnostics: enumerate all keys in the raw result
        if debug_logging {
            let keys: Vec<String> = raw
                .as_object()
                .map(|obj| obj.keys().cloned().collect())
                .unwrap_or_default();
            eprintln!("[EngineService] convert_scan_result keys: {:?}", keys);
        }

        // 从多个字段提取威胁类型（按优先级）：
        //   1. family_name — 引擎返回的家族名称（首选）
        //   2. threat_type / threatType / label — 其他可能包含威胁类型的字段
        // Extract threat type from multiple fields (by priority):
        //   1. family_name — malware family name from engine (preferred)
        //   2. threat_type / threatType / label — other fields that may contain threat type
        if debug_logging {
            let family_name_val = raw
                .get("family_name")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing>");
            let threat_type_val = raw
                .get("threat_type")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing>");
            let threattype_camel_val = raw
                .get("threatType")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing>");
            let label_val = raw
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing>");
            let error_val = raw
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing>");
            // 嵌套字段：malware_family.family_name
            let nested_family = raw
                .get("malware_family")
                .and_then(|v| v.get("family_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("<missing>");
            eprintln!(
                "[EngineService]   field family_name (flat)      = {:?}",
                family_name_val
            );
            eprintln!(
                "[EngineService]   field malware_family.family_name (nested) = {:?}",
                nested_family
            );
            eprintln!(
                "[EngineService]   field threat_type             = {:?}",
                threat_type_val
            );
            eprintln!(
                "[EngineService]   field threatType              = {:?}",
                threattype_camel_val
            );
            eprintln!(
                "[EngineService]   field label                   = {:?}",
                label_val
            );
            eprintln!(
                "[EngineService]   field error                   = {:?}",
                error_val
            );
        }

        // 威胁类型字段读取优先级：
        //   1. malware_family.family_name（引擎实际嵌套格式）
        //   2. family_name（扁平格式）
        //   3. threat_type / threatType / label（其他可能字段）
        // Threat type field priority:
        //   1. malware_family.family_name (actual engine nested format)
        //   2. family_name (flat format)
        //   3. threat_type / threatType / label (other possible fields)
        let mut threat_type = raw
            .get("malware_family")
            .and_then(|v| v.as_object())
            .and_then(|obj| obj.get("family_name"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                raw.get("family_name")
                    .or_else(|| raw.get("threat_type"))
                    .or_else(|| raw.get("threatType"))
                    .or_else(|| raw.get("label"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default();
        if debug_logging {
            eprintln!(
                "[EngineService]   extracted threat_type = {:?}",
                threat_type
            );
        }

        // 引擎返回 pe_features_failed 时视为安全文件
        // pe_features_failed 出现在原始引擎的 threat_type、threatType、label 或 error 字段中
        // Treat as clean when engine reports pe_features_failed
        let raw_threat_type = raw
            .get("threat_type")
            .or_else(|| raw.get("threatType"))
            .or_else(|| raw.get("label"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let is_pe_failed = raw_threat_type == "pe_features_failed"
            || raw
                .get("error")
                .and_then(|v| v.as_str())
                .map(|s| s == "pe_features_failed")
                .unwrap_or(false);
        if debug_logging {
            eprintln!(
                "[EngineService]   raw_threat_type = {:?}, is_pe_failed = {}",
                raw_threat_type, is_pe_failed
            );
        }

        if is_pe_failed || threat_type == "pe_features_failed" {
            if debug_logging {
                eprintln!("[EngineService]   clearing threat_type due to pe_features_failed");
            }
            threat_type = String::new();
        }

        let (verdict, severity) = if is_pe_failed {
            ("clean", 0)
        } else if has_err && !is_malware {
            ("unknown", 0)
        } else if is_malware {
            ("malware", 90)
        } else {
            ("clean", 0)
        };
        if verdict == "clean" {
            threat_type = String::new();
        }
        if debug_logging || is_malware || has_err {
            eprintln!(
                "[EngineService]   is_malware={}, confidence={}, has_err={}, verdict={}",
                is_malware, confidence, has_err, verdict
            );
        }

        let description = raw
            .get("description")
            .or_else(|| raw.get("error"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let result = serde_json::json!({
            "fileId": file_path,
            "verdict": verdict,
            "threatType": threat_type,
            "severity": severity,
            "description": description,
        });
        if debug_logging || verdict != "clean" {
            eprintln!("[EngineService]   final result = {}", result);
        }
        result
    }

    /// 函数名称：engine_debug_logging_enabled
    /// 函数作用：读取 ANXIN_ENGINE_DEBUG 环境变量，控制引擎字段级诊断日志是否输出。
    /// Purpose: Reads the ANXIN_ENGINE_DEBUG environment variable to control field-level engine diagnostic logs.
    /// 调用方：scan_file_raw_with_options、convert_scan_result、should_log_raw_scan_result。
    /// Called by: scan_file_raw_with_options, convert_scan_result, should_log_raw_scan_result.
    /// 中文关键词：引擎调试日志，环境变量，日志开关
    /// English keywords: engine debug logging, environment variable, log switch
    fn engine_debug_logging_enabled() -> bool {
        std::env::var("ANXIN_ENGINE_DEBUG")
            .map(|value| Self::engine_debug_value_enabled(&value))
            .unwrap_or(false)
    }

    /// 函数名称：engine_debug_value_enabled
    /// 函数作用：解析调试日志环境变量值，避免测试直接修改进程级环境变量。
    /// Purpose: Parses the debug-log environment variable value so tests do not need to mutate process-wide environment variables.
    /// 调用方：engine_debug_logging_enabled。
    /// Called by: engine_debug_logging_enabled.
    /// 中文关键词：引擎调试日志，环境变量解析，单元测试
    /// English keywords: engine debug logging, environment parsing, unit test
    fn engine_debug_value_enabled(value: &str) -> bool {
        let normalized = value.trim();
        normalized == "1" || normalized.eq_ignore_ascii_case("true")
    }

    /// 函数名称：should_log_raw_scan_result
    /// 函数作用：判断是否输出原始扫描结果；默认只输出恶意或错误，调试环境变量开启后输出全部。
    /// Purpose: Determines whether to log a raw scan result; by default logs only malware or error results, and logs all when debug is enabled.
    /// 调用方：scan_file_raw_with_options。
    /// Called by: scan_file_raw_with_options.
    /// 被调用方：engine_debug_logging_enabled。
    /// Calls: engine_debug_logging_enabled.
    /// 中文关键词：原始扫描日志，刷屏控制，恶意命中，错误日志
    /// English keywords: raw scan logging, log spam control, malware hit, error log
    fn should_log_raw_scan_result(raw: &serde_json::Value) -> bool {
        Self::should_log_raw_scan_result_with_debug(raw, Self::engine_debug_logging_enabled())
    }

    /// 函数名称：should_log_raw_scan_result_with_debug
    /// 函数作用：用显式调试开关判断是否输出原始扫描结果，便于稳定测试默认日志策略。
    /// Purpose: Determines raw-result logging from an explicit debug flag so the default log policy can be tested deterministically.
    /// 调用方：should_log_raw_scan_result。
    /// Called by: should_log_raw_scan_result.
    /// 中文关键词：原始扫描日志，刷屏控制，单元测试
    /// English keywords: raw scan logging, log spam control, unit test
    fn should_log_raw_scan_result_with_debug(raw: &serde_json::Value, debug_logging: bool) -> bool {
        debug_logging
            || raw
                .get("is_malware")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
            || raw.get("error").is_some()
    }

    /// 函数名称：cancel_scan
    /// 函数作用：请求取消当前扫描操作。设置取消标志，批量扫描在文件间检查此标志并提前返回。
    /// Purpose: Requests cancellation of the current scan. Sets the cancel flag; batch scan checks this between files and returns early.
    /// 调用方：commands::scanner::cancel_scan
    /// Called by: commands::scanner::cancel_scan
    /// 被调用方：AtomicBool::store。
    /// Calls: AtomicBool::store.
    /// 中文关键词：取消扫描，中断扫描，取消标志
    /// English keywords: cancel scan, abort scan, cancel flag
    pub async fn cancel_scan(&self) -> Result<bool, String> {
        self.cancel_flag.store(true, Ordering::SeqCst);
        Ok(true)
    }

    /// 函数名称：is_cancelled
    /// 函数作用：检查取消标志是否已设置。
    /// Purpose: Checks whether the cancel flag has been set.
    /// 调用方：commands::scanner::scan_batch、commands::scanner::scan_file
    /// Called by: commands::scanner::scan_batch, commands::scanner::scan_file
    /// 中文关键词：取消检查，取消标志读取
    /// English keywords: cancel check, cancel flag read
    pub fn is_cancelled(&self) -> bool {
        self.cancel_flag.load(Ordering::SeqCst)
    }

    /// 函数名称：is_loaded
    /// 函数作用：返回原生扫描引擎是否已成功加载完成。
    /// Purpose: Returns whether the native scan engine has finished loading.
    /// 调用方：ipc_server GET_STATUS（上报引擎真实在线状态，而非"是否注册过"）
    /// Called by: ipc_server GET_STATUS (reports the engine's real online state, not "was it registered")
    /// 中文关键词：引擎加载状态，真实运行态
    /// English keywords: engine load state, real runtime state
    pub fn is_loaded(&self) -> bool {
        self.native
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    /// 函数名称：reset_cancel_flag
    /// 函数作用：重置取消标志为 false，在开始新扫描前调用。
    /// Purpose: Resets the cancel flag to false, called before starting a new scan.
    /// 调用方：commands::scanner::scan_batch、commands::scanner::scan_file
    /// Called by: commands::scanner::scan_batch, commands::scanner::scan_file
    /// 中文关键词：重置取消，清除取消标志
    /// English keywords: reset cancel, clear cancel flag
    pub fn reset_cancel_flag(&self) {
        self.cancel_flag.store(false, Ordering::SeqCst);
    }

    /// 函数名称：is_malware
    /// 函数作用：快速判断文件是否恶意，在 blocking 线程中执行。
    /// Purpose: Quickly determines if a file is malware, executed in blocking thread.
    /// 调用方：process_scanner_service / file_monitor_service
    /// Called by: process_scanner_service / file_monitor_service
    /// 中文关键词：恶意判断，快速检测
    /// English keywords: malware check, quick detection
    #[allow(dead_code)]
    pub async fn is_malware(&self, file_path: &str) -> Result<(bool, f64), String> {
        let native = self.require_native()?;
        let file_path = file_path.to_string();
        tokio::task::spawn_blocking(move || native.is_malware(&file_path))
            .await
            .map_err(|e| format!("Malware check task failed: {}", e))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 辅助函数：调用私有 convert_scan_result
    fn convert(raw: serde_json::Value) -> serde_json::Value {
        EngineService::convert_scan_result(raw, "/test/path.exe")
    }

    #[test]
    fn test_engine_debug_value_enabled_parses_supported_values() {
        assert!(EngineService::engine_debug_value_enabled("1"));
        assert!(EngineService::engine_debug_value_enabled("true"));
        assert!(EngineService::engine_debug_value_enabled(" TRUE "));
        assert!(!EngineService::engine_debug_value_enabled("0"));
        assert!(!EngineService::engine_debug_value_enabled("false"));
        assert!(!EngineService::engine_debug_value_enabled(""));
    }

    #[test]
    fn test_raw_scan_log_policy_suppresses_clean_results_by_default() {
        let clean = serde_json::json!({
            "is_malware": false,
            "confidence": 0.999
        });
        let malicious = serde_json::json!({
            "is_malware": true,
            "confidence": 0.99
        });
        let error = serde_json::json!({
            "is_malware": false,
            "error": "scan timeout"
        });

        assert!(!EngineService::should_log_raw_scan_result_with_debug(
            &clean, false
        ));
        assert!(EngineService::should_log_raw_scan_result_with_debug(
            &malicious, false
        ));
        assert!(EngineService::should_log_raw_scan_result_with_debug(
            &error, false
        ));
        assert!(EngineService::should_log_raw_scan_result_with_debug(
            &clean, true
        ));
    }

    #[test]
    fn test_nested_malware_family_is_used() {
        let raw = serde_json::json!({
            "is_malware": true,
            "confidence": 0.99,
            "malware_family": {
                "cluster_id": 295,
                "family_name": "Malware_Family_295_Size452",
                "is_new_family": false
            }
        });
        let result = convert(raw);
        assert_eq!(result["threatType"], "Malware_Family_295_Size452");
        assert_eq!(result["verdict"], "malware");
    }

    #[test]
    fn test_flat_family_name_fallback() {
        let raw = serde_json::json!({
            "is_malware": true,
            "confidence": 0.99,
            "family_name": "Trojan.Agent"
        });
        let result = convert(raw);
        assert_eq!(result["threatType"], "Trojan.Agent");
        assert_eq!(result["verdict"], "malware");
    }

    #[test]
    fn test_nested_takes_priority_over_flat() {
        let raw = serde_json::json!({
            "is_malware": true,
            "confidence": 0.99,
            "malware_family": {
                "family_name": "NestedFamily"
            },
            "family_name": "FlatFamily"
        });
        let result = convert(raw);
        assert_eq!(result["threatType"], "NestedFamily");
    }

    #[test]
    fn test_fallback_to_threat_type() {
        let raw = serde_json::json!({
            "is_malware": true,
            "confidence": 0.95,
            "threat_type": "Dropper"
        });
        let result = convert(raw);
        assert_eq!(result["threatType"], "Dropper");
        assert_eq!(result["verdict"], "malware");
    }

    #[test]
    fn test_fallback_to_threattype_camel() {
        let raw = serde_json::json!({
            "is_malware": true,
            "confidence": 0.90,
            "threatType": "Ransomware"
        });
        let result = convert(raw);
        assert_eq!(result["threatType"], "Ransomware");
    }

    #[test]
    fn test_fallback_to_label() {
        let raw = serde_json::json!({
            "is_malware": true,
            "confidence": 0.85,
            "label": "Spyware"
        });
        let result = convert(raw);
        assert_eq!(result["threatType"], "Spyware");
    }

    #[test]
    fn test_flat_family_name_takes_priority_over_threat_type() {
        let raw = serde_json::json!({
            "is_malware": true,
            "confidence": 0.99,
            "family_name": "Trojan.Generic",
            "threat_type": "Dropper",
            "label": "Malware"
        });
        let result = convert(raw);
        assert_eq!(result["threatType"], "Trojan.Generic");
    }

    #[test]
    fn test_no_threat_fields_returns_empty() {
        let raw = serde_json::json!({
            "is_malware": true,
            "confidence": 0.99
        });
        let result = convert(raw);
        assert_eq!(result["threatType"], "");
    }

    #[test]
    fn test_pe_features_failed_clears_threat_type() {
        let raw = serde_json::json!({
            "is_malware": false,
            "confidence": 0.0,
            "family_name": "SomeThreat",
            "threat_type": "pe_features_failed"
        });
        let result = convert(raw);
        assert_eq!(result["threatType"], "");
        assert_eq!(result["verdict"], "clean");
    }

    #[test]
    fn test_pe_features_failed_in_error_clears_threat_type() {
        let raw = serde_json::json!({
            "is_malware": false,
            "confidence": 0.0,
            "family_name": "SomeThreat",
            "error": "pe_features_failed"
        });
        let result = convert(raw);
        assert_eq!(result["threatType"], "");
        assert_eq!(result["verdict"], "clean");
    }

    #[test]
    fn test_pe_features_failed_from_fallback_field() {
        let raw = serde_json::json!({
            "is_malware": false,
            "confidence": 0.0,
            "threat_type": "pe_features_failed"
        });
        let result = convert(raw);
        assert_eq!(result["threatType"], "");
        assert_eq!(result["verdict"], "clean");
    }

    #[test]
    fn test_clean_file() {
        let raw = serde_json::json!({
            "is_malware": false,
            "confidence": 0.01
        });
        let result = convert(raw);
        assert_eq!(result["verdict"], "clean");
        assert_eq!(result["threatType"], "");
    }

    #[test]
    fn test_non_malware_high_confidence_is_clean() {
        let raw = serde_json::json!({
            "is_malware": false,
            "confidence": 0.85,
            "malware_family": {
                "family_name": "PUP.Optional"
            }
        });
        let result = convert(raw);
        assert_eq!(result["verdict"], "clean");
        assert_eq!(result["severity"], 0);
        assert_eq!(result["threatType"], "");
    }

    #[test]
    fn test_axon_non_malware_high_confidence_is_clean() {
        let raw = serde_json::json!({
            "axon_malware": false,
            "axon_score": 0.0005608681822195649,
            "confidence": 0.9994391202926636,
            "hardcase_triggered": false,
            "is_malware": false,
            "signature_hit": false,
            "signature_score": 0.0
        });
        let result = convert(raw);
        assert_eq!(result["verdict"], "clean");
        assert_eq!(result["severity"], 0);
        assert_eq!(result["threatType"], "");
    }

    #[test]
    fn test_error_with_is_malware() {
        let raw = serde_json::json!({
            "is_malware": true,
            "confidence": 0.0,
            "error": "scan timeout",
            "malware_family": {
                "family_name": "Generic.Malware"
            }
        });
        let result = convert(raw);
        assert_eq!(result["verdict"], "malware");
        assert_eq!(result["threatType"], "Generic.Malware");
        assert_eq!(result["description"], "scan timeout");
    }
}
