// 原生 Axon 扫描引擎 — 通过 libloading 直接加载 axon_engine.dll
// Native Axon scan engine — loads axon_engine.dll directly via libloading
//
// 使用 libloading 动态加载 axon_engine.dll，调用 kvd_* 系列导出函数完成扫描。
// Dynamically loads axon_engine.dll via libloading and calls kvd_* export functions for scanning.
//
// 函数指针类型定义对应 kvd/api.h 中的导出声明
// Function pointer type definitions correspond to export declarations in kvd/api.h

use std::ffi::{CStr, CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::Mutex;

use libloading::Library;

/// kvd_config 结构体（对应 C 头文件 axon_onnx_predict.h，Axon v2.6Exp Loop151 ABI）
/// kvd_config struct (corresponds to C header axon_onnx_predict.h, Axon v2.6Exp Loop151 ABI)
///
/// x64 上 96 字节：旧 LightGBM 字段保留用于 ABI 兼容但引擎忽略，
/// 实际使用 stage2_model_json_path 指向 runtime/loop151_native_runtime.json
#[repr(C)]
struct KvdConfig {
    // 旧字段（ABI 兼容，Axon 忽略）
    model_path: *const std::os::raw::c_char,
    model_normal_path: *const std::os::raw::c_char,
    model_packed_path: *const std::os::raw::c_char,
    family_classifier_json_path: *const std::os::raw::c_char,
    allowed_scan_root: *const std::os::raw::c_char,
    max_file_size: std::os::raw::c_uint,
    prediction_threshold: std::os::raw::c_float,
    // Axon v2.6Exp 新增字段
    onnx_model_path: *const std::os::raw::c_char,
    onnx_model_normal_path: *const std::os::raw::c_char,
    onnx_model_packed_path: *const std::os::raw::c_char,
    stage2_model_json_path: *const std::os::raw::c_char,
    archive_scanner_path: *const std::os::raw::c_char,
    scan_nested: std::os::raw::c_int,
}

// 编译期断言：KvdConfig 在 x64 上必须为 96 字节
const _: () = assert!(
    std::mem::size_of::<KvdConfig>() == 96,
    "KvdConfig must be 96 bytes on x64 (see axon_onnx_predict.h)"
);

type KvdHandle = std::ffi::c_void;

type KvdCreateFn = unsafe extern "C" fn(*const KvdConfig) -> *mut KvdHandle;
type KvdDestroyFn = unsafe extern "C" fn(*mut KvdHandle);
type KvdScanPathFn = unsafe extern "C" fn(
    *mut KvdHandle,
    *const std::os::raw::c_char,
    *mut *mut std::os::raw::c_char,
    *mut usize,
) -> std::os::raw::c_int;
type KvdScanBytesFn = unsafe extern "C" fn(
    *mut KvdHandle,
    *const u8,
    usize,
    *mut *mut std::os::raw::c_char,
    *mut usize,
) -> std::os::raw::c_int;
type KvdFreeFn = unsafe extern "C" fn(*mut std::os::raw::c_char);
type KvdValidateModelsFn = unsafe extern "C" fn(
    *const KvdConfig,
    *mut *mut std::os::raw::c_char,
    *mut usize,
) -> std::os::raw::c_int;

/// 原生 Axon 扫描引擎服务
/// Native Axon scan engine service
///
/// 生命周期：初始化时加载 DLL → kvd_validate_models → kvd_create → 提供扫描 → kvd_destroy
/// Lifecycle: Load DLL → kvd_validate_models → kvd_create → provide scans → kvd_destroy
#[allow(dead_code)]
pub struct NativeEngineService {
    _library: Library,
    handle: Mutex<*mut KvdHandle>,
    kvd_destroy: KvdDestroyFn,
    kvd_scan_path: KvdScanPathFn,
    kvd_scan_bytes: KvdScanBytesFn,
    kvd_free: KvdFreeFn,
    engine_root: String,
}

unsafe impl Send for NativeEngineService {}
unsafe impl Sync for NativeEngineService {}

impl NativeEngineService {
    /// 函数名称：new
    /// 函数作用：加载 axon_engine.dll，验证模型文件，创建引擎句柄。
    /// Purpose: Loads axon_engine.dll, validates model files, creates engine handle.
    ///
    /// 参数：
    ///   dll_path: axon_engine.dll 的已解析绝对路径（由 main.rs 传入）
    ///   engine_root: Engine/Axon/ 目录的已解析绝对路径（由 main.rs 传入）
    ///
    /// 调用方：main.rs（应用启动时初始化，路径已解析完成）
    /// Called by: main.rs (initialized on app startup, paths already resolved)
    ///
    /// 中文关键词：引擎初始化，DLL加载，模型验证，引擎创建
    /// English keywords: engine init, DLL loading, model validation, engine creation
    pub fn new(dll_path: &str, engine_root: &str) -> Result<Self, String> {
        let dll_path = Path::new(dll_path);
        let engine_root = Path::new(engine_root);
        if !dll_path.exists() {
            return Err(format!("DLL path does not exist: {:?}", dll_path));
        }
        if !engine_root.exists() {
            return Err(format!("Engine root does not exist: {:?}", engine_root));
        }
        let engine_root_str = engine_root.to_string_lossy().to_string();

        eprintln!("[NativeEngine] Loading DLL from: {:?}", dll_path);

        // 将引擎目录加入 DLL 搜索路径，确保依赖 DLL 可被正确解析
        // Add engine directory to DLL search path to resolve dependencies
        let library = unsafe {
            // 先将引擎根目录设为 DLL 搜索目录
            let engine_root_wide: Vec<u16> = OsStr::new(engine_root)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            // SetDllDirectoryW 将引擎目录加入 DLL 搜索路径
            let _ = windows::Win32::System::LibraryLoader::SetDllDirectoryW(
                windows::core::PCWSTR::from_raw(engine_root_wide.as_ptr()),
            );

            // 然后加载 axon_engine.dll（libloading 内部使用 LoadLibraryExW）
            let result = Library::new(&dll_path);

            // 恢复 DLL 搜索路径
            let _ = windows::Win32::System::LibraryLoader::SetDllDirectoryW(
                windows::core::PCWSTR::null(),
            );

            result.map_err(|e| format!("Failed to load axon_engine.dll: {}", e))?
        };

        // 获取所有导出函数指针（立刻解引用为 Copy 的函数指针值）
        // Get all export function pointers (immediately deref to Copy fn ptr)
        let kvd_create: KvdCreateFn = unsafe {
            *library
                .get(b"kvd_create")
                .map_err(|e| format!("Failed to find kvd_create: {}", e))?
        };
        let kvd_destroy: KvdDestroyFn = unsafe {
            *library
                .get(b"kvd_destroy")
                .map_err(|e| format!("Failed to find kvd_destroy: {}", e))?
        };
        let kvd_scan_path: KvdScanPathFn = unsafe {
            *library
                .get(b"kvd_scan_path")
                .map_err(|e| format!("Failed to find kvd_scan_path: {}", e))?
        };
        let kvd_scan_bytes: KvdScanBytesFn = unsafe {
            *library
                .get(b"kvd_scan_bytes")
                .map_err(|e| format!("Failed to find kvd_scan_bytes: {}", e))?
        };
        let kvd_free: KvdFreeFn = unsafe {
            *library
                .get(b"kvd_free")
                .map_err(|e| format!("Failed to find kvd_free: {}", e))?
        };
        let kvd_validate_models: KvdValidateModelsFn = unsafe {
            *library
                .get(b"kvd_validate_models")
                .map_err(|e| format!("Failed to find kvd_validate_models: {}", e))?
        };

        // 构建运行时配置路径 / Build runtime config path
        // Axon v2.6Exp 只需 stage2_model_json_path 指向 runtime/loop151_native_runtime.json
        // 引擎通过该 JSON 自行定位所有 ONNX 模型（见 axon_onnx_predict.h 说明）
        let runtime_config_path = engine_root
            .join("runtime")
            .join("loop151_native_runtime.json");

        if !runtime_config_path.exists() {
            return Err(format!(
                "Runtime config not found: {:?}. Axon v2.6Exp requires runtime/loop151_native_runtime.json",
                runtime_config_path
            ));
        }

        // 构造 kvd_config / Build kvd_config
        // 按示例做法：只设置 stage2_model_json_path，其他字段置零/null
        let runtime_config_c = CString::new(runtime_config_path.to_string_lossy().as_bytes())
            .map_err(|e| format!("Invalid runtime config path: {}", e))?;

        let cfg = KvdConfig {
            model_path: std::ptr::null(),
            model_normal_path: std::ptr::null(),
            model_packed_path: std::ptr::null(),
            family_classifier_json_path: std::ptr::null(),
            allowed_scan_root: std::ptr::null(),
            max_file_size: 0,
            prediction_threshold: 0.5,
            onnx_model_path: std::ptr::null(),
            onnx_model_normal_path: std::ptr::null(),
            onnx_model_packed_path: std::ptr::null(),
            stage2_model_json_path: runtime_config_c.as_ptr(),
            archive_scanner_path: std::ptr::null(),
            scan_nested: 0,
        };

        // 验证模型 / Validate models
        // Axon v2.6Exp: KVD_MODEL_OK = 0 表示成功，非零表示失败（按示例做法）
        let mut err_ptr: *mut std::os::raw::c_char = std::ptr::null_mut();
        let mut err_len: usize = 0;
        let check = unsafe { kvd_validate_models(&cfg, &mut err_ptr, &mut err_len) };

        let err_msg = if !err_ptr.is_null() {
            let msg = unsafe { CStr::from_ptr(err_ptr).to_string_lossy().into_owned() };
            unsafe {
                kvd_free(err_ptr);
            }
            msg
        } else {
            String::new()
        };

        if check != 0 {
            return Err(format!(
                "kvd_validate_models failed with code {}: {}",
                check, err_msg
            ));
        }
        eprintln!(
            "[NativeEngine] Model validation passed: {}",
            if err_msg.is_empty() { "<ok>" } else { &err_msg }
        );

        // 创建引擎句柄 / Create engine handle
        let handle = unsafe { kvd_create(&cfg) };
        if handle.is_null() {
            return Err("kvd_create returned null handle".to_string());
        }

        eprintln!("[NativeEngine] Engine initialized successfully");

        Ok(Self {
            _library: library,
            handle: Mutex::new(handle),
            kvd_destroy,
            kvd_scan_path,
            kvd_scan_bytes,
            kvd_free,
            engine_root: engine_root_str,
        })
    }

    /// 函数名称：health_check
    /// 函数作用：检查引擎是否健康运行。
    /// Purpose: Checks if the engine is healthy and running.
    /// 返回值：引擎状态 JSON
    /// Returns: Engine status JSON
    /// 调用方：前端 OverviewPage 轮询
    /// Called by: Frontend OverviewPage polling
    /// 中文关键词：引擎健康，心跳，引擎状态
    /// English keywords: engine health, heartbeat, engine status
    pub fn health_check(&self) -> Result<serde_json::Value, String> {
        let handle = self.handle.lock().map_err(|e| e.to_string())?;
        if handle.is_null() {
            return Ok(serde_json::json!({
                "status": "stopped",
                "engine": "axon_native"
            }));
        }
        Ok(serde_json::json!({
            "status": "running",
            "engine": "axon_native",
            "version": "1.0.0"
        }))
    }

    /// 函数名称：scan_file
    /// 函数作用：扫描单个文件，返回扫描结果 JSON。
    /// Purpose: Scans a single file and returns scan result JSON.
    /// 调用方：commands::scanner::scan_file / process_scanner_service / file_monitor_service
    /// Called by: commands::scanner::scan_file / process_scanner_service / file_monitor_service
    ///
    /// 参数：
    ///   file_path: 要扫描的文件路径
    ///   _options: 扫描选项（当前 DLL 版本忽略）
    ///
    /// 返回值：
    ///   扫描结果 JSON，包含 is_malware, confidence, axon_score 等字段
    ///   Scan result JSON containing is_malware, confidence, axon_score, etc.
    ///
    /// 错误处理：
    ///   锁获取失败返回错误；DLL 扫描失败返回错误；输出解析失败返回默认 clean 结果
    ///
    /// 中文关键词：文件扫描，单文件扫描，威胁检测，恶意软件检测
    /// English keywords: file scan, single file scan, threat detection, malware detection
    pub fn scan_file(
        &self,
        file_path: &str,
        _options: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let handle = self.handle.lock().map_err(|e| e.to_string())?;
        if handle.is_null() {
            return Err("Engine handle is null".to_string());
        }

        let path_c = CString::new(file_path).map_err(|e| format!("Invalid file path: {}", e))?;

        let mut out_json: *mut std::os::raw::c_char = std::ptr::null_mut();
        let mut out_len: usize = 0;

        let rc =
            unsafe { (self.kvd_scan_path)(*handle, path_c.as_ptr(), &mut out_json, &mut out_len) };

        if rc != 0 {
            if !out_json.is_null() {
                unsafe {
                    (self.kvd_free)(out_json);
                }
            }
            return Err(format!("kvd_scan_path failed with code: {}", rc));
        }

        if out_json.is_null() || out_len == 0 {
            return Ok(serde_json::json!({
                "is_malware": false,
                "confidence": 0.0,
                "error": "empty response"
            }));
        }

        let result_str = unsafe { CStr::from_ptr(out_json).to_string_lossy().into_owned() };
        unsafe {
            (self.kvd_free)(out_json);
        }

        match serde_json::from_str::<serde_json::Value>(&result_str) {
            Ok(val) => Ok(Self::convert_loop151_result(val)),
            Err(e) => {
                eprintln!("[NativeEngine] Failed to parse scan result: {}", e);
                Ok(serde_json::json!({
                    "is_malware": false,
                    "confidence": 0.0,
                    "error": format!("parse error: {}", e),
                    "raw": result_str
                }))
            }
        }
    }

    /// 函数名称：convert_loop151_result
    /// 函数作用：将 Axon v2.6Exp Loop151 原始结果转换为上层兼容格式。
    /// Purpose: Converts Axon v2.6Exp Loop151 raw result to upper-layer compatible format.
    ///
    /// 转换规则：
    ///   - 如果已有 is_malware 字段，直接返回（引擎返回兼容格式）
    ///   - 否则从 prediction 字段提取判定（0=benign, 1=malware）
    ///   - confidence 优先取响应中的 confidence/probability/score 字段
    ///
    /// 中文关键词：结果转换，Loop151，prediction，格式兼容
    /// English keywords: result conversion, Loop151, prediction, format compatibility
    fn convert_loop151_result(mut raw: serde_json::Value) -> serde_json::Value {
        if raw.get("is_malware").is_some() {
            return raw;
        }

        let is_malware = raw
            .get("prediction")
            .and_then(|v| v.as_i64())
            .map(|p| p == 1)
            .unwrap_or(false);

        let confidence = raw
            .get("confidence")
            .and_then(|v| v.as_f64())
            .or_else(|| raw.get("probability").and_then(|v| v.as_f64()))
            .or_else(|| raw.get("score").and_then(|v| v.as_f64()))
            .or_else(|| raw.get("malware_probability").and_then(|v| v.as_f64()))
            .unwrap_or(1.0);

        if let Some(obj) = raw.as_object_mut() {
            obj.insert(
                "is_malware".to_string(),
                serde_json::Value::Bool(is_malware),
            );
            obj.insert("confidence".to_string(), serde_json::json!(confidence));
        }
        raw
    }

    /// 函数名称：scan_bytes
    /// 函数作用：扫描内存中的字节数据，返回扫描结果 JSON。
    /// Purpose: Scans bytes in memory and returns scan result JSON.
    /// 调用方：内部（当前未使用，预留接口）
    /// Called by: Internal (currently unused, reserved interface)
    /// 中文关键词：内存扫描，字节扫描
    /// English keywords: memory scan, byte scan
    #[allow(dead_code)]
    pub fn scan_bytes(&self, data: &[u8]) -> Result<serde_json::Value, String> {
        let handle = self.handle.lock().map_err(|e| e.to_string())?;
        if handle.is_null() {
            return Err("Engine handle is null".to_string());
        }

        let mut out_json: *mut std::os::raw::c_char = std::ptr::null_mut();
        let mut out_len: usize = 0;

        let rc = unsafe {
            (self.kvd_scan_bytes)(
                *handle,
                data.as_ptr(),
                data.len(),
                &mut out_json,
                &mut out_len,
            )
        };

        if rc != 0 {
            if !out_json.is_null() {
                unsafe {
                    (self.kvd_free)(out_json);
                }
            }
            return Err(format!("kvd_scan_bytes failed with code: {}", rc));
        }

        if out_json.is_null() || out_len == 0 {
            return Ok(serde_json::json!({
                "is_malware": false,
                "confidence": 0.0
            }));
        }

        let result_str = unsafe { CStr::from_ptr(out_json).to_string_lossy().into_owned() };
        unsafe {
            (self.kvd_free)(out_json);
        }

        serde_json::from_str::<serde_json::Value>(&result_str)
            .map(Self::convert_loop151_result)
            .map_err(|e| format!("Failed to parse scan result: {}", e))
    }

    /// 函数名称：is_malware
    /// 函数作用：快速判断文件是否为恶意，返回布尔值和置信度。
    /// Purpose: Quickly determines if a file is malware, returns boolean and confidence.
    /// 调用方：process_scanner_service / file_monitor_service（快速判断）
    /// Called by: process_scanner_service / file_monitor_service (quick check)
    /// 中文关键词：恶意判断，快速检测，布尔结果
    /// English keywords: malware check, quick detection, boolean result
    #[allow(dead_code)]
    pub fn is_malware(&self, file_path: &str) -> Result<(bool, f64), String> {
        let result = self.scan_file(file_path, serde_json::json!({}))?;
        let is_malware = result
            .get("is_malware")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let confidence = result
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        Ok((is_malware, confidence))
    }

    /// 函数名称：engine_root_path
    /// 函数作用：获取引擎根目录路径。
    /// Purpose: Returns the engine root directory path.
    /// 中文关键词：引擎路径，根目录
    /// English keywords: engine path, root directory
    #[allow(dead_code)]
    pub fn engine_root_path(&self) -> &str {
        &self.engine_root
    }
}

impl Drop for NativeEngineService {
    fn drop(&mut self) {
        if let Ok(mut handle) = self.handle.lock() {
            if !handle.is_null() {
                unsafe {
                    (self.kvd_destroy)(*handle);
                }
                *handle = std::ptr::null_mut();
                eprintln!("[NativeEngine] Engine handle destroyed");
            }
        }
    }
}
