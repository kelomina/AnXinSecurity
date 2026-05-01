// 扫描引擎服务 — 包装 NativeEngineService，对外提供异步扫描接口
// Scan engine service — wraps NativeEngineService, provides async scanning interface
//
// 原有的 TCP IPC 通信已被原生 DLL 直接加载取代。
// The original TCP IPC communication has been replaced by native DLL direct loading.

use crate::services::native_engine_service::NativeEngineService;
use std::sync::Arc;

/// 扫描引擎服务
/// Scan engine service
pub struct EngineService {
    native: Arc<NativeEngineService>,
}

impl EngineService {
    /// 函数名称：new
    /// 函数作用：创建 EngineService，封装 NativeEngineService。
    /// Purpose: Creates EngineService wrapping the NativeEngineService.
    /// 调用方：main.rs setup
    /// Called by: main.rs setup
    /// 中文关键词：引擎服务，初始化，原生引擎封装
    /// English keywords: engine service, initialization, native engine wrapper
    pub fn new(native: Arc<NativeEngineService>) -> Self {
        Self { native }
    }

    /// 函数名称：health_check
    /// 函数作用：检查引擎健康状态，在 blocking 线程中执行。
    /// Purpose: Checks engine health status, executed in a blocking thread.
    /// 调用方：commands::scanner::scanner_health
    /// Called by: commands::scanner::scanner_health
    /// 中文关键词：引擎健康，心跳，状态检查
    /// English keywords: engine health, heartbeat, status check
    pub async fn health_check(&self) -> Result<serde_json::Value, String> {
        let native = self.native.clone();
        tokio::task::spawn_blocking(move || {
            native.health_check()
        }).await
            .map_err(|e| format!("Health check task failed: {}", e))?
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
        let native = self.native.clone();
        let fp = file_path.to_string();
        let fp_for_closure = fp.clone();
        let result = tokio::task::spawn_blocking(move || {
            native.scan_file(&fp_for_closure, options)
        }).await
            .map_err(|e| format!("Scan file task failed: {}", e))?
            .map_err(|e| format!("Scan file failed: {}", e))?;
        eprintln!("[EngineService] scan_file raw result: {}", result);
        Ok(Self::convert_scan_result(result, &fp))
    }

    /// 函数名称：scan_batch
    /// 函数作用：批量扫描多个文件，依次在 blocking 线程中执行，所有结果统一转换为前端 ScanResult 格式。
    /// Purpose: Scans multiple files in batch, executes sequentially in blocking thread,
    ///          and converts all results to frontend ScanResult format.
    /// 调用方：commands::scanner::scan_batch
    /// Called by: commands::scanner::scan_batch
    /// 中文关键词：批量扫描，多文件扫描，批量检测，结果转换
    /// English keywords: batch scan, multi-file scan, batch detection, result conversion
    pub async fn scan_batch(
        &self,
        file_paths: &[String],
        options: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let native = self.native.clone();
        let paths = file_paths.to_vec();
        tokio::task::spawn_blocking(move || {
            let mut results: Vec<serde_json::Value> = Vec::new();
            for path in &paths {
                let raw = match native.scan_file(path, options.clone()) {
                    Ok(result) => {
                        eprintln!("[EngineService] scan_batch raw result for {}: {}", path, result);
                        result
                    },
                    Err(e) => {
                        eprintln!("[EngineService] scan_batch error for {}: {}", path, e);
                        serde_json::json!({
                            "is_malware": false,
                            "confidence": 0.0,
                            "error": e,
                        })
                    },
                };
                results.push(Self::convert_scan_result(raw, path));
            }
            let threats_found = results.iter()
                .filter(|r| r.get("verdict").and_then(|v| v.as_str()) == Some("malware"))
                .count();
            Ok(serde_json::json!({
                "results": results,
                "totalFiles": paths.len(),
                "threatsFound": threats_found,
            }))
        }).await
            .map_err(|e| format!("Batch scan task failed: {}", e))?
    }

    /// 函数名称：convert_scan_result
    /// 函数作用：将 DLL 原始扫描结果 `{is_malware, confidence, malware_family: {family_name}, ...}`
    ///   转换为前端统一的 ScanResult 格式 `{fileId, verdict, threatType, severity, description}`。
    ///   threatType 按优先级提取：
    ///     1. malware_family.family_name（引擎实际嵌套格式）
    ///     2. family_name（扁平格式）
    ///     3. threat_type / threatType / label（其他可能字段）
    /// Purpose: Converts raw DLL scan result `{is_malware, confidence, malware_family: {family_name}, ...}`
    ///   to the unified frontend ScanResult format `{fileId, verdict, threatType, severity, description}`.
    ///   threatType priority: malware_family.family_name → family_name → threat_type → threatType → label.
    /// 调用方：scan_file, scan_batch
    /// Called by: scan_file, scan_batch
    /// 中文关键词：结果转换，格式映射，ScanResult转换，威胁类型提取，嵌套字段，多字段回退
    /// English keywords: result conversion, format mapping, ScanResult conversion, threat type extraction, nested field, multi-field fallback
    fn convert_scan_result(raw: serde_json::Value, file_path: &str) -> serde_json::Value {
        let is_malware = raw.get("is_malware").and_then(|v| v.as_bool()).unwrap_or(false);
        let confidence = raw.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let has_err = raw.get("error").and_then(|v| v.as_str()).is_some();

        // 诊断：枚举原始结果中的所有字段
        // Diagnostics: enumerate all keys in the raw result
        let keys: Vec<String> = raw.as_object()
            .map(|obj| obj.keys().cloned().collect())
            .unwrap_or_default();
        eprintln!("[EngineService] convert_scan_result keys: {:?}", keys);

        // 从多个字段提取威胁类型（按优先级）：
        //   1. family_name — 引擎返回的家族名称（首选）
        //   2. threat_type / threatType / label — 其他可能包含威胁类型的字段
        // Extract threat type from multiple fields (by priority):
        //   1. family_name — malware family name from engine (preferred)
        //   2. threat_type / threatType / label — other fields that may contain threat type
        let family_name_val = raw.get("family_name").and_then(|v| v.as_str()).unwrap_or("<missing>");
        let threat_type_val = raw.get("threat_type").and_then(|v| v.as_str()).unwrap_or("<missing>");
        let threattype_camel_val = raw.get("threatType").and_then(|v| v.as_str()).unwrap_or("<missing>");
        let label_val = raw.get("label").and_then(|v| v.as_str()).unwrap_or("<missing>");
        let error_val = raw.get("error").and_then(|v| v.as_str()).unwrap_or("<missing>");
        // 嵌套字段：malware_family.family_name
        let nested_family = raw.get("malware_family")
            .and_then(|v| v.get("family_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("<missing>");
        eprintln!("[EngineService]   field family_name (flat)      = {:?}", family_name_val);
        eprintln!("[EngineService]   field malware_family.family_name (nested) = {:?}", nested_family);
        eprintln!("[EngineService]   field threat_type             = {:?}", threat_type_val);
        eprintln!("[EngineService]   field threatType              = {:?}", threattype_camel_val);
        eprintln!("[EngineService]   field label                   = {:?}", label_val);
        eprintln!("[EngineService]   field error                   = {:?}", error_val);

        // 威胁类型字段读取优先级：
        //   1. malware_family.family_name（引擎实际嵌套格式）
        //   2. family_name（扁平格式）
        //   3. threat_type / threatType / label（其他可能字段）
        // Threat type field priority:
        //   1. malware_family.family_name (actual engine nested format)
        //   2. family_name (flat format)
        //   3. threat_type / threatType / label (other possible fields)
        let mut threat_type = raw.get("malware_family")
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
        eprintln!("[EngineService]   extracted threat_type = {:?}", threat_type);

        // 引擎返回 pe_features_failed 时视为安全文件
        // pe_features_failed 出现在原始引擎的 threat_type、threatType、label 或 error 字段中
        // Treat as clean when engine reports pe_features_failed
        let raw_threat_type = raw.get("threat_type")
            .or_else(|| raw.get("threatType"))
            .or_else(|| raw.get("label"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let is_pe_failed = raw_threat_type == "pe_features_failed"
            || raw.get("error")
                .and_then(|v| v.as_str())
                .map(|s| s == "pe_features_failed")
                .unwrap_or(false);
        eprintln!("[EngineService]   raw_threat_type = {:?}, is_pe_failed = {}", raw_threat_type, is_pe_failed);

        if is_pe_failed || threat_type == "pe_features_failed" {
            eprintln!("[EngineService]   clearing threat_type due to pe_features_failed");
            threat_type = String::new();
        }

        let (verdict, severity) = if is_pe_failed {
            ("clean", 0)
        } else if has_err && !is_malware {
            ("unknown", 0)
        } else if is_malware {
            ("malware", 90)
        } else if confidence >= 0.8 {
            ("suspicious", 50)
        } else {
            ("clean", 0)
        };
        eprintln!("[EngineService]   is_malware={}, confidence={}, has_err={}, verdict={}", is_malware, confidence, has_err, verdict);

        let description = raw.get("description")
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
        eprintln!("[EngineService]   final result = {}", result);
        result
    }

    /// 函数名称：cancel_scan
    /// 函数作用：取消当前扫描操作（原生 DLL 无取消机制，直接返回 true）。
    /// Purpose: Cancels the current scan operation (native DLL has no cancel mechanism, returns true).
    /// 调用方：commands::scanner::cancel_scan
    /// Called by: commands::scanner::cancel_scan
    /// 中文关键词：取消扫描，中断扫描
    /// English keywords: cancel scan, abort scan
    pub async fn cancel_scan(&self) -> Result<bool, String> {
        Ok(true)
    }

    /// 函数名称：is_malware
    /// 函数作用：快速判断文件是否恶意，在 blocking 线程中执行。
    /// Purpose: Quickly determines if a file is malware, executed in blocking thread.
    /// 调用方：process_scanner_service / file_monitor_service
    /// Called by: process_scanner_service / file_monitor_service
    /// 中文关键词：恶意判断，快速检测
    /// English keywords: malware check, quick detection
    pub async fn is_malware(&self, file_path: &str) -> Result<(bool, f64), String> {
        let native = self.native.clone();
        let file_path = file_path.to_string();
        tokio::task::spawn_blocking(move || {
            native.is_malware(&file_path)
        }).await
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
    fn test_suspicious_file() {
        let raw = serde_json::json!({
            "is_malware": false,
            "confidence": 0.85,
            "malware_family": {
                "family_name": "PUP.Optional"
            }
        });
        let result = convert(raw);
        assert_eq!(result["verdict"], "suspicious");
        assert_eq!(result["threatType"], "PUP.Optional");
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
