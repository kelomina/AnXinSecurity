// 扫描规则命令 — 加载 JSON 规则文件
// Scan rules commands — load JSON rule files
use std::fs;
use std::path::PathBuf;

/// 函数名称：load_scan_rules
/// 函数作用：从 config/scan_rules.json 加载扫描规则列表。
/// Purpose: Loads scan rules list from config/scan_rules.json.
/// Returns: 规则 JSON 数组 / Rule JSON array
/// 调用方：前端初始化
/// 中文关键词：扫描规则，规则加载，JSON配置
/// English keywords: scan rules, rule loading, JSON config
#[tauri::command]
pub fn load_scan_rules() -> Result<serde_json::Value, String> {
    let path = PathBuf::from("config/scan_rules.json");
    if !path.exists() {
        return Ok(serde_json::json!([]));
    }
    let content = fs::read_to_string(&path).map_err(|e| format!("读取扫描规则文件失败: {}", e))?;
    serde_json::from_str(&content).map_err(|e| format!("解析扫描规则失败: {}", e))
}

/// 函数名称：load_mitre_rules
/// 函数作用：从 config/app.json 加载 MITRE ATT&CK 映射规则。
/// Purpose: Loads MITRE ATT&CK mapping rules from config/app.json.
/// Returns: MITRE 规则 JSON / MITRE rules JSON
/// 调用方：前端 BehaviorLifecyclePage
/// 中文关键词：MITRE规则，ATT&CK映射，威胁情报
/// English keywords: MITRE rules, ATT&CK mapping, threat intelligence
#[tauri::command]
pub fn load_mitre_rules() -> Result<serde_json::Value, String> {
    let path = PathBuf::from("config/app.json");
    let content = fs::read_to_string(&path).map_err(|e| format!("读取配置文件失败: {}", e))?;
    let config: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("解析配置文件失败: {}", e))?;

    let mitre = config
        .get("behaviorMitre")
        .cloned()
        .unwrap_or(serde_json::json!({
            "enabled": true,
            "tactics": [],
            "rules": [],
        }));
    Ok(mitre)
}
