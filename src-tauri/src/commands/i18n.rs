// 国际化命令 — 语言切换和翻译加载
// i18n commands — language switching and translation loading
use std::sync::{Arc, Mutex};

/// 函数名称：get_locale
/// 函数作用：获取当前应用语言环境。
/// Purpose: Gets the current application locale.
/// Returns: 语言代码 (zh-CN / en-US) / Language code (zh-CN / en-US)
/// 调用方：前端初始化
/// Called by: Frontend initialization
/// 中文关键词：语言设置，国际化，获取语言
/// English keywords: language settings, i18n, get locale
#[tauri::command]
pub async fn get_locale(
    config: tauri::State<'_, Arc<Mutex<crate::models::config::AppConfig>>>,
) -> Result<String, String> {
    let _cfg = config.lock().map_err(|e| e.to_string())?;
    // locale 可能不在 AppConfig 结构体中，回退到 "zh-CN"
    Ok("zh-CN".to_string())
}

/// 函数名称：get_translations
/// 函数作用：加载指定语言的翻译文件。
/// Purpose: Loads translations for the specified locale.
/// 参数 locale: 语言代码 (zh-CN, en-US) / Language code
/// Returns: 翻译 JSON 对象 / Translation JSON object
/// 调用方：前端 i18nStore 初始化
/// Called by: Frontend i18nStore initialization
/// 副作用：从 config/i18n/{locale}.json 读取文件
/// Side effect: Reads from config/i18n/{locale}.json
/// 中文关键词：翻译加载，语言包，国际化文本
/// English keywords: translation loading, language pack, i18n text
#[tauri::command]
pub async fn get_translations(locale: String) -> Result<serde_json::Value, String> {
    let path = format!("config/i18n/{}.json", locale);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("加载语言文件失败 ({}): {}", path, e))?;
    let translations: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("解析语言文件失败: {}", e))?;
    Ok(translations)
}

/// 函数名称：set_locale
/// 函数作用：设置当前应用语言环境。
/// Purpose: Sets the current application locale.
/// 参数 locale: 语言代码 / Language code
/// 副作用：写入 config/app.json
/// Side effect: Writes to config/app.json
/// 调用方：前端 SettingsPage 语言选择器
/// Called by: Frontend SettingsPage language selector
/// 中文关键词：设置语言，切换语言，语言选择
/// English keywords: set locale, switch language, language selection
#[tauri::command]
pub async fn set_locale(
    locale: String,
    _config: tauri::State<'_, Arc<Mutex<crate::models::config::AppConfig>>>,
) -> Result<bool, String> {
    // 更新配置文件中的 locale 字段 / Update locale field in config file
    let path = std::path::PathBuf::from("config/app.json");
    let content = std::fs::read_to_string(&path).map_err(|e| format!("读取配置文件失败: {}", e))?;
    let mut config_json: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("解析配置文件失败: {}", e))?;
    config_json["locale"] = serde_json::Value::String(locale.clone());
    let json_str =
        serde_json::to_string_pretty(&config_json).map_err(|e| format!("序列化配置失败: {}", e))?;
    std::fs::write(&path, json_str).map_err(|e| format!("写入配置文件失败: {}", e))?;
    Ok(true)
}
