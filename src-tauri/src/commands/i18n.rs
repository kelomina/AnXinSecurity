// 国际化命令 — 语言切换和翻译加载
// i18n commands — language switching and translation loading
use std::sync::{Arc, Mutex};

/// 函数名称：resolve_i18n_path
/// 函数作用：解析 i18n 资源路径，优先 CWD，其次上级目录（兼容 tauri dev）。
/// Purpose: Resolves i18n resource path, preferring CWD then parent dir (for tauri dev).
fn resolve_i18n_path(locale: &str) -> std::path::PathBuf {
    let local = std::path::PathBuf::from(format!("config/i18n/{}.json", locale));
    if local.exists() {
        return local;
    }
    let parent = std::path::PathBuf::from(format!("../config/i18n/{}.json", locale));
    if parent.exists() {
        return parent;
    }
    local
}

/// 函数名称：get_locale
/// 函数作用：从内存中的 AppConfig 状态获取当前语言环境。
/// Purpose: Gets the current application locale from in-memory AppConfig state.
/// Returns: 语言代码 (zh-CN / en-US) / Language code (zh-CN / en-US)
/// 调用方：前端初始化
/// Called by: Frontend initialization
/// 中文关键词：语言设置，国际化，获取语言
/// English keywords: language settings, i18n, get locale
#[tauri::command]
pub async fn get_locale(
    config: tauri::State<'_, Arc<Mutex<crate::models::config::AppConfig>>>,
) -> Result<String, String> {
    let cfg = config.lock().map_err(|e| e.to_string())?;
    Ok(cfg.locale.clone())
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
    let path = resolve_i18n_path(&locale);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("加载语言文件失败 ({}): {}", path.display(), e))?;
    let translations: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("解析语言文件失败: {}", e))?;
    Ok(translations)
}

/// 函数名称：set_locale
/// 函数作用：设置当前应用语言环境，更新内存状态并持久化到配置文件。
/// Purpose: Sets the current application locale, updates in-memory state and persists to config file.
/// 参数 locale: 语言代码 / Language code
/// 副作用：更新 AppConfig 内存状态，写入 config/app.json
/// Side effect: Updates AppConfig in-memory state and writes to config/app.json
/// 调用方：前端 SettingsPage 语言选择器
/// Called by: Frontend SettingsPage language selector
/// 中文关键词：设置语言，切换语言，语言选择
/// English keywords: set locale, switch language, language selection
#[tauri::command]
pub async fn set_locale(
    locale: String,
    config: tauri::State<'_, Arc<Mutex<crate::models::config::AppConfig>>>,
) -> Result<bool, String> {
    // 校验 locale 值，防止路径穿越 / Validate locale to prevent path traversal
    if !locale.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("Invalid locale format".to_string());
    }
    // 验证语言文件存在 / Verify language file exists
    let i18n_path = resolve_i18n_path(&locale);
    if !i18n_path.exists() {
        return Err(format!("Language file not found for locale: {}", locale));
    }
    // 更新内存中的 AppConfig / Update in-memory AppConfig
    {
        let mut cfg = config.lock().map_err(|e| e.to_string())?;
        cfg.locale = locale.clone();
    }
    // 通过 AppConfig::save() 持久化 / Persist via AppConfig::save()
    {
        let cfg = config.lock().map_err(|e| e.to_string())?;
        cfg.save().map_err(|e| format!("保存配置失败: {}", e))?;
    }
    Ok(true)
}
