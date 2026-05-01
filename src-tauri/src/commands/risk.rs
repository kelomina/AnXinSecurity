// 风险分析命令 — 风险状态查询
// Risk analysis commands — risk status queries
use crate::services::risk_service::RiskService;

/// 函数名称：get_risk_status
/// 函数作用：获取风险分析服务状态（事件总数等）。
/// Purpose: Gets risk analysis service status (total events, etc.).
/// 调用方：前端概览页状态面板
/// Called by: Frontend overview page status panel
/// 中文关键词：风险状态，分析统计
/// English keywords: risk status, analysis statistics
#[tauri::command]
pub async fn get_risk_status(
    risk: tauri::State<'_, RiskService>,
) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "eventCount": risk.get_event_count(),
    }))
}
