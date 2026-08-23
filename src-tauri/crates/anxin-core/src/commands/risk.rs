// 风险分析命令 — 风险状态查询
// Risk analysis commands — risk status queries
use crate::services::ipc_bridge_service::IpcBridgeService;
use crate::services::ipc_protocol::methods;
use crate::services::risk_service::RiskService;
use std::sync::Arc;
use tauri::{AppHandle, Manager};

/// 函数名称：get_risk_status
/// 函数作用：获取风险分析服务状态（事件总数等）。
/// Purpose: Gets risk analysis service status (total events, etc.).
/// 调用方：前端概览页状态面板
/// Called by: Frontend overview page status panel
/// 中文关键词：风险状态，分析统计，服务进程，IPC 查询
/// English keywords: risk status, analysis statistics, service process, IPC query
#[tauri::command]
pub async fn get_risk_status(app_handle: AppHandle) -> Result<serde_json::Value, String> {
    // 双进程架构下，风险事件由服务进程采集，UI 进程本地无数据
    //  In dual-process architecture, risk events are collected by service process; UI process has no local data
    if app_handle
        .try_state::<Arc<IpcBridgeService>>()
        .map(|b| b.is_connected())
        .unwrap_or(false)
    {
        // 通过 IPC 查询服务进程状态获取拦截队列长度作为风险指标
        //  Query service process status via IPC for interception queue length as risk indicator
        if let Ok(result) = app_handle
            .try_state::<Arc<IpcBridgeService>>()
            .unwrap()
            .request(methods::GET_STATUS, serde_json::json!({}))
        {
            let queue_len = result
                .get("interception_queue_len")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            return Ok(serde_json::json!({
                "eventCount": queue_len,
            }));
        }
        return Ok(serde_json::json!({
            "eventCount": 0,
        }));
    }

    // 独立模式：查询本地 RiskService
    //  Standalone mode: query local RiskService
    if let Some(risk) = app_handle.try_state::<RiskService>() {
        return Ok(serde_json::json!({
            "eventCount": risk.get_event_count(),
        }));
    }

    Ok(serde_json::json!({
        "eventCount": 0,
    }))
}
