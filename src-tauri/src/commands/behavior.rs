use crate::services::etw_service::{EtwDiagnosticsSnapshot, EtwService};
use crate::services::ipc_bridge_service::IpcBridgeService;
use crate::services::ipc_protocol::methods;
use crate::services::runtime_list_store::runtime_file_path;
use serde::Serialize;
use std::fs;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EtwRuntimeStatus {
    pub running: bool,
    pub collecting: bool,
}

#[tauri::command]
pub fn pause_etw(app_handle: AppHandle) -> Result<bool, String> {
    let etw_state = app_handle
        .try_state::<Arc<Mutex<EtwService>>>()
        .ok_or("EtwService not managed")?;

    let etw_service = etw_state.lock().map_err(|e| e.to_string())?;
    etw_service.pause()?;

    Ok(true)
}

/// 函数名称：get_etw_status
/// 函数作用：获取 ETW 运行态状态，区分后台任务运行和真实 provider 采集。
/// Purpose: Gets ETW runtime status, distinguishing background task running from real provider collection.
/// 调用方：前端 OverviewPage / SettingsPage 状态展示。
/// Called by: Frontend OverviewPage / SettingsPage status display.
/// 中文关键词：ETW状态，行为监控状态，采集状态
/// English keywords: ETW status, behavior monitoring status, collection status
#[tauri::command]
pub fn get_etw_status(app_handle: AppHandle) -> Result<EtwRuntimeStatus, String> {
    // 已连接服务进程时**必须优先**走 IPC：UI 进程无条件 app.manage(EtwService)（main.rs），
    // 但服务模式下本地实例从未启动，先查本地会让本分支恒命中并返回 running=false，
    // 把正在 SYSTEM 侧采集的服务显示成"ETW 已停止"，下面的 IPC 分支则成为死代码。
    // 判据与 commands/config.rs::is_service_connected 保持一致。
    //  When connected to the service process the IPC path MUST win: the UI process calls
    //  app.manage(EtwService) unconditionally (main.rs) but never starts that local instance in
    //  service mode, so checking locally first always returned running=false and rendered a
    //  actively-collecting service as "ETW stopped", leaving the IPC branch unreachable.
    if let Some(ipc_bridge) = app_handle.try_state::<Arc<IpcBridgeService>>() {
        if ipc_bridge.is_connected() {
            let result = ipc_bridge
                .request(methods::GET_STATUS, serde_json::json!({}))
                .map_err(|e| format!("Failed to query ETW status via IPC: {}", e))?;
            let running = result
                .get("etw_running")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            // 服务进程分别上报 running 与 collecting；旧版服务不带 etw_collecting 字段时
            // 回退为 running，避免把已在采集的服务显示成未采集。
            //  The service reports running and collecting separately; fall back to running when
            //  an older service omits etw_collecting so a collecting service is not shown idle.
            let collecting = result
                .get("etw_collecting")
                .and_then(|v| v.as_bool())
                .unwrap_or(running);
            return Ok(EtwRuntimeStatus {
                running,
                collecting,
            });
        }
    }

    // 独立模式：查询本地 EtwService state
    //  Standalone mode: check the local EtwService state
    if let Some(etw_state) = app_handle.try_state::<Arc<Mutex<EtwService>>>() {
        let etw_service = etw_state.lock().map_err(|e| e.to_string())?;
        return Ok(EtwRuntimeStatus {
            running: etw_service.is_running(),
            collecting: etw_service.is_collecting(),
        });
    }

    // 既无本地 state 也无 IPC 连接，返回默认状态
    //  No local state and no IPC connection, return default status
    Ok(EtwRuntimeStatus {
        running: false,
        collecting: false,
    })
}

/// 函数名称：get_etw_diagnostics_snapshot
/// 函数作用：读取 ETW 现场诊断缓存，返回最近原始事件、规整事件、provider/operation/rule 统计。
/// Purpose: Reads the ETW field diagnostics cache, including recent raw events, normalized events, and provider/operation/rule counters.
/// 调用方：调试控制台 / 后续诊断 UI。
/// Called by: debug console / future diagnostics UI.
/// 中文关键词：ETW诊断，现场缓存，事件统计，刷屏事件
/// English keywords: ETW diagnostics, field cache, event statistics, noisy event stream
#[tauri::command]
pub fn get_etw_diagnostics_snapshot(
    app_handle: AppHandle,
) -> Result<EtwDiagnosticsSnapshot, String> {
    let etw_state = app_handle
        .try_state::<Arc<Mutex<EtwService>>>()
        .ok_or("EtwService not managed")?;

    let etw_service = etw_state.lock().map_err(|e| e.to_string())?;
    Ok(etw_service.diagnostics_snapshot())
}

/// 函数名称：clear_etw_diagnostics
/// 函数作用：清空 ETW 现场诊断缓存，便于受控复现前重新采样。
/// Purpose: Clears the ETW field diagnostics cache before a controlled reproduction.
/// 中文关键词：清空ETW诊断，重新采样
/// English keywords: clear ETW diagnostics, resample
#[tauri::command]
pub fn clear_etw_diagnostics(app_handle: AppHandle) -> Result<bool, String> {
    let etw_state = app_handle
        .try_state::<Arc<Mutex<EtwService>>>()
        .ok_or("EtwService not managed")?;

    let etw_service = etw_state.lock().map_err(|e| e.to_string())?;
    etw_service.clear_diagnostics();
    Ok(true)
}

/// 函数名称：export_etw_diagnostics
/// 函数作用：把 ETW 现场诊断缓存导出到 APPDATA runtime JSON 文件，避免写回仓库配置。
/// Purpose: Exports the ETW field diagnostics cache into an APPDATA runtime JSON file, avoiding repository config writes.
/// 返回值说明：返回导出的 JSON 文件绝对路径。
/// Returns: Absolute path of the exported JSON file.
/// 中文关键词：导出ETW诊断，APPDATA，运行时文件
/// English keywords: export ETW diagnostics, APPDATA, runtime file
#[tauri::command]
pub fn export_etw_diagnostics(app_handle: AppHandle) -> Result<String, String> {
    let snapshot = get_etw_diagnostics_snapshot(app_handle)?;
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f").to_string();
    let path = runtime_file_path(&format!("etw_diagnostics_dump_{}.json", timestamp));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("Failed to create ETW diagnostics directory: {}", err))?;
    }
    let content = serde_json::to_string_pretty(&snapshot)
        .map_err(|err| format!("Failed to serialize ETW diagnostics: {}", err))?;
    fs::write(&path, content)
        .map_err(|err| format!("Failed to write ETW diagnostics dump: {}", err))?;
    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
pub fn resume_etw(app_handle: AppHandle) -> Result<bool, String> {
    let etw_state = app_handle
        .try_state::<Arc<Mutex<EtwService>>>()
        .ok_or("EtwService not managed")?;

    let ctx = crate::services::service_context::build_etw_service_context(&app_handle);
    let etw_service = etw_state.lock().map_err(|e| e.to_string())?;
    etw_service.resume(ctx)?;

    Ok(true)
}
