// 拦截命令 — 拦截弹窗操作和队列管理
// Interception commands — interception modal operations and queue management
//
// 支持两种模式：
//  Supports two modes:
// - 服务进程模式：IPC 已连接时，拦截决策转发到服务进程执行
// - 独立模式：IPC 未连接时，UI 进程本地执行拦截逻辑（向后兼容）
use crate::services::interception_service::{
    InterceptionDecision, InterceptionEntry, InterceptionService,
};
use crate::services::ipc_bridge_service::IpcBridgeService;
use crate::services::ipc_protocol::methods as ipc_methods;
use crate::services::process_control_service::{resume_process_by_pid, terminate_process_by_pid};
use crate::services::trust_service::TrustService;
use std::sync::Arc;

/// 函数名称：handle_interception
/// 函数作用：处理用户的拦截决策（放行/阻止指定 PID 的进程）。
/// Purpose: Handles user's interception decision (allow/block the process identified by PID).
/// 参数 pid: 目标进程 PID / Target process PID
/// 参数 action: 决策操作 "allow" 或 "block" / Decision action "allow" or "block"
/// 副作用：若阻止，则终止进程；若放行，则恢复进程
/// 调用方：前端 InterceptionModal 阻止/允许按钮
/// Called by: Frontend InterceptionModal block/allow buttons
/// 中文关键词：拦截决策，放行进程，阻止进程，终止进程，恢复进程，IPC 转发
/// English keywords: interception decision, allow process, block process, terminate process, resume process, IPC forward
#[tauri::command]
pub async fn handle_interception(
    app_handle: tauri::AppHandle,
    pid: u32,
    action: String,
    interception: tauri::State<'_, Arc<InterceptionService>>,
    ipc_bridge: tauri::State<'_, Arc<IpcBridgeService>>,
) -> Result<bool, String> {
    // 验证 action 参数
    //  Validate action parameter
    let decision = match action.as_str() {
        "allow" => InterceptionDecision::Allow,
        "block" => InterceptionDecision::Block,
        _ => {
            return Err(format!(
                "无效的操作类型: {}，有效值为 allow 和 block",
                action
            ))
        }
    };

    // 服务进程模式：IPC 已连接时，转发决策到服务进程
    //  Service process mode: when IPC connected, forward decision to service process
    if ipc_bridge.is_connected() {
        let params = serde_json::json!({
            "pid": pid,
            "action": action,
        });
        // 转发到服务进程执行实际的进程恢复/终止
        //  Forward to service process to execute actual process resume/terminate
        ipc_bridge
            .request(ipc_methods::HANDLE_INTERCEPTION, params)
            .map_err(|e| format!("IPC 转发拦截决策失败: {}", e))?;

        // UI 进程隐藏拦截窗口（服务进程会通过 IPC 推送下一个拦截事件，如果有）
        //  UI process hides interception window (service process will push next interception event via IPC if any)
        crate::services::interception_window_service::hide_interception_window(&app_handle);
        return Ok(true);
    }

    // 独立模式：本地执行拦截逻辑
    //  Standalone mode: execute interception logic locally
    let Some(entry) = interception.entry_for_pid(pid) else {
        return Err(format!("未找到 PID {} 的待处理拦截记录", pid));
    };

    match decision {
        InterceptionDecision::Allow => {
            interception.mark_allowed_temporarily(&entry);
            if let Err(err) = resume_process_by_pid(pid) {
                interception.remove_temporary_allow(&entry);
                return Err(err);
            }
            interception.mark_decision_with_window(pid, decision, &app_handle);
            interception.complete_allow(pid);
        }
        InterceptionDecision::Block => {
            terminate_process_by_pid(pid)?;
            interception.mark_decision_with_window(pid, decision, &app_handle);
        }
    }

    // 尝试展示下一个弹窗 / Try to show next modal
    interception.try_show_next(&app_handle);
    Ok(true)
}

/// 函数名称：get_interception_queue
/// 函数作用：获取当前拦截队列中的所有暂停进程 PID。
/// Purpose: Gets all paused process PIDs in the current interception queue.
/// 调用方：前端概览页查询拦截状态
/// Called by: Frontend overview page querying interception status
/// 中文关键词：拦截队列，暂停进程列表，队列状态，IPC 转发
/// English keywords: interception queue, paused process list, queue status, IPC forward
#[tauri::command]
pub async fn get_interception_queue(
    interception: tauri::State<'_, Arc<InterceptionService>>,
    ipc_bridge: tauri::State<'_, Arc<IpcBridgeService>>,
) -> Result<Vec<u32>, String> {
    // 服务进程模式：通过 IPC 查询服务进程的拦截队列
    //  Service process mode: query service process interception queue via IPC
    if ipc_bridge.is_connected() {
        let result = ipc_bridge
            .request(ipc_methods::GET_INTERCEPTION_QUEUE, serde_json::json!({}))
            .map_err(|e| format!("IPC 查询拦截队列失败: {}", e))?;

        // 解析服务进程返回的拦截队列条目，提取 PID 列表。
        // 服务端（ipc_server.rs）返回的是 Vec<InterceptionQueueItem> 对象数组，
        // 不能再用 as_u64() 过滤——那会丢掉全部对象，服务模式下队列永远显示为空。
        //  The service process returns Vec<InterceptionQueueItem> objects; parsing with
        //  as_u64() drops every object, making the queue appear empty in service mode.
        let pids: Vec<u32> = result
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.get("pid").and_then(|p| p.as_u64()).map(|n| n as u32))
                    .collect()
            })
            .unwrap_or_default();
        return Ok(pids);
    }

    // 独立模式：返回本地拦截队列
    //  Standalone mode: return local interception queue
    Ok(interception.get_paused_pids())
}

/// 函数名称：clear_interception_queue
/// 函数作用：清空所有拦截队列和决策记录。
/// Purpose: Clears all interception queues and decision records.
/// 调用方：前端操作
/// Called by: Frontend operation
/// 中文关键词：清空队列，重置拦截，IPC 转发
/// English keywords: clear queue, reset interception, IPC forward
#[tauri::command]
pub async fn clear_interception_queue(
    app_handle: tauri::AppHandle,
    interception: tauri::State<'_, Arc<InterceptionService>>,
    ipc_bridge: tauri::State<'_, Arc<IpcBridgeService>>,
) -> Result<bool, String> {
    // 服务进程模式：通过 IPC 清空服务进程的拦截队列
    //  Service process mode: clear service process interception queue via IPC
    if ipc_bridge.is_connected() {
        ipc_bridge
            .request(ipc_methods::CLEAR_INTERCEPTION_QUEUE, serde_json::json!({}))
            .map_err(|e| format!("IPC 清空拦截队列失败: {}", e))?;
    }

    // 无论哪种模式，都清空本地拦截状态并隐藏窗口
    //  In both modes, clear local interception state and hide window
    interception.clear_all();
    crate::services::interception_window_service::hide_interception_window(&app_handle);
    Ok(true)
}

/// 函数名称：get_interception_status
/// 函数作用：获取拦截服务的当前状态（队列大小、是否正在展示弹窗）。
/// Purpose: Gets current status of the interception service (queue size, whether a modal is showing).
/// 调用方：前端概览页
/// Called by: Frontend overview page
/// 中文关键词：拦截状态，队列大小，弹窗状态，IPC 转发
/// English keywords: interception status, queue size, modal state, IPC forward
#[tauri::command]
pub async fn get_interception_status(
    interception: tauri::State<'_, Arc<InterceptionService>>,
    ipc_bridge: tauri::State<'_, Arc<IpcBridgeService>>,
) -> Result<serde_json::Value, String> {
    // 服务进程模式：通过 IPC 查询服务进程的拦截状态
    //  Service process mode: query service process interception status via IPC
    if ipc_bridge.is_connected() {
        let result = ipc_bridge
            .request(ipc_methods::GET_INTERCEPTION_STATUS, serde_json::json!({}))
            .map_err(|e| format!("IPC 查询拦截状态失败: {}", e))?;
        return Ok(result);
    }

    // 独立模式：返回本地拦截状态
    //  Standalone mode: return local interception status
    Ok(serde_json::json!({
        "queueSize": interception.get_queue_size(),
        "pausedPids": interception.get_paused_pids(),
        "temporaryAllowlistSize": interception.get_temporary_allowlist_size(),
    }))
}

/// 函数名称：get_interception_signer_info
/// 函数作用：获取指定文件的数字签名者信息（用于拦截弹窗展示）。
/// Purpose: Gets digital signer info for the specified file (for interception modal display).
/// 调用方：前端拦截弹窗查看文件详情
/// Called by: Frontend interception modal viewing file details
/// 中文关键词：签名者信息，文件签名，拦截详情
/// English keywords: signer info, file signature, interception details
#[tauri::command]
pub async fn get_interception_signer_info(
    file_path: String,
    trust: tauri::State<'_, std::sync::Arc<TrustService>>,
) -> Result<serde_json::Value, String> {
    let signer = trust.get_signer_info(&file_path)?;
    Ok(serde_json::json!({
        "subject": signer.subject,
        "issuer": signer.issuer,
        "thumbprint": signer.thumbprint,
    }))
}

/// 函数名称：peek_current_interception
/// 函数作用：返回当前正在展示的拦截条目（若有），供拦截窗口前端初始化后主动拉取。
/// Purpose: Returns the currently shown interception entry (if any) for the interception window frontend to pull after initialization.
/// 调用方：前端 InterceptionWindowApp 初始化后调用
/// Called by: Frontend InterceptionWindowApp after initialization
/// 中文关键词：当前拦截，前端拉取，窗口初始化，IPC 转发
/// English keywords: current interception, frontend pull, window initialization, IPC forward
#[tauri::command]
pub async fn peek_current_interception(
    interception: tauri::State<'_, Arc<InterceptionService>>,
    ipc_bridge: tauri::State<'_, Arc<IpcBridgeService>>,
) -> Result<Option<InterceptionEntry>, String> {
    // 服务进程模式：通过 IPC 查询服务进程的当前拦截条目
    //  Service process mode: query service process current interception entry via IPC
    if ipc_bridge.is_connected() {
        let result = ipc_bridge
            .request(
                ipc_methods::PEEK_CURRENT_INTERCEPTION,
                serde_json::json!({}),
            )
            .map_err(|e| format!("IPC 查询当前拦截失败: {}", e))?;

        // 如果服务进程返回 null，表示当前无拦截
        //  If service process returns null, no current interception
        if result.is_null() {
            return Ok(None);
        }

        // 尝试将 JSON 转换为 InterceptionEntry
        //  Try to convert JSON to InterceptionEntry
        match serde_json::from_value::<InterceptionEntry>(result) {
            Ok(entry) => return Ok(Some(entry)),
            Err(e) => {
                eprintln!("[Interception] Failed to parse IPC peek result: {}", e);
                // 解析失败，回退到本地查询
                //  Parse failed, fall back to local query
            }
        }
    }

    // 独立模式或 IPC 解析失败：返回本地当前拦截条目
    //  Standalone mode or IPC parse failed: return local current interception entry
    Ok(interception.peek_current())
}
