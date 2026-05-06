// 拦截命令 — 拦截弹窗操作和队列管理
// Interception commands — interception modal operations and queue management
use crate::services::interception_service::{InterceptionDecision, InterceptionService};
use crate::services::trust_service::TrustService;

/// 函数名称：handle_interception
/// 函数作用：处理用户的拦截决策（放行/阻止指定 PID 的进程）。
/// Purpose: Handles user's interception decision (allow/block the process identified by PID).
/// 参数 pid: 目标进程 PID / Target process PID
/// 参数 action: 决策操作 "allow" 或 "block" / Decision action "allow" or "block"
/// 副作用：若阻止，则终止进程；若放行，则恢复进程
/// 调用方：前端 InterceptionModal 阻止/允许按钮
/// Called by: Frontend InterceptionModal block/allow buttons
/// 中文关键词：拦截决策，放行进程，阻止进程，终止进程，恢复进程
/// English keywords: interception decision, allow process, block process, terminate process, resume process
#[tauri::command]
pub async fn handle_interception(
    pid: u32,
    action: String,
    interception: tauri::State<'_, InterceptionService>,
) -> Result<bool, String> {
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

    // 记录决策 / Record decision
    interception.mark_decision(pid, decision);

    // 若阻止，则终止进程 / If block, terminate the process
    if decision == InterceptionDecision::Block {
        // 调用进程终止命令 / Call process terminate
        super::process::terminate_process_internal(pid).await?;
    }

    // 尝试展示下一个弹窗 / Try to show next modal
    // (AppHandle 由前端通过监听事件处理)
    Ok(true)
}

/// 函数名称：get_interception_queue
/// 函数作用：获取当前拦截队列中的所有暂停进程 PID。
/// Purpose: Gets all paused process PIDs in the current interception queue.
/// 调用方：前端概览页查询拦截状态
/// Called by: Frontend overview page querying interception status
/// 中文关键词：拦截队列，暂停进程列表，队列状态
/// English keywords: interception queue, paused process list, queue status
#[tauri::command]
pub async fn get_interception_queue(
    interception: tauri::State<'_, InterceptionService>,
) -> Result<Vec<u32>, String> {
    Ok(interception.get_paused_pids())
}

/// 函数名称：clear_interception_queue
/// 函数作用：清空所有拦截队列和决策记录。
/// Purpose: Clears all interception queues and decision records.
/// 调用方：前端操作
/// Called by: Frontend operation
/// 中文关键词：清空队列，重置拦截
/// English keywords: clear queue, reset interception
#[tauri::command]
pub async fn clear_interception_queue(
    interception: tauri::State<'_, InterceptionService>,
) -> Result<bool, String> {
    interception.clear_all();
    Ok(true)
}

/// 函数名称：get_interception_status
/// 函数作用：获取拦截服务的当前状态（队列大小、是否正在展示弹窗）。
/// Purpose: Gets current status of the interception service (queue size, whether a modal is showing).
/// 调用方：前端概览页
/// Called by: Frontend overview page
/// 中文关键词：拦截状态，队列大小，弹窗状态
/// English keywords: interception status, queue size, modal state
#[tauri::command]
pub async fn get_interception_status(
    interception: tauri::State<'_, InterceptionService>,
) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "queueSize": interception.get_queue_size(),
        "pausedPids": interception.get_paused_pids(),
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
    trust: tauri::State<'_, TrustService>,
) -> Result<serde_json::Value, String> {
    let signer = trust.get_signer_info(&file_path)?;
    Ok(serde_json::json!({
        "subject": signer.subject,
        "issuer": signer.issuer,
        "thumbprint": signer.thumbprint,
    }))
}
