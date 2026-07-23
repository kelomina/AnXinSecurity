// 权限检查命令
//  Privilege check commands
//
// 中文关键词：管理员权限，权限检查，UAC，IPC 连接状态
// English keywords: administrator privilege, privilege check, UAC, IPC connection status
use serde::Serialize;
use tauri::State;

use crate::services::ipc_bridge_service::IpcBridgeService;
use crate::services::privilege_service::PrivilegeService;

/// 权限状态返回给前端
///  Privilege status returned to frontend
#[derive(Debug, Clone, Serialize)]
pub struct PrivilegeStatus {
    /// 是否以管理员权限运行
    ///  Whether running with administrator privileges
    pub is_elevated: bool,
    /// 是否已连接到服务进程（防护由 SYSTEM 服务提供）
    ///  Whether connected to service process (protection provided by SYSTEM service)
    pub service_connected: bool,
}

/// 函数名称：get_privilege_status
/// 函数作用：返回当前进程的权限状态。
///           UI 进程以普通用户权限运行是正常的——只要 IPC 连接到服务进程，
///           防护就由 SYSTEM 服务提供，前端不应显示权限不足提示。
/// Purpose: Returns current process privilege status.
///          UI process running as normal user is expected — as long as IPC
///          is connected to the service process, protection is provided by
///          the SYSTEM service and frontend should not show privilege warning.
/// 调用方：前端 App.tsx 启动时
/// Called by: Frontend App.tsx on startup
/// 中文关键词：权限状态，管理员，检查，IPC 连接
/// English keywords: privilege status, administrator, check, IPC connection
#[tauri::command]
pub async fn get_privilege_status(
    ipc_bridge: State<'_, std::sync::Arc<IpcBridgeService>>,
) -> Result<PrivilegeStatus, String> {
    let service_connected = ipc_bridge.is_connected();
    // 防护可用条件：UI 进程本身是管理员，或者已连接到 SYSTEM 服务进程
    //  Protection available condition: UI process is admin itself, OR connected to SYSTEM service process
    let is_elevated = PrivilegeService::is_elevated();
    Ok(PrivilegeStatus {
        is_elevated: is_elevated || service_connected,
        service_connected,
    })
}

/// 函数名称：is_protection_available
/// 函数作用：检查防护功能是否可用。UI 进程是管理员 或 已连接服务进程都算可用。
/// Purpose: Checks if protection features are available. UI process is admin OR connected to service.
/// 调用方：前端 OverviewPage
/// Called by: Frontend OverviewPage
/// 中文关键词：防护可用，权限，IPC 连接
/// English keywords: protection available, privilege, IPC connection
#[tauri::command]
pub async fn is_protection_available(
    ipc_bridge: State<'_, std::sync::Arc<IpcBridgeService>>,
) -> Result<bool, String> {
    let service_connected = ipc_bridge.is_connected();
    Ok(PrivilegeService::is_elevated() || service_connected)
}
