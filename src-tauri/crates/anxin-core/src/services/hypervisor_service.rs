// 元核防护服务 — AnXinHypervisor.sys 的用户态编排层
//  Hypervisor service - the user-mode orchestration layer for AnXinHypervisor.sys
//
// 职责 / Responsibilities:
// - 环境检查：确认驱动已安装、服务可启动
//   Environment check: confirm the driver is installed and the service can start
// - 启动/停止驱动服务（OnDemand 模式）
//   Start/stop the driver service (OnDemand mode)
// - 连接驱动设备，查询运行模式和降级原因
//   Connect to the driver device, query operating mode and degradation reason
//
// 关键安全性质 / Key safety property:
// 驱动缺失、服务不存在、连接失败都不是致命错误。任何一种情况下服务都退回
// 「未接管」状态，系统行为与没装这个模块时完全一致。
//  A missing driver, a missing service or a failed connection are all
//  non-fatal. In every case the service falls back to the detached state,
//  and the system behaves exactly as if this module were not installed.
//
// 中文关键词：元核防护，Hypervisor 服务，按需加载，降级运行
// English keywords: hypervisor service, on-demand load, graceful degradation

use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::services::driver_install_service::DriverKind;
use crate::utils::hv_client::{HvClient, HvStatusInfo};

/// 前端事件名：元核防护状态变化
///  Frontend event name for hypervisor status changes
pub const EVENT_HYPERVISOR_STATUS: &str = "hypervisor-status";

// ============================================================================
// 前端数据类型 / Frontend-facing data types
// ============================================================================

/// 元核防护运行状态，供概览页与设置页展示。
///  Hypervisor runtime status for the overview and settings pages.
///
/// 驱动缺失或未启动时 `driverConnected` 为 false 而不是报错：
/// 前端只需要知道「没在跑」，弹一个红色错误对用户没有任何帮助。
///  When the driver is missing or not started, `driverConnected` is false
///  rather than an error: the frontend only needs to know it is not running,
///  and a red error banner helps the user with nothing.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HypervisorStatus {
    /// 驱动服务是否已启动且设备可连接
    ///  Whether the driver service is started and the device is connectable
    pub driverConnected: bool,
    /// 驱动运行模式（0=full, 1=degraded_hyperv, ... 详见 HvStatusInfo::mode_name）
    ///  Driver operating mode (0=full, 1=degraded_hyperv, ... see HvStatusInfo::mode_name)
    pub operatingMode: u32,
    /// 模式名称（full / degraded_hyperv / degraded_cpu 等）
    ///  Mode name (full / degraded_hyperv / degraded_cpu, etc.)
    pub modeName: String,
    /// CPU 厂商（Intel / AMD / Unknown）
    ///  CPU vendor (Intel / AMD / Unknown)
    pub cpuVendor: String,
    /// 虚拟化 CPU 数量（降级模式下为 0）
    ///  Number of virtualized CPUs (0 in degraded mode)
    pub cpuCount: u32,
    /// 页表是否激活（EPT/NPT）
    ///  Whether page tables (EPT/NPT) are active
    pub pageTablesActive: bool,
    /// 降级原因（降级模式下由驱动填写）
    ///  Degradation reason (filled by the driver in degraded mode)
    pub degradReason: String,
    /// 驱动版本号
    ///  Driver version
    pub versionMajor: u32,
    pub versionMinor: u32,
    pub versionPatch: u32,
}

impl HypervisorStatus {
    /// 从驱动 IOCTL 返回的状态信息转换为前端状态。
    ///  Convert IOCTL status info to frontend status.
    fn from_status(info: &HvStatusInfo) -> Self {
        Self {
            driverConnected: true,
            operatingMode: info.operating_mode,
            modeName: info.mode_name().to_string(),
            cpuVendor: info.vendor_name().to_string(),
            cpuCount: info.cpu_count,
            pageTablesActive: info.page_tables_active != 0,
            degradReason: info.reason_string(),
            versionMajor: info.version_major,
            versionMinor: info.version_minor,
            versionPatch: info.version_patch,
        }
    }
}

// ============================================================================
// HypervisorService / HypervisorService
// ============================================================================

/// 元核防护服务。状态由内部 Mutex 保护，可被多线程（命令层、main 启动路径）安全调用。
///  Hypervisor service. State is guarded by an internal Mutex and is safe to
///  call from multiple threads (command layer, main startup path).
pub struct HypervisorService {
    inner: Mutex<Inner>,
}

struct Inner {
    /// 已连接的驱动客户端（None 表示未连接）
    ///  Connected driver client (None means not connected)
    client: Option<HvClient>,
}

impl HypervisorService {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner { client: None }),
        }
    }

    /// 环境检查：确认驱动文件已安装、服务存在且可启动。
    ///  Environment check: confirm the driver file is installed, the service
    ///  exists and can be started.
    ///
    /// 返回 Ok(()) 表示环境就绪；Err 包含可读的失败原因。
    ///  Returns Ok(()) if the environment is ready; Err contains a readable
    ///  failure reason.
    pub fn check_environment(&self) -> Result<(), String> {
        use windows_service::service::{ServiceAccess, ServiceState};
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| format!("无法打开服务管理器: {}", e))?;

        let service = manager
            .open_service(
                DriverKind::Hypervisor.service_name(),
                ServiceAccess::QUERY_STATUS,
            )
            .map_err(|e| {
                format!(
                    "元核防护驱动服务未安装: {}。请先通过安装程序安装 AnXinHypervisor 驱动。",
                    e
                )
            })?;

        let status = service
            .query_status()
            .map_err(|e| format!("无法查询驱动服务状态: {}", e))?;

        // 服务存在即视为环境就绪。允许当前状态为 Stopped（start 时再启动），
        // 但如果是 StartPending/StopPending 等过渡态则拒绝。
        //  Service existence means the environment is ready. A Stopped state is
        //  acceptable (start will start it), but transitional states are rejected.
        match status.current_state {
            ServiceState::Stopped | ServiceState::Running => Ok(()),
            other => Err(format!(
                "驱动服务当前处于 {:?} 状态，请稍后再试",
                other
            )),
        }
    }

    /// 启动元核防护：环境检查 → 启动驱动服务 → 连接设备 → 查询状态。
    ///  Start hypervisor protection: env check → start driver service →
    ///  connect device → query status.
    ///
    /// 驱动缺失、服务启动失败、设备连接失败都返回 Err，由前端提示用户。
    ///  A missing driver, a service start failure or a device connection
    ///  failure all return Err for the frontend to surface to the user.
    pub fn start(&self) -> Result<HypervisorStatus, String> {
        // 1. 环境检查
        //  1. Environment check
        self.check_environment()?;

        // 2. 启动驱动服务（OnDemand）
        //  2. Start the driver service (OnDemand)
        crate::services::driver_install_service::start_driver_service_by_kind(
            DriverKind::Hypervisor,
        )?;

        // 3. 连接设备并查询状态
        //  3. Connect to the device and query status
        let client = HvClient::connect()
            .map_err(|e| format!("无法连接元核防护驱动设备: {}", e))?;
        let info = client
            .get_status()
            .map_err(|e| format!("查询元核防护状态失败: {}", e))?;

        let status = HypervisorStatus::from_status(&info);

        let mut inner = self.inner.lock().map_err(|e| e.to_string())?;
        inner.client = Some(client);

        Ok(status)
    }

    /// 停止元核防护：断开设备连接 → 停止驱动服务。
    ///  Stop hypervisor protection: disconnect device → stop driver service.
    ///
    /// 任何步骤失败都返回 Err，但会尽力清理已建立的连接。
    ///  Any step failure returns Err, but established connections are cleaned up.
    pub fn stop(&self) -> Result<(), String> {
        // 1. 断开设备连接（释放客户端句柄）
        //  1. Disconnect the device (release the client handle)
        {
            let mut inner = self.inner.lock().map_err(|e| e.to_string())?;
            inner.client = None; // Drop 会自动 CloseHandle
        }

        // 2. 停止驱动服务
        //  2. Stop the driver service
        crate::services::driver_install_service::stop_driver_service_by_kind(
            DriverKind::Hypervisor,
        )?;

        Ok(())
    }

    /// 查询当前运行状态。未连接时返回 driverConnected=false 的默认状态。
    ///  Query the current runtime status. Returns a default status with
    ///  driverConnected=false when not connected.
    pub fn status(&self) -> HypervisorStatus {
        let inner = self.inner.lock();
        let Ok(inner) = inner else {
            return HypervisorStatus::default();
        };

        match &inner.client {
            None => HypervisorStatus::default(),
            Some(client) => match client.get_status() {
                Ok(info) => HypervisorStatus::from_status(&info),
                Err(_) => HypervisorStatus::default(),
            },
        }
    }
}

impl Default for HypervisorService {
    fn default() -> Self {
        Self::new()
    }
}
