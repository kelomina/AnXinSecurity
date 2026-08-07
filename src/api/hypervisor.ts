/**
 * 元核防护 API 封装
 * Hypervisor protection API wrapper
 *
 * 封装 AnXinHypervisor.sys 驱动相关的 invoke 调用：状态查询、开关、启停。
 * Wraps every invoke call related to the AnXinHypervisor driver: status, switch, start/stop.
 *
 * 按 AGENTS.md 的分层要求，本层只做 invoke 包装，不含任何状态或业务判断。
 * Per the layering rule in AGENTS.md this layer only wraps invoke; it holds no
 * state and makes no business decisions.
 *
 * 中文关键词：元核防护 API，驱动调用，环境检查
 * English keywords: hypervisor API, driver invocation, environment check
 */
import { invoke } from '@tauri-apps/api/core'

/** 元核防护运行状态 / Hypervisor runtime status */
export interface HypervisorStatus {
  /** 驱动服务是否已启动且设备可连接 / Whether the driver service is started and the device is connectable */
  driverConnected: boolean
  /** 驱动运行模式（0=full, 1=degraded_hyperv, ...） / Driver operating mode */
  operatingMode: number
  /** 模式名称（full / degraded_hyperv / degraded_cpu 等） / Mode name */
  modeName: string
  /** CPU 厂商（Intel / AMD / Unknown） / CPU vendor */
  cpuVendor: string
  /** 虚拟化 CPU 数量（降级模式下为 0） / Number of virtualized CPUs (0 in degraded mode) */
  cpuCount: number
  /** 页表是否激活（EPT/NPT） / Whether page tables (EPT/NPT) are active */
  pageTablesActive: boolean
  /** 降级原因（降级模式下由驱动填写） / Degradation reason (filled by the driver in degraded mode) */
  degradReason: string
  /** 驱动版本号 / Driver version */
  versionMajor: number
  versionMinor: number
  versionPatch: number
}

/** 未连接驱动时的占位状态 / Placeholder status while the driver is not connected */
export const EMPTY_HYPERVISOR_STATUS: HypervisorStatus = {
  driverConnected: false,
  operatingMode: 0,
  modeName: '',
  cpuVendor: '',
  cpuCount: 0,
  pageTablesActive: false,
  degradReason: '',
  versionMajor: 0,
  versionMinor: 0,
  versionPatch: 0,
}

/**
 * 函数名称：getHypervisorStatus
 * 函数作用：查询元核防护运行状态。
 * Purpose: Queries the hypervisor runtime status.
 * 调用方：hypervisorStore.refreshStatus()
 * Called by: hypervisorStore.refreshStatus()
 * 中文关键词：元核防护状态，驱动连接
 * English keywords: hypervisor status, driver connection
 */
export async function getHypervisorStatus(): Promise<HypervisorStatus> {
  return await invoke('get_hypervisor_status')
}

/**
 * 函数名称：startHypervisor
 * 函数作用：环境检查 → 启动驱动服务 → 连接设备 → 查询状态。
 * Purpose: Environment check → start driver service → connect device → query status.
 * 调用方：hypervisorStore.setEnabled()
 * Called by: hypervisorStore.setEnabled()
 * 中文关键词：启动元核防护，环境检查
 * English keywords: hypervisor start, environment check
 */
export async function startHypervisor(): Promise<HypervisorStatus> {
  return await invoke('start_hypervisor')
}

/**
 * 函数名称：stopHypervisor
 * 函数作用：停止元核防护，断开设备连接并停止驱动服务。
 * Purpose: Stops hypervisor protection, disconnects the device and stops the driver service.
 * 调用方：hypervisorStore.setEnabled()
 * Called by: hypervisorStore.setEnabled()
 * 中文关键词：停止元核防护，恢复默认
 * English keywords: hypervisor stop, revert to default
 */
export async function stopHypervisor(): Promise<boolean> {
  return await invoke('stop_hypervisor')
}

/**
 * 函数名称：setHypervisorEnabled
 * 函数作用：设置元核防护总开关并持久化到 app.json。
 * Purpose: Sets the master switch and persists it to app.json.
 * 副作用：后端写 config/app.json
 * Side effects: the backend writes config/app.json
 * 中文关键词：总开关，配置持久化
 * English keywords: master switch, config persistence
 */
export async function setHypervisorEnabled(enabled: boolean): Promise<boolean> {
  return await invoke('set_hypervisor_enabled', { enabled })
}
