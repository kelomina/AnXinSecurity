/**
 * 权限检查 API 封装
 * Privilege check API wrapper
 *
 * 封装管理员权限状态查询，前端启动时调用以提示用户。
 * Wraps admin privilege status query, called by frontend on startup to prompt user.
 */
import { invoke } from '@tauri-apps/api/core'

/** 权限状态接口 / Privilege status interface */
export interface PrivilegeStatus {
  /** 防护是否可用（UI 是管理员 或 已连接 SYSTEM 服务）/ Whether protection is available (UI is admin OR connected to SYSTEM service) */
  is_elevated: boolean
  /** 是否已连接到服务进程 / Whether connected to service process */
  service_connected: boolean
}

/**
 * 函数名称：getPrivilegeStatus
 * 函数作用：获取当前进程的权限状态。
 * Purpose: Gets current process privilege status.
 * Called by: App.tsx 启动时
 * 中文关键词：权限状态，管理员，检查
 * English keywords: privilege status, administrator, check
 */
export async function getPrivilegeStatus(): Promise<PrivilegeStatus> {
  return await invoke('get_privilege_status')
}

/**
 * 函数名称：isProtectionAvailable
 * 函数作用：检查防护功能是否可用（需要管理员权限）。
 * Purpose: Checks if protection features are available (requires admin privileges).
 * Called by: OverviewPage
 * 中文关键词：防护可用，权限
 * English keywords: protection available, privilege
 */
export async function isProtectionAvailable(): Promise<boolean> {
  return await invoke('is_protection_available')
}
