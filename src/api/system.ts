/**
 * 系统信息 API 封装
 * System info API wrapper
 *
 * 封装 CPU 信息、进程列表等系统级操作。
 * Wraps CPU info, process list, and other system-level operations.
 */
import { invoke } from '@tauri-apps/api/core'

/** 系统信息接口 / System info interface */
export interface SystemInfo {
  cpuName: string
  cpuCores: number
  platform: string
  arch: string
  hostname: string
}

/** 运行进程接口 / Running process interface */
export interface RunningProcess {
  pid: number
  name: string
}

/**
 * 函数名称：getSystemInfo
 * 函数作用：获取系统 CPU 和基本信息。
 * Purpose: Gets system CPU and basic info.
 * Called by: OverviewPage
 * 中文关键词：系统信息，CPU信息
 * English keywords: system info, CPU info
 */
export async function getSystemInfo(): Promise<SystemInfo> {
  return await invoke('get_system_info')
}

/**
 * 函数名称：getRunningProcesses
 * 函数作用：获取当前运行的所有进程列表。
 * Purpose: Gets all currently running processes.
 * Called by: BehaviorPage 进程选择器
 * 中文关键词：进程列表，运行进程
 * English keywords: process list, running processes
 */
export async function getRunningProcesses(): Promise<RunningProcess[]> {
  return await invoke('get_running_processes')
}
