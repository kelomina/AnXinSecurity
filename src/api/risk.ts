/**
 * 风险分析 API 封装
 * Risk analysis API wrapper
 *
 * 封装风险状态查询和实时风险事件监听。
 * Wraps risk status queries and real-time risk event listening.
 */
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'

/** 风险事件数据结构/Risk event data structure */
export interface RiskEvent {
  pid: number
  processName: string
  filePath?: string
  threatType: string
  threatName?: string
  severity: number
  ruleId: string
  description: string
  timestamp: number
}

/** 风险研判结果/Risk assessment result */
export interface RiskAssessment {
  event: RiskEvent
  riskLevel: 'high' | 'medium' | 'low'
  shouldIntercept: boolean
  reason: string
}

/** 风险状态/Risk status */
export interface RiskStatus {
  eventCount: number
}

/**
 * 函数名称：getRiskStatus
 * 函数作用：获取风险分析服务状态（事件总数等）。
 * Purpose: Gets risk analysis service status (total events, etc.).
 * 调用方：OverviewPage (概览页风险卡片)
 * Called by: OverviewPage (overview risk card)
 * 中文关键词：风险状态，风险统计，事件计数
 * English keywords: risk status, risk statistics, event count
 */
export async function getRiskStatus(): Promise<RiskStatus> {
  return await invoke('get_risk_status')
}

/**
 * 函数名称：onRiskEvent
 * 函数作用：监听实时风险事件推送。后端通过 Tauri Events 推送每个风险研判结果。
 * Purpose: Listens for real-time risk event pushes from the backend via Tauri Events.
 * 调用方：OverviewPage (概览页风险卡片实时更新)
 * Called by: OverviewPage (overview risk card real-time update)
 * 参数：callback — 接收 RiskAssessment 的回调函数
 * 返回值：Promise，resolve 为取消监听的清理函数
 * 中文关键词：风险事件，实时监听，风险推送，风险研判
 * English keywords: risk event, real-time listener, risk push, risk assessment
 */
export async function onRiskEvent(
  callback: (assessment: RiskAssessment) => void
): Promise<() => void> {
  const unlisten = await listen('etw-risk-event', (event) => {
    callback(event.payload as RiskAssessment)
  })

  return () => {
    unlisten()
  }
}
