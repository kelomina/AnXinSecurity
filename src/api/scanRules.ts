/**
 * 扫描规则 API 封装
 * Scan rules API wrapper
 */
import { invoke } from '@tauri-apps/api/core'

export interface ScanRule {
  ruleId: string
  threatType: string
  threatName?: string
  provider: string
  op: string
  targetContains?: string
  targetPrefix?: string
  targetPatterns?: string[]
  severity: number
  description?: string
}

export async function loadScanRules(): Promise<ScanRule[]> {
  return await invoke('load_scan_rules')
}

/** MITRE ATT&CK 映射项 / MITRE ATT&CK mapping entry */
export interface MitreRule {
  provider: string
  op: string
  tactic: string
  techniqueId: string
  techniqueName: string
}

/**
 * 函数名称：loadMitreRules
 * 函数作用：从 config/app.json 加载 MITRE ATT&CK 映射规则。
 * Purpose: Loads MITRE ATT&CK mapping rules from config/app.json.
 * 调用方：BehaviorLifecyclePage (行为生命周期页)
 * Called by: BehaviorLifecyclePage (behavior lifecycle page)
 * 中文关键词：MITRE规则，ATT&CK映射，威胁情报，配置加载
 * English keywords: MITRE rules, ATT&CK mapping, threat intelligence, config loading
 */
export async function loadMitreRules(): Promise<MitreRule[]> {
  const config = await invoke<{ enabled: boolean; rules: MitreRule[] }>('load_mitre_rules')
  return config?.rules || []
}
