import type { InterceptionData } from '../types/interception'

type TranslateFn = (key: string, fallback?: string) => string

export function parseInterceptionPayload(rawPayload: unknown): Record<string, unknown> {
  if (typeof rawPayload === 'string') {
    try {
      const parsed = JSON.parse(rawPayload)
      return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : {}
    } catch {
      return {}
    }
  }
  return rawPayload && typeof rawPayload === 'object' ? rawPayload as Record<string, unknown> : {}
}

export function normalizeRiskLevel(value: unknown): InterceptionData['riskLevel'] {
  return value === 'high' || value === 'low' ? value : 'medium'
}

export function interceptionReasonI18nKey(reasonCode: string): string | null {
  const reasonKeys: Record<string, string> = {
    masquerade_path_mismatch: 'intercept_reason_masquerade_path_mismatch',
    certificate_revoked: 'intercept_reason_certificate_revoked',
    revocation_target_changed: 'intercept_reason_revocation_target_changed'
  }
  return reasonKeys[reasonCode] ?? null
}

export function normalizeInterceptionEventPayload(
  payload: Record<string, unknown>,
  t: TranslateFn
): InterceptionData {
  const riskPayload = parseInterceptionPayload(payload.payload)
  const reasonCode = typeof riskPayload.reasonCode === 'string' ? riskPayload.reasonCode : ''
  const reasonKey = interceptionReasonI18nKey(reasonCode)
  const reasonMessage =
    reasonKey
      ? t(reasonKey, '已拦截可疑行为，请选择允许或阻止。')
      : (payload.message as string) || t('intercept_desc_action_required', '已拦截可疑行为，请选择允许或阻止。')
  const title =
    reasonKey
      ? t('intercept_title', '威胁拦截')
      : (payload.title as string) || t('intercept_title', '威胁拦截')

  return {
    title,
    message: reasonMessage,
    processName: (payload.processName as string) || t('intercept_unknown_process', '未知进程'),
    riskLevel: normalizeRiskLevel(payload.riskLevel),
    filePath: payload.filePath as string | undefined,
    pid: payload.pid as number | undefined,
  }
}
