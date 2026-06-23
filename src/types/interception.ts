export interface InterceptionData {
  title: string
  message: string
  processName: string
  riskLevel: 'high' | 'medium' | 'low'
  filePath?: string
  pid?: number
}
