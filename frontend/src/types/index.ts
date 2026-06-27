export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Vulnerability {
  id: string
  title: string
  severity: Severity
  category: string
  description: string
  evidence: string
  remediation: string
  cwe: string
  cvss_score: number
  endpoint: string
  method: string
  request_details: Record<string, unknown>
  response_details: Record<string, unknown>
  references: string[]
  false_positive_likelihood: string
}

export interface ScanLogEntry {
  time: string
  module: string
  status: 'running' | 'done' | 'error' | 'timeout'
  message: string
  found?: number
}

export interface Scan {
  id: string
  target_url: string
  name: string | null
  status: ScanStatus
  scan_types: string[]
  progress: number
  total_vulnerabilities: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  risk_score: number
  created_at: string | null
  started_at: string | null
  completed_at: string | null
  endpoints_tested: number
  requests_made: number
  error_message: string | null
}

export interface ScanDetail extends Scan {
  vulnerabilities: Vulnerability[]
  scan_log: ScanLogEntry[]
}

export interface ScanStats {
  total_scans: number
  completed_scans: number
  running_scans: number
  total_vulnerabilities: number
  critical_total: number
  high_total: number
  medium_total: number
  avg_risk_score: number
  recent_scans: Scan[]
}

export interface WsMessage {
  scan_id: string
  status: ScanStatus
  progress: number
  total_vulnerabilities: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  log: ScanLogEntry[]
}
