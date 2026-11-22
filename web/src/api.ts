// Types mirror the Go JSON structs in internal/report, internal/score and internal/detect.

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface Finding {
  rule_id: string
  description: string
  severity: Severity
  file: string
  line: number
  column: number
  masked: string
  fingerprint: string
}

export interface Contribution {
  severity: Severity
  count: number
  weight: number
  penalty: number
}

export interface Score {
  value: number
  grade: string
  capped: boolean
  reason?: string
  breakdown: Contribution[]
}

export interface Report {
  tool: string
  version: string
  target: string
  started_at: string
  duration_ms: number
  files_scanned: number
  files_skipped: number
  incomplete: boolean
  score: Score
  findings: Finding[]
  errors: { file: string; error: string }[]
}

export type ScanRequest = { demo: true } | { repo_url: string }

export const severityRank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }

export async function startScan(req: ScanRequest, signal: AbortSignal): Promise<Report> {
  const res = await fetch('/api/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
    signal,
  })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error(body.error ?? `Request failed (HTTP ${res.status})`)
  }
  return body as Report
}
