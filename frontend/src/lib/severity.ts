export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

// Event severity is the raw Wazuh rule level (0–15): 12+ high-importance,
// 15 severe. Sysmon-derived events carry none and read as informational.
export function eventSeverity(level: number | null): Severity {
  if (level === null || level === 0) return 'info'
  if (level >= 12) return 'critical'
  if (level >= 8) return 'high'
  if (level >= 4) return 'medium'
  return 'low'
}

// Evidence score is the correlation engine's 0–100 risk score.
export function scoreSeverity(score: number): Severity {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 40) return 'medium'
  return 'low'
}

// Wazuh level threshold behind the dashboard's "Critical (24h)" tile.
export const CRITICAL_EVENT_LEVEL = 12

export const severityText: Record<Severity, string> = {
  critical: 'text-sev-critical',
  high: 'text-sev-high',
  medium: 'text-sev-medium',
  low: 'text-sev-low',
  info: 'text-sev-info',
}

export const severityDot: Record<Severity, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
}
