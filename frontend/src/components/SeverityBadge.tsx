import type { Severity } from '../lib/severity'

// Filled tint + same-family text (§5 badges). Severity color never
// appears as a large fill — badges, dots, and graph nodes only.
const styles: Record<Severity, string> = {
  critical: 'text-sev-critical bg-sev-critical/15',
  high: 'text-sev-high bg-sev-high/15',
  medium: 'text-sev-medium bg-sev-medium/15',
  low: 'text-sev-low bg-sev-low/15',
  info: 'text-sev-info bg-sev-info/15',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block rounded-full px-2 py-0.5 text-[11px] leading-4 ${styles[severity]}`}
    >
      {severity}
    </span>
  )
}
