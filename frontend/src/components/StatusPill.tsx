import type { CaseStatus } from '../lib/api'

// Case workflow pills (§4.4): each status a distinct color from the
// severity/accent families. Resolved is emerald — green = safe, always.
const styles: Record<CaseStatus, string> = {
  new: 'border-sev-info/50 text-sev-info',
  investigating: 'border-sev-medium/50 text-sev-medium',
  contained: 'border-sev-high/50 text-sev-high',
  resolved: 'border-accent/50 text-accent',
  closed: 'border-strong text-tertiary',
}

export function StatusPill({ status }: { status: CaseStatus }) {
  return (
    <span
      className={`inline-block rounded-full border-[0.5px] px-2 py-0.5 text-[11px] leading-4 ${styles[status]}`}
    >
      {status}
    </span>
  )
}
