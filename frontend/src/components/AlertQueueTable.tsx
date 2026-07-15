import { useNavigate } from 'react-router-dom'
import { ArrowUpRight, Check, Sparkles, X } from 'lucide-react'
import type { EvidenceItem, EvidenceStatus } from '../lib/api'
import { formatCount, formatUtcDateTime, relativeAge } from '../lib/format'
import { scoreSeverity } from '../lib/severity'
import { ArgusMark } from './ArgusMark'
import { SeverityBadge } from './SeverityBadge'

function signalLabel(item: EvidenceItem): string {
  if (item.tactics.length > 0) return item.tactics.join(' · ')
  return 'correlated activity'
}

// Triage states: escalated screams, open is calm blue, the rest recede.
const statusStyles: Record<EvidenceStatus, string> = {
  open: 'border-sev-info/50 text-sev-info',
  acknowledged: 'border-sev-medium/50 text-sev-medium',
  escalated: 'border-sev-critical/50 text-sev-critical',
  dismissed: 'border-strong text-tertiary',
}

function EvidenceStatusPill({ status }: { status: EvidenceStatus }) {
  return (
    <span
      className={`inline-block rounded-full border-[0.5px] px-2 py-0.5 text-[11px] leading-4 ${statusStyles[status]}`}
    >
      {status}
    </span>
  )
}

function SkeletonRows() {
  return (
    <>
      {Array.from({ length: 5 }, (_, i) => (
        <tr key={i} className="border-t-[0.5px] border-subtle">
          <td colSpan={7} className="px-3 py-3">
            <div
              className="h-4 animate-pulse rounded bg-hover"
              style={{ animationDelay: `${i * 120}ms` }}
            />
          </td>
        </tr>
      ))}
    </>
  )
}

interface TriageActionProps {
  label: string
  title: string
  icon: React.ReactNode
  onClick: () => void
  disabled?: boolean
  tone?: 'danger'
}

function TriageAction({ label, title, icon, onClick, disabled, tone }: TriageActionProps) {
  return (
    <button
      type="button"
      title={title}
      aria-label={title}
      disabled={disabled}
      onClick={onClick}
      className={`inline-flex items-center gap-1 rounded-control border-[0.5px] border-subtle px-1.5 py-1 text-[11px] leading-4 opacity-0 transition-opacity duration-120 focus-visible:opacity-100 group-hover:opacity-100 disabled:cursor-wait ${
        tone === 'danger'
          ? 'text-tertiary hover:border-sev-critical/50 hover:text-sev-critical'
          : 'text-secondary hover:bg-hover hover:text-primary'
      }`}
    >
      {icon}
      {label}
    </button>
  )
}

interface AlertQueueTableProps {
  items: EvidenceItem[] | undefined
  loading: boolean
  showStatus?: boolean
  emptyMessage: string
  onSetStatus?: (id: number, status: EvidenceStatus) => void
  busyId?: number | null
}

export function AlertQueueTable({
  items,
  loading,
  showStatus,
  emptyMessage,
  onSetStatus,
  busyId,
}: AlertQueueTableProps) {
  const navigate = useNavigate()
  const columns = showStatus ? 8 : 7

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-label">
        <thead>
          <tr className="text-left text-tertiary">
            <th className="px-3 py-2 font-normal">Severity</th>
            <th className="px-3 py-2 font-normal">Signal</th>
            <th className="px-3 py-2 font-normal">MITRE</th>
            <th className="px-3 py-2 font-normal">Asset</th>
            <th className="px-3 py-2 text-right font-normal">Events</th>
            {showStatus && <th className="px-3 py-2 font-normal">Status</th>}
            <th className="px-3 py-2 text-right font-normal">Age</th>
            <th className="px-3 py-2" aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {loading && <SkeletonRows />}
          {!loading && items?.length === 0 && (
            <tr className="border-t-[0.5px] border-subtle">
              <td colSpan={columns} className="px-3 py-10">
                <div className="flex flex-col items-center gap-3">
                  <ArgusMark size={44} className="opacity-20" />
                  <span className="text-tertiary">{emptyMessage}</span>
                </div>
              </td>
            </tr>
          )}
          {items?.map((item) => (
            <tr
              key={item.id}
              className="group border-t-[0.5px] border-subtle transition-colors duration-120 hover:bg-hover"
            >
              <td className="px-3 py-2">
                <SeverityBadge severity={scoreSeverity(item.score)} />
              </td>
              <td className="max-w-64 truncate px-3 py-2 text-primary">{signalLabel(item)}</td>
              <td className="px-3 py-2 font-mono text-data text-secondary">
                {item.technique_ids.join(', ') || '—'}
              </td>
              <td className="px-3 py-2 font-mono text-data text-secondary">
                {item.host_name ?? '—'}
              </td>
              <td className="px-3 py-2 text-right font-mono text-data text-secondary">
                {formatCount(item.event_count)}
              </td>
              {showStatus && (
                <td className="px-3 py-2">
                  <EvidenceStatusPill status={item.status} />
                </td>
              )}
              <td
                className="px-3 py-2 text-right font-mono text-data text-tertiary"
                title={formatUtcDateTime(item.window_end)}
              >
                {relativeAge(item.window_end)}
              </td>
              <td className="px-3 py-2">
                <div className="flex items-center justify-end gap-1">
                  {onSetStatus && item.status !== 'acknowledged' && item.status !== 'dismissed' && (
                    <TriageAction
                      label="Ack"
                      title="Acknowledge"
                      icon={<Check size={11} strokeWidth={1.5} />}
                      disabled={busyId === item.id}
                      onClick={() => onSetStatus(item.id, 'acknowledged')}
                    />
                  )}
                  {onSetStatus && item.status !== 'escalated' && item.status !== 'dismissed' && (
                    <TriageAction
                      label="Escalate"
                      title="Escalate"
                      icon={<ArrowUpRight size={11} strokeWidth={1.5} />}
                      disabled={busyId === item.id}
                      onClick={() => onSetStatus(item.id, 'escalated')}
                    />
                  )}
                  {onSetStatus && item.status !== 'dismissed' && (
                    <TriageAction
                      label="Dismiss"
                      title="Dismiss"
                      tone="danger"
                      icon={<X size={11} strokeWidth={1.5} />}
                      disabled={busyId === item.id}
                      onClick={() => onSetStatus(item.id, 'dismissed')}
                    />
                  )}
                  {onSetStatus && item.status === 'dismissed' && (
                    <TriageAction
                      label="Reopen"
                      title="Reopen"
                      icon={<Check size={11} strokeWidth={1.5} />}
                      disabled={busyId === item.id}
                      onClick={() => onSetStatus(item.id, 'open')}
                    />
                  )}
                  <button
                    type="button"
                    onClick={() => navigate(`/workspace?evidence=${item.id}`)}
                    className="inline-flex items-center gap-1.5 rounded-control bg-accent-bg px-2 py-1 text-[11px] leading-4 text-accent opacity-0 transition-opacity duration-120 focus-visible:opacity-100 group-hover:opacity-100"
                  >
                    <Sparkles size={11} strokeWidth={1.5} />
                    Hunt with AI
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
