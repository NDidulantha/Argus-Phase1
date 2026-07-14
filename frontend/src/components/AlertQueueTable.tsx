import { useNavigate } from 'react-router-dom'
import { Sparkles } from 'lucide-react'
import type { EvidenceItem } from '../lib/api'
import { formatCount, formatUtcDateTime, relativeAge } from '../lib/format'
import { scoreSeverity } from '../lib/severity'
import { ArgusMark } from './ArgusMark'
import { SeverityBadge } from './SeverityBadge'

function signalLabel(item: EvidenceItem): string {
  if (item.tactics.length > 0) return item.tactics.join(' · ')
  return 'correlated activity'
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

interface AlertQueueTableProps {
  items: EvidenceItem[] | undefined
  loading: boolean
  showStatus?: boolean
  emptyMessage: string
}

export function AlertQueueTable({ items, loading, showStatus, emptyMessage }: AlertQueueTableProps) {
  const navigate = useNavigate()

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
            <th className="w-28 px-3 py-2" aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {loading && <SkeletonRows />}
          {!loading && items?.length === 0 && (
            <tr className="border-t-[0.5px] border-subtle">
              <td colSpan={showStatus ? 8 : 7} className="px-3 py-10">
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
                  <span className="rounded-full border-[0.5px] border-strong px-2 py-0.5 text-[11px] leading-4 text-secondary">
                    {item.status}
                  </span>
                </td>
              )}
              <td
                className="px-3 py-2 text-right font-mono text-data text-tertiary"
                title={formatUtcDateTime(item.window_end)}
              >
                {relativeAge(item.window_end)}
              </td>
              <td className="px-3 py-2 text-right">
                <button
                  type="button"
                  onClick={() => navigate(`/workspace?evidence=${item.id}`)}
                  className="inline-flex items-center gap-1.5 rounded-control bg-accent-bg px-2 py-1 text-[11px] leading-4 text-accent opacity-0 transition-opacity duration-120 focus-visible:opacity-100 group-hover:opacity-100"
                >
                  <Sparkles size={11} strokeWidth={1.5} />
                  Hunt with AI
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
