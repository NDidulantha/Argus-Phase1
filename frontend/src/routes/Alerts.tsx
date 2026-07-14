import { useState } from 'react'
import { AlertQueueTable } from '../components/AlertQueueTable'
import { useAuthedQuery } from '../hooks/useAuthedQuery'
import * as api from '../lib/api'
import { formatCount } from '../lib/format'

const FILTERS = [
  { label: 'All', minScore: 0 },
  { label: 'Critical', minScore: 80 },
  { label: 'High +', minScore: 60 },
  { label: 'Medium +', minScore: 40 },
] as const

export function Alerts() {
  const [minScore, setMinScore] = useState<number>(0)

  const evidence = useAuthedQuery(
    ['evidence', 'alerts', minScore],
    (token) => api.listEvidence(token, { min_score: minScore, limit: 200 }),
    { refetchInterval: 30_000 },
  )

  return (
    <div className="space-y-4 p-6">
      <div className="flex items-baseline gap-3">
        <h1 className="text-page-title">Alerts</h1>
        {evidence.data && (
          <span className="font-mono text-data text-tertiary">
            {formatCount(evidence.data.total)} total
          </span>
        )}
      </div>

      <div className="flex gap-1.5">
        {FILTERS.map((f) => (
          <button
            key={f.label}
            type="button"
            onClick={() => setMinScore(f.minScore)}
            className={`rounded-full px-3 py-1 text-label transition-colors duration-120 ${
              minScore === f.minScore
                ? 'bg-accent-bg text-accent'
                : 'border-[0.5px] border-subtle text-secondary hover:bg-hover hover:text-primary'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      <section className="rounded-card border-[0.5px] border-subtle bg-elevated">
        <AlertQueueTable
          items={evidence.data?.items}
          loading={evidence.isLoading}
          showStatus
          emptyMessage={
            minScore === 0
              ? 'No alerts yet. Connect a collector or run correlation.'
              : 'Nothing at this severity. Lower the filter to see more.'
          }
        />
      </section>
    </div>
  )
}
