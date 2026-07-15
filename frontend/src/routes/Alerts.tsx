import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertQueueTable } from '../components/AlertQueueTable'
import { useAuth } from '../context/AuthContext'
import { useAuthedQuery } from '../hooks/useAuthedQuery'
import * as api from '../lib/api'
import { formatCount } from '../lib/format'

const SEVERITY_FILTERS = [
  { label: 'All', minScore: 0 },
  { label: 'Critical', minScore: 80 },
  { label: 'High +', minScore: 60 },
  { label: 'Medium +', minScore: 40 },
] as const

const STATUS_FILTERS: { label: string; status: api.EvidenceStatus | undefined }[] = [
  { label: 'Everything', status: undefined },
  { label: 'Open', status: 'open' },
  { label: 'Acknowledged', status: 'acknowledged' },
  { label: 'Escalated', status: 'escalated' },
  { label: 'Dismissed', status: 'dismissed' },
]

function FilterChip({
  active,
  label,
  onClick,
}: {
  active: boolean
  label: string
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-full px-3 py-1 text-label transition-colors duration-120 ${
        active
          ? 'bg-accent-bg text-accent'
          : 'border-[0.5px] border-subtle text-secondary hover:bg-hover hover:text-primary'
      }`}
    >
      {label}
    </button>
  )
}

export function Alerts() {
  const { token } = useAuth()
  const queryClient = useQueryClient()
  const [minScore, setMinScore] = useState<number>(0)
  const [status, setStatus] = useState<api.EvidenceStatus | undefined>(undefined)

  const evidence = useAuthedQuery(
    ['evidence', 'alerts', minScore, status ?? 'all'],
    (t) => api.listEvidence(t, { min_score: minScore, status, limit: 200 }),
    { refetchInterval: 30_000 },
  )

  const triage = useMutation({
    mutationFn: ({ id, next }: { id: number; next: api.EvidenceStatus }) =>
      api.setEvidenceStatus(token!, id, next),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['evidence'] }),
  })

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

      <div className="flex flex-wrap items-center gap-1.5">
        {SEVERITY_FILTERS.map((f) => (
          <FilterChip
            key={f.label}
            label={f.label}
            active={minScore === f.minScore}
            onClick={() => setMinScore(f.minScore)}
          />
        ))}
        <span className="mx-1.5 h-4 w-px bg-subtle" aria-hidden />
        {STATUS_FILTERS.map((f) => (
          <FilterChip
            key={f.label}
            label={f.label}
            active={status === f.status}
            onClick={() => setStatus(f.status)}
          />
        ))}
      </div>

      <section className="rounded-card border-[0.5px] border-subtle bg-elevated">
        <AlertQueueTable
          items={evidence.data?.items}
          loading={evidence.isLoading}
          showStatus
          onSetStatus={(id, next) => triage.mutate({ id, next })}
          busyId={triage.isPending ? triage.variables?.id : null}
          emptyMessage={
            minScore === 0 && status === undefined
              ? 'No alerts yet. Connect a collector or run correlation.'
              : 'Nothing matches these filters.'
          }
        />
      </section>
    </div>
  )
}
