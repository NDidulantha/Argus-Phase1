import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { Plus } from 'lucide-react'
import { ArgusMark } from '../components/ArgusMark'
import { SeverityBadge } from '../components/SeverityBadge'
import { StatusPill } from '../components/StatusPill'
import { useAuth } from '../context/AuthContext'
import { useAuthedQuery } from '../hooks/useAuthedQuery'
import * as api from '../lib/api'
import type { CaseStatus } from '../lib/api'
import { formatCount, formatUtcDateTime, relativeAge } from '../lib/format'

const STATUS_FILTERS: (CaseStatus | 'all')[] = [
  'all',
  'new',
  'investigating',
  'contained',
  'resolved',
  'closed',
]

export function Cases() {
  const navigate = useNavigate()
  const { token } = useAuth()
  const [statusFilter, setStatusFilter] = useState<CaseStatus | 'all'>('all')
  const [creating, setCreating] = useState(false)
  const [title, setTitle] = useState('')

  const cases = useAuthedQuery(
    ['cases', statusFilter],
    (t) =>
      api.listCases(t, {
        status: statusFilter === 'all' ? undefined : statusFilter,
        limit: 200,
      }),
    { refetchInterval: 30_000 },
  )

  const create = useMutation({
    mutationFn: (caseTitle: string) => api.createCase(token!, { title: caseTitle }),
    onSuccess: (c) => navigate(`/cases/${c.id}`),
  })

  function submitNew(e: FormEvent) {
    e.preventDefault()
    if (title.trim()) create.mutate(title.trim())
  }

  return (
    <div className="space-y-4 p-6">
      <div className="flex items-baseline justify-between">
        <div className="flex items-baseline gap-3">
          <h1 className="text-page-title">Cases</h1>
          {cases.data && (
            <span className="font-mono text-data text-tertiary">
              {formatCount(cases.data.total)} total
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={() => setCreating((v) => !v)}
          className="flex items-center gap-1.5 rounded-control bg-accent px-3 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim"
        >
          <Plus size={13} strokeWidth={2} />
          New case
        </button>
      </div>

      {creating && (
        <form
          onSubmit={submitNew}
          className="flex gap-2 rounded-card border-[0.5px] border-subtle bg-elevated p-3"
        >
          <input
            autoFocus
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Case title — what are you investigating?"
            className="w-full rounded-control border-[0.5px] border-subtle bg-base px-3 py-1.5 text-label text-primary outline-none transition-colors duration-120 placeholder:text-tertiary focus:border-strong"
          />
          <button
            type="submit"
            disabled={create.isPending || !title.trim()}
            className="shrink-0 rounded-control bg-accent px-3 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim disabled:opacity-60"
          >
            {create.isPending ? 'Creating…' : 'Create'}
          </button>
        </form>
      )}

      <div className="flex gap-1.5">
        {STATUS_FILTERS.map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => setStatusFilter(s)}
            className={`rounded-full px-3 py-1 text-label transition-colors duration-120 ${
              statusFilter === s
                ? 'bg-accent-bg text-accent'
                : 'border-[0.5px] border-subtle text-secondary hover:bg-hover hover:text-primary'
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      <section className="overflow-x-auto rounded-card border-[0.5px] border-subtle bg-elevated">
        <table className="w-full border-collapse text-label">
          <thead>
            <tr className="text-left text-tertiary">
              <th className="px-3 py-2 font-normal">Severity</th>
              <th className="px-3 py-2 font-normal">Title</th>
              <th className="px-3 py-2 font-normal">Status</th>
              <th className="px-3 py-2 font-normal">Assignee</th>
              <th className="px-3 py-2 text-right font-normal">Evidence</th>
              <th className="px-3 py-2 text-right font-normal">Updated</th>
            </tr>
          </thead>
          <tbody>
            {cases.isLoading &&
              Array.from({ length: 4 }, (_, i) => (
                <tr key={i} className="border-t-[0.5px] border-subtle">
                  <td colSpan={6} className="px-3 py-3">
                    <div className="h-4 animate-pulse rounded bg-hover" />
                  </td>
                </tr>
              ))}
            {cases.data?.items.length === 0 && (
              <tr className="border-t-[0.5px] border-subtle">
                <td colSpan={6} className="px-3 py-10">
                  <div className="flex flex-col items-center gap-3">
                    <ArgusMark size={44} className="opacity-20" />
                    <span className="text-tertiary">
                      {statusFilter === 'all'
                        ? 'No cases yet. Open one from an alert, or create one here.'
                        : `No ${statusFilter} cases.`}
                    </span>
                  </div>
                </td>
              </tr>
            )}
            {cases.data?.items.map((c) => (
              <tr
                key={c.id}
                onClick={() => navigate(`/cases/${c.id}`)}
                className="cursor-pointer border-t-[0.5px] border-subtle transition-colors duration-120 hover:bg-hover"
              >
                <td className="px-3 py-2">
                  <SeverityBadge severity={c.severity} />
                </td>
                <td className="max-w-md truncate px-3 py-2 text-primary">
                  <Link to={`/cases/${c.id}`} onClick={(e) => e.stopPropagation()}>
                    {c.title}
                  </Link>
                </td>
                <td className="px-3 py-2">
                  <StatusPill status={c.status} />
                </td>
                <td className="max-w-48 truncate px-3 py-2 text-secondary">
                  {c.assignee_email ?? '—'}
                </td>
                <td className="px-3 py-2 text-right font-mono text-data text-secondary">
                  {c.evidence_count}
                </td>
                <td
                  className="px-3 py-2 text-right font-mono text-data text-tertiary"
                  title={formatUtcDateTime(c.updated_at)}
                >
                  {relativeAge(c.updated_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  )
}
