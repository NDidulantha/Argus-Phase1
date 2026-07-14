import { useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ChevronDown } from 'lucide-react'
import { Suspense } from 'react'
import { ArgusMark } from '../components/ArgusMark'
import { GraphExplorer } from '../components/graph/lazy'
import { SeverityBadge } from '../components/SeverityBadge'
import { StatusPill } from '../components/StatusPill'
import { TimelineView } from '../components/timeline/TimelineView'
import { useAuth } from '../context/AuthContext'
import { useAuthedQuery } from '../hooks/useAuthedQuery'
import * as api from '../lib/api'
import type { CaseDetail as CaseDetailData, CaseStatus } from '../lib/api'
import { formatCount, formatUtcDateTime, relativeAge } from '../lib/format'
import { scoreSeverity } from '../lib/severity'

const TABS = ['Overview', 'Evidence', 'Timeline', 'Graph', 'Notes', 'Report'] as const
type Tab = (typeof TABS)[number]

const STATUSES: CaseStatus[] = ['new', 'investigating', 'contained', 'resolved', 'closed']

export function CaseDetail() {
  const { caseId } = useParams()
  const id = Number(caseId)
  const { token, tenantSlug } = useAuth()
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<Tab>('Overview')
  const [statusOpen, setStatusOpen] = useState(false)

  const caseQuery = useAuthedQuery(['case', id], (t) => api.getCase(t, id))
  const c = caseQuery.data

  const refresh = (updated: CaseDetailData) => {
    queryClient.setQueryData(['case', id, token], updated)
    queryClient.invalidateQueries({ queryKey: ['cases'] })
  }

  const setStatus = useMutation({
    mutationFn: (status: CaseStatus) => api.updateCase(token!, id, { status }),
    onSuccess: refresh,
  })
  const addNote = useMutation({
    mutationFn: (body: string) => api.addCaseNote(token!, id, body),
    onSuccess: refresh,
  })

  if (caseQuery.isLoading) {
    return (
      <div className="space-y-3 p-6">
        <div className="h-6 w-72 animate-pulse rounded bg-hover" />
        <div className="h-4 w-96 animate-pulse rounded bg-hover" />
      </div>
    )
  }
  if (!c) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 p-6">
        <ArgusMark size={56} className="opacity-20" />
        <p className="text-label text-tertiary">Case not found.</p>
        <Link to="/cases" className="text-label text-accent hover:text-accent-dim">
          ← All cases
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-4 p-6">
      {/* Case header (§4.4) */}
      <div>
        <Link
          to="/cases"
          className="text-label text-secondary transition-colors duration-120 hover:text-primary"
        >
          ← Cases
        </Link>
        <div className="mt-1.5 flex flex-wrap items-center gap-3">
          <h1 className="text-page-title">{c.title}</h1>
          <SeverityBadge severity={c.severity} />
          <div className="relative">
            <button
              type="button"
              onClick={() => setStatusOpen((v) => !v)}
              aria-haspopup="listbox"
              aria-expanded={statusOpen}
              className="flex items-center gap-1"
              title="Change status"
            >
              <StatusPill status={c.status} />
              <ChevronDown size={12} strokeWidth={1.5} className="text-tertiary" />
            </button>
            {statusOpen && (
              <ul
                role="listbox"
                className="absolute left-0 top-full z-50 mt-1.5 w-40 rounded-card border-[0.5px] border-subtle bg-elevated py-1.5 shadow-lg shadow-black/30"
              >
                {STATUSES.map((s) => (
                  <li key={s}>
                    <button
                      type="button"
                      role="option"
                      aria-selected={s === c.status}
                      onClick={() => {
                        setStatusOpen(false)
                        if (s !== c.status) setStatus.mutate(s)
                      }}
                      className="flex w-full items-center px-3 py-1.5 transition-colors duration-120 hover:bg-hover"
                    >
                      <StatusPill status={s} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
        <p className="mt-1 text-label text-secondary">
          {c.assignee_email ?? 'Unassigned'} · tenant{' '}
          <span className="font-mono text-data">{tenantSlug ?? '—'}</span> · opened{' '}
          <span className="font-mono text-data" title={formatUtcDateTime(c.created_at)}>
            {relativeAge(c.created_at)} ago
          </span>
        </p>
      </div>

      {/* Tabs: underline style, emerald active indicator (§5) */}
      <div className="flex gap-5 border-b-[0.5px] border-subtle">
        {TABS.map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`-mb-px border-b-2 pb-2 text-label transition-colors duration-120 ${
              tab === t
                ? 'border-accent text-primary'
                : 'border-transparent text-secondary hover:text-primary'
            }`}
          >
            {t}
            {t === 'Evidence' && ` (${c.evidence_count})`}
            {t === 'Notes' && ` (${c.notes.length})`}
          </button>
        ))}
      </div>

      {tab === 'Overview' && <Overview c={c} />}
      {tab === 'Evidence' && <EvidenceTab c={c} />}
      {tab === 'Notes' && (
        <NotesTab c={c} onAdd={(body) => addNote.mutate(body)} pending={addNote.isPending} />
      )}
      {tab === 'Timeline' && <CaseTimeline c={c} />}
      {tab === 'Graph' && (
        <div className="h-[520px]">
          <Suspense
            fallback={
              <div className="flex h-full items-center justify-center">
                <ArgusMark size={44} spinning className="opacity-40" />
              </div>
            }
          >
            <GraphExplorer />
          </Suspense>
        </div>
      )}
      {tab === 'Report' && (
        <div className="flex flex-col items-center gap-3 py-14">
          <ArgusMark size={44} className="opacity-20" />
          <p className="text-label text-tertiary">
            Build the incident report for this case — preview it, then export to PDF.
          </p>
          <Link
            to={`/reports?template=incident&case=${c.id}`}
            className="rounded-control bg-accent px-3 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim"
          >
            Open incident report
          </Link>
        </div>
      )}
    </div>
  )
}

// Case timeline: scoped to the case's hosts and evidence window span.
function CaseTimeline({ c }: { c: CaseDetailData }) {
  if (c.evidence.length === 0) {
    return (
      <div className="flex flex-col items-center gap-3 py-14">
        <ArgusMark size={44} className="opacity-20" />
        <p className="text-label text-tertiary">Link evidence to this case to see its timeline.</p>
      </div>
    )
  }
  const hosts = [...new Set(c.evidence.map((e) => e.host_name).filter(Boolean))] as string[]
  const ends = c.evidence.map((e) => new Date(e.window_end).getTime())
  const start = new Date(Math.min(...ends) - 2 * 3_600_000).toISOString()
  const end = new Date(Math.max(...ends) + 30 * 60_000).toISOString()
  return <TimelineView initialStart={start} initialEnd={end} hostFilter={hosts} />
}

function Overview({ c }: { c: CaseDetailData }) {
  const topScore = c.evidence.length ? Math.max(...c.evidence.map((e) => e.score)) : null
  const hosts = [...new Set(c.evidence.map((e) => e.host_name).filter(Boolean))] as string[]
  const techniques = [...new Set(c.evidence.flatMap((e) => e.technique_ids))]

  return (
    <div className="grid gap-3 md:grid-cols-3">
      <div className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
        <div className="text-label text-secondary">Top evidence score</div>
        <div className="mt-1 font-mono text-[22px] font-medium text-primary">
          {topScore ?? '—'}
        </div>
      </div>
      <div className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
        <div className="text-label text-secondary">Affected hosts</div>
        <div className="mt-1.5 flex flex-wrap gap-1.5">
          {hosts.length === 0 && <span className="text-label text-tertiary">none linked</span>}
          {hosts.map((h) => (
            <span key={h} className="rounded-control bg-base px-2 py-0.5 font-mono text-data text-secondary">
              {h}
            </span>
          ))}
        </div>
      </div>
      <div className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
        <div className="text-label text-secondary">Techniques</div>
        <div className="mt-1.5 flex flex-wrap gap-1.5">
          {techniques.length === 0 && (
            <span className="text-label text-tertiary">none linked</span>
          )}
          {techniques.map((t) => (
            <span key={t} className="rounded-control bg-base px-2 py-0.5 font-mono text-data text-secondary">
              {t}
            </span>
          ))}
        </div>
      </div>
      <div className="rounded-card border-[0.5px] border-subtle bg-elevated p-4 md:col-span-3">
        <div className="text-label text-secondary">Description</div>
        <p className="mt-1.5 text-label text-primary">
          {c.description ?? 'No description yet.'}
        </p>
      </div>
    </div>
  )
}

function EvidenceTab({ c }: { c: CaseDetailData }) {
  return (
    <section className="overflow-x-auto rounded-card border-[0.5px] border-subtle bg-elevated">
      <table className="w-full border-collapse text-label">
        <thead>
          <tr className="text-left text-tertiary">
            <th className="px-3 py-2 font-normal">Severity</th>
            <th className="px-3 py-2 font-normal">Evidence</th>
            <th className="px-3 py-2 font-normal">MITRE</th>
            <th className="px-3 py-2 font-normal">Asset</th>
            <th className="px-3 py-2 font-normal">Provenance</th>
            <th className="px-3 py-2 text-right font-normal">Age</th>
          </tr>
        </thead>
        <tbody>
          {c.evidence.length === 0 && (
            <tr className="border-t-[0.5px] border-subtle">
              <td colSpan={6} className="px-3 py-10">
                <div className="flex flex-col items-center gap-3">
                  <ArgusMark size={44} className="opacity-20" />
                  <span className="text-tertiary">
                    No evidence linked. Attach it from the AI workspace.
                  </span>
                </div>
              </td>
            </tr>
          )}
          {c.evidence.map((e) => (
            <tr
              key={e.id}
              className="border-t-[0.5px] border-subtle transition-colors duration-120 hover:bg-hover"
            >
              <td className="px-3 py-2">
                <SeverityBadge severity={scoreSeverity(e.score)} />
              </td>
              <td className="px-3 py-2">
                <Link
                  to={`/workspace?evidence=${e.id}`}
                  className="font-mono text-data text-accent transition-colors duration-120 hover:text-accent-dim"
                >
                  #{e.id} · score {formatCount(e.score)}
                </Link>
              </td>
              <td className="px-3 py-2 font-mono text-data text-secondary">
                {e.technique_ids.join(', ') || '—'}
              </td>
              <td className="px-3 py-2 font-mono text-data text-secondary">
                {e.host_name ?? '—'}
              </td>
              <td className="px-3 py-2 text-secondary">correlation engine</td>
              <td
                className="px-3 py-2 text-right font-mono text-data text-tertiary"
                title={formatUtcDateTime(e.window_end)}
              >
                {relativeAge(e.window_end)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

function NotesTab({
  c,
  onAdd,
  pending,
}: {
  c: CaseDetailData
  onAdd: (body: string) => void
  pending: boolean
}) {
  const [draft, setDraft] = useState('')

  function submit(e: FormEvent) {
    e.preventDefault()
    const body = draft.trim()
    if (!body) return
    onAdd(body)
    setDraft('')
  }

  return (
    <div className="max-w-2xl space-y-4">
      {c.notes.length === 0 && (
        <p className="text-label text-tertiary">No notes yet. Record what you find.</p>
      )}
      {c.notes.map((n) => (
        <div key={n.id} className="rounded-card border-[0.5px] border-subtle bg-elevated p-3">
          <div className="mb-1 flex items-baseline justify-between gap-2">
            <span className="truncate text-label text-secondary">{n.author_email ?? '—'}</span>
            <span className="shrink-0 font-mono text-[11px] leading-4 text-tertiary">
              {formatUtcDateTime(n.created_at)}
            </span>
          </div>
          <p className="whitespace-pre-wrap text-label text-primary">{n.body}</p>
        </div>
      ))}
      <form onSubmit={submit} className="space-y-2">
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          rows={3}
          placeholder="Add a note…"
          className="w-full rounded-control border-[0.5px] border-subtle bg-base px-3 py-2 text-label text-primary outline-none transition-colors duration-120 placeholder:text-tertiary focus:border-strong"
        />
        <button
          type="submit"
          disabled={pending || !draft.trim()}
          className="rounded-control bg-accent px-3 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim disabled:opacity-60"
        >
          {pending ? 'Saving…' : 'Add note'}
        </button>
      </form>
    </div>
  )
}
