import { useMemo, useRef, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import ReactMarkdown from 'react-markdown'
import { FolderPlus, Sparkles } from 'lucide-react'
import { AlertQueueTable } from '../components/AlertQueueTable'
import { ArgusMark } from '../components/ArgusMark'
import { AttackChain } from '../components/workspace/AttackChain'
import { ConfidenceRing } from '../components/workspace/ConfidenceRing'
import { MiniTimeline } from '../components/workspace/MiniTimeline'
import { PipelineSteps, type PipelineStep } from '../components/workspace/PipelineSteps'
import { ReasoningStream, type StreamEntry } from '../components/workspace/ReasoningStream'
import { useAuthedQuery } from '../hooks/useAuthedQuery'
import { useAuth } from '../context/AuthContext'
import * as api from '../lib/api'
import { ApiError } from '../lib/api'
import { formatCount, formatUtcWindow } from '../lib/format'
import { parseNarrative } from '../lib/narrative'

export function Workspace() {
  const [searchParams] = useSearchParams()
  const evidenceId = Number(searchParams.get('evidence')) || null

  // Key by evidence id so pivoting to another hunt resets all local state.
  return evidenceId ? <Investigation key={evidenceId} evidenceId={evidenceId} /> : <HuntPicker />
}

function HuntPicker() {
  const evidence = useAuthedQuery(['evidence', 'queue'], (token) =>
    api.listEvidence(token, { limit: 200 }),
  )

  return (
    <div className="space-y-4 p-6">
      <h1 className="text-page-title">AI workspace</h1>
      <div className="flex flex-col items-center gap-3 py-8">
        <ArgusMark size={56} className="opacity-25" />
        <p className="text-label text-tertiary">
          No active hunt. Start one from an alert below.
        </p>
      </div>
      <section className="rounded-card border-[0.5px] border-subtle bg-elevated">
        <AlertQueueTable
          items={evidence.data?.items.slice(0, 8)}
          loading={evidence.isLoading}
          emptyMessage="No alerts yet. Connect a collector or run correlation."
        />
      </section>
    </div>
  )
}

function sectionTitle(title: string): string {
  const t = title.toLowerCase()
  return (t[0].toUpperCase() + t.slice(1)).replace('att&ck', 'ATT&CK')
}

// Scope → Collector → Correlation → MITRE → Reasoning → Grounding;
// analyst steering notes trail the pipeline, ordered among themselves by time.
const STAGE_RANK: Record<string, number> = {
  scope: 0,
  collector: 1,
  correlation: 2,
  mitre: 3,
  reasoning: 4,
  'reasoning-error': 4,
  grounding: 5,
}

function stageRank(id: string): number {
  return STAGE_RANK[id] ?? 6
}

function Investigation({ evidenceId }: { evidenceId: number }) {
  const { token } = useAuth()
  const navigate = useNavigate()
  const [steerNotices, setSteerNotices] = useState<StreamEntry[]>([])
  // Capture-once timestamps per pipeline stage. Query `dataUpdatedAt` moves
  // forward on every background refetch, which would re-stamp evidence
  // entries after the conclusion — the provenance trail must record when a
  // stage first delivered, not when its data was last revalidated.
  const stageAt = useRef<{ scope?: number; collect?: number; conclude?: number }>({})

  const detail = useAuthedQuery(['evidence', 'detail', evidenceId], (t) =>
    api.getEvidenceDetail(t, evidenceId),
  )
  const similar = useAuthedQuery(['evidence', 'similar', evidenceId], (t) =>
    api.getSimilarEvidence(t, evidenceId),
  )
  const providers = useAuthedQuery(['reasoning-providers'], (t) => api.getReasoningProviders(t))
  const windowEvents = useAuthedQuery(
    ['evidence', 'window-events', evidenceId, detail.data?.window_start],
    (t) =>
      api.listEvents(t, {
        start: detail.data!.window_start,
        end: detail.data!.window_end,
        host: detail.data!.host_name ?? undefined,
        limit: 200,
      }),
  )

  const investigation = useMutation({
    mutationFn: () => api.investigateEvidence(token!, evidenceId),
    onSuccess: () => {
      stageAt.current.conclude = Date.now()
    },
    onError: () => {
      stageAt.current.conclude = Date.now()
    },
  })

  // Set-once (??=): the first successful fetch stamps the stage; refetches don't.
  if (detail.data) stageAt.current.scope ??= detail.dataUpdatedAt
  if (similar.data) stageAt.current.collect ??= similar.dataUpdatedAt

  const openCase = useMutation({
    mutationFn: () => {
      const d = detail.data!
      const title = `${d.host_name ?? `Evidence #${d.id}`}: ${
        d.tactics.join(', ') || 'correlated activity'
      }`
      return api.createCase(token!, { title, evidence_ids: [evidenceId] })
    },
    onSuccess: (c) => navigate(`/cases/${c.id}`),
  })

  const parsed = investigation.data ? parseNarrative(investigation.data.narrative) : null

  const entries = useMemo(() => {
    const out: StreamEntry[] = []
    const d = detail.data
    if (d) {
      out.push({
        id: 'scope',
        time: stageAt.current.scope!,
        agent: 'Scope',
        body: (
          <p className="text-label text-secondary">
            Evidence object <span className="font-mono text-data text-primary">#{d.id}</span> on{' '}
            <span className="font-mono text-data text-primary">{d.host_name ?? 'unknown host'}</span>{' '}
            · {formatCount(d.event_count)} events ·{' '}
            <span className="font-mono text-data">
              {formatUtcWindow(d.window_start, d.window_end)}
            </span>
          </p>
        ),
      })
      out.push({
        id: 'correlation',
        time: stageAt.current.scope!,
        agent: 'Correlation',
        body: (
          <div className="rounded-control border-[0.5px] border-subtle bg-base p-3">
            <p className="text-label text-secondary">
              Deterministic score <span className="font-mono text-primary">{d.score}</span> — every
              term recorded:
            </p>
            <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1">
              {Object.entries(d.score_breakdown)
                .filter(([k]) => k !== 'total')
                .map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-2">
                    <dt className="text-[11px] leading-4 text-tertiary">{k.replaceAll('_', ' ')}</dt>
                    <dd className="font-mono text-[11px] leading-4 text-secondary">+{v}</dd>
                  </div>
                ))}
            </dl>
          </div>
        ),
      })
      if (d.techniques.length > 0) {
        out.push({
          id: 'mitre',
          time: stageAt.current.scope!,
          agent: 'MITRE',
          body: (
            <p className="text-label text-secondary">
              Mapped to{' '}
              {d.techniques.map((t, i) => (
                <span key={t.technique_id}>
                  {i > 0 && ', '}
                  <span className="font-mono text-data text-primary">{t.technique_id}</span>
                  {t.name && <> ({t.name})</>}
                </span>
              ))}
            </p>
          ),
        })
      }
    }
    if (similar.data) {
      const top = similar.data.similar[0]
      out.push({
        id: 'collector',
        time: stageAt.current.collect!,
        agent: 'Collector',
        body: (
          <p className="text-label text-secondary">
            Retrieved {similar.data.similar.length} similar past evidence objects from tenant memory
            {top && (
              <>
                {' '}
                · closest{' '}
                <span className="font-mono text-data text-primary">
                  #{top.id} ({Math.round(top.similarity * 100)}%)
                </span>
              </>
            )}
          </p>
        ),
      })
    }
    if (investigation.data && parsed) {
      const r = investigation.data
      out.push({
        id: 'reasoning',
        time: stageAt.current.conclude!,
        agent: 'Reasoning',
        body: (
          <div className="space-y-3">
            <p className="text-[11px] leading-4 text-tertiary">
              {r.model} via {r.provider} · reasoning over curated evidence only
            </p>
            {parsed.sections.map((s) => (
              <div key={s.title} className="rounded-control border-[0.5px] border-subtle bg-base p-3">
                <h3 className="mb-1.5 text-label font-medium text-primary">
                  {sectionTitle(s.title)}
                </h3>
                <div className="narrative text-label text-secondary">
                  <ReactMarkdown>{s.body}</ReactMarkdown>
                </div>
              </div>
            ))}
          </div>
        ),
      })
      out.push({
        id: 'grounding',
        time: stageAt.current.conclude!,
        agent: 'Grounding',
        body: r.grounded ? (
          <p className="text-label text-secondary">
            Narrative grounded — artifacts match the evidence and MITRE claims match the
            ATT&CK catalog.
          </p>
        ) : (
          <div className="space-y-1">
            <p className="text-label text-sev-critical">
              The narrative makes claims the evidence doesn't support:
            </p>
            <ul className="list-disc space-y-0.5 pl-5">
              {r.unsupported_terms.map((term) => (
                <li key={term} className="font-mono text-data text-sev-critical">
                  {term}
                </li>
              ))}
            </ul>
          </div>
        ),
      })
    }
    if (investigation.error) {
      const err = investigation.error
      const message =
        err instanceof ApiError && err.status === 503
          ? 'Reasoning provider unreachable. Check that Ollama is running, then run again.'
          : `The reasoning provider returned an error: ${err.message}. Run the investigation again.`
      out.push({
        id: 'reasoning-error',
        time: stageAt.current.conclude!,
        agent: 'Reasoning',
        body: <p className="text-label text-sev-critical">{message}</p>,
      })
    }
    // Causal pipeline order, not clock order: parallel fetches may land in
    // any sequence, but the trail must always read evidence → conclusion.
    const all = [...out, ...steerNotices]
    return all.sort((a, b) => stageRank(a.id) - stageRank(b.id) || a.time - b.time)
  }, [detail.data, similar.data, investigation.data, investigation.error, parsed, steerNotices])

  const steps: PipelineStep[] = [
    {
      label: 'Scope',
      detail: detail.data ? `evidence #${evidenceId} loaded` : 'loading evidence…',
      state: detail.data ? 'done' : 'active',
    },
    {
      label: 'Collect',
      detail:
        similar.data && windowEvents.data
          ? `${formatCount(windowEvents.data.total)} events · ${similar.data.similar.length} similar`
          : 'gathering context…',
      state: similar.data && windowEvents.data ? 'done' : detail.data ? 'active' : 'pending',
    },
    {
      label: 'Correlate',
      detail: detail.data ? `deterministic engine · score ${detail.data.score}` : 'awaiting scope',
      state: detail.data ? 'done' : 'pending',
    },
    {
      label: 'Conclude',
      detail: investigation.isPending
        ? 'reasoning in progress…'
        : investigation.data
          ? `${investigation.data.model} · ${investigation.data.grounded ? 'grounded' : 'ungrounded'}`
          : 'run the investigation',
      state: investigation.isPending ? 'active' : investigation.data ? 'done' : 'pending',
    },
  ]

  function steer(message: string) {
    setSteerNotices((prev) => [
      ...prev,
      {
        id: `steer-${Date.now()}`,
        time: Date.now(),
        agent: 'Planner',
        body: (
          <div className="space-y-1">
            <p className="text-label text-primary">“{message}”</p>
            <p className="text-[11px] leading-4 text-tertiary">
              Steering isn't wired to the agent pipeline yet — it arrives with Phase 3. The
              directive was noted in this session only.
            </p>
          </div>
        ),
      },
    ])
  }

  return (
    <div className="flex h-full flex-col gap-4 p-6">
      <div className="flex items-baseline justify-between">
        <h1 className="text-page-title">AI workspace</h1>
        <Link
          to="/alerts"
          className="text-label text-secondary transition-colors duration-120 hover:text-primary"
        >
          ← All alerts
        </Link>
      </div>

      <div className="grid min-h-0 flex-1 gap-4 xl:grid-cols-[240px_minmax(0,1fr)_300px]">
        {/* Left — investigation progress */}
        <aside className="space-y-5 overflow-y-auto rounded-card border-[0.5px] border-subtle bg-elevated p-4">
          <ConfidenceRing score={detail.data?.score ?? 0} label="Evidence score" />
          {parsed?.confidence && (
            <p className="text-center text-label text-secondary">
              AI confidence: <span className="text-primary">{parsed.confidence}</span>
            </p>
          )}
          <PipelineSteps steps={steps} />
          <button
            type="button"
            onClick={() => investigation.mutate()}
            disabled={investigation.isPending || !detail.data}
            className={`flex w-full items-center justify-center gap-2 rounded-control px-3 py-2 text-label font-medium transition-colors duration-120 disabled:opacity-60 ${
              investigation.data
                ? 'border-[0.5px] border-subtle text-secondary hover:bg-hover hover:text-primary'
                : 'bg-accent text-(--bg-base) hover:bg-accent-dim'
            }`}
          >
            <Sparkles size={13} strokeWidth={1.5} />
            {investigation.isPending
              ? 'Investigating…'
              : investigation.data
                ? 'Run again'
                : 'Run investigation'}
          </button>
          {providers.data && (
            <p className="text-center text-[11px] leading-4 text-tertiary">
              provider: {providers.data.default}
              {providers.data.providers.length > 1 &&
                ` (${providers.data.providers.join(', ')} available)`}
            </p>
          )}
        </aside>

        {/* Center — AI reasoning stream */}
        <ReasoningStream
          entries={entries}
          thinking={
            investigation.isPending
              ? 'ARGUS is reasoning over the evidence — watching…'
              : detail.isLoading
                ? 'Scoping the investigation…'
                : null
          }
          onSteer={steer}
        />

        {/* Right — evidence & context */}
        <aside className="space-y-4 overflow-y-auto">
          <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
            <h2 className="text-card-title">Related entities</h2>
            <div className="mt-2.5 flex flex-wrap gap-1.5">
              {detail.data?.entities.length === 0 && (
                <p className="text-label text-tertiary">No entities extracted.</p>
              )}
              {detail.data?.entities.map((e) => (
                <Link
                  key={e.id}
                  to={`/entities?id=${e.id}`}
                  className="rounded-control border-[0.5px] border-subtle bg-base px-2 py-1 transition-colors duration-120 hover:bg-hover"
                >
                  <span className="text-[11px] leading-4 text-tertiary">{e.entity_type} </span>
                  <span className="font-mono text-data text-primary">{e.entity_key}</span>
                </Link>
              ))}
            </div>
          </section>

          <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
            <h2 className="text-card-title">Attack chain</h2>
            <div className="mt-2.5">
              <AttackChain techniques={detail.data?.techniques ?? []} />
            </div>
          </section>

          <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
            <h2 className="text-card-title">Window timeline</h2>
            <div className="mt-2.5">
              {detail.data && (
                <MiniTimeline
                  events={windowEvents.data?.items ?? []}
                  windowStart={detail.data.window_start}
                  windowEnd={detail.data.window_end}
                />
              )}
            </div>
          </section>

          <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
            <h2 className="text-card-title">Next actions</h2>
            <button
              type="button"
              onClick={() => openCase.mutate()}
              disabled={openCase.isPending || !detail.data}
              className="mt-2.5 flex w-full items-center gap-2 rounded-control border-[0.5px] border-subtle px-3 py-2 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary disabled:opacity-60"
            >
              <FolderPlus size={14} strokeWidth={1.5} className="text-accent" />
              {openCase.isPending
                ? 'Opening case…'
                : 'Open case — creates a case linked to this evidence'}
            </button>
          </section>

          <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
            <h2 className="text-card-title">Similar past evidence</h2>
            <ul className="mt-2.5 space-y-2">
              {similar.data?.similar.length === 0 && (
                <li className="text-label text-tertiary">Nothing similar yet.</li>
              )}
              {similar.data?.similar.map((s) => (
                <li key={s.id}>
                  <Link
                    to={`/workspace?evidence=${s.id}`}
                    className="flex items-center justify-between gap-2 rounded-control px-2 py-1.5 transition-colors duration-120 hover:bg-hover"
                  >
                    <span className="min-w-0 truncate font-mono text-data text-secondary">
                      #{s.id} {s.host_name ?? ''}
                    </span>
                    <span className="shrink-0 font-mono text-[11px] leading-4 text-tertiary">
                      {Math.round(s.similarity * 100)}% · score {s.score}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </section>
        </aside>
      </div>
    </div>
  )
}
