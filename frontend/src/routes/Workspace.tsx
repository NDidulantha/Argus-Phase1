import { useMemo, useRef, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import ReactMarkdown from 'react-markdown'
import { FolderPlus, Sparkles, X } from 'lucide-react'
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
import type { InvestigationRun, StageEvent } from '../lib/api'
import { formatCount, formatUtcWindow, relativeAge } from '../lib/format'
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

// Causal order: evidence context (Scope → Collector → Correlation → MITRE),
// then the run's own provenance trail, then narrative + grounding, then
// analyst steering notes. Within a rank, entries order by time.
const STAGE_RANK: Record<string, number> = {
  scope: 0,
  collector: 1,
  correlation: 2,
  mitre: 3,
  reasoning: 5,
  'reasoning-error': 5,
  grounding: 6,
}

function stageRank(id: string): number {
  if (id.startsWith('run-')) return 4
  return STAGE_RANK[id] ?? 7
}

const RUN_STAGE_AGENT: Record<string, StreamEntry['agent']> = {
  scope: 'Scope',
  collect: 'Collector',
  conclude: 'Reasoning',
  ground: 'Grounding',
}

function Investigation({ evidenceId }: { evidenceId: number }) {
  const { token } = useAuth()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [steerNotices, setSteerNotices] = useState<StreamEntry[]>([])
  const [directives, setDirectives] = useState<string[]>([])
  const [live, setLive] = useState<InvestigationRun | null>(null)
  const [streamStages, setStreamStages] = useState<StageEvent[]>([])
  const [streaming, setStreaming] = useState(false)
  const [runError, setRunError] = useState<string | null>(null)
  // Capture-once timestamps for the evidence-context entries: query
  // `dataUpdatedAt` moves forward on refetches, which must not re-stamp
  // the trail. (Run stages carry server timestamps and need no such care.)
  const stageAt = useRef<{ scope?: number; collect?: number }>({})
  const errorAt = useRef(0)

  const detail = useAuthedQuery(['evidence', 'detail', evidenceId], (t) =>
    api.getEvidenceDetail(t, evidenceId),
  )
  const similar = useAuthedQuery(['evidence', 'similar', evidenceId], (t) =>
    api.getSimilarEvidence(t, evidenceId),
  )
  const providers = useAuthedQuery(['reasoning-providers'], (t) => api.getReasoningProviders(t))
  const history = useAuthedQuery(['investigations', evidenceId], (t) =>
    api.listInvestigations(t, evidenceId),
  )
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

  // Set-once (??=): the first successful fetch stamps the stage; refetches don't.
  if (detail.data) stageAt.current.scope ??= detail.dataUpdatedAt
  if (similar.data) stageAt.current.collect ??= similar.dataUpdatedAt

  // Displayed run: the live one, else the latest persisted complete run —
  // investigations survive a page refresh.
  const run = live ?? history.data?.find((r) => r.status === 'complete') ?? null
  const runStages = useMemo(
    () => (streaming ? streamStages : (run?.stages ?? [])),
    [streaming, streamStages, run],
  )
  const parsed = run?.narrative ? parseNarrative(run.narrative) : null

  async function runInvestigation() {
    if (!token || streaming) return
    setStreaming(true)
    setRunError(null)
    setLive(null)
    setStreamStages([])
    try {
      await api.investigateStream(token, evidenceId, directives, (event) => {
        if (event.type === 'stage') {
          setStreamStages((prev) => [...prev, event])
        } else if (event.type === 'complete') {
          setLive(event.investigation)
          queryClient.invalidateQueries({ queryKey: ['investigations', evidenceId] })
        } else {
          errorAt.current = Date.now()
          setRunError(
            event.status_code === 503
              ? 'Reasoning provider unreachable. Check that Ollama is running, then run again.'
              : `The reasoning provider returned an error: ${event.detail}. Run again.`,
          )
        }
      })
    } catch {
      errorAt.current = Date.now()
      setRunError("Couldn't reach ARGUS. Check your connection and run again.")
    } finally {
      setStreaming(false)
    }
  }

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

    // The run's own provenance trail: server-stamped stage events, live or
    // replayed from the persisted record.
    for (const [i, s] of runStages.entries()) {
      out.push({
        id: `run-${s.stage}-${i}`,
        time: Date.parse(s.at),
        agent: RUN_STAGE_AGENT[s.stage] ?? 'Planner',
        body: (
          <p className="text-[11px] leading-4 text-tertiary">
            ▸ {s.stage}: <span className="text-secondary">{s.detail}</span>
          </p>
        ),
      })
    }

    if (run?.status === 'complete' && parsed && run.narrative) {
      const at = run.finished_at ? Date.parse(run.finished_at) : Date.now()
      out.push({
        id: 'reasoning',
        time: at,
        agent: 'Reasoning',
        body: (
          <div className="space-y-3">
            <p className="text-[11px] leading-4 text-tertiary">
              {run.model} via {run.provider} ·{' '}
              {run.duration_ms !== null && `${(run.duration_ms / 1000).toFixed(1)}s · `}
              {run.directives.length > 0 && `${run.directives.length} directive(s) applied · `}
              reasoning over curated evidence only
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
        time: at,
        agent: 'Grounding',
        body: run.grounded ? (
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
              {run.unsupported_terms.map((term) => (
                <li key={term} className="font-mono text-data text-sev-critical">
                  {term}
                </li>
              ))}
            </ul>
          </div>
        ),
      })
    }
    if (runError) {
      out.push({
        id: 'reasoning-error',
        time: errorAt.current,
        agent: 'Reasoning',
        body: <p className="text-label text-sev-critical">{runError}</p>,
      })
    }
    // Causal pipeline order, not clock order: parallel fetches may land in
    // any sequence, but the trail must always read evidence → conclusion.
    const all = [...out, ...steerNotices]
    return all.sort((a, b) => stageRank(a.id) - stageRank(b.id) || a.time - b.time)
  }, [detail.data, similar.data, run, runStages, parsed, runError, steerNotices])

  const lastStreamDetail = streamStages.at(-1)?.detail
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
      detail: streaming
        ? (lastStreamDetail ?? 'reasoning in progress…')
        : run?.status === 'complete'
          ? `${run.model} · ${run.grounded ? 'grounded' : 'ungrounded'}`
          : 'run the investigation',
      state: streaming ? 'active' : run?.status === 'complete' ? 'done' : 'pending',
    },
  ]

  function steer(message: string) {
    setDirectives((prev) => [...prev, message])
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
              Directive recorded — it steers the prompt of the next run
              {streaming ? ' (this run already started without it)' : ''}.
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
          <div className="space-y-2">
            <button
              type="button"
              onClick={() => void runInvestigation()}
              disabled={streaming || !detail.data}
              className={`flex w-full items-center justify-center gap-2 rounded-control px-3 py-2 text-label font-medium transition-colors duration-120 disabled:opacity-60 ${
                run
                  ? 'border-[0.5px] border-subtle text-secondary hover:bg-hover hover:text-primary'
                  : 'bg-accent text-(--bg-base) hover:bg-accent-dim'
              }`}
            >
              <Sparkles size={13} strokeWidth={1.5} />
              {streaming ? 'Investigating…' : run ? 'Run again' : 'Run investigation'}
            </button>
            {run && !live && !streaming && run.finished_at && (
              <p className="text-center text-[11px] leading-4 text-tertiary">
                showing last run · {relativeAge(run.finished_at)} ago
              </p>
            )}
            {directives.length > 0 && (
              <div className="space-y-1">
                <div className="text-[11px] font-medium uppercase tracking-[0.12em] text-tertiary">
                  Directives for next run
                </div>
                {directives.map((d, i) => (
                  <div
                    key={`${i}-${d}`}
                    className="flex items-start justify-between gap-1.5 rounded-control bg-base px-2 py-1"
                  >
                    <span className="min-w-0 break-words text-[11px] leading-4 text-secondary">
                      {d}
                    </span>
                    <button
                      type="button"
                      aria-label="Remove directive"
                      onClick={() => setDirectives((prev) => prev.filter((_, j) => j !== i))}
                      className="text-tertiary transition-colors duration-120 hover:text-primary"
                    >
                      <X size={11} strokeWidth={1.5} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
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
            streaming
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
