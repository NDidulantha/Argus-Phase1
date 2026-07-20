import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { X } from 'lucide-react'
import { ArgusMark } from '../components/ArgusMark'
import { useAuthedQuery } from '../hooks/useAuthedQuery'
import * as api from '../lib/api'
import type { CoverageEntry, MatrixTechnique } from '../lib/api'
import { formatCount, formatUtcDateTime } from '../lib/format'
import { tacticLabel, tacticRank } from '../lib/mitre'

export function Mitre() {
  const matrix = useAuthedQuery(['mitre', 'matrix'], api.getMitreMatrix)
  const coverage = useAuthedQuery(['mitre', 'coverage'], api.getMitreCoverage)
  const evidence = useAuthedQuery(['evidence', 'queue'], (t) => api.listEvidence(t, { limit: 200 }))
  const [selected, setSelected] = useState<string | null>(null)

  // events per technique for the tenant, sub-technique counts rolled into parents
  const hits = useMemo(() => {
    const map = new Map<string, number>()
    for (const c of coverage.data?.coverage ?? []) {
      map.set(c.technique_id, (map.get(c.technique_id) ?? 0) + c.event_count)
      const parent = c.technique_id.split('.')[0]
      if (parent !== c.technique_id) {
        map.set(parent, (map.get(parent) ?? 0) + c.event_count)
      }
    }
    return map
  }, [coverage.data])

  const maxHits = Math.max(...hits.values(), 1)

  // Trust tier per technique. 'only' = detected ONLY by the AI classifier — a
  // review-grade hint, quarantined from alert scoring. 'augmented' = rules or
  // vendor already confirmed it and AI merely added events. Rolled up to
  // parent techniques like the hit counts.
  const aiStatus = useMemo(() => {
    const ai = new Map<string, number>()
    const auth = new Map<string, number>()
    const bump = (m: Map<string, number>, id: string, n: number) =>
      m.set(id, (m.get(id) ?? 0) + n)
    for (const c of coverage.data?.coverage ?? []) {
      const aiN = c.sources.ai ?? 0
      const authN = Object.entries(c.sources).reduce((s, [k, v]) => (k === 'ai' ? s : s + v), 0)
      for (const id of new Set([c.technique_id, c.technique_id.split('.')[0]])) {
        bump(ai, id, aiN)
        bump(auth, id, authN)
      }
    }
    const status = new Map<string, 'only' | 'augmented'>()
    for (const [id, n] of ai) {
      if (n > 0) status.set(id, (auth.get(id) ?? 0) > 0 ? 'augmented' : 'only')
    }
    return status
  }, [coverage.data])

  const columns = useMemo(() => {
    if (!matrix.data) return []
    const byTactic = new Map<string, MatrixTechnique[]>()
    for (const t of matrix.data) {
      if (t.is_subtechnique) continue
      for (const tactic of t.tactics) {
        if (!byTactic.has(tactic)) byTactic.set(tactic, [])
        byTactic.get(tactic)!.push(t)
      }
    }
    return [...byTactic.entries()]
      .sort((a, b) => tacticRank(a[0]) - tacticRank(b[0]))
      .map(([tactic, techniques]) => ({
        tactic,
        // seen first (hottest on top), then alphabetical
        techniques: techniques.sort(
          (a, b) =>
            (hits.get(b.technique_id) ?? 0) - (hits.get(a.technique_id) ?? 0) ||
            a.name.localeCompare(b.name),
        ),
      }))
  }, [matrix.data, hits])

  return (
    <div className="flex h-full flex-col gap-4 p-6">
      <div className="flex flex-wrap items-baseline gap-x-6 gap-y-1">
        <h1 className="text-page-title">MITRE ATT&CK</h1>
        {coverage.data && (
          <p className="text-label text-secondary">
            <span className="font-mono text-data text-primary">
              {coverage.data.techniques_seen}
            </span>{' '}
            techniques detected ·{' '}
            <span className="font-mono text-data text-primary">
              {formatCount(coverage.data.total_events)}
            </span>{' '}
            mapped events
            {Object.entries(coverage.data.by_source).map(([src, n]) => (
              <span key={src} className={src === 'ai' ? 'text-(--sev-medium)' : 'text-tertiary'}>
                {' '}
                · {src === 'ai' ? 'AI-inferred' : src}:{' '}
                <span className="font-mono">{formatCount(n)}</span>
              </span>
            ))}
          </p>
        )}
        {(coverage.data?.by_source.ai ?? 0) > 0 && (
          <span
            title={AI_HINT}
            className="flex items-center gap-1.5 text-[11px] leading-4 text-tertiary"
          >
            <AiBadge /> dashed = AI-inferred, review-grade (not scored)
          </span>
        )}
      </div>

      {matrix.isLoading && (
        <div className="flex flex-1 items-center justify-center">
          <ArgusMark size={44} spinning className="opacity-40" />
        </div>
      )}

      <div className="flex min-h-0 flex-1 gap-4">
        <div className="min-w-0 flex-1 overflow-auto rounded-card border-[0.5px] border-subtle bg-elevated p-3">
          <div className="flex gap-2">
            {columns.map((col) => (
              <div key={col.tactic} className="w-40 shrink-0">
                <div className="mb-1.5 border-b-[0.5px] border-subtle pb-1.5">
                  <div className="truncate text-label font-medium text-primary">
                    {tacticLabel(col.tactic)}
                  </div>
                  <div className="font-mono text-[10px] leading-4 text-tertiary">
                    {col.techniques.length} techniques
                  </div>
                </div>
                <div className="space-y-1">
                  {col.techniques.map((t) => {
                    const count = hits.get(t.technique_id) ?? 0
                    const ai = aiStatus.get(t.technique_id)
                    // emerald intensity = detection frequency (§4.7). AI-only
                    // techniques are NOT confirmed detections, so they get no
                    // emerald fill — a dashed amber outline marks them tentative.
                    const intensity =
                      count === 0 ? 0 : 0.1 + 0.3 * (Math.log1p(count) / Math.log1p(maxHits))
                    const emerald = count > 0 && ai !== 'only'
                    return (
                      <button
                        key={`${col.tactic}-${t.technique_id}`}
                        type="button"
                        onClick={() => setSelected(t.technique_id)}
                        className={`w-full rounded-[6px] border-[0.5px] px-2 py-1.5 text-left transition-colors duration-120 hover:border-strong ${
                          selected === t.technique_id
                            ? 'border-accent'
                            : ai === 'only'
                              ? 'border-dashed border-(--sev-medium)'
                              : 'border-subtle'
                        }`}
                        style={{
                          backgroundColor: emerald
                            ? `rgba(47, 230, 160, ${intensity})`
                            : 'var(--bg-base)',
                        }}
                      >
                        <div className="flex items-center gap-1">
                          <div className="truncate text-[11px] leading-4 text-primary">{t.name}</div>
                          {ai && <AiBadge />}
                        </div>
                        <div className="flex items-center justify-between font-mono text-[10px] leading-4 text-tertiary">
                          <span>{t.technique_id}</span>
                          {count > 0 && (
                            <span className={ai === 'only' ? 'text-(--sev-medium)' : 'text-accent'}>
                              {formatCount(count)}
                            </span>
                          )}
                        </div>
                      </button>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>

        {selected && (
          <TechniqueDrawer
            techniqueId={selected}
            coverage={coverage.data?.coverage ?? []}
            evidence={evidence.data?.items ?? []}
            onClose={() => setSelected(null)}
          />
        )}
      </div>
    </div>
  )
}

const AI_HINT =
  'AI-inferred by the technique classifier — a review-grade hint, capped low and ' +
  'excluded from alert scoring until validated.'

function AiBadge() {
  return (
    <span
      title={AI_HINT}
      className="shrink-0 rounded-[3px] border-[0.5px] border-dashed border-(--sev-medium) px-1 text-[9px] font-medium leading-[13px] text-(--sev-medium)"
    >
      AI
    </span>
  )
}

function TechniqueDrawer({
  techniqueId,
  coverage,
  evidence,
  onClose,
}: {
  techniqueId: string
  coverage: CoverageEntry[]
  evidence: api.EvidenceItem[]
  onClose: () => void
}) {
  const detail = useAuthedQuery(['mitre', 'technique', techniqueId], (t) =>
    api.getTechnique(t, techniqueId),
  )
  const related = coverage.filter(
    (c) => c.technique_id === techniqueId || c.technique_id.startsWith(`${techniqueId}.`),
  )
  const relatedEvidence = evidence
    .filter((e) =>
      e.technique_ids.some((t) => t === techniqueId || t.startsWith(`${techniqueId}.`)),
    )
    .slice(0, 6)

  return (
    <aside className="w-80 shrink-0 space-y-4 overflow-y-auto rounded-card border-[0.5px] border-subtle bg-elevated p-4">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="font-mono text-data text-tertiary">{techniqueId}</div>
          <h2 className="text-card-title">{detail.data?.name ?? '…'}</h2>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close"
          className="text-tertiary transition-colors duration-120 hover:text-primary"
        >
          <X size={15} strokeWidth={1.5} />
        </button>
      </div>

      {detail.data && (
        <>
          <div className="flex flex-wrap gap-1.5">
            {detail.data.tactics.map((t) => (
              <span
                key={t}
                className="rounded-full border-[0.5px] border-subtle px-2 py-0.5 text-[11px] leading-4 text-secondary"
              >
                {tacticLabel(t)}
              </span>
            ))}
          </div>
          {detail.data.description && (
            <p className="line-clamp-6 text-label text-secondary">{detail.data.description}</p>
          )}
          {detail.data.url && (
            <a
              href={detail.data.url}
              target="_blank"
              rel="noreferrer"
              className="text-label text-accent transition-colors duration-120 hover:text-accent-dim"
            >
              attack.mitre.org →
            </a>
          )}
        </>
      )}

      <div>
        <div className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.12em] text-tertiary">
          Detections in this tenant
        </div>
        {related.length === 0 && (
          <p className="text-label text-tertiary">No detections — a coverage gap.</p>
        )}
        <ul className="space-y-2">
          {related.map((c) => (
            <li key={c.technique_id} className="rounded-control bg-base p-2.5">
              <div className="flex justify-between font-mono text-[11px] leading-4">
                <span className="text-primary">{c.technique_id}</span>
                <span className="text-accent">{formatCount(c.event_count)} events</span>
              </div>
              <div className="mt-0.5 font-mono text-[10px] leading-4 text-tertiary">
                {formatUtcDateTime(c.first_seen)} → {formatUtcDateTime(c.last_seen)}
              </div>
              <div className="mt-0.5 text-[10px] leading-4 text-tertiary">
                {Object.entries(c.sources).map(([s, n], i) => (
                  <span key={s} className={s === 'ai' ? 'text-(--sev-medium)' : undefined}>
                    {i > 0 ? ' · ' : ''}
                    {s === 'ai' ? 'AI' : s}: {n}
                  </span>
                ))}
                {' · '}max confidence {c.max_confidence}
              </div>
            </li>
          ))}
        </ul>
      </div>

      <div>
        <div className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.12em] text-tertiary">
          Related evidence
        </div>
        {relatedEvidence.length === 0 && (
          <p className="text-label text-tertiary">No correlated evidence cites it.</p>
        )}
        <ul className="space-y-1">
          {relatedEvidence.map((e) => (
            <li key={e.id}>
              <Link
                to={`/workspace?evidence=${e.id}`}
                className="flex justify-between rounded-control px-2 py-1.5 font-mono text-data text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
              >
                <span>
                  #{e.id} {e.host_name ?? ''}
                </span>
                <span className="text-tertiary">score {e.score}</span>
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </aside>
  )
}
