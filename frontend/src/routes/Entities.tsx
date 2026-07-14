import { useMemo, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Search } from 'lucide-react'
import { ArgusMark } from '../components/ArgusMark'
import { ConfidenceRing } from '../components/workspace/ConfidenceRing'
import { SeverityBadge } from '../components/SeverityBadge'
import { useAuthedQuery } from '../hooks/useAuthedQuery'
import * as api from '../lib/api'
import type { EventItem, GraphEntity } from '../lib/api'
import { formatCount, formatUtcDateTime, formatUtcTime, relativeAge } from '../lib/format'
import { eventSeverity, scoreSeverity, severityDot } from '../lib/severity'

const TYPE_DOT: Record<string, string> = {
  host: '#7F9CF2',
  user: '#A79FC4',
  process: '#9C7BF0',
  ip: '#5EEAB4',
}

export function Entities() {
  const [params, setParams] = useSearchParams()
  const query = params.get('q') ?? ''
  const selectedId = Number(params.get('id')) || null
  const [draft, setDraft] = useState(query)

  const results = useAuthedQuery(
    ['entities', 'search', query],
    (t) => api.listEntities(t, { search: query || undefined, limit: 50 }),
  )

  function submit(e: FormEvent) {
    e.preventDefault()
    setParams(draft.trim() ? { q: draft.trim() } : {})
  }


  return (
    <div className="space-y-4 p-6">
      <h1 className="text-page-title">Entity explorer</h1>

      {/* Search-first (§4.8) */}
      <form onSubmit={submit} className="max-w-xl">
        <label className="flex items-center gap-2.5 rounded-control border-[0.5px] border-subtle bg-elevated px-3 py-2 transition-colors duration-120 focus-within:border-strong">
          <Search size={15} strokeWidth={1.5} className="text-tertiary" />
          <input
            type="search"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="Search a host, user, IP, or process…"
            className="w-full bg-transparent text-body text-primary outline-none placeholder:text-tertiary"
          />
        </label>
      </form>

      {selectedId ? (
        <EntityProfile
          entityId={selectedId}
          onBack={() => setParams(query ? { q: query } : {})}
        />
      ) : (
        <section className="max-w-3xl overflow-x-auto rounded-card border-[0.5px] border-subtle bg-elevated">
          <table className="w-full border-collapse text-label">
            <thead>
              <tr className="text-left text-tertiary">
                <th className="px-3 py-2 font-normal">Type</th>
                <th className="px-3 py-2 font-normal">Entity</th>
                <th className="px-3 py-2 text-right font-normal">First seen</th>
                <th className="px-3 py-2 text-right font-normal">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {results.isLoading &&
                Array.from({ length: 5 }, (_, i) => (
                  <tr key={i} className="border-t-[0.5px] border-subtle">
                    <td colSpan={4} className="px-3 py-3">
                      <div className="h-4 animate-pulse rounded bg-hover" />
                    </td>
                  </tr>
                ))}
              {results.data?.items.length === 0 && (
                <tr className="border-t-[0.5px] border-subtle">
                  <td colSpan={4} className="px-3 py-10">
                    <div className="flex flex-col items-center gap-3">
                      <ArgusMark size={44} className="opacity-20" />
                      <span className="text-tertiary">
                        {query ? `Nothing matches “${query}”.` : 'No entities yet.'}
                      </span>
                    </div>
                  </td>
                </tr>
              )}
              {results.data?.items.map((e) => (
                <tr
                  key={e.id}
                  onClick={() =>
                    setParams(query ? { q: query, id: String(e.id) } : { id: String(e.id) })
                  }
                  className="cursor-pointer border-t-[0.5px] border-subtle transition-colors duration-120 hover:bg-hover"
                >
                  <td className="px-3 py-2">
                    <span className="flex items-center gap-2 text-secondary">
                      <span
                        className="h-2 w-2 rounded-full"
                        style={{ background: TYPE_DOT[e.entity_type] ?? '#B8B5C9' }}
                      />
                      {e.entity_type}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-data text-primary">{e.entity_key}</td>
                  <td
                    className="px-3 py-2 text-right font-mono text-data text-tertiary"
                    title={formatUtcDateTime(e.first_seen)}
                  >
                    {relativeAge(e.first_seen)}
                  </td>
                  <td
                    className="px-3 py-2 text-right font-mono text-data text-tertiary"
                    title={formatUtcDateTime(e.last_seen)}
                  >
                    {relativeAge(e.last_seen)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  )
}

function EntityProfile({ entityId, onBack }: { entityId: number; onBack: () => void }) {
  const neighborhood = useAuthedQuery(['entities', 'nb', entityId], (t) =>
    api.getNeighborhood(t, entityId),
  )
  const entity: GraphEntity | undefined = neighborhood.data?.root
  const evidence = useAuthedQuery(['evidence', 'queue'], (t) => api.listEvidence(t, { limit: 200 }))
  // hosts get a server-side filter; user/ip are filtered from the latest events
  const events = useAuthedQuery(['entities', 'events', entityId, entity?.entity_type], (t) =>
    api.listEvents(t, {
      host: entity?.entity_type === 'host' ? entity.entity_key : undefined,
      limit: 200,
    }),
  )

  const relatedEvidence = useMemo(
    () =>
      (evidence.data?.items ?? []).filter(
        (e) =>
          entity?.entity_type === 'host' &&
          e.host_name?.toLowerCase() === entity.entity_key.toLowerCase(),
      ),
    [evidence.data, entity],
  )
  const topScore = relatedEvidence.length
    ? Math.max(...relatedEvidence.map((e) => e.score))
    : null

  const relatedEvents = useMemo(() => {
    if (!entity) return []
    const items = events.data?.items ?? []
    const key = entity.entity_key.toLowerCase()
    switch (entity.entity_type) {
      case 'host':
        return items
      case 'user':
        return items.filter((e) => e.user_name?.toLowerCase() === key)
      case 'ip':
        return items.filter((e) => e.src_ip === entity.entity_key || e.dst_ip === entity.entity_key)
      default:
        return []
    }
  }, [events.data, entity])

  if (!entity) {
    return (
      <div className="flex flex-col items-center gap-3 py-14">
        {neighborhood.isLoading ? (
          <ArgusMark size={44} spinning className="opacity-40" />
        ) : (
          <>
            <ArgusMark size={44} className="opacity-20" />
            <p className="text-label text-tertiary">Entity not found.</p>
          </>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <button
        type="button"
        onClick={onBack}
        className="text-label text-secondary transition-colors duration-120 hover:text-primary"
      >
        ← Results
      </button>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
        <div className="space-y-4">
          <section className="flex items-center gap-6 rounded-card border-[0.5px] border-subtle bg-elevated p-5">
            {topScore !== null ? (
              <ConfidenceRing score={topScore} label="Top evidence score" />
            ) : (
              <ArgusMark size={56} className="opacity-25" />
            )}
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span
                  className="h-2.5 w-2.5 rounded-full"
                  style={{ background: TYPE_DOT[entity.entity_type] ?? '#B8B5C9' }}
                />
                <span className="text-label text-tertiary">{entity.entity_type}</span>
                {topScore !== null && <SeverityBadge severity={scoreSeverity(topScore)} />}
              </div>
              <h2 className="mt-1 break-all font-mono text-[18px] font-medium text-primary">
                {entity.entity_key}
              </h2>
              <p className="mt-1 font-mono text-[11px] leading-4 text-tertiary">
                first seen {formatUtcDateTime(entity.first_seen)} · last seen{' '}
                {formatUtcDateTime(entity.last_seen)}
              </p>
              <div className="mt-2 flex gap-2">
                <Link
                  to="/graph"
                  className="rounded-control border-[0.5px] border-subtle px-2.5 py-1 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
                >
                  View in graph
                </Link>
                <Link
                  to="/timeline"
                  className="rounded-control border-[0.5px] border-subtle px-2.5 py-1 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
                >
                  View timeline
                </Link>
              </div>
            </div>
          </section>

          <section className="overflow-x-auto rounded-card border-[0.5px] border-subtle bg-elevated">
            <header className="px-4 pb-1 pt-3.5">
              <h3 className="text-card-title">Recent events</h3>
            </header>
            {entity.entity_type === 'process' ? (
              <p className="px-4 pb-4 text-label text-tertiary">
                Process activity lives in the graph — events aren't indexed by process yet.
              </p>
            ) : (
              <table className="w-full border-collapse text-label">
                <tbody>
                  {relatedEvents.length === 0 && (
                    <tr>
                      <td className="px-4 pb-4 text-tertiary">
                        No matching events in the latest 200.
                      </td>
                    </tr>
                  )}
                  {relatedEvents.slice(0, 12).map((e: EventItem) => (
                    <tr key={e.id} className="border-t-[0.5px] border-subtle">
                      <td className="px-4 py-1.5">
                        <span
                          className={`mr-2 inline-block h-1.5 w-1.5 rounded-full ${severityDot[eventSeverity(e.severity)]}`}
                        />
                        <span className="text-secondary">{e.action ?? e.category}</span>
                      </td>
                      <td className="px-3 py-1.5 text-right font-mono text-[11px] leading-4 text-tertiary">
                        {formatUtcTime(e.event_time)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </div>

        <div className="space-y-4">
          <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
            <h3 className="text-card-title">Related entities</h3>
            <div className="mt-2.5 flex flex-wrap gap-1.5">
              {neighborhood.data?.entities.length === 0 && (
                <p className="text-label text-tertiary">No edges recorded.</p>
              )}
              {neighborhood.data?.entities.map((n) => (
                <Link
                  key={n.id}
                  to={`/entities?id=${n.id}`}
                  className="rounded-control border-[0.5px] border-subtle bg-base px-2 py-1 transition-colors duration-120 hover:bg-hover"
                >
                  <span className="text-[11px] leading-4 text-tertiary">{n.entity_type} </span>
                  <span className="font-mono text-data text-primary">{n.entity_key}</span>
                </Link>
              ))}
            </div>
          </section>

          <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
            <h3 className="text-card-title">Evidence on this entity</h3>
            <ul className="mt-2.5 space-y-1">
              {relatedEvidence.length === 0 && (
                <li className="text-label text-tertiary">
                  {entity.entity_type === 'host'
                    ? 'No correlated evidence.'
                    : 'Evidence is tracked per host.'}
                </li>
              )}
              {relatedEvidence.slice(0, 8).map((e) => (
                <li key={e.id}>
                  <Link
                    to={`/workspace?evidence=${e.id}`}
                    className="flex justify-between rounded-control px-2 py-1.5 font-mono text-data text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
                  >
                    <span>#{e.id}</span>
                    <span className="text-tertiary">
                      score {formatCount(e.score)} · {e.status}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </section>
        </div>
      </div>
    </div>
  )
}
