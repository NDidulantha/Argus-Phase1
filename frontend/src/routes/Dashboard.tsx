import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { AlertQueueTable } from '../components/AlertQueueTable'
import { MetricTile } from '../components/MetricTile'
import { useAuthedQuery } from '../hooks/useAuthedQuery'
import * as api from '../lib/api'
import { formatCount, formatUtcDateTime, isoHoursAgo, relativeAge } from '../lib/format'
import { CRITICAL_EVENT_LEVEL, eventSeverity, severityDot } from '../lib/severity'

const REFRESH_MS = 30_000

export function Dashboard() {
  const evidence = useAuthedQuery(
    ['evidence', 'queue'],
    (token) => api.listEvidence(token, { limit: 200 }),
    { refetchInterval: REFRESH_MS },
  )
  const events24h = useAuthedQuery(
    ['events', '24h-total'],
    (token) => api.listEvents(token, { start: isoHoursAgo(24), limit: 1 }),
    { refetchInterval: REFRESH_MS },
  )
  const critical24h = useAuthedQuery(
    ['events', '24h-critical'],
    (token) =>
      api.listEvents(token, {
        start: isoHoursAgo(24),
        min_severity: CRITICAL_EVENT_LEVEL,
        limit: 1,
      }),
    { refetchInterval: REFRESH_MS },
  )
  const recentEvents = useAuthedQuery(
    ['events', 'guardian-feed'],
    (token) => api.listEvents(token, { limit: 6 }),
    { refetchInterval: REFRESH_MS },
  )
  const apiHealth = useQuery({
    queryKey: ['health'],
    queryFn: api.healthReady,
    refetchInterval: REFRESH_MS,
    retry: 1,
  })
  const connectors = useAuthedQuery(['connectors', 'list'], api.listConnectors, {
    refetchInterval: REFRESH_MS,
  })

  const openAlerts = evidence.data
    ? evidence.data.items.filter((i) => i.status === 'open').length
    : null

  return (
    <div className="space-y-4 p-6">
      <h1 className="text-page-title">Dashboard</h1>

      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        <MetricTile label="Open alerts" value={openAlerts === null ? null : formatCount(openAlerts)} />
        <MetricTile
          label="Active hunts"
          value="0"
          valueClassName="text-accent"
          hint="No hunts running"
        />
        <MetricTile
          label="Events (24h)"
          value={events24h.data ? formatCount(events24h.data.total) : null}
        />
        <MetricTile
          label="Critical (24h)"
          value={critical24h.data ? formatCount(critical24h.data.total) : null}
          valueClassName={critical24h.data?.total ? 'text-sev-critical' : 'text-primary'}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
        <section className="rounded-card border-[0.5px] border-subtle bg-elevated">
          <header className="flex items-baseline justify-between px-4 pb-1 pt-3.5">
            <h2 className="text-card-title">Priority alert queue</h2>
            <Link
              to="/alerts"
              className="text-label text-secondary transition-colors duration-120 hover:text-primary"
            >
              View all
            </Link>
          </header>
          <AlertQueueTable
            items={evidence.data?.items.slice(0, 10)}
            loading={evidence.isLoading}
            emptyMessage="No alerts yet. Connect a collector or run correlation."
          />
        </section>

        <div className="space-y-4">
          <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
            <h2 className="text-card-title">Collector health</h2>
            <div className="mt-3 space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      apiHealth.isError ? 'bg-sev-critical' : 'bg-accent'
                    }`}
                  />
                  <span className="text-label text-primary">Ingest API</span>
                </div>
                <span className="text-label text-tertiary">
                  {apiHealth.isError ? 'unreachable' : 'healthy'}
                </span>
              </div>
              {connectors.data?.items.map((c) => (
                <div key={c.id} className="flex items-center justify-between">
                  <div className="flex min-w-0 items-center gap-2.5">
                    <span
                      className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                        c.status === 'healthy'
                          ? 'bg-accent'
                          : c.status === 'error'
                            ? 'bg-sev-critical'
                            : 'bg-silver'
                      }`}
                    />
                    <span className="truncate text-label text-primary">{c.name}</span>
                  </div>
                  <span className="shrink-0 text-label text-tertiary">
                    {c.status === 'unconfigured' ? 'not tested' : c.status}
                  </span>
                </div>
              ))}
            </div>
            <Link
              to="/integrations"
              className="mt-3 block text-label text-secondary transition-colors duration-120 hover:text-primary"
            >
              Configure connectors →
            </Link>
          </section>

          <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-4">
            <h2 className="text-card-title">Guardian activity</h2>
            <ul className="mt-3 space-y-2.5">
              {recentEvents.isLoading &&
                Array.from({ length: 4 }, (_, i) => (
                  <li key={i} className="h-4 animate-pulse rounded bg-hover" />
                ))}
              {recentEvents.data?.items.length === 0 && (
                <li className="text-label text-tertiary">Watching. No recent telemetry.</li>
              )}
              {recentEvents.data?.items.map((e) => (
                <li key={e.id} className="flex items-start gap-2.5">
                  <span
                    className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${
                      severityDot[eventSeverity(e.severity)]
                    }`}
                  />
                  <div className="min-w-0">
                    <div className="truncate text-label text-secondary">
                      {e.action ?? e.category}
                    </div>
                    <div
                      className="font-mono text-[11px] leading-4 text-tertiary"
                      title={formatUtcDateTime(e.event_time)}
                    >
                      {e.host_name ?? 'unknown host'} · {relativeAge(e.event_time)}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </section>
        </div>
      </div>
    </div>
  )
}
