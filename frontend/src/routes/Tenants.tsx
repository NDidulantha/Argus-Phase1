import { Link } from 'react-router-dom'
import { LogOut } from 'lucide-react'
import { MetricTile } from '../components/MetricTile'
import { useAuth } from '../context/AuthContext'
import { useAuthedQuery } from '../hooks/useAuthedQuery'
import * as api from '../lib/api'
import { formatCount, isoHoursAgo } from '../lib/format'

export function Tenants() {
  const { tenantSlug, user, logout } = useAuth()

  const evidence = useAuthedQuery(['evidence', 'queue'], (t) => api.listEvidence(t, { limit: 200 }))
  const events24h = useAuthedQuery(['events', '24h-total'], (t) =>
    api.listEvents(t, { start: isoHoursAgo(24), limit: 1 }),
  )
  const cases = useAuthedQuery(['cases', 'all'], (t) => api.listCases(t, { limit: 200 }))
  const connectors = useAuthedQuery(['connectors', 'list'], api.listConnectors)
  const entities = useAuthedQuery(['entities', 'count'], (t) => api.listEntities(t, { limit: 1 }))

  const openAlerts = evidence.data
    ? formatCount(evidence.data.items.filter((i) => i.status === 'open').length)
    : null
  const openCases = cases.data
    ? formatCount(cases.data.items.filter((c) => c.status !== 'closed').length)
    : null

  return (
    <div className="max-w-4xl space-y-4 p-6">
      <h1 className="text-page-title">Tenants</h1>

      <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-label text-tertiary">Active tenant</div>
            <div className="font-mono text-[18px] font-medium text-primary">
              {tenantSlug ?? '—'}
            </div>
            <div className="mt-0.5 text-label text-secondary">
              {user ? `your role: ${user.role}` : ''}
            </div>
          </div>
          <button
            type="button"
            onClick={logout}
            className="flex items-center gap-2 rounded-control border-[0.5px] border-subtle px-3 py-1.5 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
          >
            <LogOut size={13} strokeWidth={1.5} />
            Sign in to another tenant
          </button>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
          <MetricTile label="Open alerts" value={openAlerts} />
          <MetricTile label="Open cases" value={openCases} />
          <MetricTile
            label="Events (24h)"
            value={events24h.data ? formatCount(events24h.data.total) : null}
          />
          <MetricTile
            label="Entities"
            value={entities.data ? formatCount(entities.data.total) : null}
          />
        </div>

        <div className="mt-4">
          <div className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.12em] text-tertiary">
            Connectors
          </div>
          {connectors.data?.items.length === 0 && (
            <p className="text-label text-tertiary">
              None configured.{' '}
              <Link to="/integrations" className="text-accent hover:text-accent-dim">
                Add one →
              </Link>
            </p>
          )}
          <div className="space-y-1.5">
            {connectors.data?.items.map((c) => (
              <div key={c.id} className="flex items-center justify-between">
                <span className="flex items-center gap-2.5 text-label text-primary">
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      c.status === 'healthy'
                        ? 'bg-accent'
                        : c.status === 'error'
                          ? 'bg-sev-critical'
                          : 'bg-silver'
                    }`}
                  />
                  {c.name}
                </span>
                <span className="text-label text-tertiary">{c.vendor}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-5">
        <h2 className="text-card-title">MSSP control plane</h2>
        <p className="mt-2 max-w-2xl text-label text-secondary">
          Every session is scoped to one tenant: the JWT carries the tenant, and row-level
          security isolates its data end to end — it is impossible to see another client's
          telemetry from here. Tenants and their users are managed in the{' '}
          <Link to="/admin" className="text-accent hover:text-accent-dim">
            operator console
          </Link>{' '}
          (admin-key protected), not from an analyst session.
        </p>
      </section>
    </div>
  )
}
