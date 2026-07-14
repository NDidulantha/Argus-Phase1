import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Plug, Plus, RefreshCw, Trash2, X } from 'lucide-react'
import { ArgusMark } from '../components/ArgusMark'
import { useAuth } from '../context/AuthContext'
import { useAuthedQuery } from '../hooks/useAuthedQuery'
import * as api from '../lib/api'
import type { Connector, ConnectorCatalogEntry, ConnectorTestResult } from '../lib/api'
import { formatUtcDateTime } from '../lib/format'

const STATUS_STYLE: Record<Connector['status'], { dot: string; text: string; label: string }> = {
  healthy: { dot: 'bg-accent', text: 'text-accent', label: 'healthy' },
  error: { dot: 'bg-sev-critical', text: 'text-sev-critical', label: 'error' },
  unconfigured: { dot: 'bg-silver', text: 'text-secondary', label: 'not tested' },
}

export function Integrations() {
  const { token } = useAuth()
  const queryClient = useQueryClient()
  const [wizardOpen, setWizardOpen] = useState(false)

  const catalog = useAuthedQuery(['connectors', 'catalog'], api.getConnectorCatalog)
  const connectors = useAuthedQuery(['connectors', 'list'], api.listConnectors, {
    refetchInterval: 30_000,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['connectors', 'list'] })

  const runTest = useMutation({
    mutationFn: (id: number) => api.testConnector(token!, id),
    onSuccess: invalidate,
  })
  const remove = useMutation({
    mutationFn: (id: number) => api.deleteConnector(token!, id),
    onSuccess: invalidate,
  })

  const configured = connectors.data?.items ?? []
  const planned = (catalog.data ?? []).filter((c) => !c.supported)

  return (
    <div className="space-y-5 p-6">
      <div className="flex items-baseline justify-between">
        <h1 className="text-page-title">Integrations</h1>
        <button
          type="button"
          onClick={() => setWizardOpen(true)}
          className="flex items-center gap-1.5 rounded-control bg-accent px-3 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim"
        >
          <Plus size={13} strokeWidth={2} />
          Add connector
        </button>
      </div>

      <section>
        <h2 className="mb-2.5 text-card-title">Configured</h2>
        {connectors.isLoading && (
          <div className="h-28 animate-pulse rounded-card border-[0.5px] border-subtle bg-elevated" />
        )}
        {!connectors.isLoading && configured.length === 0 && (
          <div className="flex flex-col items-center gap-3 rounded-card border-[0.5px] border-subtle bg-elevated py-10">
            <ArgusMark size={44} className="opacity-20" />
            <p className="text-label text-tertiary">
              No connectors yet. Add one to start pulling telemetry.
            </p>
          </div>
        )}
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {configured.map((c) => {
            const style = STATUS_STYLE[c.status]
            return (
              <div
                key={c.id}
                className={`rounded-card border-[0.5px] bg-elevated p-4 ${
                  c.status === 'healthy' ? 'border-accent/40 border-t-accent' : 'border-subtle'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="truncate text-card-title">{c.name}</div>
                    <div className="text-label text-tertiary">{c.vendor}</div>
                  </div>
                  <span className={`flex items-center gap-1.5 text-label ${style.text}`}>
                    <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} />
                    {style.label}
                  </span>
                </div>
                <div className="mt-2 truncate font-mono text-data text-secondary">
                  {c.endpoint_url}
                </div>
                <div className="mt-1 font-mono text-[11px] leading-4 text-tertiary">
                  last check:{' '}
                  {c.last_checked_at ? formatUtcDateTime(c.last_checked_at) : 'never'}
                </div>
                {c.last_error && (
                  <p className="mt-2 text-[11px] leading-4 text-sev-critical">{c.last_error}</p>
                )}
                <div className="mt-3 flex gap-2">
                  <button
                    type="button"
                    onClick={() => runTest.mutate(c.id)}
                    disabled={runTest.isPending}
                    className="flex items-center gap-1.5 rounded-control border-[0.5px] border-subtle px-2.5 py-1 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary disabled:opacity-60"
                  >
                    <RefreshCw
                      size={11}
                      strokeWidth={1.5}
                      className={runTest.isPending ? 'animate-scan-ring' : ''}
                    />
                    Test
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      if (confirm(`Remove connector "${c.name}"? Ingested events stay.`)) {
                        remove.mutate(c.id)
                      }
                    }}
                    className="flex items-center gap-1.5 rounded-control border-[0.5px] border-subtle px-2.5 py-1 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-sev-critical"
                  >
                    <Trash2 size={11} strokeWidth={1.5} />
                    Remove
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      </section>

      <section>
        <h2 className="mb-2.5 text-card-title">Planned connectors</h2>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {planned.map((c) => (
            <div
              key={c.vendor}
              className="rounded-card border-[0.5px] border-subtle bg-elevated p-4 opacity-60"
            >
              <div className="flex items-center gap-2">
                <Plug size={14} strokeWidth={1.5} className="text-silver" />
                <span className="text-card-title">{c.name}</span>
              </div>
              <p className="mt-1.5 text-label text-secondary">{c.description}</p>
              <span className="mt-2 inline-block rounded-full border-[0.5px] border-strong px-2 py-0.5 text-[11px] leading-4 text-tertiary">
                planned
              </span>
            </div>
          ))}
        </div>
      </section>

      {wizardOpen && catalog.data && (
        <ConnectorWizard
          catalog={catalog.data.filter((c) => c.supported)}
          onClose={() => setWizardOpen(false)}
          onCreated={invalidate}
        />
      )}
    </div>
  )
}

const STEPS = ['Vendor', 'Connection', 'Test', 'Field mapping', 'Confirm'] as const

function ConnectorWizard({
  catalog,
  onClose,
  onCreated,
}: {
  catalog: ConnectorCatalogEntry[]
  onClose: () => void
  onCreated: () => void
}) {
  const { token } = useAuth()
  const [step, setStep] = useState(0)
  const [vendor, setVendor] = useState<ConnectorCatalogEntry | null>(
    catalog.length === 1 ? catalog[0] : null,
  )
  const [name, setName] = useState('')
  const [endpoint, setEndpoint] = useState('')
  const [credentials, setCredentials] = useState<Record<string, string>>({})
  const [verifyTls, setVerifyTls] = useState(true)
  const [testResult, setTestResult] = useState<ConnectorTestResult | null>(null)

  const test = useMutation({
    mutationFn: () =>
      api.testConnectorDraft(token!, {
        vendor: vendor!.vendor,
        endpoint_url: endpoint,
        credentials,
        verify_tls: verifyTls,
      }),
    onSuccess: setTestResult,
  })

  const create = useMutation({
    mutationFn: async () => {
      const created = await api.createConnector(token!, {
        vendor: vendor!.vendor,
        name,
        endpoint_url: endpoint,
        credentials,
        verify_tls: verifyTls,
      })
      // persist the health we just proved in the test step
      return api.testConnector(token!, created.id)
    },
    onSuccess: () => {
      onCreated()
      onClose()
    },
  })

  const detailsValid =
    name.trim() && endpoint.trim() && (vendor?.credential_fields ?? []).every((f) => credentials[f])

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-6"
      role="dialog"
      aria-modal="true"
      aria-label="Add connector"
    >
      <div className="w-full max-w-lg rounded-card border-[0.5px] border-subtle bg-elevated">
        <header className="flex items-center justify-between border-b-[0.5px] border-subtle px-5 py-3.5">
          <h2 className="text-card-title">Add connector</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="text-tertiary transition-colors duration-120 hover:text-primary"
          >
            <X size={16} strokeWidth={1.5} />
          </button>
        </header>

        <div className="flex gap-1.5 px-5 pt-3.5">
          {STEPS.map((s, i) => (
            <div key={s} className="flex-1">
              <div
                className={`h-0.5 rounded-full ${i <= step ? 'bg-accent' : 'bg-strong'}`}
              />
              <div
                className={`mt-1 text-[10px] leading-4 ${
                  i === step ? 'text-primary' : 'text-tertiary'
                }`}
              >
                {s}
              </div>
            </div>
          ))}
        </div>

        <div className="min-h-56 px-5 py-4">
          {step === 0 && (
            <div className="space-y-2">
              {catalog.map((c) => (
                <button
                  key={c.vendor}
                  type="button"
                  onClick={() => setVendor(c)}
                  className={`w-full rounded-control border-[0.5px] p-3 text-left transition-colors duration-120 ${
                    vendor?.vendor === c.vendor
                      ? 'border-accent bg-accent-bg/40'
                      : 'border-subtle hover:bg-hover'
                  }`}
                >
                  <div className="text-label font-medium text-primary">{c.name}</div>
                  <div className="text-label text-secondary">{c.description}</div>
                </button>
              ))}
              <p className="pt-1 text-[11px] leading-4 text-tertiary">
                More vendors are planned — only connectors with a shipped collector are listed.
              </p>
            </div>
          )}

          {step === 1 && vendor && (
            <div className="space-y-3">
              <label className="block">
                <span className="mb-1 block text-label text-secondary">Connection name</span>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={`${vendor.name} — production`}
                  className="w-full rounded-control border-[0.5px] border-subtle bg-base px-3 py-1.5 text-label text-primary outline-none transition-colors duration-120 placeholder:text-tertiary focus:border-strong"
                />
              </label>
              <label className="block">
                <span className="mb-1 block text-label text-secondary">Endpoint</span>
                <input
                  type="text"
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  placeholder={vendor.endpoint_hint}
                  className="w-full rounded-control border-[0.5px] border-subtle bg-base px-3 py-1.5 font-mono text-data text-primary outline-none transition-colors duration-120 placeholder:text-tertiary focus:border-strong"
                />
              </label>
              {(vendor.credential_fields ?? []).map((f) => (
                <label key={f} className="block">
                  <span className="mb-1 block text-label text-secondary">
                    {f[0].toUpperCase() + f.slice(1)}
                  </span>
                  <input
                    type={f === 'password' ? 'password' : 'text'}
                    value={credentials[f] ?? ''}
                    onChange={(e) =>
                      setCredentials((prev) => ({ ...prev, [f]: e.target.value }))
                    }
                    autoComplete="off"
                    className="w-full rounded-control border-[0.5px] border-subtle bg-base px-3 py-1.5 font-mono text-data text-primary outline-none transition-colors duration-120 focus:border-strong"
                  />
                </label>
              ))}
              <label className="flex items-center gap-2 text-label text-secondary">
                <input
                  type="checkbox"
                  checked={!verifyTls}
                  onChange={(e) => setVerifyTls(!e.target.checked)}
                  className="accent-(--accent)"
                />
                Skip TLS verification (lab self-signed certificates)
              </label>
            </div>
          )}

          {step === 2 && (
            <div className="flex flex-col items-center gap-4 py-6">
              {test.isPending ? (
                <>
                  <ArgusMark size={48} spinning className="opacity-60" />
                  <p className="animate-pulse text-label text-secondary">
                    Probing {endpoint}…
                  </p>
                </>
              ) : testResult ? (
                <>
                  <span
                    className={`text-label ${testResult.ok ? 'text-accent' : 'text-sev-critical'}`}
                  >
                    {testResult.ok ? '✓ Connection healthy' : 'Connection failed'}
                  </span>
                  <p className="text-center text-label text-secondary">{testResult.detail}</p>
                  <p className="font-mono text-[11px] leading-4 text-tertiary">
                    {testResult.latency_ms} ms
                  </p>
                  <button
                    type="button"
                    onClick={() => test.mutate()}
                    className="rounded-control border-[0.5px] border-subtle px-3 py-1.5 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
                  >
                    Test again
                  </button>
                </>
              ) : (
                <>
                  <p className="text-label text-secondary">
                    ARGUS will probe the endpoint with the credentials you entered. Nothing is
                    saved yet.
                  </p>
                  <button
                    type="button"
                    onClick={() => test.mutate()}
                    className="rounded-control bg-accent px-4 py-2 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim"
                  >
                    Test connection
                  </button>
                </>
              )}
            </div>
          )}

          {step === 3 && vendor && (
            <div>
              <p className="mb-2.5 text-label text-secondary">
                How {vendor.name} fields land in normalized ARGUS events (built into the{' '}
                {vendor.vendor} normalizer):
              </p>
              <div className="overflow-hidden rounded-control border-[0.5px] border-subtle">
                <table className="w-full border-collapse">
                  <tbody>
                    {Object.entries(vendor.default_mapping ?? {}).map(([src, dst]) => (
                      <tr key={src} className="border-b-[0.5px] border-subtle last:border-0">
                        <td className="bg-base px-3 py-1.5 font-mono text-[11px] leading-4 text-secondary">
                          {src}
                        </td>
                        <td className="px-3 py-1.5 font-mono text-[11px] leading-4 text-primary">
                          → {dst}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {step === 4 && vendor && (
            <div className="space-y-2 text-label">
              <p className="text-secondary">Ready to save:</p>
              <dl className="space-y-1.5 rounded-control border-[0.5px] border-subtle bg-base p-3">
                <div className="flex justify-between gap-3">
                  <dt className="text-tertiary">Vendor</dt>
                  <dd className="text-primary">{vendor.name}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-tertiary">Name</dt>
                  <dd className="text-primary">{name}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-tertiary">Endpoint</dt>
                  <dd className="break-all font-mono text-data text-primary">{endpoint}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-tertiary">TLS verification</dt>
                  <dd className="text-primary">{verifyTls ? 'on' : 'off (lab)'}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-tertiary">Last test</dt>
                  <dd className={testResult?.ok ? 'text-accent' : 'text-sev-critical'}>
                    {testResult ? (testResult.ok ? 'healthy' : 'failed') : 'not run'}
                  </dd>
                </div>
              </dl>
              {create.isError && (
                <p className="text-sev-critical">
                  Saving failed: {(create.error as Error).message}. Try again.
                </p>
              )}
            </div>
          )}
        </div>

        <footer className="flex justify-between border-t-[0.5px] border-subtle px-5 py-3">
          <button
            type="button"
            onClick={() => (step === 0 ? onClose() : setStep(step - 1))}
            className="rounded-control border-[0.5px] border-subtle px-3 py-1.5 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
          >
            {step === 0 ? 'Cancel' : 'Back'}
          </button>
          {step < 4 ? (
            <button
              type="button"
              onClick={() => setStep(step + 1)}
              disabled={
                (step === 0 && !vendor) ||
                (step === 1 && !detailsValid) ||
                (step === 2 && !testResult?.ok)
              }
              className="rounded-control bg-accent px-4 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim disabled:opacity-50"
            >
              Continue
            </button>
          ) : (
            <button
              type="button"
              onClick={() => create.mutate()}
              disabled={create.isPending}
              className="rounded-control bg-accent px-4 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim disabled:opacity-60"
            >
              {create.isPending ? 'Saving…' : 'Save connector'}
            </button>
          )}
        </footer>
      </div>
    </div>
  )
}
