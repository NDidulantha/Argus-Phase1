import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRound, Plus, ShieldCheck, UserRound, X } from 'lucide-react'
import { ArgusMark } from '../components/ArgusMark'
import * as api from '../lib/api'
import { ApiError } from '../lib/api'
import { formatCount, formatUtcDateTime } from '../lib/format'

const KEY_STORAGE = 'argus-admin-key'

// The operator console authenticates with the platform admin key, not the
// analyst JWT — it is the control plane over every tenant (ADR 0005).
export function Admin() {
  const [adminKey, setAdminKey] = useState<string | null>(
    () => sessionStorage.getItem(KEY_STORAGE),
  )

  const saveKey = (key: string) => {
    sessionStorage.setItem(KEY_STORAGE, key)
    setAdminKey(key)
  }
  const clearKey = () => {
    sessionStorage.removeItem(KEY_STORAGE)
    setAdminKey(null)
  }

  if (!adminKey) return <KeyGate onSubmit={saveKey} />
  return <Console adminKey={adminKey} onBadKey={clearKey} />
}

function KeyGate({ onSubmit }: { onSubmit: (key: string) => void }) {
  const [value, setValue] = useState('')
  return (
    <div className="flex min-h-[60vh] items-center justify-center p-6">
      <form
        onSubmit={(e) => {
          e.preventDefault()
          if (value.trim()) onSubmit(value.trim())
        }}
        className="w-full max-w-sm space-y-4 rounded-card border-[0.5px] border-subtle bg-elevated p-6"
      >
        <div className="flex items-center gap-2.5">
          <ShieldCheck size={18} strokeWidth={1.5} className="text-accent" />
          <h1 className="text-card-title">Operator console</h1>
        </div>
        <p className="text-label text-secondary">
          Tenant and user management is platform-operator territory. Enter the admin API key —
          it is held only for this browser session.
        </p>
        <label className="block">
          <span className="mb-1 block text-label text-secondary">Admin key</span>
          <input
            type="password"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            autoComplete="off"
            autoFocus
            className="w-full rounded-control border-[0.5px] border-subtle bg-base px-3 py-1.5 font-mono text-data text-primary outline-none transition-colors duration-120 focus:border-strong"
          />
        </label>
        <button
          type="submit"
          disabled={!value.trim()}
          className="flex w-full items-center justify-center gap-2 rounded-control bg-accent px-4 py-2 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim disabled:opacity-50"
        >
          <KeyRound size={13} strokeWidth={2} />
          Unlock console
        </button>
      </form>
    </div>
  )
}

function Console({ adminKey, onBadKey }: { adminKey: string; onBadKey: () => void }) {
  const queryClient = useQueryClient()
  const [selected, setSelected] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)

  const tenants = useQuery({
    queryKey: ['admin', 'tenants'],
    queryFn: () => api.adminListTenants(adminKey),
    retry: (count, error) => !(error instanceof ApiError && error.status === 401) && count < 2,
  })

  if (tenants.error instanceof ApiError && tenants.error.status === 401) {
    onBadKey()
    return null
  }

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['admin', 'tenants'] })
  const selectedTenant = tenants.data?.find((t) => t.id === selected) ?? null

  return (
    <div className="space-y-5 p-6">
      <div className="flex items-baseline justify-between">
        <div className="flex items-baseline gap-3">
          <h1 className="text-page-title">Operator console</h1>
          {tenants.data && (
            <span className="font-mono text-data text-tertiary">
              {tenants.data.length} tenants
            </span>
          )}
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setCreating(true)}
            className="flex items-center gap-1.5 rounded-control bg-accent px-3 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim"
          >
            <Plus size={13} strokeWidth={2} />
            New tenant
          </button>
          <button
            type="button"
            onClick={onBadKey}
            className="rounded-control border-[0.5px] border-subtle px-3 py-1.5 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
          >
            Lock
          </button>
        </div>
      </div>

      <section className="rounded-card border-[0.5px] border-subtle bg-elevated">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-label">
            <thead>
              <tr className="text-left text-tertiary">
                <th className="px-3 py-2 font-normal">Tenant</th>
                <th className="px-3 py-2 font-normal">Sector</th>
                <th className="px-3 py-2 text-right font-normal">Users</th>
                <th className="px-3 py-2 text-right font-normal">Events</th>
                <th className="px-3 py-2 text-right font-normal">Open alerts</th>
                <th className="px-3 py-2 font-normal">Status</th>
                <th className="px-3 py-2 font-normal">Created</th>
                <th className="px-3 py-2" aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {tenants.isLoading && (
                <tr className="border-t-[0.5px] border-subtle">
                  <td colSpan={8} className="px-3 py-3">
                    <div className="h-4 animate-pulse rounded bg-hover" />
                  </td>
                </tr>
              )}
              {tenants.data?.length === 0 && (
                <tr className="border-t-[0.5px] border-subtle">
                  <td colSpan={8} className="px-3 py-10">
                    <div className="flex flex-col items-center gap-3">
                      <ArgusMark size={44} className="opacity-20" />
                      <span className="text-tertiary">No tenants yet. Create the first one.</span>
                    </div>
                  </td>
                </tr>
              )}
              {tenants.data?.map((t) => (
                <tr
                  key={t.id}
                  onClick={() => setSelected(selected === t.id ? null : t.id)}
                  className={`cursor-pointer border-t-[0.5px] border-subtle transition-colors duration-120 hover:bg-hover ${
                    selected === t.id ? 'bg-hover' : ''
                  }`}
                >
                  <td className="px-3 py-2">
                    <div className="text-primary">{t.name}</div>
                    <div className="font-mono text-[11px] leading-4 text-tertiary">{t.slug}</div>
                  </td>
                  <td className="px-3 py-2 text-secondary">{t.sector ?? '—'}</td>
                  <td className="px-3 py-2 text-right font-mono text-data text-secondary">
                    {formatCount(t.user_count)}
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-data text-secondary">
                    {formatCount(t.event_count)}
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-data text-secondary">
                    {formatCount(t.open_alerts)}
                  </td>
                  <td className="px-3 py-2">
                    <span
                      className={`inline-block rounded-full border-[0.5px] px-2 py-0.5 text-[11px] leading-4 ${
                        t.is_active
                          ? 'border-accent/50 text-accent'
                          : 'border-strong text-tertiary'
                      }`}
                    >
                      {t.is_active ? 'active' : 'suspended'}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-data text-tertiary">
                    {formatUtcDateTime(t.created_at).slice(0, 10)}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <TenantRowActions adminKey={adminKey} tenant={t} onChanged={invalidate} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {selectedTenant && (
        <TenantUsers adminKey={adminKey} tenant={selectedTenant} />
      )}

      {creating && (
        <CreateTenantModal
          adminKey={adminKey}
          onClose={() => setCreating(false)}
          onCreated={invalidate}
        />
      )}
    </div>
  )
}

function TenantRowActions({
  adminKey,
  tenant,
  onChanged,
}: {
  adminKey: string
  tenant: api.AdminTenant
  onChanged: () => void
}) {
  const toggle = useMutation({
    mutationFn: () =>
      api.adminUpdateTenant(adminKey, tenant.id, { is_active: !tenant.is_active }),
    onSuccess: onChanged,
  })
  return (
    <button
      type="button"
      disabled={toggle.isPending}
      onClick={(e) => {
        e.stopPropagation()
        const verb = tenant.is_active ? 'Suspend' : 'Reactivate'
        if (confirm(`${verb} tenant "${tenant.name}"? Logins are affected immediately.`)) {
          toggle.mutate()
        }
      }}
      className={`rounded-control border-[0.5px] border-subtle px-2.5 py-1 text-[11px] leading-4 transition-colors duration-120 disabled:opacity-60 ${
        tenant.is_active
          ? 'text-secondary hover:border-sev-critical/50 hover:text-sev-critical'
          : 'text-secondary hover:bg-hover hover:text-accent'
      }`}
    >
      {tenant.is_active ? 'Suspend' : 'Reactivate'}
    </button>
  )
}

function TenantUsers({ adminKey, tenant }: { adminKey: string; tenant: api.AdminTenant }) {
  const queryClient = useQueryClient()
  const [adding, setAdding] = useState(false)

  const users = useQuery({
    queryKey: ['admin', 'users', tenant.id],
    queryFn: () => api.adminListUsers(adminKey, tenant.id),
  })
  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['admin', 'users', tenant.id] })
    queryClient.invalidateQueries({ queryKey: ['admin', 'tenants'] })
  }

  const update = useMutation({
    mutationFn: ({ userId, patch }: { userId: string; patch: { role?: string; is_active?: boolean } }) =>
      api.adminUpdateUser(adminKey, tenant.id, userId, patch),
    onSuccess: invalidate,
  })

  return (
    <section className="rounded-card border-[0.5px] border-subtle bg-elevated">
      <header className="flex items-center justify-between border-b-[0.5px] border-subtle px-4 py-3">
        <h2 className="flex items-center gap-2 text-card-title">
          <UserRound size={14} strokeWidth={1.5} className="text-silver" />
          Users — {tenant.name}
        </h2>
        <button
          type="button"
          onClick={() => setAdding(true)}
          className="flex items-center gap-1.5 rounded-control border-[0.5px] border-subtle px-2.5 py-1 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
        >
          <Plus size={11} strokeWidth={1.5} />
          Add user
        </button>
      </header>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-label">
          <thead>
            <tr className="text-left text-tertiary">
              <th className="px-3 py-2 font-normal">Email</th>
              <th className="px-3 py-2 font-normal">Role</th>
              <th className="px-3 py-2 font-normal">Status</th>
              <th className="px-3 py-2 font-normal">Created</th>
              <th className="px-3 py-2" aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {users.isLoading && (
              <tr className="border-t-[0.5px] border-subtle">
                <td colSpan={5} className="px-3 py-3">
                  <div className="h-4 animate-pulse rounded bg-hover" />
                </td>
              </tr>
            )}
            {users.data?.length === 0 && (
              <tr className="border-t-[0.5px] border-subtle">
                <td colSpan={5} className="px-3 py-6 text-center text-tertiary">
                  No users yet — this tenant cannot log in until one exists.
                </td>
              </tr>
            )}
            {users.data?.map((u) => (
              <tr key={u.id} className="border-t-[0.5px] border-subtle">
                <td className="px-3 py-2 font-mono text-data text-primary">{u.email}</td>
                <td className="px-3 py-2">
                  <select
                    value={u.role}
                    onChange={(e) => update.mutate({ userId: u.id, patch: { role: e.target.value } })}
                    className="rounded-control border-[0.5px] border-subtle bg-base px-2 py-1 text-label text-primary outline-none focus:border-strong"
                  >
                    <option value="analyst">analyst</option>
                    <option value="admin">admin</option>
                  </select>
                </td>
                <td className="px-3 py-2">
                  <span
                    className={`inline-block rounded-full border-[0.5px] px-2 py-0.5 text-[11px] leading-4 ${
                      u.is_active ? 'border-accent/50 text-accent' : 'border-strong text-tertiary'
                    }`}
                  >
                    {u.is_active ? 'active' : 'disabled'}
                  </span>
                </td>
                <td className="px-3 py-2 font-mono text-data text-tertiary">
                  {formatUtcDateTime(u.created_at).slice(0, 10)}
                </td>
                <td className="px-3 py-2 text-right">
                  <button
                    type="button"
                    disabled={update.isPending}
                    onClick={() =>
                      update.mutate({ userId: u.id, patch: { is_active: !u.is_active } })
                    }
                    className="rounded-control border-[0.5px] border-subtle px-2.5 py-1 text-[11px] leading-4 text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary disabled:opacity-60"
                  >
                    {u.is_active ? 'Disable' : 'Enable'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {adding && (
        <CreateUserForm
          adminKey={adminKey}
          tenantId={tenant.id}
          onClose={() => setAdding(false)}
          onCreated={invalidate}
        />
      )}
    </section>
  )
}

function CreateUserForm({
  adminKey,
  tenantId,
  onClose,
  onCreated,
}: {
  adminKey: string
  tenantId: string
  onClose: () => void
  onCreated: () => void
}) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('analyst')

  const create = useMutation({
    mutationFn: () => api.adminCreateUser(adminKey, tenantId, { email, password, role }),
    onSuccess: () => {
      onCreated()
      onClose()
    },
  })

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        create.mutate()
      }}
      className="flex flex-wrap items-end gap-3 border-t-[0.5px] border-subtle px-4 py-3"
    >
      <label className="min-w-52 flex-1">
        <span className="mb-1 block text-label text-secondary">Email</span>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          autoFocus
          className="w-full rounded-control border-[0.5px] border-subtle bg-base px-3 py-1.5 font-mono text-data text-primary outline-none transition-colors duration-120 focus:border-strong"
        />
      </label>
      <label className="min-w-52 flex-1">
        <span className="mb-1 block text-label text-secondary">Password (min 12 chars)</span>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          minLength={12}
          autoComplete="new-password"
          className="w-full rounded-control border-[0.5px] border-subtle bg-base px-3 py-1.5 font-mono text-data text-primary outline-none transition-colors duration-120 focus:border-strong"
        />
      </label>
      <label>
        <span className="mb-1 block text-label text-secondary">Role</span>
        <select
          value={role}
          onChange={(e) => setRole(e.target.value)}
          className="rounded-control border-[0.5px] border-subtle bg-base px-2 py-1.5 text-label text-primary outline-none focus:border-strong"
        >
          <option value="analyst">analyst</option>
          <option value="admin">admin</option>
        </select>
      </label>
      <div className="flex gap-2">
        <button
          type="submit"
          disabled={create.isPending || !email || password.length < 12}
          className="rounded-control bg-accent px-3 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim disabled:opacity-50"
        >
          {create.isPending ? 'Creating…' : 'Create user'}
        </button>
        <button
          type="button"
          onClick={onClose}
          className="rounded-control border-[0.5px] border-subtle px-3 py-1.5 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
        >
          Cancel
        </button>
      </div>
      {create.isError && (
        <p className="w-full text-label text-sev-critical">
          {(create.error as Error).message}
        </p>
      )}
    </form>
  )
}

function CreateTenantModal({
  adminKey,
  onClose,
  onCreated,
}: {
  adminKey: string
  onClose: () => void
  onCreated: () => void
}) {
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [sector, setSector] = useState('')

  const create = useMutation({
    mutationFn: () =>
      api.adminCreateTenant(adminKey, {
        name,
        slug,
        ...(sector.trim() ? { sector: sector.trim() } : {}),
      }),
    onSuccess: () => {
      onCreated()
      onClose()
    },
  })

  const slugValid = /^[a-z0-9-]+$/.test(slug)

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-6"
      role="dialog"
      aria-modal="true"
      aria-label="New tenant"
    >
      <form
        onSubmit={(e) => {
          e.preventDefault()
          create.mutate()
        }}
        className="w-full max-w-md rounded-card border-[0.5px] border-subtle bg-elevated"
      >
        <header className="flex items-center justify-between border-b-[0.5px] border-subtle px-5 py-3.5">
          <h2 className="text-card-title">New tenant</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="text-tertiary transition-colors duration-120 hover:text-primary"
          >
            <X size={16} strokeWidth={1.5} />
          </button>
        </header>
        <div className="space-y-3 px-5 py-4">
          <label className="block">
            <span className="mb-1 block text-label text-secondary">Organization name</span>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              autoFocus
              placeholder="Acme Bank"
              className="w-full rounded-control border-[0.5px] border-subtle bg-base px-3 py-1.5 text-label text-primary outline-none transition-colors duration-120 placeholder:text-tertiary focus:border-strong"
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-label text-secondary">
              Slug (login identifier, permanent)
            </span>
            <input
              type="text"
              value={slug}
              onChange={(e) => setSlug(e.target.value.toLowerCase())}
              required
              placeholder="acme-bank"
              className="w-full rounded-control border-[0.5px] border-subtle bg-base px-3 py-1.5 font-mono text-data text-primary outline-none transition-colors duration-120 placeholder:text-tertiary focus:border-strong"
            />
            {slug && !slugValid && (
              <span className="mt-1 block text-[11px] leading-4 text-sev-critical">
                Lowercase letters, digits and hyphens only.
              </span>
            )}
          </label>
          <label className="block">
            <span className="mb-1 block text-label text-secondary">Sector (optional)</span>
            <input
              type="text"
              value={sector}
              onChange={(e) => setSector(e.target.value)}
              placeholder="finance / healthcare / manufacturing…"
              className="w-full rounded-control border-[0.5px] border-subtle bg-base px-3 py-1.5 text-label text-primary outline-none transition-colors duration-120 placeholder:text-tertiary focus:border-strong"
            />
          </label>
          {create.isError && (
            <p className="text-label text-sev-critical">{(create.error as Error).message}</p>
          )}
        </div>
        <footer className="flex justify-end gap-2 border-t-[0.5px] border-subtle px-5 py-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded-control border-[0.5px] border-subtle px-3 py-1.5 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={create.isPending || !name.trim() || !slugValid}
            className="rounded-control bg-accent px-4 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim disabled:opacity-50"
          >
            {create.isPending ? 'Creating…' : 'Create tenant'}
          </button>
        </footer>
      </form>
    </div>
  )
}
