import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, ShieldCheck } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import * as api from '../lib/api'
import { ApiError } from '../lib/api'

function initials(email: string | null): string {
  if (!email) return '·'
  const parts = email.split('@')[0].split(/[._-]/).filter(Boolean)
  return (parts.length >= 2 ? parts[0][0] + parts[1][0] : email.slice(0, 2)).toUpperCase()
}

export function Settings() {
  const { email, user, tenantSlug } = useAuth()

  return (
    <div className="max-w-2xl space-y-4 p-6">
      <h1 className="text-page-title">Settings</h1>

      {/* Profile (§4.13): initials in an emerald ring */}
      <section className="flex items-center gap-4 rounded-card border-[0.5px] border-subtle bg-elevated p-5">
        <span className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full bg-accent-bg text-[18px] font-medium text-accent ring-2 ring-accent/50">
          {initials(email)}
        </span>
        <div className="min-w-0">
          <div className="truncate text-card-title">{email ?? '—'}</div>
          <div className="text-label text-secondary">
            {user?.role ?? '—'} · tenant <span className="font-mono text-data">{tenantSlug}</span>
          </div>
        </div>
      </section>

      <PasswordSection />

      <MfaSection />

      <IngestTokenSection />

      <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-card-title">Notifications</h2>
          <span className="rounded-full border-[0.5px] border-strong px-2 py-0.5 text-[11px] leading-4 text-tertiary">
            planned
          </span>
        </div>
        <p className="mt-1.5 text-label text-secondary">
          Alert notifications (email / webhook) arrive with the alerting pipeline.
        </p>
      </section>

      <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-5">
        <h2 className="text-card-title">Appearance</h2>
        <p className="mt-1.5 text-label text-secondary">
          Dark is the only theme — the design system is built for the SOC floor at 3am.
        </p>
      </section>
    </div>
  )
}

function PasswordSection() {
  const { token } = useAuth()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null)

  const change = useMutation({
    mutationFn: () => api.changePassword(token!, current, next),
    onSuccess: () => {
      setMessage({ ok: true, text: 'Password updated.' })
      setCurrent('')
      setNext('')
      setConfirm('')
    },
    onError: (err) => {
      setMessage({
        ok: false,
        text:
          err instanceof ApiError && err.status === 403
            ? "That current password didn't match. Try again."
            : err instanceof ApiError && err.status === 422
              ? 'The new password needs at least 10 characters.'
              : "Couldn't update the password. Try again.",
      })
    },
  })

  function submit(e: FormEvent) {
    e.preventDefault()
    setMessage(null)
    if (next !== confirm) {
      setMessage({ ok: false, text: "The new passwords don't match." })
      return
    }
    change.mutate()
  }

  const fieldClass =
    'w-full rounded-control border-[0.5px] border-subtle bg-base px-3 py-1.5 text-label text-primary outline-none transition-colors duration-120 focus:border-strong'

  return (
    <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-5">
      <h2 className="text-card-title">Password</h2>
      <form onSubmit={submit} className="mt-3 max-w-sm space-y-3">
        <label className="block">
          <span className="mb-1 block text-label text-secondary">Current password</span>
          <input
            type="password"
            required
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            className={fieldClass}
          />
        </label>
        <label className="block">
          <span className="mb-1 block text-label text-secondary">New password (10+ characters)</span>
          <input
            type="password"
            required
            minLength={10}
            autoComplete="new-password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            className={fieldClass}
          />
        </label>
        <label className="block">
          <span className="mb-1 block text-label text-secondary">Confirm new password</span>
          <input
            type="password"
            required
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className={fieldClass}
          />
        </label>
        {message && (
          <p className={`text-label ${message.ok ? 'text-accent' : 'text-sev-critical'}`}>
            {message.text}
          </p>
        )}
        <button
          type="submit"
          disabled={change.isPending}
          className="rounded-control bg-accent px-3 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim disabled:opacity-60"
        >
          {change.isPending ? 'Updating…' : 'Update password'}
        </button>
      </form>
    </section>
  )
}

function MfaSection() {
  const { token } = useAuth()
  const queryClient = useQueryClient()
  const [enrolment, setEnrolment] = useState<api.MfaEnrolment | null>(null)
  const [code, setCode] = useState('')
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null)

  const status = useQuery({
    queryKey: ['mfa', 'status'],
    queryFn: () => api.getMfaStatus(token!),
    enabled: !!token,
  })
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['mfa', 'status'] })

  const enrol = useMutation({
    mutationFn: () => api.enrolMfa(token!),
    onSuccess: (data) => {
      setEnrolment(data)
      setMessage(null)
      refresh()
    },
  })
  const activate = useMutation({
    mutationFn: () => api.activateMfa(token!, code.trim()),
    onSuccess: () => {
      setEnrolment(null)
      setCode('')
      setMessage({ ok: true, text: 'MFA is on. The next sign-in will ask for a code.' })
      refresh()
    },
    onError: (err) => {
      setMessage({
        ok: false,
        text:
          err instanceof ApiError && err.status === 403
            ? "That code didn't match. Codes rotate every 30 seconds — try the current one."
            : "Couldn't activate MFA. Try again.",
      })
    },
  })
  const disable = useMutation({
    mutationFn: () => api.disableMfa(token!, code.trim()),
    onSuccess: () => {
      setCode('')
      setMessage({ ok: true, text: 'MFA is off.' })
      refresh()
    },
    onError: (err) => {
      setMessage({
        ok: false,
        text:
          err instanceof ApiError && err.status === 403
            ? "That code didn't match. Enter a current code to turn MFA off."
            : "Couldn't disable MFA. Try again.",
      })
    },
  })

  const codeField =
    'w-40 rounded-control border-[0.5px] border-subtle bg-base px-3 py-1.5 font-mono text-data tracking-[0.3em] text-primary outline-none transition-colors duration-120 placeholder:tracking-normal placeholder:text-tertiary focus:border-strong'

  return (
    <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-5">
      <div className="flex items-center justify-between">
        <h2 className="text-card-title">Multi-factor authentication</h2>
        {status.data?.enabled && (
          <span className="flex items-center gap-1.5 rounded-full border-[0.5px] border-accent/50 px-2 py-0.5 text-[11px] leading-4 text-accent">
            <ShieldCheck size={11} strokeWidth={1.5} />
            on
          </span>
        )}
      </div>

      {!status.data?.enabled && !enrolment && (
        <div className="mt-2">
          <p className="text-label text-secondary">
            Add a TOTP authenticator (any standard app). Sign-ins will require a 6-digit code
            on top of the password.
          </p>
          <button
            type="button"
            onClick={() => enrol.mutate()}
            disabled={enrol.isPending}
            className="mt-3 rounded-control bg-accent px-3 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim disabled:opacity-60"
          >
            {enrol.isPending ? 'Generating…' : 'Set up MFA'}
          </button>
        </div>
      )}

      {enrolment && (
        <div className="mt-3 space-y-3">
          <p className="text-label text-secondary">
            Add this secret to your authenticator app (or paste the URI into it), then confirm
            with the code it shows. Nothing is enforced until you confirm.
          </p>
          <div className="rounded-control bg-base p-3">
            <div className="text-[11px] leading-4 text-tertiary">Secret</div>
            <div className="break-all font-mono text-data text-primary">{enrolment.secret}</div>
            <div className="mt-2 text-[11px] leading-4 text-tertiary">URI</div>
            <div className="break-all font-mono text-[11px] leading-4 text-secondary">
              {enrolment.otpauth_uri}
            </div>
          </div>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              activate.mutate()
            }}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]{6,8}"
              maxLength={8}
              required
              placeholder="123456"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              className={codeField}
            />
            <button
              type="submit"
              disabled={activate.isPending || code.trim().length < 6}
              className="rounded-control bg-accent px-3 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim disabled:opacity-50"
            >
              {activate.isPending ? 'Checking…' : 'Confirm & enable'}
            </button>
          </form>
        </div>
      )}

      {status.data?.enabled && (
        <form
          onSubmit={(e) => {
            e.preventDefault()
            disable.mutate()
          }}
          className="mt-3"
        >
          <p className="text-label text-secondary">
            Turning MFA off requires a current authenticator code.
          </p>
          <div className="mt-2 flex items-center gap-2">
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]{6,8}"
              maxLength={8}
              required
              placeholder="123456"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              className={codeField}
            />
            <button
              type="submit"
              disabled={disable.isPending || code.trim().length < 6}
              className="rounded-control border-[0.5px] border-subtle px-3 py-1.5 text-label text-secondary transition-colors duration-120 hover:border-sev-critical/50 hover:text-sev-critical disabled:opacity-50"
            >
              {disable.isPending ? 'Checking…' : 'Disable MFA'}
            </button>
          </div>
        </form>
      )}

      {message && (
        <p className={`mt-2.5 text-label ${message.ok ? 'text-accent' : 'text-sev-critical'}`}>
          {message.text}
        </p>
      )}
    </section>
  )
}

function IngestTokenSection() {
  const { token } = useAuth()
  const [days, setDays] = useState(90)
  const [minted, setMinted] = useState<api.IngestToken | null>(null)
  const [copied, setCopied] = useState(false)

  const mint = useMutation({
    mutationFn: () => api.mintIngestToken(token!, days),
    onSuccess: (data) => {
      setMinted(data)
      setCopied(false)
    },
  })

  return (
    <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-5">
      <h2 className="text-card-title">Ingest tokens</h2>
      <p className="mt-1.5 text-label text-secondary">
        Mint a long-lived token for a collector (Wazuh shipper, replay scripts). It is scoped
        to this tenant with analyst rights and shown once — store it in the collector's
        secret store.
      </p>
      <div className="mt-3 flex items-center gap-2">
        <label className="flex items-center gap-2 text-label text-secondary">
          Valid for
          <select
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            className="rounded-control border-[0.5px] border-subtle bg-base px-2 py-1.5 text-label text-primary outline-none focus:border-strong"
          >
            <option value={30}>30 days</option>
            <option value={90}>90 days</option>
            <option value={180}>180 days</option>
            <option value={365}>365 days</option>
          </select>
        </label>
        <button
          type="button"
          onClick={() => mint.mutate()}
          disabled={mint.isPending}
          className="rounded-control bg-accent px-3 py-1.5 text-label font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim disabled:opacity-60"
        >
          {mint.isPending ? 'Minting…' : 'Mint token'}
        </button>
      </div>
      {minted && (
        <div className="mt-3 rounded-control bg-base p-3">
          <div className="flex items-center justify-between">
            <span className="text-[11px] leading-4 text-tertiary">
              Bearer token · {minted.expires_days} days · role {minted.role}
            </span>
            <button
              type="button"
              onClick={() => {
                navigator.clipboard.writeText(minted.token).then(() => setCopied(true))
              }}
              className="flex items-center gap-1 text-[11px] leading-4 text-secondary transition-colors duration-120 hover:text-primary"
            >
              <Copy size={11} strokeWidth={1.5} />
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <div className="mt-1.5 max-h-24 overflow-y-auto break-all font-mono text-[11px] leading-4 text-secondary">
            {minted.token}
          </div>
        </div>
      )}
      {mint.isError && (
        <p className="mt-2 text-label text-sev-critical">Couldn't mint the token. Try again.</p>
      )}
    </section>
  )
}
