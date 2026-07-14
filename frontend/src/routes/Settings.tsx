import { useState, type FormEvent } from 'react'
import { useMutation } from '@tanstack/react-query'
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

      <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-card-title">Multi-factor authentication</h2>
          <span className="rounded-full border-[0.5px] border-strong px-2 py-0.5 text-[11px] leading-4 text-tertiary">
            planned
          </span>
        </div>
        <p className="mt-1.5 text-label text-secondary">
          TOTP-based MFA is on the Phase-2 security roadmap.
        </p>
      </section>

      <section className="rounded-card border-[0.5px] border-subtle bg-elevated p-5">
        <h2 className="text-card-title">API keys</h2>
        <p className="mt-1.5 text-label text-secondary">
          Long-lived ingest tokens (for collectors) are minted server-side today:
        </p>
        <pre className="mt-2 overflow-x-auto rounded-control bg-base p-3 font-mono text-data text-secondary">
          uv run python scripts/mint_ingest_token.py
        </pre>
        <p className="mt-1.5 text-[11px] leading-4 text-tertiary">
          Self-service key management from this screen is Phase-2 scope.
        </p>
      </section>

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
