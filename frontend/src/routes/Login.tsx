import { useState, type FormEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { ArgusMark } from '../components/ArgusMark'
import { useAuth } from '../context/AuthContext'
import { ApiError } from '../lib/api'

export function Login() {
  const { token, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  const [tenantSlug, setTenantSlug] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const from = (location.state as { from?: string } | null)?.from ?? '/dashboard'

  if (token) return <Navigate to={from} replace />

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setNotice(null)
    setSubmitting(true)
    try {
      await login(tenantSlug.trim(), email.trim(), password)
      navigate(from, { replace: true })
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setError("That tenant, email, or password didn't match. Try again.")
      } else {
        setError("Couldn't reach ARGUS. Check your connection and try again.")
      }
      setSubmitting(false)
    }
  }

  const fieldClass =
    'w-full rounded-control border-[0.5px] border-subtle bg-base px-3 py-2 text-body text-primary outline-none transition-colors duration-120 placeholder:text-tertiary focus:border-strong'

  return (
    <div className="flex min-h-screen items-center justify-center bg-base p-6">
      <div className="w-full max-w-sm">
        {/* The guardian opening its eye — the one radial glow allowed (§2.1, §4.3) */}
        <div className="relative mb-8 flex justify-center">
          <div
            aria-hidden="true"
            className="absolute -inset-x-24 -inset-y-16"
            style={{
              background:
                'radial-gradient(closest-side, color-mix(in srgb, var(--accent) 14%, transparent), transparent)',
            }}
          />
          <div className="relative flex flex-col items-center gap-3">
            <ArgusMark size={64} ringClassName="animate-scan-ring-once origin-center" />
            <span className="text-card-title tracking-[0.22em] text-primary">ARGUS</span>
          </div>
        </div>

        <div className="rounded-card border-[0.5px] border-subtle bg-elevated p-6">
          <h1 className="text-section">Sign in</h1>
          <p className="mt-1 text-label text-secondary">The guardian is watching your tenants.</p>

          <form onSubmit={onSubmit} className="mt-5 space-y-4">
            <label className="block">
              <span className="mb-1.5 block text-label text-secondary">Tenant</span>
              <input
                type="text"
                required
                autoComplete="organization"
                autoCapitalize="none"
                spellCheck={false}
                placeholder="acme-bank"
                value={tenantSlug}
                onChange={(e) => setTenantSlug(e.target.value)}
                className={`${fieldClass} font-mono text-data`}
              />
            </label>

            <label className="block">
              <span className="mb-1.5 block text-label text-secondary">Email</span>
              <input
                type="email"
                required
                autoComplete="email"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className={fieldClass}
              />
            </label>

            <label className="block">
              <span className="mb-1.5 block text-label text-secondary">Password</span>
              <input
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={fieldClass}
              />
            </label>

            {error && (
              <p role="alert" className="text-label text-sev-critical">
                {error}
              </p>
            )}
            {notice && <p className="text-label text-secondary">{notice}</p>}

            <button
              type="submit"
              disabled={submitting}
              className="flex w-full items-center justify-center gap-2 rounded-control bg-accent px-3 py-2 text-body font-medium text-(--bg-base) transition-colors duration-120 hover:bg-accent-dim disabled:opacity-70"
            >
              {submitting && (
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
                  <circle
                    cx="7"
                    cy="7"
                    r="5.5"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeDasharray="4 3"
                    className="animate-scan-ring origin-center"
                  />
                </svg>
              )}
              {submitting ? 'Signing in…' : 'Sign in'}
            </button>

            <button
              type="button"
              onClick={() => {
                setError(null)
                setNotice("Single sign-on isn't configured for this deployment yet.")
              }}
              className="w-full rounded-control border-[0.5px] border-subtle px-3 py-2 text-body text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
            >
              Continue with SSO
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
