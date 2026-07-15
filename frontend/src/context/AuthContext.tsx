import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import * as api from '../lib/api'
import { ApiError, type Me } from '../lib/api'

const TOKEN_KEY = 'argus.token'
const EMAIL_KEY = 'argus.email'
const TENANT_KEY = 'argus.tenant'

interface AuthContextValue {
  token: string | null
  user: Me | null
  email: string | null
  tenantSlug: string | null
  login: (tenantSlug: string, email: string, password: string, otpCode?: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem(TOKEN_KEY))
  const [email, setEmail] = useState<string | null>(() => localStorage.getItem(EMAIL_KEY))
  const [tenantSlug, setTenantSlug] = useState<string | null>(() =>
    localStorage.getItem(TENANT_KEY),
  )
  const [user, setUser] = useState<Me | null>(null)

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(EMAIL_KEY)
    localStorage.removeItem(TENANT_KEY)
    setToken(null)
    setEmail(null)
    setTenantSlug(null)
    setUser(null)
  }, [])

  // Validate a persisted token on load; a stale one sends us back to login.
  useEffect(() => {
    if (!token) return
    let cancelled = false
    api
      .fetchMe(token)
      .then((me) => {
        if (!cancelled) setUser(me)
      })
      .catch((err: unknown) => {
        if (!cancelled && err instanceof ApiError && err.status === 401) logout()
      })
    return () => {
      cancelled = true
    }
  }, [token, logout])

  const login = useCallback(
    async (slug: string, loginEmail: string, password: string, otpCode?: string) => {
      const { access_token } = await api.login(slug, loginEmail, password, otpCode)
      localStorage.setItem(TOKEN_KEY, access_token)
      localStorage.setItem(EMAIL_KEY, loginEmail)
      localStorage.setItem(TENANT_KEY, slug)
      setToken(access_token)
      setEmail(loginEmail)
      setTenantSlug(slug)
    },
    [],
  )

  return (
    <AuthContext value={{ token, user, email, tenantSlug, login, logout }}>
      {children}
    </AuthContext>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
