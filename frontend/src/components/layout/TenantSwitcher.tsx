import { useEffect, useRef, useState } from 'react'
import { Building2, ChevronsUpDown, LogOut } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'

// The JWT is tenant-scoped (mirrors backend RLS), so a session belongs to
// exactly one tenant: "switching" means signing into the other tenant.
export function TenantSwitcher() {
  const { tenantSlug, logout } = useAuth()
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    function onPointerDown(e: PointerEvent) {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false)
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('pointerdown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('pointerdown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        className="flex items-center gap-2.5 rounded-control border-[0.5px] border-subtle bg-elevated px-3 py-1.5 text-label text-primary transition-colors duration-120 hover:bg-hover"
      >
        <Building2 size={14} strokeWidth={1.5} className="text-accent" />
        <span className="max-w-40 truncate font-mono text-data">{tenantSlug ?? '—'}</span>
        <ChevronsUpDown size={13} strokeWidth={1.5} className="text-tertiary" />
      </button>

      {open && (
        <div
          role="menu"
          className="absolute left-0 top-full z-50 mt-1.5 w-72 rounded-card border-[0.5px] border-subtle bg-elevated py-1.5 shadow-lg shadow-black/30"
        >
          <div className="border-b-[0.5px] border-subtle px-3 pb-2 pt-1">
            <div className="text-label text-primary">
              Signed into <span className="font-mono text-data">{tenantSlug ?? '—'}</span>
            </div>
            <div className="text-[11px] leading-4 text-tertiary">
              Sessions are tenant-scoped — every query is isolated to this client.
            </div>
          </div>
          <Link
            to="/tenants"
            role="menuitem"
            onClick={() => setOpen(false)}
            className="block px-3 py-2 text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
          >
            Tenant overview
          </Link>
          <button
            type="button"
            role="menuitem"
            onClick={logout}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
          >
            <LogOut size={13} strokeWidth={1.5} />
            Sign in to another tenant
          </button>
        </div>
      )}
    </div>
  )
}
