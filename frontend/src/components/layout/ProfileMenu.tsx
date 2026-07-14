import { useEffect, useRef, useState } from 'react'
import { LogOut } from 'lucide-react'
import { useAuth } from '../../context/AuthContext'

function initialsFromEmail(email: string | null): string {
  if (!email) return '·'
  const local = email.split('@')[0]
  const parts = local.split(/[._-]/).filter(Boolean)
  const letters =
    parts.length >= 2 ? parts[0][0] + parts[1][0] : local.slice(0, 2)
  return letters.toUpperCase()
}

export function ProfileMenu() {
  const { email, user, logout } = useAuth()
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
    <div ref={rootRef} className="relative ml-1">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-label="Profile"
        aria-haspopup="menu"
        aria-expanded={open}
        className="flex h-8 w-8 items-center justify-center rounded-full bg-accent-bg text-label text-accent ring-1 ring-accent/40 transition-shadow duration-120 hover:ring-accent"
      >
        {initialsFromEmail(email)}
      </button>

      {open && (
        <div
          role="menu"
          className="absolute right-0 top-full z-50 mt-1.5 w-56 rounded-card border-[0.5px] border-subtle bg-elevated py-1.5 shadow-lg shadow-black/30"
        >
          <div className="border-b-[0.5px] border-subtle px-3 pb-2 pt-1">
            <div className="truncate text-label text-primary">{email ?? 'Signed in'}</div>
            <div className="text-label text-tertiary">{user?.role ?? '—'}</div>
          </div>
          <button
            type="button"
            role="menuitem"
            onClick={logout}
            className="flex w-full items-center gap-2.5 px-3 py-2 text-left text-label text-secondary transition-colors duration-120 hover:bg-hover hover:text-primary"
          >
            <LogOut size={14} strokeWidth={1.5} />
            Sign out
          </button>
        </div>
      )}
    </div>
  )
}
