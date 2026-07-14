import { Bell, Search } from 'lucide-react'
import { ProfileMenu } from './ProfileMenu'
import { TenantSwitcher } from './TenantSwitcher'

export function TopBar() {
  return (
    <header className="flex h-14 shrink-0 items-center gap-4 border-b-[0.5px] border-subtle bg-surface px-4">
      <TenantSwitcher />

      <div className="flex flex-1 justify-center">
        <label className="flex w-full max-w-xl items-center gap-2.5 rounded-control border-[0.5px] border-subtle bg-base px-3 py-1.5 transition-colors duration-120 focus-within:border-strong">
          <Search size={14} strokeWidth={1.5} className="text-tertiary" />
          <input
            type="search"
            placeholder="Search hosts, users, IPs, alerts…"
            className="w-full bg-transparent text-label text-primary outline-none placeholder:text-tertiary"
          />
        </label>
      </div>

      <div className="flex items-center gap-1">
        {/* Collector health — placeholder healthy state until wired to the API */}
        <div
          className="flex items-center gap-2 rounded-control px-3 py-1.5 text-label text-secondary"
          title="All collectors healthy"
        >
          <span className="h-1.5 w-1.5 rounded-full bg-accent" />
          <span>Collectors</span>
        </div>

        <button
          type="button"
          aria-label="Notifications"
          className="rounded-control p-2 text-silver transition-colors duration-120 hover:bg-hover hover:text-primary"
        >
          <Bell size={16} strokeWidth={1.5} />
        </button>

        <ProfileMenu />
      </div>
    </header>
  )
}
