import { NavLink } from 'react-router-dom'
import { PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import { ArgusMark } from '../ArgusMark'
import { navGroups } from '../../lib/navigation'

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  return (
    <aside
      className={`flex h-full shrink-0 flex-col border-r-[0.5px] border-subtle bg-surface transition-[width] duration-120 ${
        collapsed ? 'w-16' : 'w-60'
      }`}
    >
      <div className={`flex h-14 items-center gap-2.5 px-4 ${collapsed ? 'justify-center px-0' : ''}`}>
        <ArgusMark size={28} />
        {!collapsed && (
          <span className="text-[15px] font-medium tracking-[0.18em] text-primary">ARGUS</span>
        )}
      </div>

      <nav className="flex-1 overflow-y-auto px-2 pb-4" aria-label="Primary">
        {navGroups.map((group) => (
          <div key={group.label} className="mt-4 first:mt-1">
            {!collapsed && (
              <div className="px-3 pb-1.5 text-[11px] font-medium uppercase tracking-[0.12em] text-tertiary">
                {group.label}
              </div>
            )}
            <ul className="space-y-0.5">
              {group.items.map((item) => (
                <li key={item.path}>
                  <NavLink
                    to={item.path}
                    title={collapsed ? item.label : undefined}
                    className={({ isActive }) =>
                      `group relative flex items-center gap-3 rounded-control px-3 py-2 text-label transition-colors duration-120 ${
                        collapsed ? 'justify-center px-0' : ''
                      } ${
                        isActive
                          ? 'bg-hover text-primary'
                          : 'text-secondary hover:bg-hover/60 hover:text-primary'
                      }`
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {isActive && (
                          <span className="absolute inset-y-1.5 left-0 w-0.5 rounded-full bg-accent" />
                        )}
                        <item.icon
                          size={16}
                          strokeWidth={1.5}
                          className={isActive ? 'text-accent' : 'text-silver group-hover:text-primary'}
                        />
                        {!collapsed && <span>{item.label}</span>}
                      </>
                    )}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      <button
        type="button"
        onClick={onToggle}
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        className={`flex items-center gap-3 border-t-[0.5px] border-subtle px-3 py-3 text-label text-tertiary transition-colors duration-120 hover:text-primary ${
          collapsed ? 'justify-center px-0' : ''
        }`}
      >
        {collapsed ? (
          <PanelLeftOpen size={16} strokeWidth={1.5} />
        ) : (
          <>
            <PanelLeftClose size={16} strokeWidth={1.5} />
            <span>Collapse</span>
          </>
        )}
      </button>
    </aside>
  )
}
