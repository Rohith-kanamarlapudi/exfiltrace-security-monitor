import { NavLink } from 'react-router-dom'
import { ShieldCheck, X } from 'lucide-react'
import { NAV_ITEMS } from './navItems'

// Persistent on desktop (lg+). On smaller screens it slides in as a drawer.
export default function Sidebar({ open, onClose }) {
  return (
    <>
      {open && <div className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={onClose} aria-hidden="true" />}

      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-line bg-panel transition-transform lg:translate-x-0 ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
        aria-label="Primary"
      >
        <div className="flex h-14 items-center justify-between border-b border-line px-4">
          <div className="flex items-center gap-2.5">
            <ShieldCheck size={22} className="text-accent" />
            <span className="font-mono text-base font-bold tracking-[0.2em] text-ink">EXFILTRACE</span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-sm p-1 text-ink-dim hover:bg-panel-2 hover:text-ink lg:hidden"
            aria-label="Close navigation"
          >
            <X size={18} />
          </button>
        </div>

        <nav className="flex-1 space-y-0.5 overflow-y-auto p-3">
          {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              onClick={onClose}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-sm border-l-2 px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? 'border-accent bg-accent/10 font-medium text-ink'
                    : 'border-transparent text-ink-dim hover:bg-panel-2 hover:text-ink'
                }`
              }
            >
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-line p-4 font-mono text-[11px] leading-relaxed text-ink-faint">
          <p>LIVE FILE / USB MONITORING</p>
          <p>Network not connected</p>
        </div>
      </aside>
    </>
  )
}
