import { useEffect, useState } from 'react'
import { Menu, Monitor } from 'lucide-react'
import { getSystemStatus } from '../services/api'
import { useApi } from '../hooks'

const pad = (n) => String(n).padStart(2, '0')

function Clock() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return (
    <span className="hidden font-mono text-xs text-ink-dim sm:inline">
      {pad(now.getHours())}:{pad(now.getMinutes())}:{pad(now.getSeconds())}
    </span>
  )
}

export default function Navbar({ onMenuClick }) {
  const { data: status, error } = useApi(getSystemStatus)
  const active = status?.running && status.fileMonitor.running && status.usbMonitor.running && !error && !status.usbMonitor.lastError && !status.fileMonitor.errors.length && !status.detection.errors.length

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between gap-3 border-b border-line bg-panel/95 px-4 backdrop-blur lg:px-6">
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onMenuClick}
          className="rounded-sm p-1.5 text-ink-dim hover:bg-panel-2 hover:text-ink lg:hidden"
          aria-label="Open navigation"
        >
          <Menu size={20} />
        </button>
        {status && (
          <span className="hidden items-center gap-2 font-mono text-xs text-ink-dim sm:flex">
            <Monitor size={14} />
            {status.host}
          </span>
        )}
      </div>

      <div className="flex items-center gap-4">
        <Clock />
        <span
          className={`flex items-center gap-2 rounded-sm border px-2.5 py-1 font-mono text-xs font-semibold tracking-wider ${
            active ? 'border-safe/30 bg-safe/10 text-safe' : 'border-crit/30 bg-crit/10 text-crit'
          }`}
        >
          <span className={`h-2 w-2 rounded-full bg-current ${active ? 'pulse-dot' : ''}`} />
          {error ? 'STATUS UNAVAILABLE / STALE' : !status ? 'CONNECTING' : active ? 'FILE / USB MONITORING ACTIVE' : status.running ? 'MONITORING DEGRADED' : 'MONITORING STOPPED'}
        </span>
      </div>
    </header>
  )
}
