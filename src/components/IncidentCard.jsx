import { ChevronRight } from 'lucide-react'
import RiskBadge from './RiskBadge'
import StatusBadge from './StatusBadge'
import { formatDateTime } from '../utils/format'

export default function IncidentCard({ incident, selected, onSelect }) {
  return (
    <button
      type="button"
      onClick={() => onSelect(incident)}
      aria-pressed={selected}
      className={`block w-full rounded-sm border p-4 text-left transition-colors ${
        selected ? 'border-accent bg-accent/10' : 'border-line bg-panel hover:border-line-strong hover:bg-panel-2'
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-sm font-semibold text-accent">{incident.id}</span>
        <RiskBadge level={incident.severity} />
      </div>
      <h3 className="mt-2 text-sm font-medium text-ink">{incident.type}</h3>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
        <StatusBadge status={incident.status} />
        <span className="flex items-center gap-1 font-mono text-[11px] text-ink-faint">
          {formatDateTime(incident.timestamp)}
          <ChevronRight size={12} />
        </span>
      </div>
    </button>
  )
}
