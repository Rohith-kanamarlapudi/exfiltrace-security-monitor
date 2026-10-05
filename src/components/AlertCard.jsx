import { AlertOctagon, AlertTriangle, Info } from 'lucide-react'
import RiskBadge from './RiskBadge'
import { formatTime } from '../utils/format'

const SEVERITY_STYLE = {
  CRITICAL: { icon: AlertOctagon, color: 'text-crit', border: 'border-l-crit' },
  HIGH: { icon: AlertTriangle, color: 'text-crit', border: 'border-l-crit' },
  MEDIUM: { icon: AlertTriangle, color: 'text-warn', border: 'border-l-warn' },
  LOW: { icon: Info, color: 'text-accent', border: 'border-l-accent' },
}

export default function AlertCard({ alert }) {
  const style = SEVERITY_STYLE[alert.severity] ?? SEVERITY_STYLE.LOW
  const Icon = style.icon
  return (
    <article className={`border-b border-l-2 border-b-line/60 ${style.border} px-4 py-3 last:border-b-0`}>
      <div className="flex items-start gap-3">
        <Icon size={16} className={`mt-0.5 shrink-0 ${style.color}`} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-sm font-medium text-ink">{alert.type}</h3>
            <RiskBadge level={alert.severity} />
          </div>
          <p className="mt-1 text-xs leading-relaxed text-ink-dim">{alert.description}</p>
          <p className="mt-1.5 font-mono text-[11px] text-ink-faint">{formatTime(alert.timestamp)}</p>
        </div>
      </div>
    </article>
  )
}
