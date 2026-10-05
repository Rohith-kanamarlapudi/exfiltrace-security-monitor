import { ArrowDown, FileSearch, Files, Globe, ShieldAlert, Usb } from 'lucide-react'
import { formatTime } from '../utils/format'

// Event type -> icon + colour. "exfil" is always the red end of the chain.
const STEP = {
  usb: { icon: Usb, color: 'text-accent border-accent/40 bg-accent/10' },
  file: { icon: FileSearch, color: 'text-warn border-warn/40 bg-warn/10' },
  transfer: { icon: Files, color: 'text-warn border-warn/40 bg-warn/10' },
  network: { icon: Globe, color: 'text-crit border-crit/40 bg-crit/10' },
  exfil: { icon: ShieldAlert, color: 'text-crit border-crit bg-crit/20' },
}

// Vertical flow: each step is a node, joined by arrows (USB -> file -> transfer -> network -> exfiltration).
// `compact` hides the detail text for use in reports and the dashboard.
export default function IncidentTimeline({ steps, compact = false }) {
  if (!steps?.length) {
    return <p className="text-sm text-ink-faint">No timeline events recorded.</p>
  }

  return (
    <ol className="flex flex-col">
      {steps.map((step, i) => {
        const style = STEP[step.type] ?? STEP.usb
        const Icon = style.icon
        const last = i === steps.length - 1
        return (
          <li key={`${step.time}-${step.title}`} className="flex flex-col items-start">
            <div className="flex w-full items-start gap-3">
              <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-sm border ${style.color}`}>
                <Icon size={16} />
              </span>
              <div className="min-w-0 flex-1 pb-0.5">
                <div className="flex flex-wrap items-baseline justify-between gap-x-3">
                  <p className={`text-sm font-semibold ${step.type === 'exfil' ? 'text-crit' : 'text-ink'}`}>{step.title}</p>
                  <time className="font-mono text-[11px] text-ink-faint">{formatTime(step.time)}</time>
                </div>
                {!compact && <p className="mt-0.5 text-xs leading-relaxed text-ink-dim">{step.detail}</p>}
              </div>
            </div>
            {!last && (
              <div className="my-1 ml-3.5 flex items-center text-ink-faint" aria-hidden="true">
                <ArrowDown size={14} />
              </div>
            )}
          </li>
        )
      })}
    </ol>
  )
}
