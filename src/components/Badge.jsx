// Base badge. StatusBadge and RiskBadge map their values onto a tone.
const TONES = {
  safe: 'text-safe bg-safe/10 border-safe/30',
  warn: 'text-warn bg-warn/10 border-warn/30',
  crit: 'text-crit bg-crit/10 border-crit/30',
  info: 'text-accent bg-accent/10 border-accent/30',
  neutral: 'text-ink-dim bg-ink-dim/10 border-line-strong',
}

export default function Badge({ tone = 'neutral', children, dot = false }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-sm border px-2 py-0.5 font-mono text-[11px] font-medium uppercase tracking-wide ${TONES[tone]}`}
    >
      {dot && <span className="h-1.5 w-1.5 rounded-full bg-current" />}
      {children}
    </span>
  )
}
