const TONE_TEXT = {
  info: 'text-accent',
  safe: 'text-safe',
  warn: 'text-warn',
  crit: 'text-crit',
}

export default function StatCard({ label, value, sub, icon: Icon, tone = 'info' }) {
  return (
    <div className="rounded-sm border border-line bg-panel p-4">
      <div className="flex items-start justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-ink-faint">{label}</p>
        {Icon && <Icon size={16} className={TONE_TEXT[tone]} />}
      </div>
      <p className={`mt-2 font-mono text-2xl font-semibold ${tone === 'crit' ? 'text-crit' : 'text-ink'}`}>{value}</p>
      {sub && <p className="mt-1 text-xs text-ink-dim">{sub}</p>}
    </div>
  )
}
