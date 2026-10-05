// Standard bordered card with an optional title bar.
export default function Panel({ title, icon: Icon, action, children, className = '', bodyClassName = '' }) {
  return (
    <section className={`rounded-sm border border-line bg-panel ${className}`}>
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-ink-dim">
            {Icon && <Icon size={14} className="text-accent" />}
            {title}
          </h2>
          {action}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  )
}
