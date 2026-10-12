import { formatDateTime } from '../utils/format'
export default function LiveState({ resource, label }) {
  if (resource.loading) return <p role="status" className="p-3 text-sm text-ink-dim">Loading {label}…</p>
  if (resource.error) return <p role="alert" className="mb-3 border border-warn/40 bg-warn/10 p-3 text-sm text-warn">
    {label}: {resource.error.message}. {resource.data ? `Stale data — last success ${formatDateTime(resource.updatedAt)}.` : 'Data unavailable.'} Retrying automatically.
  </p>
  return <p className="mb-2 text-xs text-ink-faint">Live {label} · refreshed {formatDateTime(resource.updatedAt)} · polls about every 3 seconds</p>
}
