// File action label (CREATE, MODIFY, ACCESS, COPY, DELETE, MOVE)
const ACTION_STYLE = {
  CREATE: 'text-safe',
  MODIFY: 'text-accent',
  ACCESS: 'text-ink-dim',
  COPY: 'text-warn',
  DELETE: 'text-crit',
  MOVE: 'text-accent',
}

export default function ActionBadge({ action }) {
  return (
    <span className={`font-mono text-xs font-semibold tracking-wide ${ACTION_STYLE[action] ?? 'text-ink-dim'}`}>
      {action}
    </span>
  )
}
