import Badge from './Badge'

// Device and incident statuses -> tone
const STATUS_TONE = {
  SAFE: 'safe',
  SUSPICIOUS: 'warn',
  CRITICAL: 'crit',
  'INVESTIGATION REQUIRED': 'crit',
  'UNDER REVIEW': 'warn',
  RESOLVED: 'safe',
  CONNECTED: 'info',
  DISCONNECTED: 'neutral',
}

export default function StatusBadge({ status }) {
  return (
    <Badge tone={STATUS_TONE[status] ?? 'neutral'} dot>
      {status}
    </Badge>
  )
}
