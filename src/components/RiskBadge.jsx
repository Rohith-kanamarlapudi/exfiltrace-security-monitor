import Badge from './Badge'

// Risk levels and alert/incident severities -> tone
const RISK_TONE = {
  LOW: 'safe',
  MEDIUM: 'warn',
  HIGH: 'crit',
  CRITICAL: 'crit',
}

export default function RiskBadge({ level }) {
  return <Badge tone={RISK_TONE[level] ?? 'neutral'}>{level}</Badge>
}
