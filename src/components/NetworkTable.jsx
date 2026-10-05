import { ArrowUpRight } from 'lucide-react'
import DataTable from './DataTable'
import RiskBadge from './RiskBadge'
import { formatBytes, formatDateTime, formatTime } from '../utils/format'

const mono = 'font-mono text-xs text-ink-dim'

// Highlights outbound traffic flagged as high risk.
const isSuspiciousOutbound = (e) => e.direction === 'OUTBOUND' && e.risk === 'HIGH'

// variant "compact": dashboard columns. variant "full": Network Analysis columns.
export default function NetworkTable({ events, variant = 'compact' }) {
  const compact = [
    { key: 'timestamp', header: 'Timestamp', className: mono, render: (e) => formatTime(e.timestamp) },
    {
      key: 'destinationIp',
      header: 'Destination',
      render: (e) => (
        <div>
          <p className="font-mono text-xs text-ink">{e.destinationIp}</p>
          <p className="max-w-[14rem] truncate text-[11px] text-ink-faint">{e.destinationHost}</p>
        </div>
      ),
    },
    { key: 'protocol', header: 'Protocol', className: mono },
    { key: 'packetSizeBytes', header: 'Data Transferred', className: mono, render: (e) => formatBytes(e.packetSizeBytes) },
    { key: 'risk', header: 'Risk', render: (e) => <RiskBadge level={e.risk} /> },
  ]

  const full = [
    { key: 'timestamp', header: 'Timestamp', className: mono, render: (e) => formatDateTime(e.timestamp) },
    { key: 'sourceIp', header: 'Source IP', className: mono },
    {
      key: 'destinationIp',
      header: 'Destination IP',
      render: (e) => (
        <div>
          <p className="font-mono text-xs text-ink">{e.destinationIp}</p>
          <p className="max-w-[14rem] truncate text-[11px] text-ink-faint">{e.destinationHost}</p>
        </div>
      ),
    },
    {
      key: 'direction',
      header: 'Direction',
      render: (e) => (
        <span
          className={`inline-flex items-center gap-1 font-mono text-xs ${
            isSuspiciousOutbound(e) ? 'font-semibold text-crit' : 'text-ink-dim'
          }`}
        >
          {e.direction === 'OUTBOUND' && <ArrowUpRight size={13} />}
          {e.direction}
        </span>
      ),
    },
    { key: 'protocol', header: 'Protocol', className: mono, render: (e) => `${e.protocol}/${e.port}` },
    { key: 'packetSizeBytes', header: 'Packet Size', className: mono, render: (e) => formatBytes(e.packetSizeBytes) },
    { key: 'risk', header: 'Risk', render: (e) => <RiskBadge level={e.risk} /> },
  ]

  return (
    <DataTable
      columns={variant === 'full' ? full : compact}
      rows={events}
      rowClassName={(e) => (isSuspiciousOutbound(e) ? 'bg-crit/10 border-l-2 border-l-crit' : '')}
    />
  )
}
