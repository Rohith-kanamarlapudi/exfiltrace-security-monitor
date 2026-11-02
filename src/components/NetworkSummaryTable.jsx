import DataTable from './DataTable'
import RiskBadge from './RiskBadge'
import { formatBytes, formatDateTime, formatNumber } from '../utils/format'

const mono = 'font-mono text-xs text-ink-dim'

export default function NetworkSummaryTable({ rows, direction }) {
  const outbound = direction === 'OUTBOUND'
  const columns = [
    { key: 'ip', header: outbound ? 'Destination' : 'Source', render: (row) => (
      <div>
        <p className="font-mono text-xs text-ink">{row.ip}</p>
        {row.hosts.length > 0 && <p className="max-w-[18rem] truncate text-[11px] text-ink-faint" title={row.hosts.join(', ')}>{row.hosts.join(', ')}</p>}
      </div>
    ) },
    { key: 'bytes', header: outbound ? 'Sent' : 'Received', className: mono, render: (row) => formatBytes(row.bytes) },
    { key: 'flows', header: 'Recorded flows', className: mono, render: (row) => formatNumber(row.flows) },
    { key: 'protocols', header: 'Protocols', className: mono, render: (row) => row.protocols.join(', ') },
    { key: 'firstSeen', header: 'First activity', className: mono, render: (row) => formatDateTime(row.firstSeen) },
    { key: 'lastSeen', header: 'Last activity', className: mono, render: (row) => formatDateTime(row.lastSeen) },
    { key: 'risk', header: 'Highest risk', render: (row) => <RiskBadge level={row.risk} /> },
  ]
  return <DataTable columns={columns} rows={rows}
    emptyText={`No ${outbound ? 'outbound' : 'inbound'} traffic recorded.`}
    rowClassName={(row) => row.risk === 'HIGH' ? 'bg-crit/10 border-l-2 border-l-crit' : ''} />
}
