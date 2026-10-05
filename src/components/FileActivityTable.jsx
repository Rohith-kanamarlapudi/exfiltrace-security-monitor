import DataTable from './DataTable'
import ActionBadge from './ActionBadge'
import RiskBadge from './RiskBadge'
import { formatDateTime, formatTime } from '../utils/format'

const mono = 'font-mono text-xs text-ink-dim'
const session = (e) => (e.usbSession ? <span className="text-accent">{e.usbSession}</span> : <span className="text-ink-faint">None</span>)

// variant "compact": dashboard columns. variant "full": File Monitoring columns.
export default function FileActivityTable({ events, variant = 'compact' }) {
  const compact = [
    { key: 'fileName', header: 'File Name', className: 'font-mono text-xs text-ink' },
    { key: 'action', header: 'Action', render: (e) => <ActionBadge action={e.action} /> },
    { key: 'timestamp', header: 'Timestamp', className: mono, render: (e) => formatTime(e.timestamp) },
    { key: 'usbSession', header: 'USB Session', className: mono, render: session },
    { key: 'risk', header: 'Risk', render: (e) => <RiskBadge level={e.risk} /> },
  ]

  const full = [
    { key: 'timestamp', header: 'Timestamp', className: mono, render: (e) => formatDateTime(e.timestamp) },
    {
      key: 'fileName',
      header: 'File Name',
      render: (e) => (
        <div>
          <p className="font-mono text-xs text-ink">{e.fileName}</p>
          <p className="max-w-xs truncate font-mono text-[11px] text-ink-faint">{e.path}</p>
        </div>
      ),
    },
    { key: 'action', header: 'Action', render: (e) => <ActionBadge action={e.action} /> },
    { key: 'process', header: 'Process', className: mono },
    { key: 'usbSession', header: 'USB Session', className: mono, render: session },
    { key: 'risk', header: 'Risk', render: (e) => <RiskBadge level={e.risk} /> },
  ]

  return (
    <DataTable
      columns={variant === 'full' ? full : compact}
      rows={events}
      rowClassName={(e) => (e.risk === 'HIGH' ? 'bg-crit/5' : '')}
      emptyText="No file events match the selected filters."
    />
  )
}
