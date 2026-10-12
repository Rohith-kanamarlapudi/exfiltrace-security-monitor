import DataTable from './DataTable'
import ActionBadge from './ActionBadge'
import { formatDateTime, formatBytes } from '../utils/format'
const mono = 'font-mono text-xs text-ink-dim'
const columns = [
  { key: 'timestamp', header: 'Timestamp', render: (e) => formatDateTime(e.timestamp), className: mono },
  { key: 'fileName', header: 'File / path', render: (e) => <div className="max-w-md whitespace-normal break-all">
    <p className="font-mono text-xs text-ink">{e.fileName}</p>
    <p className="font-mono text-xs text-ink-faint">{e.path}</p>
    {e.destPath && <p className="font-mono text-xs text-accent">Renamed to: {e.destPath}</p>}
  </div> },
  { key: 'eventType', header: 'Activity', render: (e) => <ActionBadge action={e.eventType} /> },
  { key: 'sensitive', header: 'Sensitivity', render: (e) => <span title={e.sensitivityReason || undefined}>{e.sensitive ? 'Sensitive' : 'No rule matched'}</span> },
  { key: 'volume', header: 'Removable association', render: (e) => e.onRemovable ? <div className="max-w-xs whitespace-normal break-all text-xs">
    <p>{e.volume || 'Volume unavailable'}</p><p className="text-ink-faint">{e.usbDeviceId || 'Device ID unavailable'}</p>
  </div> : 'Not on removable volume' },
  { key: 'sizeBytes', header: 'Recorded size', render: (e) => formatBytes(e.sizeBytes), className: mono },
]
export default function FileActivityTable({ events }) {
  return <DataTable columns={columns} rows={events} emptyText="No recorded file events match the filter." />
}
