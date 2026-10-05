import DataTable from './DataTable'
import StatusBadge from './StatusBadge'
import { formatDateTime, formatTime } from '../utils/format'

const mono = 'font-mono text-xs text-ink-dim'

// variant "compact": dashboard columns. variant "full": USB Forensics columns.
export default function USBTable({ devices, variant = 'compact', onSelect, selectedId }) {
  const compact = [
    { key: 'name', header: 'Device Name', render: (d) => <span className="font-medium">{d.name}</span> },
    { key: 'vendorId', header: 'Vendor ID', className: mono },
    { key: 'productId', header: 'Product ID', className: mono },
    { key: 'serialNumber', header: 'Serial Number', className: mono },
    { key: 'connectedAt', header: 'Connected', className: mono, render: (d) => formatTime(d.connectedAt) },
    { key: 'status', header: 'Status', render: (d) => <StatusBadge status={d.status} /> },
  ]

  const full = [
    { key: 'name', header: 'Device Name', render: (d) => <span className="font-medium">{d.name}</span> },
    { key: 'vendorId', header: 'Vendor ID', className: mono },
    { key: 'productId', header: 'Product ID', className: mono },
    { key: 'serialNumber', header: 'Serial Number', className: mono },
    { key: 'deviceClass', header: 'Device Class', className: 'text-ink-dim' },
    { key: 'connectedAt', header: 'Connected', className: mono, render: (d) => formatDateTime(d.connectedAt) },
    {
      key: 'disconnectedAt',
      header: 'Disconnected',
      className: mono,
      render: (d) => (d.disconnectedAt ? formatDateTime(d.disconnectedAt) : <span className="text-accent">Still connected</span>),
    },
    { key: 'status', header: 'Status', render: (d) => <StatusBadge status={d.status} /> },
  ]

  return (
    <DataTable
      columns={variant === 'full' ? full : compact}
      rows={devices}
      onRowClick={onSelect}
      selectedId={selectedId}
      rowClassName={(d) => (d.status === 'CRITICAL' ? 'bg-crit/5' : '')}
    />
  )
}
