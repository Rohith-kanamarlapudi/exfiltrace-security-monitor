import DataTable from './DataTable'
import { formatBytes } from '../utils/format'
const mono = 'font-mono text-xs text-ink-dim'
const columns = [
  { key: 'name', header: 'Physical USB device', render: (d) => <div className="flex items-center gap-2">
    <span>{d.name}</span>
    {d.hasInterfaceFinding && <span className="rounded-sm border border-warn/40 bg-warn/10 px-2 py-0.5 text-xs font-semibold text-warn">Possible impersonation</span>}
  </div> },
  { key: 'functions', header: 'Functions', render: (d) => d.inspection?.functions?.join(', ') || 'Unavailable' },
  { key: 'mounts', header: 'Mounted volumes', render: (d) => d.mounts.join(', ') || 'No mounted volumes', className: mono },
  { key: 'vendorId', header: 'VID', render: (d) => d.vendorId || 'Unavailable', className: mono },
  { key: 'productId', header: 'PID', render: (d) => d.productId || 'Unavailable', className: mono },
  { key: 'serialNumber', header: 'Serial', render: (d) => d.serialNumber || 'Unavailable', className: mono },
  { key: 'filesystem', header: 'Filesystem', render: (d) => d.filesystem || 'Unavailable', className: mono },
  { key: 'sizeBytes', header: 'Disk size', render: (d) => formatBytes(d.sizeBytes), className: mono },
]
export default function USBTable({ devices, onSelect, selectedId }) {
  return <DataTable columns={columns} rows={devices} onRowClick={onSelect} selectedId={selectedId}
    rowClassName={(d) => d.hasInterfaceFinding ? '[&>td]:bg-warn/10 [&>td:first-child]:border-l-2 [&>td:first-child]:border-warn' : ''}
    emptyText="No USB devices in the last successful snapshot." />
}
