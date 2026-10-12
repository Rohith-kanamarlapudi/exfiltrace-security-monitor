import DataTable from './DataTable'
import { formatBytes } from '../utils/format'
const mono = 'font-mono text-xs text-ink-dim'
const columns = [
  { key: 'name', header: 'Connected storage device' },
  { key: 'mounts', header: 'Mounted volumes', render: (d) => d.mounts.join(', ') || 'No mounted volumes', className: mono },
  { key: 'vendorId', header: 'VID', render: (d) => d.vendorId || 'Unavailable', className: mono },
  { key: 'productId', header: 'PID', render: (d) => d.productId || 'Unavailable', className: mono },
  { key: 'serialNumber', header: 'Serial', render: (d) => d.serialNumber || 'Unavailable', className: mono },
  { key: 'filesystem', header: 'Filesystem', render: (d) => d.filesystem || 'Unavailable', className: mono },
  { key: 'sizeBytes', header: 'Disk size', render: (d) => formatBytes(d.sizeBytes), className: mono },
]
export default function USBTable({ devices, onSelect, selectedId }) {
  return <DataTable columns={columns} rows={devices} onRowClick={onSelect} selectedId={selectedId} emptyText="No USB storage devices in the last successful snapshot." />
}
