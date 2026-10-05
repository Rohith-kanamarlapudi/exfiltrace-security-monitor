import { useState } from 'react'
import { AlertTriangle, Clock, Eye, FileLock2, FileSearch, Usb } from 'lucide-react'
import PageHeader from '../components/PageHeader'
import Panel from '../components/Panel'
import StatCard from '../components/StatCard'
import FileActivityTable from '../components/FileActivityTable'
import DataTable from '../components/DataTable'
import Badge from '../components/Badge'
import LoadingState from '../components/LoadingState'
import ActionBadge from '../components/ActionBadge'
import { useApi } from '../hooks'
import { getFileEvents, getFileStats, getSensitiveFiles } from '../services/api'
import { formatDateTime, formatNumber } from '../utils/format'

const ACTIONS = ['CREATE', 'MODIFY', 'ACCESS', 'COPY', 'DELETE', 'MOVE']

const CLASSIFICATION_TONE = { Restricted: 'crit', Confidential: 'warn' }

const sensitiveColumns = [
  { key: 'fileName', header: 'File', className: 'font-mono text-xs text-ink' },
  { key: 'path', header: 'Location', className: 'font-mono text-xs text-ink-dim' },
  {
    key: 'classification',
    header: 'Classification',
    render: (f) => <Badge tone={CLASSIFICATION_TONE[f.classification] ?? 'neutral'}>{f.classification}</Badge>,
  },
  { key: 'size', header: 'Size', className: 'font-mono text-xs text-ink-dim' },
  { key: 'lastEvent', header: 'Last Event', render: (f) => <ActionBadge action={f.lastEvent} /> },
  { key: 'lastEventAt', header: 'Last Seen', className: 'font-mono text-xs text-ink-dim', render: (f) => formatDateTime(f.lastEventAt) },
  {
    key: 'usbTouched',
    header: 'USB Involved',
    render: (f) =>
      f.usbTouched ? (
        <span className="inline-flex items-center gap-1.5 font-mono text-xs text-warn">
          <Usb size={13} /> YES
        </span>
      ) : (
        <span className="font-mono text-xs text-ink-faint">NO</span>
      ),
  },
]

export default function FileMonitoring() {
  const events = useApi(getFileEvents)
  const sensitive = useApi(getSensitiveFiles)
  const stats = useApi(getFileStats)
  const [action, setAction] = useState('ALL')

  if (events.loading || sensitive.loading || stats.loading) return <LoadingState label="Loading file activity..." />

  const countFor = (a) => events.data.filter((e) => e.action === a).length
  const filtered = action === 'ALL' ? events.data : events.data.filter((e) => e.action === action)
  const suspicious = events.data.filter((e) => e.risk === 'HIGH').length

  const chips = [{ value: 'ALL', count: events.data.length }, ...ACTIONS.map((a) => ({ value: a, count: countFor(a) }))]

  return (
    <>
      <PageHeader title="File Monitoring" subtitle="File-system activity on monitored directories, linked to USB sessions" />

      <div className="mb-4 grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard label="Monitored Files" value={formatNumber(stats.data.monitoredFiles)} sub="across watched folders" icon={Eye} />
        <StatCard label="Sensitive Files" value={stats.data.sensitiveFiles} sub="classified and tracked" icon={FileLock2} tone="warn" />
        <StatCard label="Recent Events" value={events.data.length} sub="in the last 7 days" icon={Clock} />
        <StatCard label="Suspicious Events" value={suspicious} sub="high risk" icon={AlertTriangle} tone="crit" />
      </div>

      <Panel
        title="File Activity"
        icon={FileSearch}
        className="mb-4"
        action={<span className="font-mono text-xs text-ink-faint">{filtered.length} events</span>}
      >
        <div className="flex flex-wrap gap-2 border-b border-line px-4 py-3" role="group" aria-label="Filter by action">
          {chips.map((chip) => {
            const active = action === chip.value
            return (
              <button
                key={chip.value}
                type="button"
                onClick={() => setAction(chip.value)}
                aria-pressed={active}
                className={`rounded-sm border px-3 py-1 font-mono text-xs font-medium tracking-wide transition-colors ${
                  active
                    ? 'border-accent bg-accent/15 text-accent'
                    : 'border-line-strong text-ink-dim hover:border-ink-faint hover:text-ink'
                }`}
              >
                {chip.value} <span className="text-ink-faint">{chip.count}</span>
              </button>
            )
          })}
        </div>
        <FileActivityTable events={filtered} variant="full" />
      </Panel>

      <Panel title="Sensitive Files" icon={FileLock2}>
        <DataTable columns={sensitiveColumns} rows={sensitive.data} rowClassName={(f) => (f.usbTouched ? 'bg-warn/5' : '')} />
      </Panel>
    </>
  )
}
