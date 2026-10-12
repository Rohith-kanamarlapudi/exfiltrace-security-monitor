import { useState } from 'react'
import { FileSearch } from 'lucide-react'
import PageHeader from '../components/PageHeader'
import Panel from '../components/Panel'
import StatCard from '../components/StatCard'
import FileActivityTable from '../components/FileActivityTable'
import AlertsPanel from '../components/AlertsPanel'
import LiveState from '../components/LiveState'
import MonitorHealth from '../components/MonitorHealth'
import { useApi } from '../hooks'
import { getFileEvents, getFileStats, getSensitiveFiles, getAlerts, getSystemStatus } from '../services/api'
const ACTIONS = ['ALL', 'CREATED', 'MODIFIED', 'DELETED', 'RENAMED']
export default function FileMonitoring() {
  const events = useApi(getFileEvents), sensitive = useApi(getSensitiveFiles), stats = useApi(getFileStats)
  const alerts = useApi(getAlerts), status = useApi(getSystemStatus)
  const [action, setAction] = useState('ALL')
  const filtered = events.data?.items.filter((e) => action === 'ALL' || e.eventType === action) ?? []
  return <>
    <PageHeader title="File Monitoring" subtitle="Live activity in watched directories and removable volumes" />
    <LiveState resource={status} label="monitor status" />
    <MonitorHealth status={status.data} />
    <LiveState resource={stats} label="file statistics" />
    <div className="mb-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard label="Recorded events" value={stats.data?.totalEvents ?? 'Unavailable'} sub="stored history" icon={FileSearch} />
      <StatCard label="Observed sensitive paths" value={stats.data?.sensitiveFiles ?? 'Unavailable'} sub="distinct paths recorded as sensitive" />
      <StatCard label="Sensitive events" value={stats.data?.sensitiveEvents ?? 'Unavailable'} sub="events matching configured rules" />
      <StatCard label="Removable-volume events" value={stats.data?.removableEvents ?? 'Unavailable'} sub="activity recorded on removable volumes" />
    </div>
    <p className="mb-4 text-sm text-ink-dim">Counts describe recorded activity, not a complete filesystem inventory. CREATED is a creation event; a verified copy is identified by a VERIFIED_TRANSFER alert. Process names, ownership and session IDs are unavailable.</p>
    <Panel title="Recorded file activity" className="mb-4" bodyClassName="p-3">
      <LiveState resource={events} label="file activity" />
      <div className="mb-3 flex flex-wrap gap-2" role="group" aria-label="Filter by activity">
        {ACTIONS.map((a) => <button type="button" key={a} onClick={() => setAction(a)} aria-pressed={a === action}
          className={`rounded-sm border px-3 py-1 text-xs ${a === action ? 'border-accent text-accent' : 'border-line text-ink-dim'}`}>{a}</button>)}
      </div>
      {events.data && <>
        <p className="mb-2 text-xs text-ink-faint">Showing {filtered.length} matching events from the latest {events.data.items.length} of {events.data.total} recorded events.</p>
        <FileActivityTable events={filtered} />
      </>}
    </Panel>
    <Panel title="Latest recorded sensitive-path activity" className="mb-4" bodyClassName="p-3">
      <LiveState resource={sensitive} label="sensitive-path activity" />
      {sensitive.data && <>
        <p className="mb-2 text-xs text-ink-faint">Up to 100 latest sensitive-path records; files may have been renamed or deleted.</p>
        <FileActivityTable events={sensitive.data.items} />
      </>}
    </Panel>
    <AlertsPanel resource={alerts} />
  </>
}
