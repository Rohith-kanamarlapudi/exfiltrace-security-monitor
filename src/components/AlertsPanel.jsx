import Panel from './Panel'
import AlertCard from './AlertCard'
import LiveState from './LiveState'
export default function AlertsPanel({ resource }) {
  return <Panel title="Recorded file / USB alerts" className="mb-4" bodyClassName="p-3">
    <LiveState resource={resource} label="alerts" />
    <p className="mb-3 text-xs text-ink-dim">VERIFIED_TRANSFER means matching file contents exist on the USB. It does not establish unauthorized theft or identify who copied the file. SUSPICIOUS is a pattern requiring review; severity describes priority, not confirmed maliciousness.</p>
    {resource.data && <p className="mb-2 text-xs text-ink-faint">Showing {resource.data.items.length} of {resource.data.total} recorded alerts.</p>}
    {resource.data?.items.map((alert) => <AlertCard key={alert.id} alert={alert} />)}
    {resource.data?.items.length === 0 && <p className="p-3 text-sm text-ink-dim">No recorded alerts.</p>}
  </Panel>
}
