import { Activity, AlertTriangle, ArrowUpRight, Network, Radio } from 'lucide-react'
import PageHeader from '../components/PageHeader'
import Panel from '../components/Panel'
import StatCard from '../components/StatCard'
import Chart from '../components/Chart'
import NetworkTable from '../components/NetworkTable'
import LoadingState from '../components/LoadingState'
import LiveState from '../components/LiveState'
import { useApi } from '../hooks'
import { getNetworkEvents, getNetworkStats, getTrafficSeries } from '../services/api'
import { formatBytes, formatNumber } from '../utils/format'

export default function NetworkAnalysis() {
  const events = useApi(getNetworkEvents)
  const stats = useApi(getNetworkStats)
  const series = useApi(getTrafficSeries)

  if (events.loading || stats.loading || series.loading) return <LoadingState label="Loading network traffic..." />

  const resource = events.error ? events : stats.error ? stats : series.error ? series : events
  if (!events.data || !stats.data || !series.data) return <>
    <PageHeader title="Network Analysis" subtitle="Stored network capture and anomaly findings" />
    <LiveState resource={resource} label="network data" />
  </>

  const flagged = events.data.filter((e) => e.direction === 'OUTBOUND' && e.risk === 'HIGH')
  const destinations = [...new Set(flagged.map((e) => e.destinationIp))]
  const sessions = [...new Set(flagged.map((e) => e.usbSession).filter(Boolean))]

  return (
    <>
      <PageHeader title="Network Analysis" subtitle="Stored network capture and anomaly findings" />
      <LiveState resource={resource} label="network data" />

      <div className="mb-4 grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard label="Packets Captured" value={formatNumber(stats.data.packetsCaptured)} sub="recorded in stored capture" icon={Radio} />
        <StatCard label="Outbound Traffic" value={formatBytes(stats.data.outboundBytes)} sub="stored capture windows" icon={ArrowUpRight} tone="warn" />
        <StatCard label="Active Connections" value={stats.data.activeConnections} sub="active near latest capture" icon={Activity} tone="safe" />
        <StatCard label="Suspicious Connections" value={stats.data.suspiciousConnections} sub="flagged destination IPs" icon={AlertTriangle} tone="crit" />
      </div>

      {flagged.length > 0 && (
        <div role="alert" className="mb-4 flex items-start gap-3 rounded-sm border border-crit/40 bg-crit/10 px-4 py-3">
          <AlertTriangle size={18} className="mt-0.5 shrink-0 text-crit" />
          <p className="text-sm text-ink">
            <span className="font-semibold text-crit">Suspicious outbound traffic: </span>
            {flagged.length} high-risk upload{flagged.length > 1 ? 's' : ''} to{' '}
            <span className="font-mono text-xs">{destinations.join(', ')}</span>.
            {sessions.length > 0
              ? <> Tagged to USB session{sessions.length > 1 ? 's' : ''} <span className="font-mono text-xs">{sessions.join(', ')}</span>.</>
              : ' No USB session is tagged on these records.'}
          </p>
        </div>
      )}

      <Panel title="Traffic Over Time" icon={Activity} className="mb-4" bodyClassName="p-4">
        <Chart data={series.data} />
      </Panel>

      <Panel
        title="Network Activity"
        icon={Network}
        action={<span className="font-mono text-xs text-ink-faint">{events.data.length} events</span>}
      >
        <NetworkTable events={events.data} variant="full" />
      </Panel>
    </>
  )
}
