import { Activity, AlertTriangle, ArrowUpRight, Network, Radio } from 'lucide-react'
import PageHeader from '../components/PageHeader'
import PreviewNotice from '../components/PreviewNotice'
import Panel from '../components/Panel'
import StatCard from '../components/StatCard'
import Chart from '../components/Chart'
import NetworkTable from '../components/NetworkTable'
import LoadingState from '../components/LoadingState'
import { useApi } from '../hooks'
import { getNetworkEvents, getNetworkStats, getTrafficSeries } from '../services/api'
import { formatBytes, formatNumber } from '../utils/format'

export default function NetworkAnalysis() {
  const events = useApi(getNetworkEvents, 0)
  const stats = useApi(getNetworkStats, 0)
  const series = useApi(getTrafficSeries, 0)

  if (events.loading || stats.loading || series.loading) return <LoadingState label="Loading network traffic..." />

  const flagged = events.data.filter((e) => e.direction === 'OUTBOUND' && e.risk === 'HIGH')

  return (
    <>
      <PreviewNotice />
      <PageHeader title="Network Analysis — sample preview" subtitle="Network monitoring is not connected" />

      <div className="mb-4 grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard label="Packets Captured" value={formatNumber(stats.data.packetsCaptured)} sub="since agent start" icon={Radio} />
        <StatCard label="Outbound Traffic" value={formatBytes(stats.data.outboundBytes)} sub="today" icon={ArrowUpRight} tone="warn" />
        <StatCard label="Active Connections" value={stats.data.activeConnections} sub="open sockets" icon={Activity} tone="safe" />
        <StatCard label="Suspicious Connections" value={stats.data.suspiciousConnections} sub="flagged by correlation" icon={AlertTriangle} tone="crit" />
      </div>

      {flagged.length > 0 && (
        <div role="alert" className="mb-4 flex items-start gap-3 rounded-sm border border-crit/40 bg-crit/10 px-4 py-3">
          <AlertTriangle size={18} className="mt-0.5 shrink-0 text-crit" />
          <p className="text-sm text-ink">
            <span className="font-semibold text-crit">Suspicious outbound traffic: </span>
            {flagged.length} high-risk upload{flagged.length > 1 ? 's' : ''} to{' '}
            <span className="font-mono text-xs">{flagged[0].destinationIp}</span> during an active USB session (
            <span className="font-mono text-xs">{flagged[0].usbSession}</span>).
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
