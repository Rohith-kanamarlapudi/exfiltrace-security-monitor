import { useState } from 'react'
import { Activity, AlertTriangle, ArrowUpRight, Network, Radio } from 'lucide-react'
import PageHeader from '../components/PageHeader'
import Panel from '../components/Panel'
import StatCard from '../components/StatCard'
import Chart from '../components/Chart'
import NetworkTable from '../components/NetworkTable'
import NetworkSummaryTable from '../components/NetworkSummaryTable'
import { summarizeNetworkEvents } from '../services/networkSummary'
import LoadingState from '../components/LoadingState'
import LiveState from '../components/LiveState'
import { useApi } from '../hooks'
import { getNetworkEvents, getNetworkStats, getTrafficSeries } from '../services/api'
import { formatBytes, formatNumber } from '../utils/format'

export default function NetworkAnalysis() {
  const [direction, setDirection] = useState('OUTBOUND')
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
  const outbound = summarizeNetworkEvents(events.data, 'OUTBOUND')
  const inbound = summarizeNetworkEvents(events.data, 'INBOUND')
  const internal = events.data.filter((event) => event.direction === 'INTERNAL')

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
            {flagged.length} high-risk flow record{flagged.length > 1 ? 's' : ''} to{' '}
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

      <p className="mb-3 text-xs text-ink-dim">Totals across stored flow records, grouped by IP and sorted by bytes transferred. Risk is the highest recorded flow risk.</p>
      <div role="group" aria-label="Traffic direction" className="mb-3 inline-flex rounded-sm border border-line bg-panel p-1">
        {[
          { value: 'OUTBOUND', label: 'Outbound', count: outbound.length },
          { value: 'INBOUND', label: 'Inbound', count: inbound.length },
        ].map((option) => (
          <button key={option.value} type="button" aria-pressed={direction === option.value}
            onClick={() => setDirection(option.value)}
            className={`rounded-sm px-4 py-2 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${direction === option.value ? 'bg-accent/15 text-accent' : 'text-ink-dim hover:bg-panel-2 hover:text-ink'}`}>
            {option.label} <span className="ml-1 font-mono text-xs">({option.count})</span>
          </button>
        ))}
      </div>
      <Panel title={direction === 'OUTBOUND' ? 'Outbound destinations' : 'Inbound sources'} icon={Network} className="mb-4">
        <NetworkSummaryTable rows={direction === 'OUTBOUND' ? outbound : inbound} direction={direction} />
      </Panel>
      {internal.length > 0 && <details>
        <summary className="mb-3 cursor-pointer text-sm text-ink-dim">Internal traffic ({internal.length} recorded flows)</summary>
        <Panel title="Internal network activity" icon={Network}>
          <NetworkTable events={internal} variant="full" />
        </Panel>
      </details>}
    </>
  )
}
