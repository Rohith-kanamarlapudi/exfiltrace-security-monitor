import { Link } from 'react-router-dom'
import { Activity, FileSearch, Globe, ShieldAlert, Usb, ArrowRight, AlertTriangle, FileText, Network, CheckCircle2 } from 'lucide-react'
import PageHeader from '../components/PageHeader'
import Panel from '../components/Panel'
import StatCard from '../components/StatCard'
import USBTable from '../components/USBTable'
import FileActivityTable from '../components/FileActivityTable'
import NetworkTable from '../components/NetworkTable'
import AlertCard from '../components/AlertCard'
import IncidentTimeline from '../components/IncidentTimeline'
import RiskBadge from '../components/RiskBadge'
import LoadingState from '../components/LoadingState'
import { useApi } from '../hooks'
import {
  getAlerts,
  getDashboardStats,
  getFileEvents,
  getIncidents,
  getNetworkEvents,
  getSystemStatus,
  getUsbDevices,
} from '../services/api'
import { formatBytes, formatNumber } from '../utils/format'

const ViewAll = ({ to }) => (
  <Link to={to} className="flex items-center gap-1 text-xs text-accent hover:underline">
    View all <ArrowRight size={12} />
  </Link>
)

export default function Dashboard() {
  const status = useApi(getSystemStatus)
  const stats = useApi(getDashboardStats)
  const usb = useApi(getUsbDevices)
  const files = useApi(getFileEvents)
  const network = useApi(getNetworkEvents)
  const alerts = useApi(getAlerts)
  const incidents = useApi(getIncidents)

  const loading = [status, stats, usb, files, network, alerts, incidents].some((r) => r.loading)
  if (loading) return <LoadingState label="Loading security overview..." />

  const latestIncident = incidents.data[0]

  return (
    <>
      <PageHeader title="Security Dashboard" subtitle="Live correlation of USB, file-system and network activity" />

      {/* Monitor health */}
      <div className="mb-4 flex flex-wrap gap-x-6 gap-y-2 rounded-sm border border-line bg-panel px-4 py-2.5">
        {status.data.monitors.map((m) => (
          <span key={m.name} className="flex items-center gap-2 font-mono text-xs text-ink-dim">
            <CheckCircle2 size={13} className={m.active ? 'text-safe' : 'text-crit'} />
            {m.name}
          </span>
        ))}
        <span className="ml-auto font-mono text-xs text-ink-faint">Uptime {status.data.uptime}</span>
      </div>

      {/* Top statistics */}
      <div className="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="USB Devices"
          value={stats.data.usbDevices.connected}
          sub={`connected now, ${stats.data.usbDevices.totalSeen} seen this week`}
          icon={Usb}
        />
        <StatCard
          label="File Events"
          value={formatNumber(stats.data.fileEvents.total)}
          sub={`${stats.data.fileEvents.today} recorded today`}
          icon={FileSearch}
        />
        <StatCard
          label="Network Traffic"
          value={formatBytes(stats.data.networkTraffic.outboundBytes)}
          sub={stats.data.networkTraffic.label}
          icon={Globe}
          tone="warn"
        />
        <StatCard
          label="Security Incidents"
          value={stats.data.incidents.open}
          sub={`open of ${stats.data.incidents.total} total`}
          icon={ShieldAlert}
          tone="crit"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* Activity tables */}
        <div className="min-w-0 space-y-4 xl:col-span-2">
          <Panel title="Recent USB Activity" icon={Usb} action={<ViewAll to="/usb" />}>
            <USBTable devices={usb.data.slice(0, 5)} />
          </Panel>
          <Panel title="Recent File Activity" icon={FileSearch} action={<ViewAll to="/files" />}>
            <FileActivityTable events={files.data.slice(0, 6)} />
          </Panel>
          <Panel title="Recent Network Activity" icon={Network} action={<ViewAll to="/network" />}>
            <NetworkTable events={network.data.slice(0, 6)} />
          </Panel>
        </div>

        {/* Alerts + incident timeline */}
        <div className="space-y-4">
          <Panel
            title="Security Alerts"
            icon={AlertTriangle}
            action={<span className="font-mono text-xs text-ink-faint">{alerts.data.length} active</span>}
          >
            {alerts.data.slice(0, 5).map((a) => (
              <AlertCard key={a.id} alert={a} />
            ))}
          </Panel>

          {latestIncident && (
            <Panel
              title="Latest Incident Timeline"
              icon={Activity}
              action={<ViewAll to="/incidents" />}
              bodyClassName="p-4"
            >
              <div className="mb-4 flex items-center justify-between gap-2">
                <div>
                  <p className="font-mono text-sm font-semibold text-accent">{latestIncident.id}</p>
                  <p className="text-xs text-ink-dim">{latestIncident.type}</p>
                </div>
                <RiskBadge level={latestIncident.severity} />
              </div>
              <IncidentTimeline steps={latestIncident.timeline} compact />
              <Link
                to="/reports"
                className="mt-4 inline-flex items-center gap-1.5 text-xs text-accent hover:underline"
              >
                <FileText size={12} /> View report
              </Link>
            </Panel>
          )}
        </div>
      </div>
    </>
  )
}
