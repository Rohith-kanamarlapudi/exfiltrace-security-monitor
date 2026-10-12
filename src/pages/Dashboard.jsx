import { Link } from 'react-router-dom'
import { FileSearch, Usb, AlertTriangle } from 'lucide-react'
import PageHeader from '../components/PageHeader'
import Panel from '../components/Panel'
import StatCard from '../components/StatCard'
import USBTable from '../components/USBTable'
import FileActivityTable from '../components/FileActivityTable'
import AlertsPanel from '../components/AlertsPanel'
import LiveState from '../components/LiveState'
import MonitorHealth from '../components/MonitorHealth'
import { useApi } from '../hooks'
import { getAlerts, getFileStats, getFileEvents, getSystemStatus, getUsbDevices } from '../services/api'

export default function Dashboard() {
  const status = useApi(getSystemStatus), stats = useApi(getFileStats)
  const usb = useApi(getUsbDevices), files = useApi(getFileEvents), alerts = useApi(getAlerts)
  return <>
    <PageHeader title="Security Dashboard" subtitle="Live file and USB monitoring · network is not connected" />
    <LiveState resource={status} label="monitor status" />
    <MonitorHealth status={status.data} />
    <LiveState resource={stats} label="file statistics" />
    <div className="mb-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard label="Connected USB devices" value={usb.data?.total ?? 'Unavailable'} sub="last successful device snapshot" icon={Usb} />
      <StatCard label="Recorded file events" value={stats.data?.totalEvents ?? 'Unavailable'} sub="stored event history, not a filesystem inventory" icon={FileSearch} />
      <StatCard label="Observed sensitive paths" value={stats.data?.sensitiveFiles ?? 'Unavailable'} sub="distinct paths recorded as sensitive" icon={FileSearch} />
      <StatCard label="Recorded alerts" value={alerts.data?.total ?? 'Unavailable'} sub="file / USB alerts; not a count of proven thefts" icon={AlertTriangle} />
    </div>
    <Panel title="Connected USB devices" className="mb-4" bodyClassName="p-3" action={<Link to="/usb" className="text-xs text-accent">Device history</Link>}>
      <LiveState resource={usb} label="USB devices" />
      {usb.data && <USBTable devices={usb.data.items} />}
    </Panel>
    <Panel title="Recent recorded file activity" className="mb-4" bodyClassName="p-3" action={<Link to="/files" className="text-xs text-accent">View activity</Link>}>
      <LiveState resource={files} label="file activity" />
      {files.data && <FileActivityTable events={files.data.items.slice(0, 6)} />}
    </Panel>
    <AlertsPanel resource={alerts} />
  </>
}
