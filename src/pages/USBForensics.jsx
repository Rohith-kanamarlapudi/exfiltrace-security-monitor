import { useState } from 'react'
import { Usb } from 'lucide-react'
import PageHeader from '../components/PageHeader'
import Panel from '../components/Panel'
import USBTable from '../components/USBTable'
import USBInspection from '../components/USBInspection'
import DataTable from '../components/DataTable'
import AlertsPanel from '../components/AlertsPanel'
import LiveState from '../components/LiveState'
import MonitorHealth from '../components/MonitorHealth'
import { useApi } from '../hooks'
import { getUsbDevices, getUsbEvents, getAlerts, getSystemStatus } from '../services/api'
import { formatDateTime } from '../utils/format'

const historyColumns = [
  { key: 'timestamp', header: 'Recorded at', render: (e) => formatDateTime(e.timestamp) },
  { key: 'name', header: 'Device' },
  { key: 'eventType', header: 'Activity' },
  { key: 'mounts', header: 'Volumes', render: (e) => e.mounts.join(', ') || 'No mounted volumes' },
  { key: 'details', header: 'Context', render: (e) => e.details.preexisting ? 'Already connected at startup' : e.details.note || (e.eventType === 'MOUNT_CHANGED' ? `Previous: ${e.details.previousMounts?.join(', ') || 'None'}` : 'Recorded by USB monitor') },
]
export default function USBForensics() {
  const devices = useApi(getUsbDevices), history = useApi(getUsbEvents)
  const status = useApi(getSystemStatus), alerts = useApi(getAlerts)
  const [selectedId, setSelectedId] = useState(null)
  const selected = devices.data?.items.find((d) => d.id === selectedId) ?? devices.data?.items[0]
  return <>
    <PageHeader title="USB Forensics" subtitle="Live physical USB devices, PnP interfaces and metadata fingerprint history" />
    <LiveState resource={status} label="monitor status" />
    <MonitorHealth status={status.data} />
    <p className="mb-4 text-sm text-ink-dim">Interface inspection includes storage, HID, keyboards and mice. BadUSB verdicts, write protection and session IDs remain unavailable. Connection alone does not establish malicious activity.</p>
    <Panel title="Connected physical USB devices" icon={Usb} className="mb-4" bodyClassName="p-3">
      <LiveState resource={devices} label="USB devices" />
      {devices.data && <USBTable devices={devices.data.items} onSelect={(d) => setSelectedId(d.id)} selectedId={selected?.id} />}
      {selected && <p className="mt-3 break-all font-mono text-xs text-ink-dim">Device ID: {selected.deviceId} · Volume label: {selected.volumeLabel || 'Unavailable'}</p>}
      {selected && <USBInspection device={selected} />}
    </Panel>
    <Panel title="Recorded USB insertion / removal / mount history" className="mb-4" bodyClassName="p-3">
      <LiveState resource={history} label="USB history" />
      {history.data && <>
        <p className="mb-2 text-xs text-ink-faint">Showing {history.data.items.length} of {history.data.total} recorded events. Startup detection time is not the physical insertion time.</p>
        <DataTable rows={history.data.items} columns={historyColumns} emptyText="No recorded USB events." />
      </>}
    </Panel>
    <AlertsPanel resource={alerts} />
  </>
}
