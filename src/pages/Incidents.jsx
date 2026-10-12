import { useState } from 'react'
import { Activity, FileSearch, GitMerge, Globe, ShieldAlert, Usb } from 'lucide-react'
import PageHeader from '../components/PageHeader'
import PreviewNotice from '../components/PreviewNotice'
import Panel from '../components/Panel'
import IncidentCard from '../components/IncidentCard'
import IncidentTimeline from '../components/IncidentTimeline'
import RiskBadge from '../components/RiskBadge'
import StatusBadge from '../components/StatusBadge'
import ActionBadge from '../components/ActionBadge'
import DataTable from '../components/DataTable'
import LoadingState from '../components/LoadingState'
import { useApi } from '../hooks'
import { getIncidents } from '../services/api'
import { formatDateTime, formatTime } from '../utils/format'

function Field({ label, value }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] font-semibold uppercase tracking-wider text-ink-faint">{label}</dt>
      <dd className="mt-0.5 break-words font-mono text-sm text-ink">{value}</dd>
    </div>
  )
}

const fileColumns = [
  { key: 'fileName', header: 'File Name', className: 'font-mono text-xs text-ink' },
  { key: 'action', header: 'Action', render: (f) => <ActionBadge action={f.action} /> },
  { key: 'timestamp', header: 'Timestamp', className: 'font-mono text-xs text-ink-dim', render: (f) => formatTime(f.timestamp) },
]

function IncidentDetails({ incident }) {
  // Rows need an id for DataTable
  const fileRows = incident.files.map((f, i) => ({ ...f, id: `${f.fileName}-${i}` }))

  return (
    <div className="space-y-4">
      <Panel bodyClassName="p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="font-mono text-sm font-semibold text-accent">{incident.id}</p>
            <h2 className="mt-1 text-lg font-semibold text-ink">{incident.type}</h2>
            <p className="mt-1 font-mono text-xs text-ink-faint">
              {incident.host} · {formatDateTime(incident.timestamp)}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <RiskBadge level={incident.severity} />
            <StatusBadge status={incident.status} />
          </div>
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title="USB Information" icon={Usb} bodyClassName="p-4">
          <dl className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <Field label="Device" value={incident.usb.deviceName} />
            </div>
            <Field label="Vendor ID" value={incident.usb.vendorId} />
            <Field label="Product ID" value={incident.usb.productId} />
            <div className="col-span-2">
              <Field label="Serial Number" value={incident.usb.serialNumber} />
            </div>
            <div className="col-span-2">
              <Field label="USB Session" value={incident.usb.session} />
            </div>
          </dl>
        </Panel>

        <Panel title="Network Activity" icon={Globe} bodyClassName="p-4">
          <dl className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <Field label="Destination" value={incident.network.destination} />
            </div>
            <Field label="Protocol" value={incident.network.protocol} />
            <Field label="Data Transferred" value={incident.network.dataTransferred} />
          </dl>
        </Panel>
      </div>

      <Panel title="File Activity" icon={FileSearch}>
        <DataTable columns={fileColumns} rows={fileRows} emptyText="No file activity was recorded in this session." />
      </Panel>

      <Panel title="Correlation" icon={GitMerge} bodyClassName="p-4">
        <p className="text-sm leading-relaxed text-ink-dim">{incident.correlation}</p>
        <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-3">
          {[
            { label: 'USB activity', icon: Usb, on: true },
            { label: 'Sensitive file activity', icon: FileSearch, on: incident.files.length > 0 },
            { label: 'Outbound network activity', icon: Globe, on: incident.network.dataTransferred !== '0 B' },
          ].map(({ label, icon: Icon, on }) => (
            <div
              key={label}
              className={`flex items-center gap-2 rounded-sm border px-3 py-2 text-xs ${
                on ? 'border-warn/30 bg-warn/10 text-warn' : 'border-line text-ink-faint'
              }`}
            >
              <Icon size={14} />
              {label}
              <span className="ml-auto font-mono font-semibold">{on ? 'DETECTED' : 'NONE'}</span>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Incident Timeline" icon={Activity} bodyClassName="p-4">
        <IncidentTimeline steps={incident.timeline} />
      </Panel>
    </div>
  )
}

export default function Incidents() {
  const { data: incidents, loading } = useApi(getIncidents, 0)
  const [selectedId, setSelectedId] = useState(null)

  if (loading) return <LoadingState label="Loading incidents..." />

  const selected = incidents.find((i) => i.id === selectedId) ?? incidents[0]

  return (
    <>
      <PreviewNotice />
      <PageHeader title="Security Incidents — sample preview" subtitle="Unified incident integration is unavailable">
        <span className="flex items-center gap-2 font-mono text-xs text-ink-dim">
          <ShieldAlert size={14} className="text-crit" />
          {incidents.filter((i) => i.status !== 'RESOLVED').length} open
        </span>
      </PageHeader>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[22rem_minmax(0,1fr)]">
        <div className="space-y-3">
          {incidents.map((incident) => (
            <IncidentCard
              key={incident.id}
              incident={incident}
              selected={incident.id === selected.id}
              onSelect={(i) => setSelectedId(i.id)}
            />
          ))}
        </div>
        <IncidentDetails incident={selected} />
      </div>
    </>
  )
}
