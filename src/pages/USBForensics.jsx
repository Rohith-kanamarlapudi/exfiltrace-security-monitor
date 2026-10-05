import { useMemo, useState } from 'react'
import { CheckCircle2, Fingerprint, ShieldAlert, Usb, XCircle } from 'lucide-react'
import PageHeader from '../components/PageHeader'
import Panel from '../components/Panel'
import StatCard from '../components/StatCard'
import USBTable from '../components/USBTable'
import StatusBadge from '../components/StatusBadge'
import LoadingState from '../components/LoadingState'
import { useApi } from '../hooks'
import { getUsbDevices } from '../services/api'
import { formatDateTime } from '../utils/format'

function Field({ label, value, mono = true }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] font-semibold uppercase tracking-wider text-ink-faint">{label}</dt>
      <dd className={`mt-0.5 break-words text-sm text-ink ${mono ? 'font-mono' : ''}`}>{value}</dd>
    </div>
  )
}

// Visual hash: one cell per hex digit, brightness follows the digit value.
function HashStrip({ hash, tone }) {
  const color = tone === 'crit' ? 'bg-crit' : tone === 'warn' ? 'bg-warn' : 'bg-accent'
  return (
    <div>
      <div className="flex gap-1" aria-hidden="true">
        {hash.split('').map((ch, i) => (
          <span
            key={i}
            className={`h-6 flex-1 rounded-[2px] ${color}`}
            style={{ opacity: 0.2 + (parseInt(ch, 16) / 15) * 0.8 }}
          />
        ))}
      </div>
      <p className="mt-2 font-mono text-xs tracking-widest text-ink-dim">{hash}</p>
    </div>
  )
}

function FingerprintPanel({ device }) {
  const fp = device.fingerprint
  const passed = fp.checks.filter((c) => c.pass).length
  const total = fp.checks.length
  const tone = device.status === 'CRITICAL' ? 'crit' : device.status === 'SUSPICIOUS' ? 'warn' : 'safe'
  const scoreColor = { crit: 'text-crit', warn: 'text-warn', safe: 'text-safe' }[tone]

  return (
    <Panel
      title="USB Device Fingerprint"
      icon={Fingerprint}
      action={<span className={`font-mono text-xs font-semibold ${scoreColor}`}>{passed}/{total} CHECKS PASSED</span>}
      bodyClassName="grid gap-6 p-4 lg:grid-cols-2"
    >
      {/* Descriptor values used to identify the device */}
      <div className="space-y-5">
        <div>
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-ink-faint">Descriptor Hash</p>
          <HashStrip hash={fp.descriptorHash} tone={tone === 'safe' ? 'info' : tone} />
        </div>
        <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3">
          <Field label="VID : PID" value={`${device.vendorId} : ${device.productId}`} />
          <Field label="Manufacturer" value={fp.manufacturer} mono={false} />
          <Field label="Product String" value={fp.product} mono={false} />
          <Field label="USB Version" value={fp.usbVersion} />
          <Field label="bcdDevice" value={fp.bcdDevice} />
          <Field label="Max Power" value={fp.maxPower} />
        </dl>
        <div>
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-ink-faint">Exposed Interfaces</p>
          <div className="flex flex-wrap gap-2">
            {fp.interfaces.map((i) => {
              const unexpected = device.deviceClass.startsWith('Mass Storage') && i.startsWith('HID')
              return (
                <span
                  key={i}
                  className={`rounded-sm border px-2 py-1 font-mono text-xs ${
                    unexpected ? 'border-crit/40 bg-crit/10 text-crit' : 'border-line-strong text-ink-dim'
                  }`}
                >
                  {i}
                  {unexpected && ' (unexpected)'}
                </span>
              )
            })}
          </div>
        </div>
      </div>

      {/* Authenticity checks */}
      <div>
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-ink-faint">Authenticity Checks</p>
        <ul className="divide-y divide-line/60 rounded-sm border border-line">
          {fp.checks.map((c) => (
            <li key={c.label} className="flex items-center gap-3 px-3 py-2.5 text-sm">
              {c.pass ? (
                <CheckCircle2 size={16} className="shrink-0 text-safe" />
              ) : (
                <XCircle size={16} className="shrink-0 text-crit" />
              )}
              <span className={c.pass ? 'text-ink-dim' : 'text-ink'}>{c.label}</span>
              <span className={`ml-auto font-mono text-[11px] font-semibold ${c.pass ? 'text-safe' : 'text-crit'}`}>
                {c.pass ? 'MATCH' : 'MISMATCH'}
              </span>
            </li>
          ))}
        </ul>
        <p className="mt-4 text-sm leading-relaxed text-ink-dim">{fp.notes}</p>
      </div>
    </Panel>
  )
}

export default function USBForensics() {
  const { data: devices, loading } = useApi(getUsbDevices)
  const [selectedId, setSelectedId] = useState(null)

  // Default selection: the highest-risk device so the fingerprint view is never empty.
  const selected = useMemo(() => {
    if (!devices) return null
    return (
      devices.find((d) => d.id === selectedId) ??
      devices.find((d) => d.status === 'CRITICAL') ??
      devices[0]
    )
  }, [devices, selectedId])

  if (loading) return <LoadingState label="Loading USB devices..." />

  const connected = devices.filter((d) => !d.disconnectedAt).length
  const suspicious = devices.filter((d) => d.status === 'SUSPICIOUS').length
  const critical = devices.filter((d) => d.status === 'CRITICAL').length

  return (
    <>
      <PageHeader title="USB Forensics" subtitle="Device history, fingerprinting and impersonation detection" />

      <div className="mb-4 grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard label="Devices Seen" value={devices.length} sub="this week" icon={Usb} />
        <StatCard label="Connected Now" value={connected} sub="currently mounted" icon={Usb} tone="safe" />
        <StatCard label="Suspicious" value={suspicious} sub="need review" icon={ShieldAlert} tone="warn" />
        <StatCard label="Critical" value={critical} sub="fingerprint mismatch" icon={ShieldAlert} tone="crit" />
      </div>

      <Panel title="USB Devices" icon={Usb} action={<span className="text-xs text-ink-faint">Select a row for details</span>} className="mb-4">
        <USBTable devices={devices} variant="full" onSelect={(d) => setSelectedId(d.id)} selectedId={selected.id} />
      </Panel>

      <Panel
        title="Device Details"
        icon={Usb}
        className="mb-4"
        action={<StatusBadge status={selected.status} />}
        bodyClassName="p-4"
      >
        <div className="mb-4 flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="text-base font-semibold text-ink">{selected.name}</h2>
          <span className="font-mono text-xs text-accent">{selected.session}</span>
        </div>
        <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
          <Field label="Vendor ID" value={selected.vendorId} />
          <Field label="Product ID" value={selected.productId} />
          <Field label="Serial Number" value={selected.serialNumber} />
          <Field label="Device Class" value={selected.deviceClass} mono={false} />
          <Field label="Connected" value={formatDateTime(selected.connectedAt)} />
          <Field
            label="Disconnected"
            value={selected.disconnectedAt ? formatDateTime(selected.disconnectedAt) : 'Still connected'}
          />
        </dl>
      </Panel>

      <FingerprintPanel device={selected} />
    </>
  )
}
