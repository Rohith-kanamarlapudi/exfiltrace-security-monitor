import { useEffect, useRef, useState } from 'react'
import { getUsbSimulation, startUsbSimulation, clearUsbSimulation } from '../services/api'
import { useApi } from '../hooks'

export default function UsbSimulationControl() {
  const resource = useApi(getUsbSimulation)
  const [open, setOpen] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState(null)
  const [immediate, setImmediate] = useState(null)
  const root = useRef(null)
  const data = immediate?.previousData === resource.data ? immediate.data : resource.data
  useEffect(() => {
    if (!open) return
    const close = (event) => { if (!root.current?.contains(event.target)) setOpen(false) }
    const escape = (event) => { if (event.key === 'Escape') setOpen(false) }
    document.addEventListener('pointerdown', close)
    document.addEventListener('keydown', escape)
    return () => { document.removeEventListener('pointerdown', close); document.removeEventListener('keydown', escape) }
  }, [open])
  async function change(deviceId) {
    setBusy(true); setError(null)
    try { setImmediate({ data: await (deviceId ? startUsbSimulation(deviceId) : clearUsbSimulation()), previousData: resource.data }) }
    catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }
  return <div ref={root} className="relative">
    <button type="button" aria-expanded={open} aria-controls="usb-simulation-dropdown" onClick={() => setOpen(!open)}
      className="rounded-sm border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-semibold text-accent hover:bg-accent/20">
      Simulate BadUSB
    </button>
    {open && <div id="usb-simulation-dropdown" className="absolute right-0 top-full z-30 mt-2 max-h-[75vh] w-[min(26rem,90vw)] overflow-y-auto rounded-sm border border-line bg-panel p-3 shadow-xl">
      <p className="mb-2 text-xs text-ink-dim">Observation overlay only; no hardware changes or keystrokes.</p>
      {(!data || !data.enabled) && <p className="text-sm text-ink-dim">{data?.message || 'Loading simulation controls…'} Enable EXFILTRACE_USB_SIMULATION=1 when starting the backend.</p>}
      {(error || resource.error) && <p role="alert" className="my-2 text-sm text-warn">{error || resource.error} Controls require a successful current query.</p>}
      {data?.enabled && <>
        <p role="status" className="mb-2 text-sm text-ink">{busy ? 'Confirming the connected physical baseline…' : data.message}</p>
        {data.actualDeviceId && <p className="mb-2 break-all text-xs text-ink-dim">Selected: {data.devices.find((d) => d.deviceId === data.actualDeviceId)?.name || data.actualDeviceId}</p>}
        {data.simulatedAlertCount > 0 && <p className="mb-2 text-xs text-warn">SIMULATED finding available on USB Forensics; excluded from real totals.</p>}
        {data.phase !== 'idle' && <button type="button" disabled={busy || !!resource.error} onClick={() => change()} className="mb-3 rounded-sm border border-line px-3 py-1 text-xs text-ink">Clear / reset simulation</button>}
        <div className="space-y-2">
          {data.devices.map((d) => <button key={d.deviceId} type="button" disabled={busy || !!resource.error || !!data.actualDeviceId || !!d.unavailableReason}
            onClick={() => change(d.deviceId)} className="block w-full rounded-sm border border-line p-2 text-left text-sm text-ink hover:bg-panel-2 disabled:cursor-not-allowed disabled:opacity-60">
            <span className="block font-semibold">{d.name}</span>
            <span className="block text-xs">VID {d.vendorId || 'Unavailable'} / PID {d.productId || 'Unavailable'} · {d.mounts.join(', ') || 'No mounted drive'}</span>
            <span className="block break-all font-mono text-[10px] text-ink-dim">{d.deviceId}</span>
            {d.unavailableReason && <span className="block text-xs text-ink-dim">{d.unavailableReason}</span>}
          </button>)}
          {!data.devices.length && <p className="text-sm text-ink-dim">No connected physical USB devices available.</p>}
        </div>
      </>}
    </div>}
  </div>
}
