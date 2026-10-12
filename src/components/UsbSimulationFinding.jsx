import Panel from './Panel'
import LiveState from './LiveState'
import { forensicsPresentation } from '../services/usbPresentation'
import { formatDateTime } from '../utils/format'

export default function UsbSimulationFinding({ resource }) {
  const data = resource.data, finding = data?.alert
  if (!data?.actualDeviceId && !finding) return null
  return <Panel title="USB interface findings" className="mb-4" bodyClassName="p-3">
    <LiveState resource={{ ...resource, error: resource.error ? 'Interface observation unavailable; showing retained data.' : null }} label="USB interface findings" />
    <p role="status" className="mb-2 text-sm text-ink-dim">{data.phase === 'paused' ? 'Interface comparison paused pending complete inspection.' : finding ? 'Interface change detected.' : 'Waiting for the next complete interface inspection.'}</p>
    {finding && <div role="alert" className="space-y-2 rounded-sm border border-warn/40 bg-warn/5 p-3 text-sm text-ink">
      <p className="font-semibold text-warn">Possible USB impersonation</p>
      <p>{finding.device.name} · {finding.device.mounts.join(', ') || 'No mounted drive'} · {formatDateTime(finding.timestamp)}</p>
      <p className="break-all font-mono text-xs">Device: {finding.device.deviceId}</p>
      <p>Rule: {finding.rule}<br />Functions: {finding.previousFunctions.join(', ')} → {finding.currentFunctions.join(', ')}</p>
      <p className="break-all font-mono text-xs">Before: {finding.previousFingerprint}<br />Current: {finding.currentFingerprint}</p>
      <p>A previously observed storage device acquired a keyboard function in comparable metadata. This change may indicate USB impersonation; metadata alone cannot establish malicious activity.</p>
      <details><summary>Changed characteristics</summary><pre className="whitespace-pre-wrap break-all text-xs">{JSON.stringify(forensicsPresentation(finding.changedCharacteristics), null, 2)}</pre></details>
    </div>}
  </Panel>
}
