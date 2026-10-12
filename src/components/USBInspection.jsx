import { formatDateTime } from '../utils/format'
import DataTable from './DataTable'

const available = (v) => v || 'Unavailable'
const columns = [
  { key: 'name', header: 'Function / name', render: (i) => `${i.functions?.join(', ') || 'other'} · ${available(i.name)}` },
  { key: 'pnpClass', header: 'Windows PnP class', render: (i) => available(i.pnpClass) },
  { key: 'instanceId', header: 'Instance / parent / container', render: (i) => <div className="break-all text-xs">{i.instanceId}<br />Parent: {available(i.parentId)}<br />Container: {available(i.containerId)}</div> },
  { key: 'hardwareIds', header: 'Hardware / compatible IDs', render: (i) => <div className="break-all text-xs">{i.hardwareIds?.join(', ') || 'Unavailable'}<br />{i.compatibleIds?.join(', ') || 'Unavailable'}</div> },
]

export default function USBInspection({ device }) {
  const i = device.inspection, observation = device.observation
  return <div className="mt-4 space-y-3 text-sm text-ink-dim">
    <p>Observation source: {device.observationSource === 'windows' ? 'Physical Windows PnP observation' : `Simulated / test or unsupported backend (${device.observationSource || 'unknown'})`}</p>
    <p className="break-all">Physical instance: {i?.physicalInstanceId || device.deviceId}<br />Parent: {available(i?.parentId)}<br />Container: {available(i?.containerId)}<br />Identity scope: {available(i?.identityScope)}</p>
    <p>Manufacturer: {available(i?.manufacturer)} · Product: {available(i?.product)}<br />Serial source: {available(i?.serialSource)} · Functions: {i?.functions?.join(', ') || 'Unavailable'}</p>
    <p>Collection: {i?.completeness || 'Unavailable'} (PnP metadata only; raw USB descriptors unavailable). A complete metadata query can still contain unavailable properties.</p>
    <p>Metadata collected: {i?.collectedAt ? formatDateTime(i.collectedAt) : 'Unavailable'} · Cached between arrivals / inventory changes and the 60-second refresh.</p>
    {i?.diagnostics?.map((message) => <p key={message} className="text-amber-400">{message}</p>)}
    <DataTable rows={(i?.interfaces || []).map((item) => ({ ...item, id: item.instanceId }))} columns={columns} emptyText="Interface inspection unavailable." />
    <p className="break-all font-mono text-xs">Metadata SHA-256: {observation?.currentFingerprint || device.fingerprint?.sha256 || 'Unavailable'}<br />Version: {device.fingerprint?.version || observation?.history?.[0]?.version || 'Unavailable'}<br />Previous: {observation?.previousFingerprint || 'None observed'}</p>
    {observation?.fingerprintRetained && <p className="text-amber-400">Showing the last successful fingerprint; current collection is incomplete. No change comparison was performed.</p>}
    <p>First seen: {observation?.firstSeen ? formatDateTime(observation.firstSeen) : 'Unavailable'} · Last seen: {observation?.lastSeen ? formatDateTime(observation.lastSeen) : 'Unavailable'}<br />{observation?.newlyObserved ? 'Newly observed in this monitoring run' : 'Previously observed or unavailable'}; startup observation time is not physical insertion time.</p>
    <details><summary>Fingerprint history ({observation?.history?.length || 0})</summary>
      {(observation?.history || []).map((h) => <div key={`${h.timestamp}-${h.sha256}`} className="my-2 break-all text-xs">
        {formatDateTime(h.timestamp)} · {h.sha256}
        <pre className="whitespace-pre-wrap">{h.changes.length ? JSON.stringify(h.changes, null, 2) : 'Baseline collected; no comparable change.'}</pre>
      </div>)}
    </details>
    <p>USB version, descriptor class codes, power, firmware revision, BadUSB verdict and write protection: Unavailable. Windows PnP classes are not USB descriptor class codes. First-seen status and metadata changes do not prove BadUSB. Identifiers and hashes are not cryptographic device authentication.</p>
  </div>
}
