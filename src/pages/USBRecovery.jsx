import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import PageHeader from '../components/PageHeader'
import Panel from '../components/Panel'
import LiveState from '../components/LiveState'
import { useApi } from '../hooks'
import { getUsbRecovery, changeUsbRecovery } from '../services/api'
import { formatBytes, formatDateTime } from '../utils/format'

const input = 'w-full rounded-sm border border-line bg-panel px-3 py-2 text-sm'
const button = 'rounded-sm border border-accent px-3 py-2 text-sm text-accent disabled:opacity-40'
const active = new Set(['acquiring', 'importing', 'scanning', 'recovering'])
const key = (d) => JSON.stringify([d.deviceId, d.mount])

export default function USBRecovery() {
  const resource = useApi(getUsbRecovery)
  const [params] = useSearchParams()
  const [deviceKey, setDeviceKey] = useState('')
  const [mode, setMode] = useState('device')
  const [imageFolder, setImageFolder] = useState('')
  const [imagePath, setImagePath] = useState('')
  const [offset, setOffset] = useState('0')
  const [outputFolder, setOutputFolder] = useState('')
  const [jobId, setJobId] = useState(null)
  const [selected, setSelected] = useState([])
  const [error, setError] = useState(null)
  const [pending, setPending] = useState(false)
  const data = resource.data
  const devices = data?.devices ?? []
  const device = devices.find((d) => key(d) === deviceKey)
    ?? devices.find((d) => d.deviceId === params.get('deviceId')) ?? devices[0]
  const jobs = data?.jobs ?? []
  const job = jobs.find((j) => j.id === jobId) ?? (!jobId ? jobs[0] : null)
  const busy = pending || Boolean(data?.activeJobId) || Boolean(resource.error)
  async function change(body, id) {
    setPending(true); setError(null)
    try {
      const result = await changeUsbRecovery(body, id)
      setJobId(result.id)
      if (!id || body.action === 'scan') setSelected([])
    } catch (e) { setError(e.message) }
    finally { setPending(false) }
  }
  return <>
    <PageHeader title="USB Recovery" subtitle="Read-only FAT32 volume imaging and metadata-based deleted-file recovery" />
    <LiveState resource={resource} label="USB recovery jobs" />
    <p className="mb-4 text-sm text-ink-dim">Imaging reads the source; it does not provide forensic write blocking. Windows and other programs can still write to a mounted USB. Recovery scans the saved image, never the live USB. Deleted entries and matching file sizes do not guarantee correct contents. No file carving is performed.</p>
    {error && <p role="alert" className="mb-4 text-warn">{error}</p>}
    {data && !data.toolsAvailable && <p role="status" className="mb-4 text-warn">Scanning/recovery unavailable: install The Sleuth Kit and set EXFILTRACE_TSK_DIR to its bin folder, then restart the backend. Image acquisition remains available.</p>}
    <Panel title="1. Select source → 2. Acquire image" className="mb-4" bodyClassName="space-y-3 p-4">
      <label className="block text-sm">Source
        <select className={input} value={mode} onChange={(e) => setMode(e.target.value)}>
          <option value="device">Connected USB storage volume</option><option value="image">Import existing raw image</option>
        </select>
      </label>
      {mode === 'device' ? <>
        <label className="block text-sm">Connected device / mounted volume
          <select className={input} value={device ? key(device) : ''} onChange={(e) => setDeviceKey(e.target.value)}>
            {!devices.length && <option value="">No connected storage volumes</option>}
            {devices.map((d) => <option key={key(d)} value={key(d)}>{d.name} · {d.mount || 'unmounted'} · {d.filesystem || 'filesystem unknown'}{d.filesystem && d.filesystem !== 'FAT32' ? ' (unsupported; FAT32 only)' : ''}</option>)}
          </select>
        </label>
        {device && <p className="break-all text-xs text-ink-dim">{device.deviceId}<br />{device.note}</p>}
      </> : <>
        <label className="block text-sm">Existing image — full local path<input className={input} value={imagePath} onChange={(e) => setImagePath(e.target.value)} placeholder="C:\Evidence\usb.img" /></label>
        <label className="block text-sm">FAT32 filesystem byte offset (0 for a volume image)<input className={input} type="number" min="0" step="512" value={offset} onChange={(e) => setOffset(e.target.value)} /></label>
        <p className="text-xs text-ink-dim">Single raw images only. For a whole-disk image, supply the FAT32 partition byte offset. Import creates a separate working copy on an internal disk; unknown original device identity is recorded as unavailable.</p>
      </>}
      <label className="block text-sm">Image destination — existing folder on an internal disk<input className={input} value={imageFolder} onChange={(e) => setImageFolder(e.target.value)} placeholder="C:\Evidence" /></label>
      <button className={button} disabled={busy || !imageFolder || (mode === 'device' ? !device?.eligible : !imagePath || !offset)}
        onClick={() => change({ action: mode === 'device' ? 'acquire' : 'import', imageFolder,
          ...(mode === 'device' ? { deviceId: device.deviceId, mount: device.mount } : { imagePath, offsetBytes: Number(offset) }) })}>
        {mode === 'device' ? 'Recover deleted files — acquire image' : 'Import image copy'}
      </button>
    </Panel>
    <Panel title="Recovery job history (latest 50)" className="mb-4" bodyClassName="p-4 space-y-3">
      {!jobs.length && <p className="text-sm text-ink-dim">No recovery jobs recorded.</p>}
      <div className="flex flex-wrap gap-2">{jobs.map((j) => <button key={j.id} className={button} aria-pressed={job?.id === j.id} onClick={() => { setJobId(j.id); setSelected([]) }}>{formatDateTime(j.createdAt)} · {j.status}</button>)}</div>
      {job && <>
        <p className="text-sm">{job.phase} · {job.status} · {job.progress}%</p>
        <progress className="w-full" max="100" value={job.progress} aria-label="Recovery operation progress" />
        {active.has(job.status) && <button className={button} disabled={pending} onClick={() => change({ action: 'cancel' }, job.id)}>Cancel operation</button>}
        {job.error && <p role="alert" className="text-warn">{job.error}</p>}
        <dl className="space-y-1 break-all text-xs text-ink-dim">
          <dt>Source identity</dt><dd>{job.sourceDeviceId || 'Unavailable — imported image'} {job.sourceMount}</dd>
          <dt>Image</dt><dd>{job.imagePath || job.partialImagePath || 'Not acquired'} · {job.imageComplete ? 'Complete read/copy' : 'Incomplete'}</dd>
          <dt>Image SHA-256</dt><dd>{job.imageSha256 || 'Unavailable until acquisition completes'}</dd>
          <dt>Updated</dt><dd>{formatDateTime(job.updatedAt)}</dd>
        </dl>
        <button className={button} disabled={busy || !job.imageComplete || !data?.toolsAvailable} onClick={() => change({ action: 'scan' }, job.id)}>3. Scan image for deleted entries</button>
      </>}
    </Panel>
    {job && <Panel title="4. Review candidates → 5. Recover selected" bodyClassName="p-4 space-y-3">
      <p className="text-sm text-ink-dim">{job.limitations} Deleted directories are not recursively traversed by this scan. The original first filename character may be unavailable.</p>
      {!job.candidates.length && <p className="text-sm">{job.status === 'scanned' ? 'No deleted file entries found. This does not prove that no files were deleted.' : 'No candidates available; complete a scan first.'}</p>}
      <div className="max-h-96 overflow-auto"><table className="w-full text-left text-sm"><thead><tr><th>Select</th><th>Available name</th><th>Metadata size</th><th>Status</th></tr></thead>
        <tbody>{job.candidates.map((c) => <tr key={c.id} className="border-t border-line"><td><input type="checkbox" aria-label={`Select ${c.filename}`} checked={selected.includes(c.id)} onChange={(e) => setSelected(e.target.checked ? [...selected, c.id] : selected.filter((id) => id !== c.id))} /></td><td className="break-all p-2">{c.filename}</td><td>{formatBytes(c.sizeBytes)}</td><td>{c.status}</td></tr>)}</tbody></table></div>
      <label className="block text-sm">Recovery destination — existing local internal folder<input className={input} value={outputFolder} onChange={(e) => setOutputFolder(e.target.value)} placeholder="C:\Recovered" /></label>
      <button className={button} disabled={busy || !selected.length || !outputFolder || !data?.toolsAvailable} onClick={() => change({ action: 'recover', candidateIds: selected, outputFolder }, job.id)}>Attempt recovery of {selected.length} selected files</button>
      <p className="text-xs text-ink-dim">Each attempt creates a new output folder. Names are sanitized and end in .unverified; existing files are never overwritten. Recovery activity is separate from security alerts.</p>
      {job.results.map((r, i) => <div key={i} className="break-all border-t border-line pt-2 text-xs"><strong>{r.filename} — {r.status}</strong><p>{r.path}</p><p>{r.error || r.limitations}</p>{r.sha256 && <p>Output SHA-256: {r.sha256}</p>}</div>)}
    </Panel>}
  </>
}
