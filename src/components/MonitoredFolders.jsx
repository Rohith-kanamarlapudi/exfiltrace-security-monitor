import { useState } from 'react'
import Panel from './Panel'
import LiveState from './LiveState'
import { useApi } from '../hooks'
import { getMonitoredFolders, changeMonitoredFolder } from '../services/api'

export default function MonitoredFolders() {
  const resource = useApi(getMonitoredFolders)
  const [path, setPath] = useState(''), [editing, setEditing] = useState(null)
  const [busy, setBusy] = useState(false), [error, setError] = useState(null), [message, setMessage] = useState(null)
  const [immediate, setImmediate] = useState(null)
  const data = immediate?.previousData === resource.data ? immediate.data : resource.data
  async function change(action, folder, previousPath) {
    setBusy(true); setError(null); setMessage(null)
    try {
      const updated = await changeMonitoredFolder(action, folder.trim(), previousPath)
      setImmediate({ data: updated, previousData: resource.data })
      setMessage(action === 'remove' ? 'Folder removed from monitoring. Its files were not deleted.' : updated.monitorRunning
        ? 'Folder configuration saved. Active watches updated immediately.' : 'Folder configuration saved. Watching begins when monitoring starts.')
      if (action !== 'remove' || editing === folder) { setPath(''); setEditing(null) }
    } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }
  function submit(event) {
    event.preventDefault()
    change(editing ? 'edit' : 'add', path, editing)
  }
  return <Panel title="Monitored Folders" className="mb-4" bodyClassName="p-3">
    <LiveState resource={resource} label="monitored folders" />
    <p className="mb-3 text-sm text-ink-dim">Manage user folders here. Removing a folder stops monitoring without deleting files. USB drive watches are managed automatically.</p>
    <form onSubmit={submit} className="mb-3 flex flex-wrap items-end gap-2">
      <label className="min-w-60 flex-1 text-xs text-ink-dim" htmlFor="monitored-folder-path">{editing ? 'Replacement full Windows path' : 'Full Windows folder path'}
        <input id="monitored-folder-path" value={path} onChange={(e) => setPath(e.target.value)} placeholder="C:\Work\Documents" required disabled={busy || !!resource.error}
          className="mt-1 block w-full rounded-sm border border-line bg-panel-2 px-3 py-2 font-mono text-sm text-ink" />
      </label>
      <button type="submit" disabled={busy || !!resource.error || !path.trim() || !data} className="rounded-sm border border-accent px-3 py-2 text-sm text-accent disabled:opacity-50">{busy ? 'Saving…' : editing ? 'Save replacement' : 'Add folder'}</button>
      {editing && <button type="button" disabled={busy} onClick={() => { setEditing(null); setPath(''); setError(null) }} className="rounded-sm border border-line px-3 py-2 text-sm text-ink-dim">Cancel edit</button>}
    </form>
    {editing && <p className="mb-2 break-all text-xs text-ink-dim">Replacing: {editing}. The old folder stays watched until the replacement watch and configuration save succeed.</p>}
    {error && <p role="alert" className="mb-3 text-sm text-warn">{error}</p>}
    {message && <p role="status" className="mb-3 text-sm text-safe">{message}</p>}
    {data && <>
      {data.transferPolicy && <p className="mb-3 text-xs text-ink-dim">USB copy alerts cover all file names. Medium priority becomes critical above {data.transferPolicy.fileLimit} distinct files or {(data.transferPolicy.sizeLimitBytes / 1000000).toLocaleString()} MB of matched copies within {data.transferPolicy.windowSeconds} seconds, per USB connection.</p>}
      {!data.monitorRunning && <p className="mb-2 text-sm text-warn">Monitoring is stopped. Added folders will become active on start; edits require monitoring to be running.</p>}
      <ul className="divide-y divide-line">
        {data.folders.map((folder) => <li key={folder.path} className="flex flex-wrap items-center justify-between gap-3 py-3">
          <div className="min-w-0 flex-1"><p className="break-all font-mono text-sm text-ink">{folder.path}</p>
            <p className={`text-xs ${folder.active ? 'text-safe' : 'text-warn'}`}>{folder.active ? 'Active' : 'Inactive'}{folder.error ? ` · ${folder.error}` : ''}</p>
          </div>
          <div className="flex gap-2">
            <button type="button" disabled={busy || !!resource.error || !data.monitorRunning} onClick={() => { setEditing(folder.path); setPath(folder.path); setError(null); setMessage(null) }} className="rounded-sm border border-line px-3 py-1 text-xs text-ink">Edit</button>
            <button type="button" disabled={busy || !!resource.error} onClick={() => change('remove', folder.path)} className="rounded-sm border border-line px-3 py-1 text-xs text-warn">Remove monitoring</button>
          </div>
        </li>)}
      </ul>
      {!data.folders.length && <p className="py-3 text-sm text-ink-dim">No user-managed folders configured.</p>}
      <div className="mt-3 border-t border-line pt-3 text-xs text-ink-dim">
        <p className="font-semibold">Automatic USB watches (read-only)</p>
        {data.usbDirectories.map((folder) => <p key={folder.path} className="mt-1 break-all">{folder.path} · {folder.active ? 'Active' : 'Inactive'}{folder.error ? ` · ${folder.error}` : ''}</p>)}
        {!data.usbDirectories.length && <p className="mt-1">No automatically watched USB volumes.</p>}
      </div>
    </>}
  </Panel>
}
