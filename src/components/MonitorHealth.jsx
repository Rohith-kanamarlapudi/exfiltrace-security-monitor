export default function MonitorHealth({ status }) {
  if (!status) return null
  const file = status.fileMonitor, usb = status.usbMonitor
  return <div className="mb-4 rounded-sm border border-line bg-panel p-3 text-sm text-ink-dim">
    <p>File monitor: {file.running ? 'Running' : 'Stopped'} · USB monitor: {usb.running ? 'Running' : 'Stopped'} ({usb.backend}) · Network: Not connected</p>
    <p>Watched directories: {file.directories.map((d) => d.path).join(', ') || 'None'} · Removable watches: {file.removableWatches.join(', ') || 'None'}</p>
    {usb.lastError && <p role="alert" className="text-warn">USB query failed: {usb.lastError}. Device list is the last successful snapshot.</p>}
    {[...file.errors, ...status.detection.errors].map((error, i) => <p role="alert" className="text-warn" key={i}>{error}</p>)}
  </div>
}
