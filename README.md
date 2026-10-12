# ExfilTrace

React/Vite frontend connected to the Flask file and USB monitoring backend.
The separate network backend is not connected to this interface.

## Start on Windows

Run these in two PowerShell terminals. Existing dependencies can be reused.

Backend:

```powershell
cd C:\Users\leoan\projects\exfiltrace-security-monitor\backend
.\.venv\Scripts\python.exe run.py --config config.json --host 127.0.0.1 --port 5000
```

Frontend:

```powershell
cd C:\Users\leoan\projects\exfiltrace-security-monitor
npm run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

Open http://127.0.0.1:5173. Stop each server with Ctrl+C.
Vite automatically loads the repository-root `.env`, which sets
`VITE_API_URL=http://127.0.0.1:5000/api`. For a fresh checkout, copy
`.env.example` to `.env`. Local `.env` files are ignored by Git; the example
contains only public configuration. A PowerShell `$env:VITE_API_URL` value
overrides the file; remove that override with `Remove-Item Env:VITE_API_URL`
if you want to use the file instead.

The file/USB backend uses `backend/config.json`; it does not load `.env` files
and needs no backend `.env`. Keep monitoring directories, USB settings and API
host/port in that existing JSON configuration.

For a fresh installation, create `backend/.venv` with `py -m venv backend/.venv`,
install `backend/requirements.txt` using that environment's Python, and run
`npm ci` in the repository root.

## Connection and response contracts

The frontend makes direct HTTP requests; no Vite proxy is assumed or configured.
The backend already supplies `Access-Control-Allow-Origin: *` for local development.
`VITE_API_URL` must include `/api`; its default is `http://127.0.0.1:5000/api`.
Restart Vite after changing the variable. A production build captures its value
at build time. Do not expose the development servers to a public network.

`src/services/api.js` is the HTTP boundary. `normalize.js` validates live wrappers
(`{ data, source: "live", total? }`) and converts snake_case field names to
camelCase without changing their meanings. Lists retain `items`, `total`, and
`limit`; USB `device_id` also becomes the stable row ID. No mock fallback exists.
The Flask response schema and configuration remain unchanged.

Live endpoints: `/status`, `/usb/devices`, `/usb/events`, `/files/events`,
`/files/sensitive`, `/files/stats`, and `/alerts` under the API base URL.
Requests refresh about three seconds after the preceding request completes,
with a ten-second timeout, abort on unmount, and stale-response protection.
Refresh failures leave the last successful result visible with a stale/error
notice; initial failures show unavailable data and retry automatically.

Dashboard, USB Forensics, File Monitoring and the navbar use live data.
Network Analysis, unified Incidents and Reports remain explicitly labeled
**sample previews**; they never contribute findings or statistics to the live dashboard.

## What the data means

- Connected USB storage comes from the latest successful Windows CIM snapshot.
  Mounts are discovered dynamically, including multiple volumes or no mounted
  volumes. Query errors remain visible; a failed poll is not a removal.
- USB history records `INSERTED`, `REMOVED`, and `MOUNT_CHANGED`. Startup records
  identify devices already attached; their timestamps are detection times.
- File events retain `CREATED`, `MODIFIED`, `DELETED`, and `RENAMED`. Renames show
  both paths. A creation event alone is not evidence of a verified copy.
- Sensitivity reflects configured filename, extension and directory rules.
  Counts measure recorded events or distinct observed sensitive paths, not an
  inventory of every file. Latest-path records can refer to deleted/renamed files.
- Alerts show severity, `SUSPICIOUS` or `VERIFIED_TRANSFER`, explanations,
  evidence, and related file/USB event IDs. Verified transfer means matching
  file contents exist on USB; it does not establish unauthorized theft or
  identify who copied the file. Severity is review priority, not proof of maliciousness.
- Fingerprints, HID/BadUSB checks, write-protection, process names, ownership
  and session IDs are not provided by this backend and are not fabricated.
- Tables show the latest 200 file events, USB events and alerts. Filters apply
  to that displayed window. Sensitive-path activity shows up to 100 rows;
  totals are labeled separately where the API provides historical totals.

## Harmless Windows verification

Use USB Forensics to find the current mount rather than assuming `D:`. Safely
unplug/replug the drive and wait for both the backend and frontend polling
cycles (usually up to six seconds). Confirm the device list, removable watches
and history update. Check that `/api/status` has `usb_monitor.last_error: null`.

With the current configuration watching `C:/ExfilTraceTest`, create and modify
one harmless test file. The unique name avoids overwriting previous test files:

```powershell
$testSource = 'C:\ExfilTraceTest\confidential-ui-' + [guid]::NewGuid().ToString('N') + '.txt'
New-Item -ItemType Directory -Force C:\ExfilTraceTest
Set-Content -LiteralPath $testSource -Value 'Harmless ExfilTrace integration test'
Start-Sleep -Seconds 4
Add-Content -LiteralPath $testSource -Value 'Harmless modification'
Start-Sleep -Seconds 4
$usbDevices = (Invoke-RestMethod http://127.0.0.1:5000/api/usb/devices).data
$usbDevices | Select-Object name, mounts
# Choose a mounted drive from the output; replace this example if needed.
$testMount = 'D:\'
Copy-Item -LiteralPath $testSource -Destination $testMount
```

In http://127.0.0.1:5173/files, confirm CREATED/MODIFIED activity and the
`SENSITIVE_FILE_COPIED_TO_USB` alert with severity CRITICAL and verdict
VERIFIED_TRANSFER. Expand its evidence. Allow a few seconds for hashing and
polling. View http://127.0.0.1:5173/usb for connected devices and history.
Stop the backend briefly to check that the website retains data and shows a
stale/error notice; restart it to confirm recovery. The HTTP endpoints can also
be checked directly:

- http://127.0.0.1:5000/api/status
- http://127.0.0.1:5000/api/usb/devices
- http://127.0.0.1:5000/api/files/events?removable=true
- http://127.0.0.1:5000/api/alerts?verdict=VERIFIED_TRANSFER

## Validation

From the repository root:

```powershell
npm test
npm run lint
npm run build
.\backend\.venv\Scripts\python.exe -m pytest backend/tests -q -s
```

Frontend tests use Node's built-in runner and cover normalization, HTTP errors,
empty data, polling cleanup, timeouts, stale responses and recovery. Backend
tests include USB polling and file-copy detection with harmless temporary files.
Browser rendering and physical unplug/replug must also be checked manually when
browser automation is unavailable.
