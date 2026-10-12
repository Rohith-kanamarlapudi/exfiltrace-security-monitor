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
Existing response wrappers are retained; folder management adds live status and safe persisted edits.

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
$testSource = 'C:\ExfilTraceTest\ordinary-ui-' + [guid]::NewGuid().ToString('N') + '.txt'
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
`MONITORED_FILE_COPIED_TO_USB` alert with severity MEDIUM for a small single file and verdict
VERIFIED_TRANSFER. Expand its evidence. Allow a few seconds for hashing and
polling. View http://127.0.0.1:5173/usb for connected devices and history.
Stop the backend briefly to check that the website retains data and shows a
stale/error notice; restart it to confirm recovery. The HTTP endpoints can also
be checked directly:

- http://127.0.0.1:5000/api/status
- http://127.0.0.1:5000/api/usb/devices
- http://127.0.0.1:5000/api/files/events?removable=true
- http://127.0.0.1:5000/api/alerts?verdict=VERIFIED_TRANSFER

## Monitored Folders and USB copy policy

Open **File Monitoring ? Monitored Folders**. Enter a full existing Windows path
such as `C:\Work\Documents` (without enclosing quotes) and choose **Add folder**.
Each configured row shows active/inactive status and its error. **Edit** starts the
replacement watch and saves configuration before stopping the original; a failed
watch or save keeps the old folder. **Remove monitoring** changes configuration
and stops the watch without deleting folders or files. Automatically discovered
USB watches appear separately with no user edit/remove controls.

Folder changes use the existing `POST /api/config/directories`, extending its
add/remove actions with `edit`, `path`, and `previousPath`. `GET` on that same
endpoint provides folder/watch status and transfer policy. Existing POST
`monitored_directories` responses remain available. Duplicate canonical paths
return 409; invalid/relative/missing/file paths return 400; watch or save failures
return 503 with an explanation. Paths are normalized with Windows case/alias
handling. A stopped monitor can save additions, but cannot edit until started,
since replacements must be watched successfully first.

Configuration is atomically saved to the active `config.json` path and survives
restart. Other settings are preserved. Add/edit/remove take effect while running
without a restart; restart once to load updated code if an older backend process
is still running.

Every content-matched copy from a monitored folder to USB now produces a
`MONITORED_FILE_COPIED_TO_USB` / `VERIFIED_TRANSFER` alert regardless of filename,
extension or sensitivity. Renamed destination files can match by size and SHA-256.
Sensitivity remains descriptive metadata, not an alert eligibility condition.
Source candidates must still belong to currently monitored folders; existing
exclusions apply. Unmatched or unhashable content is never called verified.

New USB transfer alerts are **MEDIUM** until the current USB connection's rolling
120-second window exceeds **3 distinct destination files** or **5 MB (5,000,000
bytes)** of matched content. Exactly three files and exactly 5 MB remain medium;
four files or 5,000,001 bytes are critical. Repeated notifications for the same
path/content do not inflate counts. Changed content versions at the same target
accumulate bytes while counting as one destination file. Thresholds are configurable
under `detection` using `usb_transfer_file_limit`, `usb_transfer_size_limit_bytes`,
and `usb_transfer_window_seconds`; these supersede the legacy bulk threshold for
USB copy priority. Transfer evidence and window state persist in additive SQLite
`usb_transfers` rows, isolated per USB identity and connection. Every alert reports
its window count/bytes and thresholds. Earlier medium alerts retain the priority
assigned when recorded; the copy that crosses a threshold is critical. Existing
historical alerts retain their original severity and rule identifier.

Content matching retains the configured hashing limit (256 MiB by default) and a
50,000-entry source-search bound. Source hashes are cached until size or timestamps
change. Same-name evidence with unavailable/different content remains SUSPICIOUS,
not verified; source attribution cannot be guaranteed if originals disappear before
inspection. Raw filesystem activity is still recorded independently of verification.

To test:

1. Create two harmless local folders and add the first through the page. Create a
   file there and confirm active status and live recorded activity.
2. Edit to the second. Confirm it becomes active and the first leaves the list.
   Try a missing folder or duplicate path and confirm the original remains.
3. Remove the second; verify its files still exist. Add it again and restart the
   backend with the same configuration path; it should return active.
4. Copy one or two ordinary files (no confidential name required) to a discovered
   USB mount. On Dashboard, expand MEDIUM VERIFIED_TRANSFER alerts and inspect
   hashes/source paths. Copy four distinct small files within 120 seconds, or copy
   over 5 MB total, to see a CRITICAL alert at the threshold crossing. Wait more
   than 120 seconds or reconnect before testing a fresh window.

Validation for this change uses representative USB devices and actual temporary
filesystem watches/copies. Physical-drive and browser UI checks were not performed.

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
