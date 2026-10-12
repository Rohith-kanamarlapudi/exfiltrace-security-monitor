# PROJECT_CONTEXT.md — ExfilTrace

Shared source of truth for the ExfilTrace team and any coding agent helping on it.
If you are new here, read this file top to bottom first. It is self-contained:
everything you need to pick up your part is below.

> Owner-specific details live in each module folder. The network module (done)
> also has `backend/network/README.md` and `backend/network/STATUS.md`.

---

## 1. Project summary

**ExfilTrace: USB Insertion, File Activity & Network Exfiltration Monitor.**

* Information Security Lab mini project, 4 students.
* Faculty: Dr. Raghavendra Ganiga. Synopsis dated 24 August 2026.

**Problem.** Insiders with physical access can (a) copy confidential files to a
USB stick, (b) use disguised / impersonating USB hardware ("BadUSB", e.g. a
mass-storage stick that also registers as a keyboard) to evade controls, and
(c) send sensitive data to remote servers over the network. Traditional
antivirus often misses this combination.

**Solution.** A Python monitoring pipeline that combines three independent
signals and correlates them into one unified, timestamped incident report:

1. **USB Forensics & Evidence Protection** — connect/disconnect, VID/PID/serial,
   device fingerprinting, BadUSB/impersonation flags, software write-blocking.
2. **Windows Forensics (File Monitoring)** — `watchdog`-based monitoring of a
   sensitive-file watchlist, correlated with USB session timestamps.
3. **Traffic Analysis (Network Monitoring)** — TShark/PyShark capture plus
   volumetric anomaly detection on outbound traffic during USB sessions.

A final stage joins all three inside each USB session window (the "correlation
unit") and exports an XML report.

---

## 2. Architecture

```
React frontend  ->  Python (Flask) REST backend  ->  SQLite
                       ^                                   ^
                       |                                   |
             USB / File / Network monitors  ------------- run, write rows
                       |
                 real-time dashboard
```

**Tech stack**

| Layer | Technology |
|-------|------------|
| Frontend | React + Vite + Tailwind CSS v4 (Recharts for charts) |
| Backend | Python 3, Flask REST API |
| Storage | SQLite |
| USB module | Windows WMI + Registry (Windows-only, expected) |
| File module | Python `watchdog` |
| Network module | TShark / Wireshark, PyShark |
| Reports | XML export |

Final target OS is **Windows**. Code should stay cross-platform unless a module
genuinely needs OS-specific APIs (the USB and Windows-forensics modules do).

---

## 3. Team split and ownership

| Part | Synopsis module | Branch | Folder | Status | Depends on |
|------|-----------------|--------|--------|--------|------------|
| 1. USB Forensics + BadUSB Detection | Module 3: USB Forensics & Evidence Protection | `feature/usb` (suggested) | `backend/app/usb/` (actual) | storage + PnP interfaces + metadata fingerprint history + isolated BadUSB simulation implemented; physical verdicts pending | — |
| 2. File Monitoring + USB Data-Theft Detection | Module 6: Windows Forensics (File Monitoring) | `feature/files` (suggested) | `backend/app/` (actual) | live folder management and all-file USB transfer alerts implemented | USB device/volume association |
| 3. Network Monitoring + Anomaly Detection | Module 7: Traffic Analysis | `feature/np` | `backend/network/` | **done (v0.1.0)** | — |
| 4. Correlation Engine + Backend Integration + Reports | Correlation + Backend + Reports (XML) | `feature/correlation` (suggested) | `backend/app/` (file/USB service) | file/USB integrated; network and reports pending | parts 1, 2, 3 |

Branch names remain suggested. The actual file/USB backend is `backend/app/`,
started with `backend/run.py`; the separate network module is `backend/network/`.

---

## 4. Repo layout

| Path | What it is |
|------|------------|
| `src/` | React frontend. **Do not edit** unless you own the frontend. |
| `src/data/mockData.js` | **Shared contract** — defines every JSON shape the backend must return. |
| `src/services/api.js` | **Shared contract** — has `ENDPOINTS`; the only file pages import data from. Switch each mock to `fetch()` here, one function at a time. |
| `src/pages/` | Dashboard, USBForensics, FileMonitoring, NetworkAnalysis, Incidents, Reports. |
| `backend/network/` | Module 7 (done). See section 6. |
| `backend/usb/`, `backend/files/` | Suggested homes for the other modules (not created yet). |
| `.gitignore` | Ignores `*.db`, `*.pcap`, `dist/`, `node_modules/`, caches. |
| `PROJECT_CONTEXT.md` / `AGENTS.md` | This file + agent entry pointer. |

`src/hooks.js` provides `useApi(fetcher) -> { data, loading, error, updatedAt }`.
The live file/USB pages poll approximately every three seconds, retain successful
data on refresh failure, abort on unmount, and visibly mark stale results.
`src/services/normalize.js` adapts the actual Flask `{data, source, total?}`
wrappers and snake_case fields to camelCase; list results expose `items`, `total`
and `limit`. The existing backend shapes are preserved rather than replaced with
the proposed mock contracts below. `README.md` documents direct HTTP/CORS setup
and `VITE_API_URL` (default `http://127.0.0.1:5000/api`); Vite has no API proxy.

---

## 5. Conventions everyone must follow

1. **Timestamps:** ISO 8601 **UTC**, ending in `Z` (`2026-10-05T14:06:41Z`).
   This is what makes cross-module correlation work.
2. **JSON:** field names in **camelCase**, exactly as in `src/data/mockData.js`,
   including **value casing** (`"HIGH"`, `"OUTBOUND"`, `"SAFE"`, `"COPY"`, ...).
3. **Packaging:** each module lives in its own folder under `backend/`
   (e.g. `backend/usb/`), exposes a Flask **blueprint under `/api`**, and also
   exposes plain Python functions for the correlation engine.
4. **Serializers:** each module keeps its own `serializers.py` so response shapes
   can be adjusted in one place.
5. **Branches:** one branch per module, named `feature/<name>`.
6. **Never commit:** `*.db`, `*.pcap`, `__pycache__/`, `dist/`, `node_modules/`,
   or secrets. (`.gitignore` already covers the first group.)
7. **Never edit another person's folder.**
8. **Windows is the final target:** avoid OS-specific code unless the module
   needs it.

---

## 6. Network module reference (part 3 — DONE)

Location `backend/network/`. Run everything with `python -m` from the repo root
(the package uses relative imports).

**Files**

| File | Purpose |
|------|---------|
| `config.py` | All thresholds/settings and env-var reading. |
| `timeutil.py` | ISO 8601 UTC helpers (`to_iso_utc`, `parse_iso`, bucket helpers). |
| `db.py` | SQLite schema + parameterized queries. |
| `detector.py` | The four anomaly rules + `Flow`/`IntervalStats`/`Alert` types. |
| `capture.py` | PyShark live capture, pcap replay, and a simulation engine; flow aggregation. |
| `serializers.py` | DB rows -> exact frontend JSON (camelCase + casing). |
| `api.py` | Flask blueprint: the three `/api/network/*` routes. |
| `app.py` | Runnable app (CORS enabled, `/api/health`). |
| `correlation.py` | `get_events_in_window()` / `tag_usb_session()` for part 4. |
| `simulate_exfil.py` | Demo that reproduces the mock exfiltration scenario (no real traffic). |
| `tests/` | pytest: detector rules + endpoint contract + capture engine. |

**Detection rules** (`detector.py`)
1. **Volumetric** — rolling baseline of outbound bytes per interval; flags
   `value > mean + k*std` (default k=3) once `MIN_BASELINE_SAMPLES` (10) exist and
   `value >= MIN_ABSOLUTE_BYTES` (5,000,000). Flat baseline falls back to `value > k*mean`.
2. **First-seen external destination** — a public IP never seen before receiving
   ≥ `FIRST_SEEN_MIN_BYTES` (1,000,000) outbound bytes.
3. **Suspicious ports** — watchlist `21, 23, 445, 3389, 4444, 6667, 9001, 31337`
   (external traffic only).
4. **Private ranges excluded** — RFC1918, loopback, link-local, unique-local are
   never "external". (Note: documentation ranges like `203.0.113.0/24` are treated
   as **external** on purpose — the mock uses them as remote hosts.)

Severity `low|medium|high` derives from z-score + bytes and maps to the frontend
`risk` field as `LOW|MEDIUM|HIGH`.

**SQLite tables** (each with indexes on timestamps)
`network_events`, `connections`, `traffic_stats`, `alerts`, `capture_sessions`.

**Endpoints** (base `http://localhost:5000/api`, blueprint under `/api`)

| Config key (`api.js`) | Endpoint | Shape |
|-----------------------|----------|-------|
| `networkEvents` | `GET /api/network/events` | array of `{ id ('n-01'), timestamp, sourceIp, destinationIp, destinationHost, protocol (HTTPS\|TCP\|DNS\|SMB), port (number), packetSizeBytes (number), direction (OUTBOUND\|INBOUND\|INTERNAL), risk (LOW\|MEDIUM\|HIGH), usbSession (string\|null) }` |
| `networkStats` | `GET /api/network/stats` | `{ packetsCaptured, outboundBytes, activeConnections, suspiciousConnections }` |
| `trafficSeries` | `GET /api/network/traffic` | array of 30-min buckets `{ time ('08:00'), outbound (MB), inbound (MB), suspicious (MB) }` |

`/events` and `/traffic` accept optional `?start=&end=` ISO 8601 UTC filters.

**Functions for the correlation engine**

```python
from backend.network.correlation import get_events_in_window, tag_usb_session
from backend.network.capture import start_capture, stop_capture, get_capture_status

window = get_events_in_window("2026-10-05T14:02:11Z", "2026-10-05T14:06:41Z")
# -> {"events": [...], "flows": [...], "alerts": [...]}
tag_usb_session("2026-10-05T14:02:11Z", "2026-10-05T14:06:41Z", "USB-S-0417")
start_capture(usb_session_id="USB-S-0417", mode="simulate")  # or mode="live"
stop_capture()
```

**Environment variables**: `EXFILTRACE_NETWORK_DB` (SQLite path),
`EXFILTRACE_API_HOST` (default `0.0.0.0`), `EXFILTRACE_API_PORT` (default `5000`).
Also `EXFILTRACE_IFACE`, `EXFILTRACE_INTERVAL`, `EXFILTRACE_ANOMALY_K`,
`EXFILTRACE_MIN_BASELINE`, `EXFILTRACE_MIN_ABSOLUTE_BYTES`, `EXFILTRACE_FIRST_SEEN_BYTES`,
`EXFILTRACE_TRAFFIC_BUCKET`, `EXFILTRACE_SIM_INTERVAL`, `EXFILTRACE_SIM_LOCAL_IP`.

**Run / test**

```bash
python -m backend.network.app                 # API on :5000
python -m backend.network.simulate_exfil      # populate a demo DB + print report
python -m pytest backend/network/tests -q     # 24 tests
```

---

## 7. Contracts the other modules must provide

> The tables below describe the original proposed mock UI contracts. The actual
> file/USB backend is implemented in `backend/app/` and returns wrapped snake_case
> data. The frontend now normalizes those responses and omits unsupported mock
> fields; see section 4 and `README.md` for the live integration.

### USB module (part 1) — suggested `backend/usb/`

**Current implementation:** `backend/app/usb/` supports live storage mapping and
read-only native SetupAPI/Configuration Manager PnP inspection of physical USB
roots and their USB/HID/storage functions. Parent ancestry groups composite
interfaces; VID/PID, serial similarity and shared sentinel containers never merge
unrelated devices. Detailed properties are cached until inventory changes or a
60-second refresh; storage mounts update each poll. See `backend/app/usb/README.md`
for identity rules, canonical `windows-pnp-metadata-v1` SHA-256 definition,
limitations, tests and Windows website verification steps.

The existing wrapped `/api/usb/devices` fields are preserved, with camelCase
`observationSource`, `inspection`, `fingerprint` and `observation` additions.
`inspection` includes relationships, interfaces/Windows PnP classes/IDs/functions,
collection completeness, diagnostics and collectedAt. Descriptor fields are null.
`observation` exposes UTC-Z firstSeen/lastSeen, newlyObserved (new in this monitoring
run), current/previous hash and change history. SQLite tables `usb_observations`
and `usb_fingerprint_history` are additive; no duplicate history per poll.
`GET /api/usb/observations` reads persisted identities/characteristics even offline.
Partial queries defer removals and fingerprint comparisons; failures retain the
last snapshot and expose `usb_monitor.last_error`. Mount watches and existing
file-copy detection remain integrated. Metadata hashes are not descriptor hashes
or authentication. First-seen/changed/composite status is not a BadUSB verdict.
Physical BadUSB verdicts and software write protection remain unavailable.

An explicit, default-off `usb.simulation_enabled` flag (or process environment
`EXFILTRACE_USB_SIMULATION=1`) enables the header's Simulate BadUSB control.
`/api/usb/simulation` GET reads state, guarded local POST selects a connected
physical storage-only device, and guarded DELETE clears the overlay. Activation
processes unmodified actual metadata first. The next complete cycle copies that
observation and adds a marked synthetic keyboard/HID function, then uses shared
canonical hashing, comparison/history and the keyboard-addition rule. History is
isolated in memory and its finding is labeled SIMULATED, displayed separately on
USB Forensics and Dashboard, with the affected physical identity highlighted in
both connected-device lists, and excluded from real security totals. Simulation disclosure and
clear/reset controls appear only in the header dropdown; the Forensics page
projects the active keyboard/HID interface into the selected device details with
neutral wording, while API provenance remains explicit. Real objects, SQLite history,
alerts and watches remain untouched by synthetic data. Partial queries pause;
confirmed disconnect, genuine baseline change and monitor stop cancel it. Reset
never produces a reverse hardware-change finding. See the USB README for exact
Windows startup commands, endpoint guards, eligibility and validation limitations.

| Endpoint | `api.js` key | Shape (from `mockUsbDevices`) |
|----------|--------------|-------------------------------|
| `GET /api/usb/devices` | `usbDevices` | array of `{ id ('usb-001'), name, vendorId, productId, serialNumber, deviceClass, connectedAt, disconnectedAt (string\|null), status (SAFE\|SUSPICIOUS\|CRITICAL), session ('USB-S-0409'), fingerprint: { manufacturer, product, usbVersion, bcdDevice, maxPower, interfaces: string[], descriptorHash, checks: [{ label, pass: bool }], notes } }` |

Also owns the shared `GET /api/status` (`api.js` key `status`) returning
`mockSystemStatus`: `{ monitoring: bool, host, agentVersion, uptime, lastSync,
monitors: [{ name, active: bool }] }`.

**For the correlation engine (proposed, not yet in the repo):** a plain-Python
function returning USB **sessions** with a session id and start/end times, e.g.
`get_usb_sessions(start=None, end=None) -> [{ session_id, device, connectedAt,
disconnectedAt }]`, and a write-blocking status helper. *This function name is a
suggestion — agree it with the team and add it here once real.*

### File module (part 2) — suggested `backend/files/`


**Live folder management:** File Monitoring uses GET/POST
`/api/config/directories` for user folder status, add/remove and transactional edit
(`previousPath`, `path`). Full existing absolute directory paths are normalized;
duplicates are rejected. The replacement must be watched and configuration saved
before the original is unwatched. Watch/save failures roll back, files are never
deleted, and automatic USB watches stay separate. Config changes persist atomically
and take effect immediately while running.

**All-file USB copies:** Filename/sensitivity no longer gates verified copy alerts.
Size/SHA-256 matching searches eligible files in currently configured source folders,
including renamed copies. `MONITORED_FILE_COPIED_TO_USB` alerts are MEDIUM until
more than 3 distinct destination files or more than 5,000,000 bytes are matched
within a per-connection 120-second window, then CRITICAL. New `detection` settings
`usb_transfer_file_limit`, `usb_transfer_size_limit_bytes`, and
`usb_transfer_window_seconds` control this policy. Additive SQLite `usb_transfers`
records preserve window evidence across service restarts and deduplicate watcher
notifications. Historical alerts are unchanged. See README for limitations and tests.

| Endpoint | `api.js` key | Shape (from `mockData.js`) |
|----------|--------------|----------------------------|
| `GET /api/files/events` | `fileEvents` | array of `{ id ('f-01'), timestamp, fileName, path, action (CREATE\|MODIFY\|ACCESS\|COPY\|DELETE\|MOVE), process, usbSession (string\|null), risk (LOW\|MEDIUM\|HIGH), sensitive: bool }` |
| `GET /api/files/sensitive` | `sensitiveFiles` | array of `{ id ('sf-1'), fileName, path, classification ('Confidential'\|'Restricted'), owner, size, lastEvent, lastEventAt, usbTouched: bool }` |
| `GET /api/files/stats` | `fileStats` | `{ monitoredFiles: number, sensitiveFiles: number }` |

**For the correlation engine (proposed, not yet in the repo):** a plain-Python
function to fetch file events inside a window, e.g.
`get_file_events_in_window(start, end) -> [...]` returning the same camelCase
shape. *Suggestion — confirm and record the real name here later.*

---

## 8. How the correlation stage will work (part 4)

* The **USB session window** (start/end) is the unit of analysis.
* **File events** and **network events** whose timestamps fall inside the window
  are attached to that session.
* `usbSession` on network events is set by the **correlation engine**, not by the
  network module (the network module leaves it `null` unless you pass
  `usb_session_id` to `start_capture`, or call `tag_usb_session`).
* **Incidents** are built from these joined sessions (see `mockIncidents` shape:
  `{ id ('EXF-001'), type, severity, status, timestamp, host, usb: {...},
  files: [...], network: {...}, correlation, timeline: [{ time, title, detail,
  type }] }`).
* Reports (`mockReports`) are generated from incidents and exported to **XML**.

---

## 9. Known gotchas

* **macOS AirPlay Receiver occupies port 5000.** Use `EXFILTRACE_API_PORT=5001`
  for local dev (and set `VITE_API_URL=http://localhost:5001/api`), or turn off
  AirPlay Receiver (System Settings → General → AirDrop & Handoff).
* **Packet capture needs TShark/Wireshark and admin rights.** Live capture is
  unavailable without them; the network module's **simulation mode** works
  without either.
* **Stop your dev servers** (backend + `npm run dev`) after testing.
* **Dashboard, USB Forensics and File Monitoring use live file/USB data.**
  Network Analysis, unified Incidents and Reports are labeled sample previews.
  Network is not connected and sample findings never appear on the live dashboard.
* **Times shown in the browser are local time** (IST here) while the API stores
  UTC — expected.

---

## 10. Status and remaining work

### A. Network module (part 3 — done)
- [x] Config, time helpers, SQLite schema + queries.
- [x] Detector (4 rules) + capture engine (live/pcap/simulate) with background thread.
- [x] Flask API (3 endpoints) + correlation helper + exfil demo.
- [x] Tests (24) covering detector, endpoint contract, capture engine.
- [ ] Test **live** capture with TShark/PyShark (install Wireshark, `pip install pyshark`, run with elevated rights).
- [ ] Test on **Windows**.
- [ ] Make the demo history more realistic (several hours of baseline so the chart shows a real ramp+spike).
- [ ] Fix/explain the 96-byte DNS packet to the exfil IP being flagged HIGH.
- [ ] Wire capture start/stop to USB session start/stop (depends on **part 1**).

### B. USB module (part 1 - interface inspection and metadata fingerprints implemented)
- [x] Windows CIM USB storage enumeration and disk/partition/drive-letter mapping.
- [x] Startup, insertion, removal and mount-change callbacks into file monitoring.
- [x] Existing `/api/usb/devices` and `/api/status` routes in the integrated backend (current shapes preserved).
- [x] Regression coverage for multiple mounted volumes, unmounted disks, poll failures and recovery.
- [x] Enumerate physical USB/PnP functions with identifiers, ancestry, available serials and connection observations.
- [x] Versioned metadata SHA-256 fingerprints, SQLite observations/history, completeness and webpage integration.
- [x] Isolated, opt-in physical-device BadUSB observation overlay and explainable unexpected-keyboard rule.
- [ ] Physical BadUSB/impersonation verdicts (metadata changes alone are not proof).
- [ ] Software write-blocking for evidence protection.
- [x] Additive real inspection API fields and frontend normalization; unsupported mock capabilities remain unavailable.
- [ ] Plain-Python USB-session accessor for the correlation engine.
- [ ] Physical unplug/replug and multi-partition Windows hardware verification (automated coverage exists).

### C. File module (part 2 — file/USB monitoring implemented in `backend/app/`)
- [x] `watchdog` monitoring over configured directories and discovered USB volumes.
- [x] Live Monitored Folders CRUD/status, replacement-before-removal and atomic configuration persistence.
- [x] All-file monitored-source copy alerts with per-USB count/5 MB severity thresholds and persistent evidence.
- [x] Existing file event, sensitive-path and statistics endpoints connected to the frontend through response normalization.
- [x] Content-matching file/USB alerts with explanations, evidence and verdicts displayed live.
- [x] File event values preserved: CREATED, MODIFIED, DELETED and RENAMED.
- [x] Recorded-event and distinct observed sensitive-path counts labeled accurately; unsupported attribution omitted.
- [ ] USB session IDs (current integration uses device/volume and event IDs).
- [ ] Plain-Python file-events-in-window accessor for the correlation engine.
- [x] Backend monitoring/detection tests and frontend normalization/polling tests.

### D. Correlation + backend integration + Reports (part 4 — not started; do last)
- [ ] Flask app factory that mounts every module blueprint under `/api`.
- [ ] Join USB + file + network events per USB session window; set `usbSession` on network events.
- [ ] Build incidents (`mockIncidents` shape) and alerts (`mockAlerts` shape).
- [ ] XML report export (`mockReports` shape) + `/api/incidents`, `/api/alerts`, `/api/reports`.
- [ ] Dashboard summary endpoint (`/api/dashboard`).
- [ ] End-to-end test.

### E. Delivery (all)
- [ ] Final report document.
- [ ] Demo script / walkthrough.
- [ ] README refresh at repo root.
- [ ] Screenshots (dashboard, each monitor page, an incident).
- [ ] End-to-end test on Windows.

---

## 11. How to keep this file useful

* Each owner edits **only their own section** and the status table, in **small**
  commits, to avoid merge conflicts.
* Record new decisions in the **Decision log** (section 12) with a date and author.
* If a **JSON shape changes**, update both the module's serializer **and** this file.
* Prefer appending a new decision over rewriting history.

---

## 12. Decision log

| Date | Author | Decision |
|------|--------|----------|
| 2026-10-11 | Network module (part 3) | **UTC timestamps everywhere.** All timestamps are ISO 8601 UTC ending in `Z`, for cross-module correlation. |
| 2026-10-11 | Network module (part 3) | **Port 5001 for local testing** because macOS AirPlay Receiver holds port 5000. `EXFILTRACE_API_PORT=5001`, `VITE_API_URL=http://localhost:5001/api`. |
| 2026-10-11 | Network module (part 3) | **Simulation mode** in the network module so development and demos work without root or TShark. |
| 2026-10-11 | Network module (part 3) | The **96-byte DNS packet to the exfil IP** is flagged HIGH in the demo; this may be adjusted (it is real behaviour of the rule set, not a bug per se). |
