# ExfilTrace — Module 7: Network Monitoring & Anomaly Detection

Live network capture + flow aggregation + exfiltration-style anomaly detection,
stored in SQLite with correlation-ready UTC timestamps and served over three
REST endpoints whose JSON matches the frontend mock contract
(`src/data/mockData.js`).

The module can run standalone or be mounted alongside the shared USB/file
backend through `combined.py`. It does not replace teammate-owned routes or
start network capture automatically; the Network Analysis page reads stored
capture data and remains usable when the network database is unavailable.

## Layout

```
backend/network/
  config.py          thresholds/settings (single place, env-overridable)
  timeutil.py        ISO 8601 UTC helpers
  db.py              SQLite schema + queries (parameterized only)
  detector.py        the 4 anomaly rules + Flow/Alert types
  capture.py         PyShark live capture / pcap replay / simulation engine
  serializers.py     DB rows -> exact frontend JSON (camelCase, casing)
  api.py             Flask blueprint: /api/network/events|stats|traffic
  app.py             standalone network-only Flask app (port 5000)
  integration.py     mounts the network blueprint in the shared Flask app
  combined.py        one-process launcher: USB/file monitoring + network API
  correlation.py     get_events_in_window() for the correlation stage
  simulate_exfil.py  demo that reproduces the mock exfiltration scenario
  tests/             pytest: detector rules + endpoint response shapes
  requirements.txt / requirements-dev.txt
```

## Install

```bash
cd <repo root>
python3 -m venv .venv && source .venv/bin/activate     # optional but recommended
pip install -r backend/network/requirements-dev.txt
```

`pyshark` is only needed for **live** capture. Simulation and the REST API work
without it (and without root).

## Running

### Combined system (USB/file + network)

From the repository root, use port 5001 on macOS because AirPlay Receiver owns
port 5000. The shared service reads `backend/config.json`; the network module
uses its own SQLite database and environment variables.

```bash
# The demo database defaults to <tempfile.gettempdir()>/exfil_demo.db.
python3 -m backend.network.simulate_exfil

# Use the same path for the API (shown explicitly for clarity):
DEMO_DB="$(python3 -c 'import tempfile, pathlib; print(pathlib.Path(tempfile.gettempdir()) / "exfil_demo.db")')"
EXFILTRACE_NETWORK_DB="$DEMO_DB" \
  python3 -m backend.network.combined --config backend/config.json \
  --host 127.0.0.1 --port 5001

# In another terminal, point the existing frontend at the combined backend:
VITE_API_URL=http://127.0.0.1:5001/api npm run dev
```

On Windows PowerShell use `$env:TEMP`; see **Windows setup** below. Every
interface and temp path is auto-detected, so no macOS-specific value is required.

`combined.py` preserves the existing USB and file routes. If the network
database or blueprint cannot initialize, it logs the failure and still starts
the USB/file monitoring service. Stop both servers with `Ctrl+C`.

### Opt-in live capture

Live capture is **off by default**; the combined launcher keeps using the demo
or stored network database unless `--live-capture` is passed. With capture
enabled, the live database is used only for network data and the USB/file
service keeps serving from the shared app.

```bash
# Interface auto-detected (Wi-Fi preferred, then Ethernet, then other adapters):
python3 -m backend.network.combined \
  --config backend/config.json --host 127.0.0.1 --port 5001 \
  --live-capture --capture-seconds 120

# Pin an interface (TShark index, device name or friendly name) and TShark:
python3 -m backend.network.combined \
  --config backend/config.json --host 127.0.0.1 --port 5001 \
  --live-capture --interface "Wi-Fi" --tshark-path "/Applications/Wireshark.app/Contents/MacOS/tshark" \
  --capture-seconds 120
```

Flags:

* `--interface VALUE` — TShark index (`2`), device name (`en0`,
  `\Device\NPF_{GUID}`) or friendly name (`Wi-Fi`). Default: auto-detect from
  `tshark -D` (first suitable non-loopback, up interface; Wi-Fi preferred).
  `EXFILTRACE_IFACE` is used when the flag is omitted.
* `--tshark-path PATH` — `tshark` executable or install directory. Default
  lookup: this flag, `EXFILTRACE_TSHARK_PATH`, `PATH`, then common install
  locations (Homebrew/Wireshark.app on macOS; `Program Files\Wireshark` on
  Windows).
* `--live-db PATH` — default `<tempfile.gettempdir()>/exfil_live.db`; the demo
  database (any file named `exfil_demo.db`, compared as a resolved absolute
  path) is refused.
* `--capture-seconds N` — optional capture duration; omitted means unlimited.
* `--promiscuous` — explicit opt-in; capture is non-promiscuous by default.

Switch back to the demo database by omitting `--live-capture` and starting the
launcher with `--network-db "$DEMO_DB"` (or `EXFILTRACE_NETWORK_DB="$DEMO_DB"`).

Live capture stores metadata only: timestamps, IPs, ports, protocol, byte counts,
DNS query names/answers and TLS SNI. It never writes payload bytes or a PCAP
file. DNS A/AAAA answers are used to attach the queried hostname to later
flows; PyShark's nested JSON layers (`Queries`, `Answers`, and the TLS record
handshake) are handled explicitly.
Loopback and the local backend/Vite ports (`5001`, `5173`) are filtered so the
Network page does not count its own polling. DNS names and SNI are still
sensitive metadata; use this mode only on a network you are authorised to observe.

### Network module only

```bash
python -m backend.network.app          # standalone API on http://localhost:5000/api
python -m backend.network.simulate_exfil   # populate DB + print a demo report
python -m pytest backend/network/tests -q  # run the tests
```

`-m` (module) form is required because the package uses relative imports.

### Capture modes

* **simulate** (default, no root needed) — synthetic traffic through the same
  pipeline. Start/stop it from Python or via the helpers:

  ```python
  from backend.network.capture import start_capture, stop_capture, get_capture_status
  start_capture(session_label="demo", mode="simulate")
  # ... later ...
  stop_capture()
  ```

* **live** — real sniffing via PyShark/TShark:

  ```python
  start_capture(session_label="usb-session", usb_session_id="USB-S-0417",
                mode="live", interface="Wi-Fi",   # index, device or friendly name
                promiscuous=False)                # omit interface to auto-detect
  ```

* **pcap** — replay a capture file:

  ```python
  start_capture(mode="pcap", pcap_file="/path/to/capture.pcap")
  ```

### TShark / privileges

* Install Wireshark/TShark:
  * macOS: `brew install --cask wireshark` (installs `tshark` and ChmodBPF).
  * Windows: install Wireshark with **Npcap** (see **Windows setup** below).
  * Linux: install the `tshark` package with your system package manager.
* TShark lookup order: `--tshark-path`, `EXFILTRACE_TSHARK_PATH`, `PATH`,
  then common install locations. `--tshark-path` accepts the executable or its
  install directory.
* Live capture needs packet-capture permissions, but **never sudo**:
  * macOS: Wireshark's ChmodBPF helper grants the current user access to the
    capture devices (`tshark -D` works unprivileged). If capture is denied,
    run the ChmodBPF helper again and log out/back in.
  * Linux: add your user to the `wireshark` group or grant only `dumpcap` the
    required capabilities.
  * Windows: Npcap installs the driver; enable **non-admin capture** during
    setup, or run the terminal as Administrator.
* Capture errors are translated into platform-specific instructions. If
  TShark/PyShark is missing, `start_capture(mode="live", ...)` raises a clear
  `RuntimeError` and the combined launcher keeps serving USB/file routes —
  use `mode="simulate"` meanwhile.

### Windows setup (UNTESTED ON WINDOWS)

Everything in this section is written defensively but has **not been run on a
real Windows machine**. macOS capture is verified; Windows capture is
**mock-tested only**. Please report the exact output of each step.

1. Install **Wireshark for Windows** from <https://www.wireshark.org/> and keep
   the **Npcap** component selected. In the Npcap installer, leave
   "Restrict Npcap driver's access to Administrators only" **unchecked** if you
   want non-admin capture; otherwise run the terminal as Administrator.
2. Install Python 3.10+ and the module dependencies (PowerShell; this includes
   `pyshark`):

   ```powershell
   python -m pip install -r backend/network/requirements.txt
   ```

3. Check TShark and list interfaces:

   ```powershell
   & "C:\Program Files\Wireshark\tshark.exe" -D
   # Example entries (GUID varies):
   # \Device\NPF_{GUID-1} (Wi-Fi)
   # \Device\NPF_{GUID-2} (Ethernet)
   ```

4. Point the module at TShark and the demo database:

   ```powershell
   $env:EXFILTRACE_TSHARK_PATH = "C:\Program Files\Wireshark\tshark.exe"
   $env:EXFILTRACE_NETWORK_DB = "$env:TEMP\exfil_demo.db"
   python -m backend.network.simulate_exfil --db "$env:TEMP\exfil_demo.db"
   ```

5. Start the combined backend with live capture (PowerShell, port 5001):

   ```powershell
   python -m backend.network.combined --config backend/config.json `
     --host 127.0.0.1 --port 5001 `
     --live-capture --interface "Wi-Fi" `
     --live-db "$env:TEMP\exfil_live.db" --capture-seconds 120
   ```

   `--interface` accepts the friendly name (`Wi-Fi`), the number from
   `tshark -D`, or the `\Device\NPF_{GUID}` device name. Omit it to
   auto-detect. The default live database is `$env:TEMP\exfil_live.db`.

6. Start the frontend in another PowerShell window:

   ```powershell
   $env:VITE_API_URL = "http://127.0.0.1:5001/api"
   npm run dev
   ```

Troubleshooting:

| Symptom | Likely cause | Fix (UNTESTED ON WINDOWS) |
|---|---|---|
| `TShark was not found` | Wireshark not installed or not on `PATH` | Set `$env:EXFILTRACE_TSHARK_PATH = "C:\Program Files\Wireshark\tshark.exe"` or pass `--tshark-path` |
| `The NPF driver isn't running` / no interfaces | Npcap missing or driver disabled | Reinstall Wireshark with Npcap; enable the Npcap service |
| `Access is denied` / `Error opening adapter` | Npcap restricted to Administrators | Reinstall Npcap with the admin-only option unchecked, or run the terminal as Administrator |
| `tshark -D` works, capture yields no packets | Wrong adapter selected | Try `--interface "Wi-Fi"` or the `\Device\NPF_{GUID}` name; disable VPN/virtual adapters |
| `pyshark` import error | Dependencies not installed for this Python | `python -m pip install -r backend/network/requirements.txt` |
| Port 5000 in use | Another service (e.g. AirPlay on macOS) | Use `--port 5001` and matching `VITE_API_URL` |
| Database is locked | Another process has the same SQLite file | Stop the other launcher; use separate `--live-db` / `--network-db` files |

## REST endpoints

Standalone base URL `http://localhost:5000/api`; the combined launcher uses
the selected shared backend port (5001 in the example). These map 1:1 to
`ENDPOINTS` in `src/services/api.js`:

| api.js key     | endpoint              | returns                    |
|----------------|-----------------------|----------------------------|
| `networkEvents`| `GET /api/network/events`  | array of event objects  |
| `networkStats` | `GET /api/network/stats`   | stats object            |
| `trafficSeries`| `GET /api/network/traffic` | array of 30-min buckets |

`/events` and `/traffic` accept optional `?start=&end=` ISO 8601 UTC filters,
e.g. `?start=2026-10-05T14:02:11Z&end=2026-10-05T14:06:41Z`.

```bash
curl -s "http://localhost:5000/api/network/events" | python -m json.tool
curl -s "http://localhost:5000/api/network/stats"  | python -m json.tool
curl -s "http://localhost:5000/api/network/traffic" | python -m json.tool
```

### Frontend contract

The Network Analysis fetchers call these routes directly. They accept the
module's bare arrays/objects, normalize and validate them, and reject malformed
responses instead of falling back to sample data. Set `VITE_API_URL` to the
combined backend (for example `http://127.0.0.1:5001/api`) before starting or
building Vite.

## Demo an exfiltration alert

```bash
python -m backend.network.simulate_exfil          # <tempdir>/exfil_demo.db
EXFILTRACE_NETWORK_DB="$(python3 -c 'import tempfile, pathlib; print(pathlib.Path(tempfile.gettempdir()) / "exfil_demo.db")')" \
  python -m backend.network.combined --config backend/config.json \
  --host 127.0.0.1 --port 5001
curl -s "http://localhost:5001/api/network/events?start=2026-10-05T14:05:00Z&end=2026-10-05T14:06:00Z"
```

You should see a ~48 MB OUTBOUND HTTPS flow to `203.0.113.58`
(`files-transfer.example-share.net`) marked `risk: "HIGH"`, plus a HIGH
volumetric alert and a HIGH first-seen-destination alert in the `alerts` table.
No real packets leave the machine — everything is injected.

## Detection rules (detector.py)

1. **Volumetric** — rolling baseline of outbound bytes/interval; flags
   `value > mean + k*std` (k=3) once `MIN_BASELINE_SAMPLES` exist and
   `value >= MIN_ABSOLUTE_BYTES`.
2. **First-seen external destination** — a public IP never seen before
   receiving ≥ `FIRST_SEEN_MIN_BYTES`.
3. **Suspicious ports** — watchlist `21,23,445,3389,4444,6667,9001,31337`.
4. **Private ranges ignored** — RFC1918/loopback/link-local are not "external".

Severity (`low`/`medium`/`high`) is derived from z-score + bytes and mapped to
the frontend `risk` field as `LOW`/`MEDIUM`/`HIGH`.

## Correlation integration (for teammate #4)

```python
from backend.network.correlation import get_events_in_window, tag_usb_session

# Pull everything the network module saw inside a USB session window:
data = get_events_in_window("2026-10-05T14:02:11Z", "2026-10-05T14:06:41Z")
# -> {"events": [...], "flows": [...], "alerts": [...]}

# Optionally stamp the USB session id onto those events:
tag_usb_session("2026-10-05T14:02:11Z", "2026-10-05T14:06:41Z", "USB-S-0417")
```

To bracket a live USB session, call `capture.start_capture(usb_session_id=...)`
on connect and `capture.stop_capture()` on disconnect — every event produced in
between is tagged with that id.

## Configuration (environment variables)

| Var | Default | Meaning |
|-----|---------|---------|
| `EXFILTRACE_NETWORK_DB` | `backend/network/exfiltrace_network.db` | SQLite path |
| `EXFILTRACE_IFACE` | auto-detect | capture interface (index, device or friendly name) |
| `EXFILTRACE_TSHARK_PATH` | auto | TShark executable or install directory |
| `EXFILTRACE_INTERVAL` | `10` | stats/detection interval (s) |
| `EXFILTRACE_ANOMALY_K` | `3.0` | volumetric k |
| `EXFILTRACE_MIN_BASELINE` | `10` | samples before volumetric rule |
| `EXFILTRACE_MIN_ABSOLUTE_BYTES` | `5000000` | noise floor |
| `EXFILTRACE_API_HOST` / `EXFILTRACE_API_PORT` | `0.0.0.0` / `5000` | API bind |

> **macOS note:** Control Center's AirPlay Receiver occupies port 5000. Either
> disable it (System Settings → General → AirDrop & Handoff → AirPlay Receiver)
> or run with `EXFILTRACE_API_PORT=5001` (and set `VITE_API_URL` to match).

## Tests

```bash
python -m pytest backend/network/tests -q
```

Covers: the four detector rules, severity/risk mapping, flow-risk classification,
end-to-end capture→persist→detect, nested PyShark DNS/SNI metadata, live-capture
shutdown/validation and failure isolation, the correlation helper, and the exact
field names/casing of all three endpoint payloads. Cross-platform tests mock
`sys.platform`, TShark lookup, macOS/Windows `tshark -D` output (including Npcap
GUID names), interface auto-detection, tempdir paths and demo-DB refusal.

## Assumptions

* All timestamps are ISO 8601 **UTC** with a `Z` suffix. The USB and file modules
  must emit the same format for correlation to line up.
* `id` is emitted as `n-01` style (DB row id zero-padded).
* Documentation IPs (203.0.113.0/24, 198.51.100.0/24) are treated as *external*
  because the mock scenario uses them as remote hosts.
