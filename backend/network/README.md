# ExfilTrace — Module 7: Network Monitoring & Anomaly Detection

Live network capture + flow aggregation + exfiltration-style anomaly detection,
stored in SQLite with correlation-ready UTC timestamps and served over three
REST endpoints whose JSON matches the frontend mock contract
(`src/data/mockData.js`).

This is a self-contained module: it does **not** import or modify the frontend.

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
  app.py             runnable Flask app (port 5000, CORS enabled)
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

```bash
# From the repository root:
python -m backend.network.app          # serves http://localhost:5000/api/...
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
                mode="live", interface="en0")   # macOS; Windows: an Npcap device name
  ```

* **pcap** — replay a capture file:

  ```python
  start_capture(mode="pcap", pcap_file="/path/to/capture.pcap")
  ```

### TShark / privileges

* Install Wireshark/TShark:
  * macOS: `brew install --cask wireshark` (installs `tshark`).
  * Windows: install Wireshark with **Npcap**; add `tshark.exe` to `PATH`.
  * Debian/Ubuntu: `sudo apt install tshark`.
* Live capture needs packet-capture privileges:
  * macOS/Linux: run with `sudo` **or** grant capture rights to `dumpcap`
    (`sudo chmod +x /usr/sbin/dumpcap` / add your user to the `pktap` group).
  * Windows: Npcap installs the driver with the needed rights.
* If TShark/PyShark is missing, `start_capture(mode="live", ...)` raises a clear
  `RuntimeError` instead of crashing — use `mode="simulate"` meanwhile.

## REST endpoints

Base URL `http://localhost:5000/api`. These map 1:1 to `ENDPOINTS` in
`src/services/api.js`:

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

### Point the frontend at the real API

Edit only `src/services/api.js` (do not touch it in this module): set
`VITE_API_URL=http://localhost:5000/api` (or the default) and replace each
`delay(mock...)` with `fetch(API_BASE_URL + ENDPOINTS.x).then(r => r.json())`.
Field names and value casing already match `mockData.js`.

## Demo an exfiltration alert

```bash
python -m backend.network.simulate_exfil          # clean DB, prints alerts
python -m backend.network.app                     # in another terminal
curl -s "http://localhost:5000/api/network/events?start=2026-10-05T14:05:00Z&end=2026-10-05T14:06:00Z"
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
| `EXFILTRACE_IFACE` | auto | capture interface |
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
end-to-end capture→persist→detect, the correlation helper, and the exact field
names/casing of all three endpoint payloads.

## Assumptions

* All timestamps are ISO 8601 **UTC** with a `Z` suffix. The USB and file modules
  must emit the same format for correlation to line up.
* `id` is emitted as `n-01` style (DB row id zero-padded).
* Documentation IPs (203.0.113.0/24, 198.51.100.0/24) are treated as *external*
  because the mock scenario uses them as remote hosts.
