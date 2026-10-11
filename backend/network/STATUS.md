# Module 7 — Network Monitoring + Anomaly Detection — STATUS

Owner: part 3 (branch `feature/np`). Folder: `backend/network/`.
Cross-references: `backend/network/README.md` (how to run),
`PROJECT_CONTEXT.md` (shared contracts, section 6).

---

## 1. What I built

A self-contained Python module that captures traffic, aggregates it into flows,
detects exfiltration-like anomalies, stores everything in SQLite with
correlation-ready UTC timestamps, and exposes three REST endpoints whose JSON
matches `src/data/mockData.js` exactly.

### Files and purpose

| File | Lines | Purpose |
|------|------:|---------|
| `config.py` | 100 | All thresholds/settings in one place, overridable via env vars. |
| `timeutil.py` | 71 | ISO 8601 UTC helpers (`to_iso_utc`, `parse_iso`, bucket helpers). |
| `db.py` | 382 | SQLite schema, indexes and parameterized query helpers. |
| `detector.py` | 304 | The four anomaly rules + `Flow` / `IntervalStats` / `Alert` types. |
| `capture.py` | 609 | PyShark live capture, pcap replay, and a simulation engine; flow aggregation and persistence. |
| `serializers.py` | 128 | DB rows -> exact frontend JSON (camelCase + value casing). |
| `api.py` | 74 | Flask blueprint with the three `/api/network/*` routes. |
| `app.py` | 59 | Runnable Flask app (CORS enabled, `/api/health`). |
| `correlation.py` | 58 | `get_events_in_window()` / `tag_usb_session()` for the correlation stage. |
| `simulate_exfil.py` | 128 | Demo that reproduces the mock exfiltration scenario (no real traffic). |
| `tests/` | 40+147+91+147 | pytest: detector rules, endpoint contract, capture engine. |
| `requirements*.txt`, `README.md`, `.gitignore` | — | Dependencies, module README, local ignore rules. |

### Detection rules (`detector.py`)

1. **Volumetric** — rolling baseline of outbound bytes per interval; flags when
   `value > mean + k*std` (default **k = 3**) once at least `MIN_BASELINE_SAMPLES`
   (**10**) samples exist, **and** `value >= MIN_ABSOLUTE_BYTES` (**5,000,000**).
2. **First-seen external destination** — a public IP never seen before that
   receives >= `FIRST_SEEN_MIN_BYTES` (**1,000,000**) outbound bytes.
3. **Suspicious-port watchlist** — `21, 23, 445, 3389, 4444, 6667, 9001, 31337`
   (external traffic only).
4. **Private ranges ignored** — RFC1918, loopback, link-local and unique-local
   destinations are never "external". Documentation ranges such as
   `203.0.113.0/24` are treated as **external on purpose** (the mock uses them as
   remote hosts).

Severity `low | medium | high` is derived from z-score + bytes and mapped to the
frontend `risk` field as `LOW | MEDIUM | HIGH` (uppercase).

### SQLite tables (each with indexes on timestamps)

`network_events`, `connections`, `traffic_stats`, `alerts`, `capture_sessions`.
All statements are parameterized (no value is ever interpolated into SQL).

### Endpoints (blueprint mounted under `/api`)

| `api.js` key | Endpoint | Shape |
|--------------|----------|-------|
| `networkEvents` | `GET /api/network/events` | array of `{ id ('n-01'), timestamp, sourceIp, destinationIp, destinationHost, protocol (HTTPS\|TCP\|DNS\|SMB), port, packetSizeBytes, direction (OUTBOUND\|INBOUND\|INTERNAL), risk (LOW\|MEDIUM\|HIGH), usbSession (string\|null) }` |
| `networkStats` | `GET /api/network/stats` | `{ packetsCaptured, outboundBytes, activeConnections, suspiciousConnections }` |
| `trafficSeries` | `GET /api/network/traffic` | array of 30-min buckets `{ time ('08:00'), outbound (MB), inbound (MB), suspicious (MB) }` |

`/events` and `/traffic` also accept optional `?start=&end=` ISO 8601 UTC
filters so the correlation engine can query a single USB-session window.

### Simulation mode

`capture.CaptureEngine(mode="simulate")` (and `start_capture(mode="simulate")`)
produces realistic traffic without root or TShark; `mode="pcap"` replays a saved
capture; `mode="live"` uses PyShark. `simulate_exfil.py` scripts the mock
scenario end to end.

---

## 2. What was verified

* **Tests:** `python3 -m pytest backend/network/tests -q` -> **24 passed**
  (detector rules, endpoint response contract incl. exact field names/casing,
  capture engine + simulation).
* **Exfiltration demo:** `python3 -m backend.network.simulate_exfil` populates a
  DB and fires **two HIGH alerts**:
  * Volumetric: 50,529,376 bytes in one interval (z = 1204.4) to
    `203.0.113.58:443`.
  * First-seen external destination: 50,529,280 outbound bytes to `203.0.113.58`.
* **Frontend smoke test (local, manual):** I temporarily pointed the Network
  Analysis page at the backend by editing the three network functions in
  `src/services/api.js` to `fetch()` and running the backend on **port 5001**
  (`EXFILTRACE_API_PORT=5001`) with `VITE_API_URL=http://localhost:5001/api`.
  Verified in the browser:
  * stats cards matched the API exactly — **42,111 packets**, **12 active
    connections**, **1 suspicious**, **58,938,452 outbound bytes** shown as
    **56.2 MB**;
  * no console errors;
  * the page survived a reload.
* **The temporary `src/services/api.js` edit was never committed.** It is
  reverted with `git checkout src/services/api.js` so `src/` stays
  frontend-owned.
* Demo stats above independently reproduced against a fresh DB
  (`/tmp/exfil_check.db`): `packetsCaptured=42111`, `outboundBytes=58938452`,
  `activeConnections=12`, `suspiciousConnections=1`.

---

## 3. Known limitations

* **Live capture with TShark/PyShark is not yet tested** — TShark/Wireshark is
  not installed on the dev Mac. Only simulation and the code path for live/pcap
  are implemented (live path is covered by unit tests with fakes).
* **Demo history is short** — only ~2 buckets of meaningful history, so the
  traffic chart shows a ramp (baseline intervals are quiet and compressed)
  rather than a realistic hours-long baseline with a spike.
* **The demo includes a 96-byte DNS packet to the exfil IP** which is surfaced
  as a HIGH-risk row; this is real behaviour of the rule set, not a crash, but
  it looks odd and should be tuned or explained.
* **`usbSession` is simulated** and stays `null` for real captures until the
  correlation engine sets it (via `start_capture(usb_session_id=...)` or
  `tag_usb_session(...)`).
* **Time zones:** the API stores and returns UTC; the browser displays local
  time (IST here). This is expected but can confuse during demos.
* **Port 5000 conflict:** macOS AirPlay Receiver holds port 5000, so local
  testing used 5001 (`EXFILTRACE_API_PORT=5001`).
* **Windows target untested.** The module avoids OS-specific code, but it has
  only been exercised on macOS.

---

## 4. Remaining work for this module

- [ ] Test **live** capture with TShark/PyShark: install Wireshark,
      `pip install pyshark`, run with elevated rights on a chosen interface.
- [ ] Test on **Windows** (interface names, Npcap).
- [ ] Make the demo data more realistic (several hours of baseline traffic so
      the chart shows a genuine spike).
- [ ] Fix or explain the **DNS-to-exfil-IP HIGH** row.
- [ ] Decide how capture is **started/stopped by USB sessions** (depends on
      part 1 / the correlation engine).
