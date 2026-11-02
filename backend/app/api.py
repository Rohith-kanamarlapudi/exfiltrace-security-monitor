"""REST API (Flask). All routes live under /api and return {"data": ..., "source": "live"}."""
import logging
import ipaddress
import os
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
from datetime import datetime, timezone

from flask import Blueprint, Flask, jsonify, make_response, request

from .config import Config, ConfigError
from .service import MonitoringService, DirectoryError

log = logging.getLogger("exfiltrace.api")
bp = Blueprint("api", __name__, url_prefix="/api")

FILE_TYPES = {"CREATED", "MODIFIED", "DELETED", "RENAMED"}
USB_TYPES = {"INSERTED", "REMOVED", "MOUNT_CHANGED"}
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VERDICTS = {"SUSPICIOUS", "VERIFIED_TRANSFER"}


class BadRequest(Exception):
    pass


def svc() -> MonitoringService:
    from flask import current_app
    return current_app.config["SERVICE"]


def _int(name, default, lo, hi):
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise BadRequest(f"'{name}' must be an integer")
    return max(lo, min(hi, value))


def _bool(name):
    raw = request.args.get(name)
    if raw is None or raw == "":
        return None
    if raw.lower() in ("1", "true", "yes"):
        return True
    if raw.lower() in ("0", "false", "no"):
        return False
    raise BadRequest(f"'{name}' must be true or false")


def _choice(name, allowed):
    raw = request.args.get(name)
    if not raw:
        return None
    if raw.upper() not in allowed:
        raise BadRequest(f"'{name}' must be one of {sorted(allowed)}")
    return raw.upper()


def _list(rows, total, limit, offset):
    return jsonify({"data": rows, "total": total, "limit": limit, "offset": offset, "source": "live"})


@bp.get("/health")
def health():
    return jsonify({"status": "ok", "source": "live"})


@bp.get("/status")
def status():
    return jsonify({"data": svc().status(), "source": "live"})


@bp.post("/monitoring/<action>")
def control(action):
    if action == "start":
        svc().start()
    elif action == "stop":
        svc().stop()
    else:
        raise BadRequest("action must be 'start' or 'stop'")
    return jsonify({"data": {"running": svc().running}, "source": "live"})


@bp.get("/files/events")
def file_events():
    limit, offset = _int("limit", 200, 1, 1000), _int("offset", 0, 0, 10**9)
    rows, total = svc().db.query_file_events(
        event_type=_choice("type", FILE_TYPES), sensitive=_bool("sensitive"), removable=_bool("removable"),
        search=request.args.get("search") or None, since=request.args.get("since"),
        until=request.args.get("until"), limit=limit, offset=offset)
    return _list(rows, total, limit, offset)


@bp.get("/files/stats")
def file_stats():
    return jsonify({"data": svc().db.file_stats(), "source": "live"})


@bp.get("/files/sensitive")
def sensitive_files():
    rows = svc().db.sensitive_files(_int("limit", 100, 1, 1000))
    return jsonify({"data": rows, "total": len(rows), "source": "live"})


@bp.get("/usb/events")
def usb_events():
    limit, offset = _int("limit", 200, 1, 1000), _int("offset", 0, 0, 10**9)
    rows, total = svc().db.query_usb_events(
        event_type=_choice("type", USB_TYPES), search=request.args.get("search") or None, limit=limit, offset=offset)
    return _list(rows, total, limit, offset)


@bp.get("/usb/devices")
def usb_devices():
    devices = svc().usb.devices()
    return jsonify({"data": devices, "total": len(devices), "source": "live"})


@bp.get('/usb/observations')
def usb_observations():
    rows = svc().usb.history.records()
    return jsonify({'data': rows, 'total': len(rows), 'source': 'live'})


def _local_simulation_request():
    def local(host):
        if host == 'localhost':
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False
    origin = request.headers.get('Origin')
    try:
        return local(request.remote_addr or '') and local(urlsplit(request.host_url).hostname or '') and (
            not origin or urlsplit(origin).scheme in ('http', 'https') and local(urlsplit(origin).hostname or ''))
    except ValueError:
        return False


@bp.route('/usb/simulation', methods=['GET'], provide_automatic_options=False)
def usb_simulation_status():
    return jsonify({'data': svc().usb.simulation_status(), 'source': 'live'})


@bp.route('/usb/simulation', methods=['POST', 'DELETE', 'OPTIONS'])
def usb_simulation_mutation():
    if not svc().usb.simulation.enabled:
        return jsonify({'error': 'USB simulation is disabled by configuration.'}), 403
    if not _local_simulation_request():
        return jsonify({'error': 'Simulation controls require a local connection and local page origin.'}), 403
    if request.method == 'OPTIONS':
        return '', 204
    if request.headers.get('X-ExfilTrace-Simulation') != '1':
        return jsonify({'error': 'Explicit simulation request header required.'}), 403
    if request.method == 'DELETE':
        data = svc().usb.clear_simulation()
    else:
        if not request.is_json:
            raise BadRequest('Expected application/json with deviceId.')
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not isinstance(body.get('deviceId'), str) or not body['deviceId'].strip():
            raise BadRequest('deviceId must be a nonempty physical device identifier.')
        if not svc().usb.running:
            return jsonify({'error': 'Start USB monitoring before activating an overlay.'}), 409
        try:
            data = svc().usb.start_simulation(body['deviceId'])
        except ValueError as exc:
            return jsonify({'error': str(exc)}), 409
    return jsonify({'data': data, 'source': 'live'})


@bp.get("/alerts")
def alerts():
    limit, offset = _int("limit", 200, 1, 1000), _int("offset", 0, 0, 10**9)
    rows, total = svc().db.query_alerts(
        severity=_choice("severity", SEVERITIES), verdict=_choice("verdict", VERDICTS), limit=limit, offset=offset)
    return _list(rows, total, limit, offset)


def _build_reports():
    """Build evidence reports from USB session windows and module event stores."""
    usb_rows, _ = svc().db.query_usb_events(limit=500, offset=0)
    usb_rows.reverse()
    sessions = []
    active = {}
    for event in usb_rows:
        device_id = event.get("device_id")
        if event.get("event_type") == "INSERTED":
            session = {"start": event, "end": None}
            sessions.append(session)
            active[device_id] = session
        elif event.get("event_type") == "REMOVED" and device_id in active:
            active[device_id]["end"] = event
            del active[device_id]
        elif event.get("event_type") == "MOUNT_CHANGED" and device_id in active:
            known_mounts = active[device_id]["start"].get("mounts") or []
            active[device_id]["start"]["mounts"] = list(dict.fromkeys(known_mounts + (event.get("mounts") or [])))

    grouped = {}
    for session in sessions:
        if session["start"].get("mounts"):
            grouped.setdefault(session["start"].get("device_id"), []).append(session)
    device_reports = list(grouped.items())[-1:]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    if not device_reports:
        return []
    sessions = [session for _, device_sessions in device_reports for session in device_sessions]
    window_start = min(session["start"]["timestamp"] for session in sessions)
    window_end = max(session["end"]["timestamp"] if session["end"] else now for session in sessions)
    file_rows, _ = svc().db.query_file_events(since=window_start, until=window_end, limit=5000, offset=0)
    network_rows = []
    network_available = True
    try:
        from backend.network import db as network_db, serializers as network_serializers
        connection = network_db.get_connection()
        try:
            network_rows = [network_serializers.event_to_api(row) for row in
                            network_db.fetch_events(connection, start=window_start, end=window_end, limit=5000)]
        finally:
            connection.close()
    except Exception:
        log.info("Network evidence unavailable while building reports", exc_info=True)
        network_available = False

    reports = []
    for device_id, device_sessions in device_reports:
        first_event = device_sessions[0]["start"]
        last_event = device_sessions[-1]["end"] or device_sessions[-1]["start"]
        files_by_id, network_by_id = {}, {}
        timeline = []
        for session in device_sessions:
            start_event, end_event = session["start"], session["end"]
            start = start_event["timestamp"]
            end = end_event["timestamp"] if end_event else now
            timeline.append({"time": start, "title": "USB connected", "detail": start_event.get("name") or "USB device connected", "type": "usb"})
            mounts = [os.path.normcase(os.path.normpath(path)) for path in (start_event.get("mounts") or [])]
            def belongs_to_session(row):
                if not row.get("on_removable"):
                    return False
                if row.get("usb_device_id"):
                    return row["usb_device_id"] == device_id
                location = row.get("volume") or row.get("path") or ""
                location = os.path.normcase(os.path.normpath(location))
                return any(location == mount or location.startswith(mount.rstrip("\\/") + os.sep) for mount in mounts)
            for row in file_rows:
                if start <= row["timestamp"] <= end and belongs_to_session(row):
                    files_by_id[row["id"]] = row
            for row in network_rows:
                if start <= row["timestamp"] <= end:
                    network_by_id[row["id"]] = row
            if end_event:
                timeline.append({"time": end, "title": "USB disconnected", "detail": end_event.get("name") or "USB device removed", "type": "usb"})

        files, network = list(files_by_id.values()), list(network_by_id.values())
        timeline.extend({"time": row["timestamp"], "title": f"File {row['event_type'].lower()}",
                         "detail": row.get("path") or row.get("file_name") or "File event", "type": "file"} for row in files)
        timeline.extend({"time": row["timestamp"], "title": f"{row['direction'].title()} {row['protocol']} activity",
                         "detail": f"{row['destinationIp']}:{row.get('port') or ''} · {row['risk']} risk", "type": "network"} for row in network)

        sensitive = [row for row in files if row.get("sensitive")]
        suspicious_network = [row for row in network if row.get("direction") == "OUTBOUND" and row.get("risk") in ("MEDIUM", "HIGH")]
        if sensitive and suspicious_network:
            severity, incident_type = "HIGH", "Sensitive USB Activity with Suspicious Network Traffic"
        elif sensitive:
            severity, incident_type = "HIGH", "Sensitive File Activity on USB"
        elif suspicious_network:
            severity, incident_type = "MEDIUM", "Suspicious Network Activity During USB Session"
        elif files:
            severity, incident_type = "LOW", "File Activity on USB"
        else:
            severity, incident_type = "LOW", "USB Session Activity"

        timeline.sort(key=lambda item: item["time"])
        name = first_event.get("name") or "USB device"
        file_names = [row.get("file_name") or row.get("path") or "File" for row in files]
        net_desc = [f"{row['destinationIp']} ({row['protocol']}, {row['risk']})" for row in network]
        latest_time = last_event["timestamp"]
        ongoing = any(session["end"] is None for session in device_sessions)
        summary = f"{name} was connected in {len(device_sessions)} session(s). {len(files)} removable file event(s) and {len(network)} network event(s) were recorded."
        reports.append({"id": f"RPT-USB-{first_event['id']:06d}", "date": first_event["timestamp"][:10], "timestamp": latest_time,
                        "severity": severity, "incidentType": incident_type, "incidentId": f"USB-{first_event['id']}",
                        "status": "ONGOING" if ongoing else "COMPLETE", "summary": summary,
                        "usbActivity": f"{name} · VID {first_event.get('vendor_id') or 'unknown'} / PID {first_event.get('product_id') or 'unknown'} · {len(device_sessions)} connection session(s)",
                        "fileActivity": "; ".join(file_names) if file_names else "No removable file events recorded in this session.",
                        "networkActivity": "; ".join(net_desc) if net_desc else
                            ("No network events recorded in this session." if network_available else "Network data is unavailable."),
                        "networkAvailable": network_available, "timeline": timeline, "fileCount": len(files),
                        "sensitiveFileCount": len(sensitive), "networkEventCount": len(network)})
    return list(reversed(reports))


@bp.get("/reports")
def reports():
    rows = _build_reports()
    return jsonify({"data": rows, "total": len(rows), "source": "live"})


@bp.get("/reports/<report_id>/export")
def export_report(report_id):
    report = next((row for row in _build_reports() if row["id"] == report_id), None)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    root = ET.Element("report", {"id": report["id"], "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")})
    for key in ("date", "timestamp", "severity", "incidentType", "incidentId", "status", "summary", "usbActivity", "fileActivity", "networkActivity", "networkAvailable"):
        ET.SubElement(root, key).text = str(report[key])
    timeline = ET.SubElement(root, "timeline")
    for step in report["timeline"]:
        node = ET.SubElement(timeline, "event", {"time": step["time"], "type": step["type"]})
        ET.SubElement(node, "title").text = step["title"]
        ET.SubElement(node, "detail").text = step["detail"]
    response = make_response(ET.tostring(root, encoding="utf-8", xml_declaration=True))
    response.headers["Content-Type"] = "application/xml; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="{report_id}.xml"'
    return response


@bp.get("/config")
def get_config():
    return jsonify({"data": svc().config.public_dict(), "source": "live"})


@bp.get('/config/directories')
def directories_status():
    return jsonify({'data': svc().directory_status(), 'source': 'live'})


@bp.post("/config/directories")
def config_directories():
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        raise BadRequest('Expected a JSON object.')
    action, path = body.get("action"), body.get("path")
    if action not in ('add', 'remove', 'edit') or not isinstance(path, str) or not path.strip():
        raise BadRequest('Expected action add, remove or edit and a full folder path.')
    try:
        if action == 'edit':
            dirs = svc().edit_directory(body.get('previousPath'), path)
        else:
            dirs = svc().add_directory(path) if action == 'add' else svc().remove_directory(path)
    except DirectoryError as exc:
        return jsonify({'error': str(exc)}), exc.status
    return jsonify({'data': {'monitored_directories': dirs, **svc().directory_status()}, 'source': 'live'})


def create_app(config=None, service=None, autostart=True):
    app = Flask(__name__)
    if service is None:
        try:
            config = config or Config.load()
        except ConfigError as exc:
            raise SystemExit(f"Configuration error: {exc}")
        service = MonitoringService(config)
    app.config["SERVICE"] = service
    app.register_blueprint(bp)
    from .usb.recovery.api import register as register_recovery
    register_recovery(app, service)

    @app.after_request
    def cors(resp):  # dev convenience: the Vite dev server proxies /api, but allow direct calls too
        if request.path.startswith('/api/usb/recovery'):
            return resp
        if request.path == '/api/usb/simulation' and request.method != 'GET':
            if _local_simulation_request() and svc().usb.simulation.enabled:
                resp.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', request.host_url.rstrip('/'))
                resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-ExfilTrace-Simulation'
                resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS'
                resp.headers['Vary'] = 'Origin'
            return resp
        resp.headers.setdefault("Access-Control-Allow-Origin", "*")
        resp.headers.setdefault("Access-Control-Allow-Headers", "Content-Type")
        return resp

    @app.errorhandler(BadRequest)
    def bad_request(exc):
        return jsonify({"error": str(exc)}), 400

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def not_allowed(_):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(Exception)
    def server_error(exc):
        log.exception("Unhandled API error")
        return jsonify({"error": "Internal server error"}), 500

    if autostart:
        service.start()
    return app
