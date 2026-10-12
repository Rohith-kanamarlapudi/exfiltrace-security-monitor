"""REST API (Flask). All routes live under /api and return {"data": ..., "source": "live"}."""
import logging

from flask import Blueprint, Flask, jsonify, request

from .config import Config, ConfigError
from .service import MonitoringService

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


@bp.get("/alerts")
def alerts():
    limit, offset = _int("limit", 200, 1, 1000), _int("offset", 0, 0, 10**9)
    rows, total = svc().db.query_alerts(
        severity=_choice("severity", SEVERITIES), verdict=_choice("verdict", VERDICTS), limit=limit, offset=offset)
    return _list(rows, total, limit, offset)


@bp.get("/config")
def get_config():
    return jsonify({"data": svc().config.public_dict(), "source": "live"})


@bp.post("/config/directories")
def config_directories():
    body = request.get_json(silent=True) or {}
    action, path = body.get("action"), body.get("path")
    if action not in ("add", "remove") or not isinstance(path, str) or not path.strip():
        raise BadRequest("Body must be {\"action\": \"add\"|\"remove\", \"path\": \"<folder>\"}")
    try:
        dirs = svc().add_directory(path) if action == "add" else svc().remove_directory(path)
    except ValueError as exc:
        raise BadRequest(str(exc))
    return jsonify({"data": {"monitored_directories": dirs}, "source": "live"})


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

    @app.after_request
    def cors(resp):  # dev convenience: the Vite dev server proxies /api, but allow direct calls too
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
