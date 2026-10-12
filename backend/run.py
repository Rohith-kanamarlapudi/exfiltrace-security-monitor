"""Start the ExfilTrace integrated backend with all 3 core modules:
1. File Monitoring + USB Data-Theft Detection (Module 1)
2. Network Monitoring + Anomaly Detection (Module 2)
3. USB Forensics + BadUSB Detection (Module 3)

Usage:
    python backend/run.py [--config backend/config.json] [--host 127.0.0.1] [--port 5000]
"""
import argparse
import logging
import os
import socket
import sys
import time
from datetime import datetime, timezone

# Ensure repository root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from flask import Flask, jsonify
from flask_cors import CORS

from backend.app.api import bp as file_bp
from backend.app.config import Config, ConfigError
from backend.app.service import MonitoringService
from backend.network.api import network_bp
from backend.network.capture import get_capture_status
from backend.usb.api import set_service as set_usb_service, usb_bp
from backend.usb.service import UsbForensicsService

log = logging.getLogger("exfiltrace.main")


def create_integrated_app(config: Config, file_service: MonitoringService, usb_service: UsbForensicsService) -> Flask:
    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    app.config["SERVICE"] = file_service
    app.config["USB_FORENSICS_SERVICE"] = usb_service
    set_usb_service(usb_service)

    start_time = time.time()

    # 1. Master Unified Status Endpoint (registered first so it matches frontend mockSystemStatus contract)
    @app.get("/api/status")
    def unified_status():
        uptime_seconds = int(time.time() - start_time)
        hours, rem = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        uptime_str = f"{hours}h {minutes}m {seconds}s"
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        net_status = get_capture_status()

        return jsonify({
            "monitoring": True,
            "host": socket.gethostname(),
            "agentVersion": "1.0.0",
            "uptime": uptime_str,
            "lastSync": now_utc,
            "monitors": [
                {"name": "USB Forensics & BadUSB", "active": usb_service.running},
                {"name": "File Monitor", "active": file_service.files.running},
                {"name": "Network Monitor", "active": True},
                {"name": "Correlation Engine", "active": False},
            ],
            "details": {
                "usb": usb_service.get_status(),
                "files": file_service.status()["file_monitor"],
                "network": net_status,
            },
        })

    # 2. Register Module 3: USB Forensics + BadUSB Detection under /api
    app.register_blueprint(usb_bp, url_prefix="/api")

    # 3. Register Module 2: Network Monitoring + Anomaly Detection under /api
    app.register_blueprint(network_bp, url_prefix="/api")

    # 4. Register Module 1: File Monitoring + USB Data-Theft Detection under /api
    app.register_blueprint(file_bp)

    @app.after_request
    def cors_headers(resp):
        resp.headers.setdefault("Access-Control-Allow-Origin", "*")
        resp.headers.setdefault("Access-Control-Allow-Headers", "Content-Type, Authorization")
        resp.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        return resp

    return app


def main():
    parser = argparse.ArgumentParser(description="ExfilTrace Unified Backend")
    parser.add_argument("--config", help="path to config.json")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    try:
        config = Config.load(args.config)
    except ConfigError as exc:
        raise SystemExit(f"Configuration error: {exc}")

    log.info("Starting ExfilTrace Unified Backend...")

    # Initialize Module 1: File Monitoring + USB Data Theft
    file_service = MonitoringService(config, async_detection=True)

    # Initialize Module 3: USB Forensics + BadUSB Detection
    usb_service = UsbForensicsService(enable_real_discovery=True)

    # Build integrated application
    app = create_integrated_app(config, file_service, usb_service)

    host = args.host or config["api"].get("host", "0.0.0.0")
    port = args.port or config["api"].get("port", 5000)

    # Start backend services
    file_service.start()
    usb_service.start()
    log.info("All 3 modules initialized. Serving on http://%s:%d/api", host, port)

    try:
        app.run(host=host, port=port, threaded=True, use_reloader=False)
    finally:
        log.info("Shutting down ExfilTrace services...")
        file_service.stop()
        usb_service.stop()


if __name__ == "__main__":
    main()
