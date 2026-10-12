"""Flask Blueprint exposing USB Forensics, Trust Management, and BadUSB Detection endpoints."""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from .service import UsbForensicsService

usb_bp = Blueprint("usb_forensics", __name__)

_global_service: UsbForensicsService | None = None


def get_service() -> UsbForensicsService:
    global _global_service
    if _global_service is None:
        if current_app and "USB_FORENSICS_SERVICE" in current_app.config:
            _global_service = current_app.config["USB_FORENSICS_SERVICE"]
        else:
            _global_service = UsbForensicsService()
    return _global_service


def set_service(svc: UsbForensicsService) -> None:
    global _global_service
    _global_service = svc


@usb_bp.get("/usb/devices")
def get_usb_devices():
    """Returns array of USB devices matching mockUsbDevices schema exactly."""
    connected_only = request.args.get("connected", "").lower() in ("1", "true")
    svc = get_service()
    devices = svc.get_all_devices(connected_only=connected_only)
    return jsonify([d.to_api() for d in devices])


@usb_bp.get("/usb/devices/<device_id>")
def get_usb_device_detail(device_id: str):
    svc = get_service()
    dev = svc.get_device(device_id)
    if not dev:
        return jsonify({"error": f"USB device {device_id} not found"}), 404
    return jsonify(dev.to_api())


@usb_bp.post("/usb/devices/<device_id>/trust")
def update_device_trust(device_id: str):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if not status or status.upper() not in ("TRUSTED", "UNKNOWN", "SUSPICIOUS"):
        return jsonify({"error": "status must be TRUSTED, UNKNOWN, or SUSPICIOUS"}), 400

    reason = data.get("reason", "Updated via Security Console")
    svc = get_service()
    success = svc.set_device_trust(device_id, status.upper(), reason)
    if not success:
        return jsonify({"error": f"Device {device_id} not found"}), 404

    updated = svc.get_device(device_id)
    return jsonify({"success": True, "device": updated.to_api() if updated else None})


@usb_bp.get("/usb/alerts")
def get_usb_alerts():
    limit = int(request.args.get("limit", 100))
    unack_only = request.args.get("unack", "").lower() in ("1", "true")
    svc = get_service()
    alerts = svc.get_alerts(limit=limit, unack_only=unack_only)
    return jsonify([a.to_dict() for a in alerts])


@usb_bp.post("/usb/alerts/<alert_id>/ack")
def acknowledge_alert(alert_id: str):
    svc = get_service()
    success = svc.acknowledge_alert(alert_id)
    if not success:
        return jsonify({"error": f"Alert {alert_id} not found"}), 404
    return jsonify({"success": True, "alertId": alert_id})


@usb_bp.post("/usb/scan")
def trigger_usb_scan():
    svc = get_service()
    devices = svc.scan_once()
    return jsonify({
        "success": True,
        "scannedDevices": len(devices),
        "realHardware": svc.real_hardware_count,
        "devices": [d.to_api() for d in devices],
    })


@usb_bp.post("/usb/simulate")
def simulate_usb_scenario():
    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario", "badusb_sandisk")
    svc = get_service()
    dev = svc.inject_scenario(scenario)
    if not dev:
        return jsonify({
            "error": f"Unknown scenario '{scenario}'. Available: badusb_sandisk, teensy_injector, legit_logitech, legit_sandisk, unregistered_kingston"
        }), 400
    return jsonify({
        "success": True,
        "message": f"Injected simulated device for scenario '{scenario}'",
        "device": dev.to_api(),
    })


@usb_bp.get("/usb/status")
def get_usb_status():
    svc = get_service()
    return jsonify(svc.get_status())
