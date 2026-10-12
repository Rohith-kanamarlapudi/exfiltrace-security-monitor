"""MonitoringService wires the file monitor, USB monitor, detection engine and database together."""
import logging
import os
import queue
import socket
import threading
import time

from .config import Config
from .db import Database, now_iso
from .detection import DetectionEngine
from .file_monitor import FileMonitor
from .usb import create_backend
from .usb.monitor import UsbMonitor
from .usb.history import UsbHistory

log = logging.getLogger("exfiltrace.service")


class MonitoringService:
    def __init__(self, config=None, db=None, usb_backend=None, async_detection=True):
        self.config = config or Config.load()
        self.db = db or Database(self.config.database_path)
        self.async_detection = async_detection
        backend = usb_backend or create_backend(self.config)
        self.usb = UsbMonitor(
            backend, interval=float(self.config["usb"].get("poll_interval_seconds", 3)),
            on_insert=self._on_usb_insert, on_remove=self._on_usb_remove,
            on_mounts_changed=self._on_usb_mounts_changed, history=UsbHistory(self.db),
            simulation_enabled=self.config['usb'].get('simulation_enabled', False))
        self.files = FileMonitor(self.config, self.db, volume_resolver=self.usb.volume_for,
                                 on_event=self._on_file_event)
        self.detector = DetectionEngine(self.config, self.db, self.usb)
        self._queue = queue.Queue()
        self._worker = None
        self.started_at = None
        self.running = False
        self.errors = []

    # ---------------- lifecycle ----------------
    def start(self):
        if self.running:
            return
        self.running = True
        self.started_at = time.time()
        if self.async_detection:
            self._worker = threading.Thread(target=self._work, name="detection", daemon=True)
            self._worker.start()
        self.files.start()   # before USB so removable mounts found at startup can be watched
        self.usb.start()
        log.info("Monitoring service started")

    def stop(self):
        if not self.running:
            return
        self.running = False
        self.usb.stop()
        self.files.stop()
        if self._worker:
            self._queue.put(None)
            self._worker.join(timeout=10)
            self._worker = None
        log.info("Monitoring service stopped")

    # ---------------- callbacks ----------------
    def _note(self, msg):
        log.warning(msg)
        self.errors.append(msg)
        del self.errors[:-20]

    def _on_file_event(self, fe):
        if self.async_detection and self._worker:
            self._queue.put(fe)
        else:
            self.detector.on_file_event(fe)

    def _work(self):
        while True:
            item = self._queue.get()
            if item is None:
                return
            try:
                self.detector.on_file_event(item)
            except Exception as exc:
                self._note(f"Detection worker error: {exc}")

    def _usb_event(self, event_type, dev, details=None):
        return self.db.add_usb_event(
            event_type=event_type, device_id=dev["device_id"], name=dev["name"],
            vendor_id=dev["vendor_id"], product_id=dev["product_id"], serial_number=dev["serial_number"],
            mounts=dev["mounts"], volume_label=dev["volume_label"], filesystem=dev["filesystem"],
            size_bytes=dev["size_bytes"], details=details or {})

    def _on_usb_insert(self, dev, preexisting):
        self._usb_event("INSERTED", dev, {"preexisting": bool(preexisting),
                                          "note": "Already connected when monitoring started" if preexisting else
                                                  "Connection only; not evidence of data theft"})
        for mount in dev["mounts"]:
            self.files.add_watch(mount, removable=True)

    def _on_usb_remove(self, dev):
        self._usb_event("REMOVED", dev)
        current_mounts = {m for d in self.usb.devices() for m in d['mounts']}
        for mount in dev["mounts"]:
            # A partial storage fallback may resolve into its physical USB root.
            # Keep the watch if the new identity still owns this mounted volume.
            if mount not in current_mounts:
                self.files.remove_watch(mount)

    def _on_usb_mounts_changed(self, dev, old, new):
        self._usb_event("MOUNT_CHANGED", dev, {"previous_mounts": old, "new_mounts": new})
        for mount in set(old) - set(new):
            self.files.remove_watch(mount)
        for mount in new:
            self.files.add_watch(mount, removable=True)

    # ---------------- configuration ----------------
    def add_directory(self, path):
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            raise ValueError(f"Not an existing directory: {path}")
        dirs = list(self.config.get("monitored_directories", []))
        if path not in dirs:
            dirs.append(path)
            self.config.set_directories(dirs)
        if self.files.running:
            self.files.add_watch(path)
        return dirs

    def remove_directory(self, path):
        path = os.path.abspath(path)
        dirs = [d for d in self.config.get("monitored_directories", []) if os.path.abspath(d) != path]
        self.config.set_directories(dirs)
        self.files.remove_watch(path)
        return dirs

    # ---------------- status ----------------
    def status(self):
        stats = self.db.file_stats()
        removable = {w["path"] for w in self.files.watches() if w["removable"]}
        return {
            "running": self.running,
            "host": socket.gethostname(),
            "started_at": self.started_at and time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(self.started_at)),
            "uptime_seconds": int(time.time() - self.started_at) if self.started_at and self.running else 0,
            "server_time": now_iso(),
            "file_monitor": {
                "running": self.files.running,
                "directories": [w for w in self.files.watches() if not w["removable"]],
                "removable_watches": sorted(removable),
                "errors": list(self.files.errors),
                "stats": stats,
            },
            "usb_monitor": {
                "running": self.usb.running,
                "backend": self.usb.backend.name,
                "poll_interval_seconds": self.usb.interval,
                "connected_devices": self.usb.devices(),
                "last_error": self.usb.last_error,
                "polls": self.usb.polls,
            },
            "detection": {
                "alerts_total": self.db.alert_count(),
                "queue_size": self._queue.qsize(),
                "worker_alive": bool(self._worker and self._worker.is_alive()),
                "errors": list(self.errors),
            },
            "database": {"path": self.db.path},
        }
