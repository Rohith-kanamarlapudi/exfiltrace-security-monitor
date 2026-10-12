"""MonitoringService wires the file monitor, USB monitor, detection engine and database together."""
import logging
import os
import queue
import socket
import threading
import time
import ntpath

from .config import Config
from .db import Database, now_iso
from .detection import DetectionEngine
from .file_monitor import FileMonitor
from .usb import create_backend
from .usb.monitor import UsbMonitor
from .usb.history import UsbHistory

log = logging.getLogger("exfiltrace.service")


class DirectoryError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


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
        self._directory_lock = threading.RLock()

    # ---------------- lifecycle ----------------
    def start(self):
        with self._directory_lock:
            self._start()

    def _start(self):
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
        with self._directory_lock:
            self._stop()

    def _stop(self):
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
    @staticmethod
    def _directory_key(path):
        return os.path.normcase(os.path.realpath(path))

    def _directory_path(self, path, must_exist=True):
        if not isinstance(path, str) or not path.strip() or '\x00' in path:
            raise DirectoryError('Enter a full directory path.')
        path = path.strip()
        if not os.path.isabs(path) or os.name == 'nt' and not ntpath.splitdrive(path)[0]:
            raise DirectoryError('Path must be absolute, including the Windows drive letter or UNC share.')
        path = os.path.realpath(path)
        if must_exist and not os.path.isdir(path):
            raise DirectoryError(f'Not an existing directory: {path}')
        if must_exist and self.usb.volume_for(path):
            raise DirectoryError('USB volumes are watched automatically and cannot be added as user-managed folders.', 409)
        return path

    def directory_status(self):
        with self._directory_lock:
            watches = {self._directory_key(w['path']): w for w in self.files.watches()}
            folders = []
            for path in self.config.get('monitored_directories', []):
                watch = watches.get(self._directory_key(path))
                exists = os.path.isdir(path)
                folders.append({'path': path, 'active': bool(exists and self.files.running and watch and watch['active']),
                                'error': 'Directory is missing or inaccessible' if not exists else
                                    (watch['error'] if watch else ('Monitor stopped' if not self.files.running else 'Folder is not actively watched'))})
            return {'monitoredDirectories': list(self.config.get('monitored_directories', [])), 'folders': folders,
                    'usbDirectories': [w for w in watches.values() if w['removable']], 'monitorRunning': self.files.running,
                    'transferPolicy': {'fileLimit': self.config['detection']['usb_transfer_file_limit'],
                                       'sizeLimitBytes': self.config['detection']['usb_transfer_size_limit_bytes'],
                                       'windowSeconds': self.config['detection']['usb_transfer_window_seconds']}}

    def _save_directories(self, directories):
        try:
            self.config.set_directories(directories)
        except (OSError, ValueError) as exc:
            raise DirectoryError(f'Could not persist folder configuration: {exc}', 503) from exc

    def _watch_replacement(self, path):
        if self.files.running and not self.files.add_watch(path):
            error = next((w['error'] for w in self.files.watches() if self._directory_key(w['path']) == self._directory_key(path)), None)
            self.files.remove_watch(path)
            raise DirectoryError(f'Could not watch replacement folder: {error or path}', 503)

    def add_directory(self, path):
        with self._directory_lock:
            path = self._directory_path(path)
            dirs = list(self.config.get('monitored_directories', []))
            if any(self._directory_key(d) == self._directory_key(path) for d in dirs):
                raise DirectoryError('This folder is already monitored.', 409)
            self._watch_replacement(path)
            try:
                self._save_directories(dirs + [path])
            except DirectoryError:
                self.files.remove_watch(path)
                raise
            return dirs + [path]

    def remove_directory(self, path):
        with self._directory_lock:
            path = self._directory_path(path, must_exist=False)
            dirs = list(self.config.get('monitored_directories', []))
            if not any(self._directory_key(d) == self._directory_key(path) for d in dirs):
                raise DirectoryError('This folder is not user-managed; automatic USB watches cannot be removed here.', 409)
            remaining = [d for d in dirs if self._directory_key(d) != self._directory_key(path)]
            self._save_directories(remaining)
            if not self.usb.volume_for(path):
                if self.files.remove_watch(path) is False:
                    self._save_directories(dirs)
                    raise DirectoryError('Could not stop the folder watch; original configuration retained.', 503)
            return remaining

    def edit_directory(self, previous_path, path):
        with self._directory_lock:
            previous_path = self._directory_path(previous_path, must_exist=False)
            path = self._directory_path(path)
            dirs = list(self.config.get('monitored_directories', []))
            index = next((i for i, d in enumerate(dirs) if self._directory_key(d) == self._directory_key(previous_path)), None)
            if index is None:
                raise DirectoryError('Original monitored folder no longer exists in configuration.', 409)
            if self._directory_key(path) == self._directory_key(previous_path):
                return dirs
            if any(self._directory_key(d) == self._directory_key(path) for d in dirs):
                raise DirectoryError('Replacement folder is already monitored.', 409)
            if not self.files.running:
                raise DirectoryError('Start file monitoring before editing so the replacement can be watched first.', 409)
            self._watch_replacement(path)
            replacement = list(dirs); replacement[index] = path
            try:
                self._save_directories(replacement)
            except DirectoryError:
                self.files.remove_watch(path)
                raise
            if not self.usb.volume_for(previous_path):
                if self.files.remove_watch(previous_path) is False:
                    self._save_directories(dirs)
                    self.files.remove_watch(path)
                    raise DirectoryError('Could not stop the old folder watch; original configuration retained.', 503)
            return replacement

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
