"""File-system monitoring built on watchdog.

Detects creation, modification, deletion and rename, applies sensitive-file rules and
exclusions, drops duplicate events, and stores each event through the Database.
"""
import fnmatch
import logging
import os
import threading
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

log = logging.getLogger("exfiltrace.files")

CREATED, MODIFIED, DELETED, RENAMED = "CREATED", "MODIFIED", "DELETED", "RENAMED"


class FileClassifier:
    """Sensitive-file rules and exclusions, both driven by config."""

    def __init__(self, config):
        rules = config["sensitive_rules"]
        self.extensions = {e.lower() for e in rules.get("extensions", [])}
        self.keywords = [k.lower() for k in rules.get("filename_keywords", [])]
        self.directories = {d.lower() for d in rules.get("directories", [])}
        ex = config["exclusions"]
        self.patterns = [p.lower() for p in ex.get("patterns", [])]
        self.excluded_dirs = {d.lower() for d in ex.get("directories", [])}

    def is_excluded(self, path):
        parts = [p.lower() for p in os.path.normpath(path).split(os.sep) if p]
        if any(p in self.excluded_dirs for p in parts[:-1]):
            return True
        name = os.path.basename(path).lower()
        return any(fnmatch.fnmatch(name, pat) for pat in self.patterns)

    def classify(self, path):
        """Returns (is_sensitive, reason or None)."""
        name = os.path.basename(path).lower()
        stem, ext = os.path.splitext(name)
        if ext in self.extensions:
            return True, f"Sensitive file type ({ext})"
        for kw in self.keywords:
            if kw in stem:
                return True, f"File name contains '{kw}'"
        parts = [p.lower() for p in os.path.normpath(path).split(os.sep) if p][:-1]
        for p in parts:
            if p in self.directories:
                return True, f"Located in sensitive directory '{p}'"
        return False, None


def compute_risk(sensitive, on_removable, event_type):
    if sensitive and on_removable:
        return "HIGH"
    if sensitive or on_removable:
        return "MEDIUM"
    return "LOW"


class FileMonitor:
    def __init__(self, config, db, volume_resolver=None, on_event=None):
        """
        volume_resolver(path) -> (mount, device_dict) | None   (supplied by the USB layer)
        on_event(event_dict)                                   (called after each stored event)
        """
        self.config = config
        self.db = db
        self.classifier = FileClassifier(config)
        self.volume_resolver = volume_resolver or (lambda p: None)
        self.on_event = on_event or (lambda e: None)
        self.window = float(config.get("dedupe_window_seconds", 1.5))
        self._observer = None
        self._watches = {}          # normalized path -> {"path", "removable", "watch", "error"}
        self._seen = {}             # dedupe key -> monotonic time
        self._created_ids = {}      # path -> (stored CREATED event id, monotonic time)
        # Lock rules (avoid deadlock with watchdog): watchdog's dispatch thread holds the observer's
        # internal lock while it calls our handler, so we must NEVER hold `_lock` while calling
        # observer.schedule/unschedule/start/stop, and event handling only ever takes `_dedupe_lock`.
        self._lock = threading.RLock()          # guards _watches / _observer / running
        self._dedupe_lock = threading.Lock()    # guards _seen
        self._db_path = os.path.abspath(config.database_path) if hasattr(config, "database_path") else None
        self.errors = []
        self.running = False

    # ---------------- lifecycle ----------------
    def start(self):
        with self._lock:
            if self.running:
                return
            self._observer = Observer()
            self.running = True
            observer = self._observer
        observer.start()
        for d in self.config.get("monitored_directories", []):
            self.add_watch(d)
        log.info("File monitor started with %d watch(es)", len(self._watches))

    def stop(self):
        with self._lock:
            observer, self._observer = self._observer, None
            self.running = False
            self._watches.clear()
        if observer is not None:
            try:
                observer.stop()
                observer.join(timeout=5)
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("Error stopping observer: %s", exc)
        log.info("File monitor stopped")

    # ---------------- watch management ----------------
    def add_watch(self, path, removable=False):
        key = os.path.normcase(os.path.abspath(path))
        with self._lock:
            existing = self._watches.get(key)
            if existing and existing.get("watch"):
                return True
            entry = {"path": path, "removable": removable, "watch": None, "error": None}
            self._watches[key] = entry
            observer = self._observer
        if not observer:
            entry["error"] = "Monitor not running"
            return False
        if not os.path.isdir(path):
            entry["error"] = "Directory does not exist"
            self._note_error(f"Cannot watch '{path}': directory does not exist")
            return False
        try:
            watch = observer.schedule(_Handler(self, path), path, recursive=True)   # outside our lock
        except Exception as exc:
            entry["error"] = str(exc)
            self._note_error(f"Cannot watch '{path}': {exc}")
            return False
        with self._lock:
            entry["watch"] = watch
        return True

    def remove_watch(self, path):
        key = os.path.normcase(os.path.abspath(path))
        with self._lock:
            entry = self._watches.get(key)
            observer = self._observer
        if entry and entry.get("watch") and observer:
            try:
                observer.unschedule(entry["watch"])                                  # outside our lock
            except Exception as exc:
                entry['error'] = f'Could not stop watch: {exc}'
                log.warning("Could not unschedule %s: %s", path, exc)
                return False
        with self._lock:
            if self._watches.get(key) is entry:
                self._watches.pop(key, None)
        return True

    def watches(self):
        with self._lock:
            return [{"path": e["path"], "removable": e["removable"],
                     "active": bool(e["watch"]), "error": e["error"]} for e in self._watches.values()]

    def _note_error(self, msg):
        log.warning(msg)
        self.errors.append(msg)
        del self.errors[:-20]

    # ---------------- event handling ----------------
    def _dedupe(self, event_type, path, dest):
        """None = new event, "duplicate" = same event repeated, "after_create" = MODIFY right after CREATE."""
        now = time.monotonic()
        with self._dedupe_lock:
            if len(self._seen) > 5000:
                self._seen = {k: t for k, t in self._seen.items() if now - t < self.window}
                self._created_ids = {k: v for k, v in self._created_ids.items() if now - v[1] < self.window}
            key = (event_type, path, dest)
            last = self._seen.get(key)
            self._seen[key] = now
            if last is not None and now - last < self.window:
                return "duplicate"
            # Windows/inotify report CREATE followed straight away by MODIFY for the same file.
            if event_type == MODIFIED:
                created = self._seen.get((CREATED, path, None))
                if created is not None and now - created < self.window:
                    return "after_create"
        return None

    def _refresh_created_size(self, path):
        with self._dedupe_lock:
            entry = self._created_ids.get(path)
        if entry:
            try:
                self.db.update_file_event_size(entry[0], os.path.getsize(path))
            except OSError:
                pass

    def handle(self, event_type, path, dest=None, watch_root=None):
        """Entry point for a raw file-system event. Returns the stored event or None."""
        try:
            if self._db_path and os.path.abspath(path).startswith(self._db_path):
                return None
            effective = dest or path
            if self.classifier.is_excluded(path) or (dest and self.classifier.is_excluded(dest)):
                return None
            dup = self._dedupe(event_type, path, dest)
            if dup == "after_create":
                self._refresh_created_size(path)   # the file was still being written at CREATE time
                return None
            if dup:
                return None

            sensitive, reason = self.classifier.classify(effective)
            if not sensitive and dest:  # renamed away from a sensitive name
                sensitive, reason = self.classifier.classify(path)
            volume = self.volume_resolver(effective)
            mount, device = (volume if volume else (None, None))
            size = None
            if event_type != DELETED:
                try:
                    size = os.path.getsize(effective)
                except OSError:
                    size = None
            ext = os.path.splitext(effective)[1].lower() or None
            stored = self.db.add_file_event(
                event_type=event_type,
                path=path,
                dest_path=dest,
                file_name=os.path.basename(effective),
                extension=ext,
                size_bytes=size,
                sensitive=1 if sensitive else 0,
                sensitivity_reason=reason,
                on_removable=1 if volume else 0,
                volume=mount,
                usb_device_id=device["device_id"] if device else None,
                risk=compute_risk(sensitive, bool(volume), event_type),
                details={"watch_root": watch_root, "source": "watchdog",
                         "device_name": device.get("name") if device else None},
            )
        except Exception as exc:
            self._note_error(f"Failed to record {event_type} {path}: {exc}")
            return None
        if event_type == CREATED:
            with self._dedupe_lock:
                self._created_ids[path] = (stored["id"], time.monotonic())
        try:
            self.on_event(stored)
        except Exception as exc:
            self._note_error(f"Event callback failed for {path}: {exc}")
        return stored


class _Handler(FileSystemEventHandler):
    def __init__(self, monitor, root):
        super().__init__()
        self.monitor, self.root = monitor, root

    def on_created(self, event):
        if not event.is_directory:
            self.monitor.handle(CREATED, event.src_path, watch_root=self.root)

    def on_modified(self, event):
        if not event.is_directory:
            self.monitor.handle(MODIFIED, event.src_path, watch_root=self.root)

    def on_deleted(self, event):
        if not event.is_directory:
            self.monitor.handle(DELETED, event.src_path, watch_root=self.root)

    def on_moved(self, event):
        if not event.is_directory:
            self.monitor.handle(RENAMED, event.src_path, dest=event.dest_path, watch_root=self.root)
