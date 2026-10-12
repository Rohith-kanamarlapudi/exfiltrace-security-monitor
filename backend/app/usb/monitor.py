"""Polls a UsbBackend and turns snapshot differences into insert / remove / mount-change events."""
import logging
import threading

from .base import UsbBackendError

log = logging.getLogger("exfiltrace.usb")


class UsbMonitor:
    def __init__(self, backend, interval=3.0, on_insert=None, on_remove=None, on_mounts_changed=None, history=None):
        self.backend = backend
        self.history = history
        self.interval = interval
        self.on_insert = on_insert or (lambda d, pre: None)
        self.on_remove = on_remove or (lambda d: None)
        self.on_mounts_changed = on_mounts_changed or (lambda d, old, new: None)
        self.current = {}               # device_id -> device dict
        self.last_error = None
        self.polls = 0
        self.running = False
        self._first = True
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.RLock()

    # ---- state access ----
    def devices(self):
        with self._lock:
            return list(self.current.values())

    def volume_for(self, path):
        """(mount, device) when `path` is on a mounted USB volume, else None."""
        import os
        target = os.path.normcase(os.path.abspath(path))
        with self._lock:
            for dev in self.current.values():
                for mount in dev["mounts"]:
                    m = os.path.normcase(os.path.abspath(mount))
                    if target == m or target.startswith(m.rstrip(os.sep) + os.sep):
                        return mount, dev
        return None

    # ---- polling ----
    def poll_once(self):
        """One diff cycle. Safe to call directly (used by tests)."""
        try:
            snapshot = {d["device_id"]: d for d in self.backend.snapshot()}
            complete = getattr(self.backend, 'snapshot_complete', True)
            self.last_error = None if complete else 'Partial USB inspection; removals and fingerprint comparisons deferred'
        except UsbBackendError as exc:
            self.last_error = str(exc)
            log.warning("USB poll failed: %s", exc)
            return
        except Exception as exc:  # never let a backend bug kill monitoring
            self.last_error = f"Unexpected USB backend error: {exc}"
            log.exception("USB backend crashed")
            return

        self.polls += 1
        with self._lock:
            old = self.current
            if not complete:
                # Unknown ancestry can split a formerly grouped storage device. Do
                # not publish that as a new physical device or tear down watches.
                for key, dev in list(snapshot.items()):
                    if key not in old and any(key in d.get('inspection', {}).get('storageDeviceIds', []) for d in old.values()):
                        del snapshot[key]
                snapshot = {**old, **snapshot}
            for dev in snapshot.values():
                dev.setdefault('observationSource', self.backend.name)
                if self.history and (complete or dev is not old.get(dev['device_id'])):
                    try:
                        self.history.observe(dev)
                    except Exception as exc:
                        self.last_error = f'USB observation persistence failed: {exc}'
                        log.exception('USB observation persistence failed; retaining previous state')
                        return
            self.current = snapshot
            first = self._first
            self._first = False

        for dev_id, dev in snapshot.items():
            if dev_id not in old:
                self._safe(self.on_insert, dev, first)   # first poll => already plugged in at startup
            elif sorted(old[dev_id]["mounts"]) != sorted(dev["mounts"]):
                self._safe(self.on_mounts_changed, dev, old[dev_id]["mounts"], dev["mounts"])
        for dev_id, dev in old.items():
            if dev_id not in snapshot:
                self._safe(self.on_remove, dev)

    @staticmethod
    def _safe(fn, *args):
        try:
            fn(*args)
        except Exception:
            log.exception("USB event handler failed")

    # ---- lifecycle ----
    def start(self):
        if self.running:
            return
        self._stop.clear()
        self.running = True
        self.poll_once()   # synchronous first poll so pre-attached devices are known immediately
        self._thread = threading.Thread(target=self._loop, name="usb-monitor", daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.wait(self.interval):
            self.poll_once()

    def stop(self):
        self._stop.set()
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
