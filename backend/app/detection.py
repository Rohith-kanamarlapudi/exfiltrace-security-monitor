"""USB data-theft detection: correlates file events with USB devices and raises alerts.

Verdicts
--------
SUSPICIOUS         Activity that matches a risky pattern but does not prove a transfer.
VERIFIED_TRANSFER  A file created on a USB volume is byte-identical (SHA-256) to a monitored
                   file. This proves a COPY exists on the device. It does not prove who made
                   it, that it was unauthorised, or that data left the device afterwards.

Plain "a USB device was connected" is never an alert by itself.
"""
import hashlib
import logging
import os
import time
import threading
from datetime import datetime, timedelta, timezone

from .file_monitor import CREATED, DELETED, MODIFIED, RENAMED, FileClassifier

log = logging.getLogger("exfiltrace.detection")

SUSPICIOUS, VERIFIED = "SUSPICIOUS", "VERIFIED_TRANSFER"
MAX_WALK_ENTRIES = 50000


def sha256_of(path, max_bytes):
    """Hex digest, or None when the file is too large / unreadable."""
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


class DetectionEngine:
    def __init__(self, config, db, usb_state):
        """usb_state needs: devices() and volume_for(path), as provided by UsbMonitor."""
        self.config, self.db, self.usb = config, db, usb_state
        self.cfg = config["detection"]
        self.classifier = FileClassifier(config)
        self._transfer_lock = threading.RLock()
        self._hash_cache = {}
        self._verified_events = set()

    # ------------------------------------------------------------ entry points
    def on_file_event(self, fe):
        """Returns the list of alerts newly created for this event."""
        alerts = []
        try:
            eff = fe["dest_path"] or fe["path"]
            if fe["on_removable"]:
                if fe["event_type"] in (CREATED, RENAMED, MODIFIED):
                    with self._transfer_lock:
                        alerts += self._removable_write(fe, eff)
                if fe["event_type"] in (CREATED, RENAMED):
                    if fe['id'] not in self._verified_events:
                        alerts += self._bulk_copy(fe)
                        alerts += self._archive(fe, eff)
            elif fe["sensitive"]:
                if fe["event_type"] == DELETED:
                    alerts += self._moved_to_usb(fe)
                alerts += self._coincident(fe)
        except Exception:
            log.exception("Detection failed for file event %s", fe.get("id"))
        return [a for a in alerts if a]

    # ------------------------------------------------------------ helpers
    def _device(self, fe):
        dev_id = fe.get("usb_device_id")
        dev = next((d for d in self.usb.devices() if d["device_id"] == dev_id), None)
        insert = self.db.last_insert_event(dev_id, at_time=fe.get('timestamp')) if dev_id else None
        return dev, insert

    @staticmethod
    def _dev_text(dev, fallback_name=None):
        if not dev:
            return fallback_name or "unknown USB device"
        ids = f"VID {dev['vendor_id'] or '?'} / PID {dev['product_id'] or '?'}"
        serial = dev["serial_number"] or "no serial"
        return f"{dev['name']} ({ids}, serial {serial})"

    def _since(self, seconds):
        return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat(timespec="milliseconds").replace('+00:00', 'Z')

    def _alert(self, rule, severity, verdict, title, explanation, evidence, file_ids, usb_ids, key):
        return self.db.add_alert(rule=rule, severity=severity, verdict=verdict, title=title,
                                 explanation=explanation, evidence=evidence,
                                 file_event_ids=file_ids, usb_event_ids=usb_ids, dedupe_key=key)

    def _wait_stable(self, path):
        """Wait until a file being copied stops growing (so we hash the complete file)."""
        interval = float(self.cfg.get("stable_check_interval_seconds", 0.5))
        last = -1
        for _ in range(20):
            try:
                size = os.path.getsize(path)
            except OSError:
                return None
            if size == last:
                return size
            last = size
            time.sleep(interval)
        return last

    def _find_sources(self, file_name, dest_path):
        """Search eligible monitored sources by size/content, prioritizing matching names."""
        found, seen = [], set()
        size = os.path.getsize(dest_path)
        roots = [os.path.normcase(os.path.realpath(p)) for p in self.config.get('monitored_directories', [])]

        def add(path):
            key = os.path.normcase(os.path.realpath(path))
            if key in seen or key == os.path.normcase(os.path.realpath(dest_path)) or self.usb.volume_for(path):
                return
            if self.classifier.is_excluded(path) or not any(key.startswith(root.rstrip(os.sep) + os.sep) for root in roots):
                return
            try:
                if os.path.isfile(path) and (os.path.getsize(path) == size or os.path.basename(path).lower() == file_name.lower()):
                    seen.add(key)
                    found.append(path)
            except OSError:
                return  # a source can disappear during enumeration

        for ev in reversed(self.db.recent_file_events(self._since(self.cfg['correlation_window_seconds']))):
            if not ev['on_removable']:
                add(ev['dest_path'] or ev['path'])
        scanned = 0
        for root_dir in self.config.get('monitored_directories', []):
            for root, dirs, files in os.walk(root_dir):
                dirs[:] = [d for d in dirs if d.lower() not in self.classifier.excluded_dirs]
                for name in files:
                    scanned += 1
                    if scanned > MAX_WALK_ENTRIES:
                        break
                    add(os.path.join(root, name))
                if scanned > MAX_WALK_ENTRIES:
                    break
            if scanned > MAX_WALK_ENTRIES:
                break
        return sorted(found, key=lambda p: (os.path.basename(p).lower() != file_name.lower(), p))

    def _source_hash(self, path, max_bytes):
        try:
            stat = os.stat(path)
            key = (os.path.normcase(os.path.abspath(path)), stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
        except OSError:
            return None
        if key not in self._hash_cache:
            if len(self._hash_cache) > 5000:
                self._hash_cache.clear()
            self._hash_cache[key] = sha256_of(path, max_bytes)
        return self._hash_cache[key]

    # ------------------------------------------------------------ rules
    def _removable_write(self, fe, eff):
        """Rule 1: file appears on a USB volume. Verified when hash-identical to a monitored file."""
        if not os.path.isfile(eff):
            return []
        dest_size = self._wait_stable(eff)
        if dest_size is None:
            return []
        dev, insert = self._device(fe)
        usb_ids = [insert["id"]] if insert else []
        max_bytes = int(self.cfg["max_hash_bytes"])
        dest_hash = sha256_of(eff, max_bytes)
        dest_sensitive, dest_reason = self.classifier.classify(eff)

        sources = self._find_sources(fe["file_name"], eff)
        verified = unverified = None
        for src in sources:
            src_hash = self._source_hash(src, max_bytes)
            if dest_hash and src_hash and dest_hash == src_hash:
                verified = (src, src_hash)
                break
            if os.path.basename(src).lower() == fe['file_name'].lower():
                unverified = unverified or src

        base_evidence = [
            f"USB device: {self._dev_text(dev)}",
            f"Mounted at: {fe['volume']}" + (f" (inserted {insert['timestamp']})" if insert else ""),
            f"File created on removable volume: {eff} ({dest_size} bytes) at {fe['timestamp']}",
        ]
        if dest_sensitive:
            base_evidence.append(f"Sensitive rule matched on the USB copy: {dest_reason}")

        if verified:
            src, digest = verified
            if len(self._verified_events) > 5000:
                self._verified_events.clear()
            self._verified_events.add(fe['id'])
            src_sensitive, src_reason = self.classifier.classify(src)
            created, transfers = self.db.record_usb_transfer(fe, src, digest, dest_size, insert['id'] if insert else 0,
                int(self.cfg['usb_transfer_window_seconds']))
            if not created:
                return []
            count = len({t['destination_key'] for t in transfers})
            total_bytes = sum(t['size_bytes'] for t in transfers)
            critical = count > int(self.cfg['usb_transfer_file_limit']) or total_bytes > int(self.cfg['usb_transfer_size_limit_bytes'])
            severity = 'CRITICAL' if critical else 'MEDIUM'
            evidence = base_evidence + [
                f'Identical file in monitored location: {src}', f'SHA-256 (source and USB copy): {digest}',
                f"Transfer window: {count} distinct files, {total_bytes} bytes in {self.cfg['usb_transfer_window_seconds']}s",
                f"Critical only above {self.cfg['usb_transfer_file_limit']} files or {self.cfg['usb_transfer_size_limit_bytes']} bytes",
            ] + ([f'Sensitive rule matched on source: {src_reason}'] if src_sensitive else [])
            return [self._alert(
                'MONITORED_FILE_COPIED_TO_USB', severity, VERIFIED,
                f"Monitored file copied to USB: {fe['file_name']}",
                f"'{fe['file_name']}' was created on removable volume {fe['volume']} while monitoring was active, "
                f'and its SHA-256 hash is identical to the file at {src}. This verifies that a copy of the monitored '
                'file now exists on the USB device. It does not show who made the copy, whether it was authorised, '
                f'or that the data left the device afterwards. The {count}-file, {total_bytes}-byte transfer window determines severity.',
                evidence, [fe['id']], usb_ids, f"transfer-event:{fe['id']}")]

        if unverified:
            if dest_hash is None:
                note = "Content could not be compared (file too large or unreadable)."
            else:
                note = "Content differs from the same-named file (may be an edited copy, or an unrelated file)."
            return [self._alert(
                "MONITORED_NAME_MATCH_ON_USB", "CRITICAL" if dest_size > int(self.cfg["usb_transfer_size_limit_bytes"]) else "MEDIUM", SUSPICIOUS,
                f"Possible monitored file copy to USB: {fe['file_name']}",
                f"A file named '{fe['file_name']}' appeared on removable volume {fe['volume']} and a file with the same "
                f"name exists in a monitored location ({unverified}). {note} This is suspicious but NOT a verified transfer.",
                base_evidence + [f"Same-named file in monitored location: {unverified}", note],
                [fe["id"]], usb_ids, f"namematch:{os.path.normcase(eff)}")]

        if dest_sensitive:
            return [self._alert(
                "SENSITIVE_FILE_ON_USB", "MEDIUM", SUSPICIOUS,
                f"Sensitive-looking file written to USB: {fe['file_name']}",
                f"A file matching a sensitive-file rule ({dest_reason}) was created on removable volume {fe['volume']}. "
                "No matching source file could be found in the monitored locations, so the origin is unknown and "
                "no transfer is verified.",
                base_evidence + ["No same-named source file found in monitored directories or recent events"],
                [fe["id"]], usb_ids, f"sensitiveusb:{os.path.normcase(eff)}")]
        return []

    def _bulk_copy(self, fe):
        """Rule 2: many files written to a USB volume in a short time."""
        window = int(self.cfg['usb_transfer_window_seconds'])
        threshold = int(self.cfg["usb_transfer_file_limit"]) + 1
        dev, insert = self._device(fe)
        events = [e for e in self.db.recent_file_events(self._since(window))
                  if e["on_removable"] and e["usb_device_id"] == fe["usb_device_id"]
                  and e["event_type"] in (CREATED, RENAMED)]
        if insert:
            connected = datetime.fromisoformat(insert['timestamp'].replace('Z', '+00:00'))
            events = [e for e in events if datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) >= connected]
        events = list({os.path.normcase(e['dest_path'] or e['path']): e for e in events}.values())
        total_bytes = sum(e['size_bytes'] or 0 for e in events)
        if len(events) < threshold and total_bytes <= int(self.cfg['usb_transfer_size_limit_bytes']):
            return []
        sensitive_count = sum(1 for e in events if e["sensitive"])
        key = f"bulk:{fe['usb_device_id']}:{insert['id'] if insert else 0}"
        return [self._alert(
            "BULK_COPY_TO_USB", "CRITICAL", SUSPICIOUS,
            f"Bulk file copy to USB ({len(events)} files in {window}s)",
            f"{len(events)} files were created on {fe['volume']} within {window} seconds "
            f"({sensitive_count} matched sensitive-file rules). Bulk copying is a common data-theft pattern but can also be "
            "a legitimate backup, so this is suspicious, not verified.",
            [f"USB device: {self._dev_text(dev)}", f"Files created on volume: {len(events)} (threshold {threshold})",
             f"Sensitive files among them: {sensitive_count}",
             "Examples: " + ", ".join(e["file_name"] for e in events[:5])],
            [e["id"] for e in events][:50], [insert["id"]] if insert else [], key)]

    def _archive(self, fe, eff):
        """Rule 3: an archive (zip/7z/...) created on the USB volume can hide many files."""
        ext = os.path.splitext(eff)[1].lower()
        if ext not in {e.lower() for e in self.cfg["archive_extensions"]}:
            return []
        dev, insert = self._device(fe)
        return [self._alert(
            "ARCHIVE_ON_USB", "MEDIUM", SUSPICIOUS, f"Archive created on USB: {fe['file_name']}",
            f"An archive ({ext}) was created on removable volume {fe['volume']}. Archives can bundle many files, and "
            "their contents are not inspected by this monitor, so the content is unverified.",
            [f"USB device: {self._dev_text(dev)}", f"Archive: {eff}", f"Created at: {fe['timestamp']}"],
            [fe["id"]], [insert["id"]] if insert else [], f"archive:{os.path.normcase(eff)}")]

    def _moved_to_usb(self, fe):
        """Rule 4: sensitive file deleted from a monitored dir shortly after a same-named file appeared on USB."""
        recent = self.db.recent_file_events(self._since(int(self.cfg["correlation_window_seconds"])))
        match = next((e for e in reversed(recent)
                      if e["on_removable"] and e["event_type"] in (CREATED, RENAMED)
                      and e["file_name"].lower() == fe["file_name"].lower()), None)
        if not match:
            return []
        dev, insert = self._device(match)
        return [self._alert(
            "SENSITIVE_FILE_MOVED_TO_USB", "HIGH", SUSPICIOUS,
            f"Sensitive file possibly moved to USB: {fe['file_name']}",
            f"'{fe['file_name']}' was deleted from {fe['path']} after a file with the same name was created on "
            f"{match['volume']}. This is consistent with moving the file to the USB device (cut and paste), but the "
            "deleted original can no longer be compared, so the transfer is unverified.",
            [f"USB device: {self._dev_text(dev)}",
             f"Created on USB: {match['dest_path'] or match['path']} at {match['timestamp']}",
             f"Deleted from: {fe['path']} at {fe['timestamp']}",
             f"Sensitive rule: {fe['sensitivity_reason']}"],
            [match["id"], fe["id"]], [insert["id"]] if insert else [],
            f"moved:{os.path.normcase(fe['path'])}:{match['id']}")]

    def _coincident(self, fe):
        """Rule 5: sensitive file activity while a USB storage device is connected (weak signal)."""
        devices = [d for d in self.usb.devices() if d["mounts"]]
        if not devices:
            return []
        out = []
        verb = {"CREATED": "created", "MODIFIED": "modified", "DELETED": "deleted", "RENAMED": "renamed"}[fe["event_type"]]
        for dev in devices:
            insert = self.db.last_insert_event(dev["device_id"])
            out.append(self._alert(
                "SENSITIVE_ACTIVITY_DURING_USB", "MEDIUM" if fe["event_type"] == DELETED else "LOW", SUSPICIOUS,
                f"Sensitive file {verb} while USB connected: {fe['file_name']}",
                f"Sensitive file '{fe['file_name']}' was {verb} while USB storage device '{dev['name']}' was connected. "
                "The two overlap in time, but no file was seen on the device, so this is NOT evidence of a transfer.",
                [f"USB device: {self._dev_text(dev)}", f"Mounted at: {', '.join(dev['mounts'])}",
                 f"Sensitive file event: {fe['event_type']} {fe['path']} at {fe['timestamp']}",
                 f"Sensitive rule: {fe['sensitivity_reason']}"],
                [fe["id"]], [insert["id"]] if insert else [],
                f"coincident:{dev['device_id']}:{insert['id'] if insert else 0}:{os.path.normcase(fe['path'])}"))
        return out
