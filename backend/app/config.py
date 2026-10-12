"""Configuration loading. Values come from config.json; anything missing falls back to DEFAULTS."""
import copy
import json
import os
import threading

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # backend/
DEFAULT_CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

DEFAULTS = {
    "monitored_directories": [],
    "database_path": "data/exfiltrace.db",
    # Built-in rules apply even when config.json omits them (a partial config must not disable detection).
    "sensitive_rules": {
        "extensions": [".kdbx", ".pem", ".key", ".pfx", ".p12", ".sql", ".bak", ".env"],
        "filename_keywords": ["confidential", "password", "passwords", "credential", "secret", "employee",
                              "salary", "payroll", "private", "project_data"],
        "directories": ["confidential", "hr", "finance", "secrets"],
    },
    "exclusions": {
        "patterns": ["*.tmp", "*.swp", "~$*", "*.crdownload", "Thumbs.db", "desktop.ini",
                     "*.db-journal", "*.db-wal", "*.db-shm"],
        "directories": [".git", "node_modules", "__pycache__", "System Volume Information", "$RECYCLE.BIN"],
    },
    "dedupe_window_seconds": 1.5,
    "usb": {"backend": "auto", "poll_interval_seconds": 3, "simulated_file": "data/simulated_usb.json", "simulation_enabled": False},
    "detection": {
        "correlation_window_seconds": 600,
        "bulk_file_threshold": 10,
        "bulk_window_seconds": 120,
        "archive_extensions": [".zip", ".7z", ".rar", ".tar", ".gz"],
        "max_hash_bytes": 268435456,
    },
    "api": {"host": "127.0.0.1", "port": 5000},
}


class ConfigError(Exception):
    pass


def _merge(base, override):
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


class Config:
    """Thread-safe config wrapper. `data` is the merged dict."""

    def __init__(self, data=None, path=None):
        self.path = path
        self.data = _merge(copy.deepcopy(DEFAULTS), data or {})
        self._lock = threading.Lock()

    @classmethod
    def load(cls, path=None):
        path = path or os.environ.get("EXFILTRACE_CONFIG") or DEFAULT_CONFIG_PATH
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except FileNotFoundError:
            raw = {}
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"Cannot read config file {path}: {exc}") from exc
        if os.environ.get('EXFILTRACE_USB_SIMULATION') == '1':
            raw.setdefault('usb', {})['simulation_enabled'] = True
        return cls(raw, path=path)

    def resolve_path(self, value):
        """Relative paths in the config are relative to the backend folder."""
        return value if os.path.isabs(value) else os.path.join(BASE_DIR, value)

    @property
    def database_path(self):
        return self.resolve_path(self.data["database_path"])

    def __getitem__(self, key):
        return self.data[key]

    def get(self, key, default=None):
        return self.data.get(key, default)

    # --- monitored directory management (persisted to the config file) ---
    def set_directories(self, dirs):
        with self._lock:
            self.data["monitored_directories"] = list(dirs)
            self._save()

    def _save(self):
        if not self.path:
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                on_disk = json.load(fh)
        except (OSError, json.JSONDecodeError):
            on_disk = {}
        on_disk["monitored_directories"] = self.data["monitored_directories"]
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(on_disk, fh, indent=2)
        os.replace(tmp, self.path)

    def public_dict(self):
        d = copy.deepcopy(self.data)
        d["database_path"] = self.database_path
        return d
