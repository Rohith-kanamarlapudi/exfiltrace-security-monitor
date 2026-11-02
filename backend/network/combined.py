"""Run USB/file monitoring and the network endpoints in one Flask process.

Usage (from the repository root)::

    python -m backend.network.simulate_exfil          # writes <tempdir>/exfil_demo.db
    EXFILTRACE_NETWORK_DB="$(python3 -c 'import tempfile,pathlib; print(pathlib.Path(tempfile.gettempdir()) / "exfil_demo.db")')" \
        python -m backend.network.combined --config backend/config.json \
        --host 127.0.0.1 --port 5001

Optional live capture (off by default)::

    python -m backend.network.combined --config backend/config.json \
        --host 127.0.0.1 --port 5001 --live-capture \
        --interface Wi-Fi --capture-seconds 120

The interface is auto-detected unless ``--interface`` (a TShark index, device
name or friendly name such as ``Wi-Fi``) is supplied.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Optional

from backend.app.api import create_app
from backend.app.config import Config, ConfigError
from backend.app.service import MonitoringService

from . import capture as network_capture
from . import config, platform_support

log = logging.getLogger("exfiltrace.combined")


def default_live_db() -> str:
    """Live database default, resolved through ``tempfile.gettempdir()``."""
    return str(config.default_live_db())


def default_demo_db() -> str:
    """Demo database default, resolved through ``tempfile.gettempdir()``."""
    return str(config.default_demo_db())


class LiveConfigError(ValueError):
    """Invalid live-capture configuration supplied on the command line."""


def _same_path(left: Path | str, right: Path | str) -> bool:
    """Compare paths with the host platform's case/slash rules."""
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def resolve_live_db(path: str) -> str:
    """Resolve a live database path and refuse the demo database.

    Both sides are resolved to absolute paths first so ``..`` segments, symlinks
    and platform-specific temp directories compare correctly.  A file with the
    demo database's name is refused too, which protects demo DBs created by
    older versions that used a different temp directory.
    """
    resolved = Path(path).expanduser().resolve()
    demo = Path(default_demo_db()).expanduser().resolve()
    if _same_path(resolved, demo) or _same_path(resolved.name, demo.name):
        raise LiveConfigError(
            f"--live-db must not be the demo database ({demo}); "
            "live capture never overwrites demo data."
        )
    return str(resolved)


def start_live_capture(args: argparse.Namespace, live_db: str, port: int) -> Optional[threading.Timer]:
    """Start capture and return its timeout timer, or ``None`` on failure.

    Startup failures are deliberately contained here so Flask can continue
    serving the shared USB/file routes even when capture is unavailable.
    """
    try:
        tshark_path = platform_support.find_tshark(getattr(args, "tshark_path", None))
        selector = args.interface or config.CAPTURE_INTERFACE
        if selector:
            interface = network_capture.validate_capture_interface(selector, tshark_path)
        else:
            interface = network_capture.detect_capture_interface(tshark_path)
        local_ip = network_capture.discover_local_ip(interface)
        if not local_ip:
            log.warning(
                "Could not determine the local IP for %s; using private-range direction fallback",
                interface,
            )
        network_capture.start_capture(
            session_label="live",
            mode="live",
            interface=interface,
            db_path=live_db,
            local_ip=local_ip,
            promiscuous=args.promiscuous,
            ignored_ports=(port, 5001, 5173),
            tshark_path=tshark_path,
        )
        timer = None
        if args.capture_seconds:
            def stop_after_timeout() -> None:
                log.info("Capture duration elapsed; stopping live capture")
                try:
                    network_capture.stop_capture()
                except Exception:
                    log.exception("Error stopping live capture after timeout")

            timer = threading.Timer(args.capture_seconds, stop_after_timeout)
            timer.daemon = True
            timer.start()
        log.info(
            "Live capture started on %s using %s (database %s)",
            interface,
            tshark_path,
            live_db,
        )
        return timer
    except Exception:
        log.exception("Live capture unavailable; continuing with USB/file endpoints")
        return None


def _install_shutdown_handler() -> None:
    """Translate SIGTERM into KeyboardInterrupt where the platform supports it.

    Flask already turns SIGINT/Ctrl+C into KeyboardInterrupt on every platform.
    Windows has no SIGTERM equivalent, so only the POSIX path is registered.
    """
    if sys.platform == "win32" or not hasattr(signal, "SIGTERM"):
        return

    def _raise_keyboard_interrupt(_signum, _frame):
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)
    except (OSError, ValueError):  # pragma: no cover - non-main thread/unsupported
        log.debug("could not install SIGTERM handler", exc_info=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="ExfilTrace combined backend (USB/file + network)")
    parser.add_argument("--config", help="path to the shared config.json")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--network-db", help="network SQLite path (overrides EXFILTRACE_NETWORK_DB)")
    parser.add_argument("--live-capture", action="store_true", help="enable opt-in PyShark/TShark live capture")
    parser.add_argument(
        "--interface",
        default=None,
        help="capture interface: TShark index, device name or friendly name (default: auto-detect)",
    )
    parser.add_argument(
        "--tshark-path",
        default=None,
        help="path to the tshark executable or install directory (or set EXFILTRACE_TSHARK_PATH)",
    )
    parser.add_argument(
        "--live-db",
        default=default_live_db(),
        help=f"live capture SQLite path (default: {default_live_db()})",
    )
    parser.add_argument("--capture-seconds", type=float, help="stop live capture after this many seconds (default: unlimited)")
    parser.add_argument("--promiscuous", action="store_true", help="put the capture interface in promiscuous mode (opt-in)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    if args.capture_seconds is not None and args.capture_seconds <= 0:
        parser.error("--capture-seconds must be a positive number")

    live_db = None
    if args.live_capture:
        try:
            live_db = resolve_live_db(args.live_db)
            network_db = Path(args.network_db).expanduser().resolve() if args.network_db else None
            if network_db is not None and not _same_path(network_db, live_db):
                raise LiveConfigError("--network-db and --live-db must match in --live-capture mode")
        except LiveConfigError as exc:
            raise SystemExit(f"Live capture configuration error: {exc}")

    try:
        config = Config.load(args.config)
    except ConfigError as exc:
        raise SystemExit(f"Configuration error: {exc}")
    service = MonitoringService(config)
    app = create_app(service=service, autostart=False)

    try:
        from .integration import register_network
    except Exception:
        log.exception("Network module could not be imported; continuing without it")
        network_ready = False
    else:
        network_ready = register_network(app, live_db or args.network_db)

    service.start()
    host = args.host or config["api"]["host"]
    port = args.port or config["api"]["port"]

    _install_shutdown_handler()
    capture_timer = None
    if args.live_capture:
        if not network_ready:
            log.error("Network routes are unavailable; live capture was not started")
        else:
            capture_timer = start_live_capture(args, live_db, port)

    try:
        app.run(host=host, port=port, threaded=True, use_reloader=False)
    finally:
        if capture_timer is not None:
            capture_timer.cancel()
        try:
            network_capture.stop_capture()
        except Exception:
            log.exception("Error stopping live capture")
        service.stop()


if __name__ == "__main__":
    main()
