"""Mount the network API inside the shared ExfilTrace Flask app.

The shared app owns the USB/file monitoring lifecycle.  This module only
prepares the network database and registers the existing network blueprint, so
the standalone ``backend.network.app`` remains independent.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from flask import Flask

from . import config, db

log = logging.getLogger(__name__)


def initialize_database(db_path: Optional[str] = None) -> str:
    """Create the network database directory/schema and return the path used."""
    path = Path(db_path or config.get_db_path()).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = db.get_connection(str(path))
    try:
        db.init_db(conn)
    finally:
        conn.close()
    return str(path)


def register_network(app: Flask, db_path: Optional[str] = None) -> bool:
    """Register ``/api/network/*`` without taking over the shared app.

    Returns ``False`` after logging an initialization/import failure so the
    combined launcher can continue with USB and file monitoring available.
    """
    try:
        path = initialize_database(db_path)
        if db_path:
            os.environ["EXFILTRACE_NETWORK_DB"] = path
        from .api import network_bp

        if "network" not in app.blueprints:
            app.register_blueprint(network_bp, url_prefix="/api")
        log.info("Network routes mounted with database %s", path)
        return True
    except Exception:
        log.exception("Network endpoints unavailable; continuing without them")
        return False
