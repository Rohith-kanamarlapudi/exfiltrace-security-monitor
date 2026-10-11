"""Runnable Flask app for the network module.

Run (from the repository root)::

    python -m backend.network.app

Listens on ``http://localhost:5000`` by default and serves ``/api/network/*``.
CORS is enabled so the Vite dev server (http://localhost:5173) can call it.
"""

from __future__ import annotations

import logging

from flask import Flask

from . import config, db
from .api import network_bp

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _enable_cors(app: Flask) -> None:
    """Use flask-cors when available, otherwise add permissive headers manually."""
    try:
        from flask_cors import CORS  # type: ignore

        CORS(app, resources={r"/api/*": {"origins": "*"}})
        return
    except Exception:
        @app.after_request
        def _add_cors_headers(response):  # pragma: no cover - trivial
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
            return response


def create_app() -> Flask:
    """Application factory: init DB, register the blueprint, enable CORS."""
    app = Flask(__name__)
    db.init_db(db.get_connection())
    app.register_blueprint(network_bp, url_prefix="/api")
    _enable_cors(app)

    @app.get("/api/health")
    def health():
        from .capture import get_capture_status

        return {"status": "ok", "capture": get_capture_status()}

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host=config.API_HOST, port=config.API_PORT, debug=False)
