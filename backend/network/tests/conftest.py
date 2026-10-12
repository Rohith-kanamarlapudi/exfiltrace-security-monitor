"""Shared pytest fixtures.

Makes sure the repository root is importable (so ``backend.network`` resolves)
and gives each test an isolated SQLite database via the ``EXFILTRACE_NETWORK_DB``
environment variable.
"""

from __future__ import annotations

import os
import sys
import pathlib

import pytest

# repo root = .../exfiltrace-security-monitor  (tests -> network -> backend -> root)
REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    """Point the module at a throwaway SQLite file and yield its path."""
    path = tmp_path / "test_network.db"
    monkeypatch.setenv("EXFILTRACE_NETWORK_DB", str(path))
    # Keep detector thresholds predictable in tests.
    monkeypatch.setenv("EXFILTRACE_MIN_BASELINE", "5")
    return str(path)


@pytest.fixture()
def client(temp_db):
    """Flask test client wired to the isolated database."""
    from backend.network.app import create_app

    app = create_app()
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        yield test_client
