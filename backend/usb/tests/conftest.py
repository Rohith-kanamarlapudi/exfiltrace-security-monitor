"""Pytest fixtures for USB Forensics & BadUSB detection module."""
from __future__ import annotations

import os
import sys
import tempfile
import pytest

# Ensure repository root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from flask import Flask
from backend.usb.api import usb_bp, set_service
from backend.usb.db import UsbForensicsDb
from backend.usb.detector import BadUsbDetector
from backend.usb.service import UsbForensicsService


@pytest.fixture
def temp_db(tmp_path):
    path = str(tmp_path / "test_usb_forensics.db")
    return UsbForensicsDb(path)


@pytest.fixture
def detector():
    return BadUsbDetector()


@pytest.fixture
def service(tmp_path):
    db_path = str(tmp_path / "test_service.db")
    svc = UsbForensicsService(db_path=db_path, enable_real_discovery=False)
    return svc


@pytest.fixture
def client(service):
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["USB_FORENSICS_SERVICE"] = service
    set_service(service)
    app.register_blueprint(usb_bp, url_prefix="/api")
    with app.test_client() as test_client:
        yield test_client
