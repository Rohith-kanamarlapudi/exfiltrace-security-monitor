import json

import pytest

from app.usb import SimulatedUsbBackend, create_backend
from app.usb.base import UsbBackendError
from app.usb.monitor import UsbMonitor
from app.usb.windows import WindowsUsbBackend, parse_powershell_output
from tests.conftest import make_device

SAMPLE = {
    "disks": [{
        "pnp": "USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\\4C530001230821115&0",
        "model": "SanDisk Ultra USB Device", "serial": "4C530001230821115", "size": 32000000000,
        "volumes": [{"drive": "E:", "label": "BACKUP", "fs": "FAT32", "size": 31900000000}],
    }],
    "usb_ids": ["USB\\VID_0781&PID_5581\\4C530001230821115", "USB\\VID_046D&PID_C52B\\5&2a1b&0&1"],
}


def test_windows_parser_extracts_ids_drive_and_volume():
    [dev] = parse_powershell_output(json.dumps(SAMPLE))
    assert dev["vendor_id"] == "0781" and dev["product_id"] == "5581"
    assert dev["serial_number"] == "4C530001230821115"
    assert dev["mounts"] == ["E:\\"] and dev["volume_label"] == "BACKUP" and dev["filesystem"] == "FAT32"


def test_windows_parser_handles_single_object_collapse_and_no_volume():
    collapsed = {"disks": {"pnp": "USBSTOR\\DISK&VEN_X&PROD_Y&REV_1\\ABC&0", "model": "X Y", "volumes": []},
                 "usb_ids": "USB\\VID_1111&PID_2222\\ABC"}
    [dev] = parse_powershell_output(json.dumps(collapsed))
    assert dev["mounts"] == [] and dev["vendor_id"] == "1111"


def test_windows_parser_rejects_garbage_and_handles_empty():
    assert parse_powershell_output("") == []
    with pytest.raises(UsbBackendError):
        parse_powershell_output("not json")


def test_windows_backend_refuses_on_other_os(monkeypatch):
    monkeypatch.setattr("sys.platform", "linux")
    with pytest.raises(UsbBackendError):
        WindowsUsbBackend().snapshot()


def test_simulated_backend_reads_file_and_reports_bad_json(tmp_path):
    f = tmp_path / "usb.json"
    b = SimulatedUsbBackend(str(f))
    assert b.snapshot() == []
    f.write_text(json.dumps({"devices": [make_device("/mnt/x")]}))
    assert b.snapshot()[0]["vendor_id"] == "0781"
    f.write_text("{broken")
    with pytest.raises(UsbBackendError):
        b.snapshot()


def test_backend_factory(config):
    config.data["usb"]["backend"] = "simulated"
    assert create_backend(config).name == "simulated"
    config.data["usb"]["backend"] = "none"
    assert create_backend(config).name == "none"


def test_insert_remove_and_multiple_devices(backend):
    inserted, removed = [], []
    mon = UsbMonitor(backend, on_insert=lambda d, pre: inserted.append((d["device_id"], pre)),
                     on_remove=lambda d: removed.append(d["device_id"]))
    mon.poll_once()                                   # nothing attached
    backend.devices = [make_device("/mnt/a", "A")]
    mon.poll_once()
    backend.devices.append(make_device("/mnt/b", "B"))
    mon.poll_once()
    assert inserted == [("A", False), ("B", False)]
    backend.devices = [make_device("/mnt/b", "B")]
    mon.poll_once()
    assert removed == ["A"] and [d["device_id"] for d in mon.devices()] == ["B"]


def test_devices_present_at_startup_are_marked_preexisting(backend):
    seen = []
    backend.devices = [make_device("/mnt/a", "A")]
    UsbMonitor(backend, on_insert=lambda d, pre: seen.append(pre)).poll_once()
    assert seen == [True]


def test_mount_change_detected(backend):
    changes = []
    mon = UsbMonitor(backend, on_mounts_changed=lambda d, o, n: changes.append((o, n)))
    backend.devices = [make_device("/mnt/a", "A", mounts=[])]
    mon.poll_once()
    backend.devices = [make_device("/mnt/a", "A", mounts=["/mnt/a"])]
    mon.poll_once()
    assert changes == [([], ["/mnt/a"])]


def test_backend_errors_do_not_stop_monitoring(backend):
    mon = UsbMonitor(backend)
    backend.fail_with = UsbBackendError("powershell missing")
    mon.poll_once()
    assert "powershell missing" in mon.last_error
    backend.fail_with = RuntimeError("bug")
    mon.poll_once()
    assert "Unexpected" in mon.last_error
    backend.fail_with = None
    backend.devices = [make_device("/mnt/a", "A")]
    mon.poll_once()
    assert mon.last_error is None and len(mon.devices()) == 1


def test_handler_exceptions_are_contained(backend):
    def bad(*_):
        raise RuntimeError("handler bug")
    mon = UsbMonitor(backend, on_insert=bad)
    backend.devices = [make_device("/mnt/a", "A")]
    mon.poll_once()
    assert len(mon.devices()) == 1


def test_volume_for_matches_paths_under_mount_only(backend, dirs):
    mon = UsbMonitor(backend)
    backend.devices = [make_device(dirs["usb"], "A")]
    mon.poll_once()
    assert mon.volume_for(str(dirs["usb"] / "sub" / "f.txt"))[1]["device_id"] == "A"
    assert mon.volume_for(str(dirs["monitored"] / "f.txt")) is None
    assert mon.volume_for(str(dirs["usb"]) + "2/f.txt") is None      # prefix lookalike
