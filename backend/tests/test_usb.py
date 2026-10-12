import json
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from app.usb import SimulatedUsbBackend, create_backend
from app.usb.base import UsbBackendError
from app.usb.monitor import UsbMonitor
from app.usb.windows import POWERSHELL_SCRIPT, WindowsUsbBackend, parse_powershell_output
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


def test_windows_parser_handles_valid_empty_snapshot():
    assert parse_powershell_output('{"disks": [], "usb_ids": []}') == []


@pytest.mark.parametrize("text", ["", "   ", "not json", "null", "[]", "{}", '{"disks": []}'])
def test_windows_parser_rejects_missing_or_invalid_snapshot(text):
    with pytest.raises(UsbBackendError):
        parse_powershell_output(text)


def test_windows_parser_preserves_all_mounted_volumes():
    sample = json.loads(json.dumps(SAMPLE))
    sample["disks"][0]["volumes"].append({"drive": "F:", "label": "SECOND", "fs": "NTFS"})
    [dev] = parse_powershell_output(json.dumps(sample))
    assert dev["mounts"] == ["E:\\", "F:\\"]
    assert dev["volume_label"] == "BACKUP" and dev["size_bytes"] == 32000000000


@pytest.mark.parametrize("failure", [
    SimpleNamespace(returncode=1, stderr="Get-CimAssociatedInstance: Not found", stdout=""),
    SimpleNamespace(returncode=1, stderr="", stdout="association failed"),
    SimpleNamespace(returncode=1, stderr="", stdout=""),
    OSError("powershell missing"),
    subprocess.TimeoutExpired("powershell", 30),
])
def test_windows_snapshot_reports_process_failures(monkeypatch, failure):
    monkeypatch.setattr("sys.platform", "win32")

    def run(*args, **kwargs):
        if isinstance(failure, Exception):
            raise failure
        return failure

    monkeypatch.setattr("app.usb.windows.subprocess.run", run)
    with pytest.raises(UsbBackendError, match="PowerShell"):
        WindowsUsbBackend().snapshot()


def test_windows_snapshot_errors_keep_devices_until_successful_removal(monkeypatch):
    monkeypatch.setattr("sys.platform", "win32")
    outputs = iter([
        SimpleNamespace(returncode=0, stdout=json.dumps(SAMPLE), stderr=""),
        SimpleNamespace(returncode=1, stdout="", stderr="CIM association failed"),
        SimpleNamespace(returncode=0, stdout="", stderr=""),
        SimpleNamespace(returncode=0, stdout='{"disks": [], "usb_ids": []}', stderr=""),
    ])
    monkeypatch.setattr("app.usb.windows.subprocess.run", lambda *a, **k: next(outputs))
    inserted, removed = [], []
    mon = UsbMonitor(WindowsUsbBackend(), on_insert=lambda d, pre: inserted.append(pre),
                     on_remove=lambda d: removed.append(d))
    mon.poll_once()
    assert inserted == [True] and mon.devices()[0]["mounts"] == ["E:\\"]
    mon.poll_once()
    assert "CIM association failed" in mon.last_error and len(mon.devices()) == 1 and not removed
    mon.poll_once()
    assert "Unreadable PowerShell output" in mon.last_error and len(mon.devices()) == 1 and not removed
    mon.poll_once()
    assert mon.last_error is None and mon.devices() == [] and len(removed) == 1


@pytest.mark.skipif(not shutil.which("powershell"), reason="Windows PowerShell unavailable")
@pytest.mark.parametrize("fail_association", [False, True])
def test_powershell_script_traverses_cim_objects(fail_association):
    # Execute the production script with fake CIM providers: disk object identity,
    # both association classes, multiple partitions, unmounted disks and failures.
    provider = r'''
$script:sourceDisk = [pscustomobject]@{ DeviceID = '\\.\PHYSICALDRIVE1'; InterfaceType = 'USB'; PNPDeviceID = 'USBSTOR\DISK\ABC&0'; Model = 'Test USB'; Size = 100 }
$script:sourceBare = [pscustomobject]@{ DeviceID = '\\.\PHYSICALDRIVE2'; InterfaceType = 'USB'; PNPDeviceID = 'USBSTOR\DISK\BARE&0'; Model = 'Unmounted' }
function Get-CimInstance {
  param($ClassName)
  switch ($ClassName) {
    'Win32_DiskDrive' { $script:sourceDisk; $script:sourceBare }
    'Win32_PnPEntity' { [pscustomobject]@{ DeviceID = 'USB\VID_1234&PID_5678\ABC' } }
    default { throw "Unexpected query: $ClassName" }
  }
}
function Get-CimAssociatedInstance {
  param($InputObject, $Association, $ResultClassName)
  if ($script:fail) { throw 'Injected association failure' }
  if ($Association -eq 'Win32_DiskDriveToDiskPartition' -and $ResultClassName -eq 'Win32_DiskPartition') {
    if ([object]::ReferenceEquals($InputObject, $script:sourceDisk)) {
      foreach ($letter in @('E:', 'F:', $null)) { [pscustomobject]@{ DeviceID = "Partition $letter"; Letter = $letter } }
    } elseif (-not [object]::ReferenceEquals($InputObject, $script:sourceBare)) { throw 'Disk identity lost' }
  } elseif ($Association -eq 'Win32_LogicalDiskToPartition' -and $ResultClassName -eq 'Win32_LogicalDisk') {
    if ($InputObject.Letter) { [pscustomobject]@{ DeviceID = $InputObject.Letter; VolumeName = 'TEST'; FileSystem = 'NTFS'; Size = 40 } }
  } else { throw "Unexpected association: $Association / $ResultClassName" }
}
'''
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         provider + "$script:fail = $" + str(fail_association).lower() + "\n" + POWERSHELL_SCRIPT],
        capture_output=True, text=True, timeout=30,
    )
    if fail_association:
        assert proc.returncode != 0 and "Injected association failure" in proc.stderr
        assert not proc.stdout.strip()  # no partial successful snapshot
    else:
        assert proc.returncode == 0, proc.stderr
        dev, bare = parse_powershell_output(proc.stdout)
        assert dev["mounts"] == ["E:\\", "F:\\"] and dev["vendor_id"] == "1234"
        assert bare["mounts"] == []


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


def test_usb_service_watches_startup_and_delayed_multiple_mounts(config, db, backend, dirs):
    from app.api import create_app
    from app.service import MonitoringService

    second = dirs["root"] / "second_volume"
    second.mkdir()
    mounts = [str(dirs["usb"]), str(second)]
    backend.devices = [make_device(dirs["usb"], "STARTUP", mounts=mounts),
                       make_device(dirs["usb"], "UNMOUNTED", mounts=[])]
    service = MonitoringService(config, db=db, usb_backend=backend, async_detection=False)
    client = create_app(service=service, autostart=False).test_client()
    service.start()
    try:
        status = client.get("/api/status").get_json()["data"]
        assert status["usb_monitor"]["last_error"] is None
        assert set(status["file_monitor"]["removable_watches"]) == set(mounts)
        assert client.get("/api/usb/devices").get_json()["total"] == 2
        assert all(ev["details"]["preexisting"] for ev in db.query_usb_events()[0])

        backend.devices = [make_device(second, "UNMOUNTED", mounts=[])]
        service.usb.poll_once()
        assert service.status()["file_monitor"]["removable_watches"] == []
        backend.devices = [make_device(second, "UNMOUNTED", mounts=[str(second)])]
        service.usb.poll_once()
        assert service.status()["file_monitor"]["removable_watches"] == [str(second)]
        backend.devices = []
        service.usb.poll_once()
        assert service.status()["file_monitor"]["removable_watches"] == []
        assert client.get("/api/usb/devices").get_json()["total"] == 0
    finally:
        service.stop()


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
