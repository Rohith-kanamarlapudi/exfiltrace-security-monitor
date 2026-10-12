"""Representative Windows devnodes, not physical hardware test results."""
import copy
import json
from types import SimpleNamespace

from app.usb.base import normalize_device, UsbBackendError
from app.usb.inspection import inspect_nodes, fingerprint
from app.usb.history import UsbHistory
from app.usb.monitor import UsbMonitor
from app.usb.windows import WindowsUsbBackend

ROOT = r'USB\VID_1234&PID_ABCD\SERIAL-A'
OTHER = r'USB\VID_1234&PID_ABCD\6&PORT-B&0&2'
DISK = r'USBSTOR\DISK&VEN_TEST&PROD_TEST\SERIAL-A&0'


def node(instance, parent=None, cls='USB', **fields):
    return {'instanceId': instance, 'parentId': parent, 'pnpClass': cls, 'name': 'Test device',
            'containerId': 'fixture-container', 'hardwareIds': [instance.split('\\')[0] + r'\TEST'],
            'compatibleIds': [], 'manufacturer': 'Fixture vendor', 'capabilities': 0,
            'errors': [], **fields}


def fixture():
    return {'nodes': [node(ROOT, 'USB\\ROOT_HUB30\\HUB', capabilities=0x10, compatibleIds=[r'USB\COMPOSITE']),
                      node(ROOT.replace('PID_ABCD', 'PID_ABCD&MI_00'), ROOT, 'HIDClass'),
                      node(r'HID\VID_1234&PID_ABCD\KEYBOARD', ROOT.replace('PID_ABCD', 'PID_ABCD&MI_00'), 'Keyboard'),
                      node(DISK, ROOT, 'DiskDrive'), node(OTHER, 'USB\\ROOT_HUB30\\HUB', 'HIDClass'),
                      node(r'HID\VID_1234&PID_ABCD\MOUSE', OTHER, 'Mouse')]}


def storage():
    return [normalize_device({'device_id': DISK, 'mounts': ['D:\\'], 'volume_label': 'LARP', 'filesystem': 'FAT32'})]


def test_composite_grouping_storage_and_unrelated_identical_vid_pid():
    devices = inspect_nodes(fixture(), storage())
    assert len(devices) == 2
    a, b = devices
    assert a['mounts'] == ['D:\\'] and b['mounts'] == []
    assert a['serial_number'] == 'SERIAL-A' and b['serial_number'] is None
    assert set(a['inspection']['functions']) == {'composite', 'hid', 'keyboard', 'storage'}
    assert b['inspection']['functions'] == ['hid', 'mouse']
    assert a['device_id'] != b['device_id']
    assert all(i['usbDescriptorClass'] is None for i in a['inspection']['interfaces'])


def test_fingerprint_order_drive_and_volatile_identity_independent():
    a = inspect_nodes(fixture(), storage())[0]
    payload = fixture()
    payload['nodes'].reverse()
    disks = storage(); disks[0]['mounts'] = ['Z:\\']
    b = next(d for d in inspect_nodes(payload, disks) if d['device_id'] == ROOT)
    assert a['fingerprint'] == b['fingerprint']
    b['device_id'] = 'changed'; b['serial_number'] = 'changed'; b['timestamp'] = 'later'
    b['inspection']['interfaces'].reverse()
    assert fingerprint(b) == a['fingerprint']
    b['inspection']['interfaces'][0]['hardwareIds'].append(r'USB\NEW_CHARACTERISTIC')
    assert fingerprint(b)['sha256'] != a['fingerprint']['sha256']


def test_persistence_restart_dedupe_changes_and_partial(db):
    history = UsbHistory(db)
    a = inspect_nodes(fixture(), storage())[0]
    history.observe(a)
    first = a['observation']['firstSeen']
    assert first.endswith('Z') and a['observation']['newlyObserved']
    history.observe(a)
    assert len(a['observation']['history']) == 1
    from app.db import Database
    restarted = UsbHistory(Database(db.path))
    restarted.observe(a)
    assert not a['observation']['newlyObserved'] and a['observation']['firstSeen'] == first
    changed = copy.deepcopy(a)
    changed['inspection']['manufacturer'] = 'Changed Windows metadata'
    changed['fingerprint'] = fingerprint(changed)
    restarted.observe(changed)
    assert len(changed['observation']['history']) == 2
    assert changed['observation']['history'][0]['changes'][0]['field'] == 'manufacturer'
    assert changed['observation']['previousFingerprint'] == a['fingerprint']['sha256']
    partial = copy.deepcopy(changed); partial['fingerprint'] = None
    restarted.observe(partial)
    assert partial['observation']['fingerprintRetained']
    assert len(partial['observation']['history']) == 2
    assert db.file_stats()['total_events'] == 0


def test_partial_query_retains_devices_fingerprint_and_watches(db):
    payload = fixture()
    devices = inspect_nodes(payload, storage())
    backend = SimpleNamespace(name='windows', snapshot_complete=True, snapshot=lambda: devices)
    removed, mounts = [], []
    monitor = UsbMonitor(backend, history=UsbHistory(db), on_remove=lambda d: removed.append(d),
                         on_mounts_changed=lambda *args: mounts.append(args))
    monitor.poll_once()
    original = monitor.devices()[0]['observation']['currentFingerprint']
    payload['nodes'][0]['errors'] = ['access denied']
    devices = inspect_nodes(payload, storage())[:1]
    assert devices[0]['fingerprint'] is None
    backend.snapshot_complete = False
    monitor.poll_once()
    assert len(monitor.devices()) == 2 and not removed and not mounts
    assert monitor.devices()[0]['observation']['currentFingerprint'] == original
    assert monitor.last_error
    backend.snapshot_complete = True; devices = []
    monitor.poll_once()
    assert len(removed) == 2 and monitor.last_error is None


def test_unresolved_storage_never_fakes_serial_or_merges_by_vid_pid():
    disks = storage(); disks[0]['device_id'] = r'USBSTOR\DISK\UNKNOWN&0'
    disks[0]['serial_number'] = 'generated-location'
    devices = inspect_nodes(fixture(), disks)
    assert len(devices) == 3
    assert devices[-1]['inspection']['completeness'] == 'partial'
    assert devices[-1]['serial_number'] is None and devices[-1]['fingerprint'] is None


def test_bluetooth_peers_are_not_radio_interfaces():
    payload = fixture()
    payload['nodes'].append(node(r'BTHENUM\REMOTE_PEER', ROOT, 'Bluetooth'))
    assert inspect_nodes(payload, storage())[0]['fingerprint'] == inspect_nodes(fixture(), storage())[0]['fingerprint']


def test_same_model_equal_hashes_remain_distinct_physical_records():
    payload = {'nodes': [node(ROOT), node(OTHER)]}
    a, b = inspect_nodes(payload, [])
    assert a['device_id'] != b['device_id']
    assert a['fingerprint'] == b['fingerprint']


def test_additive_schema_preserves_existing_usb_event(db):
    event = db.add_usb_event(event_type='INSERTED', device_id='legacy', mounts=['X:\\'])
    assert event['timestamp'].endswith('Z')
    UsbHistory(db)
    events, count = db.query_usb_events()
    assert count == 1 and events[0] == event
    db.add_usb_event(event_type='INSERTED', device_id='timezone-fixture-old', timestamp='2026-10-12T09:00:00+05:30')
    db.add_usb_event(event_type='INSERTED', device_id='timezone-fixture-new', timestamp='2026-10-12T04:00:00Z')
    ordered, _ = db.query_usb_events(search='timezone-fixture')
    assert [e['device_id'] for e in ordered] == ['timezone-fixture-new', 'timezone-fixture-old']
    window = [e['device_id'] for e in db.usb_events_since('2026-10-12T03:45:00Z') if e['device_id'].startswith('timezone-fixture')]
    assert window == ['timezone-fixture-new']


def test_windows_caches_inspection_refreshes_on_inventory_and_detects_race(monkeypatch):
    payload = fixture()
    ids = [n['instanceId'] for n in payload['nodes']]
    data = {'disks': [], 'usb_ids': [i for i in ids if i.startswith('USB\\')], 'present_ids': ids}
    calls = []
    monkeypatch.setattr('sys.platform', 'win32')
    monkeypatch.setattr('app.usb.windows.subprocess.run', lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps(data), stderr=''))
    monkeypatch.setattr('app.usb.windows.enumerate_nodes', lambda: calls.append(1) or payload)
    backend = WindowsUsbBackend()
    backend.snapshot(); backend.snapshot()
    assert len(calls) == 1
    backend._inspected_at = 0
    backend.snapshot()
    assert len(calls) == 2
    data['present_ids'] = ids[:-1]
    import pytest
    with pytest.raises(UsbBackendError, match='inventory changed'):
        backend.snapshot()


def test_inspection_api_preserves_legacy_fields(config, db):
    from app.service import MonitoringService
    from app.api import create_app
    devices = inspect_nodes(fixture(), storage())
    backend = SimpleNamespace(name='windows', snapshot=lambda: copy.deepcopy(devices))
    service = MonitoringService(config, db=db, usb_backend=backend)
    service.usb.poll_once()
    data = create_app(service=service, autostart=False).test_client().get('/api/usb/devices').get_json()
    assert data['source'] == 'live' and data['total'] == 2
    assert data['data'][0]['mounts'] == ['D:\\']
    assert data['data'][0]['inspection']['interfaces']
    assert data['data'][0]['observation']['currentFingerprint']
    assert db.alert_count() == 0
    records = create_app(service=service, autostart=False).test_client().get('/api/usb/observations').get_json()
    assert records['total'] == 2 and records['data'][0]['lastSeen'].endswith('Z')


def test_missing_previously_available_property_defers_comparison(db):
    history = UsbHistory(db)
    a = inspect_nodes(fixture(), storage())[0]
    history.observe(a)
    previous = a['observation']['currentFingerprint']
    a['inspection']['manufacturer'] = None
    a['fingerprint'] = fingerprint(a)
    history.observe(a)
    assert a['fingerprint'] is None and a['inspection']['completeness'] == 'partial'
    assert a['observation']['currentFingerprint'] == previous
    assert len(a['observation']['history']) == 1


def test_inspected_physical_identity_preserves_sensitive_copy_detection(config, db, backend, dirs):
    import shutil
    from app.service import MonitoringService
    from tests.conftest import wait_for
    disks = storage(); disks[0]['mounts'] = [str(dirs['usb'])]
    devices = inspect_nodes(fixture(), disks)
    backend.devices = devices
    source = dirs['monitored'] / 'confidential-inspection.txt'
    source.write_text('fixture-only sensitive-copy check\n' * 100)
    service = MonitoringService(config, db=db, usb_backend=backend, async_detection=False)
    service.start()
    try:
        assert str(dirs['usb']) in service.status()['file_monitor']['removable_watches']
        shutil.copy(source, dirs['usb'] / source.name)
        assert wait_for(lambda: db.query_alerts(verdict='VERIFIED_TRANSFER')[1] >= 1)
        events, _ = db.query_file_events(removable=True)
        assert any(e['usb_device_id'] == ROOT for e in events)
        backend.devices = []
        service.usb.poll_once()
        assert service.status()['file_monitor']['removable_watches'] == []
    finally:
        service.stop()


def test_storage_fallback_resolution_keeps_existing_watch(config, db, backend, dirs):
    from app.service import MonitoringService
    disks = storage(); disks[0]['mounts'] = [str(dirs['usb'])]
    backend.devices = disks
    service = MonitoringService(config, db=db, usb_backend=backend, async_detection=False)
    service.start()
    try:
        backend.devices = inspect_nodes(fixture(), disks)
        service.usb.poll_once()
        assert str(dirs['usb']) in service.status()['file_monitor']['removable_watches']
        assert service.usb.volume_for(str(dirs['usb'] / 'file.txt'))[1]['device_id'] == ROOT
    finally:
        service.stop()
