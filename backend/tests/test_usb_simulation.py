"""Physical observation fixtures; overlays run through the production pipeline."""
from copy import deepcopy
from types import SimpleNamespace
import threading

import pytest

from app.api import create_app
from app.service import MonitoringService
from app.usb.inspection import inspect_nodes, fingerprint
from app.usb.simulation import UsbSimulation
from tests.test_usb_inspection import fixture, storage, ROOT, node


def actual_storage():
    payload = fixture()
    payload['nodes'] = [n for n in payload['nodes'] if n['instanceId'] == ROOT or n['pnpClass'] == 'DiskDrive']
    device = inspect_nodes(payload, storage())[0]
    device['observationSource'] = 'windows'
    return device


@pytest.fixture
def setup(config, db):
    config.data['usb']['simulation_enabled'] = True
    backend = SimpleNamespace(name='windows', snapshot_complete=True, fail=None, devices=[actual_storage()])
    def snapshot():
        if backend.fail:
            raise backend.fail
        return deepcopy(backend.devices)
    backend.snapshot = snapshot
    service = MonitoringService(config, db=db, usb_backend=backend, async_detection=False)
    service.usb.running = True
    client = create_app(service=service, autostart=False).test_client()
    return service, backend, client


HEADERS = {'X-ExfilTrace-Simulation': '1', 'Origin': 'http://localhost:5173'}


def activate(client, device=ROOT):
    return client.post('/api/usb/simulation', json={'deviceId': device}, headers=HEADERS)


def test_next_cycle_hash_rule_and_isolated_history(setup, db):
    service, backend, client = setup
    original = deepcopy(backend.devices)
    assert db.alert_count() == 0
    response = activate(client)
    assert response.status_code == 200
    data = response.json['data']
    assert data['phase'] == 'armed' and data['alert'] is None and data['observation'] is None
    actual = service.usb.devices()[0]
    baseline_hash = actual['fingerprint']['sha256']
    genuine_history = actual['observation']['history']
    assert len(genuine_history) == 1
    assert service.usb.simulation.baseline['fingerprint']['sha256'] == baseline_hash
    assert service.usb.simulation.history.records()[0]['history'][0]['sha256'] == baseline_hash
    for _ in range(3):
        service.usb.poll_once()
    data = client.get('/api/usb/simulation').json['data']
    finding = data['alert']
    assert data['phase'] == 'finding' and data['simulatedAlertCount'] == 1
    assert finding['title'] == 'SIMULATED — possible USB impersonation'
    assert finding['device']['deviceId'] == ROOT and finding['simulated']
    assert finding['previousFunctions'] == ['composite', 'storage']
    assert set(finding['currentFunctions']) == {'composite', 'storage', 'hid', 'keyboard'}
    assert finding['previousFingerprint'] == baseline_hash
    assert finding['currentFingerprint'] != baseline_hash
    assert finding['rule'] == 'USB_UNEXPECTED_KEYBOARD_ADDITION_V1' and finding['timestamp'].endswith('Z')
    assert finding['changedCharacteristics'][0]['field'] == 'interfaces'
    modified = data['observation']
    assert modified['simulated'] and modified['inspection']['simulated']
    assert modified['inspection']['interfaces'][-1]['simulated']
    assert len(modified['observation']['history']) == 2
    assert modified['fingerprint'] == fingerprint(modified)
    without_provenance = deepcopy(modified)
    without_provenance['inspection']['interfaces'][-1].pop('simulated')
    assert fingerprint(without_provenance) == modified['fingerprint']
    without_provenance['inspection']['interfaces'].pop()
    assert fingerprint(without_provenance)['sha256'] == baseline_hash
    assert backend.devices == original
    assert service.usb.devices()[0]['observation']['history'] == genuine_history
    assert service.usb.devices()[0]['fingerprint']['sha256'] == baseline_hash
    assert db.alert_count() == 0 and client.get('/api/alerts').json['total'] == 0
    assert len(service.usb.history.records()) == 1  # no simulation rows in physical history
    assert all('SIMULATED' not in i['instanceId'] for i in client.get('/api/usb/devices').json['data'][0]['inspection']['interfaces'])


def test_clear_disconnect_and_no_automatic_reconnect(setup):
    service, backend, client = setup
    activate(client); service.usb.poll_once()
    assert client.delete('/api/usb/simulation', headers=HEADERS).json['data']['phase'] == 'idle'
    service.usb.poll_once()
    assert service.usb.simulation_status()['alert'] is None
    activate(client); service.usb.poll_once()
    backend.devices = []
    service.usb.poll_once()
    assert service.usb.simulation_status()['phase'] == 'cancelled'
    backend.devices = [actual_storage()]
    service.usb.poll_once()
    assert service.usb.simulation_status()['alert'] is None
    assert service.usb.simulation_status()['actualDeviceId'] is None


def test_partial_and_failed_queries_pause_then_recover(setup):
    from app.usb.base import UsbBackendError
    service, backend, client = setup
    activate(client)
    backend.snapshot_complete = False
    backend.devices[0]['inspection']['completeness'] = 'partial'
    backend.devices[0]['fingerprint'] = None
    service.usb.poll_once()
    assert service.usb.simulation_status()['phase'] == 'paused'
    assert service.usb.simulation_status()['alert'] is None
    backend.fail = UsbBackendError('Enumeration failed')
    service.usb.poll_once()
    assert service.usb.simulation_status()['phase'] == 'paused'
    backend.fail = None; backend.snapshot_complete = True; backend.devices = [actual_storage()]
    service.usb.poll_once()
    assert service.usb.simulation_status()['phase'] == 'finding'
    timestamp = service.usb.simulation.alert['timestamp']
    backend.snapshot_complete = False; backend.devices = []
    service.usb.poll_once()
    assert service.usb.simulation.baseline is not None  # uncertain absence is not confirmed removal
    assert service.usb.simulation.alert['timestamp'] == timestamp


@pytest.mark.parametrize('case, message', [('keyboard', 'already has a keyboard'), ('partial', 'complete'),
                                         ('nonstorage', 'storage-only'), ('simulated', 'physical Windows')])
def test_unsuitable_baselines_rejected(setup, case, message):
    service, backend, client = setup
    actual = backend.devices[0]
    if case == 'keyboard':
        actual['inspection']['interfaces'].append(node('KEY', ROOT, 'Keyboard', functions=['keyboard']))
    elif case == 'partial':
        actual['inspection']['completeness'] = 'partial'; actual['fingerprint'] = None
    elif case == 'nonstorage':
        actual['inspection']['interfaces'] = [i for i in actual['inspection']['interfaces'] if 'storage' not in i['functions']]
    else:
        actual['observationSource'] = 'simulated'
    response = activate(client)
    assert response.status_code == 409 and message in response.json['error']
    assert service.usb.simulation.baseline is None


def test_disabled_guard_remote_origin_header_validation_and_fresh_presence(setup):
    service, backend, client = setup
    service.usb.simulation.enabled = False
    assert activate(client).status_code == 403
    assert client.delete('/api/usb/simulation', headers=HEADERS).status_code == 403
    service.usb.simulation.enabled = True
    assert client.post('/api/usb/simulation', json={'deviceId': ROOT}).status_code == 403
    assert client.post('/api/usb/simulation', json={'deviceId': ROOT}, headers={**HEADERS, 'Origin': 'https://foreign.example'}).status_code == 403
    assert client.post('/api/usb/simulation', json={'deviceId': ROOT}, headers=HEADERS, environ_overrides={'REMOTE_ADDR': '192.0.2.1'}).status_code == 403
    assert client.post('/api/usb/simulation', json={'deviceId': 42}, headers=HEADERS).status_code == 400
    service.usb.poll_once(); backend.devices = []  # stale API snapshot must not be selectable
    assert activate(client).status_code == 409
    assert service.usb.simulation.baseline is None


def test_local_cors_preflight_and_stopped_monitor(setup):
    service, _, client = setup
    response = client.options('/api/usb/simulation', headers={**HEADERS, 'Access-Control-Request-Method': 'POST'})
    assert response.status_code == 204
    assert response.headers['Access-Control-Allow-Origin'] == 'http://localhost:5173'
    assert 'X-ExfilTrace-Simulation' in response.headers['Access-Control-Allow-Headers']
    service.usb.running = False
    assert activate(client).status_code == 409


def test_poll_clear_concurrency_and_actual_characteristic_change(setup):
    service, backend, client = setup
    activate(client)
    errors = []
    def poll():
        try:
            for _ in range(6):
                service.usb.poll_once()
        except Exception as exc:
            errors.append(exc)
    thread = threading.Thread(target=poll)
    thread.start(); service.usb.clear_simulation(); thread.join()
    assert not errors and service.usb.simulation_status()['alert'] is None
    activate(client)
    backend.devices[0]['inspection']['manufacturer'] = 'New actual manufacturer metadata'
    service.usb.poll_once()
    assert service.usb.simulation_status()['phase'] == 'cancelled'
    assert service.usb.simulation_status()['alert'] is None


def test_isolated_overlay_never_writes_real_database_and_dedupes():
    actual = actual_storage(); original = deepcopy(actual)
    overlay = UsbSimulation(True)
    overlay.activate(actual)
    for _ in range(5):
        overlay.cycle({ROOT: actual}, True)
    assert actual == original
    assert len(overlay.history.records()) == 1
    assert len(overlay.history.records()[0]['history']) == 2
    assert overlay.status([actual], True)['simulatedAlertCount'] == 1
    overlay.clear()


def test_default_config_disabled_and_explicit_environment_flag(monkeypatch, tmp_path):
    from app.config import Config
    path = tmp_path / 'config.json'; path.write_text('{}')
    monkeypatch.delenv('EXFILTRACE_USB_SIMULATION', raising=False)
    assert not Config.load(str(path))['usb']['simulation_enabled']
    monkeypatch.setenv('EXFILTRACE_USB_SIMULATION', '1')
    assert Config.load(str(path))['usb']['simulation_enabled']
    assert path.read_text() == '{}'


def test_overlay_preserves_filesystem_watches_and_sensitive_copy(setup, db, dirs):
    import shutil
    from tests.conftest import wait_for
    service, backend, client = setup
    backend.devices[0]['mounts'] = [str(dirs['usb'])]
    source = dirs['monitored'] / 'confidential-simulation-check.txt'
    source.write_text('harmless temporary copy detection content\n' * 100)
    service.start()
    try:
        assert activate(client).status_code == 200
        watches = service.files.watches()
        service.usb.poll_once()
        assert service.files.watches() == watches
        assert 'keyboard' not in service.usb.volume_for(str(dirs['usb'] / source.name))[1]['inspection']['functions']
        assert client.get('/api/alerts').json['total'] == 0
        shutil.copy(source, dirs['usb'] / source.name)
        assert wait_for(lambda: db.query_alerts(verdict='VERIFIED_TRANSFER')[1] >= 1)
        assert client.get('/api/usb/simulation').json['data']['simulatedAlertCount'] == 1
        assert all(a['rule'] != 'USB_UNEXPECTED_KEYBOARD_ADDITION_V1' for a in db.query_alerts()[0])
        client.delete('/api/usb/simulation', headers=HEADERS)
        assert service.files.watches() == watches
    finally:
        service.stop()


def test_simulation_failure_does_not_stop_actual_monitoring(setup, monkeypatch):
    service, _, client = setup
    activate(client)
    def fail(*args):
        raise RuntimeError('Injected simulation failure')
    monkeypatch.setattr(service.usb.simulation, 'cycle', fail)
    service.usb.poll_once()
    assert service.usb.devices()[0]['device_id'] == ROOT
    assert service.usb.simulation_status()['phase'] == 'cancelled'
    assert service.usb.last_error is None
