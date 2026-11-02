import io
import os
from pathlib import Path
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from app.api import create_app
from app.service import MonitoringService
from app.usb.recovery import windows
from app.usb.recovery.engine import Cancelled, SleuthKit, digest, image_geometry, safe_name
from app.usb.recovery.jobs import RecoveryJobs
from .conftest import wait_for
from .fat32_fixture import make_image


@pytest.fixture
def image(tmp_path):
    path = tmp_path / 'controlled.img'
    expected = make_image(path)
    return path, expected


@pytest.fixture
def kit():
    kit = SleuthKit()
    if not kit.available():
        pytest.skip('Install Sleuth Kit / EXFILTRACE_TSK_DIR for real FAT32 tool integration tests')
    return kit


def test_real_deleted_entries_and_uncertain_reconstruction(image, kit, tmp_path):
    path, expected = image
    cancel = threading.Event()
    before = digest(path, cancel)
    candidates = kit.scan(path, 0, cancel)
    assert len(candidates) == 3
    outputs = {}
    for candidate in candidates:
        assert candidate['status'] == 'uncertain'
        assert 'fragmentation' in candidate['limitations']
        output = tmp_path / (candidate['id'] + '.out')
        try:
            with output.open('xb') as f:
                kit.recover(path, 0, candidate, f, cancel)
            outputs[candidate['filename']] = output.read_bytes()
        except ValueError:
            outputs[candidate['filename']] = None
    plain = next(v for k, v in outputs.items() if 'LAIN' in k)
    frag = next(v for k, v in outputs.items() if 'RAG' in k)
    over = next(v for k, v in outputs.items() if 'VER' in k)
    assert plain == expected['plain']
    assert frag != expected['fragmented']  # FAT deletion erased the noncontiguous chain
    assert over != expected['overwrittenOriginal']
    assert digest(path, cancel) == before


def test_geometry_malformed_truncated_and_offset(image, tmp_path):
    path, _ = image
    assert image_geometry(path, 0)['sizeBytes'] == 70000 * 512
    for offset in (-1, 1, '0', True):
        with pytest.raises(ValueError):
            image_geometry(path, offset)
    short = tmp_path / 'short.img'
    short.write_bytes(path.read_bytes()[:1024])
    with pytest.raises(ValueError, match='Truncated'):
        image_geometry(short, 0)
    short.write_bytes(b'bad' * 512)
    with pytest.raises(ValueError, match='signature'):
        image_geometry(short, 0)


@pytest.mark.parametrize('value', ['../../CON', '..\\..\\file:ads', '/absolute/NUL.txt', 'a\x00b', '...'])
def test_safe_names(value):
    name = safe_name(value)
    assert name.startswith('recovered_')
    assert not any(c in name for c in '/\\:\x00')
    assert not name.endswith('.')


def test_cancellation_and_exclusive_copy(db, tmp_path):
    manager = RecoveryJobs(SimpleNamespace(db=db))
    job = {'id': 'copy', 'progress': 0}
    path = tmp_path / 'existing'
    path.write_bytes(b'preserve')
    with pytest.raises(FileExistsError):
        manager.copy(io.BytesIO(b'123'), 3, path, job)
    assert path.read_bytes() == b'preserve'
    manager.cancel_event.set()
    with pytest.raises(Cancelled):
        manager.copy(io.BytesIO(b'123'), 3, tmp_path / 'new.partial', job)
    manager.worker.shutdown()


@pytest.fixture
def local_paths(monkeypatch):
    # Disk topology is mocked for unit/integration tests only; production rejects
    # USB/UNC/reparse mounts through native Windows checks and CIM relationships.
    def validate(value, directory=True):
        path = Path(value)
        if not path.is_absolute() or not (path.is_dir() if directory else path.is_file()):
            raise ValueError('Expected existing absolute local path')
        return path.resolve()
    monkeypatch.setattr(windows, 'local_path', validate)


def finish(manager, job):
    assert wait_for(lambda: manager.active is None, timeout=20)
    return manager.get(job['id'])


def test_jobs_persistence_source_integrity_and_alert_isolation(db, image, kit, tmp_path, local_paths):
    usb = SimpleNamespace(devices=lambda: [], last_error=None)
    service = SimpleNamespace(db=db, usb=usb)
    manager = RecoveryJobs(service, kit)
    path, _ = image
    before = digest(path, threading.Event())
    job = finish(manager, manager.start({'action': 'import', 'imagePath': str(path), 'imageFolder': str(tmp_path)}))
    assert job['status'] == 'imageReady', job.get('error')
    assert job['imageSha256'] == before
    job = finish(manager, manager.action(job['id'], {'action': 'scan'}))
    assert job['status'] == 'scanned', job.get('error')
    job = finish(manager, manager.action(job['id'], {'action': 'recover', 'candidateIds': [job['candidates'][0]['id']], 'outputFolder': str(tmp_path)}))
    assert job['status'] == 'completed', job.get('error')
    assert job['results'][0]['status'] in ('unverified', 'failed')
    assert digest(path, threading.Event()) == before
    manager.worker.shutdown()
    restarted = RecoveryJobs(service, kit)
    assert restarted.get(job['id'])['results'] == job['results']
    with db.connect() as conn:
        assert conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0] == 0
        assert conn.execute('SELECT COUNT(*) FROM usb_events').fetchone()[0] == 0
    # Changed image cannot use old candidate IDs for reconstruction.
    with open(job['imagePath'], 'r+b') as f:
        f.seek(-1, os.SEEK_END); f.write(b'!')
    changed = finish(restarted, restarted.action(job['id'], {'action': 'scan'}))
    assert changed['status'] == 'failed' and 'SHA-256 changed' in changed['error']
    restarted.worker.shutdown()


def test_api_guards(config, db, backend):
    service = MonitoringService(config, db=db, usb_backend=backend)
    app = create_app(service=service, autostart=False)
    client = app.test_client()
    assert client.get('/api/usb/recovery').status_code == 200
    assert client.post('/api/usb/recovery/jobs', json={'action': 'import'}).status_code == 403
    assert client.post('/api/usb/recovery/jobs', json={'action': 'import'}, headers={
        'X-ExfilTrace-Recovery': '1', 'Origin': 'https://evil.example'}).status_code == 403
    assert client.get('/api/usb/recovery', environ_base={'REMOTE_ADDR': '192.0.2.1'}).status_code == 403
    assert client.post('/api/usb/recovery/jobs', json={'action': 'wrong'}, headers={'X-ExfilTrace-Recovery': '1'}).status_code == 409


def test_restart_marks_inflight_as_interrupted(db):
    service = SimpleNamespace(db=db)
    manager = RecoveryJobs(service)
    manager.save({'id': 'interrupted', 'status': 'acquiring', 'imageComplete': False})
    restarted = RecoveryJobs(service)
    assert restarted.get('interrupted')['status'] == 'interrupted'
    manager.worker.shutdown(); restarted.worker.shutdown()


def test_physical_acquisition_read_only_fixture_and_disconnect(db, image, tmp_path, local_paths, monkeypatch):
    path, _ = image
    before = digest(path, threading.Event())
    manager = RecoveryJobs(SimpleNamespace(db=db))
    record = {'diskNumber': 7, 'partitionSize': path.stat().st_size}
    monkeypatch.setattr(manager, 'source', lambda job: record)
    monkeypatch.setattr(windows, 'inventory', lambda: [record])
    @contextmanager
    def volume(mount, number):
        assert mount == 'TEST_VOLUME' and number == 7
        with open(path, 'rb') as f:
            yield f
    monkeypatch.setattr(windows, 'open_volume', volume)
    job = finish(manager, manager.start({'action': 'acquire', 'mount': 'TEST_VOLUME',
        'deviceId': 'actual-root', 'imageFolder': str(tmp_path)}))
    assert job['status'] == 'imageReady', job.get('error')
    assert job['sourceDeviceId'] == 'actual-root'
    assert job['imageSha256'] == before == digest(path, threading.Event())
    monkeypatch.setattr(windows, 'inventory', lambda: [])
    lost = finish(manager, manager.start({'action': 'acquire', 'mount': 'TEST_VOLUME',
        'deviceId': 'actual-root', 'imageFolder': str(tmp_path)}))
    assert lost['status'] == 'failed' and not lost['imageComplete']
    manager.worker.shutdown()


def test_missing_partial_or_simulated_source_rejected(db):
    usb = SimpleNamespace(_poll_lock=threading.RLock(), poll_once=lambda: None,
                          devices=lambda: [], last_error=None)
    manager = RecoveryJobs(SimpleNamespace(db=db, usb=usb))
    for error in (None, 'Partial query'):
        usb.last_error = error
        with pytest.raises(ValueError, match='Cannot verify'):
            manager.source({'sourceDeviceId': 'gone', 'sourceMount': 'E:\\'})
    manager.worker.shutdown()


def test_failed_import_no_space_and_missing_tool(db, image, tmp_path, local_paths, monkeypatch):
    manager = RecoveryJobs(SimpleNamespace(db=db))
    monkeypatch.setattr('app.usb.recovery.jobs.shutil.disk_usage', lambda p: SimpleNamespace(free=0))
    job = finish(manager, manager.start({'action': 'import', 'imagePath': str(image[0]), 'imageFolder': str(tmp_path)}))
    assert job['status'] == 'failed' and 'Insufficient' in job['error']
    assert not job['imageComplete']
    kit = SleuthKit()
    kit.tools = dict.fromkeys(kit.tools)
    with pytest.raises(ValueError, match='Install The Sleuth Kit'):
        kit.scan(image[0], 0, threading.Event())
    manager.worker.shutdown()


def test_active_job_cancel_rejects_concurrent_operation(db, tmp_path, local_paths, monkeypatch):
    manager = RecoveryJobs(SimpleNamespace(db=db))
    entered = threading.Event()
    def slow(job, body):
        entered.set()
        manager.cancel_event.wait(5)
        from app.usb.recovery.engine import check
        check(manager.cancel_event)
    monkeypatch.setattr(manager, 'acquire', slow)
    job = manager.start({'action': 'import'})
    assert entered.wait(2)
    with pytest.raises(ValueError, match='current recovery operation'):
        manager.start({'action': 'import'})
    manager.action(job['id'], {'action': 'cancel'})
    assert finish(manager, job)['status'] == 'cancelled'
    manager.worker.shutdown()


def test_recovery_artifacts_do_not_enter_file_alert_pipeline(config, db, backend, tmp_path):
    service = MonitoringService(config, db=db, usb_backend=backend)
    manager = RecoveryJobs(service)
    output = tmp_path / 'recovered_confidential.txt'
    manager.save({'id': 'owned', 'status': 'completed', 'results': [{'path': str(output)}]})
    output.write_text('recovery evidence')
    assert service.files.handle('CREATED', str(output)) is None
    ordinary = tmp_path / 'ordinary.txt'
    ordinary.write_text('still monitored')
    assert service.files.handle('CREATED', str(ordinary)) is not None
    manager.worker.shutdown()
