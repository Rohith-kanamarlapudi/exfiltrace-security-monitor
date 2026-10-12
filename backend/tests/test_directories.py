import json
import os

import pytest

from app.api import create_app
from app.config import Config
from app.service import MonitoringService
from tests.conftest import make_device, wait_for


@pytest.fixture
def folders(dirs, db, backend):
    config_path = dirs['root'] / 'config.json'
    config_path.write_text(json.dumps({'monitored_directories': [str(dirs['monitored'])],
        'database_path': db.path, 'usb': {'backend': 'none'}, 'untouched': {'value': 42}}))
    config = Config.load(str(config_path))
    service = MonitoringService(config, db=db, usb_backend=backend, async_detection=False)
    client = create_app(service=service, autostart=False).test_client()
    yield service, client, config_path
    service.stop()


def test_live_add_edit_remove_and_restart_persistence(folders, dirs, db):
    service, client, path = folders
    first = dirs['root'] / 'Folder with spaces'; first.mkdir()
    replacement = dirs['root'] / 'replacement'; replacement.mkdir()
    service.start()
    assert client.post('/api/config/directories', json={'action': 'add', 'path': str(first)}).status_code == 200
    (first / 'ordinary.txt').write_text('ordinary contents')
    assert wait_for(lambda: db.query_file_events(search='ordinary.txt')[1] > 0)
    status = client.get('/api/config/directories').json['data']
    assert next(f for f in status['folders'] if f['path'] == str(first))['active']
    assert client.post('/api/config/directories', json={'action': 'edit', 'previousPath': str(first), 'path': str(replacement)}).status_code == 200
    assert str(first) not in [w['path'] for w in service.files.watches()]
    assert str(replacement) in [w['path'] for w in service.files.watches()]
    assert json.loads(path.read_text())['untouched'] == {'value': 42}
    service.stop()
    restarted = Config.load(str(path))
    assert str(replacement) in restarted.get('monitored_directories')
    assert str(first) not in restarted.get('monitored_directories')
    restarted_service = MonitoringService(restarted, db=db, usb_backend=service.usb.backend, async_detection=False)
    restarted_service.start()
    try:
        assert next(f for f in restarted_service.directory_status()['folders'] if f['path'] == str(replacement))['active']
    finally:
        restarted_service.stop()
    assert client.post('/api/config/directories', json={'action': 'remove', 'path': str(replacement)}).status_code == 200
    assert replacement.is_dir() and first.is_dir() and (first / 'ordinary.txt').is_file()
    assert str(replacement) not in Config.load(str(path)).get('monitored_directories')


def test_invalid_duplicate_and_non_directory_paths(folders, dirs):
    service, client, _ = folders
    file = dirs['root'] / 'file.txt'; file.write_text('x')
    for invalid in ('relative', '', str(file), str(dirs['root'] / 'missing'), '\\root-relative' if os.name == 'nt' else 'relative/path'):
        assert client.post('/api/config/directories', json={'action': 'add', 'path': invalid}).status_code == 400
    assert client.post('/api/config/directories', json={'action': 'add', 'path': str(dirs['monitored']) + os.sep}).status_code == 409
    assert client.post('/api/config/directories', json=[]).status_code == 400
    assert len(service.config.get('monitored_directories')) == 1


def test_failed_edit_watch_keeps_original_and_config(folders, dirs, monkeypatch):
    service, client, path = folders
    replacement = dirs['root'] / 'replacement'; replacement.mkdir()
    service.start()
    original = path.read_bytes()
    monkeypatch.setattr(service.files, 'add_watch', lambda p: False)
    response = client.post('/api/config/directories', json={'action': 'edit', 'previousPath': str(dirs['monitored']), 'path': str(replacement)})
    assert response.status_code == 503
    assert path.read_bytes() == original
    assert str(dirs['monitored']) in [w['path'] for w in service.files.watches()]


def test_failed_save_rolls_back_new_watch_and_memory(folders, dirs, monkeypatch):
    service, client, path = folders
    replacement = dirs['root'] / 'replacement'; replacement.mkdir()
    service.start(); original = path.read_bytes()
    def fail(*args):
        raise OSError('Injected save failure')
    monkeypatch.setattr('app.config.os.replace', fail)
    response = client.post('/api/config/directories', json={'action': 'edit', 'previousPath': str(dirs['monitored']), 'path': str(replacement)})
    assert response.status_code == 503 and 'persist' in response.json['error']
    assert path.read_bytes() == original
    assert service.config.get('monitored_directories') == [str(dirs['monitored'])]
    assert [w['path'] for w in service.files.watches()] == [str(dirs['monitored'])]


def test_usb_watches_separate_and_missing_folder_errors(folders, dirs):
    service, client, _ = folders
    service.usb.backend.devices = [make_device(dirs['usb'])]
    service.start()
    data = client.get('/api/config/directories').json['data']
    assert [w['path'] for w in data['usbDirectories']] == [str(dirs['usb'])]
    for action in ('add', 'remove'):
        assert client.post('/api/config/directories', json={'action': action, 'path': str(dirs['usb'])}).status_code == 409
    assert str(dirs['usb']) in [w['path'] for w in service.files.watches()]
    service.stop()
    assert not client.get('/api/config/directories').json['data']['folders'][0]['active']
    dirs['monitored'].rmdir()
    assert 'missing' in client.get('/api/config/directories').json['data']['folders'][0]['error']
    assert client.post('/api/config/directories', json={'action': 'remove', 'path': str(dirs['monitored'])}).status_code == 200


def test_edit_watch_happens_before_old_watch_removed(folders, dirs, monkeypatch):
    service, client, _ = folders
    replacement = dirs['root'] / 'replacement'; replacement.mkdir()
    service.start(); actions = []
    add, remove = service.files.add_watch, service.files.remove_watch
    def watch(path):
        actions.append(('watch', path)); return add(path)
    def unwatch(path):
        assert any(w['path'] == str(replacement) and w['active'] for w in service.files.watches())
        actions.append(('unwatch', path)); return remove(path)
    monkeypatch.setattr(service.files, 'add_watch', watch)
    monkeypatch.setattr(service.files, 'remove_watch', unwatch)
    assert client.post('/api/config/directories', json={'action': 'edit', 'previousPath': str(dirs['monitored']), 'path': str(replacement)}).status_code == 200
    assert actions == [('watch', str(replacement)), ('unwatch', str(dirs['monitored']))]


def test_edit_to_duplicate_and_stopped_edit_keep_original(folders, dirs):
    service, client, path = folders
    replacement = dirs['root'] / 'replacement'; replacement.mkdir()
    original = path.read_bytes()
    body = {'action': 'edit', 'previousPath': str(dirs['monitored']), 'path': str(replacement)}
    assert client.post('/api/config/directories', json=body).status_code == 409
    assert path.read_bytes() == original
    service.start()
    assert client.post('/api/config/directories', json={'action': 'add', 'path': str(replacement)}).status_code == 200
    assert client.post('/api/config/directories', json=body).status_code == 409
    assert str(dirs['monitored']) in service.config.get('monitored_directories')


def test_remove_save_failure_leaves_watch_and_config(folders, dirs, monkeypatch):
    service, client, path = folders
    service.start(); original = path.read_bytes()
    def fail(*args):
        raise OSError('Save denied')
    monkeypatch.setattr('app.config.os.replace', fail)
    response = client.post('/api/config/directories', json={'action': 'remove', 'path': str(dirs['monitored'])})
    assert response.status_code == 503
    assert path.read_bytes() == original and service.files.watches()[0]['active']


def test_added_folder_ordinary_file_copy_reaches_dashboard_alert_api(folders, dirs, db):
    import shutil
    service, client, _ = folders
    service.usb.backend.devices = [make_device(dirs['usb'])]
    service.start()
    added = dirs['root'] / 'new-source'; added.mkdir()
    assert client.post('/api/config/directories', json={'action': 'add', 'path': str(added)}).status_code == 200
    source = added / 'notes.txt'; source.write_text('ordinary unique transfer contents')
    shutil.copy(source, dirs['usb'] / source.name)
    assert wait_for(lambda: client.get('/api/alerts?verdict=VERIFIED_TRANSFER').json['total'] >= 1)
    alert = client.get('/api/alerts?verdict=VERIFIED_TRANSFER').json['data'][0]
    assert alert['severity'] == 'MEDIUM' and alert['rule'] == 'MONITORED_FILE_COPIED_TO_USB'
    assert any(str(added) in e for e in alert['evidence'])
