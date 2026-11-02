"""Single-worker recovery jobs with additive SQLite records and cancellation."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import threading
import uuid

from ...db import now_iso
from . import windows
from .engine import Cancelled, LIMITATION, SleuthKit, check, digest, fat32_geometry, image_geometry, safe_name

BUSY = {'acquiring', 'importing', 'scanning', 'recovering'}


class RecoveryJobs:
    def __init__(self, service, tool=None):
        self.service, self.db = service, service.db
        self.tool = tool or SleuthKit()
        self.lock = threading.RLock()
        self.worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix='usb-recovery')
        self.active = None
        self.cancel_event = threading.Event()
        self.owned_paths = set()
        with self.db.connect() as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS usb_recovery_jobs (id TEXT PRIMARY KEY, updated_at TEXT NOT NULL, data TEXT NOT NULL)')
            for row in conn.execute('SELECT data FROM usb_recovery_jobs').fetchall():
                job = json.loads(row['data'])
                self.remember_paths(job)
                if job['status'] in BUSY:
                    job.update(status='interrupted', error='Backend stopped during this job. Partial output is not a completed image or recovery.')
                    self.save(job)
        if hasattr(service, 'files'):
            service.files.is_recovery_artifact = self.is_owned

    def remember_paths(self, job):
        for key in ('imagePath', 'partialImagePath', 'outputFolder'):
            if job.get(key):
                self.owned_paths.add(os.path.normcase(os.path.abspath(job[key])))
        for result in job.get('results', []):
            if result.get('path'):
                self.owned_paths.add(os.path.normcase(os.path.abspath(result['path'])))

    def is_owned(self, path):
        value = os.path.normcase(os.path.abspath(path))
        # Snapshot avoids iteration over a set being extended by the worker.
        return any(value == p or value.startswith(p + os.sep) for p in self.owned_paths.copy())

    def save(self, job):
        self.remember_paths(job)
        job['updatedAt'] = now_iso()
        with self.db.connect() as conn:
            conn.execute('INSERT OR REPLACE INTO usb_recovery_jobs VALUES (?,?,?)',
                         (job['id'], job['updatedAt'], json.dumps(job)))

    def get(self, job_id):
        with self.db.connect() as conn:
            row = conn.execute('SELECT data FROM usb_recovery_jobs WHERE id=?', (job_id,)).fetchone()
        if not row:
            raise ValueError('Recovery job not found.')
        return json.loads(row['data'])

    def status(self):
        with self.db.connect() as conn:
            jobs = [json.loads(r['data']) for r in conn.execute('SELECT data FROM usb_recovery_jobs ORDER BY updated_at DESC LIMIT 50')]
        devices = []
        for d in self.service.usb.devices():
            if 'storage' not in d.get('inspection', {}).get('functions', []) and not d['mounts']:
                continue
            for mount in d['mounts'] or [None]:
                eligible = (d.get('observationSource') == 'windows' and mount is not None
                            and d.get('inspection', {}).get('completeness') == 'complete'
                            and not self.service.usb.last_error)
                devices.append({'deviceId': d['device_id'], 'name': d['name'], 'mount': mount,
                                'filesystem': d.get('filesystem'), 'eligible': eligible,
                                'note': 'FAT32 is verified again before acquisition; other filesystems are unsupported.' if eligible
                                else 'Requires a connected, mounted physical storage device and complete inspection.'})
        return {'jobs': jobs, 'devices': devices, 'toolsAvailable': self.tool.available(),
                'limitations': LIMITATION, 'activeJobId': self.active}

    def start(self, body):
        action = body.get('action')
        if action not in ('acquire', 'import'):
            raise ValueError('Choose acquire or import.')
        with self.lock:
            if self.active:
                raise ValueError('Wait for or cancel the current recovery operation.')
            job = {'id': uuid.uuid4().hex, 'createdAt': now_iso(), 'status': 'acquiring' if action == 'acquire' else 'importing',
                   'phase': 'Validating paths and source', 'progress': 0, 'error': None, 'sourceDeviceId': body.get('deviceId'),
                   'sourceMount': body.get('mount'), 'sourceKind': action, 'imagePath': None, 'imageSha256': None,
                   'imageComplete': False, 'candidates': [], 'results': [], 'limitations': LIMITATION,
                   'offsetBytes': body.get('offsetBytes', 0)}
            self.launch(job, lambda: self.acquire(job, body))
            return deepcopy(job)

    def launch(self, job, operation):
        self.active = job['id']
        self.cancel_event = threading.Event()
        self.save(job)

        def run():
            try:
                operation()
            except Cancelled as exc:
                job.update(status='cancelled', error=str(exc))
            except Exception as exc:
                hint = ' Run the backend as Administrator for physical imaging.' if isinstance(exc, PermissionError) else ''
                job.update(status='failed', error=f'{type(exc).__name__}: {exc}{hint}')
            finally:
                with self.lock:
                    self.save(job)
                    self.active = None
        self.worker.submit(run)

    def action(self, job_id, body):
        with self.lock:
            action = body.get('action')
            if action == 'cancel':
                if self.active != job_id:
                    raise ValueError('This job has no active operation.')
                self.cancel_event.set()
                return self.get(job_id)
            if self.active:
                raise ValueError('Wait for or cancel the current recovery operation.')
            job = self.get(job_id)
            if not job['imageComplete']:
                raise ValueError('A complete acquired/imported image is required. Start a new job.')
            if action == 'scan':
                job.update(status='scanning', progress=0, phase='Verifying image SHA-256', error=None)
                self.launch(job, lambda: self.scan(job))
            elif action == 'recover':
                ids = body.get('candidateIds')
                if not isinstance(ids, list) or not ids or any(not isinstance(i, str) for i in ids):
                    raise ValueError('Select one or more scanned candidate IDs.')
                selected = [c for c in job['candidates'] if c['id'] in ids]
                if len(selected) != len(set(ids)):
                    raise ValueError('Unknown candidate ID; scan the image first.')
                job.update(status='recovering', progress=0, phase='Verifying image SHA-256', error=None)
                self.launch(job, lambda: self.recover(job, selected, body.get('outputFolder')))
            else:
                raise ValueError('Choose scan, recover or cancel.')
            return deepcopy(job)

    def progress(self, job, value, phase=None):
        percent = int(value * 100)
        if job['progress'] != percent or phase:
            job['progress'] = percent
            if phase:
                job['phase'] = phase
            self.save(job)

    @staticmethod
    def space(folder, size):
        if shutil.disk_usage(folder).free < size + 16 * 1024 * 1024:
            raise ValueError('Insufficient free disk space (including 16 MiB safety margin).')

    def source(self, job):
        usb = self.service.usb
        with usb._poll_lock:
            usb.poll_once()
            d = next((d for d in usb.devices() if d['device_id'] == job['sourceDeviceId']), None)
            if (usb.last_error or not d or d.get('observationSource') != 'windows'
                    or d.get('inspection', {}).get('completeness') != 'complete'
                    or job['sourceMount'] not in d['mounts']):
                raise ValueError('Cannot verify the selected physical USB is still connected with a complete observation.')
            ids = d['inspection'].get('storageDeviceIds', [])
            rows = [v for v in windows.inventory() if v['mount'] == job['sourceMount'] and v['usb']
                    and v['diskId'].upper() in {i.upper() for i in ids}]
            if len(rows) != 1 or rows[0]['filesystem'] != 'FAT32':
                raise ValueError('The selected volume is not a verified FAT32 USB volume; other filesystems are unsupported.')
            job['sourceDeviceName'] = d['name']
            job['sourceDiskId'] = rows[0]['diskId']
            return rows[0]

    def copy(self, stream, size, path, job):
        self.space(path.parent, size)
        sha = hashlib.sha256()
        done = 0
        # Exclusive creation protects existing files; .partial is never scanned.
        with open(path, 'xb') as target:
            while done < size:
                check(self.cancel_event)
                chunk = stream.read(min(4 * 1024 * 1024, size - done))
                if not chunk:
                    raise ValueError('Source ended early or disconnected; image is incomplete.')
                target.write(chunk)
                sha.update(chunk)
                done += len(chunk)
                self.progress(job, done / size)
            target.flush()
            os.fsync(target.fileno())
        check(self.cancel_event)
        return sha.hexdigest()

    def acquire(self, job, body):
        folder = windows.local_path(body.get('imageFolder'))
        partial = folder / (job['id'] + '.partial')
        final = folder / (job['id'] + '.img')
        job['partialImagePath'] = str(partial)
        self.save(job)
        try:
            if body['action'] == 'import':
                source = windows.local_path(body.get('imagePath'), directory=False)
                image_geometry(source, job['offsetBytes'])
                job['importedFrom'] = str(source)
                with open(source, 'rb') as stream:
                    size = os.fstat(stream.fileno()).st_size
                    before = os.fstat(stream.fileno())
                    sha = self.copy(stream, size, partial, job)
                    after = os.fstat(stream.fileno())
                    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                        raise ValueError('Import source changed during copying; retry from a stable image.')
            else:
                source = self.source(job)
                job['offsetBytes'] = 0
                with windows.open_volume(job['sourceMount'], source['diskNumber']) as stream:
                    size = fat32_geometry(stream)['sizeBytes']
                    if size > source['partitionSize']:
                        raise ValueError('FAT32 geometry exceeds the Windows partition size.')
                    stream.seek(0)
                    sha = self.copy(stream, size, partial, job)
                if not any(v == source for v in windows.inventory()):
                    raise ValueError('Storage mapping changed during acquisition; image not accepted.')
            image_geometry(partial, job['offsetBytes'])
            # hard link is atomic and refuses replacement on both Windows/Unix.
            self.owned_paths.add(os.path.normcase(str(final)))
            os.link(partial, final)
            partial.unlink()
            job.update(imagePath=str(final), imageSha256=sha, imageSizeBytes=size, imageComplete=True,
                       status='imageReady', phase='Image ready to scan', progress=100)
        finally:
            # Keep interrupted bytes explicitly marked .partial for review. No
            # source or user-existing file is removed by this workflow.
            self.save(job)

    def verify(self, job):
        path = windows.local_path(job['imagePath'], directory=False)
        if digest(path, self.cancel_event, lambda p: self.progress(job, p * .2)) != job['imageSha256']:
            raise ValueError('Image SHA-256 changed since acquisition; refusing to use stale scan results.')
        return path

    def scan(self, job):
        path = self.verify(job)
        self.progress(job, .2, 'Scanning deleted FAT32 directory entries (indeterminate)')
        candidates = self.tool.scan(path, job['offsetBytes'], self.cancel_event)
        # Verify again to avoid publishing candidates from an image edited mid-scan.
        if digest(path, self.cancel_event) != job['imageSha256']:
            raise ValueError('Image changed while scanning.')
        job.update(candidates=candidates, status='scanned', phase='Review uncertain candidates', progress=100)

    def recover(self, job, candidates, folder):
        folder = windows.local_path(folder)
        path = self.verify(job)
        self.space(folder, sum(c['sizeBytes'] for c in candidates))
        # A new directory per attempt guarantees no replacement of previous output.
        destination = folder / ('exfiltrace-recovery-' + uuid.uuid4().hex)
        job['outputFolder'] = str(destination)
        self.save(job)
        destination.mkdir()
        attempt = []
        for index, candidate in enumerate(candidates):
            check(self.cancel_event)
            name = candidate['id'] + '_' + safe_name(candidate['filename']) + '.unverified'
            output = destination / name
            result = {'candidateId': candidate['id'], 'filename': candidate['filename'], 'path': str(output),
                      'timestamp': now_iso(), 'status': 'unverified', 'limitations': LIMITATION}
            try:
                with open(output, 'xb') as stream:
                    self.tool.recover(path, job['offsetBytes'], candidate, stream, self.cancel_event)
                result['sizeBytes'] = output.stat().st_size
                result['sha256'] = digest(output, self.cancel_event)
            except Cancelled:
                result.update(status='cancelled', error='Partial output; do not treat as recovered.')
                raise
            except Exception as exc:
                result.update(status='failed', error=str(exc))
            finally:
                job['results'].append(result)
                attempt.append(result)
                self.progress(job, .2 + .7 * (index + 1) / len(candidates), 'Reconstructing selected files')
        if digest(path, self.cancel_event) != job['imageSha256']:
            for result in attempt:
                result.update(status='invalid', error='Image changed during recovery.')
            raise ValueError('Image changed during recovery; all output from this attempt is invalid.')
        job.update(status='completed', phase='Recovery attempts finished; validate output independently', progress=100)
