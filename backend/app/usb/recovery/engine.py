"""Bounded raw-image validation and cancellable Sleuth Kit operations."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import time

LIMITATION = ('Unverified reconstruction: a deleted entry does not prove recoverability. '
              'FAT chains may be cleared; fragmentation, reused clusters and overwritten bytes '
              'can produce incorrect content even when the output size matches.')


class Cancelled(Exception):
    pass


def check(cancel):
    if cancel.is_set():
        raise Cancelled('Cancelled by user.')


def fat32_geometry(stream, offset=0):
    stream.seek(offset)
    boot = stream.read(512)
    if len(boot) != 512 or boot[510:512] != b'\x55\xaa':
        raise ValueError('Missing FAT32 boot signature; unsupported or malformed image.')
    bps = struct.unpack_from('<H', boot, 11)[0]
    spc, reserved, fats = boot[13], struct.unpack_from('<H', boot, 14)[0], boot[16]
    total, fat = struct.unpack_from('<I', boot, 32)[0], struct.unpack_from('<I', boot, 36)[0]
    roots, smallfat = struct.unpack_from('<H', boot, 17)[0], struct.unpack_from('<H', boot, 22)[0]
    root = struct.unpack_from('<I', boot, 44)[0]
    if (bps not in (512, 1024, 2048, 4096) or spc not in (1, 2, 4, 8, 16, 32, 64, 128)
            or not reserved or fats not in (1, 2) or not fat or roots or smallfat
            or total <= reserved + fats * fat):
        raise ValueError('Only valid FAT32 filesystems are supported (not FAT12/16, exFAT or NTFS).')
    clusters = (total - reserved - fats * fat) // spc
    if not 65525 <= clusters < 0x0ffffff5 or fat * bps // 4 < clusters + 2 or not 2 <= root < clusters + 2:
        raise ValueError('Invalid FAT32 cluster geometry.')
    return {'sizeBytes': total * bps, 'sectorSize': bps, 'offsetBytes': offset}


def image_geometry(path, offset):
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset % 512:
        raise ValueError('Filesystem byte offset must be a nonnegative multiple of 512.')
    with open(path, 'rb') as stream:
        result = fat32_geometry(stream, offset)
    if offset + result['sizeBytes'] > os.path.getsize(path):
        raise ValueError('Truncated image: FAT32 extent exceeds the available image bytes.')
    return result


def digest(path, cancel, progress=lambda _: None):
    size = os.path.getsize(path)
    value = hashlib.sha256()
    done = 0
    with open(path, 'rb') as stream:
        while chunk := stream.read(4 * 1024 * 1024):
            check(cancel)
            value.update(chunk)
            done += len(chunk)
            progress(done / max(size, 1))
    return value.hexdigest()


def safe_name(name):
    # Flatten paths, remove ADS, controls and Windows reserved punctuation. Prefix
    # also makes CON/PRN/AUX/NUL/COM*/LPT* harmless; never use an image path as output.
    leaf = re.split(r'[/\\]', name)[-1]
    leaf = re.sub(r'[<>:"/\\|?*\x00-\x1f\x7f]', '_', leaf).strip(' .')[:100]
    return 'recovered_' + (leaf or 'unnamed')


class SleuthKit:
    def __init__(self):
        directory = os.environ.get('EXFILTRACE_TSK_DIR')
        self.tools = {name: (str(Path(directory) / (name + ('.exe' if os.name == 'nt' else '')))
                            if directory else shutil.which(name)) for name in ('fls', 'icat', 'fsstat')}

    def available(self):
        return all(p and Path(p).is_file() for p in self.tools.values())

    def run(self, tool, args, cancel, output=None, max_bytes=16 * 1024 * 1024):
        if not self.available():
            raise ValueError('Install The Sleuth Kit and set EXFILTRACE_TSK_DIR to its bin folder; restart the backend.')
        # Temporary stdout/stderr avoid pipe deadlocks and unbounded RAM. Tools
        # only receive our local copied raw image; no shell or live device path.
        with tempfile.TemporaryFile() as captured, tempfile.TemporaryFile() as errors:
            target = output if output is not None else captured
            proc = subprocess.Popen([self.tools[tool], *map(str, args)], stdout=target, stderr=errors,
                                    creationflags=0x08000000 if os.name == 'nt' else 0)
            started = time.monotonic()
            try:
                while proc.poll() is None:
                    check(cancel)
                    if time.monotonic() - started > 600:
                        raise ValueError('Sleuth Kit exceeded its 10-minute operation limit.')
                    if os.fstat(target.fileno()).st_size > max_bytes or os.fstat(errors.fileno()).st_size > 1024 * 1024:
                        raise ValueError('Recovery tool exceeded its bounded output limit.')
                    cancel.wait(0.1)
                check(cancel)
                errors.seek(0)
                error = errors.read(1024 * 1024).decode('utf-8', 'replace').strip()
                if proc.returncode or error:
                    raise ValueError(f'{tool}: ' + (error[:2000] or f'exit {proc.returncode}'))
                if os.fstat(target.fileno()).st_size > max_bytes:
                    raise ValueError('Recovery output exceeded the expected size limit.')
                captured.seek(0)
                return captured.read(max_bytes).decode('utf-8', 'replace') if output is None else None
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.wait()

    @staticmethod
    def args(image, offset):
        # -b 512 makes -o an unambiguous byteOffset/512 even on 4K FAT volumes.
        return ['-i', 'raw', '-f', 'fat32', '-b', '512', '-o', offset // 512, image]

    def scan(self, image, offset, cancel):
        geometry = image_geometry(image, offset)
        self.run('fsstat', self.args(image, offset), cancel)
        body = self.run('fls', ['-r', '-d', '-F', '-m', '/', *self.args(image, offset)], cancel)
        candidates = []
        for line in body.splitlines():
            check(cancel)
            fields = line.split('|')
            if len(fields) != 11 or not re.fullmatch(r'\d+', fields[2]) or not fields[6].isdigit():
                raise ValueError('Unrecognized deleted-entry output; scan was not accepted as complete.')
            size = int(fields[6])
            if size > geometry['sizeBytes']:
                raise ValueError('Malformed deleted entry declares a size larger than the filesystem.')
            candidates.append({'id': fields[2], 'filename': fields[1].removeprefix('/').removesuffix(' (deleted)'),
                               'sizeBytes': size, 'status': 'uncertain', 'limitations': LIMITATION})
            if len(candidates) > 10000:
                raise ValueError('Scan exceeded the 10,000-candidate limit.')
        return candidates

    def recover(self, image, offset, candidate, output, cancel):
        self.run('icat', ['-r', *self.args(image, offset), candidate['id']], cancel,
                 output=output, max_bytes=candidate['sizeBytes'])
        if os.fstat(output.fileno()).st_size != candidate['sizeBytes']:
            raise ValueError('Reconstruction is incomplete: output length differs from deleted metadata.')
