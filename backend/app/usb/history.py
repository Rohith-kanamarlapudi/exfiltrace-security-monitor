"""Additive USB observations and change history in the existing SQLite database."""
import json
from datetime import datetime, timezone
from .inspection import metadata_changes

SCHEMA = '''
CREATE TABLE IF NOT EXISTS usb_observations (
 identity TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
 fingerprint TEXT, characteristics TEXT
);
CREATE TABLE IF NOT EXISTS usb_fingerprint_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT, identity TEXT NOT NULL, timestamp TEXT NOT NULL,
 fingerprint TEXT NOT NULL, previous_fingerprint TEXT, changes TEXT NOT NULL, version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usb_history_identity ON usb_fingerprint_history(identity, id);
'''


class UsbHistory:
    def __init__(self, db):
        self.db = db
        self._new = set()
        with db.connect() as conn:
            conn.executescript(SCHEMA)

    def observe(self, device):
        identity = device['device_id']
        # Simulation cannot contaminate genuine Windows identity history.
        identity = device.get('observationSource', 'unknown') + ':' + identity
        now = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        fp = device.get('fingerprint')
        with self.db.connect() as conn:
            row = conn.execute('SELECT * FROM usb_observations WHERE identity=?', (identity,)).fetchone()
            if row is None:
                self._new.add(identity)
                conn.execute('INSERT INTO usb_observations(identity, first_seen, last_seen) VALUES (?, ?, ?)', (identity, now, now))
            else:
                conn.execute('UPDATE usb_observations SET last_seen=? WHERE identity=?', (now, identity))
            if fp and row and row['characteristics']:
                old_metadata = json.loads(row['characteristics'])
                # Property unavailability is not a comparable characteristic change.
                lost = [k for k in ('manufacturer', 'product', 'vendorId', 'productId')
                        if old_metadata.get(k) is not None and fp['characteristics'].get(k) is None]
                for interface in fp['characteristics']['interfaces']:
                    peers = [i for i in old_metadata.get('interfaces', [])
                             if i.get('pnpClass') == interface.get('pnpClass') and i.get('functions') == interface.get('functions')]
                    for key in ('hardwareIds', 'compatibleIds'):
                        if peers and all(i.get(key) for i in peers) and not interface.get(key):
                            lost.append('interfaces.' + key)
                if lost:
                    fp = None
                    device['fingerprint'] = None
                    inspection = device.setdefault('inspection', {})
                    inspection['completeness'] = 'partial'
                    inspection.setdefault('diagnostics', []).append('Previously available metadata missing: ' + ', '.join(lost))
            if fp and (not row or row['fingerprint'] != fp['sha256']):
                previous = row['fingerprint'] if row else None
                old = json.loads(row['characteristics']) if row and row['characteristics'] else None
                new = fp['characteristics']
                changes = metadata_changes(old, new)
                conn.execute('INSERT INTO usb_fingerprint_history(identity,timestamp,fingerprint,previous_fingerprint,changes,version) VALUES (?,?,?,?,?,?)',
                             (identity, now, fp['sha256'], previous, json.dumps(changes), fp['version']))
                conn.execute('UPDATE usb_observations SET fingerprint=?,characteristics=? WHERE identity=?',
                             (fp['sha256'], json.dumps(new), identity))
            current = conn.execute('SELECT * FROM usb_observations WHERE identity=?', (identity,)).fetchone()
            rows = conn.execute('SELECT * FROM usb_fingerprint_history WHERE identity=? ORDER BY id DESC', (identity,)).fetchall()
        history = [{'timestamp': r['timestamp'], 'sha256': r['fingerprint'], 'previousFingerprint': r['previous_fingerprint'],
                    'version': r['version'], 'changes': json.loads(r['changes'])} for r in rows]
        device['observation'] = {'firstSeen': current['first_seen'], 'lastSeen': current['last_seen'],
                                 'newlyObserved': identity in self._new, 'currentFingerprint': current['fingerprint'],
                                 'previousFingerprint': history[0]['previousFingerprint'] if history else None,
                                 'history': history, 'fingerprintRetained': not bool(fp) and bool(current['fingerprint'])}
        return device

    def records(self):
        """Historical observations remain readable even while devices are disconnected."""
        with self.db.connect() as conn:
            rows = conn.execute('SELECT * FROM usb_observations ORDER BY last_seen DESC').fetchall()
            histories = conn.execute('SELECT * FROM usb_fingerprint_history ORDER BY id DESC').fetchall()
        by_identity = {}
        for h in histories:
            by_identity.setdefault(h['identity'], []).append({'timestamp': h['timestamp'], 'sha256': h['fingerprint'],
                'previousFingerprint': h['previous_fingerprint'], 'version': h['version'], 'changes': json.loads(h['changes'])})
        return [{'identity': r['identity'], 'firstSeen': r['first_seen'], 'lastSeen': r['last_seen'],
                 'currentFingerprint': r['fingerprint'],
                 'history': by_identity.get(r['identity'], []),
                 'characteristics': json.loads(r['characteristics']) if r['characteristics'] else None} for r in rows]
