"""Memory-only overlay and isolated history, seeded from a connected physical device.

All methods are called under the monitor's polling lock. No Windows APIs or real
database/alert writes are performed here. Reset closes the isolated database.
"""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import sqlite3

from .history import UsbHistory
from .processing import process_observation, unexpected_keyboard


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def unavailable_reason(device):
    if device.get('observationSource') != 'windows':
        return 'Only a connected physical Windows USB observation can be selected.'
    inspection = device.get('inspection') or {}
    if inspection.get('completeness') != 'complete' or not device.get('fingerprint'):
        return 'A complete, unmodified inspection and stable fingerprint are required; retry after collection recovers.'
    functions = {f for i in inspection.get('interfaces', []) for f in i.get('functions', [])}
    if 'keyboard' in functions:
        return 'This device already has a keyboard function; the addition demonstration is unavailable.'
    if 'storage' not in functions or functions - {'storage', 'composite', 'other'}:
        return 'A storage-only baseline is required; this device has non-storage functions or no storage function.'
    if any('other' in i.get('functions', []) and i.get('instanceId') != device['device_id']
           for i in inspection.get('interfaces', [])):
        return 'An unidentified non-storage child function prevents a suitable storage-only baseline.'
    if not inspection.get('physicalInstanceId') or inspection['physicalInstanceId'] != device['device_id']:
        return 'The physical device relationship is unresolved.'
    return None


class MemoryDatabase:
    def __init__(self):
        self.connection = sqlite3.connect(':memory:', check_same_thread=False)
        self.connection.row_factory = sqlite3.Row

    @contextmanager
    def connect(self):
        try:
            yield self.connection
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise


class UsbSimulation:
    def __init__(self, enabled=False):
        self.enabled = enabled is True
        self.db = None
        self.history = None
        self.baseline = None
        self.modified = None
        self.alert = None
        self.phase = 'idle'
        self.message = 'Choose a connected storage-only USB device.' if self.enabled else 'Simulation is disabled by configuration.'

    def clear(self, phase='idle', message='Simulation cleared; only actual observations are displayed.'):
        if self.db:
            self.db.connection.close()
        self.db = self.history = self.baseline = self.modified = self.alert = None
        self.phase, self.message = phase, message

    def activate(self, actual):
        if not self.enabled:
            raise PermissionError('USB simulation is disabled by configuration.')
        reason = unavailable_reason(actual)
        if reason:
            raise ValueError(reason)
        if self.baseline:
            raise ValueError('Clear the active simulation before choosing another device.')
        # No modified observation or finding is constructed by activation.
        self.db = MemoryDatabase()
        self.history = UsbHistory(self.db)
        self.baseline = deepcopy(actual)
        self.baseline['observationSource'] = 'simulation'
        self.baseline['actualDeviceId'] = actual['device_id']
        self.baseline['simulated'] = False  # unmodified physical baseline in isolated context
        process_observation(self.baseline, self.history)
        self.phase = 'armed'
        self.message = 'Unmodified physical baseline seeded. Waiting for the next complete inspection cycle.'

    def cycle(self, devices, complete):
        if not self.baseline:
            return
        identity = self.baseline['device_id']
        if not complete:
            self.phase = 'paused'
            self.message = 'Inspection is partial or failed; simulation comparison is paused.'
            return
        actual = devices.get(identity)
        if actual is None:
            self.clear('cancelled', 'Selected device disconnected. Simulation cancelled; reconnect does not reactivate it.')
            return
        if actual.get('inspection', {}).get('completeness') != 'complete' or not actual.get('fingerprint'):
            self.phase = 'paused'
            self.message = 'Selected observation is incomplete; waiting for reliable inspection.'
            return
        if actual['fingerprint']['sha256'] != self.baseline['fingerprint']['sha256']:
            self.clear('cancelled', 'Actual device characteristics changed; select it again after reviewing the new physical baseline.')
            return
        modified = deepcopy(actual)
        modified['observationSource'] = 'simulation'
        modified['simulated'] = True
        modified['actualDeviceId'] = identity
        modified['inspection']['simulated'] = True
        modified['inspection']['interfaces'].append({
            'instanceId': 'SIMULATED\\KEYBOARD\\' + identity, 'parentId': identity,
            'containerId': actual['inspection'].get('containerId'), 'name': 'SIMULATED keyboard/HID overlay',
            'pnpClass': 'Keyboard', 'hardwareIds': ['EXFILTRACE_SIMULATION\\KEYBOARD'],
            'compatibleIds': ['EXFILTRACE_SIMULATION\\HID'], 'functions': ['hid', 'keyboard'],
            'usbDescriptorClass': None, 'simulated': True})
        modified['inspection']['functions'] = sorted(set(actual['inspection']['functions']) | {'hid', 'keyboard'})
        process_observation(modified, self.history)
        self.modified = modified
        finding = unexpected_keyboard(self.baseline['fingerprint']['characteristics'], modified['fingerprint']['characteristics'])
        if finding and not self.alert:
            self.alert = finding | {'id': 'simulated-keyboard-addition', 'simulated': True,
                'title': 'SIMULATED — possible USB impersonation', 'timestamp': now(),
                'device': {'deviceId': identity, 'name': actual['name'], 'vendorId': actual['vendor_id'],
                           'productId': actual['product_id'], 'mounts': deepcopy(actual['mounts'])},
                'previousFingerprint': self.baseline['fingerprint']['sha256'],
                'currentFingerprint': modified['fingerprint']['sha256'],
                'explanation': 'SIMULATED observation overlay only. ' + finding['explanation'] +
                               ' No physical keyboard, firmware modification or keystrokes were observed or executed.'}
        self.phase = 'finding' if self.alert else 'processed'
        self.message = 'Synthetic keyboard/HID addition processed through metadata hashing, isolated history and the change rule.'

    def status(self, devices, healthy):
        return deepcopy({'enabled': self.enabled, 'phase': self.phase, 'message': self.message,
                         'actualDeviceId': self.baseline['device_id'] if self.baseline else None,
                         'devices': [{'deviceId': d['device_id'], 'name': d['name'], 'vendorId': d['vendor_id'],
                                      'productId': d['product_id'], 'mounts': d['mounts'],
                                      'unavailableReason': unavailable_reason(d) if healthy else 'USB query is partial or failed; retry after recovery.'}
                                     for d in devices if d.get('observationSource') == 'windows'],
                         'observation': self.modified, 'alert': self.alert,
                         'simulatedAlertCount': int(self.alert is not None)})
