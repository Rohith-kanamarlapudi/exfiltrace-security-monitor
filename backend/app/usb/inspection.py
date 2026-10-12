"""Windows PnP metadata inspection; deliberately not a USB descriptor reader."""
import hashlib
import json
import re

from .base import normalize_device, UsbBackendError

VERSION = 'windows-pnp-metadata-v1'


def canonical_metadata(device):
    """No identity, topology, connection, mounts or observation fields in hash."""
    interfaces = [{k: i.get(k) for k in ('pnpClass', 'hardwareIds', 'compatibleIds', 'functions')}
                  for i in device['inspection']['interfaces']]
    for i in interfaces:
        for key in ('hardwareIds', 'compatibleIds', 'functions'):
            i[key] = sorted(set(i[key] or []))
    interfaces.sort(key=lambda i: json.dumps(i, sort_keys=True))
    return {'version': VERSION, 'vendorId': device['vendor_id'], 'productId': device['product_id'],
            'manufacturer': device['inspection']['manufacturer'], 'product': device['inspection']['product'],
            'interfaces': interfaces}


def fingerprint(device):
    value = canonical_metadata(device)
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return {'version': VERSION, 'kind': 'metadata', 'sha256': hashlib.sha256(encoded).hexdigest(), 'characteristics': value}


def _ids(value):
    return sorted({str(v).upper() for v in (value or []) if v})


def inspect_nodes(payload, disks):
    if not isinstance(payload, dict) or not isinstance(payload.get('nodes'), list):
        raise UsbBackendError('Invalid PnP inspection snapshot')
    nodes = {n['instanceId'].upper(): n for n in payload['nodes'] if n.get('instanceId')}
    roots = {key: n for key, n in nodes.items() if re.match(r'^USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}', key)
             and '&MI_' not in key.split('\\')[1]}

    def root_for(key):
        seen = set()
        while key and key not in seen:
            # Bluetooth peers are separate physical devices behind a USB radio,
            # not interfaces of that radio. Do not fingerprint their presence.
            if key.startswith(('BTH', 'SWD\\')):
                return None
            if key in roots:
                return key
            seen.add(key)
            key = str(nodes.get(key, {}).get('parentId') or '').upper()
        return None

    groups = {key: [] for key in roots}
    for key, node in nodes.items():
        root = root_for(key)
        if root and key.startswith(('USB\\', 'USBSTOR\\', 'HID\\', 'SCSI\\')):
            groups[root].append(node)
    result = []
    assigned = set()
    # Unknown ancestry is global uncertainty: do not silently drop an interface.
    topology_errors = [n['instanceId'] for n in nodes.values() if n.get('errors')]
    topology_errors += [key for key in nodes if key.startswith('USB\\VID_') and root_for(key) is None]
    diagnostics = [f"{n['instanceId']}: {error}" for n in nodes.values() for error in n.get('errors', [])]
    diagnostics += ['Unresolved USB ancestry: ' + key for key in nodes
                    if key.startswith('USB\\VID_') and root_for(key) is None]
    for key, root in roots.items():
        interfaces = []
        for n in groups[key]:
            cls = n.get('pnpClass')
            functions = {'DiskDrive': 'storage', 'HIDClass': 'hid', 'Keyboard': 'keyboard', 'Mouse': 'mouse',
                         'Camera': 'camera', 'Image': 'imaging', 'MEDIA': 'audio', 'Bluetooth': 'bluetooth',
                         'Net': 'network interface', 'Printer': 'printer'}
            interfaces.append({k: n.get(k) for k in ('instanceId', 'parentId', 'containerId', 'name', 'pnpClass')} |
                              {'hardwareIds': _ids(n.get('hardwareIds')), 'compatibleIds': _ids(n.get('compatibleIds')),
                               'functions': ['composite'] if 'USB\\COMPOSITE' in _ids(n.get('compatibleIds')) else [functions.get(cls, 'other')], 'usbDescriptorClass': None})
        matched = [d for d in disks if root_for(d['device_id'].upper()) == key]
        assigned.update(d['device_id'] for d in matched)
        vid, pid = re.search(r'VID_([0-9A-F]{4})&PID_([0-9A-F]{4})', key).groups()
        # CM_DEVCAP_UNIQUEID (0x10) is Windows' indication of a bus-provided unique ID.
        # Without it, the instance suffix can be a generated location identifier.
        serial = key.rsplit('\\', 1)[-1] if isinstance(root.get('capabilities'), int) and root['capabilities'] & 0x10 else None
        first = matched[0] if matched else {}
        dev = normalize_device(first | {'device_id': key, 'vendor_id': vid, 'product_id': pid,
                               'serial_number': serial, 'name': root.get('name') or first.get('name'),
                               'mounts': sorted({m for d in matched for m in d['mounts']})})
        dev['inspection'] = {'physicalInstanceId': key, 'parentId': root.get('parentId'), 'containerId': root.get('containerId'),
                             'identityScope': 'Windows instance (may change by port without a serial)',
                             'serialSource': 'PnP unique instance suffix' if serial else None,
                             'manufacturer': root.get('manufacturer'), 'product': root.get('name'),
                             'interfaces': sorted(interfaces, key=lambda i: i['instanceId']),
                             'functions': sorted({f for i in interfaces for f in i['functions']}),
                             'storageDeviceIds': [d['device_id'] for d in matched],
                             'completeness': 'partial' if topology_errors else 'complete',
                             'diagnostics': diagnostics,
                             'rawDescriptors': None, 'usbVersion': None, 'maxPower': None, 'firmwareRevision': None,
                             'badUsbVerdict': None, 'writeProtection': None}
        dev['fingerprint'] = fingerprint(dev) if not topology_errors else None
        result.append(dev)
    # Keep storage usable even when Windows provides no resolvable ancestry.
    for disk in disks:
        if disk['device_id'] not in assigned:
            disk['serial_number'] = None  # storage instance suffix is not a proven USB serial
            disk['inspection'] = {'completeness': 'partial', 'interfaces': [], 'functions': ['storage'],
                                  'physicalInstanceId': None, 'parentId': None, 'containerId': None,
                                  'manufacturer': None, 'product': None, 'serialSource': None,
                                  'rawDescriptors': None, 'usbVersion': None, 'maxPower': None,
                                  'firmwareRevision': None, 'badUsbVerdict': None, 'writeProtection': None,
                                  'diagnostics': diagnostics + ['Storage ancestry unavailable; not merged by VID/PID or serial']}
            disk['fingerprint'] = None
            result.append(disk)
    return result
