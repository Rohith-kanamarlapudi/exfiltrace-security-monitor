"""Shared observation pipeline and an explainable metadata-change rule.

The caller chooses the history context and finding sink. This module never writes
an alert or authenticates hardware. Physical BadUSB verdicts remain unavailable.
"""
from .inspection import fingerprint, metadata_changes


def process_observation(device, history):
    if device.get('inspection', {}).get('completeness') == 'complete':
        device['fingerprint'] = fingerprint(device)
    history.observe(device)
    return device


def unexpected_keyboard(before, after):
    if not before or not after or before['version'] != after['version']:
        return None
    previous = sorted({f for i in before['interfaces'] for f in i['functions']})
    current = sorted({f for i in after['interfaces'] for f in i['functions']})
    if 'storage' not in previous or 'keyboard' in previous or 'keyboard' not in current:
        return None
    return {'rule': 'USB_UNEXPECTED_KEYBOARD_ADDITION_V1', 'previousFunctions': previous,
            'currentFunctions': current, 'changedCharacteristics': metadata_changes(before, after),
            'explanation': 'A previously observed storage device acquired a keyboard function in comparable PnP metadata. '
                           'This can indicate possible USB impersonation, but metadata alone cannot establish malicious activity.'}
