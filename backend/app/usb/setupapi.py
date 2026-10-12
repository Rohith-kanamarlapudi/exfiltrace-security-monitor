"""Read-only present-devnode inventory using Windows SetupAPI / Configuration Manager.

No device handles, descriptor requests, driver changes or input capture are used.
Imports Windows libraries only when called, allowing fixture tests on any OS.
"""
import ctypes as c
from ctypes import wintypes as w
import uuid

from .base import UsbBackendError


def enumerate_nodes():
    class GUID(c.Structure):
        _fields_ = [('data', c.c_ubyte * 16)]

    class KEY(c.Structure):
        _fields_ = [('fmtid', GUID), ('pid', w.DWORD)]

    class INFO(c.Structure):
        _fields_ = [('cbSize', w.DWORD), ('ClassGuid', GUID), ('DevInst', w.DWORD), ('Reserved', c.c_size_t)]

    setup = c.WinDLL('setupapi', use_last_error=True)
    cm = c.WinDLL('cfgmgr32', use_last_error=True)
    setup.SetupDiGetClassDevsW.argtypes = [c.c_void_p, w.LPCWSTR, w.HWND, w.DWORD]
    setup.SetupDiGetClassDevsW.restype = w.HANDLE
    setup.SetupDiEnumDeviceInfo.argtypes = [w.HANDLE, w.DWORD, c.POINTER(INFO)]
    setup.SetupDiEnumDeviceInfo.restype = w.BOOL
    setup.SetupDiDestroyDeviceInfoList.argtypes = [w.HANDLE]
    setup.SetupDiDestroyDeviceInfoList.restype = w.BOOL
    cm.CM_Get_Device_IDW.argtypes = [w.DWORD, w.LPWSTR, w.ULONG, w.ULONG]
    cm.CM_Get_Device_IDW.restype = w.ULONG
    cm.CM_Get_Parent.argtypes = [c.POINTER(w.DWORD), w.DWORD, w.ULONG]
    cm.CM_Get_Parent.restype = w.ULONG
    cm.CM_Get_DevNode_PropertyW.argtypes = [w.DWORD, c.POINTER(KEY), c.POINTER(w.ULONG), c.c_void_p, c.POINTER(w.ULONG), w.ULONG]
    cm.CM_Get_DevNode_PropertyW.restype = w.ULONG

    def instance(devinst):
        buf = c.create_unicode_buffer(4096)
        status = cm.CM_Get_Device_IDW(devinst, buf, len(buf), 0)
        if status:
            raise UsbBackendError(f'CM_Get_Device_IDW failed: {status:#x}')
        return buf.value

    def property_value(devinst, pid, errors, container=False):
        fmtid = '8c7ed206-3f8a-4827-b3ab-ae9e1faefc6c' if container else 'a45c254e-df1c-4efd-8020-67d146a850e0'
        key = KEY(GUID((c.c_ubyte * 16).from_buffer_copy(uuid.UUID(fmtid).bytes_le)), pid)
        typ, size = w.ULONG(), w.ULONG()
        status = cm.CM_Get_DevNode_PropertyW(devinst, c.byref(key), c.byref(typ), None, c.byref(size), 0)
        if status == 0x25:  # CR_NO_SUCH_VALUE: available API, property absent
            return None
        if status != 0x1a:  # CR_BUFFER_SMALL
            errors.append(f'Property {fmtid}/{pid}: CM status {status:#x}')
            return None
        buf = (c.c_ubyte * size.value)()
        status = cm.CM_Get_DevNode_PropertyW(devinst, c.byref(key), c.byref(typ), buf, c.byref(size), 0)
        if status:
            errors.append(f'Property {pid} changed/unavailable: CM status {status:#x}')
            return None
        raw = bytes(buf)
        if typ.value == 0x12:
            return raw.decode('utf-16-le').rstrip('\0')
        if typ.value == 0x2012:
            return [v for v in raw.decode('utf-16-le').rstrip('\0').split('\0') if v]
        if typ.value == 7 and len(raw) == 4:
            return int.from_bytes(raw, 'little')
        if typ.value == 0xd and len(raw) == 16:
            return str(uuid.UUID(bytes_le=raw))
        errors.append(f'Unexpected property type {typ.value:#x} for {pid}')
        return None

    handle = setup.SetupDiGetClassDevsW(None, None, None, 0x2 | 0x4)  # PRESENT | ALLCLASSES
    if handle == c.c_void_p(-1).value:
        raise UsbBackendError(f'SetupDiGetClassDevsW failed: {c.get_last_error()}')
    nodes = []
    try:
        index = 0
        while True:
            info = INFO()
            info.cbSize = c.sizeof(INFO)
            if not setup.SetupDiEnumDeviceInfo(handle, index, c.byref(info)):
                error = c.get_last_error()
                if error == 259:  # ERROR_NO_MORE_ITEMS: only successful end condition
                    break
                raise UsbBackendError(f'SetupDiEnumDeviceInfo failed: {error}')
            index += 1
            errors = []
            try:
                node = {'instanceId': instance(info.DevInst)}
            except UsbBackendError as exc:
                nodes.append({'instanceId': f'UNRESOLVED:{info.DevInst}', 'errors': [str(exc)]})
                continue
            for name, pid in [('hardwareIds', 3), ('compatibleIds', 4), ('pnpClass', 9),
                              ('manufacturer', 13), ('name', 14), ('capabilities', 17)]:
                node[name] = property_value(info.DevInst, pid, errors)
            node['name'] = node['name'] or property_value(info.DevInst, 2, errors)
            parent = w.DWORD()
            status = cm.CM_Get_Parent(c.byref(parent), info.DevInst, 0)
            try:
                node['parentId'] = instance(parent.value) if not status else None
            except UsbBackendError as exc:
                node['parentId'] = None
                errors.append(str(exc))
            if status and node['instanceId'].upper() != 'HTREE\\ROOT\\0':
                errors.append(f'Parent query failed: CM status {status:#x}')
            node['containerId'] = property_value(info.DevInst, 2, errors, container=True)
            node['errors'] = errors
            nodes.append(node)
    finally:
        setup.SetupDiDestroyDeviceInfoList(handle)
    return {'nodes': nodes}
