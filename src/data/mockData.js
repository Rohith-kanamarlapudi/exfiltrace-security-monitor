// ---------------------------------------------------------------------------
// Centralized mock data for ExfilTrace.
//
// Every page reads its data through src/services/api.js, which currently
// returns these objects. When the Python REST API exists, only api.js needs
// to change - the shapes below are the contract the backend should return.
//
// Scenario: on 2026-10-05 a USB device (USB-S-0417) is connected to
// WKSTN-FIN-07, sensitive files are copied to it, and ~48 MB leaves the
// network to an unknown external host within a few minutes.
// ---------------------------------------------------------------------------

export const mockSystemStatus = {
  monitoring: true,
  host: 'WKSTN-FIN-07',
  agentVersion: '0.4.2',
  uptime: '6d 14h 22m',
  lastSync: '2026-10-05T14:07:02',
  monitors: [
    { name: 'USB Monitor', active: true },
    { name: 'File Monitor', active: true },
    { name: 'Network Monitor', active: true },
    { name: 'Correlation Engine', active: true },
  ],
}

// ---- USB devices ----------------------------------------------------------
// status: SAFE | SUSPICIOUS | CRITICAL
export const mockUsbDevices = [
  {
    id: 'usb-001',
    name: 'Logitech USB Receiver',
    vendorId: '046D',
    productId: 'C52B',
    serialNumber: 'LGT-8F21A09C',
    deviceClass: 'HID (03h)',
    connectedAt: '2026-10-01T09:12:44',
    disconnectedAt: null,
    status: 'SAFE',
    session: 'USB-S-0409',
    fingerprint: {
      manufacturer: 'Logitech',
      product: 'USB Receiver',
      usbVersion: '2.00',
      bcdDevice: '12.11',
      maxPower: '98 mA',
      interfaces: ['HID Keyboard', 'HID Mouse'],
      descriptorHash: '9e41c7a2b0d85f13',
      checks: [
        { label: 'VID/PID registered to claimed vendor', pass: true },
        { label: 'Manufacturer string matches vendor', pass: true },
        { label: 'Serial number format valid', pass: true },
        { label: 'Interface set matches device class', pass: true },
        { label: 'Seen on this host before', pass: true },
      ],
      notes: 'Known peripheral. Allow-listed since 2026-03-14.',
    },
  },
  {
    id: 'usb-002',
    name: 'SanDisk Ultra Fit',
    vendorId: '0781',
    productId: '5583',
    serialNumber: '4C530001230821115',
    deviceClass: 'Mass Storage (08h)',
    connectedAt: '2026-10-04T16:40:05',
    disconnectedAt: '2026-10-04T17:02:31',
    status: 'SAFE',
    session: 'USB-S-0415',
    fingerprint: {
      manufacturer: 'SanDisk',
      product: 'Ultra Fit',
      usbVersion: '3.00',
      bcdDevice: '1.00',
      maxPower: '224 mA',
      interfaces: ['Mass Storage (SCSI)'],
      descriptorHash: '3b7de0419aa2c6f8',
      checks: [
        { label: 'VID/PID registered to claimed vendor', pass: true },
        { label: 'Manufacturer string matches vendor', pass: true },
        { label: 'Serial number format valid', pass: true },
        { label: 'Interface set matches device class', pass: true },
        { label: 'Seen on this host before', pass: true },
      ],
      notes: 'Company-issued encrypted drive. Low-volume copy activity only.',
    },
  },
  {
    id: 'usb-003',
    name: 'Generic Flash Disk',
    vendorId: '0781',
    productId: '5567',
    serialNumber: '0000000000000001',
    deviceClass: 'Mass Storage (08h)',
    connectedAt: '2026-10-05T14:02:11',
    disconnectedAt: null,
    status: 'CRITICAL',
    session: 'USB-S-0417',
    fingerprint: {
      manufacturer: 'Generic',
      product: 'Flash Disk',
      usbVersion: '2.00',
      bcdDevice: '0.01',
      maxPower: '500 mA',
      interfaces: ['Mass Storage (SCSI)', 'HID Keyboard'],
      descriptorHash: 'f02a91d7c35e6b44',
      checks: [
        { label: 'VID/PID registered to claimed vendor', pass: true },
        { label: 'Manufacturer string matches vendor', pass: false },
        { label: 'Serial number format valid', pass: false },
        { label: 'Interface set matches device class', pass: false },
        { label: 'Seen on this host before', pass: false },
      ],
      notes:
        'VID 0781 belongs to SanDisk, but the manufacturer string reads "Generic", the serial is a placeholder value, and an unexpected HID keyboard interface is exposed. Likely impersonating a SanDisk drive. Correlated with incident EXF-001.',
    },
  },
  {
    id: 'usb-004',
    name: 'Kingston DataTraveler 3.0',
    vendorId: '0951',
    productId: '1666',
    serialNumber: '60A44C413C8CF1B0',
    deviceClass: 'Mass Storage (08h)',
    connectedAt: '2026-10-05T11:26:50',
    disconnectedAt: '2026-10-05T11:48:09',
    status: 'SUSPICIOUS',
    session: 'USB-S-0416',
    fingerprint: {
      manufacturer: 'Kingston',
      product: 'DataTraveler 3.0',
      usbVersion: '3.00',
      bcdDevice: '1.10',
      maxPower: '200 mA',
      interfaces: ['Mass Storage (SCSI)'],
      descriptorHash: '71c8e5b92d04a3fe',
      checks: [
        { label: 'VID/PID registered to claimed vendor', pass: true },
        { label: 'Manufacturer string matches vendor', pass: true },
        { label: 'Serial number format valid', pass: true },
        { label: 'Interface set matches device class', pass: true },
        { label: 'Seen on this host before', pass: false },
      ],
      notes:
        'Descriptor is genuine, but this is a personal, unregistered device that copied files from a monitored folder.',
    },
  },
  {
    id: 'usb-005',
    name: 'Samsung Portable SSD T7',
    vendorId: '04E8',
    productId: '61F5',
    serialNumber: 'S5SXNS0R412987K',
    deviceClass: 'Mass Storage (08h)',
    connectedAt: '2026-10-03T10:05:19',
    disconnectedAt: '2026-10-03T10:31:44',
    status: 'SAFE',
    session: 'USB-S-0412',
    fingerprint: {
      manufacturer: 'Samsung',
      product: 'PSSD T7',
      usbVersion: '3.20',
      bcdDevice: '1.00',
      maxPower: '896 mA',
      interfaces: ['Mass Storage (UASP)'],
      descriptorHash: 'a6d03f7e18c9b215',
      checks: [
        { label: 'VID/PID registered to claimed vendor', pass: true },
        { label: 'Manufacturer string matches vendor', pass: true },
        { label: 'Serial number format valid', pass: true },
        { label: 'Interface set matches device class', pass: true },
        { label: 'Seen on this host before', pass: true },
      ],
      notes: 'IT-managed backup drive.',
    },
  },
  {
    id: 'usb-006',
    name: 'Unknown HID Device',
    vendorId: '16C0',
    productId: '27DB',
    serialNumber: 'N/A',
    deviceClass: 'HID (03h)',
    connectedAt: '2026-10-02T13:44:02',
    disconnectedAt: '2026-10-02T13:44:09',
    status: 'SUSPICIOUS',
    session: 'USB-S-0411',
    fingerprint: {
      manufacturer: 'Teensyduino',
      product: 'Keyboard/Mouse/Joystick',
      usbVersion: '2.00',
      bcdDevice: '2.80',
      maxPower: '100 mA',
      interfaces: ['HID Keyboard', 'HID Mouse'],
      descriptorHash: 'c19b44e07a2d58f6',
      checks: [
        { label: 'VID/PID registered to claimed vendor', pass: true },
        { label: 'Manufacturer string matches vendor', pass: true },
        { label: 'Serial number format valid', pass: false },
        { label: 'Interface set matches device class', pass: true },
        { label: 'Seen on this host before', pass: false },
      ],
      notes:
        'Development-board HID connected for 7 seconds. Short-lived keyboard emulators can inject keystrokes; no file activity followed.',
    },
  },
]

// ---- File events ----------------------------------------------------------
// action: CREATE | MODIFY | ACCESS | COPY | DELETE | MOVE
// risk:   LOW | MEDIUM | HIGH
export const mockFileEvents = [
  { id: 'f-01', timestamp: '2026-10-05T14:06:02', fileName: 'project_data.pdf', path: 'D:\\Projects\\Atlas\\project_data.pdf', action: 'COPY', process: 'explorer.exe', usbSession: 'USB-S-0417', risk: 'HIGH', sensitive: true },
  { id: 'f-02', timestamp: '2026-10-05T14:04:32', fileName: 'employee_data.xlsx', path: 'D:\\HR\\Confidential\\employee_data.xlsx', action: 'COPY', process: 'explorer.exe', usbSession: 'USB-S-0417', risk: 'HIGH', sensitive: true },
  { id: 'f-03', timestamp: '2026-10-05T14:04:05', fileName: 'confidential.txt', path: 'D:\\Finance\\confidential.txt', action: 'COPY', process: 'explorer.exe', usbSession: 'USB-S-0417', risk: 'HIGH', sensitive: true },
  { id: 'f-04', timestamp: '2026-10-05T14:03:40', fileName: 'passwords.txt', path: 'C:\\Users\\finance\\Documents\\passwords.txt', action: 'ACCESS', process: 'notepad.exe', usbSession: 'USB-S-0417', risk: 'HIGH', sensitive: true },
  { id: 'f-05', timestamp: '2026-10-05T14:03:12', fileName: 'confidential.txt', path: 'D:\\Finance\\confidential.txt', action: 'ACCESS', process: 'explorer.exe', usbSession: 'USB-S-0417', risk: 'MEDIUM', sensitive: true },
  { id: 'f-06', timestamp: '2026-10-05T14:02:58', fileName: 'archive_2026.zip', path: 'E:\\archive_2026.zip', action: 'CREATE', process: 'explorer.exe', usbSession: 'USB-S-0417', risk: 'MEDIUM', sensitive: false },
  { id: 'f-07', timestamp: '2026-10-05T11:41:20', fileName: 'employee_data.xlsx', path: 'D:\\HR\\Confidential\\employee_data.xlsx', action: 'COPY', process: 'explorer.exe', usbSession: 'USB-S-0416', risk: 'HIGH', sensitive: true },
  { id: 'f-08', timestamp: '2026-10-05T11:38:07', fileName: 'quarterly_report.docx', path: 'D:\\Finance\\quarterly_report.docx', action: 'COPY', process: 'explorer.exe', usbSession: 'USB-S-0416', risk: 'MEDIUM', sensitive: false },
  { id: 'f-09', timestamp: '2026-10-05T10:15:33', fileName: 'budget_2027.xlsx', path: 'D:\\Finance\\budget_2027.xlsx', action: 'MODIFY', process: 'EXCEL.EXE', usbSession: null, risk: 'LOW', sensitive: false },
  { id: 'f-10', timestamp: '2026-10-05T09:52:18', fileName: 'meeting_notes.txt', path: 'C:\\Users\\finance\\Documents\\meeting_notes.txt', action: 'CREATE', process: 'notepad.exe', usbSession: null, risk: 'LOW', sensitive: false },
  { id: 'f-11', timestamp: '2026-10-05T09:30:41', fileName: 'project_data.pdf', path: 'D:\\Projects\\Atlas\\project_data.pdf', action: 'ACCESS', process: 'AcroRd32.exe', usbSession: null, risk: 'LOW', sensitive: true },
  { id: 'f-12', timestamp: '2026-10-04T17:00:12', fileName: 'backup_set.7z', path: 'E:\\backup_set.7z', action: 'MOVE', process: 'explorer.exe', usbSession: 'USB-S-0415', risk: 'LOW', sensitive: false },
  { id: 'f-13', timestamp: '2026-10-04T16:52:09', fileName: 'old_credentials.csv', path: 'C:\\Users\\finance\\Downloads\\old_credentials.csv', action: 'DELETE', process: 'explorer.exe', usbSession: 'USB-S-0415', risk: 'MEDIUM', sensitive: true },
  { id: 'f-14', timestamp: '2026-10-04T15:20:44', fileName: 'invoice_template.xlsx', path: 'D:\\Finance\\invoice_template.xlsx', action: 'MODIFY', process: 'EXCEL.EXE', usbSession: null, risk: 'LOW', sensitive: false },
  { id: 'f-15', timestamp: '2026-10-03T10:20:57', fileName: 'system_image.bak', path: 'E:\\system_image.bak', action: 'CREATE', process: 'backup_agent.exe', usbSession: 'USB-S-0412', risk: 'LOW', sensitive: false },
]

export const mockSensitiveFiles = [
  { id: 'sf-1', fileName: 'confidential.txt', path: 'D:\\Finance\\confidential.txt', classification: 'Confidential', owner: 'finance', size: '18 KB', lastEvent: 'COPY', lastEventAt: '2026-10-05T14:04:05', usbTouched: true },
  { id: 'sf-2', fileName: 'employee_data.xlsx', path: 'D:\\HR\\Confidential\\employee_data.xlsx', classification: 'Restricted', owner: 'hr-admin', size: '2.4 MB', lastEvent: 'COPY', lastEventAt: '2026-10-05T14:04:32', usbTouched: true },
  { id: 'sf-3', fileName: 'passwords.txt', path: 'C:\\Users\\finance\\Documents\\passwords.txt', classification: 'Restricted', owner: 'finance', size: '3 KB', lastEvent: 'ACCESS', lastEventAt: '2026-10-05T14:03:40', usbTouched: true },
  { id: 'sf-4', fileName: 'project_data.pdf', path: 'D:\\Projects\\Atlas\\project_data.pdf', classification: 'Confidential', owner: 'pm-office', size: '41.7 MB', lastEvent: 'COPY', lastEventAt: '2026-10-05T14:06:02', usbTouched: true },
  { id: 'sf-5', fileName: 'old_credentials.csv', path: 'C:\\Users\\finance\\Downloads\\old_credentials.csv', classification: 'Restricted', owner: 'finance', size: '9 KB', lastEvent: 'DELETE', lastEventAt: '2026-10-04T16:52:09', usbTouched: false },
]

export const mockFileStats = {
  monitoredFiles: 1284,
  sensitiveFiles: mockSensitiveFiles.length,
}

// ---- Network events -------------------------------------------------------
// risk: LOW | MEDIUM | HIGH
// direction: OUTBOUND | INBOUND | INTERNAL
export const mockNetworkEvents = [
  { id: 'n-01', timestamp: '2026-10-05T14:06:41', sourceIp: '192.168.1.57', destinationIp: '203.0.113.58', destinationHost: 'files-transfer.example-share.net', protocol: 'HTTPS', port: 443, packetSizeBytes: 50529280, direction: 'OUTBOUND', risk: 'HIGH', usbSession: 'USB-S-0417' },
  { id: 'n-02', timestamp: '2026-10-05T14:06:25', sourceIp: '192.168.1.57', destinationIp: '203.0.113.58', destinationHost: 'files-transfer.example-share.net', protocol: 'TCP', port: 443, packetSizeBytes: 1048576, direction: 'OUTBOUND', risk: 'HIGH', usbSession: 'USB-S-0417' },
  { id: 'n-03', timestamp: '2026-10-05T14:06:18', sourceIp: '192.168.1.57', destinationIp: '203.0.113.58', destinationHost: 'files-transfer.example-share.net', protocol: 'DNS', port: 53, packetSizeBytes: 96, direction: 'OUTBOUND', risk: 'MEDIUM', usbSession: 'USB-S-0417' },
  { id: 'n-04', timestamp: '2026-10-05T14:05:02', sourceIp: '192.168.1.57', destinationIp: '142.250.183.14', destinationHost: 'www.google.com', protocol: 'HTTPS', port: 443, packetSizeBytes: 18432, direction: 'OUTBOUND', risk: 'LOW', usbSession: null },
  { id: 'n-05', timestamp: '2026-10-05T14:01:47', sourceIp: '192.168.1.57', destinationIp: '192.168.1.10', destinationHost: 'fileserver.corp.local', protocol: 'SMB', port: 445, packetSizeBytes: 262144, direction: 'INTERNAL', risk: 'LOW', usbSession: null },
  { id: 'n-06', timestamp: '2026-10-05T13:58:30', sourceIp: '192.168.1.57', destinationIp: '13.107.42.14', destinationHost: 'outlook.office365.com', protocol: 'HTTPS', port: 443, packetSizeBytes: 54272, direction: 'OUTBOUND', risk: 'LOW', usbSession: null },
  { id: 'n-07', timestamp: '2026-10-05T13:44:09', sourceIp: '198.51.100.23', destinationIp: '192.168.1.57', destinationHost: 'wkstn-fin-07.corp.local', protocol: 'TCP', port: 3389, packetSizeBytes: 740, direction: 'INBOUND', risk: 'MEDIUM', usbSession: null },
  { id: 'n-08', timestamp: '2026-10-05T11:44:12', sourceIp: '192.168.1.57', destinationIp: '198.51.100.77', destinationHost: 'dl.personal-cloud-drive.io', protocol: 'HTTPS', port: 443, packetSizeBytes: 8388608, direction: 'OUTBOUND', risk: 'MEDIUM', usbSession: 'USB-S-0416' },
  { id: 'n-09', timestamp: '2026-10-05T11:20:03', sourceIp: '192.168.1.57', destinationIp: '192.168.1.1', destinationHost: 'dns.corp.local', protocol: 'DNS', port: 53, packetSizeBytes: 84, direction: 'INTERNAL', risk: 'LOW', usbSession: null },
  { id: 'n-10', timestamp: '2026-10-05T10:02:51', sourceIp: '192.168.1.57', destinationIp: '104.18.32.47', destinationHost: 'cdn.updates.vendor.com', protocol: 'HTTPS', port: 443, packetSizeBytes: 3145728, direction: 'INBOUND', risk: 'LOW', usbSession: null },
  { id: 'n-11', timestamp: '2026-10-05T09:15:36', sourceIp: '192.168.1.57', destinationIp: '192.168.1.10', destinationHost: 'fileserver.corp.local', protocol: 'SMB', port: 445, packetSizeBytes: 524288, direction: 'INTERNAL', risk: 'LOW', usbSession: null },
  { id: 'n-12', timestamp: '2026-10-05T08:58:14', sourceIp: '192.168.1.57', destinationIp: '172.217.160.78', destinationHost: 'mail.google.com', protocol: 'HTTPS', port: 443, packetSizeBytes: 22016, direction: 'OUTBOUND', risk: 'LOW', usbSession: null },
]

export const mockNetworkStats = {
  packetsCaptured: 184392,
  outboundBytes: 63500000, // ~60.6 MB outbound today
  activeConnections: 37,
  suspiciousConnections: 3,
}

// Outbound / inbound traffic in MB per 30 minute bucket (for the Recharts chart)
export const mockTrafficSeries = [
  { time: '08:00', outbound: 1.2, inbound: 6.4, suspicious: 0 },
  { time: '08:30', outbound: 1.8, inbound: 7.9, suspicious: 0 },
  { time: '09:00', outbound: 2.4, inbound: 9.1, suspicious: 0 },
  { time: '09:30', outbound: 1.9, inbound: 8.2, suspicious: 0 },
  { time: '10:00', outbound: 2.1, inbound: 12.6, suspicious: 0 },
  { time: '10:30', outbound: 1.4, inbound: 7.3, suspicious: 0 },
  { time: '11:00', outbound: 1.7, inbound: 6.8, suspicious: 0 },
  { time: '11:30', outbound: 9.9, inbound: 5.1, suspicious: 8.0 },
  { time: '12:00', outbound: 1.3, inbound: 5.6, suspicious: 0 },
  { time: '12:30', outbound: 0.9, inbound: 4.2, suspicious: 0 },
  { time: '13:00', outbound: 1.6, inbound: 6.9, suspicious: 0 },
  { time: '13:30', outbound: 2.0, inbound: 7.4, suspicious: 0 },
  { time: '14:00', outbound: 49.6, inbound: 4.8, suspicious: 48.2 },
]

// ---- Incidents ------------------------------------------------------------
// severity: LOW | MEDIUM | HIGH | CRITICAL
// status:   INVESTIGATION REQUIRED | UNDER REVIEW | RESOLVED
export const mockIncidents = [
  {
    id: 'EXF-001',
    type: 'Possible Data Exfiltration',
    severity: 'HIGH',
    status: 'INVESTIGATION REQUIRED',
    timestamp: '2026-10-05T14:06:41',
    host: 'WKSTN-FIN-07',
    usb: {
      deviceName: 'Generic Flash Disk',
      vendorId: '0781',
      productId: '5567',
      serialNumber: '0000000000000001',
      session: 'USB-S-0417',
    },
    files: [
      { fileName: 'passwords.txt', action: 'ACCESS', timestamp: '2026-10-05T14:03:40' },
      { fileName: 'confidential.txt', action: 'COPY', timestamp: '2026-10-05T14:04:05' },
      { fileName: 'employee_data.xlsx', action: 'COPY', timestamp: '2026-10-05T14:04:32' },
      { fileName: 'project_data.pdf', action: 'COPY', timestamp: '2026-10-05T14:06:02' },
    ],
    network: {
      destination: '203.0.113.58 (files-transfer.example-share.net)',
      protocol: 'HTTPS',
      dataTransferred: '48.2 MB',
    },
    correlation:
      'USB device USB-S-0417 was connected at 14:02:11. Within the same session, 4 sensitive files were accessed or copied between 14:03:40 and 14:06:02, and 48.2 MB was sent to an unrecognised external host at 14:06:41. All three activities fall inside a single 4 min 30 s window on WKSTN-FIN-07.',
    timeline: [
      { time: '2026-10-05T14:02:11', title: 'USB Connected', detail: 'Generic Flash Disk (VID 0781 / PID 5567) mounted as E:. Fingerprint mismatch flagged.', type: 'usb' },
      { time: '2026-10-05T14:03:40', title: 'Sensitive File Accessed', detail: 'passwords.txt opened by notepad.exe.', type: 'file' },
      { time: '2026-10-05T14:04:32', title: 'File Transfer Detected', detail: 'confidential.txt, employee_data.xlsx and project_data.pdf copied to E:\\.', type: 'transfer' },
      { time: '2026-10-05T14:06:18', title: 'Outbound Network Activity', detail: 'DNS lookup and HTTPS session opened to 203.0.113.58.', type: 'network' },
      { time: '2026-10-05T14:06:41', title: 'Possible Data Exfiltration', detail: '48.2 MB uploaded to an unrecognised external host.', type: 'exfil' },
    ],
  },
  {
    id: 'EXF-002',
    type: 'Unauthorized USB Storage Copy',
    severity: 'MEDIUM',
    status: 'UNDER REVIEW',
    timestamp: '2026-10-05T11:44:12',
    host: 'WKSTN-FIN-07',
    usb: {
      deviceName: 'Kingston DataTraveler 3.0',
      vendorId: '0951',
      productId: '1666',
      serialNumber: '60A44C413C8CF1B0',
      session: 'USB-S-0416',
    },
    files: [
      { fileName: 'quarterly_report.docx', action: 'COPY', timestamp: '2026-10-05T11:38:07' },
      { fileName: 'employee_data.xlsx', action: 'COPY', timestamp: '2026-10-05T11:41:20' },
    ],
    network: {
      destination: '198.51.100.77 (dl.personal-cloud-drive.io)',
      protocol: 'HTTPS',
      dataTransferred: '8.0 MB',
    },
    correlation:
      'Unregistered USB device USB-S-0416 was connected at 11:26:50. A restricted file and a finance document were copied to it, and 8.0 MB was sent to a personal cloud storage domain within the same session. Volume is lower than EXF-001 and the user may have an approved reason.',
    timeline: [
      { time: '2026-10-05T11:26:50', title: 'USB Connected', detail: 'Kingston DataTraveler 3.0 mounted as E:. Device not previously registered.', type: 'usb' },
      { time: '2026-10-05T11:38:07', title: 'Sensitive File Accessed', detail: 'quarterly_report.docx read from D:\\Finance.', type: 'file' },
      { time: '2026-10-05T11:41:20', title: 'File Transfer Detected', detail: 'employee_data.xlsx copied to E:\\.', type: 'transfer' },
      { time: '2026-10-05T11:44:12', title: 'Outbound Network Activity', detail: '8.0 MB HTTPS upload to dl.personal-cloud-drive.io.', type: 'network' },
    ],
  },
  {
    id: 'EXF-003',
    type: 'Suspicious HID Device Insertion',
    severity: 'MEDIUM',
    status: 'UNDER REVIEW',
    timestamp: '2026-10-02T13:44:09',
    host: 'WKSTN-FIN-07',
    usb: {
      deviceName: 'Unknown HID Device',
      vendorId: '16C0',
      productId: '27DB',
      serialNumber: 'N/A',
      session: 'USB-S-0411',
    },
    files: [],
    network: {
      destination: '198.51.100.23 (inbound RDP probe)',
      protocol: 'TCP',
      dataTransferred: '740 B',
    },
    correlation:
      'A keyboard-emulating development board was connected for 7 seconds with no serial number. No file activity followed, but an unsolicited inbound connection on port 3389 was observed from an external address shortly after.',
    timeline: [
      { time: '2026-10-02T13:44:02', title: 'USB Connected', detail: 'HID device with VID 16C0 / PID 27DB, no serial number.', type: 'usb' },
      { time: '2026-10-02T13:44:09', title: 'USB Disconnected', detail: 'Device removed after 7 seconds.', type: 'usb' },
    ],
  },
  {
    id: 'EXF-004',
    type: 'Bulk Copy to Approved Drive',
    severity: 'LOW',
    status: 'RESOLVED',
    timestamp: '2026-10-03T10:31:44',
    host: 'WKSTN-FIN-07',
    usb: {
      deviceName: 'Samsung Portable SSD T7',
      vendorId: '04E8',
      productId: '61F5',
      serialNumber: 'S5SXNS0R412987K',
      session: 'USB-S-0412',
    },
    files: [{ fileName: 'system_image.bak', action: 'CREATE', timestamp: '2026-10-03T10:20:57' }],
    network: {
      destination: 'None',
      protocol: '-',
      dataTransferred: '0 B',
    },
    correlation:
      'Large write to an IT-managed backup drive. No sensitive file access and no outbound traffic in the same window. Closed as an approved scheduled backup.',
    timeline: [
      { time: '2026-10-03T10:05:19', title: 'USB Connected', detail: 'Samsung Portable SSD T7 mounted as E:.', type: 'usb' },
      { time: '2026-10-03T10:20:57', title: 'File Transfer Detected', detail: 'system_image.bak written by backup_agent.exe.', type: 'transfer' },
      { time: '2026-10-03T10:31:44', title: 'USB Disconnected', detail: 'Device safely removed. Incident closed.', type: 'usb' },
    ],
  },
]

// ---- Alerts ---------------------------------------------------------------
// severity: LOW | MEDIUM | HIGH | CRITICAL
export const mockAlerts = [
  { id: 'a-01', type: 'Data Exfiltration Suspected', severity: 'CRITICAL', timestamp: '2026-10-05T14:06:41', description: '48.2 MB sent to 203.0.113.58 within 4 minutes of sensitive files being copied to USB-S-0417.' },
  { id: 'a-02', type: 'USB Impersonation', severity: 'HIGH', timestamp: '2026-10-05T14:02:12', description: 'Device claims SanDisk VID 0781 but manufacturer string and serial number do not match a genuine SanDisk drive.' },
  { id: 'a-03', type: 'Sensitive File Copied', severity: 'HIGH', timestamp: '2026-10-05T14:04:32', description: 'employee_data.xlsx copied to removable media E:\\.' },
  { id: 'a-04', type: 'Credential File Accessed', severity: 'MEDIUM', timestamp: '2026-10-05T14:03:40', description: 'passwords.txt opened while an unverified USB device was mounted.' },
  { id: 'a-05', type: 'Unregistered USB Device', severity: 'MEDIUM', timestamp: '2026-10-05T11:26:50', description: 'Kingston DataTraveler 3.0 (serial 60A44C413C8CF1B0) is not in the approved device list.' },
  { id: 'a-06', type: 'Inbound RDP Probe', severity: 'LOW', timestamp: '2026-10-05T13:44:09', description: 'External address 198.51.100.23 attempted a connection to TCP 3389.' },
]

// ---- Reports --------------------------------------------------------------
export const mockReports = [
  {
    id: 'RPT-2026-1005-001',
    date: '2026-10-05',
    severity: 'HIGH',
    incidentType: 'Possible Data Exfiltration',
    incidentId: 'EXF-001',
    summary:
      'An unverified USB storage device impersonating a SanDisk drive was connected to WKSTN-FIN-07. Four sensitive files were accessed or copied to it, and 48.2 MB was then uploaded to an unrecognised external host within the same session.',
    usbActivity: 'Generic Flash Disk (VID 0781 / PID 5567, serial 0000000000000001) connected 14:02:11. Fingerprint checks failed: manufacturer, serial format and interface set.',
    fileActivity: 'passwords.txt accessed; confidential.txt, employee_data.xlsx and project_data.pdf copied to E:\\ between 14:03:40 and 14:06:02.',
    networkActivity: '48.2 MB HTTPS upload to 203.0.113.58 (files-transfer.example-share.net) at 14:06:41, preceded by a DNS lookup at 14:06:18.',
    timeline: mockIncidentsTimelineRef('EXF-001'),
  },
  {
    id: 'RPT-2026-1005-002',
    date: '2026-10-05',
    severity: 'MEDIUM',
    incidentType: 'Unauthorized USB Storage Copy',
    incidentId: 'EXF-002',
    summary:
      'A personal Kingston USB drive not on the approved list was used to copy a restricted HR file and a finance document. A related 8.0 MB upload to a personal cloud storage domain occurred in the same session.',
    usbActivity: 'Kingston DataTraveler 3.0 (VID 0951 / PID 1666) connected 11:26:50, disconnected 11:48:09. Descriptor genuine, device unregistered.',
    fileActivity: 'quarterly_report.docx and employee_data.xlsx copied to E:\\ between 11:38:07 and 11:41:20.',
    networkActivity: '8.0 MB HTTPS upload to dl.personal-cloud-drive.io at 11:44:12.',
    timeline: mockIncidentsTimelineRef('EXF-002'),
  },
  {
    id: 'RPT-2026-1003-001',
    date: '2026-10-03',
    severity: 'LOW',
    incidentType: 'Bulk Copy to Approved Drive',
    incidentId: 'EXF-004',
    summary:
      'A scheduled backup wrote a large system image to an IT-managed Samsung SSD. No sensitive file access or outbound traffic was correlated. Closed as expected behaviour.',
    usbActivity: 'Samsung Portable SSD T7 (VID 04E8 / PID 61F5) connected 10:05:19, disconnected 10:31:44.',
    fileActivity: 'system_image.bak created on E:\\ by backup_agent.exe at 10:20:57.',
    networkActivity: 'No outbound activity associated with the session.',
    timeline: mockIncidentsTimelineRef('EXF-004'),
  },
]

// Reports reuse the timeline of the incident they were generated from.
function mockIncidentsTimelineRef(incidentId) {
  return mockIncidents.find((i) => i.id === incidentId)?.timeline ?? []
}

// ---- Dashboard summary ----------------------------------------------------
export const mockDashboardStats = {
  usbDevices: { connected: 2, totalSeen: mockUsbDevices.length },
  fileEvents: { total: 3892, today: 412 },
  networkTraffic: { outboundBytes: mockNetworkStats.outboundBytes, label: 'outbound today' },
  incidents: { open: 3, total: mockIncidents.length },
}
