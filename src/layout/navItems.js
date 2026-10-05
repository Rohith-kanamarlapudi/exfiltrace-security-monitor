import { FileSearch, LayoutDashboard, Network, ShieldAlert, FileText, Usb } from 'lucide-react'

export const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/usb', label: 'USB Forensics', icon: Usb },
  { to: '/files', label: 'File Monitoring', icon: FileSearch },
  { to: '/network', label: 'Network Analysis', icon: Network },
  { to: '/incidents', label: 'Incidents', icon: ShieldAlert },
  { to: '/reports', label: 'Reports', icon: FileText },
]
