import { FileSearch, LayoutDashboard, Network, FileText, Usb } from 'lucide-react'

export const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/usb', label: 'USB Forensics', icon: Usb },
  { to: '/usb-recovery', label: 'USB Recovery', icon: FileSearch },
  { to: '/files', label: 'File Monitoring', icon: FileSearch },
  { to: '/network', label: 'Network', icon: Network },
  { to: '/reports', label: 'Reports', icon: FileText },
]
