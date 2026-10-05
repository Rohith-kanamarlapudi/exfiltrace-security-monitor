// ---------------------------------------------------------------------------
// API layer.
//
// Every page gets its data from here. Today each function resolves with mock
// data; to connect the Python REST API later, replace the body of each
// function with a fetch() call to the matching endpoint (see ENDPOINTS) and
// keep the returned shape the same.
// ---------------------------------------------------------------------------
import {
  mockSystemStatus,
  mockDashboardStats,
  mockUsbDevices,
  mockFileEvents,
  mockSensitiveFiles,
  mockFileStats,
  mockNetworkEvents,
  mockNetworkStats,
  mockTrafficSeries,
  mockIncidents,
  mockAlerts,
  mockReports,
} from '../data/mockData'

export const API_BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:5000/api'

// Planned REST endpoints (Python API -> SQLite)
export const ENDPOINTS = {
  status: '/status',
  dashboard: '/dashboard',
  usbDevices: '/usb/devices',
  fileEvents: '/files/events',
  sensitiveFiles: '/files/sensitive',
  fileStats: '/files/stats',
  networkEvents: '/network/events',
  networkStats: '/network/stats',
  trafficSeries: '/network/traffic',
  incidents: '/incidents',
  alerts: '/alerts',
  reports: '/reports',
}

// Example of what a real call will look like:
// async function get(path) {
//   const res = await fetch(`${API_BASE_URL}${path}`)
//   if (!res.ok) throw new Error(`Request failed: ${res.status}`)
//   return res.json()
// }

// Simulated network latency so loading states behave like a real API.
const delay = (data, ms = 150) => new Promise((resolve) => setTimeout(() => resolve(data), ms))

export const getSystemStatus = () => delay(mockSystemStatus)
export const getDashboardStats = () => delay(mockDashboardStats)
export const getUsbDevices = () => delay(mockUsbDevices)
export const getFileEvents = () => delay(mockFileEvents)
export const getSensitiveFiles = () => delay(mockSensitiveFiles)
export const getFileStats = () => delay(mockFileStats)
export const getNetworkEvents = () => delay(mockNetworkEvents)
export const getNetworkStats = () => delay(mockNetworkStats)
export const getTrafficSeries = () => delay(mockTrafficSeries)
export const getIncidents = () => delay(mockIncidents)
export const getAlerts = () => delay(mockAlerts)
export const getReports = () => delay(mockReports)
