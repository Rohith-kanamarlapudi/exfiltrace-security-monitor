// ---------------------------------------------------------------------------
// API layer.
//
// Every page gets its data from here. Swaps to real fetch() calls against
// API_BASE_URL with graceful fallback to mock data when backend endpoints are
// offline or pending.
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

// REST endpoints
export const ENDPOINTS = {
  status: '/status',
  dashboard: '/dashboard',
  usbDevices: '/usb/devices',
  usbAlerts: '/usb/alerts',
  usbScan: '/usb/scan',
  usbSimulate: '/usb/simulate',
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

const delay = (data, ms = 50) => new Promise((resolve) => setTimeout(() => resolve(data), ms))

async function fetchJson(endpoint, fallback) {
  try {
    const res = await fetch(`${API_BASE_URL}${endpoint}`, {
      signal: AbortSignal.timeout ? AbortSignal.timeout(2500) : undefined,
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const json = await res.json()
    // Handle { data: [...] } envelope if returned by legacy endpoints
    if (json && typeof json === 'object' && json.data !== undefined) {
      return json.data
    }
    return json
  } catch {
    return delay(fallback)
  }
}

export const getSystemStatus = () => fetchJson(ENDPOINTS.status, mockSystemStatus)
export const getDashboardStats = () => fetchJson(ENDPOINTS.dashboard, mockDashboardStats)
export const getUsbDevices = () => fetchJson(ENDPOINTS.usbDevices, mockUsbDevices)
export const getFileEvents = () => fetchJson(ENDPOINTS.fileEvents, mockFileEvents)
export const getSensitiveFiles = () => fetchJson(ENDPOINTS.sensitiveFiles, mockSensitiveFiles)
export const getFileStats = () => fetchJson(ENDPOINTS.fileStats, mockFileStats)
export const getNetworkEvents = () => fetchJson(ENDPOINTS.networkEvents, mockNetworkEvents)
export const getNetworkStats = () => fetchJson(ENDPOINTS.networkStats, mockNetworkStats)
export const getTrafficSeries = () => fetchJson(ENDPOINTS.trafficSeries, mockTrafficSeries)
export const getIncidents = () => fetchJson(ENDPOINTS.incidents, mockIncidents)
export const getAlerts = () => fetchJson(ENDPOINTS.alerts, mockAlerts)
export const getReports = () => fetchJson(ENDPOINTS.reports, mockReports)

// ---- Module 3: USB Forensics and BadUSB Actions ---------------------------
export async function setDeviceTrust(deviceId, status) {
  const res = await fetch(`${API_BASE_URL}/usb/devices/${deviceId}/trust`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  })
  if (!res.ok) throw new Error(`Failed to update trust: ${res.status}`)
  return res.json()
}

export async function simulateUsb(scenario) {
  const res = await fetch(`${API_BASE_URL}/usb/simulate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario }),
  })
  if (!res.ok) throw new Error(`Failed to simulate scenario: ${res.status}`)
  return res.json()
}

export async function scanUsb() {
  const res = await fetch(`${API_BASE_URL}/usb/scan`, { method: 'POST' })
  if (!res.ok) throw new Error(`Failed to scan hardware: ${res.status}`)
  return res.json()
}

export async function getUsbAlerts() {
  return fetchJson(ENDPOINTS.usbAlerts, [])
}

export async function ackUsbAlert(alertId) {
  const res = await fetch(`${API_BASE_URL}/usb/alerts/${alertId}/ack`, { method: 'POST' })
  if (!res.ok) throw new Error(`Failed to acknowledge alert: ${res.status}`)
  return res.json()
}
