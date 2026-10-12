import { mockNetworkEvents, mockNetworkStats, mockTrafficSeries, mockIncidents, mockReports } from '../data/mockData.js'
import { normalizeList, normalizeObject, normalizeUsbDevices } from './normalize.js'

// Direct requests; Flask enables CORS. VITE_API_URL includes /api.
export const API_BASE_URL = (import.meta.env?.VITE_API_URL ?? 'http://127.0.0.1:5000/api').replace(/\/$/, '')
export const ENDPOINTS = {
  status: '/status', usbDevices: '/usb/devices', usbEvents: '/usb/events',
  fileEvents: '/files/events', sensitiveFiles: '/files/sensitive', fileStats: '/files/stats', alerts: '/alerts',
}
export async function get(path, { signal } = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, { signal, cache: 'no-store' })
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`)
  try { return await response.json() }
  catch { throw new Error(`${path}: invalid JSON response`) }
}
const list = (path) => async (options) => normalizeList(await get(path, options))
export const getSystemStatus = async (options) => normalizeObject(await get(ENDPOINTS.status, options))
export const getUsbDevices = async (options) => normalizeUsbDevices(await get(ENDPOINTS.usbDevices, options))
export const getUsbEvents = list(`${ENDPOINTS.usbEvents}?limit=200`)
export const getFileEvents = list(`${ENDPOINTS.fileEvents}?limit=200`)
export const getSensitiveFiles = list(`${ENDPOINTS.sensitiveFiles}?limit=100`)
export const getFileStats = async (options) => normalizeObject(await get(ENDPOINTS.fileStats, options))
export const getAlerts = list(`${ENDPOINTS.alerts}?limit=200`)
// Explicit preview pages only; never a fallback for failed live requests.
export const getNetworkEvents = async () => mockNetworkEvents
export const getNetworkStats = async () => mockNetworkStats
export const getTrafficSeries = async () => mockTrafficSeries
export const getIncidents = async () => mockIncidents
export const getReports = async () => mockReports
