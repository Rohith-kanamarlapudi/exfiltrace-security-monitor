// Convert field names without inventing capabilities or changing event meanings.
export function camelCase(value) {
  if (Array.isArray(value)) return value.map(camelCase)
  if (value && typeof value === 'object') return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [key.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase()), camelCase(item)]),
  )
  return value
}
function validate(payload) {
  if (!payload || payload.source !== 'live' || !Object.hasOwn(payload, 'data')) throw new Error('Invalid live API response (expected data and source: live)')
}
export function normalizeObject(payload) {
  validate(payload)
  if (!payload.data || Array.isArray(payload.data) || typeof payload.data !== 'object') throw new Error('Expected API object')
  return camelCase(payload.data)
}
export function normalizeList(payload) {
  validate(payload)
  if (!Array.isArray(payload.data) || !Number.isInteger(payload.total) || payload.total < 0) throw new Error('Expected API list and total')
  return { items: payload.data.map((row) => {
    const item = camelCase(row)
    return { ...item, id: item.id ?? item.deviceId }
  }), total: payload.total, limit: payload.limit ?? payload.data.length }
}

export function normalizeUsbDevices(payload) {
  const result = normalizeList(payload)
  return { ...result, items: result.items.map((d) => ({ ...d, mounts: d.mounts || [],
    inspection: d.inspection || null, fingerprint: d.fingerprint || null, observation: d.observation || null,
    observationSource: d.observationSource || 'unknown' })) }
}

export function normalizeUsbSimulation(payload) {
  const data = normalizeObject(payload)
  if (typeof data.enabled !== 'boolean' || typeof data.phase !== 'string' || !Array.isArray(data.devices)) throw new Error('Invalid USB simulation response')
  if (data.alert && data.alert.simulated !== true || data.observation && data.observation.simulated !== true) throw new Error('Simulation response must explicitly mark synthetic observations and alerts')
  return data
}

const NETWORK_DIRECTIONS = new Set(['OUTBOUND', 'INBOUND', 'INTERNAL'])
const NETWORK_RISKS = new Set(['LOW', 'MEDIUM', 'HIGH'])
const isCount = (value) => Number.isInteger(value) && value >= 0
const isText = (value) => typeof value === 'string' && value.length > 0

function networkArray(payload, label) {
  if (!Array.isArray(payload)) throw new Error(`Expected network ${label} array`)
  return payload
}

export function normalizeNetworkEvents(payload) {
  return networkArray(payload, 'events').map((row) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) throw new Error('Invalid network event')
    const event = camelCase(row)
    if (!isText(event.id) || !isText(event.timestamp) || !isText(event.sourceIp) ||
        !isText(event.destinationIp) || !isText(event.destinationHost) || !isText(event.protocol) ||
        !(event.port === null || (Number.isInteger(event.port) && event.port >= 0)) ||
        !isCount(event.packetSizeBytes) || !NETWORK_DIRECTIONS.has(event.direction) ||
        !NETWORK_RISKS.has(event.risk) || !(event.usbSession === null || typeof event.usbSession === 'string')) {
      throw new Error('Invalid network event')
    }
    return event
  })
}

export function normalizeNetworkStats(payload) {
  const stats = camelCase(payload)
  if (!stats || Array.isArray(stats) || typeof stats !== 'object' ||
      !['packetsCaptured', 'outboundBytes', 'activeConnections', 'suspiciousConnections'].every((key) => isCount(stats[key]))) {
    throw new Error('Invalid network stats')
  }
  return stats
}

export function normalizeNetworkTraffic(payload) {
  return networkArray(payload, 'traffic').map((row) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) throw new Error('Invalid network traffic bucket')
    const bucket = camelCase(row)
    if (!isText(bucket.time) || !['outbound', 'inbound', 'suspicious'].every(
      (key) => typeof bucket[key] === 'number' && Number.isFinite(bucket[key]) && bucket[key] >= 0,
    )) throw new Error('Invalid network traffic bucket')
    return bucket
  })
}
