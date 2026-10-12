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
