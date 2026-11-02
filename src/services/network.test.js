import test from 'node:test'
import assert from 'node:assert/strict'
import { getNetworkEvents, getNetworkStats, getTrafficSeries, getRecentNetworkEvents, getRecentTrafficSeries } from './api.js'
import { normalizeNetworkEvents, normalizeNetworkStats, normalizeNetworkTraffic } from './normalize.js'

const event = {
  id: 'n-01', timestamp: '2026-10-05T14:06:41Z', sourceIp: '192.168.1.57',
  destinationIp: '203.0.113.58', destinationHost: 'files-transfer.example-share.net',
  protocol: 'HTTPS', port: 443, packetSizeBytes: 50529280, direction: 'OUTBOUND',
  risk: 'HIGH', usbSession: 'USB-S-0417',
}
const stats = { packetsCaptured: 42111, outboundBytes: 51500000, activeConnections: 12, suspiciousConnections: 1 }
const traffic = [{ time: '14:00', outbound: 49.6, inbound: 4.8, suspicious: 48.2 }]

test('last-hour fetchers filter on the server and advance their UTC window on every poll', async () => {
  const originalFetch = globalThis.fetch
  const originalNow = Date.now
  const seen = []
  let now = Date.parse('2026-11-03T00:30:00.999Z')
  try {
    Date.now = () => now
    globalThis.fetch = async (url, options) => {
      seen.push({ url: new URL(url), signal: options.signal })
      return { ok: true, json: async () => [] }
    }
    const controller = new AbortController()
    assert.deepEqual(await getRecentNetworkEvents({ signal: controller.signal }), [])
    assert.deepEqual(await getRecentTrafficSeries(), [])
    for (const request of seen) {
      assert.equal(request.url.searchParams.get('start'), '2026-11-02T23:30:00Z')
      assert.equal(request.url.searchParams.get('end'), '2026-11-03T00:30:00Z')
    }
    assert.equal(seen[0].url.pathname, '/api/network/events')
    assert.equal(seen[1].url.pathname, '/api/network/traffic')
    assert.equal(seen[0].signal, controller.signal)
    now += 60_000
    await getRecentNetworkEvents()
    assert.equal(seen[2].url.searchParams.get('start'), '2026-11-02T23:31:00Z')
    assert.equal(seen[2].url.searchParams.get('end'), '2026-11-03T00:31:00Z')
  } finally {
    globalThis.fetch = originalFetch
    Date.now = originalNow
  }
})

test('network fetchers use the live endpoints and accept bare response payloads', async () => {
  const original = globalThis.fetch
  const seen = []
  try {
    globalThis.fetch = async (url, options) => {
      seen.push({ url, signal: options.signal })
      const payload = url.endsWith('/network/events') ? [event]
        : url.endsWith('/network/stats') ? stats
          : traffic
      return { ok: true, json: async () => payload }
    }
    const controller = new AbortController()
    assert.deepEqual(await getNetworkEvents({ signal: controller.signal }), [event])
    assert.deepEqual(await getNetworkStats(), stats)
    assert.deepEqual(await getTrafficSeries(), traffic)
    assert.match(seen[0].url, /\/api\/network\/events$/)
    assert.match(seen[1].url, /\/api\/network\/stats$/)
    assert.match(seen[2].url, /\/api\/network\/traffic$/)
    assert.equal(seen[0].signal, controller.signal)
  } finally { globalThis.fetch = original }
})

test('network normalizers accept empty live data and reject malformed shapes', () => {
  assert.deepEqual(normalizeNetworkEvents([]), [])
  assert.deepEqual(normalizeNetworkTraffic([]), [])
  assert.deepEqual(normalizeNetworkStats({ ...stats }), stats)
  assert.throws(() => normalizeNetworkEvents({ data: [event] }), /array/)
  assert.throws(() => normalizeNetworkEvents([{ ...event, direction: 'SIDEWAYS' }]), /Invalid network event/)
  assert.throws(() => normalizeNetworkStats({ ...stats, packetsCaptured: 1.5 }), /Invalid network stats/)
  assert.throws(() => normalizeNetworkTraffic([{ time: '14:00', outbound: '49.6', inbound: 4.8, suspicious: 0 }]), /Invalid/)
})

test('malformed live network responses reject instead of falling back to samples', async () => {
  const original = globalThis.fetch
  try {
    globalThis.fetch = async () => ({ ok: true, json: async () => [{ ...event, risk: 'UNKNOWN' }] })
    await assert.rejects(getNetworkEvents(), /Invalid network event/)
  } finally { globalThis.fetch = original }
})
