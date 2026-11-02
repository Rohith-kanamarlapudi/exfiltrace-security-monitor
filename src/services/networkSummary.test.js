import test from 'node:test'
import assert from 'node:assert/strict'
import { summarizeNetworkEvents } from './networkSummary.js'

const flow = (overrides = {}) => ({ sourceIp: '192.168.1.2', destinationIp: '203.0.113.1',
  destinationHost: 'upload.example', direction: 'OUTBOUND', packetSizeBytes: 100,
  risk: 'LOW', protocol: 'HTTPS', timestamp: '2026-11-03T01:00:00Z', ...overrides })

test('combines destinations across intervals, preserving highest risk and time bounds', () => {
  const rows = summarizeNetworkEvents([
    flow({ timestamp: '2026-11-03T01:02:00Z', risk: 'HIGH' }),
    flow({ protocol: 'DNS', packetSizeBytes: 20 }),
    flow({ destinationIp: '203.0.113.2', packetSizeBytes: 200 }),
    flow({ direction: 'INTERNAL', packetSizeBytes: 999 }),
  ], 'OUTBOUND')
  assert.equal(rows.length, 2)
  assert.equal(rows[0].bytes, 200)
  assert.equal(rows[1].bytes, 120)
  assert.equal(rows[1].flows, 2)
  assert.equal(rows[1].risk, 'HIGH')
  assert.equal(rows[1].firstSeen, '2026-11-03T01:00:00Z')
  assert.equal(rows[1].lastSeen, '2026-11-03T01:02:00Z')
  assert.deepEqual(rows[1].protocols, ['DNS', 'HTTPS'])
  assert.deepEqual(rows[1].hosts, ['upload.example'])
})

test('inbound groups by sender, not local destination, without mislabeling source hostnames', () => {
  const rows = summarizeNetworkEvents([
    flow({ direction: 'INBOUND', sourceIp: '203.0.113.1', destinationIp: '192.168.1.2' }),
    flow({ direction: 'INBOUND', sourceIp: '203.0.113.1', destinationIp: '192.168.1.3' }),
    flow({ direction: 'INBOUND', sourceIp: '203.0.113.2', destinationIp: '192.168.1.2' }),
    flow(),
  ], 'INBOUND')
  assert.equal(rows.length, 2)
  assert.equal(rows[0].ip, '203.0.113.1')
  assert.equal(rows[0].bytes, 200)
  assert.deepEqual(rows[0].hosts, [])
  assert.equal(rows[1].bytes, 100)
  assert.deepEqual(summarizeNetworkEvents([], 'OUTBOUND'), [])
})
