import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeList, normalizeObject } from './normalize.js'
import { get, getUsbDevices } from './api.js'

test('USB wrapper retains dynamic multi-volume mapping without fictional capabilities', () => {
  const result = normalizeList({ source: 'live', total: 2, data: [
    { device_id: 'USBSTOR\\A', vendor_id: '1234', product_id: null, mounts: ['D:\\', 'G:\\'], size_bytes: 42 },
    { device_id: 'USBSTOR\\B', mounts: [] },
  ] })
  assert.equal(result.items[0].id, 'USBSTOR\\A')
  assert.deepEqual(result.items[0].mounts, ['D:\\', 'G:\\'])
  assert.equal(result.items[0].productId, null)
  assert.equal(result.items[0].sizeBytes, 42)
  for (const field of ['fingerprint', 'status', 'session', 'connectedAt']) assert.equal(field in result.items[0], false)
  assert.deepEqual(result.items[1].mounts, [])
})

test('file actions, sensitivity, rename paths and removable association retain backend meaning', () => {
  for (const eventType of ['CREATED', 'MODIFIED', 'DELETED', 'RENAMED']) {
    const [event] = normalizeList({ source: 'live', total: 1, data: [{
      id: 7, event_type: eventType, file_name: 'confidential.txt', dest_path: 'D:\\new.txt',
      sensitive: 1, on_removable: 1, usb_device_id: 'USB-A', sensitivity_reason: 'Keyword',
    }] }).items
    assert.equal(event.eventType, eventType)
    assert.equal(event.destPath, 'D:\\new.txt')
    assert.equal(event.usbDeviceId, 'USB-A')
    assert.equal(event.sensitivityReason, 'Keyword')
    assert.equal('process' in event, false)
    assert.equal('usbSession' in event, false)
  }
})

test('verdicts, alert evidence and event references are preserved independently of severity', () => {
  for (const verdict of ['SUSPICIOUS', 'VERIFIED_TRANSFER']) {
    const alert = normalizeList({ source: 'live', total: 1, limit: 200, data: [{
      id: 1, severity: 'CRITICAL', verdict, rule: 'SENSITIVE_FILE_COPIED_TO_USB',
      explanation: 'Matching contents', evidence: ['SHA-256 matches'], file_event_ids: [7], usb_event_ids: [2],
    }] }).items[0]
    assert.equal(alert.verdict, verdict)
    assert.deepEqual(alert.evidence, ['SHA-256 matches'])
    assert.deepEqual(alert.fileEventIds, [7])
    assert.equal(alert.severity, 'CRITICAL')
  }
})

test('status and file stats normalize nested snake_case keys without inventing network activity', () => {
  const status = normalizeObject({ source: 'live', data: { running: false, usb_monitor: { last_error: 'CIM failed' }, file_monitor: { removable_watches: ['G:\\'] } } })
  assert.equal(status.running, false)
  assert.equal(status.usbMonitor.lastError, 'CIM failed')
  assert.deepEqual(status.fileMonitor.removableWatches, ['G:\\'])
  assert.equal('networkMonitor' in status, false)
  const stats = normalizeObject({ source: 'live', data: { total_events: 0, sensitive_files: 0 } })
  assert.deepEqual(stats, { totalEvents: 0, sensitiveFiles: 0 })
})

test('zero results are valid; sample and malformed responses fail visibly', () => {
  assert.deepEqual(normalizeList({ source: 'live', data: [], total: 0 }), { items: [], total: 0, limit: 0 })
  for (const payload of [{}, { source: 'mock', data: [], total: 0 }, { source: 'live', data: {}, total: 0 }, { source: 'live', data: [] }]) {
    assert.throws(() => normalizeList(payload))
  }
  assert.throws(() => normalizeObject({ source: 'live', data: null }))
})

test('HTTP and JSON failures reject instead of falling back to mocks; abort is passed to fetch', async () => {
  const original = globalThis.fetch
  try {
    const controller = new AbortController()
    globalThis.fetch = async (url, options) => {
      assert.equal(options.signal, controller.signal)
      assert.match(url, /\/api\/usb\/devices$/)
      return { ok: false, status: 503 }
    }
    await assert.rejects(getUsbDevices({ signal: controller.signal }), /HTTP 503/)
    globalThis.fetch = async () => ({ ok: true, json: async () => { throw new Error('broken') } })
    await assert.rejects(get('/status'), /invalid JSON/)
    globalThis.fetch = async () => { throw new Error('Backend unavailable') }
    await assert.rejects(getUsbDevices(), /Backend unavailable/)
  } finally { globalThis.fetch = original }
})
