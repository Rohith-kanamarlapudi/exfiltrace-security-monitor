import test from 'node:test'
import assert from 'node:assert/strict'
import { exportReport, getReports } from './api.js'

test('reports fetch live session evidence and reject malformed or failed responses', async () => {
  const original = globalThis.fetch
  const report = { id: 'RPT-USB-000001', timestamp: '2026-11-03T10:05:00Z', file_count: 1,
    network_available: true, timeline: [{ time: '2026-11-03T10:00:00Z', title: 'USB connected', type: 'usb' }] }
  try {
    let requested
    globalThis.fetch = async (url, options) => {
      requested = { url, signal: options.signal }
      return { ok: true, json: async () => ({ data: [report], total: 1, source: 'live' }) }
    }
    const controller = new AbortController()
    const result = await getReports({ signal: controller.signal })
    assert.equal(requested.url, 'http://127.0.0.1:5000/api/reports?limit=100')
    assert.equal(requested.signal, controller.signal)
    assert.equal(result.items[0].fileCount, 1)
    assert.equal(result.items[0].networkAvailable, true)
    globalThis.fetch = async () => ({ ok: true, json: async () => ({ data: [], source: 'sample' }) })
    await assert.rejects(getReports(), /Invalid live API response/)
    globalThis.fetch = async () => ({ ok: false, status: 503 })
    await assert.rejects(getReports(), /HTTP 503/)
  } finally { globalThis.fetch = original }
})

test('report export downloads the report XML blob', async () => {
  const original = globalThis.fetch
  const blob = new Blob(['<report/>'], { type: 'application/xml' })
  try {
    let requested
    globalThis.fetch = async (url, options) => {
      requested = { url, cache: options.cache }
      return { ok: true, blob: async () => blob }
    }
    assert.equal(await exportReport('RPT-USB-000001'), blob)
    assert.equal(requested.url, 'http://127.0.0.1:5000/api/reports/RPT-USB-000001/export')
    assert.equal(requested.cache, 'no-store')
  } finally { globalThis.fetch = original }
})
