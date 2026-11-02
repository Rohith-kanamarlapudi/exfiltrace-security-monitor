import test from 'node:test'
import assert from 'node:assert/strict'
import { getUsbRecovery, changeUsbRecovery } from './api.js'

test('recovery state keeps candidate uncertainty and image provenance', async () => {
  const original = globalThis.fetch
  const data = { jobs: [{ imageSha256: 'abc', candidates: [{ status: 'uncertain' }] }], devices: [] }
  try {
    globalThis.fetch = async () => ({ ok: true, json: async () => ({ data, source: 'live' }) })
    assert.deepEqual(await getUsbRecovery(), data)
  } finally { globalThis.fetch = original }
})

test('recovery mutations use explicit guard header and preserve backend errors', async () => {
  const original = globalThis.fetch
  try {
    globalThis.fetch = async (url, options) => {
      assert.ok(url.endsWith('/usb/recovery/jobs/job-1'))
      assert.equal(options.headers['X-ExfilTrace-Recovery'], '1')
      assert.deepEqual(JSON.parse(options.body), { action: 'cancel' })
      return { ok: false, json: async () => ({ error: 'No active operation' }) }
    }
    await assert.rejects(changeUsbRecovery({ action: 'cancel' }, 'job-1'), /No active operation/)
  } finally { globalThis.fetch = original }
})
