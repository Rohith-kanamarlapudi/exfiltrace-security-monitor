import test from 'node:test'
import assert from 'node:assert/strict'
import { changeMonitoredFolder, getMonitoredFolders } from './api.js'

test('folder mutations preserve Windows paths, edit source and immediate watch status', async () => {
  const original = globalThis.fetch, calls = []
  const payload = { source: 'live', data: { monitored_directories: ['C:\\Work\\New folder'],
    folders: [{ path: 'C:\\Work\\New folder', active: true, error: null }],
    usbDirectories: [{ path: 'E:\\', active: true, removable: true }], monitorRunning: true } }
  try {
    globalThis.fetch = async (url, options) => {
      calls.push({ url, options }); return { ok: true, json: async () => payload }
    }
    const data = await changeMonitoredFolder('edit', 'C:\\Work\\New folder', 'C:\\Work\\Old')
    assert.match(calls[0].url, /\/api\/config\/directories$/)
    assert.equal(calls[0].options.method, 'POST')
    assert.deepEqual(JSON.parse(calls[0].options.body), { action: 'edit', path: 'C:\\Work\\New folder', previousPath: 'C:\\Work\\Old' })
    assert.equal(data.folders[0].active, true)
    assert.deepEqual(data.monitoredDirectories, ['C:\\Work\\New folder'])
    assert.equal(data.usbDirectories[0].removable, true)
    await changeMonitoredFolder('remove', 'C:\\Work\\New folder')
    assert.deepEqual(JSON.parse(calls[1].options.body), { action: 'remove', path: 'C:\\Work\\New folder' })
  } finally { globalThis.fetch = original }
})

test('folder polling forwards cancellation and failed mutations retain actionable errors', async () => {
  const original = globalThis.fetch, controller = new AbortController()
  try {
    globalThis.fetch = async (_, options) => {
      assert.equal(options.signal, controller.signal)
      return { ok: true, json: async () => ({ source: 'live', data: { folders: [{ path: 'C:\\Missing', active: false, error: 'Directory missing' }] } }) }
    }
    assert.equal((await getMonitoredFolders({ signal: controller.signal })).folders[0].active, false)
    for (const error of ['Already monitored', 'Path must be absolute', 'Could not watch replacement', 'Could not persist configuration']) {
      globalThis.fetch = async () => ({ ok: false, json: async () => ({ error }) })
      await assert.rejects(changeMonitoredFolder('add', 'C:\\Work'), (e) => e.message === error)
    }
  } finally { globalThis.fetch = original }
})
