import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizeUsbSimulation } from './normalize.js'
import { getUsbSimulation, startUsbSimulation, clearUsbSimulation } from './api.js'
import { forensicsPresentation, connectedUsbPresentation } from './usbPresentation.js'

const status = (extra = {}) => ({ source: 'live', data: { enabled: true, phase: 'armed',
  devices: [{ deviceId: 'USB\\ACTUAL', name: 'Physical stick', vendorId: '1234', productId: 'ABCD', mounts: ['E:\\'], unavailableReason: null }],
  message: 'Waiting for inspection', actualDeviceId: 'USB\\ACTUAL', observation: null, alert: null, simulatedAlertCount: 0, ...extra } })

test('guarded simulation mutation activates only selected physical identity and preserves server reasons', async () => {
  const original = globalThis.fetch
  const calls = []
  try {
    globalThis.fetch = async (url, options) => { calls.push({ url, options }); return { ok: true, json: async () => status() } }
    const data = await startUsbSimulation('USB\\ACTUAL')
    assert.equal(data.phase, 'armed'); assert.equal(data.alert, null)
    assert.equal(calls[0].options.method, 'POST')
    assert.equal(calls[0].options.headers['X-ExfilTrace-Simulation'], '1')
    assert.deepEqual(JSON.parse(calls[0].options.body), { deviceId: 'USB\\ACTUAL' })
    assert.match(calls[0].url, /\/api\/usb\/simulation$/)
    await clearUsbSimulation()
    assert.equal(calls[1].options.method, 'DELETE'); assert.equal(calls[1].options.body, undefined)
    globalThis.fetch = async () => ({ ok: false, status: 409, json: async () => ({ error: 'Device already has a keyboard function' }) })
    await assert.rejects(startUsbSimulation('USB\\ACTUAL'), /already has a keyboard/)
    globalThis.fetch = async () => ({ ok: false, status: 403, json: async () => ({ error: 'Simulation disabled' }) })
    await assert.rejects(clearUsbSimulation(), /disabled/)
  } finally { globalThis.fetch = original }
})

test('simulation fetch forwards cancellation and retains explicit provenance and isolated evidence', async () => {
  const original = globalThis.fetch, controller = new AbortController()
  const payload = status({ phase: 'finding', simulatedAlertCount: 1,
    observation: { simulated: true, actualDeviceId: 'USB\\ACTUAL', inspection: { interfaces: [{ simulated: true, functions: ['keyboard', 'hid'] }] } },
    alert: { simulated: true, title: 'SIMULATED — possible USB impersonation', previousFunctions: ['storage'],
      currentFunctions: ['storage', 'hid', 'keyboard'], previousFingerprint: 'old', currentFingerprint: 'new', changedCharacteristics: [{ field: 'interfaces' }] } })
  try {
    globalThis.fetch = async (_, options) => {
      assert.equal(options.signal, controller.signal)
      return { ok: true, json: async () => payload }
    }
    const data = await getUsbSimulation({ signal: controller.signal })
    assert.equal(data.simulatedAlertCount, 1)
    assert.equal(data.observation.inspection.interfaces[0].simulated, true)
    assert.deepEqual(data.alert.currentFunctions, ['storage', 'hid', 'keyboard'])
    assert.equal(data.alert.previousFingerprint, 'old')
    assert.equal(data.devices[0].mounts[0], 'E:\\')
  } finally { globalThis.fetch = original }
})

test('disabled, empty and partial states are valid; unmarked findings are rejected', () => {
  assert.equal(normalizeUsbSimulation(status({ enabled: false, phase: 'idle', devices: [] })).enabled, false)
  const partial = normalizeUsbSimulation(status({ phase: 'paused', devices: [{ deviceId: 'USB\\ACTUAL', unavailableReason: 'Partial query' }] }))
  assert.equal(partial.devices[0].unavailableReason, 'Partial query')
  assert.throws(() => normalizeUsbSimulation(status({ alert: { title: 'Finding' } })), /explicitly mark/)
  assert.throws(() => normalizeUsbSimulation(status({ observation: { simulated: false } })), /explicitly mark/)
  assert.throws(() => normalizeUsbSimulation({ source: 'mock', data: {} }))
})

test('forensics view shows keyboard characteristics without provenance labels or fabricated Windows identifiers', () => {
  const original = { deviceId: 'USB\\ACTUAL', fingerprint: { sha256: 'unchanged' }, simulated: true,
    inspection: { interfaces: [{ instanceId: 'SIMULATED\\KEYBOARD', name: 'SIMULATED keyboard/HID overlay',
      simulated: true, parentId: 'USB\\ACTUAL', pnpClass: 'Keyboard', functions: ['hid', 'keyboard'],
      hardwareIds: ['EXFILTRACE_SIMULATION\\KEYBOARD'], compatibleIds: ['EXFILTRACE_SIMULATION\\HID'] }] },
    observation: { history: [{ changes: [{ field: 'interfaces', after: [{ pnpClass: 'Keyboard',
      functions: ['hid', 'keyboard'], hardwareIds: ['EXFILTRACE_SIMULATION\\KEYBOARD'], compatibleIds: [] }] }] }] } }
  const baseline = structuredClone(original)
  const displayed = forensicsPresentation(original)
  const keyboard = displayed.inspection.interfaces[0]
  assert.equal(keyboard.name, 'Keyboard / HID interface')
  assert.equal(keyboard.pnpClass, 'Keyboard')
  assert.deepEqual(keyboard.functions, ['hid', 'keyboard'])
  assert.equal(keyboard.instanceId, null)
  assert.deepEqual(keyboard.hardwareIds, [])
  assert.equal(keyboard.simulated, undefined)
  assert.equal(displayed.fingerprint.sha256, 'unchanged')
  assert.doesNotMatch(JSON.stringify(displayed.observation.history), /EXFILTRACE_SIMULATION/)
  assert.deepEqual(original, baseline)
})

test('shared connected-device view highlights only the finding identity and resets without changing physical data', () => {
  const physical = [{ id: 'A', deviceId: 'USB\\A', name: 'Same model', vendorId: '1234', productId: 'ABCD', inspection: { functions: ['storage'] } },
    { id: 'B', deviceId: 'USB\\B', name: 'Same model', vendorId: '1234', productId: 'ABCD', inspection: { functions: ['storage'] } }]
  const original = structuredClone(physical)
  const context = { observation: { ...physical[0], actualDeviceId: 'USB\\A', inspection: { functions: ['storage', 'hid', 'keyboard'] } },
    alert: { device: { deviceId: 'USB\\A' } } }
  const active = connectedUsbPresentation(physical, context)
  assert.deepEqual(active.map((d) => d.hasInterfaceFinding), [true, false])
  assert.deepEqual(active[0].inspection.functions, ['storage', 'hid', 'keyboard'])
  assert.deepEqual(active[1].inspection.functions, ['storage'])
  assert.deepEqual(connectedUsbPresentation(physical, { alert: null }).map((d) => d.hasInterfaceFinding), [false, false])
  assert.deepEqual(connectedUsbPresentation(physical, { observation: context.observation }).map((d) => d.hasInterfaceFinding), [false, false])
  assert.deepEqual(connectedUsbPresentation([], context), [])
  assert.deepEqual(physical, original)
})
