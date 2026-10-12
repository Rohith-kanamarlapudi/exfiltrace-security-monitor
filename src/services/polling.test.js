import test from 'node:test'
import assert from 'node:assert/strict'
import { startPolling, applyPollResult } from './polling.js'
const flush = async () => { await Promise.resolve(); await Promise.resolve() }
function clock() {
  const timers = new Map()
  let id = 0
  return {
    timers,
    schedule: (fn, delay) => { timers.set(++id, { fn, delay }); return id },
    cancel: (key) => timers.delete(key),
    fire(delay) { const [key, timer] = [...timers].find(([, t]) => t.delay === delay); timers.delete(key); timer.fn() },
  }
}

test('polls only after completion and cleans up pending refresh on unmount', async () => {
  const timers = clock(), results = []
  let resolve, calls = 0
  const stop = startPolling(() => { calls++; return new Promise((r) => { resolve = r }) }, (r) => results.push(r), timers)
  assert.equal(calls, 1)
  assert.equal([...timers.timers.values()].some((t) => t.delay === 3000), false)
  resolve('first'); await flush()
  assert.equal(results[0].data, 'first')
  timers.fire(3000)
  assert.equal(calls, 2)
  stop(); resolve('late'); await flush()
  assert.equal(results.length, 1)
  assert.equal(timers.timers.size, 0)
})

test('cleanup aborts active request and ignores stale response', async () => {
  const timers = clock(), results = []
  let signal, resolve
  const stop = startPolling((options) => { signal = options.signal; return new Promise((r) => { resolve = r }) }, (r) => results.push(r), timers)
  stop()
  assert.equal(signal.aborted, true)
  resolve('stale'); await flush()
  assert.deepEqual(results, [])
})

test('timeout aborts hung request and retries; errors retain last successful data', async () => {
  const timers = clock(), results = []
  const stop = startPolling(({ signal }) => new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason))), (r) => results.push(r), timers)
  timers.fire(10000); await flush()
  assert.match(results[0].error.message, /timed out/)
  assert.equal([...timers.timers.values()].some((t) => t.delay === 3000), true)
  const initial = { data: null, loading: true, error: null, updatedAt: null }
  const good = applyPollResult(initial, { data: [], updatedAt: new Date(0), error: null })
  const stale = applyPollResult(good, results[0])
  assert.deepEqual(stale.data, [])
  assert.equal(stale.updatedAt, good.updatedAt)
  assert.equal(stale.loading, false)
  const recovered = applyPollResult(stale, { data: ['new'], updatedAt: new Date(1), error: null })
  assert.equal(recovered.error, null)
  assert.deepEqual(recovered.data, ['new'])
  stop()
})
