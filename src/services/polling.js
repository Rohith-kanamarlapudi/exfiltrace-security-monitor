// Schedule after completion so slow requests never overlap.
export function startPolling(fetcher, notify, {
  interval = 3000, timeout = 10000, schedule = setTimeout, cancel = clearTimeout,
} = {}) {
  let stopped = false
  let nextTimer, timeoutTimer, controller
  async function poll() {
    controller = new AbortController()
    timeoutTimer = schedule(() => controller.abort(new Error('Request timed out')), timeout)
    try {
      const data = await fetcher({ signal: controller.signal })
      if (controller.signal.aborted) throw controller.signal.reason
      if (!stopped) notify({ data, error: null, updatedAt: new Date() })
    } catch (error) {
      if (!stopped) notify({ error, updatedAt: null })
    } finally {
      cancel(timeoutTimer)
      if (!stopped && interval > 0) nextTimer = schedule(poll, interval)
    }
  }
  void poll()
  return () => { stopped = true; cancel(nextTimer); cancel(timeoutTimer); controller.abort() }
}

export function applyPollResult(previous, result) {
  return {
    data: result.error ? previous.data : result.data,
    updatedAt: result.error ? previous.updatedAt : result.updatedAt,
    error: result.error, loading: false,
  }
}
