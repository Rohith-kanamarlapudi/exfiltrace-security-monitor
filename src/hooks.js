import { useEffect, useState } from 'react'
import { startPolling, applyPollResult } from './services/polling.js'

export function useApi(fetcher, interval = 3000) {
  const initial = { data: null, loading: true, error: null, updatedAt: null }
  const [state, setState] = useState(() => ({ ...initial, fetcher }))
  useEffect(() => {
    return startPolling(fetcher, (result) => setState((previous) => ({
      ...applyPollResult(previous.fetcher === fetcher ? previous : { data: null, updatedAt: null }, result), fetcher,
    })), { interval })
  }, [fetcher, interval])
  return state.fetcher === fetcher ? state : initial
}
