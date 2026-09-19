// web/src/useEventStream.ts — SSE subscription feeding the live table.
//
// One EventSource on /api/stream/events; every `data:` line is an EventRow
// JSON payload (gateway serializes UUIDs as strings) which is prepended and
// the feed capped at FEED_CAP rows client-side. Newest ends up first because
// the server snapshot arrives oldest-first and later rows are newer.
//
// Reconnect policy: while the browser keeps retrying (readyState CONNECTING)
// EventSource's built-in retry handles it; once the socket is fully CLOSED we
// close it for good and come back after a 2s backoff so a down gateway can't
// flap the feed hot.
import { useEffect, useState } from 'react'
import type { EventRow } from './types'

export const FEED_CAP = 200

const RECONNECT_BACKOFF_MS = 2000

export function useEventStream(url: string = '/api/stream/events'): EventRow[] {
  const [rows, setRows] = useState<EventRow[]>([])

  useEffect(() => {
    let source: EventSource | null = null
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null
    let disposed = false

    const connect = () => {
      source = new EventSource(url)
      source.onmessage = (event: MessageEvent) => {
        let row: EventRow
        try {
          row = JSON.parse(event.data) as EventRow
        } catch {
          console.warn('useEventStream: dropped malformed SSE data line')
          return
        }
        setRows((prev) => [row, ...prev].slice(0, FEED_CAP))
      }
      source.onerror = () => {
        if (source !== null && source.readyState === EventSource.CLOSED) {
          scheduleReconnect()
        }
      }
    }

    const scheduleReconnect = () => {
      source?.close()
      source = null
      if (!disposed && reconnectTimer === null) {
        reconnectTimer = setTimeout(() => {
          reconnectTimer = null
          connect()
        }, RECONNECT_BACKOFF_MS)
      }
    }

    connect()

    return () => {
      disposed = true
      if (reconnectTimer !== null) clearTimeout(reconnectTimer)
      source?.close()
      source = null
    }
  }, [url])

  return rows
}
