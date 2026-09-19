// @vitest-environment jsdom
// web/src/useEventStream.test.ts — renderHook against a mock EventSource
// installed on globalThis (node/jsdom ships none). Asserts the feed contract:
// every SSE data line becomes a row, newest first, capped at FEED_CAP rows.
import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { FEED_CAP, useEventStream } from './useEventStream'
import type { EventRow } from './types'

/** Minimal EventSource double: records instances, delivers data lines, and
 * can simulate a socket that fully closed (readyState CLOSED + onerror). */
class MockEventSource {
  static instances: MockEventSource[] = []
  static readonly CONNECTING = 0
  static readonly OPEN = 1
  static readonly CLOSED = 2

  url: string
  readyState: number = MockEventSource.OPEN
  onmessage: ((ev: MessageEvent) => void) | null = null
  onerror: ((ev: Event) => void) | null = null

  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
  }

  close(): void {
    this.readyState = MockEventSource.CLOSED
  }

  emit(row: unknown): void {
    this.onmessage?.({ data: JSON.stringify(row) } as MessageEvent)
  }

  failAsClosed(): void {
    this.readyState = MockEventSource.CLOSED
    this.onerror?.(new Event('error'))
  }
}

function makeRow(seq: number): EventRow {
  return {
    event_id: `00000000-0000-0000-0000-${String(seq).padStart(12, '0')}`,
    raw_id: `10000000-0000-0000-0000-${String(seq).padStart(12, '0')}`,
    fingerprint_id: `fp-${seq}`,
    rule_version: 1,
    status: seq % 2 === 0 ? 'parsed' : 'unparsed',
    parsed_at: new Date(Date.UTC(2026, 8, 19, 12, 0, seq)).toISOString(),
    ocsf: null,
  }
}

beforeEach(() => {
  MockEventSource.instances = []
  vi.stubGlobal('EventSource', MockEventSource as unknown as typeof EventSource)
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('useEventStream', () => {
  it('subscribes to the gateway SSE stream', () => {
    renderHook(() => useEventStream())
    expect(MockEventSource.instances).toHaveLength(1)
    expect(MockEventSource.instances[0]?.url).toBe('/api/stream/events')
  })

  it('prepends each event, newest first', () => {
    const { result } = renderHook(() => useEventStream())
    const es = MockEventSource.instances[0]
    act(() => {
      for (const seq of [1, 2, 3]) es?.emit(makeRow(seq))
    })
    expect(result.current).toHaveLength(3)
    // row[0] is the last-received event
    expect(result.current[0]?.fingerprint_id).toBe('fp-3')
    expect(result.current[1]?.fingerprint_id).toBe('fp-2')
    expect(result.current[2]?.fingerprint_id).toBe('fp-1')
  })

  it(`caps the feed at ${FEED_CAP} rows`, () => {
    const { result } = renderHook(() => useEventStream())
    const es = MockEventSource.instances[0]
    act(() => {
      for (let seq = 1; seq <= FEED_CAP + 5; seq++) es?.emit(makeRow(seq))
    })
    expect(result.current).toHaveLength(FEED_CAP)
    // newest survives at the head...
    expect(result.current[0]?.fingerprint_id).toBe(`fp-${FEED_CAP + 5}`)
    // ...and the FEED_CAP-th oldest is the first to fall off the tail
    expect(result.current[FEED_CAP - 1]?.fingerprint_id).toBe('fp-6')
  })

  it('drops malformed data lines instead of poisoning the feed', () => {
    const { result } = renderHook(() => useEventStream())
    const es = MockEventSource.instances[0]
    act(() => {
      es?.emit(makeRow(1))
      es?.onmessage?.({ data: 'not-json' } as MessageEvent)
      es?.emit(makeRow(2))
    })
    expect(result.current).toHaveLength(2)
    expect(result.current[0]?.fingerprint_id).toBe('fp-2')
  })

  it('reconnects once after a 2s backoff when the socket fully closes', () => {
    vi.useFakeTimers()
    renderHook(() => useEventStream())
    expect(MockEventSource.instances).toHaveLength(1)

    act(() => {
      MockEventSource.instances[0]?.failAsClosed()
    })
    // no immediate reconnect — the 2s backoff guards a flapping gateway
    expect(MockEventSource.instances).toHaveLength(1)

    act(() => {
      vi.advanceTimersByTime(2000)
    })
    expect(MockEventSource.instances).toHaveLength(2)
    expect(MockEventSource.instances[1]?.url).toBe('/api/stream/events')
  })

  it('closes the socket on unmount', () => {
    const { unmount } = renderHook(() => useEventStream())
    const es = MockEventSource.instances[0]
    expect(es?.readyState).toBe(MockEventSource.OPEN)
    unmount()
    expect(es?.readyState).toBe(MockEventSource.CLOSED)
  })
})
