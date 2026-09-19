// web/src/api.ts — thin fetch wrappers over the same-origin /api gateway
// (services/gateway, Task 9). Every wrapper throws on non-2xx so callers get
// a real error instead of a resolved promise with an error body.
//
// getEvents is part of the client surface mirroring the gateway (status /
// fingerprint filters arrive in M2); the Overview page itself is fed by the
// SSE stream, which already snapshots the latest rows on connect.
import type { EventsResponse, RawTrace, Stats } from './types'

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url)
  if (!res.ok) {
    throw new Error(`GET ${url} failed: ${res.status} ${res.statusText}`)
  }
  return (await res.json()) as T
}

export function getStats(): Promise<Stats> {
  return getJson<Stats>('/api/stats')
}

export interface EventQuery {
  status?: string
  fingerprint?: string
  limit?: number
  before?: string
}

export function getEvents(params: EventQuery = {}): Promise<EventsResponse> {
  const q = new URLSearchParams()
  if (params.status) q.set('status', params.status)
  if (params.fingerprint) q.set('fingerprint', params.fingerprint)
  if (params.limit !== undefined) q.set('limit', String(params.limit))
  if (params.before) q.set('before', params.before)
  const qs = q.toString()
  return getJson<EventsResponse>(`/api/events${qs ? `?${qs}` : ''}`)
}

export function getRaw(eventId: string): Promise<RawTrace> {
  return getJson<RawTrace>(`/api/events/${encodeURIComponent(eventId)}/raw`)
}
