// web/src/api.ts — thin fetch wrappers over the same-origin /api gateway
// (services/gateway). Every wrapper throws on non-2xx so callers get a real
// error instead of a resolved promise with an error body. POST failures carry
// the FastAPI `detail` payload (string for 409s; {checks, notes} for 422
// validation failures) so the Review Queue can render the gate's verdict.
//
// The Overview page is fed by the SSE stream; getRules/getSamples serve the
// M2 review surfaces (Tasks 8/9), mirroring the gateway endpoint shapes.
import type {
  EventsResponse,
  RawTrace,
  RulesResponse,
  SamplesListResponse,
  SamplesStatus,
  Stats,
} from './types'

async function getJson<T>(url: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(url, { signal })
  if (!res.ok) {
    throw new Error(`GET ${url} failed: ${res.status} ${res.statusText}`)
  }
  return (await res.json()) as T
}

/** Format a non-2xx response body's `detail` for display: strings pass
 * through (409/404), objects are JSON-encoded (422 carries {checks, notes}). */
async function detailText(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { detail?: unknown }
    const d = body?.detail
    if (typeof d === 'string') return d
    if (d !== undefined) return JSON.stringify(d)
  } catch {
    /* body was not JSON — fall through to status text */
  }
  return `${res.status} ${res.statusText}`
}

async function postJson<T>(url: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal,
  })
  if (!res.ok) {
    throw new Error(`POST ${url} failed: ${await detailText(res)}`)
  }
  return (await res.json()) as T
}

export { postJson }

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

export function getRaw(eventId: string, signal?: AbortSignal): Promise<RawTrace> {
  return getJson<RawTrace>(
    `/api/events/${encodeURIComponent(eventId)}/raw`,
    signal,
  )
}

// --- M2 review surfaces (Task 7 endpoints; consumed by Tasks 8/9) ------------

export function getRules(params: { status?: string } = {}): Promise<RulesResponse> {
  const q = new URLSearchParams()
  if (params.status) q.set('status', params.status)
  const qs = q.toString()
  return getJson<RulesResponse>(`/api/rules${qs ? `?${qs}` : ''}`)
}

/** GET /api/onboarding/samples — single-fingerprint form (the row object)
 * when a fingerprint is given, the {samples: [...]} list form otherwise. */
export function getSamples(
  fingerprint?: string,
): Promise<SamplesStatus | SamplesListResponse> {
  const qs = fingerprint
    ? `?fingerprint=${encodeURIComponent(fingerprint)}`
    : ''
  return getJson<SamplesStatus | SamplesListResponse>(
    `/api/onboarding/samples${qs}`,
  )
}
