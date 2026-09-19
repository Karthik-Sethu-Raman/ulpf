// web/src/types.ts — mirrors the frozen M1 gateway contract (Task 9,
// services/gateway/queries.py + app.py) key for key. EventRow carries EXACTLY
// these 7 keys; UUIDs arrive as strings (the gateway serializes UUIDs as JSON
// strings in REST and SSE alike), timestamps as ISO-8601 strings.

export type EventStatus = 'parsed' | 'unparsed' | 'parse_error' | 'quarantined'

/** Curated OCSF endpoint object (libs/ulpf-core parsing.py: {ip, port}); the
 * document sets it to null when the rule mapped nothing into it. */
export interface OcsfEndpoint {
  ip?: string
  port?: number | string | null
}

/** The OCSF document produced by the pipeline parser (class_uid 4001 shape):
 * src_endpoint/dst_endpoint are objects-or-null, unmapped carries captured
 * fields with no OCSF mapping. Present only when status = "parsed". */
export interface OcsfDocument {
  class_uid: number
  class_name: string
  activity_id: number
  severity_id: number | null
  time: string | null
  src_endpoint: OcsfEndpoint | null
  dst_endpoint: OcsfEndpoint | null
  action: string | null
  message: string | null
  metadata: { product: string }
  unmapped: Record<string, unknown>
}

/** One normalized event (current view) — GET /api/events rows and the
 * /api/stream/events SSE payload share this exact shape. */
export interface EventRow {
  event_id: string
  raw_id: string
  fingerprint_id: string
  rule_version: number | null
  status: EventStatus
  parsed_at: string
  ocsf: OcsfDocument | null
}

/** GET /api/events response. */
export interface EventsResponse {
  events: EventRow[]
}

/** One per-fingerprint aggregate from GET /api/stats. */
export interface FingerprintStats {
  fingerprint_id: string
  total: number
  parsed: number
}

/** GET /api/stats response (dlq_total is always null in M1). */
export interface Stats {
  raw_total: number
  by_status: Record<EventStatus, number>
  by_fingerprint: FingerprintStats[]
  events_last_minute: number
  dlq_total: number | null
}

/** GET /api/events/{event_id}/raw response — the raw line behind an event. */
export interface RawTrace {
  raw_id: string
  received_at: string
  source_id: string
  transport: string
  content_hash: string
  raw_text: string
}
