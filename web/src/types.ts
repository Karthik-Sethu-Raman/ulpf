// web/src/types.ts — mirrors the gateway contracts key for key: the frozen M1
// shapes below the marker (Task 9, services/gateway/queries.py + app.py) and
// the M2 rule-lifecycle shapes (Task 7). EventRow carries EXACTLY its 7 keys;
// UUIDs arrive as strings (the gateway serializes UUIDs as JSON strings in
// REST and SSE alike), timestamps as ISO-8601 strings.

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

// --- M2 rule lifecycle (Task 7 shapes, mirrored key for key; Task 8) ----------

/** One source-field -> OCSF-path row; rules.mappings JSONB and the
 * edited_mappings / override.mappings request bodies share this shape. */
export interface RuleMapping {
  source_field: string
  ocsf_path: string
}

/** One entry of ValidationReport.previews: the held-out sample line and what
 * the candidate parser produced for it (ocsf is null when status = "error"). */
export interface ValidationPreview {
  line: string
  status: 'parsed' | 'error'
  ocsf: object | null
}

/** The Task-3 deterministic gate's stored report (rules.validation JSONB, or
 * null on rows predating it). `checks` keys are the gate's verbatim check
 * names — the UI renders them as-is (Task 3 ruling: the key IS the label). */
export interface ValidationReport {
  passed: boolean
  checks: Record<string, boolean>
  held_out_match_rate: number
  notes: string[]
  previews: ValidationPreview[]
  prompt_count: number
  held_out_count: number
}

/** rules.status CHECK vocabulary (deploy/migrations/001_init.sql). */
export type RuleStatus =
  | 'pending_review'
  | 'active'
  | 'superseded'
  | 'deactivated'
  | 'rejected'

/** rules.provenance CHECK vocabulary. "slm-edited" marks approve-with-edits. */
export type RuleProvenance = 'slm' | 'slm-edited' | 'human'

/** GET /api/rules row — EXACTLY these 13 keys (gateway _RULE_COLUMNS).
 * `id` doubles as the candidate id in the approve/reject URLs; UUID-ish ids
 * are strings, timestamps ISO-8601 strings. */
export interface RuleRow {
  id: number
  fingerprint_id: string
  version: number
  pattern: string
  mappings: RuleMapping[]
  provenance: RuleProvenance
  confidence: number | null
  status: RuleStatus
  created_by: string
  created_at: string
  activated_at: string | null
  deactivated_at: string | null
  validation: ValidationReport | null
}

/** GET /api/rules response. */
export interface RulesResponse {
  rules: RuleRow[]
}

/** POST /api/rules/{fp}/candidates/{cid}/approve response. */
export interface ApproveResponse {
  rule_id: number
  version: number
  status: string
}

/** POST /api/rules/{fp}/candidates/{cid}/reject response. */
export interface RejectResponse {
  status: 'rejected'
}

/** POST /api/rules/{fp}/candidates/{cid}/approve body. */
export interface ApproveBody {
  actor: string
  reason?: string
  edited_mappings?: RuleMapping[]
  override?: { pattern: string; mappings: RuleMapping[] }
}

/** POST /api/rules/{fp}/candidates/{cid}/reject body. */
export interface RejectBody {
  actor: string
  reason?: string
}

/** GET /api/onboarding/samples?fingerprint=… row — per-fingerprint sample
 * accounting, by_role zero-filled (Task 9 renders the list form). */
export interface SamplesStatus {
  fingerprint_id: string
  total: number
  by_role: { prompt: number; held_out: number; unused: number }
  latest_captured_at: string | null
}

/** GET /api/onboarding/samples (no fingerprint) — the list form. */
export interface SamplesListResponse {
  samples: SamplesStatus[]
}
