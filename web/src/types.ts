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

/** One audit_log row (gateway SELECT: id, ts, actor, action, entity, detail —
 * EXACTLY these 6 keys). `action` is the gateway's closed CHECK vocabulary
 * (samples_split, candidate_created, candidate_failed, rule_approved,
 * rule_rejected, rule_deactivated, rule_reactivated, reparse_complete) and is
 * rendered VERBATIM — the string IS the label (same ruling as the validation
 * checks grid). `detail` is the JSONB payload (object or null); `ts` is an
 * ISO-8601 string. */
export interface AuditRow {
  id: number
  ts: string
  actor: string
  action: string
  entity: string
  detail: object | null
}

/** GET /api/rules/{fp} response — every version of the fingerprint (newest
 * first) plus its audit trail (entity = fingerprint_id, latest 200). The
 * page renders `rules`; the embedded audit array is redundant with
 * GET /api/audit (Task 9 ruling) but part of the response shape. */
export interface RuleHistoryResponse {
  rules: RuleRow[]
  audit: AuditRow[]
}

/** GET /api/audit?fingerprint=&limit= response. */
export interface AuditResponse {
  audit: AuditRow[]
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

// --- M3 drift surfaces (Task 7 shapes, mirrored key for key; Task 10) ---------

/** drift_windows.severity CHECK vocabulary (migration 007 / SEVERITIES). */
export type DriftSeverity = 'none' | 'minor' | 'moderate' | 'severe'

/** drift_windows.action_taken CHECK vocabulary; null when the window's
 * severity warranted no action ("none", or an already-quarantined field —
 * the idempotent skip records no action). */
export type DriftAction = 'alert' | 'field_quarantined' | 'rule_deactivated'

/** One drift_windows row — GET /api/drift/metrics rows carry EXACTLY these
 * 12 keys (gateway _DRIFT_WINDOW_COLUMNS): the latest closed window per
 * (fingerprint_id, field). `field` is an OCSF path, 'unmapped.<key>', or
 * the '__rule__' sentinel; rates are 0..1 REALs, null where the window does
 * not measure that rate for the field (match_rate is __rule__-only;
 * violation_rate is null on unmapped rows); shape_dist is the JSONB
 * shape-class histogram over non-null scalar values ({} when the field
 * observed no values, null on __rule__ rows); timestamps ISO-8601 strings. */
export interface DriftMetricRow {
  fingerprint_id: string
  rule_version: number
  field: string
  window_start: string
  window_end: string
  events_count: number
  null_rate: number | null
  match_rate: number | null
  violation_rate: number | null
  shape_dist: Record<string, number> | null
  severity: DriftSeverity
  action_taken: DriftAction | null
}

/** GET /api/drift/metrics response. */
export interface DriftMetricsResponse {
  metrics: DriftMetricRow[]
}

/** One GET /api/drift/alerts row — ruling P-4's kind-discriminated union:
 * ONE latest-first merged list the endpoint already ordered (the page
 * renders it verbatim and never re-merges or re-sorts client-side).
 * "window" rows carry the drift_windows columns (minor/moderate/severe —
 * the row IS the alert); "audit" rows carry the audit_log shape with action
 * field_quarantined / field_unquarantined / rule_deactivated (any actor). */
export type DriftAlertRow =
  | (DriftMetricRow & { kind: 'window' })
  | (AuditRow & { kind: 'audit' })

/** GET /api/drift/alerts response. */
export interface DriftAlertsResponse {
  alerts: DriftAlertRow[]
}

/** POST /api/rules/{fp}/unquarantine body — the human override that removes
 * one field from the active rule's quarantined_fields (audited, paired in
 * the same transaction as the mutation). */
export interface UnquarantineBody {
  field: string
  actor?: string
  reason?: string
}

/** POST /api/rules/{fp}/unquarantine 200 response — the post-state list. */
export interface UnquarantineResponse {
  fingerprint_id: string
  field: string
  quarantined_fields: string[]
}
