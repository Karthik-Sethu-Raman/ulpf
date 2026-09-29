# M3 drift detection — ruling record

How firmware drift on a live rule is detected, graduated, and recovered, and
why the pieces look the way they do. Migrating decisions from the M3 plan
brainstorm (2026-09-21, rulings R-M3-1..11) are recorded here because they
bind later milestones. Numbers below are measured on the live compose stack
(Task 12 exit gate) unless marked as a default.

## R-M3-1 — the drift service reads the DB current view, not the topic

One convergent loop (`services/drift/app.py`, cold path, Postgres only — no
Kafka consumer) polls the active rules and statelessly recomputes each
`(fingerprint_id, rule_version)`'s windows from
`normalized_events WHERE superseded_by_event_id IS NULL AND rule_version =
<active>` (the `ne_current_idx` semantics).

Why the DB and not `normalized.events`:

- **Correct by construction.** The topic is at-least-once and the M2 reparse
  sweep writes DB rows only — it emits no envelopes (M2 ledger R17). A topic
  consumer would need dedupe machinery AND would still miss backlog
  re-parses, i.e. it would be wrong in exactly the cases drift exists for.
- **Single replica needs no fencing.** Window math keyed by
  `(fingerprint_id, rule_version, field, window_start)` is idempotent under
  re-scan (`ON CONFLICT DO NOTHING`); a consumer group adds offsets, commits,
  and rebalance races that a single cold-path reader has no use for.
- **Fail-closed posture.** A failed scan is logged and retried next poll
  (`ULPF_DRIFT_POLL_S`, default 5 s); drift can never block the hot path.

Rejected alternatives: **hybrid topic + DB** (two feeds to merge, ~1.5 tasks
more, no correctness gain at MVP scale — the DB already holds the topic's
information plus the reparse rows); **topic-only** (contradicts the R17
ledger ruling — misses reparse rows).

**R17 topic note:** `normalized.events` remains produced by the pipeline in
M3 exactly as in M2 — all-status envelopes keyed by `fingerprint_id`,
at-least-once, dedupable by `(raw_id, rule_version)` — but nothing consumes
it in the MVP. It is the documented future streaming path: when drift (or any
other consumer) needs multi-replica scale-out, §7.1's per-partition ownership
applies and the DB poll becomes a topic read plus the same window math.

## R-M3-2 — stateless windows, INSERT-only

Each scan slices the version's current view (ordered by `parsed_at`) into
windows that close on **count** (`ULPF_DRIFT_WINDOW_COUNT`, default 1000
rows) **or time** (`ULPF_DRIFT_WINDOW_TIME_S`, default 600 s), whichever
first; the trailing partial is held back (it may still grow). `window_start`
is the `parsed_at` of the window's first row, so the primary key
`(fingerprint_id, rule_version, field, window_start)` is deterministic from
data: re-scans INSERT nothing new (`ON CONFLICT DO NOTHING`), and no cursor
table or UPDATE grant on drift tables exists. The acceptance smoke runs the
demo with `ULPF_DRIFT_WINDOW_COUNT=30` plus a time horizon no demo gap can
cross (count-close only — deterministic 30-row boundaries the smoke's tuning
replica models exactly). The brief's original 15 s time horizon was measured
unsound on the accumulating DB: it slices the days-spread M1/M2 history into
~255 one-row windows at the first scan, arming an all-zero baseline from ten
of them, after which the tier-2 null ladder deactivates the rule at any 5%
null rate — before the moderate quarantine (Assert J) can ever land
(observed live; recorded in `scripts/smoke.py`'s header).

Windows are recomputed from the whole current view every scan — including
already-recorded ones, whose findings are re-evaluated. That is what makes
enforcement convergent after a baseline arms (the establishing scan is
tier-1-only by construction: the profile row is inserted only after that
scan's windows are recorded, so its findings predate the profile), and it is
also why a severe window is permanent for its version: recovery is a version
bump, not a wait (see the restoration note under R-M3-11).

## R-M3-3/R-M3-11 — the grant matrix is the design; enforcement is graduated

`deploy/migrations/007_drift_tables.sql` (natural PKs only — no serials, so
the 004/005/006 sequence-grant bug class is structurally impossible; the only
serial-backed INSERT drift makes is `audit_log`, whose sequence is granted):

```sql
-- deploy/migrations/007_drift_tables.sql — M3 drift detection (R-M3-2/3).
-- Natural PKs ONLY (no serials): the 004/005/006 sequence-grant bug class is
-- structurally impossible here. Drift writes are INSERT-only.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='drift_role') THEN
    CREATE ROLE drift_role LOGIN PASSWORD 'drift_dev'; END IF;
END $$;

CREATE TABLE drift_windows (
  fingerprint_id TEXT NOT NULL,
  rule_version   INT NOT NULL,
  field          TEXT NOT NULL,        -- OCSF path, 'unmapped.<key>', or '__rule__' sentinel
  window_start   TIMESTAMPTZ NOT NULL, -- parsed_at of the window's first event (deterministic key)
  window_end     TIMESTAMPTZ NOT NULL,
  events_count   INT NOT NULL,
  null_rate      REAL,
  match_rate     REAL,                 -- '__rule__' rows: parsed / (parsed + parse_error)
  violation_rate REAL,                 -- tier-1 invariant violations for this field
  shape_dist     JSONB,                -- {"ipv4": 12, "int": 3, ...} over non-null scalar values
  severity       TEXT NOT NULL CHECK (severity IN ('none','minor','moderate','severe')),
  action_taken   TEXT CHECK (action_taken IS NULL OR action_taken IN
                ('alert','field_quarantined','rule_deactivated')),
  scanned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (fingerprint_id, rule_version, field, window_start)
);
CREATE INDEX drift_windows_recent ON drift_windows (fingerprint_id, window_start DESC);

CREATE TABLE baseline_profiles (
  fingerprint_id TEXT NOT NULL,
  rule_version   INT NOT NULL,
  field          TEXT NOT NULL,
  profile        JSONB NOT NULL,       -- {events_count, null_rate, match_rate, shape_dist}
  windows_seen   INT NOT NULL,
  established_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (fingerprint_id, rule_version, field)
);

-- drift service (detection + enforcement, R-M3-3)
GRANT SELECT ON normalized_events, rules TO drift_role;
GRANT INSERT ON drift_windows, baseline_profiles TO drift_role;
-- P-2: drift_role self-reads — baseline existence checks + recent-window lookups.
GRANT SELECT ON drift_windows, baseline_profiles TO drift_role;
GRANT UPDATE (quarantined_fields) ON rules TO drift_role;
GRANT UPDATE (status, deactivated_at) ON rules TO drift_role;
GRANT INSERT ON audit_log TO drift_role;
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO drift_role;

-- gateway: human override of quarantine (audited, rules_role write path)
GRANT UPDATE (quarantined_fields) ON rules TO rules_role;
-- gateway SELECT on both new tables arrives via 003's ALTER DEFAULT PRIVILEGES.
```

drift_role never INSERTs rules; rule content stays immutable for every role.
Every enforcement mutation carries its expected-state predicate in the WHERE
(`status = 'active'`, `NOT (field = ANY(quarantined_fields))`) with a
rowcount check — a no-op returns False and writes NO audit row — and the
audit INSERT is paired inside the same transaction, actor `drift`.

Graduated enforcement per (field, window), severity = max(tier-1, tier-2
signals), enforced worst-first with one deactivate per fingerprint per scan:

- `minor` → alert only (the `drift_windows` row IS the alert).
- `moderate` → `field_quarantined` (idempotent append to
  `rules.quarantined_fields`).
- `severe` → `rule_deactivated`; the fingerprint reverts to raw-only and
  re-enters onboarding through the M2 `_READY_SQL` path (samples re-accumulate
  — zero onboarding changes needed).
- Quarantined fields are still measured and still escalate: quarantine
  suppresses only a redundant re-quarantine, never a finding — a quarantined
  field going severe still deactivates the rule.
- `unmapped.*` rows are new-key-emergence signals only: alert-only,
  `decide_action` bypassed (binding Task-4 review ruling).

Humans override any state: `POST /api/rules/{fp}/unquarantine` (rules_role,
audited, `field_unquarantined`) and the M2
reactivate/deactivate endpoints. Restoration note (measured live in the Task
12 smoke): a reactivated version whose current view still contains severe
windows is re-deactivated by the next scan — recovery from a real drift event
is a **version bump** (approve a successor rule; the M2 backlog sweep
supersedes the poisoned version's rows out of its drift view), which is the
same path a human edit takes.

## R-M3-4/R-M3-5 — two detection tiers; the math is pure

**Tier 1 (from event zero, always on):** invariant-violation rates over the
stored OCSF docs — `src/dst_endpoint.ip` IPv4 shape, ports int 0..65535,
`severity_id` int 0..6, `time` ISO-parsable — mirroring the candidate gate's
`_value_sanity` semantics at drift time (deliberately not an import:
candidate-time vs drift-time). Ladder: `<0.05 none, <0.20 minor, <0.50
moderate, else severe`.

**Tier 2 (armed once a baseline exists per `(fingerprint, version)`,
R-M3-7):** the first `ULPF_DRIFT_BASELINE_WINDOWS` (default 10) closed
windows aggregate into `baseline_profiles` (mean null_rate, mean match_rate,
min/max events_count, shape_dist summed and normalized); the profile row is
INSERTed once when the Nth window closes and never re-arms for that version —
a version bump re-arms naturally. Signals: null-rate ratio ladder (the legacy
demo's proven 3x/10x/40x + 0.05-absolute gate), match-rate absolute-drop
ladder (0.10/0.25/0.50), JS-divergence shape ladder (0.15/0.35/0.60,
add-1-smoothed, count-scaled), per-fingerprint volume bounds (silence severe,
outside minor). All of it lives in `libs/ulpf-core/ulpf_core/drift.py` —
stdlib-only, zero deps, fully unit-tested (Task 3: 37 tests; the drift
service suites add 102).

## R-M3-6 — quarantine is honored at parse time, new parses only

`ActiveRule` carries `quarantined_fields`; the pipeline worker builds a
parse-time rule copy with the quarantined mappings removed, so the captured
key lands in `ocsf.unmapped` automatically (spec §7.2 "mapping disabled,
values preserved" — no `parse()` API change). Measured in the Task 12 smoke:
after drift quarantined `src_endpoint.ip`, subsequent parses carried the SRC
value under `ocsf.unmapped.SRC` with `src_endpoint.ip` absent; after the human
un-quarantine, the next clean parses mapped `src_endpoint.ip` again.

Quarantine affects NEW parses only. The existing backlog is NOT auto
re-parsed — a deliberate scope line: a backlog re-parse requires a version
bump (a human edit/approve rides the M2 sweep, which re-parses stale rows and
supersedes the old version's view). Automatic backlog re-parse would need
either an onboarding-side quarantine awareness (re-parse honoring the
filter — not built, see "Deferred") or churn on every quarantine toggle.

## R-M3-9 — the demo: deterministic escalating firmware drift

`simulator/simulate.py --mode firmware-drift --drift-after S --duration D`
keeps the steady corpus set but corrupts syslog lines on the wire after the
deadline: a line is corrupted iff `(index * 2654435761 % 1000)/1000 <
phase`, `phase = clamp(elapsed_since_drift/span, 0, 1)`,
`span = max(duration - drift_after, 1.0)`; among corrupted lines `index % 3
== 0` renames `SRC` -> `SRCADDR` (a null at parse time) and the rest write
`SRC=uplink-trust-0x4f` (a tier-1 IP violation) — exactly 1:2 nulls to
violations. The corruption is deterministic (the seed IS the corpus line
index; no RNG state), which is what lets the acceptance smoke replicate the
math host-side and pre-tune each run (see `tune_drift_run` in
`scripts/smoke.py`). Only line content mutates — per-corpus counts, the other
corpora, and the `<name> sent=<N>` stdout contract are unchanged.

## Audit vocabulary additions

`action` gains `field_quarantined` and `field_unquarantined`; `rule_deactivated`
is reused with actor `drift` (enforcement) vs a human actor (gateway). The
closed set is now {`samples_split`, `candidate_created`, `candidate_failed`,
`rule_approved`, `rule_rejected`, `rule_deactivated`, `rule_reactivated`,
`field_quarantined`, `field_unquarantined`, `reparse_complete`}; entity =
fingerprint_id. Drift-side rows carry actor `drift` and detail
`{field, rule_id, version, window_start}` (quarantine) / `{rule_id, version,
window_start}` (deactivate).

## R-M3-10 — per-SOURCE volume deferred to M4

Per-fingerprint volume bounds ship now (`__rule__` sentinel rows carry
events_count min/max from the baseline; silence is severe — a dead feed never
looks healthy). Per-SOURCE volume needs a `raw_events` join
(`normalized_events` carries no `source_id`); deferred to M4 as polish — the
current-view granularity is what the spec's silence/flood signal needs at MVP
scale.

## Deferred, with numbers

- **Per-source volume** — see R-M3-10 above.
- **Re-parse honoring quarantine** — the M2 sweep re-parses under the rule's
  full mappings (it rebuilds the Rule without the quarantine filter), so a
  quarantined field's backlog re-parse maps it again. Measured consequence
  (Task 12): after K's deactivation window, the sweep's re-parsed rows
  re-introduce the violations at the new version. Bounded by the same
  version-bump recovery path above; not worth onboarding-side quarantine
  plumbing in M3.
- **Auth** — actor is a request field defaulting to "anonymous" (MVP has no
  auth); every mutation is audited regardless.
