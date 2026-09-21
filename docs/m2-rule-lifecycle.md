# M2 rule lifecycle — ruling record

How an unknown-appliance fingerprint becomes an active parsing rule, and why
the pieces look the way they do. Migrating decisions from the M2 plan
brainstorm (2026-09-19) are recorded here because they bind later milestones.

## R11 — the grant matrix is the design

`deploy/migrations/003_m2_lifecycle.sql`:

```sql
-- gateway write path (approve/reject/manual/deactivate/reactivate)
GRANT SELECT, INSERT ON rules TO rules_role;
GRANT UPDATE (status, activated_at, deactivated_at) ON rules TO rules_role;
GRANT INSERT ON audit_log TO rules_role;
GRANT SELECT ON onboarding_samples TO rules_role;

-- onboarding service (candidate generation + backlog re-parse, R11)
GRANT SELECT, INSERT ON rules TO onboarding_role;
GRANT INSERT ON audit_log TO onboarding_role;
GRANT SELECT, UPDATE (role) ON onboarding_samples TO onboarding_role;
GRANT SELECT ON raw_events TO onboarding_role;
GRANT INSERT, SELECT, UPDATE (superseded_by_event_id) ON normalized_events TO onboarding_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON onboarding_attempts TO onboarding_role;
```

Completion note (migration `006_rules_sequence_grants.sql`): 003 granted the
TABLES but not the BIGSERIAL backing sequence, so the first live rules INSERT
— the Task 12 smoke's manual candidate — failed with "permission denied for
sequence rules_id_seq" (same bug class 004/005 fixed for the sample and audit
sequences; latent because unit tests mock the DB and no earlier live run ever
stored a rule). 006 grants `USAGE, SELECT ON SEQUENCE rules_id_seq` to
`rules_role` and `onboarding_role`; the sequence audit against
information_schema now covers every INSERT-granted table's sequence.

Content columns of `rules` are UPDATE-denied for every role — a candidate is
immutable once stored. The event store has exactly ONE mutable cell:
`normalized_events.superseded_by_event_id`, held by `onboarding_role`
(column-scoped; `services/onboarding/reparse.py` issues exactly that
`UPDATE ... SET superseded_by_event_id = %s`). Everything else is
append-only.

Rejected alternatives: **supersede-via-append** (mark old rows dead by
inserting tombstone rows) kills the `ne_current_idx` partial index, taxes
every hot-path query, and fights spec §4's current-view semantics; a
**migration-role batch** (run the sweep as a superuser from a migration)
opens a runtime superuser path. The sweep instead runs in the onboarding
service under its least-privilege role, batch by batch, each batch one
transaction (insert new-version rows + supersede old ones together), so a
crash never leaves a duplicated or orphaned backlog row and a re-run
converges: whatever stayed stale is re-found, swept rows are a no-op.

## R17 — the topic feed carries all statuses

The pipeline produces an envelope
`{event_id, raw_id, fingerprint_id, rule_version, status, ocsf?}` for EVERY
event — parsed, unparsed, and parse_error — keyed by `fingerprint_id`.
Two ledger notes for M3 drift:

- The topic is **at-least-once** and envelope produce precedes the persist
  transaction's commit, so consumers see duplicates. They are dedupable by
  construction: `event_id = uuid5(NAMESPACE, "{raw_id}:{rule_version}")` is
  deterministic, so dedup key = `(raw_id, rule_version)`.
- The **reparse sweep writes DB rows only — it emits no envelopes.** M3's
  drift detector must read the DB current view
  (`superseded_by_event_id IS NULL`, served by `ne_current_idx`), not the
  topic, or it would miss backlog re-parses.

The topic contract changed in M2 deliberately: no external consumer existed,
and M1's frozen contract was the HTTP API, not the topic. DLQ stays
pipeline-owned (hot path only); re-parse parse_errors are recorded as rows,
not DLQ messages.

## Version minting (X-b′) — versions are not gap-free

Candidates are created `pending_review` with `version = MAX(version)+1` for
the fingerprint. **Plain approve** flips the candidate row in place (status +
timestamps only — content columns are grant-denied). **Approve-with-edits**
INSERTs a fresh row at `version = MAX+1` with the edited content (provenance
`slm-edited`/`human`) and flips the draft candidate to `rejected` with audit
detail `consumed_by_edit`. Rejected candidates therefore burn version
numbers: gaps are expected and accepted. One pending candidate per fingerprint
(partial unique index). Every activation goes through one human-approved code
path.

## Audit vocabulary (closed set)

`action` ∈ {`samples_split`, `candidate_created`, `candidate_failed`,
`rule_approved`, `rule_rejected`, `rule_deactivated`, `rule_reactivated`,
`reparse_complete`}; entity = the fingerprint_id; detail JSONB carries
ids/actor/reason/counts. `actor` is a request field (MVP has no auth).

## Deferred, with numbers

- **Template miner (spec §9): NOT built.** M1's fragmentation bench
  (docs/m1-fragmentation.md) measured 100% mutation stability and zero
  fragmentation across all 5 golden corpora / 7 fingerprint groups (incl.
  `auto_9d3d5688` acmegw, `auto_8274266a` zenwall) — "only if the numbers
  warrant it" is answered no.
- **Baseline profiles (spec §6.2 step 7): M3.** Drift machinery needs
  tables that do not exist yet; migration 003's `ALTER DEFAULT PRIVILEGES`
  grants gateway SELECT on future tables so they inherit access when added.
- **SLM tier quality** is a recorded limitation of the default qwen3:4b
  tier on 8GB hosts (0 rules stored; docs/m2-slm-sanity.md). The human
  approval step and deterministic validation gate bound model quality:
  a weaker model costs retries and latency, never correctness.
