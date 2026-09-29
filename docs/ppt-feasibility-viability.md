# PPT feasibility & industry-viability points (slide 4 replacement copy)

Companion to `docs/ppt-accuracy-fixes.md`. Replacement text for the deck's
slide 4 ("FEASIBILITY AND VIABILITY"), reworked from idea-stage ("should
work") to prototype-stage ("does work, with numbers"). Every claim is true of
the merged repo (M2, a8f578d). The withdrawn claims stay out: no unmeasured
throughput figures, no Granite naming, no unverified research attribution.

Usage: drop the three sections into the slide's three template fields. If the
final-round template has a dedicated "viability in the industry" field, the
middle section lifts out as-is.

## Analysis and Feasibility of the idea

- **Built and verified, not proposed** — the full pipeline (ingest →
  fingerprint → normalize → human review → backlog re-parse) is merged and
  green: 244 automated tests, 8/8 end-to-end acceptance checks including a
  forced Kafka replay (0 duplicates, 0 losses) and independent re-verification
  of every Merkle hash-chain link
- **Proven building blocks only** — Redpanda (Kafka protocol), PostgreSQL,
  FastAPI, React, Ollama: no exotic dependencies; the whole stack demos on
  one laptop via `docker compose up`
- **Deterministic hot path** — per-event cost is regex + hashing, never
  inference; scale-out is Kafka partitions + worker replicas (benchmarks
  measured in M4 — no extrapolated throughput claims)
- **Tamper-evidence by construction** — immutable raw store with
  per-partition hash chains; the database roles themselves deny update/delete
  to the pipeline

## Viability — in the industry

- **Attacks the costliest step in log adoption** — per-vendor parser projects
  collapse into a review-and-approve cycle; analysts approve rules instead of
  writing them
- **Standards-aligned, not proprietary** — normalizes to OCSF (Linux
  Foundation; backed by AWS, Splunk, IBM and 30+ vendors) and exports
  JSONL/Parquet → integrates with existing SIEMs and data lakes, no
  rip-and-replace
- **Serves networks cloud AI cannot** — fully air-gapped operation (offline
  SLM, self-hosted UI assets, container bundle) fits government, defense,
  banking and OT/ICS deployments
- **Trust survives automation** — every rule versioned with provenance
  (slm / slm-edited / human), every transition audited, and no code path can
  activate a rule without a human action
- **Reversible adoption** — raw bytes are stored first and never mutated, so
  ULPF can sit in front of any existing pipeline; removing it loses nothing

## Potential Challenges → Strategies (paired)

| Challenge | Strategy (already built) |
|---|---|
| SLM rule quality varies with hardware | Deterministic 8-point validation gate + human approval **bound** model quality — a weaker model costs review time, never correctness (measured and documented on the default tier) |
| OCSF coverage is a curated subset | Unmapped fields are preserved, never dropped; extending the schema is additive work |
| Vendor formats drift silently | Tier-1 invariant checks fire from event zero (no baseline needed); tier-2 statistical drift arms after baseline; enforcement is fail-closed — quarantine or deactivate, never silently wrong data |
| Low-volume sources are hard to baseline | Windows close on event-count OR time, so a 40-events/day sensor is monitored on its own clock |

## Speaker notes (don't put on the slide)

- The strongest single sentence if a judge asks "is this real?": *"You can
  delete our consumer group mid-run and replay every message — the store
  comes out identical; that check runs in our acceptance gate."*
- If asked about the SLM tier honestly: the default 4B tier on modest CPU
  hardware stores zero rules unaided (documented in docs/m2-slm-sanity.md) —
  which is exactly why the architecture never lets model quality touch
  correctness: the gate + human review bound it, and manual authoring always
  works.
- If asked about scale numbers: commit only to "partitions + consumer-group
  workers; measured per-worker benchmarks are the M4 deliverable" — the spec
  explicitly withdrew unmeasured throughput claims.
