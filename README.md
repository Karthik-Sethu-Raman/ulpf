# ULPF — Universal Log Pre-processing Framework

A prototype built for Smart India Hackathon 2026, Problem Statement 26156
(NTRO, Blockchain & Cybersecurity theme).

## What this is

ULPF ingests security logs from perimeter network devices (firewalls,
IDS, VPN gateways) in heterogeneous vendor formats — Syslog, CEF, LEEF,
JSON, CSV, and undocumented proprietary formats — and normalizes them
into a common schema (OCSF) for SIEM and analytics use.

The core design idea: when a genuinely new, unrecognized log format
appears, a small local language model (SLM) proposes a parsing rule
(a regex + field mapping) from a handful of sample lines. A human
reviews, edits, or overrides that candidate before it's trusted on real
traffic. From that point on, parsing is fully deterministic — the model
is never called again for that format unless it later drifts.

## Architecture

```
Perimeter device logs
        |
   Ingestion + raw storage (immutable, before any processing)
        |
   Format fingerprinting (deterministic, no model calls)
        |
   Known format? ----no----> SLM generates candidate rule
        |                          |
       yes                    Human review (approve/edit/override)
        |                          |
   Deterministic parser  <---------+
        |
   Normalized OCSF event (linked to raw log for traceability)
        |
   Drift monitoring (continuous; degraded rules fail closed)
        |
   SIEM / data lake
```

Full technical rationale, design decisions, and references are in
`docs/`.

## Repo structure

```
schemas/schemas.py       — canonical data contracts used by every module
onboarding/               — SLM-based rule generation for new formats
parser_engine/            — format fingerprinting + deterministic parsing
ingestion/                — raw log storage, traceability, rule validation
review_ui/                — Streamlit review-gate UI + event browser
drift_monitor/            — rule health tracking and drift response
testdata/                 — sample logs, fixtures, integration test runner
app.py                    — wires every module into the end-to-end pipeline
docs/                     — module-level documentation
```

## Running it

**One-time setup:**
```
pip install ollama streamlit
ollama pull ibm/granite4.1:3b   # or a larger tag if available
```

**Run the full pipeline once, to onboard and register rules:**
```
python testdata/integration_runner.py
```

**Launch the review UI (uses the rules the runner just registered):**
```
streamlit run review_ui/app.py
```

Run the integration runner at least once before the UI — the UI reads
from the same persisted rule store, and falls back to fixture data if
no real rules are registered yet.

## Module documentation

- [`docs/onboarding.md`](docs/onboarding.md) — SLM rule generation
- [`docs/parser-engine.md`](docs/parser-engine.md) — fingerprinting + deterministic parsing
- [`docs/ingestion.md`](docs/ingestion.md) — raw storage + rule validation
- [`docs/review-ui.md`](docs/review-ui.md) — human review gate + event browser
- [`docs/drift-monitor.md`](docs/drift-monitor.md) — rule health monitoring
- [`docs/testing.md`](docs/testing.md) — test data and the integration runner

## Scope notes

Built as a hackathon prototype in a short timeframe. A few deliberate
scope decisions, documented for transparency rather than hidden:

- **Kafka, Postgres**, and horizontally-scaled deployment are part of
  the intended production architecture (see the idea presentation) but
  are not implemented here — SQLite and in-process function calls are
  sufficient to demonstrate the design at prototype scale.
- **Drift detection** uses simple threshold-based severity
  classification, not full statistical process control — documented as
  the honest scope for this stage.
- One deliberately difficult, invented vendor format is intentionally
  left un-auto-onboarded in test data, to demonstrate the manual
  override path when the model can't fully resolve a format on its own.