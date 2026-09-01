# Role P6 — Test Data + Integration Test Runner

## Project context

We're building a prototype of ULPF — a system that ingests security logs
from perimeter devices in many vendor formats and normalizes them into a
common schema (OCSF), using an AI-assisted onboarding flow with human
review, deterministic parsing, and drift monitoring. Five other people
(P1-P5) are each building one module of this pipeline in isolation,
against shared fixture files. Your job is twofold: keep everyone supplied
with good mock data, and — critically — on day 3, be the person who can
answer "which module just broke" when everything gets wired together.
P1 will help you with this role too.

## Part 1 — Test data (days 1-2)

The repo already has a starting set in `/testdata/`:
- `raw_logs_cef.txt`, `raw_logs_syslog.txt`, `raw_logs_json.txt` — 2-3
  lines each, real-looking mock logs
- `fixtures/*.json` — one example of each schema type

**Your job: expand this.** Specifically:
1. Add 10-15 more lines to each raw log file, varied enough to be
   realistic (different IPs, ports, actions, severities) — this gives P1
   better SLM prompting material and gives everyone else more to test
   against.
2. Invent a 4th, deliberately "weird" format — a made-up vendor with a
   non-standard key=value layout that isn't CEF/LEEF/syslog/JSON. This is
   what makes the "unrecognized format" onboarding demo scene convincing
   rather than obviously staged.
3. Build the **drift simulation data**: working with P5, take a batch of
   normal-looking `NormalizedEvent`s and produce a sequence of batches
   where a field's null rate rises over "time" (see
   `/testdata/fixtures/drift_sequence.json` for the shape you're
   ultimately feeding into P5's functions).

## Part 2 — Integration test runner (day 3, main focus)

```python
# testdata/integration_runner.py
"""
Runs the full pipeline end to end and reports pass/fail per stage.
This does NOT contain new logic — it only calls other people's functions
in sequence and checks the output at each step.
"""

def run_pipeline(raw_log_lines: list[str], source_id: str):
    # Stage 1: ingest each line (P3)
    # Stage 2: fingerprint each (P2) -> known or unknown
    # Stage 3: for unknown fingerprints, generate a rule (P1)
    # Stage 4: validate the generated rule (P3)
    # Stage 5: (simulate) human approval -- for automated testing, just
    #          auto-approve if validation passed
    # Stage 6: apply the rule to produce NormalizedEvents (P2)
    # Stage 7: check drift on a batch of events (P5)
    # At each stage, print a clear PASS/FAIL line with the reason for
    # any failure, e.g.:
    #   "[FAIL] Stage 3 (rule generation): confidence 0.31 below threshold"
    ...
```

## Day-by-day

**Day 1**
- Expand the mock log files as described in Part 1, items 1-2.
- Read every other role's file (`ROLE_P1.md` through `ROLE_P5.md`) so you
  understand the full pipeline shape — you'll need this context for day
  3's debugging.

**Day 2**
- Work with P5 on the drift simulation data (Part 1, item 3).
- Start drafting `integration_runner.py` against fixtures (since most
  modules are still fixture-based on day 2) — you can build the
  structure and stage-checking logic now, even before real modules exist
  to plug in.

**Day 3**
- This is your main day. As P1 and others wire real modules into
  `app.py`, run `integration_runner.py` repeatedly and report exactly
  which stage is failing and why, to whoever owns that module.
- Help with final demo data selection — pick the cleanest, most
  convincing example run to show in the video/live demo.

## What makes a good bug report to a teammate

Since everyone's using different AI agents and won't be in the same room,
your bug reports need to be self-contained enough to hand directly to
their agent:
```
Stage 4 (validate_rule) failing for the syslog rule from P1.
Input: <paste the actual Rule JSON>
Held-out lines: <paste the actual lines>
Error: ip_fields_look_like_ips check returned False for field "SRC"
Expected: True, since SRC values in these lines are valid IPv4 addresses
```

## Instructions for your AI agent

Paste this whole file plus `schemas/schemas.py` and the other five role
files as context (your agent needs to understand every module's expected
interface to help debug integration). Ask it to help you build the mock
data first, then the integration runner, then use it actively on day 3 to
localize failures.
