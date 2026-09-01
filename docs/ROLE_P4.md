# Role P4 — Review-Gate UI + Normalized Event Browser

## Project context

We're building a prototype of ULPF — a system that ingests security logs
from perimeter devices in many vendor formats and normalizes them into a
common schema (OCSF). When a new/unknown log format shows up, a local AI
model generates a candidate parsing rule. Before that rule is trusted on
real traffic, a human has to look at it and approve, edit, or reject it.
**This review screen is the single most important screen in the whole
demo** — it's what proves the system isn't blindly trusting AI output.
You own it, plus a second screen showing the normalized events the system
has produced so far.

You don't need to wait for real AI-generated rules to start — build
against the fixture files first, they have the exact same shape.

## What to build

A **Streamlit app** with (at least) two pages/tabs:

### Page 1 — Rule Review
- Load a `Rule` + its `ValidationResult` (from fixtures on day 1, real
  data later).
- Display: the fingerprint_id, the regex pattern, a table of
  `field_mappings` (source field → OCSF path), the confidence score, and
  the validation checks (pass/fail per check, with notes).
- Show a "before → after" example: pick one raw sample line, show what the
  rule extracts and maps it to, side by side.
- Three buttons: **Approve**, **Edit**, **Override**.
  - Approve: just confirms the rule as-is (for the prototype, this can
    just print/log "approved" and mark it as usable — no need for
    complex state management).
  - Edit: let the user tweak the field_mappings table in the UI (a simple
    editable table is fine) before approving.
  - Override: let the user paste in a completely different pattern +
    mappings by hand.
- Whichever path is taken, tag the resulting rule's `provenance`
  correctly: `"slm-generated"` (approved as-is), `"slm-generated-edited"`,
  or `"human-authored"` (full override).

### Page 2 — Normalized Event Browser
- A table of `NormalizedEvent` records (from fixtures on day 1, real
  output later): event_id, class_name, time, src/dst endpoints,
  severity, action.
- Each row should have a way to view the linked raw log — a button or
  expander that calls `get_raw_event(raw_id)` (P3's function) and shows
  the original raw text.
- This screen demonstrates the traceability requirement directly — make
  sure the raw-to-normalized link is visually obvious, not buried.

## Schemas you're displaying (from schemas.py — do not redefine)

```python
@dataclass
class Rule:
    fingerprint_id: str
    pattern: str
    field_mappings: list[FieldMapping]   # each has .source_field, .ocsf_path
    confidence: float
    provenance: str
    version: int
    created_at: str

@dataclass
class ValidationResult:
    rule_fingerprint_id: str
    passed: bool
    checks: dict[str, bool]
    notes: str

@dataclass
class NormalizedEvent:
    event_id: str
    raw_id: str
    fingerprint_id: str
    rule_version: int
    class_name: str
    time: str
    severity_id: Optional[int]
    src_endpoint: Optional[dict]
    dst_endpoint: Optional[dict]
    action: Optional[str]
    unmapped_fields: dict
```

## Day-by-day

**Day 1**
- Set up the Streamlit app skeleton with both pages.
- Build Page 1 fully against `/testdata/fixtures/sample_rule.json` and
  `/testdata/fixtures/sample_validation_result.json`.
- Build Page 2 fully against `/testdata/fixtures/sample_normalized_event.json`
  (just wrap it in a list — even one row is enough to build the table UI).
- By end of day: both pages render correctly and look reasonably polished
  using ONLY fixture data.

**Day 2**
- Swap fixture data for real data where available: P1's real generated
  rules on Page 1, P2's real normalized output on Page 2 (as it starts
  producing real events).
- Wire the "view raw" button to P3's real `get_raw_event()` function.

**Day 3**
- Polish: make sure the demo narrative screens (from the demo video plan)
  are all present and look clean — this is likely to be the most-shown
  part of your live/recorded demo.
- Support integration testing.

## Definition of done (day 1 checkpoint)

- Running `streamlit run review_ui/app.py` opens a working app with both
  pages.
- Page 1 correctly displays all fields of the sample rule and validation
  result, and the three buttons are present and clickable (don't need
  complex backend logic behind them yet — day 1 goal is the UI existing
  and looking right).
- Page 2 correctly displays the sample normalized event in a table, with
  a working "view raw" expander (can show the raw text as plain string
  for now, real DB lookup comes day 2).

## What NOT to build

- No React/Electron — Streamlit only, for speed.
- No user authentication/login — out of scope for a 3-day prototype.
- No complex state management library — Streamlit's own session_state is
  enough for approve/edit/override flow.

## Instructions for your AI agent

Paste this whole file plus `schemas/schemas.py` as context. Ask it to
build a Streamlit app with the two pages described above, using the
fixture JSON files in `/testdata/fixtures/` as the initial data source.
