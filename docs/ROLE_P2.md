# Role P2 — Format Fingerprinting + Deterministic Parser Engine

## Project context

We're building a prototype of ULPF — a system that ingests security logs
from perimeter devices (firewalls, IDS, VPNs) in many vendor formats and
normalizes them into a common schema (OCSF). Most log volume flows through
a fast, deterministic path: no AI, just applying a pre-approved parsing
rule. Your job is that deterministic path — the part that runs on every
single event, so it needs to be correct and fast, not clever.

You own two things:
1. **Fingerprinting** — given a raw log line, decide "have we seen this
   structural shape before?" (routing, not full parsing)
2. **Parser engine** — given a raw log line AND a matching `Rule`, apply
   the rule and produce a `NormalizedEvent`

## Your function signatures

```python
# parser_engine/fingerprint.py
def fingerprint(raw_text: str) -> str:
    """
    Return a fingerprint_id string identifying the structural family of
    this log line. Deterministic, cheap, NO model calls.
    Heuristics to use:
      - Starts with "CEF:" -> cef family, extract vendor/product for the id
        e.g. "cef_paloalto"
      - Starts with "LEEF:" -> leef family, similarly
      - Starts with "{" and valid JSON -> "json" (or more specific if you
        want to distinguish by top-level keys present)
      - Matches classic syslog shape (starts with a 3-letter month
        abbreviation) -> "syslog"
      - Otherwise -> "unknown"
    """

# parser_engine/apply_rule.py
from schemas.schemas import Rule, RawEvent, NormalizedEvent

def apply_rule(raw_event: RawEvent, rule: Rule) -> NormalizedEvent:
    """
    Apply rule.pattern (a regex) to raw_event.raw_text. Use rule.field_mappings
    to build the OCSF-shaped output. Any captured field with no OCSF mapping
    goes into unmapped_fields — never drop it.
    Must raise a clear exception (not silently return garbage) if the
    pattern does not match at all.
    """
```

## Schemas you consume/produce (from schemas.py — do not redefine)

```python
@dataclass
class RawEvent:
    raw_id: str
    source_id: str
    timestamp_ingested: str
    format_guess: str
    raw_text: str

@dataclass
class Rule:
    fingerprint_id: str
    pattern: str
    field_mappings: list[FieldMapping]   # source_field -> ocsf_path
    confidence: float
    provenance: str
    version: int
    created_at: str

@dataclass
class NormalizedEvent:
    event_id: str
    raw_id: str            # = raw_event.raw_id — this is the traceability link
    fingerprint_id: str
    rule_version: int
    class_name: str
    time: str
    severity_id: Optional[int] = None
    src_endpoint: Optional[dict] = None
    dst_endpoint: Optional[dict] = None
    action: Optional[str] = None
    unmapped_fields: dict = field(default_factory=dict)
```

## Day-by-day

**Day 1**
- Build `fingerprint()` against all 3 files in `/testdata/` (cef, syslog,
  json) — confirm it correctly buckets each line's family.
- Build `apply_rule()` against `/testdata/fixtures/sample_rule.json` +
  `/testdata/fixtures/sample_raw_event.json`. Confirm your output matches
  `/testdata/fixtures/sample_normalized_event.json` closely (exact field
  values should match, since it's the same input).
- Both functions should work standalone by end of day, no dependency on
  anyone else's code yet.

**Day 2**
- Connect to P1: take their REAL generated `Rule` (not the fixture) for
  CEF logs, run it through your `apply_rule()`. Debug any mismatches
  together — this is where regex/mapping issues surface.
- Add a small rule store — even just a dict in memory or a JSON file
  mapping `fingerprint_id -> Rule`, so `fingerprint()` output can look up
  the right rule automatically.

**Day 3**
- Extend to handle syslog and JSON rules from P1.
- Handle the "unknown fingerprint" case cleanly — if `fingerprint()`
  returns something with no rule in the store, that event should be routed
  toward the onboarding flow (P1), not crash.
- Help P6/P1 with final integration testing.

## Definition of done (day 1 checkpoint)

```python
from testdata.fixtures import load_fixture  # or just json.load directly

raw = load_fixture("sample_raw_event.json")
rule = load_fixture("sample_rule.json")
result = apply_rule(raw, rule)

assert result.src_endpoint["ip"] == "203.0.113.45"
assert result.dst_endpoint["port"] == 443
assert result.raw_id == "raw_00042"
assert result.action == "block"
assert "cat" in result.unmapped_fields   # cat/msg have no OCSF mapping in this rule
```

And:
```python
assert fingerprint(open("testdata/raw_logs_cef.txt").readlines()[0]).startswith("cef")
assert fingerprint(open("testdata/raw_logs_syslog.txt").readlines()[0]) == "syslog"
```

## What NOT to build

- No ML-based clustering for fingerprinting — simple deterministic
  heuristics (string prefix checks, JSON-parse attempt, regex) are correct
  and sufficient.
- No performance/throughput optimization — correctness first, this is a
  prototype, not a load test.
- Don't build the rule store as a real database — a Python dict or a
  single JSON file is fine for 3 days.

## Instructions for your AI agent

Paste this whole file plus `schemas/schemas.py` as context. Ask it to
implement both functions above. Test against the fixtures in
`/testdata/fixtures/` before touching real output from P1.
