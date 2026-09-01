# Role P3 — Ingestion + Raw Storage + Traceability + Rule Validation

## Project context

We're building a prototype of ULPF — a system that ingests security logs
from perimeter devices in many vendor formats and normalizes them into a
common schema (OCSF). One of the system's core requirements (straight from
the problem statement) is that raw logs are NEVER lost — every event is
stored verbatim before any processing happens, and every normalized event
must be traceable back to its exact raw source. You own that foundation,
plus a second, unrelated piece: sanity-checking a candidate parser rule
before it's allowed to go live.

You have no dependency on anyone else's code — you can build and test your
whole module in complete isolation using the mock log files already in the
repo.

## Your function signatures

```python
# ingestion/ingest.py
from schemas.schemas import RawEvent

def ingest_line(raw_text: str, source_id: str, format_guess: str = "unknown") -> RawEvent:
    """
    Assign a unique raw_id, stamp timestamp_ingested (now, ISO8601),
    store raw_text verbatim to disk (see storage below), and return the
    RawEvent object. This must be called for every incoming line, no
    exceptions — even if downstream parsing later fails.
    """

def get_raw_event(raw_id: str) -> RawEvent:
    """
    Look up and return a previously ingested RawEvent by its raw_id.
    This is what powers the "view raw" traceability feature in P4's UI.
    """

# ingestion/validate_rule.py
from schemas.schemas import Rule, ValidationResult

def validate_rule(rule: Rule, held_out_lines: list[str]) -> ValidationResult:
    """
    Run rule.pattern against held_out_lines (raw log lines NOT used to
    generate the rule). Checks to run:
      - Does the pattern match at all on each line?
      - For any mapped field whose ocsf_path contains "ip", does the
        captured value look like an IP (basic regex, doesn't need to be
        perfect)?
      - For any mapped field whose ocsf_path contains "port", is the
        captured value a number between 0 and 65535?
      - Are all field_mappings actually present as named groups in the
        pattern (no orphan mappings)?
    Return a ValidationResult with checks as a dict and passed = True only
    if ALL checks pass on ALL held_out_lines.
    """
```

## Storage — keep this simple

Use **SQLite** (Python's built-in `sqlite3`, no server setup needed) for a
table of `RawEvent` records, and write the raw text to a local file too if
you want (SQLite column is fine on its own for 3 days — don't
over-engineer this into separate blob storage).

```sql
CREATE TABLE raw_events (
    raw_id TEXT PRIMARY KEY,
    source_id TEXT,
    timestamp_ingested TEXT,
    format_guess TEXT,
    raw_text TEXT
);
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
    field_mappings: list[FieldMapping]
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
```

## Day-by-day

**Day 1**
- Build `ingest_line()` + `get_raw_event()` backed by SQLite. Test against
  all 3 mock log files in `/testdata/` — every line should be ingested and
  retrievable.
- Build `validate_rule()` against
  `/testdata/fixtures/sample_rule.json` and a couple of held-out CEF
  lines from `/testdata/raw_logs_cef.txt` (use lines NOT already inside
  the fixture). Confirm it correctly returns `passed=True` for a good
  rule.
- Bonus if time allows: hand-write a deliberately bad rule (wrong regex,
  or a mapping to a nonexistent field) and confirm `validate_rule()`
  correctly returns `passed=False`.

**Day 2**
- Connect: feed P1's real generated rules (once available) through your
  `validate_rule()` instead of the fixture. Report back to P1 if
  validation is failing and why — your `notes` field should be specific
  enough for them to debug.
- Make sure `ingest_line()` is being called by whatever ingestion driver
  P6/P1 build for the demo (reading from the mock log files line by line).

**Day 3**
- Support P4: they'll need `get_raw_event()` for the "view raw" button.
- Support integration testing with P6.

## Definition of done (day 1 checkpoint)

```python
event = ingest_line(
    "CEF:0|PaloAlto|PAN-OS|10.1|THREAT|spyware|5|src=203.0.113.45 dst=192.168.1.10",
    source_id="fw01",
    format_guess="cef",
)
assert event.raw_id  # non-empty, unique
fetched = get_raw_event(event.raw_id)
assert fetched.raw_text == event.raw_text

rule = load_fixture("sample_rule.json")
result = validate_rule(rule, ["CEF:0|PaloAlto|PAN-OS|10.1|THREAT|spyware|5|src=198.51.100.22 dst=192.168.1.14 spt=1234 dpt=80 act=alert"])
assert result.passed == True
```

## What NOT to build

- No Postgres, no Kafka — SQLite and plain function calls are enough.
- No file-tailing or live network listeners — you're reading from static
  mock log files for this prototype.
- Don't try to make validation statistically rigorous — simple, explicit
  rule-based checks (as listed above) are the correct scope for 3 days.

## Instructions for your AI agent

Paste this whole file plus `schemas/schemas.py` as context. Ask it to
implement both modules above using `sqlite3` from the Python standard
library. Test against the mock log files in `/testdata/` before anyone
else's real data is available.
