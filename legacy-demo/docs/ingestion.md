# Ingestion (`ingestion/`)

Raw log storage, traceability, and rule validation — the foundation
everything else builds on.

## Core functions

```python
# ingestion/ingest.py
def ingest_line(raw_text: str, source_id: str, format_guess: str = "unknown") -> RawEvent
def get_raw_event(raw_id: str) -> RawEvent
```
Every incoming line is stored verbatim (SQLite) before any processing —
this is unconditional, matching the "preserve complete raw event data
without information loss" requirement directly. `get_raw_event` powers
the "view raw log" traceability feature in the review UI.

```python
# ingestion/validate_rule.py
def validate_rule(rule: Rule, held_out_lines: list[str]) -> ValidationResult
```
Sanity-checks a candidate rule against held-out lines before it's
allowed to reach human review or go live:
- IP-shaped fields actually look like IPs
- Port-shaped fields are numeric and in range
- No orphan field mappings (a mapping referencing a field the pattern
  never actually captures)
- For JSON rules, every mapped dotted path resolves to a real value

A rule that fails validation never reaches deployment — this is what
stops a bad or hallucinated AI-generated mapping from silently
corrupting data. Demonstrated concretely: a deliberately mismapped test
rule produces garbage output if run without this gate (a string where a
port number should be), confirming this check is load-bearing, not
decorative.

## What this deliberately does not do

- No Postgres, no Kafka — SQLite and plain function calls are enough to
  demonstrate the design.
- No live network listeners — reads from static log files/lines for
  this stage, not a real Syslog UDP/TCP receiver.
- No statistically rigorous validation — explicit, rule-based checks
  only, which is honest and sufficient at this scope.