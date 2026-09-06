# Parser Engine (`parser_engine/`)

The deterministic hot path — no AI, no model calls. Runs on every
ingested event; needs to be correct and fast.

## Core functions

```python
# parser_engine/fingerprint.py
def fingerprint(raw_text: str) -> str:
```
Deterministic structural classification of a raw log line — delimiter
patterns, JSON-shape detection, CEF/LEEF header presence. Disambiguates
by vendor where relevant (e.g. `cef_paloalto` vs `cef_ciscoasa`, not one
generic `cef` bucket), since different vendors under the same wire
format can have materially different field sets.

```python
# parser_engine/apply_rule.py
def apply_rule(raw_event: RawEvent, rule: Rule) -> NormalizedEvent:
```
Applies a rule's pattern to a raw event and produces a normalized OCSF
event. Handles two rule types:
- **Regex rules** — the common case, including CEF/LEEF's two-part
  header + key=value extension shape.
- **JSON rules** (`rule.pattern == "__JSON__"`) — parses the raw text as
  JSON and walks dotted-path field mappings instead of using regex.

Any captured field with no OCSF mapping goes into `unmapped_fields` —
never silently dropped.

```python
# parser_engine/rule_store.py
def register_rule(rule: Rule) -> None
def get_rule(fingerprint_id: str) -> Rule | None
def list_rules() -> list[Rule]
```
In-memory rule store with disk persistence (`testdata/registered_rules.json`),
so rules registered by one process (e.g. the integration runner) are
visible to another (e.g. the Streamlit review UI) without needing a real
database for this stage.

## What this deliberately does not do

- No ML-based format clustering — fingerprinting is cheap, deterministic
  heuristics only.
- No throughput/performance optimization — correctness first; this is a
  prototype, not a load test.
- No real database — the rule store is a JSON file, sufficient for
  demonstrating the design without the setup overhead of Postgres.