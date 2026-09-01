# Role P1 — Onboarding Engine (SLM) + Integration Lead

## Project context

We're building a prototype of ULPF — a system that ingests security logs
from perimeter devices (firewalls, IDS, VPNs) in many different vendor
formats (Syslog, CEF, LEEF, JSON, CSV) and normalizes them into a common
schema (OCSF) for SIEM/analytics use. The hard, differentiating part: when
a genuinely new/unrecognized log format shows up, instead of a human
writing a parser by hand, a small local language model (SLM) looks at
sample raw log lines and generates a candidate parsing rule (a regex +
field-mapping table). A human reviews and approves it before it ever runs
on real traffic. After that, parsing is 100% deterministic — the SLM is
never called again for that format unless it breaks later (drift).

Your job is that generation step: **raw sample logs in → candidate `Rule`
out.**

## Your function signature

```python
# onboarding/generate_rule.py
from schemas.schemas import Rule, FieldMapping

def generate_rule(fingerprint_id: str, sample_lines: list[str]) -> Rule:
    """
    Given 5-20 raw sample log lines (all believed to be the same format),
    call a local SLM to infer:
      1. A regex pattern with named capture groups matching the line structure
      2. A mapping from each captured field to an OCSF field path
    Return a Rule with provenance="slm-generated" and a confidence score
    (your own heuristic — e.g. how consistently the pattern matched across
    all sample_lines).
    """
```

## Schema you must produce (from schemas.py — do not redefine)

```python
@dataclass
class Rule:
    fingerprint_id: str
    pattern: str                     # regex with named capture groups
    field_mappings: list[FieldMapping]
    confidence: float                 # 0.0-1.0
    provenance: Literal["slm-generated", "slm-generated-edited", "human-authored"]
    version: int
    created_at: str
```

## Suggested approach

1. **Runtime:** Ollama, running locally. Model: Granite 4.1 (3B) — pull it
   with `ollama pull granite4.1` or similar (check exact tag on
   ollama.com/library). Qwen3.5-4B is an acceptable fallback if Granite
   gives you trouble.
2. **Prompt design (this is the core of your work):** Give the model the
   sample lines plus a short list of relevant OCSF target fields (don't
   dump the whole OCSF spec — pick ~8-10 fields relevant to network
   activity: src ip/port, dst ip/port, timestamp, severity, action,
   signature/message). Ask for a JSON response containing a regex pattern
   with named groups and a field mapping table. Use few-shot: include ONE
   worked example (a different, unrelated format) in the prompt showing
   the exact output shape you want, so the model imitates the format
   reliably.
3. **Confidence scoring (keep this simple):** Run your generated regex
   against all `sample_lines`. Confidence = fraction of lines that
   successfully matched all expected groups. Don't overthink this for 3
   days — a simple match-rate heuristic is enough.
4. **Test data:** Use `/testdata/raw_logs_cef.txt` first (most structured,
   easiest to get working), then syslog, then JSON.

## Day-by-day

**Day 1**
- Get Ollama running locally with your chosen model, confirm you can send
  a prompt and get a response back via the Python client.
- Design and iterate on your prompt using `/testdata/raw_logs_cef.txt`.
- By end of day: `generate_rule()` runs standalone, produces a `Rule`
  object matching the schema, for the CEF sample lines. Doesn't need to be
  perfect yet — needs to run and produce the right shape.

**Day 2**
- Improve prompt reliability — run it multiple times, check consistency.
- Hand your real generated `Rule` (not the fixture) to P2 — this is the
  first real cross-module connection. Confirm P2's parser engine can
  actually apply your rule and get sensible output.
- Start integration lead duties: check in with P3, P4, P5 on their
  progress against fixtures.

**Day 3**
- Extend `generate_rule()` to work on syslog and JSON sample lines too.
- Build `app.py` (with P6) wiring: P3 ingests → your `generate_rule()` on
  unknowns → P4's review UI → P2 applies approved rule → P5 checks drift.
- Test the whole thing end to end, fix integration bugs.

## Definition of done (day 1 checkpoint)

Given `/testdata/raw_logs_cef.txt`, `generate_rule("cef_test", lines)`
must return a `Rule` where:
- `pattern` is a valid regex (compiles without error)
- Applying `pattern` to at least 2 of the 3 sample lines successfully
  extracts `src`, `dst`, `spt`, `dpt`
- `field_mappings` includes at least `src_endpoint.ip` and `dst_endpoint.ip`
- `confidence` is between 0.0 and 1.0

## What NOT to build

- Don't fine-tune anything — this is few-shot prompting only, no time for
  fine-tuning in 3 days.
- Don't try to handle every possible log format — CEF, syslog, JSON is the
  full scope.
- Don't build a queueing/async system around the SLM call — a single
  synchronous function call is fine, this only runs once per new format.

## Instructions for your AI agent

Paste this whole file plus `schemas/schemas.py` as context. Ask it to
implement `onboarding/generate_rule.py` per the function signature above,
using the Ollama Python client. Test against `/testdata/raw_logs_cef.txt`
before moving to the other formats.
