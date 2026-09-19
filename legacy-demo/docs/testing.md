# Test Data & Integration Testing (`testdata/`)

## Sample logs

Four formats, of increasing difficulty:
- `raw_logs_cef.txt` — CEF, multiple vendors (PaloAlto, Cisco ASA,
  FortiGate) under the same wire format but different field sets
- `raw_logs_syslog.txt` — raw Syslog, no delimiters, positional fields
- `raw_logs_json.txt` — Suricata-style JSON, already structured
- `raw_logs_acmegw.txt` — a deliberately invented, harder format with
  combined IP:port fields and text-based severity, used to demonstrate
  the manual-override path when the model can't fully resolve a format

## Fixtures (`testdata/fixtures/`)

Hand-authored example instances of every schema type
(`RawEvent`, `Rule`, `ValidationResult`, `NormalizedEvent`,
`DriftMetric`), plus deliberately broken examples (a rule with an
orphan field mapping, a rule that reverts to hardcoding instead of
generalizing) used to confirm validation correctly rejects bad rules
rather than silently accepting them. `fixtures.py` provides shared
dict-to-dataclass loaders used across modules.

## `check_fixtures.py`

A regression/sanity checker that runs every fixture (good and
deliberately bad) against the real modules and reports pass/fail per
check — confirms, for example, that a known-bad rule is actually
rejected by validation rather than silently accepted.

## `integration_runner.py`

The full end-to-end pipeline test — no fixtures, no mocks. For each
format: fingerprints every line, onboards each distinct fingerprint
exactly once (critical: samples are grouped by fingerprint before
onboarding, since mixing multiple vendors' lines into one onboarding
batch reliably confuses rule generation), then processes every line for
real through ingestion → parsing → normalization, and finishes with a
real drift check against the produced events.

Run it before launching the review UI, since it's what populates the
persisted rule store with real, working rules.