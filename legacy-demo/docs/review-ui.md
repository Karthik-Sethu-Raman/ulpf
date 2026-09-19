# Review UI (`review_ui/`)

A Streamlit app with two pages: the human review gate for AI-generated
rules, and a browser for normalized events with full raw-log
traceability.

## Rule Review page

Shows a candidate rule's fingerprint, pattern, field mappings,
confidence, and validation results, plus a live before → after example
on a real sample line. Three decisions:
- **Approve** — deploy the rule as generated
- **Edit** — adjust field mappings before approving
- **Override** — discard the candidate and hand-author a rule instead

Whichever path is taken, the resulting rule is tagged with the correct
provenance (`slm-generated`, `slm-generated-edited`, or
`human-authored`), giving a clear audit trail of how each rule came to
exist.

## Normalized Event Browser page

A table of normalized OCSF events, each with a "view raw log" link that
retrieves and displays the exact original log line an event was derived
from — and a separate view for `unmapped_fields`, made explicit rather
than buried, since those are fields the system chose not to drop.

## Data access design

`data_access.py` is written to prefer real module output over fixture
data, with a fallback: it tries importing the real rule store, parser
engine, and ingestion modules, and only falls back to
`testdata/fixtures/*.json` if a real module isn't available or errors.
This means the UI code never has to change based on which modules are
wired up — pages read the same schema types either way, and the app
can't crash mid-demo even if one upstream module has an issue.

## Running it

```
streamlit run review_ui/app.py
```

Run `testdata/integration_runner.py` first if you want the pages to show
real onboarded rules and events rather than fixture data.