"""
ULPF -- Review-Gate UI + Normalized Event Browser

Run with:

    streamlit run review_ui/app.py

Page 1 (Rule Review) and Page 2 (Normalized Event Browser) live under
pages/ and are picked up automatically by Streamlit's multipage support
(they'll show up in the sidebar).
"""
import streamlit as st

st.set_page_config(page_title="ULPF - Review Gate", page_icon="\U0001F6E1", layout="wide")

st.title("\U0001F6E1 ULPF -- Review Gate")
st.markdown(
    """
This prototype demonstrates the human-in-the-loop review gate for
AI-generated log parsing rules, plus traceability from normalized events
back to the raw logs they came from.

**Use the sidebar to navigate:**

- **Rule Review** -- inspect a candidate rule, its validation results,
  and a before/after example on a real sample line. Approve it as-is,
  edit its field mappings, or override it with a hand-authored rule.
- **Normalized Event Browser** -- see the normalized (OCSF) events
  produced so far, and trace each one back to its original raw log line.

**Status:** both pages are currently wired to fixture data in
`testdata/fixtures/`. Day 2 swaps these for real output from the rule
generator (P1), the normalization pipeline (P2), and the raw event
store (P3) -- see `data_access.py` for the exact functions to replace.
"""
)
