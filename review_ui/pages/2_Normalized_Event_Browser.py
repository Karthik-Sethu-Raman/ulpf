"""
Page 2 -- Normalized Event Browser

Shows normalized (OCSF-shaped) events produced by the pipeline, with an
explicit, un-buried link back to the original raw log for every event --
this is the traceability requirement, made visible.
"""
import sys
from pathlib import Path

REVIEW_UI_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = REVIEW_UI_DIR.parent
for _p in (PROJECT_ROOT, REVIEW_UI_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import pandas as pd
import streamlit as st

from data_access import get_raw_event, load_normalized_events

st.set_page_config(page_title="Normalized Events", layout="wide")
st.title("\U0001F4C1 Normalized Event Browser")
st.caption(
    "Every normalized event here traces back to exactly one raw log line. "
    "Expand a row below to see it."
)

events = load_normalized_events()

if not events:
    st.info("No normalized events yet.")
    st.stop()

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

summary_rows = []
for e in events:
    src = e.src_endpoint or {}
    dst = e.dst_endpoint or {}
    summary_rows.append(
        {
            "event_id": e.event_id,
            "class_name": e.class_name,
            "time": e.time,
            "src": f"{src.get('ip', '\u2014')}:{src.get('port', '\u2014')}" if src else "\u2014",
            "dst": f"{dst.get('ip', '\u2014')}:{dst.get('port', '\u2014')}" if dst else "\u2014",
            "severity_id": e.severity_id if e.severity_id is not None else "\u2014",
            "action": e.action or "\u2014",
            "raw_id": e.raw_id,
        }
    )

st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)

st.divider()
st.subheader("Event detail + raw log trace")

for e in events:
    with st.container(border=True):
        header_col, trace_col = st.columns([3, 1])
        with header_col:
            st.markdown(f"**{e.event_id}** \u00b7 {e.class_name} \u00b7 {e.time}")
            st.caption(
                f"rule `{e.fingerprint_id}` v{e.rule_version}  \u00b7  "
                f"severity `{e.severity_id}`  \u00b7  action `{e.action}`"
            )
        with trace_col:
            st.markdown(f"\U0001F517 raw_id: `{e.raw_id}`")

        detail_cols = st.columns(2)
        with detail_cols[0]:
            st.markdown("**src_endpoint**")
            st.json(e.src_endpoint or {})
        with detail_cols[1]:
            st.markdown("**dst_endpoint**")
            st.json(e.dst_endpoint or {})

        if e.unmapped_fields:
            with st.expander("Unmapped fields (never silently dropped)"):
                st.json(e.unmapped_fields)

        with st.expander(f"View raw log for {e.raw_id}"):
            raw = get_raw_event(e.raw_id)
            if raw is None:
                st.warning(f"No raw event found for raw_id={e.raw_id}")
            else:
                st.code(raw.raw_text, language="text")
                st.caption(
                    f"source: {raw.source_id} \u00b7 format guess: {raw.format_guess} \u00b7 "
                    f"ingested: {raw.timestamp_ingested}"
                )
