"""
Page 1 -- Rule Review

The single most important screen in the demo: shows a candidate parsing
rule (AI-generated or human-edited) next to its validation results and a
concrete before/after example, and lets a human Approve, Edit, or
Override it before it's trusted on real traffic.
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

from data_access import (
    apply_rule_to_raw_text,
    load_sample_raw_event,
    load_sample_rule,
    load_sample_validation_result,
)
from schemas.schemas import FieldMapping, Rule

st.set_page_config(page_title="Rule Review", layout="wide")
st.title("\U0001F50D Rule Review")
st.caption(
    "Review the candidate parsing rule below before it's trusted on real "
    "traffic. Approve as-is, edit the mappings, or override entirely."
)

# ---------------------------------------------------------------------------
# Load rule + validation result into session_state so edits/decisions
# persist across reruns (Streamlit reruns the whole script on every click).
# ---------------------------------------------------------------------------

if "rule" not in st.session_state:
    st.session_state.rule = load_sample_rule()
if "validation_result" not in st.session_state:
    st.session_state.validation_result = load_sample_validation_result()
if "raw_sample" not in st.session_state:
    st.session_state.raw_sample = load_sample_raw_event()
if "review_status" not in st.session_state:
    st.session_state.review_status = None  # None | "approved" | "overridden"
if "edit_mode" not in st.session_state:
    st.session_state.edit_mode = False
if "override_mode" not in st.session_state:
    st.session_state.override_mode = False

rule: Rule = st.session_state.rule
vr = st.session_state.validation_result
raw_sample = st.session_state.raw_sample

if st.button("\u21BA Reset to fixture / re-review", help="Start this review over from the original candidate rule"):
    for key in ("rule", "validation_result", "raw_sample", "review_status", "edit_mode", "override_mode"):
        st.session_state.pop(key, None)
    st.rerun()

# ---------------------------------------------------------------------------
# Status banner
# ---------------------------------------------------------------------------

if st.session_state.review_status == "approved":
    st.success(f"Rule approved. provenance = `{rule.provenance}`")
elif st.session_state.review_status == "overridden":
    st.info(f"Rule replaced by human override. provenance = `{rule.provenance}`")

st.divider()

# ---------------------------------------------------------------------------
# Rule summary
# ---------------------------------------------------------------------------

col1, col2, col3 = st.columns(3)
col1.metric("Fingerprint ID", rule.fingerprint_id)
col2.metric("Confidence", f"{rule.confidence:.0%}")
col3.metric("Provenance", rule.provenance)

st.subheader("Pattern")
st.code(rule.pattern, language="regex")

st.subheader("Field Mappings")
mapping_df = pd.DataFrame(
    [{"source_field": fm.source_field, "ocsf_path": fm.ocsf_path} for fm in rule.field_mappings]
)
st.dataframe(mapping_df, use_container_width=True, hide_index=True)

st.divider()

# ---------------------------------------------------------------------------
# Validation results
# ---------------------------------------------------------------------------

st.subheader("Validation")
badge = "PASSED" if vr.passed else "FAILED"
st.markdown(f"**Overall: {badge}**")

check_rows = [{"check": k, "result": "pass" if v else "fail"} for k, v in vr.checks.items()]
st.dataframe(pd.DataFrame(check_rows), use_container_width=True, hide_index=True)
st.caption(vr.notes)

st.divider()

# ---------------------------------------------------------------------------
# Before -> after example
# ---------------------------------------------------------------------------

st.subheader("Before \u2192 After")
left, right = st.columns(2)

with left:
    st.markdown("**Raw sample line**")
    st.code(raw_sample.raw_text, language="text")
    st.caption(f"source: {raw_sample.source_id} \u00b7 format guess: {raw_sample.format_guess}")

applied = apply_rule_to_raw_text(rule, raw_sample.raw_text)

with right:
    st.markdown("**Extracted \u2192 mapped output**")
    if not applied["matched"]:
        st.error(applied["error"])
    else:
        st.json(applied["mapped_output"])
        with st.expander("Raw regex captures (pre-mapping)"):
            st.json(applied["captured_groups"])

st.divider()

# ---------------------------------------------------------------------------
# Approve / Edit / Override
# ---------------------------------------------------------------------------

st.subheader("Decision")

btn_col1, btn_col2, btn_col3 = st.columns(3)
approve_clicked = btn_col1.button("Approve", use_container_width=True, type="primary")
edit_clicked = btn_col2.button("Edit", use_container_width=True)
override_clicked = btn_col3.button("Override", use_container_width=True)

if approve_clicked:
    rule.provenance = "slm-generated"
    st.session_state.rule = rule
    st.session_state.review_status = "approved"
    st.session_state.edit_mode = False
    st.session_state.override_mode = False
    print(f"[review_ui] APPROVED rule {rule.fingerprint_id} v{rule.version} as slm-generated")
    st.rerun()

if edit_clicked:
    st.session_state.edit_mode = True
    st.session_state.override_mode = False

if override_clicked:
    st.session_state.override_mode = True
    st.session_state.edit_mode = False

# --- Edit flow: tweak field_mappings, then confirm ---
if st.session_state.edit_mode:
    st.markdown("#### Edit field mappings")
    st.caption("Add, remove, or change rows below, then confirm to approve with your edits.")
    editable_df = pd.DataFrame(
        [{"source_field": fm.source_field, "ocsf_path": fm.ocsf_path} for fm in rule.field_mappings]
    )
    edited_df = st.data_editor(
        editable_df,
        num_rows="dynamic",
        use_container_width=True,
        key="field_mapping_editor",
    )

    if st.button("Confirm edited mappings", type="primary"):
        new_mappings = [
            FieldMapping(source_field=row["source_field"], ocsf_path=row["ocsf_path"])
            for _, row in edited_df.iterrows()
            if row["source_field"] and row["ocsf_path"]
        ]
        rule.field_mappings = new_mappings
        rule.provenance = "slm-generated-edited"
        st.session_state.rule = rule
        st.session_state.review_status = "approved"
        st.session_state.edit_mode = False
        print(f"[review_ui] APPROVED rule {rule.fingerprint_id} v{rule.version} as slm-generated-edited")
        st.rerun()

# --- Override flow: paste a completely different pattern + mappings ---
if st.session_state.override_mode:
    st.markdown("#### Override with a human-authored rule")
    st.caption(
        "Paste a new regex pattern and define field mappings from scratch. "
        "This discards the AI-generated rule entirely."
    )

    new_pattern = st.text_area(
        "New regex pattern",
        value=rule.pattern,
        height=100,
        key="override_pattern",
    )

    st.caption("Field mappings for the override:")
    override_df = st.data_editor(
        pd.DataFrame([{"source_field": "", "ocsf_path": ""}]),
        num_rows="dynamic",
        use_container_width=True,
        key="override_mapping_editor",
    )

    if st.button("Confirm override", type="primary"):
        new_mappings = [
            FieldMapping(source_field=row["source_field"], ocsf_path=row["ocsf_path"])
            for _, row in override_df.iterrows()
            if row["source_field"] and row["ocsf_path"]
        ]
        rule.pattern = new_pattern
        rule.field_mappings = new_mappings
        rule.provenance = "human-authored"
        st.session_state.rule = rule
        st.session_state.review_status = "overridden"
        st.session_state.override_mode = False
        print(f"[review_ui] OVERRIDDEN rule {rule.fingerprint_id} v{rule.version} as human-authored")
        st.rerun()
