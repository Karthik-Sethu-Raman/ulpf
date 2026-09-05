"""
testdata/integration_runner.py

End-to-end test of the real pipeline (no fixtures, no mocks) across all
three formats: CEF, syslog, JSON. Reports PASS/FAIL per stage so a
failure is immediately traceable to the module that caused it.

Run from repo root: python testdata/integration_runner.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import process_raw_line, onboard_new_format, UnknownFormatError
from parser_engine.rule_store import clear_rules, list_rules
from drift_monitor.monitor import compute_null_rate, classify_severity, response_for_severity


def load_lines(filename):
    path = os.path.join(os.path.dirname(__file__), filename)
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def run_format(label: str, filename: str, source_id: str):
    print(f"\n{'=' * 60}\n{label}\n{'=' * 60}")
    lines = load_lines(filename)

    # --- Pass 1: fingerprint every line FIRST, group by fingerprint_id.
    # This is critical — generate_rule() must only ever see samples from
    # ONE true structural family at a time. Feeding it a mixed batch
    # (e.g. PaloAlto + Cisco ASA + Fortigate lines together, all under a
    # shared "cef" prefix) is exactly the day-1 mixed-vendor bug, and
    # produces compromised, low-confidence rules for all of them.
    from parser_engine.fingerprint import fingerprint as fp_func

    lines_by_fingerprint: dict[str, list[str]] = {}
    for line in lines:
        fp_id = fp_func(line)
        lines_by_fingerprint.setdefault(fp_id, []).append(line)

    print(f"  Detected {len(lines_by_fingerprint)} distinct fingerprint(s): "
          f"{list(lines_by_fingerprint.keys())}")

    # --- Pass 2: onboard each unique fingerprint EXACTLY ONCE, using only
    # that fingerprint's own lines as both sample and held-out set.
    from parser_engine.rule_store import get_rule

    for fp_id, fp_lines in lines_by_fingerprint.items():
        if get_rule(fp_id) is not None:
            continue  # already registered from an earlier format/run

        print(f"  [INFO] Onboarding '{fp_id}' using its own {len(fp_lines)} sample line(s)")
        candidate, valid = onboard_new_format(
            fp_id, sample_lines=fp_lines, held_out_lines=fp_lines, auto_approve_if_valid=True
        )
        if valid:
            print(f"  [PASS] '{fp_id}' onboarded — confidence={candidate.confidence}")
        else:
            print(f"  [FAIL] '{fp_id}' failed validation (confidence={candidate.confidence}) "
                  f"— would go to human review, not auto-applied. Lines with this "
                  f"fingerprint will be skipped this run.")

    # --- Pass 3: process every line for real, now that every fingerprint
    # either has a registered rule or is a known failure.
    normalized_events = []
    for i, line in enumerate(lines):
        try:
            event = process_raw_line(line, source_id=source_id, format_guess=label.lower())
            print(f"  [PASS] Line {i}: {event.src_endpoint} -> {event.dst_endpoint} (raw_id={event.raw_id})")
            normalized_events.append(event)
        except UnknownFormatError as e:
            print(f"  [SKIP] Line {i}: fingerprint '{e.fingerprint_id}' never got a valid rule this run")
        except Exception as e:
            print(f"  [FAIL] Line {i}: unexpected error — {e}")

    return normalized_events


def run_drift_check(events):
    print(f"\n{'=' * 60}\nDrift check (real events, simulated baseline)\n{'=' * 60}")
    if not events:
        print("  [SKIP] No normalized events to check.")
        return

    by_fingerprint = {}
    for e in events:
        by_fingerprint.setdefault(e.fingerprint_id, []).append(e)

    for fp_id, evts in by_fingerprint.items():
        null_rate = compute_null_rate(evts, "src_endpoint.ip")
        # baseline assumed near-zero for a healthy field on real data
        severity = classify_severity(null_rate, baseline_null_rate=0.01)
        response = response_for_severity(severity)
        print(f"  {fp_id}: null_rate={null_rate}, severity={severity}, response='{response}'")


if __name__ == "__main__":
    clear_rules()  # start clean each run

    all_events = []
    all_events += run_format("CEF", "raw_logs_cef.txt", source_id="fw01")
    all_events += run_format("Syslog", "raw_logs_syslog.txt", source_id="fw02")
    all_events += run_format("JSON", "raw_logs_json.txt", source_id="ids01")
    all_events += run_format("AcmeGW (unrecognized vendor)", "raw_logs_acmegw.txt", source_id="acme01")

    run_drift_check(all_events)

    print(f"\n{'=' * 60}")
    print(f"TOTAL: {len(all_events)} events normalized across {len(list_rules())} registered rule(s)")
    print(f"{'=' * 60}")