import json
from drift_monitor.monitor import classify_severity

sequence = json.load(open("testdata/fixtures/drift_sequence.json"))
for snapshot in sequence:
    predicted = classify_severity(snapshot["null_rate"], snapshot["baseline_null_rate"])
    assert predicted == snapshot["severity"], f"mismatch at {snapshot}"

print("All snapshots matched. Day 1 done.")
