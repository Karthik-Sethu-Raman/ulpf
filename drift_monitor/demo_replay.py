import json
from drift_monitor.monitor import classify_severity, response_for_severity

sequence = json.load(open("testdata/fixtures/drift_sequence.json"))

print(f"{'step':<6}{'null_rate':<12}{'baseline':<12}{'severity':<12}{'response'}")
print("-" * 70)

for i, snapshot in enumerate(sequence):
    severity = classify_severity(snapshot["null_rate"], snapshot["baseline_null_rate"])
    response = response_for_severity(severity)
    print(f"{i:<6}{snapshot['null_rate']:<12}{snapshot['baseline_null_rate']:<12}{severity:<12}{response}")
