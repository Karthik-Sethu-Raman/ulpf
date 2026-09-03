from schemas.schemas import NormalizedEvent, DriftMetric


def compute_null_rate(events, field_path):
    parts = field_path.split(".")
    null_count = 0

    for event in events:
        value = getattr(event, parts[0], None)
        for part in parts[1:]:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                value = None
        if value is None:
            null_count += 1

    return null_count / len(events)


def classify_severity(current_null_rate, baseline_null_rate):
    ratio = current_null_rate / baseline_null_rate if baseline_null_rate > 0 else float("inf")
    difference = current_null_rate - baseline_null_rate

    if ratio < 3 or difference < 0.05:
        return "none"
    elif ratio < 6:
        return "minor"
    elif ratio < 15:
        return "moderate"
    else:
        return "severe"


def check_drift(fingerprint_id, field_path, events, baseline_null_rate):
    null_rate = compute_null_rate(events, field_path)
    severity = classify_severity(null_rate, baseline_null_rate)

    times = sorted(e.time for e in events)
    window_start = times[0]
    window_end = times[-1]

    return DriftMetric(
        fingerprint_id=fingerprint_id,
        field_name=field_path,
        window_start=window_start,
        window_end=window_end,
        null_rate=null_rate,
        baseline_null_rate=baseline_null_rate,
        severity=severity,
    )


def response_for_severity(severity):
    responses = {
        "none": "no action",
        "minor": "logged for review",
        "moderate": "field quarantined, rule stays live",
        "severe": "reverted to raw-only forwarding",
    }
    return responses[severity]
