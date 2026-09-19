"""
Day 2 test/demo for the simulated drift generator.

Builds a batch of fake but realistic healthy NormalizedEvents, runs them
through simulate_drift_windows(), then checks drift on each window using
check_drift(). You should see severity climb from "none" to "severe" as
the corruption percentage increases per window.
"""

from schemas.schemas import NormalizedEvent
from drift_monitor.simulate_drift import simulate_drift_windows
from drift_monitor.monitor import check_drift


def make_fake_healthy_events(count):
    """Build `count` fake healthy NormalizedEvents for testing."""
    events = []
    for i in range(count):
        events.append(
            NormalizedEvent(
                event_id=f"evt_{i}",
                raw_id=f"raw_{i}",
                fingerprint_id="cef_paloalto_v1",
                rule_version=1,
                class_name="Network Activity",
                time=f"t{i}",
                severity_id=2,
                src_endpoint={"ip": f"10.1.1.{i % 255}"},
                dst_endpoint={"ip": "8.8.8.8"},
                action="allow",
                unmapped_fields={},
            )
        )
    return events


def run():
    healthy_events = make_fake_healthy_events(100)

    corruption_levels = [0.0, 0.1, 0.3, 0.6]
    windows = simulate_drift_windows(healthy_events, "src_endpoint.ip", corruption_levels)

    baseline_null_rate = 0.01

    print(f"{'window':<8}{'null_rate':<12}{'severity'}")
    print("-" * 40)

    for i, window in enumerate(windows):
        metric = check_drift(
            fingerprint_id="cef_paloalto_v1",
            field_path="src_endpoint.ip",
            events=window,
            baseline_null_rate=baseline_null_rate,
        )
        print(f"{i:<8}{metric.null_rate:<12.2f}{metric.severity}")


if __name__ == "__main__":
    run()