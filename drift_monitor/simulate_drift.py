"""
drift_monitor/simulate_drift.py

Day 2: simulated drift generator.

Takes a batch of real, healthy NormalizedEvents and deliberately
corrupts a growing fraction of them across several windows, so we can
demo drift detection without waiting for real vendor drift to happen
naturally.
"""

import copy
import random
from schemas.schemas import NormalizedEvent


def corrupt_field(event, field_path):
    """
    Return a COPY of the event with the given field_path set to None.
    Only handles one level of nesting (e.g. "src_endpoint" or
    "src_endpoint.ip"), which is enough for our schema.
    """
    event_copy = copy.deepcopy(event)
    parts = field_path.split(".")

    if len(parts) == 1:
        setattr(event_copy, parts[0], None)
    else:
        top = getattr(event_copy, parts[0])
        if isinstance(top, dict) and parts[1] in top:
            top[parts[1]] = None

    return event_copy


def simulate_drift_windows(events, field_path, corruption_levels, seed=42):
    """
    Split `events` into len(corruption_levels) windows, and in each
    window, corrupt `field_path` on that window's percentage of events.

    corruption_levels: list of fractions, e.g. [0.0, 0.1, 0.3, 0.6]
        window 0 -> 0% corrupted (healthy baseline)
        window 1 -> 10% corrupted
        window 2 -> 30% corrupted
        window 3 -> 60% corrupted

    Returns a list of windows, where each window is a list of events
    (some real, some corrupted copies).
    """
    random.seed(seed)  # makes the "randomness" repeatable for demos

    num_windows = len(corruption_levels)
    window_size = len(events) // num_windows
    windows = []

    for i, corruption_fraction in enumerate(corruption_levels):
        start = i * window_size
        end = start + window_size if i < num_windows - 1 else len(events)
        window_events = events[start:end]

        num_to_corrupt = int(len(window_events) * corruption_fraction)
        indices_to_corrupt = set(
            random.sample(range(len(window_events)), num_to_corrupt)
        )

        corrupted_window = [
            corrupt_field(event, field_path) if idx in indices_to_corrupt else event
            for idx, event in enumerate(window_events)
        ]

        windows.append(corrupted_window)

    return windows
