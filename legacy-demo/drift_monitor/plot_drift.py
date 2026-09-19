"""
drift_monitor/plot_drift.py

Day 3: plots null_rate over time/windows as a line chart, using either
the fixture sequence or the simulated drift windows. This is the visual
demo asset.
"""

import json
import matplotlib.pyplot as plt


def plot_from_fixture():
    """Plot null_rate over time using the Day 1 fixture file."""
    with open("testdata/fixtures/drift_sequence.json") as f:
        sequence = json.load(f)

    steps = list(range(len(sequence)))
    null_rates = [s["null_rate"] for s in sequence]
    severities = [s["severity"] for s in sequence]

    color_map = {
        "none": "green",
        "minor": "gold",
        "moderate": "orange",
        "severe": "red",
    }
    colors = [color_map[sev] for sev in severities]

    plt.figure(figsize=(8, 5))
    plt.plot(steps, null_rates, color="gray", linestyle="--", zorder=1)
    plt.scatter(steps, null_rates, c=colors, s=100, zorder=2)

    for i, sev in enumerate(severities):
        plt.annotate(sev, (steps[i], null_rates[i]), textcoords="offset points", xytext=(0, 10))

    plt.xlabel("Time step")
    plt.ylabel("Null rate")
    plt.title("Drift detection: field null rate over time")
    plt.ylim(0, 1)
    plt.tight_layout()
    plt.savefig("drift_monitor/drift_chart.png")
    plt.show()


if __name__ == "__main__":
    plot_from_fixture()
