# services/drift/tests/test_windows.py — pure window math + tier-1 semantics
# (plan Task 4 Steps 1/2), all with concrete rows/docs; NEVER a live DB.
from datetime import UTC, datetime, timedelta

from drift.windows import FieldStats, Window, compute_windows, tier1_violation


def _ts(seconds: float) -> datetime:
    """Aware UTC timestamp (the shape psycopg returns for TIMESTAMPTZ)."""
    return datetime(2026, 9, 21, 10, 0, 0, tzinfo=UTC) + timedelta(seconds=seconds)


def _row(seconds: float, status: str = "parsed", ocsf: dict | None = None):
    """One current-view row: (parsed_at, status, ocsf|None)."""
    return (_ts(seconds), status, ocsf)


def _doc(ip="198.51.100.4", port=443, sev=3, time="2026-09-19T10:00:03Z",
         unmapped: dict | None = None):
    return {
        "src_endpoint": {"ip": ip, "port": port},
        "severity_id": sev,
        "time": time,
        "unmapped": unmapped if unmapped is not None else {},
    }


# --- compute_windows: count-close / time-close / trailing held back ------------


def _fast_row(millis: int, status: str = "parsed", ocsf: dict | None = None):
    """Row packed milliseconds apart — 1000 rows stay well inside window_time_s,
    so only the COUNT boundary can close these windows."""
    return (_ts(0) + timedelta(milliseconds=millis), status, ocsf)


def test_count_close_exactly_at_boundary():
    # The 1000th row CLOSES the window; the 1001st STARTS a new one — which is
    # a trailing partial and therefore held back (never emitted).
    rows = [_fast_row(i) for i in range(1001)]
    windows = compute_windows(rows, count_window=1000, time_window_s=600)
    assert len(windows) == 1
    assert windows[0].count == 1000
    assert windows[0].start == rows[0][0] and windows[0].end == rows[999][0]


def test_two_full_windows_close_cleanly():
    rows = [_fast_row(i) for i in range(2000)]
    windows = compute_windows(rows, count_window=1000, time_window_s=600)
    assert [w.count for w in windows] == [1000, 1000]
    assert windows[1].start == rows[1000][0] and windows[1].end == rows[1999][0]


def test_time_close_low_volume_without_reaching_count():
    # 3 rows spread beyond window_time_s: the first row is older than the
    # horizon of the newest row, so its window closes on TIME at count 1; the
    # fresh tail [700, 800] is the trailing partial and is held back.
    rows = [_row(0), _row(700), _row(800)]
    windows = compute_windows(rows, count_window=1000, time_window_s=600)
    assert len(windows) == 1
    assert windows[0].count == 1
    assert windows[0].start == _ts(0) and windows[0].end == _ts(0)


def test_trailing_partial_window_is_never_emitted():
    rows = [_row(i) for i in range(5)]
    assert compute_windows(rows, count_window=10, time_window_s=600) == []


def test_window_start_and_end_are_first_and_last_parsed_at():
    rows = [_row(i) for i in range(7)]
    windows = compute_windows(rows, count_window=3, time_window_s=600)
    # [0,1,2] and [3,4,5] close on count; [6] is trailing and held back.
    assert len(windows) == 2
    assert windows[0].start == _ts(0) and windows[0].end == _ts(2)
    assert windows[1].start == _ts(3) and windows[1].end == _ts(5)


def test_same_rows_twice_produce_identical_windows():
    rows = [_row(i, "parsed" if i % 3 else "parse_error",
                 _doc() if i % 3 else None) for i in range(50)]
    first = compute_windows(rows, count_window=7, time_window_s=600,
                            mapped_paths=("src_endpoint.ip",))
    second = compute_windows(rows, count_window=7, time_window_s=600,
                             mapped_paths=("src_endpoint.ip",))
    assert first == second  # determinism: data only, never wall-clock


def test_parsed_and_parse_errors_partition_the_window():
    rows = [_row(0, "parsed", _doc()), _row(1, "parsed", _doc()),
            _row(2, "parse_error", None)]
    windows = compute_windows(rows, count_window=3, time_window_s=600)
    assert windows[0].count == 3
    assert windows[0].parsed == 2 and windows[0].parse_errors == 1


def test_empty_rows_return_no_windows():
    assert compute_windows([], count_window=1000, time_window_s=600) == []


# --- field stats: nulls / violations / values ----------------------------------


def test_nulls_counted_not_tier1_violations():
    doc = _doc(ip=None)  # mapped field present but None: a null, never a violation
    windows = compute_windows([_row(0, "parsed", doc)],
                              count_window=1, time_window_s=600,
                              mapped_paths=("src_endpoint.ip",))
    assert windows[0].field_stats["src_endpoint.ip"] == FieldStats(
        nulls=1, violations=0, values=[])


def test_field_stats_values_collected_for_the_histogram():
    docs = [_row(0, "parsed", _doc(ip="198.51.100.4")),
            _row(1, "parsed", _doc(ip="198.51.100.5"))]
    windows = compute_windows(docs, count_window=2, time_window_s=600,
                              mapped_paths=("src_endpoint.ip",))
    assert windows[0].field_stats["src_endpoint.ip"].values == [
        "198.51.100.4", "198.51.100.5"]


def test_field_stats_covers_mapped_paths_that_never_fire():
    # A mapping whose group never matches: every parsed doc counts a null.
    docs = [_row(0, "parsed", _doc()), _row(1, "parsed", _doc())]
    windows = compute_windows(docs, count_window=2, time_window_s=600,
                              mapped_paths=("dst_endpoint.ip", "src_endpoint.ip"))
    assert windows[0].field_stats["dst_endpoint.ip"].nulls == 2
    assert "dst_endpoint.ip" in windows[0].field_stats  # present even at zero


def test_tier1_violations_counted_per_field_in_window():
    docs = [_row(0, "parsed", _doc(ip="SRC=198.51.100.4")),  # firmware-drift garbage
            _row(1, "parsed", _doc(ip="198.51.100.5")),
            _row(2, "parsed", _doc(ip="DST=203.0.113.9")),
            _row(3, "parsed", _doc(ip="198.51.100.6"))]
    windows = compute_windows(docs, count_window=4, time_window_s=600,
                              mapped_paths=("src_endpoint.ip",))
    assert windows[0].field_stats["src_endpoint.ip"].violations == 2


# --- unmapped keys: recorded always, "new" only against a baseline -------------


def test_unmapped_keys_recorded_as_field_stats():
    docs = [_row(0, "parsed", _doc(unmapped={"IN": "eth0", "OUT": None})),
            _row(1, "parsed", _doc(unmapped={"IN": "eth1"}))]
    windows = compute_windows(docs, count_window=2, time_window_s=600)
    stats = windows[0].field_stats
    assert stats["unmapped.IN"].values == ["eth0", "eth1"]
    assert stats["unmapped.IN"].nulls == 0
    assert stats["unmapped.OUT"].nulls == 1 and stats["unmapped.OUT"].values == []


def test_new_unmapped_empty_without_baseline():
    # Before a baseline exists, keys are just RECORDED — none are "new".
    rows = [_row(0, "parsed", _doc(unmapped={"IN": "eth0"}))]
    windows = compute_windows(rows, count_window=1, time_window_s=600)
    assert windows[0].new_unmapped == set()


def test_new_unmapped_flagged_against_known_set():
    rows = [_row(0, "parsed", _doc(unmapped={"IN": "eth0", "OUT": "wan"}))]
    windows = compute_windows(rows, count_window=1, time_window_s=600,
                              known_unmapped=frozenset({"IN"}))
    assert windows[0].new_unmapped == {"OUT"}


def test_unmapped_key_equal_to_a_mapped_target_never_new():
    # A quarantined mapping relocates its value into `unmapped` under the
    # SOURCE key (Task 6); a key equal to a mapped OCSF target is never "new".
    rows = [_row(0, "parsed", _doc(unmapped={"src_endpoint.ip": "1.2.3.4"}))]
    windows = compute_windows(rows, count_window=1, time_window_s=600,
                              mapped_paths=("src_endpoint.ip",),
                              known_unmapped=frozenset())
    assert windows[0].new_unmapped == set()


# --- tier1_violation: mirrors validation._value_sanity, window-aggregated -------


def test_ip_fields_require_dotted_quad_string():
    assert tier1_violation("src_endpoint.ip", "SRC=198.51.100.4") is True
    assert tier1_violation("dst_endpoint.ip", "198.51.100.4") is False
    assert tier1_violation("src_endpoint.ip", "999.999.999.999") is False  # shape-level
    assert tier1_violation("src_endpoint.ip", 123) is True  # must be a str
    assert tier1_violation("dst_endpoint.ip", "1.2.3.4.5") is True


def test_ports_must_be_int_in_0_65535():
    assert tier1_violation("src_endpoint.port", 70000) is True
    assert tier1_violation("dst_endpoint.port", "443") is True  # a str port is a failure
    assert tier1_violation("src_endpoint.port", True) is True   # bool is not an int
    assert tier1_violation("src_endpoint.port", 0) is False
    assert tier1_violation("dst_endpoint.port", 65535) is False
    assert tier1_violation("src_endpoint.port", 65536) is True
    assert tier1_violation("dst_endpoint.port", -1) is True


def test_severity_id_must_be_int_0_to_6():
    assert tier1_violation("severity_id", 9) is True
    assert tier1_violation("severity_id", 3) is False
    assert tier1_violation("severity_id", 0) is False
    assert tier1_violation("severity_id", False) is True   # bool is not an int
    assert tier1_violation("severity_id", "5") is True     # a str severity fails


def test_time_must_be_iso_parsable_string():
    assert tier1_violation("time", "not-a-ts") is True
    assert tier1_violation("time", "2026-09-19T10:00:03Z") is False
    assert tier1_violation("time", "2026-09-19") is False
    assert tier1_violation("time", 12345) is True  # must be a str


def test_none_is_a_null_not_a_violation():
    for path in ("src_endpoint.ip", "dst_endpoint.ip", "src_endpoint.port",
                 "dst_endpoint.port", "severity_id", "time"):
        assert tier1_violation(path, None) is False


def test_unregulated_fields_never_violate():
    assert tier1_violation("message", "anything") is False
    assert tier1_violation("action", 12345) is False
    assert tier1_violation("unmapped.IN", "DROP") is False


def test_window_dataclass_is_frozen_shape():
    win = Window(start=_ts(0), end=_ts(1), count=1, parsed=1, parse_errors=0,
                 field_stats={}, new_unmapped=set())
    assert win.count == 1
    import dataclasses

    import pytest
    with pytest.raises(dataclasses.FrozenInstanceError):
        win.count = 2
