# services/drift/tests/test_app.py — loop wiring tests (onboarding-loop shape):
# fail-closed scan retries, the loop never raises out, scan_rule threading
# (baseline -> known_unmapped), and the single-loop main(). Monkeypatch style:
# app.py imports its store collaborators by name, so patching the app module's
# globals observes the wiring; NEVER a live DB.
import threading
from datetime import UTC, datetime, timedelta

from ulpf_core.models import Mapping

from drift import app
from drift.config import Config
from drift.store import ActiveDriftRule


def _ts(seconds: float) -> datetime:
    return datetime(2026, 9, 21, 10, 0, 0, tzinfo=UTC) + timedelta(seconds=seconds)


def _rule(fp="fp_a", rule_id=7, version=2):
    return ActiveDriftRule(
        id=rule_id, fingerprint_id=fp, version=version, pattern=r"x",
        mappings=[Mapping(source_field="SRC", ocsf_path="src_endpoint.ip")],
        provenance="human", quarantined_fields=[])


def _doc(ip="198.51.100.4"):
    return {"src_endpoint": {"ip": ip, "port": 443}, "severity_id": 3,
            "time": "2026-09-19T10:00:03Z", "unmapped": {}}


class FakeStoreConn:
    """Just the context-manager role of a psycopg connection."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fast_cfg(**kw):
    kw.setdefault("poll_s", 0.0)  # stop.wait(0): the loop test never sleeps
    return Config(**kw)


# --- the loop: fail-closed, never raises out ------------------------------------


def test_loop_continues_after_a_failed_iteration(monkeypatch):
    stop = threading.Event()
    loads = {"n": 0}
    scanned = []

    def fake_load(conn):
        loads["n"] += 1
        if loads["n"] == 1:
            raise RuntimeError("db down")  # first poll fails...
        return [_rule()]                   # ...the next one scans

    def fake_scan(cfg, rule):
        scanned.append(rule.fingerprint_id)
        stop.set()  # done: end the loop from inside the scan

    monkeypatch.setattr(app, "connect_db", lambda url: FakeStoreConn())
    monkeypatch.setattr(app, "load_active_rules", fake_load)
    monkeypatch.setattr(app, "scan_rule", fake_scan)

    app.run_drift_loop(_fast_cfg(), stop)
    assert loads["n"] == 2 and scanned == ["fp_a"]


def test_loop_never_raises_out_when_everything_fails(monkeypatch):
    stop = threading.Event()
    loads = {"n": 0}

    def fake_load(conn):
        loads["n"] += 1
        if loads["n"] >= 3:
            stop.set()
        raise RuntimeError("still down")

    monkeypatch.setattr(app, "connect_db", lambda url: FakeStoreConn())
    monkeypatch.setattr(app, "load_active_rules", fake_load)

    app.run_drift_loop(_fast_cfg(), stop)  # returns instead of raising
    assert loads["n"] == 3


def test_loop_continues_past_a_failed_single_scan(monkeypatch):
    stop = threading.Event()

    def fake_load(conn):
        return [_rule("fp_a"), _rule("fp_b")]

    def fake_scan(cfg, rule):
        if rule.fingerprint_id == "fp_a":
            raise RuntimeError("scan blew up")
        stop.set()  # fp_b still scanned after fp_a failed

    monkeypatch.setattr(app, "connect_db", lambda url: FakeStoreConn())
    monkeypatch.setattr(app, "load_active_rules", fake_load)
    monkeypatch.setattr(app, "scan_rule", fake_scan)

    app.run_drift_loop(_fast_cfg(), stop)
    assert stop.is_set()  # reached fp_b: one failed rule does not stop the sweep


# --- scan_rule wiring -------------------------------------------------------------


def test_scan_rule_threads_baseline_into_known_unmapped_and_inserts(monkeypatch):
    view = [(_ts(0), "parsed", _doc()), (_ts(1), "parsed", _doc(ip="SRC=1.2.3.4"))]
    baseline = {"src_endpoint.ip": {"null_rate": 0.0}, "unmapped.IN": {"null_rate": 0.0}}
    captured, inserted = {}, []

    monkeypatch.setattr(app, "connect_db", lambda url: FakeStoreConn())
    monkeypatch.setattr(app, "fetch_current_view", lambda conn, fp, v: view)
    monkeypatch.setattr(app, "baseline_for", lambda conn, fp, v: baseline)
    monkeypatch.setattr(app, "first_window_unmapped",
                        lambda conn, fp, v: {"IN", "OUT"})

    real_compute = app.compute_windows

    def spy(rows, **kw):
        captured.update(kw)
        return real_compute(rows, **kw)

    monkeypatch.setattr(app, "compute_windows", spy)
    monkeypatch.setattr(app, "insert_windows",
                        lambda conn, rows: inserted.extend(rows))

    n = app.scan_rule(_fast_cfg(window_count=2), _rule())
    assert n == 1  # one closed window
    # Rule context threaded into the pure window math: the rule's mapped
    # targets, and the baseline's first-window keys (NOT the raw baseline).
    assert captured["mapped_paths"] == ("src_endpoint.ip",)
    assert captured["known_unmapped"] == {"IN", "OUT"}
    assert captured["count_window"] == 2 and captured["time_window_s"] == 600
    fields = [row[2] for row in inserted]
    assert "src_endpoint.ip" in fields and "__rule__" in fields
    # 1 violation of 2 parsed docs -> violation_rate 0.5 -> tier-1 'severe'.
    ip_row = next(row for row in inserted if row[2] == "src_endpoint.ip")
    assert ip_row[8] == 0.5 and ip_row[10] == "severe"


def test_scan_rule_without_baseline_passes_known_none(monkeypatch):
    captured = {}
    monkeypatch.setattr(app, "connect_db", lambda url: FakeStoreConn())
    monkeypatch.setattr(app, "fetch_current_view", lambda conn, fp, v: [])
    monkeypatch.setattr(app, "baseline_for", lambda conn, fp, v: None)
    monkeypatch.setattr(app, "first_window_unmapped",
                        lambda conn, fp, v: (_ for _ in ()).throw(
                            AssertionError("must not run pre-baseline")))
    real_compute = app.compute_windows

    def spy(rows, **kw):
        captured.update(kw)
        return real_compute(rows, **kw)

    monkeypatch.setattr(app, "compute_windows", spy)

    assert app.scan_rule(_fast_cfg(), _rule()) == 0  # no rows -> no windows
    assert captured["known_unmapped"] is None  # pre-baseline: keys recorded, none new


def test_scan_rule_holds_back_trailing_partial(monkeypatch):
    # 3 fresh rows with window_count=10: nothing is provably closed, so
    # insert_windows never runs.
    view = [(_ts(i), "parsed", _doc()) for i in range(3)]
    inserted = []
    monkeypatch.setattr(app, "connect_db", lambda url: FakeStoreConn())
    monkeypatch.setattr(app, "fetch_current_view", lambda conn, fp, v: view)
    monkeypatch.setattr(app, "baseline_for", lambda conn, fp, v: None)
    monkeypatch.setattr(app, "insert_windows",
                        lambda conn, rows: inserted.extend(rows))

    assert app.scan_rule(_fast_cfg(), _rule()) == 0
    assert inserted == []


# --- main(): ONE loop, single-threaded -------------------------------------------


def test_main_runs_the_single_loop_in_the_main_thread(monkeypatch):
    invoked = []

    def fake_loop(cfg, stop):
        invoked.append((cfg, stop, threading.current_thread() is threading.main_thread()))

    monkeypatch.setattr(app, "run_drift_loop", fake_loop)
    app.main()

    assert len(invoked) == 1  # ONE loop (controller ruling), no daemon threads
    cfg, stop, in_main = invoked[0]
    assert isinstance(cfg, Config) and isinstance(stop, threading.Event)
    assert in_main
