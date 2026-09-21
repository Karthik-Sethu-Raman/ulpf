# services/drift/tests/test_app.py — loop wiring tests (onboarding-loop shape):
# fail-closed scan retries, the loop never raises out, scan_rule threading
# (baseline -> known_unmapped), the frozen Task 5 pipeline order (scan ->
# evaluate -> record -> FIRST baseline insert -> enforce worst-first), and the
# single-loop main(). Monkeypatch style: app.py imports its collaborators by
# name, so patching the app module's globals observes the wiring; NEVER a
# live DB.
import threading
from datetime import UTC, datetime, timedelta

from ulpf_core.models import Mapping

from drift import app
from drift.config import Config
from drift.store import ActiveDriftRule


def _ts(seconds: float) -> datetime:
    return datetime(2026, 9, 21, 10, 0, 0, tzinfo=UTC) + timedelta(seconds=seconds)


def _rule(fp="fp_a", rule_id=7, version=2, quarantined=()):
    return ActiveDriftRule(
        id=rule_id, fingerprint_id=fp, version=version, pattern=r"x",
        mappings=[Mapping(source_field="SRC", ocsf_path="src_endpoint.ip")],
        provenance="human", quarantined_fields=list(quarantined))


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


def test_scan_rule_threads_baseline_into_known_unmapped_and_records(monkeypatch):
    view = [(_ts(0), "parsed", _doc()), (_ts(1), "parsed", _doc(ip="SRC=1.2.3.4"))]
    baseline = {"src_endpoint.ip": {"null_rate": 0.0, "shape_dist": {"ipv4": 1.0}},
                "unmapped.IN": {"null_rate": 0.0, "shape_dist": {}}}
    captured, recorded, enforced = {}, [], []

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
    monkeypatch.setattr(app, "record_windows",
                        lambda conn, rule, findings, win: recorded.append(findings))
    monkeypatch.setattr(app, "enforce_findings",
                        lambda conn, rule, findings: enforced.append(findings))

    n = app.scan_rule(_fast_cfg(window_count=2), _rule())
    assert n == 1  # one closed window
    # Rule context threaded into the pure window math: the rule's mapped
    # targets, and the baseline's first-window keys (NOT the raw baseline).
    assert captured["mapped_paths"] == ("src_endpoint.ip",)
    assert captured["known_unmapped"] == {"IN", "OUT"}
    assert captured["count_window"] == 2 and captured["time_window_s"] == 600
    (findings,) = recorded
    fields = [f.field for f in findings]
    assert "src_endpoint.ip" in fields and "__rule__" in fields
    # 1 violation of 2 parsed docs -> violation_rate 0.5 -> tier-1 'severe'
    # -> rule_deactivated, and the scan's enforcement saw that finding.
    ip = next(f for f in findings if f.field == "src_endpoint.ip")
    assert ip.stats["violation_rate"] == 0.5
    assert ip.severity == "severe" and ip.action == "rule_deactivated"
    assert enforced == [findings]


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
    # record_windows never runs.
    view = [(_ts(i), "parsed", _doc()) for i in range(3)]
    recorded = []
    monkeypatch.setattr(app, "connect_db", lambda url: FakeStoreConn())
    monkeypatch.setattr(app, "fetch_current_view", lambda conn, fp, v: view)
    monkeypatch.setattr(app, "baseline_for", lambda conn, fp, v: None)
    monkeypatch.setattr(app, "record_windows",
                        lambda conn, rule, findings, win: recorded.append(findings))

    assert app.scan_rule(_fast_cfg(), _rule()) == 0
    assert recorded == []


# --- scan_rule pipeline: the frozen Task 5 order ----------------------------------


def test_scan_rule_runs_scan_evaluate_record_baseline_enforce_in_order(monkeypatch):
    view = [(_ts(i * 10), "parsed", _doc()) for i in range(4)]   # 2 windows of 2
    history = [(_ts(0), "__rule__", 2, None, 1.0, None),
               (_ts(20), "__rule__", 2, None, 1.0, None)]
    order = []

    real_compute, real_evaluate = app.compute_windows, app.evaluate_window

    def compute_spy(rows, **kw):
        order.append("windows")
        return real_compute(rows, **kw)

    def evaluate_spy(win, baseline, *, rule_quarantined):
        order.append("evaluate")
        return real_evaluate(win, baseline, rule_quarantined=rule_quarantined)

    monkeypatch.setattr(app, "connect_db", lambda url: FakeStoreConn())
    monkeypatch.setattr(app, "fetch_current_view",
                        lambda conn, fp, v: (order.append("scan"), view)[1])
    monkeypatch.setattr(app, "baseline_for",
                        lambda conn, fp, v: (order.append("baseline-read"), None)[1])
    monkeypatch.setattr(app, "first_window_unmapped",
                        lambda conn, fp, v: (_ for _ in ()).throw(
                            AssertionError("must not run pre-baseline")))
    monkeypatch.setattr(app, "compute_windows", compute_spy)
    monkeypatch.setattr(app, "evaluate_window", evaluate_spy)
    monkeypatch.setattr(app, "record_windows",
                        lambda conn, rule, findings, win: order.append("record"))
    monkeypatch.setattr(app, "fetch_window_history", lambda conn, fp, v: history)
    monkeypatch.setattr(app, "insert_baseline",
                        lambda conn, fp, v, profiles, n:
                        (order.append("baseline-insert"), True)[1])
    monkeypatch.setattr(app, "enforce_findings",
                        lambda conn, rule, findings: order.append("enforce"))

    assert app.scan_rule(_fast_cfg(window_count=2, baseline_windows=2), _rule()) == 2
    # evaluate+record run per window; the FIRST baseline insert comes after
    # all windows are recorded; enforcement is last, worst-first.
    assert order == ["scan", "baseline-read", "windows", "evaluate", "record",
                     "evaluate", "record", "baseline-insert", "enforce"]


def test_scan_rule_establishes_baseline_exactly_at_the_nth_window(monkeypatch):
    # 20 rows / window_count 2 -> the 10th window closes on THIS scan: the
    # profile INSERTs once, windows_seen == 10, aggregates from the history.
    view = [(_ts(i * 10), "parsed", _doc()) for i in range(20)]
    history = [(_ts(i * 10), "src_endpoint.ip", 2, 0.0, None, {"ipv4": 2})
               for i in range(0, 20, 2)]
    history += [(_ts(i * 10), "__rule__", 2, None, 1.0, None)
                for i in range(0, 20, 2)]
    inserts = []

    monkeypatch.setattr(app, "connect_db", lambda url: FakeStoreConn())
    monkeypatch.setattr(app, "fetch_current_view", lambda conn, fp, v: view)
    monkeypatch.setattr(app, "baseline_for", lambda conn, fp, v: None)
    monkeypatch.setattr(app, "first_window_unmapped",
                        lambda conn, fp, v: (_ for _ in ()).throw(
                            AssertionError("must not run pre-baseline")))
    monkeypatch.setattr(app, "record_windows",
                        lambda conn, rule, findings, win: None)
    monkeypatch.setattr(app, "fetch_window_history", lambda conn, fp, v: history)
    monkeypatch.setattr(app, "insert_baseline",
                        lambda conn, fp, v, profiles, n:
                        inserts.append((fp, v, profiles, n)) or True)

    assert app.scan_rule(_fast_cfg(window_count=2, baseline_windows=10),
                         _rule()) == 10
    assert len(inserts) == 1                       # exactly one insert, this scan
    fp, version, profiles, windows_seen = inserts[0]
    assert (fp, version, windows_seen) == ("fp_a", 2, 10)
    assert set(profiles) == {"src_endpoint.ip", "__rule__"}
    assert profiles["src_endpoint.ip"] == {"null_rate": 0.0,
                                           "shape_dist": {"ipv4": 1.0}}
    assert profiles["__rule__"]["events_count"] == {"min": 2, "max": 2}


def test_scan_rule_below_n_windows_never_inserts_a_baseline(monkeypatch):
    view = [(_ts(i * 10), "parsed", _doc()) for i in range(20)]
    history = [(_ts(i * 10), "__rule__", 2, None, 1.0, None)
               for i in range(0, 20, 2)]           # 10 windows, N demands 11
    inserts = []
    monkeypatch.setattr(app, "connect_db", lambda url: FakeStoreConn())
    monkeypatch.setattr(app, "fetch_current_view", lambda conn, fp, v: view)
    monkeypatch.setattr(app, "baseline_for", lambda conn, fp, v: None)
    monkeypatch.setattr(app, "record_windows",
                        lambda conn, rule, findings, win: None)
    monkeypatch.setattr(app, "fetch_window_history", lambda conn, fp, v: history)
    monkeypatch.setattr(app, "insert_baseline",
                        lambda conn, fp, v, profiles, n:
                        inserts.append((fp, v, profiles, n)) or True)

    app.scan_rule(_fast_cfg(window_count=2, baseline_windows=11), _rule())
    assert inserts == []                           # not due: 10 < 11


def test_scan_rule_post_baseline_never_reinserts_and_runs_tier2(monkeypatch):
    # The 11th+ scan: baseline_for returns the profile, so establishment never
    # runs, evaluate receives the profile (tier-2 armed) plus the rule's
    # quarantine list, and enforcement still sees every finding.
    baseline = {"src_endpoint.ip": {"null_rate": 0.0, "shape_dist": {"ipv4": 1.0}},
                "__rule__": {"match_rate": 1.0,
                             "events_count": {"min": 1, "max": 4}}}
    view = [(_ts(i), "parsed", _doc()) for i in range(4)]
    evaluated, enforced = [], []

    real_evaluate = app.evaluate_window

    def evaluate_spy(win, baseline_arg, *, rule_quarantined):
        evaluated.append((baseline_arg, rule_quarantined))
        return real_evaluate(win, baseline_arg, rule_quarantined=rule_quarantined)

    monkeypatch.setattr(app, "connect_db", lambda url: FakeStoreConn())
    monkeypatch.setattr(app, "fetch_current_view", lambda conn, fp, v: view)
    monkeypatch.setattr(app, "baseline_for", lambda conn, fp, v: baseline)
    monkeypatch.setattr(app, "first_window_unmapped", lambda conn, fp, v: set())
    monkeypatch.setattr(app, "evaluate_window", evaluate_spy)
    monkeypatch.setattr(app, "record_windows",
                        lambda conn, rule, findings, win: None)
    monkeypatch.setattr(app, "establish_baseline",
                        lambda conn, cfg, rule: (_ for _ in ()).throw(
                            AssertionError("establishment must not re-run")))
    monkeypatch.setattr(app, "enforce_findings",
                        lambda conn, rule, findings: enforced.append(findings))

    assert app.scan_rule(_fast_cfg(window_count=2), _rule()) == 2
    assert all(b is baseline and q == [] for b, q in evaluated)
    assert len(enforced) == 1 and len(enforced[0]) == 4   # 2 windows x 2 fields


def test_scan_rule_version_bump_is_tier1_only_then_rebases(monkeypatch):
    # A new (fingerprint, version) has no profile: evaluate runs tier-1-only
    # (baseline None), establishment is attempted (not due on empty history),
    # and enforcement still runs — tier-1 fires from event zero.
    view = [(_ts(0), "parsed", _doc()), (_ts(1), "parsed", _doc())]
    evaluated, enforced, inserts = [], [], []

    real_evaluate = app.evaluate_window

    def evaluate_spy(win, baseline_arg, *, rule_quarantined):
        evaluated.append(baseline_arg)
        return real_evaluate(win, baseline_arg, rule_quarantined=rule_quarantined)

    monkeypatch.setattr(app, "connect_db", lambda url: FakeStoreConn())
    monkeypatch.setattr(app, "fetch_current_view", lambda conn, fp, v: view)
    monkeypatch.setattr(app, "baseline_for", lambda conn, fp, v: None)
    monkeypatch.setattr(app, "first_window_unmapped",
                        lambda conn, fp, v: (_ for _ in ()).throw(
                            AssertionError("must not run pre-baseline")))
    monkeypatch.setattr(app, "evaluate_window", evaluate_spy)
    monkeypatch.setattr(app, "record_windows",
                        lambda conn, rule, findings, win: None)
    monkeypatch.setattr(app, "fetch_window_history", lambda conn, fp, v: [])
    monkeypatch.setattr(app, "insert_baseline",
                        lambda conn, fp, v, profiles, n:
                        inserts.append(n) or True)
    monkeypatch.setattr(app, "enforce_findings",
                        lambda conn, rule, findings: enforced.append(findings))

    assert app.scan_rule(_fast_cfg(window_count=2), _rule(version=5)) == 1
    assert evaluated == [None]                     # tier-1-only phase
    assert inserts == []                           # nothing to aggregate yet
    assert len(enforced) == 1                      # enforcement ran anyway


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
