# services/drift/tests/test_enforce.py — Task 5 enforcement: quarantine /
# deactivate SQL (TOCTOU expected-status predicates + rowcount checks, the
# gateway writes.py discipline under drift_role's column-scoped grants),
# record_windows row assembly, and worst-first scan enforcement. Everything is
# pinned through a recording fake conn/cursor or monkeypatched collaborators;
# NEVER a live DB.
import json
from datetime import UTC, datetime, timedelta

import pytest
from ulpf_core.models import Mapping

from drift import enforce
from drift.detect import RULE_FIELD, Finding, evaluate_window
from drift.enforce import (
    deactivate_rule,
    enforce_findings,
    quarantine_field,
    record_windows,
)
from drift.store import ActiveDriftRule
from drift.windows import FieldStats, Window


def _ts(seconds: float) -> datetime:
    return datetime(2026, 9, 21, 10, 0, 0, tzinfo=UTC) + timedelta(seconds=seconds)


def _rule(fp="fp_a", rule_id=7, version=2, quarantined=()):
    return ActiveDriftRule(
        id=rule_id, fingerprint_id=fp, version=version, pattern=r"x",
        mappings=[Mapping(source_field="SRC", ocsf_path="src_endpoint.ip")],
        provenance="human", quarantined_fields=list(quarantined))


class FakeConn:
    """Fake psycopg connection: records SQL + params, replays scripted
    rowcounts (drift enforcement's TOCTOU answers) and fetch results."""

    def __init__(self, rowcounts=(), fetchone_results=(), fetchall_results=()):
        self.sql: list = []
        self.params: list = []
        self.txns_opened = 0
        self._rowcounts = list(rowcounts)
        self._fetchone = list(fetchone_results)
        self._fetchall = list(fetchall_results)

    def transaction(self):
        conn = self

        class Txn:
            def __enter__(self):
                conn.txns_opened += 1
                conn.sql.append("TXN-START")
                conn.params.append(None)  # keep sql/params index-aligned

            def __exit__(self, exc_type, exc, tb):
                conn.sql.append("TXN-ROLLBACK" if exc_type is not None else "TXN-COMMIT")
                conn.params.append(None)
                return False

        return Txn()

    def cursor(self):
        conn = self

        class Cur:
            rowcount = None

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def execute(self, sql, params=None):
                conn.sql.append(sql)
                conn.params.append(params)
                self.rowcount = (conn._rowcounts.pop(0)
                                 if conn._rowcounts else 1)

            def fetchone(self):
                return list(conn._fetchone.pop(0)) if conn._fetchone else [1]

            def fetchall(self):
                return list(conn._fetchall.pop(0)) if conn._fetchall else []

        return Cur()


def _unwrap(value):
    """psycopg's Json adapter -> plain Python (duck-typed: no psycopg here)."""
    return value.obj if hasattr(value, "obj") else value


def _statements(conn):
    return [(s, p) for s, p in zip(conn.sql, conn.params) if isinstance(s, str)]


# --- quarantine_field: array_append + NOT ANY + expected status -------------------


def test_quarantine_field_sql_and_params():
    conn = FakeConn(rowcounts=[1])
    assert quarantine_field(conn, _rule(), "src_endpoint.ip", _ts(0)) is True

    (sql, params), = [sp for sp in _statements(conn) if sp[0].startswith("UPDATE")]
    assert sql == (
        "UPDATE rules SET quarantined_fields = array_append(quarantined_fields, %s) "
        "WHERE id = %s AND status = 'active' "
        "AND NOT (%s = ANY(quarantined_fields))")
    # (field for array_append, rule id, field again for the ANY guard)
    assert params == ("src_endpoint.ip", 7, "src_endpoint.ip")


def test_quarantine_field_rowcount_zero_is_false_and_never_audited():
    # Already quarantined OR rule inactive: the WHERE matches nothing -> 0
    # rows -> False, idempotent, and NO audit row on the no-op.
    conn = FakeConn(rowcounts=[0])
    assert quarantine_field(conn, _rule(), "src_endpoint.ip", _ts(0)) is False
    assert not [s for s, _ in _statements(conn) if s.startswith("INSERT")]
    assert conn.txns_opened == 1  # the UPDATE still ran inside its transaction


def test_quarantine_field_true_audits_with_actor_drift_and_detail():
    conn = FakeConn(rowcounts=[1])
    rule = _rule(rule_id=9, version=3)
    assert quarantine_field(conn, rule, "dst_endpoint.ip", _ts(90)) is True

    audits = [(s, p) for s, p in _statements(conn) if s.startswith("INSERT INTO audit_log")]
    (sql, params), = audits
    assert sql == ("INSERT INTO audit_log (actor, action, entity, detail) "
                   "VALUES (%s, %s, %s, %s)")
    assert params[0] == "drift" and params[1] == "field_quarantined"
    assert params[2] == "fp_a"
    assert _unwrap(params[3]) == {"field": "dst_endpoint.ip", "rule_id": 9,
                                  "version": 3, "window_start": _ts(90).isoformat()}
    # The detail is JSONB: every value must survive plain json.dumps — a raw
    # datetime raised TypeError inside psycopg's Json() and rolled the paired
    # mutation back (observed live in Task 12; fake conns never serialize, so
    # this pin is the regression guard for that exact bug class).
    json.dumps(_unwrap(params[3]))
    # UPDATE and its audit pair inside ONE transaction (the writes.py pairing).
    assert conn.txns_opened == 1
    assert conn.sql[0] == "TXN-START" and conn.sql[-1] == "TXN-COMMIT"


def test_quarantine_field_touches_only_the_granted_column():
    conn = FakeConn(rowcounts=[1])
    quarantine_field(conn, _rule(), "f", _ts(0))
    (sql, _), = [sp for sp in _statements(conn) if sp[0].startswith("UPDATE")]
    # Only quarantined_fields is SET — migration 007 grants UPDATE on exactly
    # that column (plus status/deactivated_at for deactivate).
    assert sql.startswith("UPDATE rules SET quarantined_fields = array_append")


# --- deactivate_rule: expected-status predicate -----------------------------------


def test_deactivate_rule_sql_expected_status_predicate():
    conn = FakeConn(rowcounts=[1])
    assert deactivate_rule(conn, _rule(), _ts(0)) is True

    (sql, params), = [sp for sp in _statements(conn) if sp[0].startswith("UPDATE")]
    assert sql == ("UPDATE rules SET status = 'deactivated', deactivated_at = now() "
                   "WHERE id = %s AND status = 'active'")
    assert params == (7,)


def test_deactivate_rule_false_on_non_active_and_never_audited():
    # The 409-equivalent under drift_role: status moved concurrently -> 0 rows
    # -> False, no audit (a silent no-op that still audits would lie).
    conn = FakeConn(rowcounts=[0])
    assert deactivate_rule(conn, _rule(), _ts(0)) is False
    assert not [s for s, _ in _statements(conn) if s.startswith("INSERT")]


def test_deactivate_rule_true_audits_with_actor_drift():
    conn = FakeConn(rowcounts=[1])
    rule = _rule(rule_id=11, version=4)
    assert deactivate_rule(conn, rule, _ts(30)) is True

    (_, params), = [(s, p) for s, p in _statements(conn)
                    if s.startswith("INSERT INTO audit_log")]
    assert params[0] == "drift" and params[1] == "rule_deactivated"
    assert params[2] == "fp_a"
    # window_start rides as ISO-8601 (JSONB detail — see the quarantine test).
    detail = _unwrap(params[3])
    assert detail == {"rule_id": 11, "version": 4,
                      "window_start": _ts(30).isoformat()}
    json.dumps(detail)


# --- record_windows: findings overlaid onto the measured rows ---------------------


def _win():
    return Window(start=_ts(0), end=_ts(9), count=10, parsed=10, parse_errors=0,
                  field_stats={"src_endpoint.ip": FieldStats(
                      nulls=0, violations=3, values=["198.51.100.7"] * 7)},
                  new_unmapped=set())


def test_record_windows_writes_severity_and_action_taken():
    conn = FakeConn()
    rule, win = _rule(), _win()
    findings = evaluate_window(win, None, rule_quarantined=[])
    record_windows(conn, rule, findings, win)

    inserts = [(s, p) for s, p in _statements(conn)
               if s.startswith("INSERT INTO drift_windows")]
    assert len(inserts) == 2  # field row + __rule__ row
    assert all("ON CONFLICT (fingerprint_id, rule_version, field, window_start) "
               "DO NOTHING" in s for s, _ in inserts)
    by_field = {p[2]: p for _, p in inserts}
    ip = by_field["src_endpoint.ip"]
    # 3 violations of 10 parsed = 0.3 -> tier-1 moderate -> field_quarantined.
    assert ip[8] == pytest.approx(0.3) and ip[10] == "moderate"
    assert ip[11] == "field_quarantined"
    assert _unwrap(ip[9]) == {"ipv4": 7}
    assert by_field[RULE_FIELD][10] == "none" and by_field[RULE_FIELD][11] is None


def test_record_windows_keeps_zero_parsed_and_unmapped_row_shapes():
    conn = FakeConn()
    rule = _rule()
    win = Window(start=_ts(0), end=_ts(2), count=3, parsed=3, parse_errors=0,
                 field_stats={"unmapped.NEW": FieldStats(nulls=0, violations=0,
                                                        values=["eth9"])},
                 new_unmapped={"NEW"})
    record_windows(conn, rule, evaluate_window(win, None, rule_quarantined=[]), win)

    by_field = {p[2]: p for s, p in _statements(conn)
                if s.startswith("INSERT INTO drift_windows")}
    new = by_field["unmapped.NEW"]
    assert new[8] is None            # no tier-1 invariant on unmapped
    assert new[10] == "minor" and new[11] == "alert"

    zero = Window(start=_ts(0), end=_ts(2), count=3, parsed=0, parse_errors=3,
                  field_stats={}, new_unmapped=set())
    conn2 = FakeConn()
    record_windows(conn2, rule, evaluate_window(zero, None, rule_quarantined=[]),
                   zero)
    fields = [p[2] for s, p in _statements(conn2)
              if s.startswith("INSERT INTO drift_windows")]
    assert fields == [RULE_FIELD]    # zero-parsed: only the sentinel row


# --- enforce_findings: worst-first, one deactivate per scan -----------------------


def _finding(field, severity, action, start=0):
    return Finding(field, severity, action, {}, _ts(start))


class _Spy:
    def __init__(self, results=()):
        self.calls = []
        self._results = list(results)

    def __call__(self, conn, rule, *args):
        self.calls.append(args if args else rule.fingerprint_id)
        return self._results.pop(0) if self._results else True


def test_enforce_findings_severe_first_skips_moderate_after_deactivate(monkeypatch):
    deact, quar = _Spy(), _Spy()
    monkeypatch.setattr(enforce, "deactivate_rule", deact)
    monkeypatch.setattr(enforce, "quarantine_field", quar)
    findings = [
        _finding("src_endpoint.ip", "moderate", "field_quarantined", 60),
        _finding("dst_endpoint.ip", "severe", "rule_deactivated", 0),
    ]
    result = enforce_findings(FakeConn(), _rule(), findings)
    assert result == {"deactivated": True, "quarantined": []}
    assert len(deact.calls) == 1 and quar.calls == []  # worst-first: severe won


def test_enforce_findings_one_deactivate_per_scan(monkeypatch):
    deact = _Spy()
    monkeypatch.setattr(enforce, "deactivate_rule", deact)
    findings = [
        _finding("src_endpoint.ip", "severe", "rule_deactivated", 0),
        _finding(RULE_FIELD, "severe", "rule_deactivated", 60),
        _finding("dst_endpoint.ip", "severe", "rule_deactivated", 120),
    ]
    result = enforce_findings(FakeConn(), _rule(), findings)
    assert result["deactivated"] is True
    assert len(deact.calls) == 1  # the first worst finding deactivates, rest skip


def test_enforce_findings_quarantines_each_moderate_field(monkeypatch):
    quar = _Spy()
    monkeypatch.setattr(enforce, "deactivate_rule", _Spy())
    monkeypatch.setattr(enforce, "quarantine_field", quar)
    findings = [
        _finding("src_endpoint.ip", "moderate", "field_quarantined", 60),
        _finding("dst_endpoint.ip", "moderate", "field_quarantined", 0),
    ]
    result = enforce_findings(FakeConn(), _rule(), findings)
    assert result == {"deactivated": False,
                      "quarantined": ["dst_endpoint.ip", "src_endpoint.ip"]}
    assert quar.calls == [("dst_endpoint.ip", _ts(0)), ("src_endpoint.ip", _ts(60))]


def test_enforce_findings_ignores_none_minor_and_none_actions(monkeypatch):
    deact = _Spy()
    quar = _Spy()
    monkeypatch.setattr(enforce, "deactivate_rule", deact)
    monkeypatch.setattr(enforce, "quarantine_field", quar)
    findings = [
        _finding("src_endpoint.ip", "none", None),
        _finding("unmapped.NEW", "minor", "alert"),
        _finding("dst_endpoint.ip", "moderate", None),  # already quarantined
    ]
    assert enforce_findings(FakeConn(), _rule(), findings) == {
        "deactivated": False, "quarantined": []}
    assert deact.calls == [] and quar.calls == []


def test_enforce_findings_deactivate_false_still_ends_the_scan(monkeypatch):
    # deactivate_rule False (rule no longer active, TOCTOU): remaining actions
    # are skipped too — every later UPDATE would no-op anyway.
    deact, quar = _Spy(results=[False]), _Spy()
    monkeypatch.setattr(enforce, "deactivate_rule", deact)
    monkeypatch.setattr(enforce, "quarantine_field", quar)
    findings = [
        _finding("src_endpoint.ip", "severe", "rule_deactivated"),
        _finding("dst_endpoint.ip", "moderate", "field_quarantined"),
    ]
    result = enforce_findings(FakeConn(), _rule(), findings)
    assert result == {"deactivated": False, "quarantined": []}
    assert quar.calls == []


def test_enforce_findings_alerts_never_touch_the_db(monkeypatch):
    monkeypatch.setattr(enforce, "deactivate_rule", _Spy())
    conn = FakeConn()
    findings = [_finding("src_endpoint.ip", "minor", "alert")]
    enforce_findings(conn, _rule(), findings)
    assert _statements(conn) == []   # an alert IS the drift_windows row, no SQL
