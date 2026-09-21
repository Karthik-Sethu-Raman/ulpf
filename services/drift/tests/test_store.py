# services/drift/tests/test_store.py — store SQL pinned through a recording
# fake conn/cursor (the onboarding/pipeline house style; NEVER a live DB).
#
# The fake records (sql, params) in execution order and brackets each
# `with conn.transaction():` block with TXN-START / TXN-COMMIT (or
# TXN-ROLLBACK) markers. Fetch results are consumed FIFO. psycopg is not on
# the test path, so its Json wrapper is unwrapped duck-typed via .obj.
from ulpf_core.models import Mapping

from drift.store import (
    ActiveDriftRule,
    baseline_for,
    fetch_current_view,
    first_window_unmapped,
    insert_baseline,
    insert_windows,
    load_active_rules,
)


class FakeConn:
    """Fake psycopg connection: records SQL, replays scripted fetch results."""

    def __init__(self, fetchone_results=(), fetchall_results=()):
        self.sql: list = []
        self.params: list = []
        self.txns_opened = 0
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
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def execute(self, sql, params=None):
                conn.sql.append(sql)
                conn.params.append(params)

            def fetchone(self):
                return list(conn._fetchone.pop(0)) if conn._fetchone else [1]

            def fetchall(self):
                return list(conn._fetchall.pop(0)) if conn._fetchall else []

        return Cur()


def _unwrap(value):
    """psycopg's Json adapter -> plain Python (duck-typed: no psycopg here)."""
    return value.obj if hasattr(value, "obj") else value


def _rule_row(fp="fp_a", rule_id=7, version=2, quarantined=("dst_endpoint.ip",)):
    return (rule_id, fp, version, r"x", [
        {"source_field": "SRC", "ocsf_path": "src_endpoint.ip"}],
        list(quarantined) if quarantined is not None else None, "human")


# --- load_active_rules: id + mappings + quarantined_fields ---------------------


def test_load_active_rules_rebuilds_typed_rules_with_quarantine():
    conn = FakeConn(fetchall_results=[[_rule_row()]])
    rules = load_active_rules(conn)

    assert len(rules) == 1 and isinstance(rules[0], ActiveDriftRule)
    rule = rules[0]
    assert rule.id == 7 and rule.fingerprint_id == "fp_a" and rule.version == 2
    assert rule.mappings == [Mapping(source_field="SRC", ocsf_path="src_endpoint.ip")]
    assert rule.quarantined_fields == ["dst_endpoint.ip"]
    sql = next(s for s in conn.sql if isinstance(s, str))
    assert "FROM rules WHERE status = 'active'" in sql
    assert "quarantined_fields" in sql and "mappings" in sql
    assert "ORDER BY fingerprint_id" in sql  # deterministic scan order


def test_load_active_rules_returns_rules_in_fingerprint_order():
    conn = FakeConn(fetchall_results=[[_rule_row("fp_b", 9), _rule_row("fp_a", 7)]])
    rules = load_active_rules(conn)
    assert [r.fingerprint_id for r in rules] == ["fp_b", "fp_a"]  # DB orders; passthrough


def test_load_active_rules_null_quarantine_becomes_empty_list():
    conn = FakeConn(fetchall_results=[[_rule_row(quarantined=None)]])
    assert load_active_rules(conn)[0].quarantined_fields == []


# --- fetch_current_view: the DB current view, oldest first ----------------------


def test_fetch_current_view_selects_unsuperseded_active_version_rows():
    rows = [("2026-09-21T10:00:00Z", "parsed", {"a": 1})]
    conn = FakeConn(fetchall_results=[rows])
    assert fetch_current_view(conn, "fp_a", 2) == rows

    sql = next(s for s in conn.sql if isinstance(s, str))
    assert sql == ("SELECT parsed_at, status, ocsf FROM normalized_events "
                   "WHERE fingerprint_id = %s AND rule_version = %s "
                   "AND superseded_by_event_id IS NULL ORDER BY parsed_at")
    assert conn.params[conn.sql.index(sql)] == ("fp_a", 2)


# --- insert_windows: idempotent by deterministic PK, one txn per batch ----------


def test_insert_windows_on_conflict_do_nothing_in_one_transaction():
    row = ("fp_a", 2, "src_endpoint.ip", "t0", "t1", 4, 0.0, None, 0.25,
           {"ipv4": 3}, "moderate", None)
    conn = FakeConn()
    insert_windows(conn, [row, row])

    inserts = [(s, p) for s, p in zip(conn.sql, conn.params)
               if isinstance(s, str) and s.startswith("INSERT INTO drift_windows")]
    assert len(inserts) == 2
    sql, params = inserts[0]
    assert "ON CONFLICT (fingerprint_id, rule_version, field, window_start) DO NOTHING" in sql
    assert params[:3] == ("fp_a", 2, "src_endpoint.ip")
    assert params[6] == 0.0 and params[8] == 0.25 and params[10] == "moderate"
    assert params[11] is None                      # action_taken NULL until Task 5
    assert _unwrap(params[9]) == {"ipv4": 3}       # shape_dist rides as JSONB
    # One txn around the whole batch: a crash never leaves a half-written window.
    assert conn.txns_opened == 1
    assert conn.sql[0] == "TXN-START" and conn.sql[-1] == "TXN-COMMIT"


def test_insert_windows_null_shape_dist_stays_null():
    row = ("fp_a", 2, "__rule__", "t0", "t1", 4, None, 1.0, None, None, "none", None)
    conn = FakeConn()
    insert_windows(conn, [row])
    params = next(p for s, p in zip(conn.sql, conn.params)
                  if isinstance(s, str) and s.startswith("INSERT INTO drift_windows"))
    assert params[9] is None


def test_insert_windows_never_updates_anything():
    conn = FakeConn()
    insert_windows(conn, [("fp_a", 2, "__rule__", "t0", "t1", 1, None, 1.0,
                           None, None, "none", None)])
    assert not [s for s in conn.sql if isinstance(s, str)
                and s.upper().startswith("UPDATE")]  # INSERT-only grants honored


# --- baseline_for: dict of profiles or None -------------------------------------


def test_baseline_for_none_when_no_rows():
    conn = FakeConn(fetchall_results=[[]])
    assert baseline_for(conn, "fp_a", 2) is None
    sql = next(s for s in conn.sql if isinstance(s, str))
    assert sql == ("SELECT field, profile FROM baseline_profiles "
                   "WHERE fingerprint_id = %s AND rule_version = %s")
    assert conn.params[conn.sql.index(sql)] == ("fp_a", 2)


def test_baseline_for_maps_fields_to_profiles():
    profiles = [("src_endpoint.ip", {"null_rate": 0.1}), ("__rule__", {"match_rate": 1.0})]
    conn = FakeConn(fetchall_results=[profiles])
    assert baseline_for(conn, "fp_a", 2) == {
        "src_endpoint.ip": {"null_rate": 0.1}, "__rule__": {"match_rate": 1.0}}


# --- first_window_unmapped: the baseline's first-window key set ------------------


def test_first_window_unmapped_reads_earliest_window_keys():
    conn = FakeConn(fetchall_results=[[("unmapped.IN",), ("unmapped.OUT",)]])
    assert first_window_unmapped(conn, "fp_a", 2) == {"IN", "OUT"}
    sql = next(s for s in conn.sql if isinstance(s, str))
    assert "SELECT DISTINCT field FROM drift_windows" in sql
    assert "field LIKE 'unmapped.%%'" in sql
    assert "(SELECT MIN(window_start) FROM drift_windows" in sql
    assert conn.params[conn.sql.index(sql)] == ("fp_a", 2, "fp_a", 2)


# --- insert_baseline: existence-guarded, once -----------------------------------


def test_insert_baseline_skips_when_one_already_exists():
    conn = FakeConn()  # default fetchone -> [1]: a row exists
    inserted = insert_baseline(conn, "fp_a", 2, {"__rule__": {"match_rate": 1.0}}, 10)

    assert inserted is False
    sql = [s for s in conn.sql if isinstance(s, str)]
    assert any("SELECT 1 FROM baseline_profiles" in s for s in sql)
    assert not [s for s in sql if s.startswith("INSERT")]  # no write on the no-op
    assert conn.txns_opened == 1  # guard still ran inside one txn


def test_insert_baseline_writes_each_field_once_with_conflict_noop():
    conn = FakeConn(fetchone_results=[[]])  # fetchone -> []: no baseline yet
    profiles = {"src_endpoint.ip": {"null_rate": 0.1}, "__rule__": {"match_rate": 1.0}}
    inserted = insert_baseline(conn, "fp_a", 2, profiles, 10)

    assert inserted is True
    sql = [s for s in conn.sql if isinstance(s, str)]
    guard = next(s for s in sql if "SELECT 1 FROM baseline_profiles" in s)
    inserts = [s for s in sql if s.startswith("INSERT INTO baseline_profiles")]
    assert len(inserts) == 2  # one row per field, sorted for determinism
    assert all("ON CONFLICT (fingerprint_id, rule_version, field) DO NOTHING" in s
               for s in inserts)
    assert conn.txns_opened == 1
    assert sql.index(guard) < sql.index(inserts[0])
    first_params = conn.params[sql.index(inserts[0])]
    assert first_params[:3] == ("fp_a", 2, "__rule__")  # sorted() puts __rule__ first
    assert first_params[4] == 10                        # windows_seen
    assert _unwrap(first_params[3]) == {"match_rate": 1.0}
