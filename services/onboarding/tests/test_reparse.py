# services/onboarding/tests/test_reparse.py — R11 backlog re-parse sweep, SQL
# pinned through a recording fake conn/cursor (the M1 db-test style; NEVER a
# live DB). Same shape as test_store.py plus a `copy()` on the fake cursor so
# the staged-COPY insert (the pipeline.db.persist_normalized pattern,
# duplicated per the no-cross-import ruling) is observable: every write_row
# lands in conn.copied in call order, psycopg's Json wrapper unwrapped via .obj.
import uuid
from datetime import UTC, datetime

from ulpf_core.ids import event_id_for
from ulpf_core.models import Mapping, Rule
from ulpf_core.parsing import parse

from onboarding.reparse import SUPERSEDE_SQL, find_stale, sweep_one

RECEIVED_AT = datetime(2026, 9, 19, 12, 0, 0, tzinfo=UTC)


class FakeCopy:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def write_row(self, row):
        self._conn.copied.append(tuple(row))


class FakeConn:
    """Fake psycopg connection: records SQL, replays scripted fetch results."""

    def __init__(self, fetchall_results=()):
        self.sql: list = []
        self.params: list = []
        self.copied: list = []
        self.txns_opened = 0
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

            def fetchall(self):
                return list(conn._fetchall.pop(0)) if conn._fetchall else []

            def copy(self, sql):
                conn.sql.append(sql)
                conn.params.append(None)
                return FakeCopy(conn)

        return Cur()


def _unwrap(value):
    """psycopg's Json adapter -> plain Python (duck-typed: no psycopg here)."""
    return value.obj if hasattr(value, "obj") else value


def _rule_row(**over):
    """One find_stale row (dict). provenance rides along per the controller
    ruling: ulpf_core.models.Rule requires it, so STALE_SQL selects it too."""
    row = {
        "id": 7,
        "fingerprint_id": "fp_a",
        "version": 2,
        "pattern": r"(?P<message>.*)",
        "mappings": [{"source_field": "message", "ocsf_path": "message"}],
        "provenance": "slm",
    }
    row.update(over)
    return row


def _old_row(n=0, raw_text="host1 sshd: accepted"):
    """One BATCH_SQL fetch row: (event_id, raw_id, raw_received_at, raw_text)."""
    return (
        uuid.uuid5(uuid.NAMESPACE_URL, f"old-event-{n}"),
        uuid.uuid5(uuid.NAMESPACE_URL, f"raw-{n}"),
        RECEIVED_AT,
        raw_text,
    )


# --- (a) find_stale: active rules over unsuperseded older-version rows -------


def test_find_stale_selects_active_rules_over_unsuperseded_older_rows():
    conn = FakeConn(fetchall_results=[[
        (7, "fp_a", 2, "pat", [{"source_field": "m", "ocsf_path": "message"}], "slm"),
    ]])
    rows = find_stale(conn)

    assert rows == [{
        "id": 7,
        "fingerprint_id": "fp_a",
        "version": 2,
        "pattern": "pat",
        "mappings": [{"source_field": "m", "ocsf_path": "message"}],
        "provenance": "slm",
    }]
    # Whitespace-normalized: the predicate must keep the partial-index shape.
    sql = " ".join(next(s for s in conn.sql if isinstance(s, str)).split())
    assert "FROM rules r" in sql
    assert "r.status = 'active'" in sql
    assert ("ne.superseded_by_event_id IS NULL AND "
            "COALESCE(ne.rule_version, 0) < r.version") in sql
    assert "EXISTS" in sql
    assert "ne.fingerprint_id = r.fingerprint_id" in sql
    assert conn.params[conn.sql.index(next(
        s for s in conn.sql if isinstance(s, str)))] is None


# --- (b) sweep_one: INSERT + supersede in ONE txn, then reparse_complete -----


def test_sweep_one_inserts_new_row_and_supersedes_in_one_txn_then_audits():
    conn = FakeConn(fetchall_results=[[_old_row()]])
    result = sweep_one(conn, _rule_row(), batch_size=500)

    assert result == {"inserted": 1, "superseded": 1, "status": "complete"}
    sql = [s for s in conn.sql if isinstance(s, str)]
    create = next(s for s in sql if s.startswith("CREATE TEMP TABLE staging_ne"))
    copy_sql = next(s for s in sql if s.startswith("COPY staging_ne"))
    insert_sql = next(s for s in sql if s.startswith("INSERT INTO normalized_events"))
    supersede_ix = sql.index(SUPERSEDE_SQL)
    audit_sql = next(s for s in sql if s.startswith("INSERT INTO audit_log"))
    # One txn: staging COPY -> INSERT -> supersede; the audit follows the commit.
    assert conn.txns_opened == 1
    assert (sql.index("TXN-START") < sql.index(create) < sql.index(copy_sql)
            < sql.index(insert_sql) < supersede_ix < sql.index("TXN-COMMIT")
            < sql.index(audit_sql))
    assert "ON CONFLICT (event_id, parsed_at) DO NOTHING" in insert_sql

    # New row: deterministic event_id, worker-parity fields.
    assert len(conn.copied) == 1
    (event_id, raw_id, raw_received_at, parsed_at, fp, rule_id, rule_version,
     status, _ocsf) = conn.copied[0]
    assert event_id == event_id_for(raw_id, 2)
    assert raw_id == _old_row()[1]
    assert raw_received_at == RECEIVED_AT
    assert parsed_at == RECEIVED_AT  # parsed_at := raw received_at
    assert (fp, rule_id, rule_version, status) == ("fp_a", 7, 2, "parsed")

    # The column-scoped UPDATE, old row keyed by (event_id, parsed_at).
    assert conn.params[supersede_ix] == (event_id, _old_row()[0], RECEIVED_AT)

    # One reparse_complete audit for the sweep, counts in the detail.
    assert conn.params[sql.index(audit_sql)][:3] == ("onboarding", "reparse_complete", "fp_a")
    detail = _unwrap(conn.params[sql.index(audit_sql)][3])
    assert detail == {"rule_id": 7, "version": 2, "inserted": 1, "superseded": 1}


# --- (c) raw that fails under the new version: parse_error + still supersede -


def test_sweep_one_parse_failure_stores_parse_error_and_still_supersedes():
    conn = FakeConn(fetchall_results=[[_old_row()]])
    result = sweep_one(conn, _rule_row(pattern=r"^NEVER-MATCH$"), batch_size=500)

    assert result == {"inserted": 1, "superseded": 1, "status": "complete"}
    (event_id, _raw_id, _raw_received_at, _parsed_at, _fp, rule_id, rule_version,
     status, ocsf) = conn.copied[0]
    # The parse_error row is attributed to the new rule_id/version.
    assert (event_id, rule_id, rule_version, status, ocsf) == (
        event_id_for(_old_row()[1], 2), 7, 2, "parse_error", None)
    # ...and the old row is still superseded, inside the same txn.
    supersede_ix = next(i for i, s in enumerate(conn.sql) if s == SUPERSEDE_SQL)
    assert conn.txns_opened == 1
    assert conn.sql.index("TXN-START") < supersede_ix < conn.sql.index("TXN-COMMIT")
    assert conn.params[supersede_ix] == (event_id, _old_row()[0], RECEIVED_AT)


# --- (d) idempotency: nothing stale -> nothing inserted, updated or audited --


def test_sweep_one_is_idempotent_once_nothing_is_stale():
    # The fake models the predicate: sweep #1 supersedes the row, so the same
    # stale-select drains and sweep #2 must insert/update/audit nothing.
    conn = FakeConn(fetchall_results=[[_old_row()], [], []])
    first = sweep_one(conn, _rule_row(), batch_size=500)
    second = sweep_one(conn, _rule_row(), batch_size=500)

    assert first == {"inserted": 1, "superseded": 1, "status": "complete"}
    assert second == {"inserted": 0, "superseded": 0, "status": "complete"}
    assert len(conn.copied) == 1
    assert sum(1 for s in conn.sql if s == SUPERSEDE_SQL) == 1
    audits = [s for s in conn.sql
              if isinstance(s, str) and s.startswith("INSERT INTO audit_log")]
    assert len(audits) == 1


# --- (e) doc["time"] is None -> filled with the raw received_at (parity) -----


def test_sweep_one_fills_missing_doc_time_with_raw_received_at():
    # Baseline: the rule maps no timestamp, so parse() itself leaves time None
    # — the fill below is the sweep's doing, exactly like the pipeline worker.
    rule = Rule(
        fingerprint_id="fp_a", version=2, pattern=r"(?P<message>.*)",
        mappings=[Mapping(source_field="message", ocsf_path="message")],
        provenance="slm",
    )
    doc, err = parse(_old_row()[3], rule)
    assert err is None and doc["time"] is None

    conn = FakeConn(fetchall_results=[[_old_row()]])
    sweep_one(conn, _rule_row(), batch_size=500)

    assert conn.copied[0][7] == "parsed"
    assert _unwrap(conn.copied[0][8])["time"] == RECEIVED_AT.isoformat()


# --- batch drain: full batches loop, one audit per sweep ---------------------


def test_sweep_one_loops_full_batches_and_audits_once_for_the_sweep():
    conn = FakeConn(fetchall_results=[
        [_old_row(1, "line one")], [_old_row(2, "line two")], [],
    ])
    result = sweep_one(conn, _rule_row(), batch_size=1)

    assert result == {"inserted": 2, "superseded": 2, "status": "complete"}
    assert conn.txns_opened == 2  # one txn per batch
    assert len(conn.copied) == 2
    audits = [s for s in conn.sql
              if isinstance(s, str) and s.startswith("INSERT INTO audit_log")]
    assert len(audits) == 1
    detail = _unwrap(conn.params[conn.sql.index(audits[0])][3])
    assert detail == {"rule_id": 7, "version": 2, "inserted": 2, "superseded": 2}
