# services/pipeline/tests/test_db_samples.py — sample capture (R17) + the T7
# transaction refactor.
#
# collect_samples is pure (rows, active_rules, existing_counts, cap ->
# SampleRows); the SQL it feeds lands in persist_normalized's SAME transaction
# as the normalized rows. The fake conn records SQL in order and brackets each
# `with conn.transaction():` block with TXN-START / TXN-COMMIT markers (the
# COMMIT-equivalent of psycopg's context manager), so "the samples INSERT
# precedes COMMIT" is an assertion on the recorded sequence, the autocommit
# refactor is pinned by exactly-one-transaction per persist, and a zero-event
# batch must open no transaction at all. It also has no commit() method: a
# dropped explicit conn.commit() is the refactor's RED assertion.
import hashlib
import uuid
from datetime import UTC, datetime

import pytest

from pipeline.db import (
    NormalizedRow,
    PartitionMeta,
    RawRow,
    SampleRow,
    collect_samples,
    persist_batch,
    persist_normalized,
)

_TS = datetime(2026, 9, 19, 12, 0, 0, tzinfo=UTC)


def _row(fp="auto_x", n=0):
    return RawRow(
        raw_id=uuid.uuid5(uuid.NAMESPACE_DNS, f"raw-{fp}-{n}"),
        received_at=_TS,
        source_id="s",
        transport="http",
        format_hint=None,
        fingerprint_id=fp,
        content_hash=hashlib.sha256(f"line {n}".encode()).hexdigest(),
        raw_text=f"line {n}",
    )


def _norm(fp="auto_x", status="unparsed", seq=0):
    return NormalizedRow(
        event_id=uuid.uuid5(uuid.NAMESPACE_DNS, f"ev-{seq}"),
        raw_id=uuid.uuid5(uuid.NAMESPACE_DNS, f"raw-{seq}"),
        raw_received_at=_TS,
        parsed_at=_TS,
        fingerprint_id=fp,
        rule_id=None,
        rule_version=0,
        status=status,
        ocsf=None,
    )


# --- (b) collect_samples: pure capture policy --------------------------------


def test_unknown_fingerprint_rows_yield_samples():
    rows = [_row(n=i) for i in range(3)]
    samples = collect_samples(rows, {}, {"auto_x": 0}, cap=200)
    assert samples == [SampleRow("auto_x", r.raw_id, r.raw_text) for r in rows]


def test_capture_capped_at_cap_minus_existing():
    rows = [_row(n=i) for i in range(5)]
    samples = collect_samples(rows, {}, {}, cap=3)
    assert len(samples) == 3  # in-call takes count toward the cap too


def test_existing_at_cap_yields_no_samples():
    rows = [_row(n=i) for i in range(3)]
    assert collect_samples(rows, {}, {"auto_x": 200}) == []


def test_fingerprint_with_active_rule_never_sampled():
    rows = [_row("auto_r", n=i) for i in range(3)]
    assert collect_samples(rows, {"auto_r": object()}, {"auto_r": 0}, cap=200) == []


def test_mixed_batch_samples_only_rule_less_fingerprints():
    rows = [_row("auto_a", 0), _row("known", 1), _row("auto_a", 2)]
    samples = collect_samples(rows, {"known": object()}, {}, cap=200)
    assert [s.raw_id for s in samples] == [rows[0].raw_id, rows[2].raw_id]
    assert all(s.fingerprint_id == "auto_a" for s in samples)


# --- fake conn: records SQL, brackets transactions ----------------------------


class RecordingConn:
    """Fake psycopg connection for the txn refactor.

    transaction() returns a context manager that brackets the recorded SQL
    with TXN-START and TXN-COMMIT (or TXN-ROLLBACK when the body raised) —
    the COMMIT-equivalent of psycopg's autocommit transaction block. There is
    deliberately no commit() method: persist_* must not call one anymore.
    """

    def __init__(self, fail_on: str | None = None):
        self.sql: list = []
        self.params: list = []
        self.txns_opened = 0
        self.fail_on = fail_on

    def transaction(self):
        conn = self

        class Txn:
            def __enter__(self):
                conn.txns_opened += 1
                conn.sql.append("TXN-START")
                return self

            def __exit__(self, exc_type, exc, tb):
                conn.sql.append("TXN-ROLLBACK" if exc_type is not None else "TXN-COMMIT")
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
                if conn.fail_on and conn.fail_on in sql:
                    raise RuntimeError("db down")
                conn.sql.append(sql)
                conn.params.append(params)

            def executemany(self, sql, params_seq):
                if conn.fail_on and conn.fail_on in sql:
                    raise RuntimeError("db down")
                conn.sql.append(sql)
                conn.params.extend(params_seq)

            def fetchone(self):
                return [1]

            def fetchall(self):
                return []

            def copy(self, sql):
                conn.sql.append(sql)

                class Copy:
                    def __enter__(self):
                        return self

                    def __exit__(self, *exc):
                        return False

                    def write_row(self, row):
                        conn.sql.append(("COPY-ROW", row))

                return Copy()

        return Cur()

    def rollback(self):
        self.sql.append("ROLLBACK")


# --- (c) samples ride the normalized transaction ------------------------------


def test_samples_insert_inside_the_normalized_transaction():
    conn = RecordingConn()
    events = [_norm(seq=0), _norm(seq=1)]
    samples = [SampleRow("auto_x", events[0].raw_id, "line 0")]
    persist_normalized(conn, events, samples)

    sql = [s for s in conn.sql if isinstance(s, str)]
    sample_inserts = [s for s in sql if s.startswith("INSERT INTO onboarding_samples")]
    assert len(sample_inserts) == 1
    assert "ON CONFLICT (raw_id) DO NOTHING" in sample_inserts[0]
    # Same txn as the normalized rows: bracketed, INSERT before COMMIT.
    assert conn.txns_opened == 1
    norm_insert = next(i for i, s in enumerate(sql) if "INSERT INTO normalized_events" in s)
    assert sql.index("TXN-START") < norm_insert
    assert sql.index(sample_inserts[0]) < sql.index("TXN-COMMIT")
    # Columns fingerprint_id, raw_id, raw_text; captured_at left to default.
    assert ("auto_x", events[0].raw_id, "line 0") in conn.params


def test_persist_normalized_without_samples_skips_the_insert():
    conn = RecordingConn()
    persist_normalized(conn, [_norm()])
    assert not [s for s in conn.sql if isinstance(s, str)
                and s.startswith("INSERT INTO onboarding_samples")]


def test_persist_batch_opens_exactly_one_transaction():
    conn = RecordingConn()
    rows = [_row(n=0), _row(n=1)]
    parts = {0: PartitionMeta(0, 0, 1, [r.content_hash for r in rows])}
    persist_batch(conn, rows, parts)
    assert conn.txns_opened == 1
    assert conn.sql[0] == "TXN-START" and conn.sql[-1] == "TXN-COMMIT"


def test_persist_normalized_failure_propagates_and_marks_rollback():
    # The T7 refactor must keep the failure path intact: the exception leaves
    # the transaction block (which marks the rollback) and reaches the caller,
    # whose rollback+seek-back handling redelivers the batch unchanged.
    conn = RecordingConn(fail_on="INSERT INTO normalized_events")
    with pytest.raises(RuntimeError):
        persist_normalized(conn, [_norm()])
    assert "TXN-ROLLBACK" in conn.sql


# --- (d) txn hygiene: empty work opens nothing --------------------------------


def test_zero_event_batch_opens_no_transaction():
    conn = RecordingConn()
    persist_normalized(conn, [])
    persist_normalized(conn, [], None)
    persist_batch(conn, [], {})
    assert conn.txns_opened == 0
    assert conn.sql == []
