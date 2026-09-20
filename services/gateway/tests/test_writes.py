# services/gateway/tests/test_writes.py — the gateway write path (Task 7),
# pinned through a recording fake conn (the onboarding test_store style; NEVER
# a live DB).
#
# The fake records (sql, params) in execution order and brackets each
# `with conn.transaction():` block with TXN-START / TXN-COMMIT (or
# TXN-ROLLBACK) markers, so "supersede active -> activate -> audit, one txn"
# is an assertion on the recorded sequence. Fetch results are consumed FIFO;
# `raise_on` scripts one-shot exceptions (the IntegrityError retry). psycopg
# appears ONLY as its exception class (the retry contract); Json wrappers are
# unwrapped duck-typed via .obj.
#
# The revalidation fixtures drive the REAL Task 3 gate (validate_candidate) —
# the same ACME rule/lines that pass in libs/ulpf-core's own suite.
import pytest
from psycopg import IntegrityError

from gateway import writes

ACME_PROMPT = ("ACMEGW fw01 2026-09-19T10:00:03Z DROP IN=eth0 OUT= SRC=198.51.100.4 "
               "DST=203.0.113.9 SPT=52114 DPT=8443")
ACME_HELD_OUT = ("ACMEGW fw02 2026-09-19T10:00:11Z ACCEPT IN=eth1 OUT= SRC=198.51.100.9 "
                 "DST=203.0.113.4 SPT=49300 DPT=443")
PATTERN = r"^.*?(?:DROP|ACCEPT)\s+(?P<extension>.*)$"
MAPPINGS = [
    {"source_field": "SRC", "ocsf_path": "src_endpoint.ip"},
    {"source_field": "DST", "ocsf_path": "dst_endpoint.ip"},
    {"source_field": "SPT", "ocsf_path": "src_endpoint.port"},
    {"source_field": "DPT", "ocsf_path": "dst_endpoint.port"},
]
SAMPLE_ROWS = [{"raw_text": ACME_PROMPT, "role": "prompt"},
               {"raw_text": ACME_HELD_OUT, "role": "held_out"}]


def candidate_row(**overrides) -> dict:
    """One pending candidate as psycopg dict_row returns it."""
    row = {
        "id": 9,
        "fingerprint_id": "fp_a",
        "version": 2,
        "status": "pending_review",
        "pattern": PATTERN,
        "mappings": MAPPINGS,
        "provenance": "slm",
        "confidence": 0.87,
    }
    row.update(overrides)
    return row


class FakeConn:
    """Fake psycopg dict_row connection: records SQL, replays scripted fetch
    results, raises scripted one-shot exceptions on matching SQL."""

    def __init__(self, fetchone=(), fetchall=(), raise_on=()):
        self.sql: list = []
        self.params: list = []
        self.txns_opened = 0
        self._fetchone = list(fetchone)
        self._fetchall = list(fetchall)
        self._raise_on = list(raise_on)  # (sql-substring, exception) pairs

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
                for i, (needle, exc) in enumerate(conn._raise_on):
                    if needle in sql:
                        conn._raise_on.pop(i)  # one-shot
                        raise exc

            def fetchone(self):
                if not conn._fetchone:
                    return None
                row = conn._fetchone.pop(0)
                return None if row is None else dict(row)  # scripted None = no row

            def fetchall(self):
                return [dict(r) for r in conn._fetchall.pop(0)] if conn._fetchall else []

        return Cur()


def _unwrap(value):
    """psycopg's Json adapter -> plain Python (duck-typed: no wrapper here)."""
    return value.obj if hasattr(value, "obj") else value


def _audit_rows(conn):
    """(params, unwrapped detail) per audit INSERT, in execution order."""
    out = []
    for i, sql in enumerate(conn.sql):
        if isinstance(sql, str) and sql.startswith("INSERT INTO audit_log"):
            params = conn.params[i]
            out.append((params, _unwrap(params[3])))
    return out


def _statements(conn, prefix):
    return [(sql, conn.params[i]) for i, sql in enumerate(conn.sql)
            if isinstance(sql, str) and sql.startswith(prefix)]


# --- approve: plain (status flip only, partial-index ordering, one audit) ----


def test_approve_plain_supersedes_active_first_then_activates_candidate():
    conn = FakeConn(fetchone=[candidate_row(), {"version": 2}])
    result = writes.approve_candidate("fp_a", 9, actor="amy", reason="looks right",
                                      conn=conn)

    assert result == {"rule_id": 9, "version": 2, "status": "active"}
    assert conn.txns_opened == 1  # single transaction
    assert conn.sql[0] == "TXN-START" and conn.sql[-1] == "TXN-COMMIT"

    sql = [s for s in conn.sql if isinstance(s, str)]
    supersede = next(s for s in sql if "status = 'superseded'" in s)
    activate = next(s for s in sql if "status = 'active', activated_at = now()" in s)
    # Partial-unique gotcha: the prior active row MUST flip to superseded
    # before the candidate goes active (per-statement index check).
    assert sql.index(supersede) < sql.index(activate)
    assert "WHERE fingerprint_id = %s AND status = 'active'" in supersede
    # Plain approve touches status + timestamps ONLY (content is UPDATE-denied).
    assert conn.params[conn.sql.index(activate)] == (9,)

    audits = _audit_rows(conn)
    assert len(audits) == 1  # exactly one audit INSERT
    (actor, action, entity, _), detail = audits[0]
    assert (actor, action, entity) == ("amy", "rule_approved", "fp_a")
    assert detail["actor"] == "amy" and detail["reason"] == "looks right"
    assert detail["prior_version"] == 2
    assert detail["rule_id"] == 9 and detail["version"] == 2


def test_approve_without_prior_active_records_null_prior_version():
    conn = FakeConn(fetchone=[candidate_row(), None])
    result = writes.approve_candidate("fp_a", 9, conn=conn)
    assert result["status"] == "active"
    (_p, detail) = _audit_rows(conn)[0]
    assert detail["prior_version"] is None


# --- approve: with edits / full override (new version row, draft consumed) ---


def test_approve_with_edited_mappings_mints_new_active_row_and_consumes_draft():
    conn = FakeConn(
        fetchone=[candidate_row(), {"version": 2}, {"next_version": 3}, {"id": 12}],
        fetchall=[SAMPLE_ROWS],
    )
    edited = [dict(MAPPINGS[0])]
    result = writes.approve_candidate("fp_a", 9, actor="amy", reason="fix src",
                                      edited_mappings=edited, conn=conn)

    assert result == {"rule_id": 12, "version": 3, "status": "active"}
    assert conn.txns_opened == 1 and conn.sql[-1] == "TXN-COMMIT"

    sql = [s for s in conn.sql if isinstance(s, str)]
    samples = next(s for s in sql if "FROM onboarding_samples" in s)
    version_sel = next(s for s in sql if "COALESCE(MAX(version), 0) + 1" in s)
    supersede = next(s for s in sql if "status = 'superseded'" in s)
    insert = next(s for s in sql if s.startswith("INSERT INTO rules"))
    flip = next(s for s in sql if "SET status = 'rejected'" in s)
    # Gate inputs fetched first; supersede BEFORE the new row is born active
    # (per-statement partial index); the draft is flipped after the mint.
    assert sql.index(samples) < sql.index(supersede) < sql.index(insert)
    assert sql.index(version_sel) < sql.index(insert)
    assert ("WHERE fingerprint_id = %s AND role IN ('prompt','held_out')") in samples
    assert "ORDER BY captured_at, id" in samples

    ip = conn.params[conn.sql.index(insert)]
    assert ip[0] == "fp_a" and ip[1] == 3  # version = MAX+1 minted inside the txn
    assert ip[2] == PATTERN  # edited mappings keep the candidate pattern
    assert _unwrap(ip[3]) == edited
    assert ip[4] == "slm-edited"
    assert ip[5] == 0.87  # candidate confidence carried through an edit
    assert ip[6] == "amy"  # created_by = the approving actor
    validation = _unwrap(ip[7])
    assert validation["passed"] is True  # revalidated through the REAL gate

    assert conn.params[conn.sql.index(flip)] == (9,)  # draft candidate consumed
    audits = _audit_rows(conn)
    assert len(audits) == 1
    (actor, action, entity, _), detail = audits[0]
    assert (actor, action, entity) == ("amy", "rule_approved", "fp_a")
    assert detail["consumed_by_edit"] == 3
    assert detail["prior_version"] == 2 and detail["reason"] == "fix src"


def test_approve_full_override_inserts_human_row_with_override_content():
    conn = FakeConn(
        fetchone=[candidate_row(), {"version": 2}, {"next_version": 4}, {"id": 13}],
        fetchall=[SAMPLE_ROWS],
    )
    override = {"pattern": PATTERN, "mappings": [dict(m) for m in MAPPINGS]}
    result = writes.approve_candidate("fp_a", 9, actor="amy", override=override,
                                      conn=conn)

    assert result == {"rule_id": 13, "version": 4, "status": "active"}
    insert = _statements(conn, "INSERT INTO rules")[0]
    ip = insert[1]
    assert ip[2] == override["pattern"]  # the override pattern, not the draft's
    assert _unwrap(ip[3]) == override["mappings"]
    assert ip[4] == "human"  # provenance records the human origin
    assert ip[5] is None  # the SLM confidence no longer describes this content
    assert ip[6] == "amy"
    assert _unwrap(ip[7])["passed"] is True
    (_p, detail) = _audit_rows(conn)[0]
    assert detail["consumed_by_edit"] == 4


# --- approve: failure paths ---------------------------------------------------


def test_approve_unknown_candidate_not_found():
    conn = FakeConn(fetchone=[None])
    with pytest.raises(writes.NotFoundError):
        writes.approve_candidate("fp_a", 999, conn=conn)
    assert not _statements(conn, "UPDATE rules")


def test_approve_non_pending_conflicts_without_writes():
    conn = FakeConn(fetchone=[candidate_row(status="rejected")])
    with pytest.raises(writes.ConflictError):
        writes.approve_candidate("fp_a", 9, conn=conn)
    sql = [s for s in conn.sql if isinstance(s, str)]
    assert not [s for s in sql if s.startswith("UPDATE rules")]
    assert not [s for s in sql if s.startswith("INSERT INTO rules")]
    assert "TXN-ROLLBACK" in sql


# --- reject -------------------------------------------------------------------


def test_reject_flips_candidate_and_audits_once():
    conn = FakeConn(fetchone=[candidate_row()])
    result = writes.reject_candidate("fp_a", 9, actor="amy", reason="wrong shape",
                                     conn=conn)

    assert result == {"status": "rejected"}
    assert conn.txns_opened == 1
    updates = _statements(conn, "UPDATE rules")
    assert "SET status = 'rejected'" in updates[0][0]
    assert updates[0][1] == (9,)
    (actor, action, entity, _), detail = _audit_rows(conn)[0]
    assert (actor, action, entity) == ("amy", "rule_rejected", "fp_a")
    assert detail["reason"] == "wrong shape" and detail["version"] == 2


def test_reject_non_pending_conflicts():
    conn = FakeConn(fetchone=[candidate_row(status="active")])
    with pytest.raises(writes.ConflictError):
        writes.reject_candidate("fp_a", 9, conn=conn)


def test_reject_unknown_candidate_not_found():
    conn = FakeConn(fetchone=[None])
    with pytest.raises(writes.NotFoundError):
        writes.reject_candidate("fp_a", 999, conn=conn)


# --- manual authoring (two-step: candidate here, approve via approve) ---------


def test_create_manual_candidate_success_stores_pending_human_row():
    conn = FakeConn(fetchone=[{"next_version": 1}, {"id": 33}], fetchall=[SAMPLE_ROWS])
    result = writes.create_manual_candidate("fp_a", PATTERN, MAPPINGS, actor="amy",
                                            confidence=0.5, conn=conn)

    assert result == {"rule_id": 33, "version": 1, "status": "pending_review"}
    assert conn.txns_opened == 1 and conn.sql[-1] == "TXN-COMMIT"
    insert = _statements(conn, "INSERT INTO rules")[0]
    assert "pending_review" in insert[0]
    ip = insert[1]
    assert ip[0] == "fp_a" and ip[1] == 1
    assert ip[4] == "human" and ip[5] == 0.5 and ip[6] == "amy"
    assert _unwrap(ip[7])["passed"] is True  # validated through the REAL gate
    (actor, action, entity, _), detail = _audit_rows(conn)[0]
    assert (actor, action, entity) == ("amy", "candidate_created", "fp_a")
    assert detail["rule_id"] == 33 and detail["version"] == 1


def test_create_manual_candidate_validation_failure_writes_nothing():
    conn = FakeConn(fetchall=[SAMPLE_ROWS])
    with pytest.raises(writes.ValidationError) as caught:
        writes.create_manual_candidate("fp_a", r"^NOMATCH.*$", MAPPINGS, actor="amy",
                                       conn=conn)
    assert caught.value.checks["held_out_match_all"] is False
    assert caught.value.notes  # gate notes carried for the 422 body
    sql = [s for s in conn.sql if isinstance(s, str)]
    assert not [s for s in sql if s.startswith("INSERT INTO rules")]
    assert "TXN-ROLLBACK" in sql


def test_create_manual_candidate_with_no_samples_degrades_to_pass():
    # The unseen-format path: the Task 3 gate passes with a "no samples" note.
    conn = FakeConn(fetchone=[{"next_version": 1}, {"id": 34}], fetchall=[[]])
    result = writes.create_manual_candidate("fp_new", PATTERN, MAPPINGS, actor="amy",
                                            conn=conn)
    assert result["status"] == "pending_review"
    validation = _unwrap(_statements(conn, "INSERT INTO rules")[0][1][7])
    assert validation["passed"] is True
    assert any("no samples" in note for note in validation["notes"])


# --- IntegrityError retry (concurrent candidate INSERT -> once, then 409) -----


def test_manual_integrity_error_retries_once_and_succeeds():
    conn = FakeConn(
        fetchone=[{"next_version": 1}, {"next_version": 1}, {"id": 33}],
        fetchall=[SAMPLE_ROWS, SAMPLE_ROWS],
        raise_on=[("INSERT INTO rules", IntegrityError("rules_one_pending"))],
    )
    result = writes.create_manual_candidate("fp_a", PATTERN, MAPPINGS, actor="amy",
                                            conn=conn)
    assert result["rule_id"] == 33
    assert len(_statements(conn, "INSERT INTO rules")) == 2  # retried once
    assert conn.txns_opened == 2


def test_manual_integrity_error_twice_conflicts():
    conn = FakeConn(
        fetchone=[{"next_version": 1}, {"next_version": 1}],
        fetchall=[SAMPLE_ROWS, SAMPLE_ROWS],
        raise_on=[("INSERT INTO rules", IntegrityError("rules_one_pending")),
                  ("INSERT INTO rules", IntegrityError("rules_one_pending"))],
    )
    with pytest.raises(writes.ConflictError):
        writes.create_manual_candidate("fp_a", PATTERN, MAPPINGS, actor="amy", conn=conn)
    assert len(_statements(conn, "INSERT INTO rules")) == 2  # retry, then give up


# --- deactivate / reactivate --------------------------------------------------


def test_deactivate_targets_the_active_row_and_audits():
    conn = FakeConn(fetchone=[{"id": 5, "version": 2}])
    result = writes.deactivate_rule("fp_a", actor="amy", reason="drift", conn=conn)

    assert result == {"rule_id": 5, "version": 2, "status": "deactivated"}
    assert conn.txns_opened == 1
    update = _statements(conn, "UPDATE rules")[0]
    assert "status = 'deactivated', deactivated_at = now()" in update[0]
    assert update[1] == (5,)
    (actor, action, entity, _), detail = _audit_rows(conn)[0]
    assert (actor, action, entity) == ("amy", "rule_deactivated", "fp_a")
    assert detail == {"rule_id": 5, "version": 2, "actor": "amy", "reason": "drift"}


def test_deactivate_without_active_rule_not_found():
    conn = FakeConn(fetchone=[None])
    with pytest.raises(writes.NotFoundError):
        writes.deactivate_rule("fp_a", conn=conn)


def test_reactivate_sets_active_and_audits():
    conn = FakeConn(fetchone=[
        {"id": 5, "fingerprint_id": "fp_a", "version": 2, "status": "deactivated"},
        None,  # no other active version
    ])
    result = writes.reactivate_rule(5, actor="amy", reason="false positive", conn=conn)

    assert result == {"rule_id": 5, "version": 2, "status": "active"}
    update = _statements(conn, "UPDATE rules")[0]
    assert "status = 'active', activated_at = now()" in update[0]
    assert update[1] == (5,)
    (actor, action, entity, _), detail = _audit_rows(conn)[0]
    assert (actor, action, entity) == ("amy", "rule_reactivated", "fp_a")
    assert detail["reason"] == "false positive"


def test_reactivate_conflicts_while_another_version_is_active():
    conn = FakeConn(fetchone=[
        {"id": 5, "fingerprint_id": "fp_a", "version": 2, "status": "deactivated"},
        {"id": 7},  # v3 is already active
    ])
    with pytest.raises(writes.ConflictError):
        writes.reactivate_rule(5, conn=conn)
    assert not _statements(conn, "UPDATE rules")


def test_reactivate_unknown_rule_not_found():
    conn = FakeConn(fetchone=[None])
    with pytest.raises(writes.NotFoundError):
        writes.reactivate_rule(999, conn=conn)
