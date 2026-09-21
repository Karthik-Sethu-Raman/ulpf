# services/gateway/tests/test_gateway.py — gateway contract tests (M1 API contract,
# frozen at M1 exit; the Task 10 dashboard mirrors these shapes in web/src/types.ts).
#
# No DB in unit tests: every queries function is monkeypatched with fixed returns
# (controller R13 / brief Step 1). Real-SQL correctness rides on the Task 11/12
# end-to-end smoke. SSE is exercised with a bounded stream (max_polls) so
# TestClient consumes it fully — no connection is held open.
#
# Fixture shapes mirror real psycopg dict_row output EXACTLY: uuid.UUID objects
# for id columns (psycopg3 default UUID loader), real datetimes for timestamptz,
# dicts for JSONB, {"status": ..., "n": ...} dicts for GROUP BY rows. The
# jsonable() helper states what FastAPI/json.dumps put on the wire, so a
# serializer gap (e.g. an unhandled UUID) fails loudly here.
import json
import uuid
from datetime import UTC, datetime

import pytest

# Exact key sets — Task 10's types.ts mirrors EventRow EXACTLY.
EVENT_ROW_KEYS = {
    "event_id", "raw_id", "fingerprint_id", "rule_version", "status", "parsed_at", "ocsf",
}
RAW_TRACE_KEYS = {"raw_id", "received_at", "source_id", "transport", "content_hash", "raw_text"}
HEAD_KEYS = {"partition_id", "batch_seq", "merkle_root", "count"}


def event_row(**overrides) -> dict:
    """One EventRow as psycopg dict_row returns it: UUID objects, real datetime."""
    row = {
        "event_id": uuid.uuid4(),
        "raw_id": uuid.uuid4(),
        "fingerprint_id": "fp_ssh_denied",
        "rule_version": 3,
        "status": "parsed",
        "parsed_at": datetime(2026, 9, 19, 12, 0, 0, tzinfo=UTC),
        "ocsf": {"class_uid": 1004, "activity_name": "Create"},
    }
    row.update(overrides)
    return row


def jsonable(row: dict) -> dict:
    """The row as it appears on the wire: UUID -> str, datetime -> ISO-8601
    (what FastAPI's encoder and the SSE _json_default must both produce)."""
    return {
        key: value.isoformat() if isinstance(value, datetime) else
        str(value) if isinstance(value, uuid.UUID) else value
        for key, value in row.items()
    }


@pytest.fixture
def queries():
    import gateway.queries as q

    return q


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from gateway.app import build_app

    # Bounded SSE (poll_seconds=0, max_polls=2) so TestClient can drain the stream.
    return TestClient(build_app(poll_seconds=0.0, heartbeat_seconds=0.0, max_polls=2))


# ---------- GET /api/stats ----------

STATS = {
    "raw_total": 42,
    "by_status": {"parsed": 30, "unparsed": 9, "parse_error": 2, "quarantined": 1},
    "by_fingerprint": [{"fingerprint_id": "fp_ssh_denied", "total": 12, "parsed": 11}],
    "events_last_minute": 7,
    "dlq_total": None,
    "note": "dlq_total is not counted in M1",
}


def test_stats_shape(client, queries, monkeypatch):
    monkeypatch.setattr(queries, "fetch_stats", lambda: STATS)
    r = client.get("/api/stats")
    assert r.status_code == 200
    assert r.json() == STATS
    assert r.json()["dlq_total"] is None  # controller R3: null + note, not a number
    assert isinstance(r.json()["note"], str)


# ---------- GET /api/events ----------

def test_events_shape(client, queries, monkeypatch):
    rows = [event_row(), event_row(status="unparsed", rule_version=0, ocsf=None)]
    seen = {}

    def fake(status=None, fingerprint=None, limit=50, before=None):
        seen.update(status=status, fingerprint=fingerprint, limit=limit, before=before)
        return rows

    monkeypatch.setattr(queries, "fetch_events", fake)
    r = client.get("/api/events")
    assert r.status_code == 200
    assert r.json() == {"events": [jsonable(row) for row in rows]}
    assert set(r.json()["events"][0]) == EVENT_ROW_KEYS  # exact keys, no extras
    # defaults: no filters, limit 50
    assert seen == {"status": None, "fingerprint": None, "limit": 50, "before": None}


def test_events_filters_forwarded(client, queries, monkeypatch):
    seen = {}

    def fake(status=None, fingerprint=None, limit=50, before=None):
        seen.update(status=status, fingerprint=fingerprint, limit=limit, before=before)
        return []

    monkeypatch.setattr(queries, "fetch_events", fake)
    r = client.get("/api/events", params={
        "status": "parsed", "fingerprint": "fp_x", "limit": 10,
        "before": "2026-09-19T00:00:00Z",
    })
    assert r.status_code == 200
    assert r.json() == {"events": []}
    assert seen["status"] == "parsed" and seen["fingerprint"] == "fp_x"
    assert seen["limit"] == 10
    assert seen["before"] == datetime(2026, 9, 19, tzinfo=UTC)


def test_events_limit_bounds_rejected(client):
    # sane LIMIT: 1..500 accepted (default 50); nonsense bounds -> 422 FastAPI shape
    assert client.get("/api/events", params={"limit": 501}).status_code == 422
    assert client.get("/api/events", params={"limit": 0}).status_code == 422


def test_events_limit_upper_boundary_accepted(client, queries, monkeypatch):
    monkeypatch.setattr(queries, "fetch_events", lambda *a, **k: [])
    r = client.get("/api/events", params={"limit": 500})  # the le= boundary itself
    assert r.status_code == 200
    assert r.json() == {"events": []}


# ---------- GET /api/events/{event_id}/raw ----------

def test_raw_trace_shape(client, queries, monkeypatch):
    trace = {
        "raw_id": uuid.uuid4(),
        "received_at": datetime(2026, 9, 19, 11, 59, 59, tzinfo=UTC),
        "source_id": "udp-10.1.2.3",
        "transport": "syslog-udp",
        "content_hash": "ab" * 32,
        "raw_text": "Aug 27 14:32:07 fw01 kernel: X",
    }
    eid = uuid.uuid4()
    seen = {}

    def fake(event_id):
        seen["event_id"] = event_id
        return trace

    monkeypatch.setattr(queries, "fetch_raw_trace", fake)
    r = client.get(f"/api/events/{eid}/raw")
    assert r.status_code == 200
    assert r.json() == jsonable(trace)
    assert set(r.json()) == RAW_TRACE_KEYS  # exact keys, no extras
    assert seen["event_id"] == eid  # route hands the query a real UUID


def test_raw_404(client, queries, monkeypatch):
    monkeypatch.setattr(queries, "fetch_raw_trace", lambda event_id: None)
    r = client.get(f"/api/events/{uuid.uuid4()}/raw")
    assert r.status_code == 404
    body = r.json()
    assert "detail" in body and isinstance(body["detail"], str)  # FastAPI {"detail": ...}


def test_raw_malformed_id_422(client):
    assert client.get("/api/events/not-a-uuid/raw").status_code == 422


# ---------- GET /api/audit/chain/head ----------

def test_chain_head(client, queries, monkeypatch):
    heads = [
        {"partition_id": 0, "batch_seq": 4, "merkle_root": "c" * 64, "count": 500},
        {"partition_id": 1, "batch_seq": 2, "merkle_root": "d" * 64, "count": 120},
    ]
    monkeypatch.setattr(queries, "fetch_chain_heads", lambda: heads)
    r = client.get("/api/audit/chain/head")
    assert r.status_code == 200
    assert r.json() == {"heads": heads}
    assert all(set(h) == HEAD_KEYS for h in r.json()["heads"])


# ---------- GET /api/stream/events (SSE) ----------
# SSE rows keep their real dict_row shape (uuid.UUID ids, datetime parsed_at) —
# the endpoint's own serializer must cope, so any gap dies here, not in the demo.

def test_sse_headers(client, queries, monkeypatch):
    monkeypatch.setattr(queries, "poll_events", lambda after, limit=None: [event_row()])
    r = client.get("/api/stream/events")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")


def test_sse_first_data_line(client, queries, monkeypatch):
    r1 = event_row()
    r2 = event_row(status="unparsed", rule_version=0, ocsf=None)
    calls = []

    def fake(after, limit=None):
        calls.append(after)
        return [r1, r2] if len(calls) == 1 else []

    monkeypatch.setattr(queries, "poll_events", fake)
    r = client.get("/api/stream/events")
    data_lines = [ln for ln in r.text.splitlines() if ln.startswith("data: ")]
    assert len(data_lines) == 2  # one data: line per new current-view row
    assert json.loads(data_lines[0][len("data: "):]) == jsonable(r1)
    assert json.loads(data_lines[1][len("data: "):]) == jsonable(r2)
    # incremental poll: first call snapshots (after=None), then resumes strictly
    # past the last emitted row's parsed_at
    assert calls[0] is None
    assert calls[1] == r2["parsed_at"]


def test_sse_keepalive_comment(client, queries, monkeypatch):
    monkeypatch.setattr(queries, "poll_events", lambda after, limit=None: [])
    r = client.get("/api/stream/events")
    assert ": keepalive" in r.text  # heartbeat comment emitted when idle


def test_sse_serializes_uuids_and_datetimes(client, queries, monkeypatch):
    row = event_row(parsed_at=datetime(2026, 9, 19, 12, 30, 45, tzinfo=UTC))
    monkeypatch.setattr(queries, "poll_events", lambda after, limit=None: [row])
    r = client.get("/api/stream/events")
    data_lines = [ln for ln in r.text.splitlines() if ln.startswith("data: ")]
    parsed = json.loads(data_lines[0][len("data: "):])
    assert parsed["event_id"] == str(row["event_id"])  # UUID -> str, not a crash
    assert parsed["raw_id"] == str(row["raw_id"])
    assert parsed["parsed_at"] == "2026-09-19T12:30:45+00:00"  # ISO-8601, not str()


# ---------- queries pure helpers (no DB, real dict_row shapes) ----------

def test_zero_fill_statuses(queries):
    assert queries.zero_fill_statuses(
        [{"status": "parsed", "n": 5}, {"status": "quarantined", "n": 2}]
    ) == {
        "parsed": 5, "unparsed": 0, "parse_error": 0, "quarantined": 2,
    }
    assert queries.zero_fill_statuses([]) == {
        "parsed": 0, "unparsed": 0, "parse_error": 0, "quarantined": 0,
    }


def test_clamp_limit(queries):
    assert queries.clamp_limit(-5) == 1
    assert queries.clamp_limit(10**9) == 500
    assert queries.clamp_limit(50) == 50
    assert queries.clamp_limit(500) == 500


def test_r9_current_view_predicate_in_every_normalized_query(queries):
    # Controller R9: EVERY query over normalized_events carries
    # `superseded_by_event_id IS NULL` — fetch_stats (3 normalized queries),
    # fetch_events, fetch_raw_trace (join), poll_events. fetch_chain_heads is
    # deliberately absent (raw_batches has no supersede column).
    import inspect

    for fn_name in ("fetch_stats", "fetch_events", "fetch_raw_trace", "poll_events"):
        src = inspect.getsource(getattr(queries, fn_name))
        assert "superseded_by_event_id IS NULL" in src, f"{fn_name} missing R9 predicate"


# ================= M2 (Task 7): rules/samples/audit reads + write path =======
# Everything below is ADDITIVE — the frozen M1 contract above is untouched.
# Same monkeypatch pattern: new GETs return the queries-module fixtures
# verbatim; POSTs forward to gateway.writes (asserted to run off the event
# loop in a worker thread). The T9 fixes pin fetch_stats' truncation flag and
# zero_fill_statuses' strictness through a fake _connect.

RULE_ROW_KEYS = {
    "id", "fingerprint_id", "version", "pattern", "mappings", "provenance", "confidence",
    "status", "created_by", "created_at", "activated_at", "deactivated_at", "validation",
}
AUDIT_ROW_KEYS = {"id", "ts", "actor", "action", "entity", "detail"}


def rule_row(**overrides) -> dict:
    """One RuleRow as psycopg dict_row returns it (JSONB loaded, real datetimes)."""
    row = {
        "id": 7,
        "fingerprint_id": "fp_ssh_denied",
        "version": 3,
        "pattern": r"^.*?DENIED\s+(?P<extension>.*)$",
        "mappings": [{"source_field": "SRC", "ocsf_path": "src_endpoint.ip"}],
        "provenance": "slm",
        "confidence": 0.93,
        "status": "active",
        "created_by": "onboarding",
        "created_at": datetime(2026, 9, 19, 9, 0, 0, tzinfo=UTC),
        "activated_at": datetime(2026, 9, 19, 9, 5, 0, tzinfo=UTC),
        "deactivated_at": None,
        "validation": {"passed": True, "checks": {"caps_and_allowlist": True},
                       "held_out_match_rate": 1.0, "notes": [], "previews": [],
                       "prompt_count": 5, "held_out_count": 15},
    }
    row.update(overrides)
    return row


def audit_row(**overrides) -> dict:
    row = {
        "id": 41,
        "ts": datetime(2026, 9, 19, 9, 5, 0, tzinfo=UTC),
        "actor": "amy",
        "action": "rule_approved",
        "entity": "fp_ssh_denied",
        "detail": {"rule_id": 7, "version": 3, "actor": "amy"},
    }
    row.update(overrides)
    return row


class _FakeRowsConn:
    """Fake dict_row connection for the read helpers: records SQL, replays
    scripted fetch results FIFO (consumed per fetchone / fetchall call)."""

    def __init__(self, fetchone=(), fetchall=()):
        self.sql = []
        self.params = []
        self._fetchone = [dict(r) for r in fetchone]
        self._fetchall = [[dict(r) for r in batch] for batch in fetchall]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

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
                return conn._fetchone.pop(0)

            def fetchall(self):
                return conn._fetchall.pop(0)

        return Cur()


def _raises(exc):
    def _fn(*args, **kwargs):
        raise exc

    return _fn


# ---------- GET /api/rules + GET /api/rules/{fp} ----------

def test_rules_list_shape(client, queries, monkeypatch):
    rows = [rule_row(), rule_row(id=8, version=4, status="pending_review",
                                 activated_at=None)]
    monkeypatch.setattr(queries, "fetch_rules", lambda status=None: rows)
    r = client.get("/api/rules")
    assert r.status_code == 200
    assert r.json() == {"rules": [jsonable(row) for row in rows]}
    assert set(r.json()["rules"][0]) == RULE_ROW_KEYS  # exact RuleRow keys


def test_rules_status_filter_forwarded(client, queries, monkeypatch):
    seen = {}

    def fake(status=None):
        seen["status"] = status
        return []

    monkeypatch.setattr(queries, "fetch_rules", fake)
    assert client.get("/api/rules", params={"status": "pending_review"}).status_code == 200
    assert seen["status"] == "pending_review"
    assert client.get("/api/rules").status_code == 200  # no filter -> all statuses
    assert seen["status"] is None


def test_rule_history_shape(client, queries, monkeypatch):
    body = {"rules": [rule_row(version=3), rule_row(version=2, status="superseded")],
            "audit": [audit_row()]}
    monkeypatch.setattr(queries, "fetch_rule_history", lambda fp: body)
    r = client.get("/api/rules/fp_ssh_denied")
    assert r.status_code == 200
    assert r.json() == {
        "rules": [jsonable(row) for row in body["rules"]],
        "audit": [jsonable(row) for row in body["audit"]],
    }


# ---------- GET /api/onboarding/samples ----------

def test_samples_status_single_fingerprint_form(client, queries, monkeypatch):
    row = {"fingerprint_id": "fp_ssh_denied", "total": 20,
           "by_role": {"prompt": 5, "held_out": 15, "unused": 0},
           "latest_captured_at": datetime(2026, 9, 19, 10, 0, tzinfo=UTC)}
    seen = {}

    def fake(fingerprint=None):
        seen["fingerprint"] = fingerprint
        return [row]

    monkeypatch.setattr(queries, "fetch_samples_status", fake)
    r = client.get("/api/onboarding/samples", params={"fingerprint": "fp_ssh_denied"})
    assert r.status_code == 200
    assert r.json() == jsonable(row)  # fp given -> the single-fingerprint shape
    assert seen["fingerprint"] == "fp_ssh_denied"


def test_samples_status_all_fingerprints_form(client, queries, monkeypatch):
    rows = [{"fingerprint_id": "fp_a", "total": 20,
             "by_role": {"prompt": 5, "held_out": 15, "unused": 0},
             "latest_captured_at": None}]
    monkeypatch.setattr(queries, "fetch_samples_status", lambda fingerprint=None: rows)
    r = client.get("/api/onboarding/samples")
    assert r.status_code == 200
    assert r.json() == {"samples": rows}  # omitted -> that shape per fingerprint


# ---------- GET /api/audit ----------

def test_audit_endpoint_forwards_filters(client, queries, monkeypatch):
    rows = [audit_row()]
    seen = {}

    def fake(fingerprint=None, limit=50):
        seen.update(fingerprint=fingerprint, limit=limit)
        return rows

    monkeypatch.setattr(queries, "fetch_audit", fake)
    r = client.get("/api/audit", params={"fingerprint": "fp_ssh_denied", "limit": 10})
    assert r.status_code == 200
    assert r.json() == {"audit": [jsonable(row) for row in rows]}
    assert set(r.json()["audit"][0]) == AUDIT_ROW_KEYS
    assert seen == {"fingerprint": "fp_ssh_denied", "limit": 10}


def test_audit_limit_bounds_rejected(client):
    assert client.get("/api/audit", params={"limit": 501}).status_code == 422
    assert client.get("/api/audit", params={"limit": 0}).status_code == 422


# ---------- read helpers over a fake conn (real SQL pinned) ----------

def test_fetch_rules_filters_status_and_orders(queries, monkeypatch):
    conn = _FakeRowsConn(fetchall=[[rule_row()]])
    monkeypatch.setattr(queries, "_connect", lambda: conn)
    assert queries.fetch_rules("pending_review") == [rule_row()]
    assert "WHERE (%s::text IS NULL OR status = %s)" in conn.sql[0]
    assert "ORDER BY fingerprint_id, version DESC" in conn.sql[0]
    assert conn.params[0] == ("pending_review", "pending_review")


def test_fetch_rule_history_returns_rules_and_scoped_audit(queries, monkeypatch):
    conn = _FakeRowsConn(fetchall=[
        [rule_row(version=3), rule_row(version=2, status="superseded")],
        [audit_row()],
    ])
    monkeypatch.setattr(queries, "_connect", lambda: conn)
    body = queries.fetch_rule_history("fp_ssh_denied")
    assert body["rules"][0]["version"] == 3  # versions newest-first
    assert body["audit"] == [audit_row()]
    assert "ORDER BY version DESC" in conn.sql[0]
    assert "FROM audit_log" in conn.sql[1] and "ORDER BY id DESC LIMIT 200" in conn.sql[1]
    assert conn.params[1] == ("fp_ssh_denied",)


def test_fetch_samples_status_groups_by_fingerprint_and_role(queries, monkeypatch):
    latest = datetime(2026, 9, 19, 10, 0, tzinfo=UTC)
    conn = _FakeRowsConn(fetchall=[[
        {"fingerprint_id": "fp_a", "total": 20, "prompt": 5, "held_out": 15,
         "unused": 0, "latest_captured_at": latest},
    ]])
    monkeypatch.setattr(queries, "_connect", lambda: conn)
    assert queries.fetch_samples_status() == [{
        "fingerprint_id": "fp_a", "total": 20,
        "by_role": {"prompt": 5, "held_out": 15, "unused": 0},
        "latest_captured_at": latest,
    }]
    assert "GROUP BY fingerprint_id" in conn.sql[0]
    assert conn.params[0] == (None, None)


def test_fetch_samples_status_zero_fills_unknown_fingerprint(queries, monkeypatch):
    conn = _FakeRowsConn(fetchall=[[]])
    monkeypatch.setattr(queries, "_connect", lambda: conn)
    assert queries.fetch_samples_status("fp_none") == [{
        "fingerprint_id": "fp_none", "total": 0,
        "by_role": {"prompt": 0, "held_out": 0, "unused": 0},
        "latest_captured_at": None,
    }]
    assert conn.params[0] == ("fp_none", "fp_none")


def test_fetch_audit_scopes_entity_and_clamps_limit(queries, monkeypatch):
    conn = _FakeRowsConn(fetchall=[[audit_row()]])
    monkeypatch.setattr(queries, "_connect", lambda: conn)
    assert queries.fetch_audit(fingerprint="fp_ssh_denied", limit=10**9) == [audit_row()]
    assert "FROM audit_log" in conn.sql[0] and "ORDER BY id DESC LIMIT %s" in conn.sql[0]
    assert conn.params[0] == ("fp_ssh_denied", "fp_ssh_denied", 500)


# ---------- T9 fixes ----------

def test_fetch_stats_flags_by_fingerprint_truncation_at_cap(queries, monkeypatch):
    conn = _FakeRowsConn(
        fetchone=[{"n": 1}, {"n": 0}],
        fetchall=[[], [{"fingerprint_id": f"fp_{i}", "total": 1, "parsed": 1}
                       for i in range(queries.MAX_LIMIT)]],
    )
    monkeypatch.setattr(queries, "_connect", lambda: conn)
    out = queries.fetch_stats()
    assert out["by_fingerprint_truncated"] is True  # LIMIT cap hit -> say so


def test_fetch_stats_omits_truncation_key_below_cap(queries, monkeypatch):
    conn = _FakeRowsConn(
        fetchone=[{"n": 1}, {"n": 0}],
        fetchall=[[], [{"fingerprint_id": f"fp_{i}", "total": 1, "parsed": 1}
                       for i in range(queries.MAX_LIMIT - 1)]],
    )
    monkeypatch.setattr(queries, "_connect", lambda: conn)
    assert "by_fingerprint_truncated" not in queries.fetch_stats()  # additive only


def test_zero_fill_statuses_rejects_unknown_status_key(queries):
    with pytest.raises(ValueError):
        queries.zero_fill_statuses([{"status": "weird", "n": 1}])
    # the known four still zero-fill
    assert queries.zero_fill_statuses([{"status": "parsed", "n": 2}])["parsed"] == 2


# ---------- POST write endpoints (forward to gateway.writes) ----------

def test_approve_endpoint_forwards_and_runs_in_worker_thread(client, monkeypatch):
    import threading

    from gateway import writes

    seen = {}

    def fake(fp, cid, **kwargs):
        seen["fp"], seen["cid"], seen["kwargs"] = fp, cid, kwargs
        seen["main_thread"] = threading.current_thread() is threading.main_thread()
        return {"rule_id": 9, "version": 3, "status": "active"}

    monkeypatch.setattr(writes, "approve_candidate", fake)
    r = client.post("/api/rules/fp_ssh_denied/candidates/9/approve",
                    json={"actor": "amy", "reason": "checked held-out"})
    assert r.status_code == 200
    assert r.json() == {"rule_id": 9, "version": 3, "status": "active"}
    assert (seen["fp"], seen["cid"]) == ("fp_ssh_denied", 9)
    assert seen["kwargs"]["actor"] == "amy"
    assert seen["kwargs"]["reason"] == "checked held-out"
    assert seen["main_thread"] is False  # asyncio.to_thread, not the event loop


def test_approve_edited_mappings_forwarded_as_dicts(client, monkeypatch):
    from gateway import writes

    seen = {}

    def fake(fp, cid, **kwargs):
        seen.update(kwargs)
        return {"rule_id": 10, "version": 4, "status": "active"}

    monkeypatch.setattr(writes, "approve_candidate", fake)
    r = client.post("/api/rules/fp/candidates/9/approve", json={
        "actor": "amy",
        "edited_mappings": [{"source_field": "SRC", "ocsf_path": "src_endpoint.ip"}],
    })
    assert r.status_code == 200
    assert seen["edited_mappings"] == [{"source_field": "SRC",
                                        "ocsf_path": "src_endpoint.ip"}]
    assert seen["override"] is None


def test_approve_error_mapping_404_and_409(client, monkeypatch):
    from gateway import writes

    monkeypatch.setattr(writes, "approve_candidate", _raises(writes.NotFoundError("gone")))
    assert client.post("/api/rules/fp/candidates/9/approve", json={}).status_code == 404

    monkeypatch.setattr(writes, "approve_candidate",
                        _raises(writes.ConflictError("not pending")))
    assert client.post("/api/rules/fp/candidates/9/approve", json={}).status_code == 409


def _gate_failure_report():
    from ulpf_core.validation import CandidateReport

    return CandidateReport(
        passed=False,
        checks={"caps_and_allowlist": False, "samples_parse": False,
                "held_out_match_all": False, "ip_fields_valid": True,
                "port_fields_valid": True, "no_orphan_mappings": True,
                "adversarial_probe": True, "no_hardcoded_literals": True},
        held_out_match_rate=0.0,
        notes=["compile error: boom"],
    )


def test_manual_422_carries_gate_checks_and_notes(client, monkeypatch):
    from gateway import writes

    report = _gate_failure_report()
    monkeypatch.setattr(writes, "create_manual_candidate",
                        _raises(writes.ValidationError(report)))
    r = client.post("/api/rules/manual", json={
        "fingerprint_id": "fp_a", "pattern": "^(", "mappings": [], "actor": "amy"})
    assert r.status_code == 422
    # FastAPI HTTPException detail: the gate's checks/notes, faithful for the UI
    assert r.json()["detail"]["checks"] == report.checks
    assert r.json()["detail"]["notes"] == report.notes


def test_approve_revalidation_failure_maps_to_422(client, monkeypatch):
    from gateway import writes

    report = _gate_failure_report()
    monkeypatch.setattr(writes, "approve_candidate", _raises(writes.ValidationError(report)))
    r = client.post("/api/rules/fp/candidates/9/approve", json={
        "edited_mappings": [{"source_field": "SRC", "ocsf_path": "bogus.path"}]})
    assert r.status_code == 422
    assert r.json()["detail"]["notes"] == report.notes


def test_manual_endpoint_201_and_forwards(client, monkeypatch):
    from gateway import writes

    seen = {}

    def fake(fp, pattern, mappings, **kwargs):
        seen.update(fp=fp, pattern=pattern, mappings=mappings, **kwargs)
        return {"rule_id": 12, "version": 1, "status": "pending_review"}

    monkeypatch.setattr(writes, "create_manual_candidate", fake)
    r = client.post("/api/rules/manual", json={
        "fingerprint_id": "fp_new", "pattern": "^.*?(?P<extension>.*)$",
        "mappings": [{"source_field": "msg", "ocsf_path": "message"}],
        "actor": "amy", "confidence": 0.5})
    assert r.status_code == 201
    assert r.json() == {"rule_id": 12, "version": 1, "status": "pending_review"}
    assert seen["fp"] == "fp_new"
    assert seen["mappings"] == [{"source_field": "msg", "ocsf_path": "message"}]
    assert seen["actor"] == "amy" and seen["confidence"] == 0.5


def test_reject_endpoint_forwards(client, monkeypatch):
    from gateway import writes

    seen = {}

    def fake(fp, cid, **kwargs):
        seen.update(fp=fp, cid=cid, **kwargs)
        return {"status": "rejected"}

    monkeypatch.setattr(writes, "reject_candidate", fake)
    r = client.post("/api/rules/fp/candidates/9/reject",
                    json={"actor": "amy", "reason": "bad"})
    assert r.status_code == 200
    assert r.json() == {"status": "rejected"}
    assert (seen["fp"], seen["cid"]) == ("fp", 9)
    assert seen["actor"] == "amy" and seen["reason"] == "bad"


def test_deactivate_and_reactivate_endpoints_forward(client, monkeypatch):
    from gateway import writes

    seen = {}

    def fake_deactivate(fp, **kwargs):
        seen["deactivate"] = (fp, kwargs)
        return {"rule_id": 5, "version": 2, "status": "deactivated"}

    def fake_reactivate(rule_id, **kwargs):
        seen["reactivate"] = (rule_id, kwargs)
        return {"rule_id": 5, "version": 2, "status": "active"}

    monkeypatch.setattr(writes, "deactivate_rule", fake_deactivate)
    monkeypatch.setattr(writes, "reactivate_rule", fake_reactivate)

    r = client.post("/api/rules/fp_ssh_denied/deactivate", json={"actor": "amy"})
    assert r.status_code == 200
    assert r.json() == {"rule_id": 5, "version": 2, "status": "deactivated"}
    assert seen["deactivate"] == ("fp_ssh_denied", {"actor": "amy", "reason": None})

    r = client.post("/api/rules/5/reactivate")  # empty body allowed
    assert r.status_code == 200
    assert r.json() == {"rule_id": 5, "version": 2, "status": "active"}
    assert seen["reactivate"][0] == 5
    assert seen["reactivate"][1]["actor"] == "anonymous"  # default actor
