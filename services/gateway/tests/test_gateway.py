# services/gateway/tests/test_gateway.py — gateway contract tests (M1 API contract,
# frozen at M1 exit; the Task 10 dashboard mirrors these shapes in web/src/types.ts).
#
# No DB in unit tests: every queries function is monkeypatched with fixed returns
# (controller R13 / brief Step 1). Real-SQL correctness rides on the Task 11/12
# end-to-end smoke. SSE is exercised with a bounded stream (max_polls) so
# TestClient consumes it fully — no connection is held open.
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
    """One EventRow-shaped dict (contract keys only)."""
    row = {
        "event_id": str(uuid.uuid4()),
        "raw_id": str(uuid.uuid4()),
        "fingerprint_id": "fp_ssh_denied",
        "rule_version": 3,
        "status": "parsed",
        "parsed_at": "2026-09-19T12:00:00+00:00",
        "ocsf": {"class_uid": 1004, "activity_name": "Create"},
    }
    row.update(overrides)
    return row


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
    assert r.json() == {"events": rows}
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


# ---------- GET /api/events/{event_id}/raw ----------

def test_raw_trace_shape(client, queries, monkeypatch):
    trace = {
        "raw_id": str(uuid.uuid4()),
        "received_at": "2026-09-19T11:59:59+00:00",
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
    assert r.json() == trace
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
    assert json.loads(data_lines[0][len("data: "):]) == r1
    assert json.loads(data_lines[1][len("data: "):]) == r2
    # incremental poll: first call snapshots (after=None), then resumes strictly
    # past the last emitted row's parsed_at
    assert calls[0] is None
    assert calls[1] == r2["parsed_at"]


def test_sse_keepalive_comment(client, queries, monkeypatch):
    monkeypatch.setattr(queries, "poll_events", lambda after, limit=None: [])
    r = client.get("/api/stream/events")
    assert ": keepalive" in r.text  # heartbeat comment emitted when idle


def test_sse_serializes_datetimes_iso(client, queries, monkeypatch):
    row = event_row(parsed_at=datetime(2026, 9, 19, 12, 0, 0, tzinfo=UTC))
    monkeypatch.setattr(queries, "poll_events", lambda after, limit=None: [row])
    r = client.get("/api/stream/events")
    data_lines = [ln for ln in r.text.splitlines() if ln.startswith("data: ")]
    parsed = json.loads(data_lines[0][len("data: "):])
    assert parsed["parsed_at"] == "2026-09-19T12:00:00+00:00"  # ISO-8601, not str()


# ---------- queries pure helpers (no DB) ----------

def test_zero_fill_statuses(queries):
    assert queries.zero_fill_statuses([("parsed", 5), ("quarantined", 2)]) == {
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
