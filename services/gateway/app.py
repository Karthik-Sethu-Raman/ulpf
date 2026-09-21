# services/gateway/app.py — FastAPI gateway for the M1 dashboard (spec §15:
# the M1 API contract is frozen at M1 exit; Task 10 mirrors EventRow exactly).
#
# CORS is deliberately NOT enabled: the dashboard is same-origin through Caddy
# (reverse_proxy /api/* gateway:8000), so there is no cross-origin caller.
#
# Every DB touch runs in a worker thread (asyncio.to_thread) so psycopg's
# blocking I/O never stalls the event loop — including the SSE poll loop, which
# awaits asyncio.sleep(1) between polls and emits a `: keepalive` comment after
# 15s of silence. Streams are bounded via max_polls ONLY for tests; production
# runs unbounded and is cancelled by client disconnect.
import asyncio
import json
import logging
import time
import uuid
from datetime import datetime

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel

from gateway import queries, writes

log = logging.getLogger("gateway")

HTTP_PORT = 8000
SSE_POLL_SECONDS = 1.0
SSE_HEARTBEAT_SECONDS = 15.0


def _json_default(value):
    """SSE bodies are hand-serialized: dict_row rows carry uuid.UUID for UUID
    columns (psycopg3's default UUID loader) and datetime for timestamptz —
    both must become JSON scalars (str / ISO-8601 with the T separator)."""
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"unserializable SSE value: {type(value).__name__}")


def _wire_str(value) -> str:
    """Scalar wire form shared by BOTH exports: exactly the serialization
    _json_default applies inside json.dumps (UUID -> str, datetime ->
    ISO-8601), applied to Parquet columns BEFORE the arrow table is built so
    every non-int column is a plain string and the file schema stays stable."""
    return value.isoformat() if isinstance(value, datetime) else str(value)


async def sse_events(queries_module, poll_seconds, heartbeat_seconds, max_polls):
    """Yield one `data:` line per new current-view row, then poll.

    First poll (last_seen=None) snapshots the latest rows and emits them
    oldest-first; later polls fetch rows strictly newer than the last emitted
    parsed_at (brief: WHERE parsed_at > last_seen ... ORDER BY parsed_at). A
    `: keepalive` comment goes out after heartbeat_seconds without output so
    intermediaries never time the stream out.
    """
    last_seen = None
    last_activity = time.monotonic()
    polls = 0
    while max_polls is None or polls < max_polls:
        polls += 1
        if time.monotonic() - last_activity >= heartbeat_seconds:
            yield ": keepalive\n\n"
            last_activity = time.monotonic()
        rows = await asyncio.to_thread(queries_module.poll_events, last_seen)
        for row in rows:
            last_seen = row["parsed_at"]
            last_activity = time.monotonic()
            yield f"data: {json.dumps(row, default=_json_default)}\n\n"
        await asyncio.sleep(poll_seconds)


# --- M2 write path + review surfaces (Task 7; additive to the frozen M1 API) --
# Request bodies (actor defaults to "anonymous" — no auth in MVP).

class MappingBody(BaseModel):
    source_field: str
    ocsf_path: str


class OverrideBody(BaseModel):
    pattern: str
    mappings: list[MappingBody]


class ApproveBody(BaseModel):
    actor: str = "anonymous"
    reason: str | None = None
    edited_mappings: list[MappingBody] | None = None
    override: OverrideBody | None = None


class RejectBody(BaseModel):
    actor: str = "anonymous"
    reason: str | None = None


class ManualBody(BaseModel):
    fingerprint_id: str
    pattern: str
    mappings: list[MappingBody]
    actor: str = "anonymous"
    confidence: float | None = None


class UnquarantineBody(BaseModel):
    field: str
    actor: str = "anonymous"
    reason: str | None = None


# --- M3 export bodies (Task 8; spec §11 / PS g+h — SIEM/data-lake feeds). ------
# Both builders are module-level like sse_events so the routes can run them in
# a worker thread; both share fetch_export_rows (parsed-only current view,
# newest first, EXPORT_MAX-capped) so the two formats carry identical rows.

def _export_jsonl_lines(queries_module, fingerprint, status, limit) -> list[str]:
    """OCSF JSONL export body, assembled in the caller's worker thread (the
    route runs this via asyncio.to_thread so the fetch + serialization never
    touch the event loop): ONE OCSF document per line, newest first. Rows
    arrive parsed-only from fetch_export_rows, so no line is ever "null".
    Memory bound = the EXPORT_MAX cap: the row list and the line list are both
    capped by the same LIMIT."""
    rows = queries_module.fetch_export_rows(fingerprint, status, limit)
    return [json.dumps(row["ocsf"], default=_json_default) for row in rows]


def _export_parquet_bytes(queries_module, fingerprint, limit) -> bytes:
    """Parquet export body, built in the caller's worker thread. pyarrow is
    imported lazily (mirrors queries.py's lazy psycopg) so importing
    gateway.app stays cheap for non-export callers. The ocsf column is stored
    as a JSON-serialized STRING per row: nested OCSF documents vary row to row
    (optional attributes come and go), so a struct schema would churn with
    every producer change — a flat string column keeps the file schema
    constant for data-lake ingestion (consumers json-parse it on read).
    Timestamps/UUIDs are wire-serialized BEFORE the table (_wire_str: the same
    serialization as the JSONL export) so both formats carry identical values
    and the arrow types are plain strings. Memory bound = the EXPORT_MAX cap
    (row list + column arrays + the in-memory file)."""
    import io

    import pyarrow as pa
    import pyarrow.parquet as pq

    rows = queries_module.fetch_export_rows(fingerprint, None, limit)
    table = pa.table({
        "event_id": pa.array([_wire_str(r["event_id"]) for r in rows], type=pa.string()),
        "raw_id": pa.array([_wire_str(r["raw_id"]) for r in rows], type=pa.string()),
        "fingerprint_id": pa.array([r["fingerprint_id"] for r in rows], type=pa.string()),
        "rule_version": pa.array([r["rule_version"] for r in rows], type=pa.int32()),
        "status": pa.array([r["status"] for r in rows], type=pa.string()),
        "parsed_at": pa.array([_wire_str(r["parsed_at"]) for r in rows], type=pa.string()),
        "ocsf": pa.array([json.dumps(r["ocsf"], default=_json_default) for r in rows],
                         type=pa.string()),
    })
    sink = io.BytesIO()
    pq.write_table(table, sink, compression="snappy")
    return sink.getvalue()


def _write_http_error(exc: writes.WriteError) -> HTTPException:
    """writes.* typed errors -> the API contract: 404 unknown, 409 conflict,
    422 failed validation carrying the gate's checks + notes (the Review UI
    renders them)."""
    if isinstance(exc, writes.ValidationError):
        return HTTPException(status_code=422,
                             detail={"checks": exc.checks, "notes": exc.notes})
    if isinstance(exc, writes.ConflictError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=404, detail=str(exc))  # NotFoundError


def build_app(queries_module=queries, writes_module=writes,
              poll_seconds=SSE_POLL_SECONDS, heartbeat_seconds=SSE_HEARTBEAT_SECONDS,
              max_polls=None):
    """FastAPI app factory; the queries/writes modules are injected (tests
    monkeypatch gateway.queries / gateway.writes attributes — routes resolve
    them at request time)."""

    app = FastAPI(title="ulpf-gateway", version="0.1.0")

    @app.get("/api/stats")
    async def stats():
        return await asyncio.to_thread(queries_module.fetch_stats)

    @app.get("/api/events")
    async def events(
        status: str | None = None,
        fingerprint: str | None = None,
        limit: int = Query(default=queries.DEFAULT_LIMIT, ge=1, le=queries.MAX_LIMIT),
        before: datetime | None = None,
    ):
        rows = await asyncio.to_thread(
            queries_module.fetch_events, status, fingerprint, limit, before
        )
        return {"events": rows}

    @app.get("/api/events/{event_id}/raw")
    async def raw_trace(event_id: uuid.UUID):
        trace = await asyncio.to_thread(queries_module.fetch_raw_trace, event_id)
        if trace is None:
            raise HTTPException(status_code=404, detail=f"event {event_id} not found")
        return trace

    @app.get("/api/audit/chain/head")
    async def chain_head():
        return {"heads": await asyncio.to_thread(queries_module.fetch_chain_heads)}

    @app.get("/api/stream/events")
    async def stream_events():
        return StreamingResponse(
            sse_events(queries_module, poll_seconds, heartbeat_seconds, max_polls),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ---------- M2: rules, samples status, audit; rule lifecycle ----------

    @app.get("/api/rules")
    async def list_rules(status: str | None = None):
        return {"rules": await asyncio.to_thread(queries_module.fetch_rules, status)}

    @app.get("/api/rules/{fingerprint_id}")
    async def rule_history(fingerprint_id: str):
        return await asyncio.to_thread(
            queries_module.fetch_rule_history, fingerprint_id)

    @app.get("/api/onboarding/samples")
    async def samples_status(fingerprint: str | None = None):
        rows = await asyncio.to_thread(queries_module.fetch_samples_status, fingerprint)
        if fingerprint is not None:
            return rows[0]  # single-fingerprint form; fetch_* zero-fills unknown fps
        return {"samples": rows}

    @app.get("/api/audit")
    async def audit_trail(
        fingerprint: str | None = None,
        limit: int = Query(default=queries.DEFAULT_LIMIT, ge=1, le=queries.MAX_LIMIT),
    ):
        return {"audit": await asyncio.to_thread(
            queries_module.fetch_audit, fingerprint, limit)}

    @app.post("/api/rules/manual", status_code=201)
    async def create_manual(body: ManualBody):
        # Two-step manual authoring: this stores a validated pending_review
        # candidate; a human approves it through the SAME endpoint as SLM
        # candidates (one activation path, uniform audit).
        try:
            return await asyncio.to_thread(
                writes_module.create_manual_candidate, body.fingerprint_id,
                body.pattern, [m.model_dump() for m in body.mappings],
                actor=body.actor, confidence=body.confidence)
        except writes.WriteError as exc:
            raise _write_http_error(exc) from exc

    @app.post("/api/rules/{fingerprint_id}/candidates/{candidate_id}/approve")
    async def approve(fingerprint_id: str, candidate_id: int, body: ApproveBody):
        try:
            return await asyncio.to_thread(
                writes_module.approve_candidate, fingerprint_id, candidate_id,
                actor=body.actor, reason=body.reason,
                edited_mappings=None if body.edited_mappings is None
                else [m.model_dump() for m in body.edited_mappings],
                override=None if body.override is None else body.override.model_dump())
        except writes.WriteError as exc:
            raise _write_http_error(exc) from exc

    @app.post("/api/rules/{fingerprint_id}/candidates/{candidate_id}/reject")
    async def reject(fingerprint_id: str, candidate_id: int,
                     body: RejectBody | None = None):
        body = body or RejectBody()  # actor/reason are optional in the contract
        try:
            return await asyncio.to_thread(
                writes_module.reject_candidate, fingerprint_id, candidate_id,
                actor=body.actor, reason=body.reason)
        except writes.WriteError as exc:
            raise _write_http_error(exc) from exc

    @app.post("/api/rules/{fingerprint_id}/deactivate")
    async def deactivate(fingerprint_id: str, body: RejectBody | None = None):
        body = body or RejectBody()
        try:
            return await asyncio.to_thread(
                writes_module.deactivate_rule, fingerprint_id,
                actor=body.actor, reason=body.reason)
        except writes.WriteError as exc:
            raise _write_http_error(exc) from exc

    @app.post("/api/rules/{rule_id}/reactivate")
    async def reactivate(rule_id: int, body: RejectBody | None = None):
        body = body or RejectBody()
        try:
            return await asyncio.to_thread(
                writes_module.reactivate_rule, rule_id,
                actor=body.actor, reason=body.reason)
        except writes.WriteError as exc:
            raise _write_http_error(exc) from exc

    # ---------- M3: drift surfaces + human un-quarantine (Task 7) ----------

    @app.get("/api/drift/metrics")
    async def drift_metrics():
        return {"metrics": await asyncio.to_thread(queries_module.fetch_drift_metrics)}

    @app.get("/api/drift/alerts")
    async def drift_alerts():
        # P-4: one kind-discriminated list — "window" rows (drift_windows with
        # minor/moderate/severe severity) merged with "audit" rows (quarantine/
        # un-quarantine/deactivate actions, any actor), latest first.
        return {"alerts": await asyncio.to_thread(queries_module.fetch_drift_alerts)}

    @app.post("/api/rules/{fingerprint_id}/unquarantine")
    async def unquarantine(fingerprint_id: str, body: UnquarantineBody):
        try:
            return await asyncio.to_thread(
                writes_module.unquarantine_field, fingerprint_id, body.field,
                actor=body.actor, reason=body.reason)
        except writes.WriteError as exc:
            raise _write_http_error(exc) from exc

    # ---------- M3: export endpoints (Task 8; spec §11 / PS g+h) ----------

    @app.get("/api/export/ocsf")
    async def export_ocsf(
        fingerprint: str | None = None,
        status: str | None = None,
        limit: int = Query(default=queries.EXPORT_MAX),
    ):
        """OCSF JSONL export: application/x-ndjson, ONE OCSF document per
        line, newest first. Parsed-status DEFAULT — the export carries OCSF
        documents and only parsed rows have one, so the status filter narrows
        WITHIN parsed: non-parsed rows are SKIPPED (status=unparsed/
        parse_error/quarantined matches nothing and yields a 200 with an empty
        stream — never a "null" line). limit deliberately has NO le= bound:
        a bulk export must not 422; the fetch clamps it to EXPORT_MAX."""
        lines = await asyncio.to_thread(
            _export_jsonl_lines, queries_module, fingerprint, status, limit)
        return StreamingResponse((line + "\n" for line in lines),
                                 media_type="application/x-ndjson")

    @app.get("/api/export/parquet")
    async def export_parquet(
        fingerprint: str | None = None,
        limit: int = Query(default=queries.EXPORT_MAX),
    ):
        """Parquet export: the SAME fetch as the JSONL endpoint (EventRow
        columns + ocsf, parsed-only current view, newest first, EXPORT_MAX-
        capped; no status param in the frozen signature — the parsed default
        applies), returned as a snappy-compressed attachment. The ocsf column
        rides as a JSON string (flat, stable schema) and timestamps are
        ISO-8601 strings — see _export_parquet_bytes."""
        data = await asyncio.to_thread(
            _export_parquet_bytes, queries_module, fingerprint, limit)
        return Response(
            content=data,
            media_type="application/octet-stream",
            headers={"Content-Disposition":
                     'attachment; filename="ulpf-events.parquet"'},
        )

    return app


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    uvicorn.run(build_app(), host="0.0.0.0", port=HTTP_PORT, log_level="info")


if __name__ == "__main__":
    main()
