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
from fastapi.responses import StreamingResponse
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

    return app


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    uvicorn.run(build_app(), host="0.0.0.0", port=HTTP_PORT, log_level="info")


if __name__ == "__main__":
    main()
