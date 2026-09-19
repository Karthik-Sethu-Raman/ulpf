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

from gateway import queries

log = logging.getLogger("gateway")

HTTP_PORT = 8000
SSE_POLL_SECONDS = 1.0
SSE_HEARTBEAT_SECONDS = 15.0


def _json_default(value):
    """SSE bodies are hand-serialized: datetimes must come out ISO-8601 (with
    the T separator), which str(datetime) would not guarantee."""
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


def build_app(queries_module=queries, poll_seconds=SSE_POLL_SECONDS,
              heartbeat_seconds=SSE_HEARTBEAT_SECONDS, max_polls=None):
    """FastAPI app factory; the queries module is injected (tests monkeypatch
    gateway.queries attributes — routes resolve them at request time)."""

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

    return app


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    uvicorn.run(build_app(), host="0.0.0.0", port=HTTP_PORT, log_level="info")


if __name__ == "__main__":
    main()
