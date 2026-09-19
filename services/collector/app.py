# services/collector/app.py — collector ingest service (M1 walking skeleton).
# Wraps every inbound line in a RawEnvelope and produces it to raw.logs. Zero parsing.
#
# M1 queue-down behavior (documented deviation, spooling arrives in M3):
# produce errors -> HTTP 503 / syslog drop with an error log.
import asyncio
import contextlib
import logging
import os
from datetime import UTC, datetime

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ValidationError
from ulpf_core.models import RawEnvelope

from collector.producer import KafkaProducer

log = logging.getLogger("collector")

SYSLOG_PORT = 5514
HTTP_PORT = 8080
MAX_LINE_CHARS = 65536  # RawEnvelope.raw cap, spec §10


def make_envelope(transport: str, source_id: str, raw: str) -> dict:
    """Wrap one raw line in a RawEnvelope-shaped dict (validated before produce)."""
    return {
        "transport": transport,
        "source_id": source_id,
        "received_at": datetime.now(UTC).isoformat(),
        "raw": raw,
    }


def source_id_for(transport: str, peer: tuple | None) -> str:
    """R7: UDP/TCP syslog source_id derives from the peer address (udp-<ip>/tcp-<ip>).

    Falls back to the transport name if the peer address is unavailable.
    """
    if peer is None:
        return transport
    prefix = "udp" if transport == "syslog-udp" else "tcp"
    return f"{prefix}-{peer[0]}"


def _validated(env: dict) -> dict:
    """Validate the envelope against RawEnvelope (empty/oversized lines raise)."""
    RawEnvelope(**env)
    return env


class SyslogUdpProtocol(asyncio.DatagramProtocol):
    """One datagram = one event. Produce runs off-loop via the default executor."""

    def __init__(self, producer):
        self.producer = producer
        self._in_flight: set = set()

    def datagram_received(self, data: bytes, addr):
        source_id = source_id_for("syslog-udp", addr)
        raw = data.decode("utf-8", errors="replace").rstrip("\r\n")
        try:
            env = _validated(make_envelope("syslog-udp", source_id, raw))
        except ValidationError:
            log.warning("udp %s: datagram rejected (%d chars), dropped", source_id, len(raw))
            return
        fut = asyncio.get_running_loop().run_in_executor(
            None, self.producer.produce_raw, env
        )
        self._in_flight.add(fut)
        fut.add_done_callback(self._on_produced)

    def _on_produced(self, fut) -> None:
        self._in_flight.discard(fut)
        if fut.cancelled():
            return
        if exc := fut.exception():
            log.error("udp produce failed, event dropped: %s", exc)


async def run_syslog_udp(producer, host: str = "0.0.0.0", port: int = SYSLOG_PORT):
    """Bind the UDP socket and serve datagrams until cancelled."""
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: SyslogUdpProtocol(producer), local_addr=(host, port)
    )
    log.info("syslog udp listening on %s:%d", host, port)
    try:
        await asyncio.Future()  # run until cancelled
    finally:
        transport.close()


async def handle_syslog_tcp(producer, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """One line = one event. source_id from the peer address (R7)."""
    source_id = source_id_for("syslog-tcp", writer.get_extra_info("peername"))
    try:
        while line := await reader.readline():
            raw = line.decode("utf-8", errors="replace").rstrip("\r\n")
            try:
                env = _validated(make_envelope("syslog-tcp", source_id, raw))
            except ValidationError:
                log.warning("tcp %s: line rejected (%d chars), dropped", source_id, len(raw))
                continue
            producer.produce_raw(env)
    except (ConnectionError, asyncio.IncompleteReadError):
        pass  # client went away mid-line; nothing to salvage
    except Exception:
        log.exception("tcp %s: handler error", source_id)
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()


async def run_syslog_tcp(producer, host: str = "0.0.0.0", port: int = SYSLOG_PORT):
    """TCP line server; serves until cancelled."""
    server = await asyncio.start_server(
        lambda r, w: handle_syslog_tcp(producer, r, w), host, port
    )
    log.info("syslog tcp listening on %s:%d", host, port)
    async with server:
        await server.serve_forever()


class IngestRequest(BaseModel):
    source_id: str
    lines: list[str]
    format_hint: str | None = None


def build_app(producer, udp: bool = True):
    """FastAPI app factory; the Kafka producer is injected (tests use a fake)."""

    @contextlib.asynccontextmanager
    async def lifespan(app):
        tasks: list[asyncio.Task] = []
        if udp:
            tasks.append(asyncio.create_task(run_syslog_udp(producer)))
            tasks.append(asyncio.create_task(run_syslog_tcp(producer)))
        try:
            yield
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if flush := getattr(producer, "flush", None):
                remaining = flush(5)
                log.info("shutdown flush: %d message(s) remaining", remaining)

    app = FastAPI(lifespan=lifespan)

    @app.post("/v1/ingest", status_code=202)
    async def ingest(body: IngestRequest):
        envelopes = []
        for line in body.lines:
            env = make_envelope("http", body.source_id, line)
            if body.format_hint is not None:
                env["format_hint"] = body.format_hint
            try:
                envelopes.append(_validated(env))
            except ValidationError:
                raise HTTPException(
                    status_code=422,
                    detail="line rejected: must be 1..65536 chars",
                )
        try:
            for env in envelopes:
                producer.produce_raw(env)
        except Exception:
            log.exception("http produce failed")
            raise HTTPException(status_code=503, detail="ingest temporarily unavailable")
        return {"accepted": len(envelopes)}

    return app


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    producer = KafkaProducer(os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092"))
    app = build_app(producer, udp=True)
    # uvicorn installs the SIGTERM/SIGINT handlers; graceful shutdown runs the
    # lifespan shutdown above, which flushes the producer.
    uvicorn.run(app, host="0.0.0.0", port=HTTP_PORT, log_level="info")
    producer.flush(10)  # belt-and-suspenders once the event loop is down


if __name__ == "__main__":
    main()
