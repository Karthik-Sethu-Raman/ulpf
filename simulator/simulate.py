# simulator/simulate.py — multi-vendor traffic simulator over the frozen golden corpora.
#
# Routes each corpus to the transport the collector expects (R7):
#   cef/syslog/acmegw -> UDP datagrams, one log line each, no envelope (the
#                        collector derives source_id from the peer address, so
#                        there is nothing to tag on the wire);
#   json              -> batched HTTP POSTs to /v1/ingest, source_id "ids01"
#                        (that field IS the raw.logs message key).
#
# Pacing: --eps is the TOTAL event rate, distributed evenly across the corpora
# found on disk; corpora are interleaved round-robin, one line per corpus per
# tick. --loop repeats the corpora until --duration elapses; without it, each
# corpus is sent once through (still paced), then the run ends.
#
# Stdout contract (parsed by the M1 smoke test): exactly one line per corpus,
#   <name> sent=<N>
# then a final "total sent=<N>". Everything else goes to stderr. Exit 0 unless
# the run was a total failure (no corpora, bad config, or every send failed).

from __future__ import annotations

import argparse
import asyncio
import inspect
import os
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

DEFAULT_UDP_ADDR = ("localhost", 5514)
DEFAULT_HTTP_BASE = "http://localhost:8080"
HTTP_SOURCE_ID = "ids01"
HTTP_BATCH_SIZE = 10
HTTP_TIMEOUT_S = 5.0

UDP_KEYS = frozenset({"cef", "syslog", "acmegw"})
HTTP_KEYS = frozenset({"json"})
CORPUS_KEYS = sorted(UDP_KEYS | HTTP_KEYS)


def transport_for(key: str) -> str:
    if key in UDP_KEYS:
        return "udp"
    if key in HTTP_KEYS:
        return "http"
    raise ValueError(f"unknown corpus key {key!r} (expected one of {CORPUS_KEYS})")


def parse_udp_addr(raw: str) -> tuple[str, int]:
    host, sep, port = raw.rpartition(":")
    if not sep or not host:
        raise ValueError(f"invalid COLLECTOR_UDP {raw!r} (expected host:port)")
    try:
        return host, int(port)
    except ValueError:
        raise ValueError(f"invalid COLLECTOR_UDP {raw!r} (bad port)") from None


class UdpSender:
    """One log line per datagram. Socket is created lazily (nothing sent, nothing bound)."""

    def __init__(self, addr: tuple[str, int], sock: socket.socket | None = None):
        self.addr = addr
        self._sock = sock

    def _ensure_sock(self) -> socket.socket:
        if self._sock is None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self._sock

    async def send(self, line: str) -> int:
        self._ensure_sock().sendto(line.encode("utf-8"), self.addr)
        return 1

    async def flush(self) -> int:
        return 0

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None


class HttpSender:
    """Buffers lines and POSTs batches to /v1/ingest; events count only on a 202."""

    def __init__(self, base_url: str, source_id: str = HTTP_SOURCE_ID,
                 batch_size: int = HTTP_BATCH_SIZE,
                 client: httpx.AsyncClient | None = None):
        self.url = base_url.rstrip("/") + "/v1/ingest"
        self.source_id = source_id
        self.batch_size = batch_size
        self._client = client if client is not None else httpx.AsyncClient(timeout=HTTP_TIMEOUT_S)
        self._buf: list[str] = []

    async def send(self, line: str) -> int:
        self._buf.append(line)
        if len(self._buf) >= self.batch_size:
            return await self.flush()
        return 0

    async def flush(self) -> int:
        if not self._buf:
            return 0
        lines, self._buf = self._buf, []
        resp = await self._client.post(self.url, json={"source_id": self.source_id, "lines": lines})
        if resp.status_code != 202:
            print(f"error: http {resp.status_code} from {self.url} "
                  f"({len(lines)} lines dropped)", file=sys.stderr)
            return 0
        try:
            return int(resp.json().get("accepted", len(lines)))
        except Exception:
            return len(lines)  # 202 but unparseable body: trust the transport

    async def close(self) -> None:
        await self._client.aclose()


@dataclass
class Corpus:
    name: str
    lines: list[str]
    sender: object  # UdpSender / HttpSender / test double: async send(line)->int, flush()->int


def load_lines(path: Path) -> list[str]:
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            lines.append(line)
    return lines


def load_corpora(corpus_dir: Path | str, senders: dict) -> list[Corpus]:
    corpus_dir = Path(corpus_dir)
    corpora = []
    for key in CORPUS_KEYS:
        path = corpus_dir / f"raw_logs_{key}.txt"
        if not path.is_file():
            print(f"warning: corpus file missing, skipping: {path}", file=sys.stderr)
            continue
        sender = senders.get(key)
        if sender is None:
            print(f"warning: no sender wired for corpus {key!r}, skipping", file=sys.stderr)
            continue
        lines = load_lines(path)
        if not lines:
            print(f"warning: corpus {key!r} has no lines, skipping", file=sys.stderr)
            continue
        corpora.append(Corpus(name=key, lines=lines, sender=sender))
    return corpora


def default_senders() -> dict:
    """Wire every corpus key to its transport per R7, from COLLECTOR_UDP / COLLECTOR_HTTP."""
    udp_addr = parse_udp_addr(os.environ.get("COLLECTOR_UDP", "localhost:5514"))
    http_base = os.environ.get("COLLECTOR_HTTP", DEFAULT_HTTP_BASE)
    udp = UdpSender(udp_addr)
    senders = {key: udp for key in sorted(UDP_KEYS)}
    senders["json"] = HttpSender(http_base)
    return senders


async def run(corpora: list[Corpus], *, eps: float, duration: float,
              loop: bool = False) -> tuple[dict, int]:
    """Send the corpora round-robin at eps total events/sec.

    Returns (sent_per_corpus, error_count). A send counts only when the
    transport accepted it (UDP sendto returned; HTTP got a 202).
    """
    sent = {c.name: 0 for c in corpora}
    errors = 0
    n = len(corpora)
    if n == 0 or eps <= 0:
        return sent, errors

    tick = n / eps  # one round-robin pass per tick; n events per pass -> eps total
    start = time.monotonic()
    deadline = start + max(duration, 0.0)
    cursors = [0] * n

    pass_no = 0
    while True:
        if loop and time.monotonic() >= deadline:
            break
        if not loop and all(cursors[i] >= len(corpora[i].lines) for i in range(n)):
            break
        for i, corpus in enumerate(corpora):
            if cursors[i] >= len(corpus.lines):
                if not loop:
                    continue
                cursors[i] = 0
            line = corpus.lines[cursors[i]]
            cursors[i] += 1
            try:
                sent[corpus.name] += await corpus.sender.send(line)
            except Exception as exc:
                errors += 1
                print(f"error: {corpus.name}: {exc}", file=sys.stderr)
        pass_no += 1
        delay = start + pass_no * tick - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)

    # Drain sender-side buffers (HTTP batches) so nothing simulated is silently dropped.
    for corpus in corpora:
        try:
            sent[corpus.name] += await corpus.sender.flush()
        except Exception as exc:
            errors += 1
            print(f"error: {corpus.name} flush: {exc}", file=sys.stderr)
    return sent, errors


async def _close_all(senders: dict) -> None:
    for sender in senders.values():
        result = sender.close()
        if inspect.isawaitable(result):
            await result


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="simulate.py",
        description="Replay the golden corpora against the collector at a steady rate.")
    p.add_argument("--eps", type=float, default=20.0,
                   help="total events/sec across all corpora (default 20)")
    p.add_argument("--duration", type=float, default=60.0,
                   help="seconds to run when --loop is set (default 60)")
    p.add_argument("--corpora", default=None,
                   help="directory holding raw_logs_*.txt (default: simulator/data)")
    p.add_argument("--loop", action="store_true",
                   help="repeat the corpora until --duration elapses")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.eps <= 0:
        print(f"error: --eps must be > 0 (got {args.eps})", file=sys.stderr)
        return 1
    corpus_dir = Path(args.corpora) if args.corpora else Path(__file__).resolve().parent / "data"

    try:
        senders = default_senders()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    corpora = load_corpora(corpus_dir, senders)
    if not corpora:
        print(f"error: no corpora found in {corpus_dir}", file=sys.stderr)
        asyncio.run(_close_all(senders))
        return 1

    async def drive():
        try:
            return await run(corpora, eps=args.eps, duration=args.duration, loop=args.loop)
        finally:
            await _close_all(senders)

    sent, errors = asyncio.run(drive())

    for name in sorted(sent):
        print(f"{name} sent={sent[name]}")
    total = sum(sent.values())
    print(f"total sent={total}")

    if total == 0 and errors > 0:
        print(f"error: all {errors} sends failed; is the collector up?", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
