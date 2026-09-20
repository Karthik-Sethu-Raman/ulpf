# simulator/simulate.py — multi-vendor traffic simulator over the frozen golden corpora.
#
# Routes each corpus to the transport the collector expects (R7):
#   cef/syslog/acmegw/newapp -> UDP datagrams, one log line each, no envelope (the
#                        collector derives source_id from the peer address, so
#                        there is nothing to tag on the wire);
#   json              -> batched HTTP POSTs to /v1/ingest, source_id "ids01"
#                        (that field IS the raw.logs message key).
#
# Pacing: --eps is the TOTAL event rate, distributed evenly across the corpora
# found on disk; corpora are interleaved round-robin, one line per corpus per
# tick. --loop repeats the corpora until --duration elapses; without it, each
# corpus is sent once through (still paced), then the run ends. --duration is a
# hard budget in both modes: no send may start after the deadline, checked
# between passes AND mid-pass.
#
# Modes (T10): "steady" replays only the M1 golden corpora. "new-appliance"
# additionally loads the newapp corpus (an unknown proprietary format for the
# M2 onboarding loop) after --new-after seconds: until then its rotation slot
# is idle — no send, no cursor advance — so the already-running corpora are
# untouched while it waits.
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
from typing import Protocol, runtime_checkable

import httpx

DEFAULT_UDP_ADDR = ("localhost", 5514)
DEFAULT_HTTP_BASE = "http://localhost:8080"
HTTP_SOURCE_ID = "ids01"
HTTP_BATCH_SIZE = 10
HTTP_TIMEOUT_S = 5.0

UDP_KEYS = frozenset({"cef", "syslog", "acmegw", "newapp"})
HTTP_KEYS = frozenset({"json"})
CORPUS_KEYS = sorted(UDP_KEYS | HTTP_KEYS)
NEWAPP_KEY = "newapp"  # loaded only in --mode new-appliance (see load_corpora)


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
        except Exception:  # noqa: BLE001 - any 202-body failure still trusts the transport
            return len(lines)  # 202 but unparseable body: trust the transport

    async def close(self) -> None:
        await self._client.aclose()


@runtime_checkable
class Sender(Protocol):
    """Anything that can carry corpus lines (structural — no declaration needed).

    UdpSender, HttpSender and the tests' fakes all qualify by shape:
    async send(line)->int, flush()->int. close() is intentionally not part of
    the protocol: it is sync on UdpSender, async on HttpSender, and _close_all
    already handles both.
    """

    async def send(self, line: str) -> int: ...
    async def flush(self) -> int: ...


@dataclass
class Corpus:
    name: str
    lines: list[str]
    sender: Sender
    start_at: float = 0.0  # seconds from run start before this corpus joins the rotation


def load_lines(path: Path) -> list[str]:
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            lines.append(line)
    return lines


def load_corpora(corpus_dir: Path | str, senders: dict,
                 include_newapp: bool = False) -> list[Corpus]:
    """Load raw_logs_<key>.txt per corpus key; default (steady) excludes newapp.

    include_newapp=True is --mode new-appliance: the unknown-format corpus
    joins the load so onboarding can meet a format it has no rule for. The
    default keeps the M1 smoke's stdout contract byte-identical.
    """
    corpus_dir = Path(corpus_dir)
    corpora = []
    for key in CORPUS_KEYS:
        if key == NEWAPP_KEY and not include_newapp:
            continue  # steady mode: the unknown appliance stays off the wire
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

    A corpus with start_at > 0 stays idle (no send, no cursor advance) until
    that many seconds have elapsed, then joins the rotation in place.

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
        if time.monotonic() >= deadline:  # hard budget in loop AND one-shot mode
            break
        if not loop and all(cursors[i] >= len(corpora[i].lines) for i in range(n)):
            break
        stopped = False
        for i, corpus in enumerate(corpora):
            if time.monotonic() >= deadline:
                stopped = True  # mid-pass: a pass that would overrun stops here
                break
            if time.monotonic() - start < corpus.start_at:
                continue  # not yet due (start_at): its slot is idle this pass
            if cursors[i] >= len(corpus.lines):
                if not loop:
                    continue
                cursors[i] = 0
            line = corpus.lines[cursors[i]]
            cursors[i] += 1
            try:
                sent[corpus.name] += await corpus.sender.send(line)
            except Exception as exc:  # noqa: BLE001 - one failed send counts and moves on
                errors += 1
                print(f"error: {corpus.name}: {exc}", file=sys.stderr)
        if stopped:
            break
        pass_no += 1
        delay = start + pass_no * tick - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)

    # Drain sender-side buffers (HTTP batches) so nothing simulated is silently dropped.
    for corpus in corpora:
        try:
            sent[corpus.name] += await corpus.sender.flush()
        except Exception as exc:  # noqa: BLE001 - a failed flush counts and moves on
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
                   help="seconds before the run is cut off (hard budget in both "
                        "modes; --loop repeats until then) (default 60)")
    p.add_argument("--corpora", default=None,
                   help="directory holding raw_logs_*.txt (default: simulator/data)")
    p.add_argument("--loop", action="store_true",
                   help="repeat the corpora until --duration elapses")
    p.add_argument("--mode", choices=("steady", "new-appliance"), default="steady",
                   help="steady: golden corpora only (default); new-appliance: "
                        "also replay the unknown-format newapp corpus (T10)")
    p.add_argument("--new-after", type=float, default=0.0, dest="new_after",
                   help="new-appliance only: seconds before the newapp corpus "
                        "joins the rotation (default 0; steady ignores this)")
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

    include_newapp = args.mode == "new-appliance"
    corpora = load_corpora(corpus_dir, senders, include_newapp=include_newapp)
    if not corpora:
        print(f"error: no corpora found in {corpus_dir}", file=sys.stderr)
        asyncio.run(_close_all(senders))
        return 1
    for corpus in corpora:
        if corpus.name == NEWAPP_KEY:
            corpus.start_at = max(args.new_after, 0.0)

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
