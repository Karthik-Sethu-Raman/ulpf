# simulator/tests/test_simulate.py — simulator unit tests (fake senders, no network).
# Routing, source tagging (R7: HTTP only), pacing floor, round-robin order, exit codes.
import asyncio
import json as jsonlib
import re
import time

import httpx
import pytest

from simulator.simulate import (
    HTTP_SOURCE_ID,
    Corpus,
    HttpSender,
    Sender,
    UdpSender,
    default_senders,
    load_corpora,
    main,
    run,
    transport_for,
)

# --- fakes (capture destination + payload; no sockets, no collector) -----------

class FakeSock:
    def __init__(self):
        self.sent = []  # (payload_bytes, addr)

    def sendto(self, data, addr):
        self.sent.append((data, addr))


class FakeUdp:
    """Stands in for UdpSender; records every line in a shared event log."""

    def __init__(self, name, log, fail_every=0):
        self.name = name
        self.log = log
        self.fail_every = fail_every
        self.lines = []
        self.calls = 0

    async def send(self, line):
        self.calls += 1
        if self.fail_every and self.calls % self.fail_every == 0:
            raise OSError("udp send failed")
        self.lines.append(line)
        self.log.append((self.name, line))
        return 1

    async def flush(self):
        return 0

    def close(self):
        pass


class FakeHttp:
    """Stands in for HttpSender; behaves like it (buffer, flush on demand)."""

    def __init__(self, name, log, batch_size=10, status=202):
        self.name = name
        self.log = log
        self.batch_size = batch_size
        self.status = status
        self.batches = []  # list of posted line-lists
        self.buf = []

    async def send(self, line):
        self.buf.append(line)
        if len(self.buf) >= self.batch_size:
            return await self.flush()
        return 0

    async def flush(self):
        if not self.buf:
            return 0
        lines, self.buf = self.buf, []
        if self.status != 202:
            self.log.append((self.name, f"ERROR:{self.status}"))
            return 0
        self.batches.append(lines)
        for line in lines:
            self.log.append((self.name, line))
        return len(lines)

    async def close(self):
        pass


def make_corpora(dir, contents):
    for name, text in contents.items():
        (dir / f"raw_logs_{name}.txt").write_text(text, encoding="utf-8")


def do_run(corpora, **kw):
    return asyncio.run(run(corpora, **kw))


# --- routing table -------------------------------------------------------------

def test_transport_routing_table():
    assert transport_for("cef") == "udp"
    assert transport_for("syslog") == "udp"
    assert transport_for("acmegw") == "udp"
    assert transport_for("newapp") == "udp"
    assert transport_for("json") == "http"
    with pytest.raises(ValueError):
        transport_for("zenwall")


# --- UDP sender: raw datagram, no envelope (R7: no source tagging on UDP) ------

def test_udp_sender_sends_raw_line_to_destination():
    sock = FakeSock()
    sender = UdpSender(("10.9.9.9", 5514), sock=sock)
    line = "CEF:0|PaloAlto|PAN-OS|10.1|THREAT|spyware|5|src=203.0.113.45"
    sent = asyncio.run(sender.send(line))
    assert sent == 1
    payload, addr = sock.sent[0]
    assert addr == ("10.9.9.9", 5514)
    # R7: the datagram IS the log line — no JSON envelope, no source_id field.
    assert payload == line.encode("utf-8")
    assert b"source_id" not in payload
    assert b"fw01" not in payload


def test_udp_sender_socket_is_lazy_and_close_is_idempotent():
    sender = UdpSender(("localhost", 5514))  # no socket created yet
    sender.close()  # must not raise
    assert sender._sock is None


# --- HTTP sender: source tagging ids01, batching, 202-gated counting -----------

def test_http_sender_posts_batches_tagged_ids01_in_order():
    reqs = []

    def handler(request: httpx.Request) -> httpx.Response:
        reqs.append(request)
        body = jsonlib.loads(request.read())
        return httpx.Response(202, json={"accepted": len(body["lines"])})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    sender = HttpSender("http://collector:8080/", batch_size=2, client=client)
    lines = ['{"a":1}', '{"a":2}', '{"a":3}']

    async def drive():
        n1 = await sender.send(lines[0])
        n2 = await sender.send(lines[1])   # batch_size=2 -> flush here
        await sender.send(lines[2])        # buffers the third line
        n3 = await sender.flush()          # drains it as a second POST
        await sender.close()
        return n1, n2, n3

    n1, n2, n3 = asyncio.run(drive())
    assert (n1, n2, n3) == (0, 2, 1)
    assert len(reqs) == 2
    first = reqs[0]
    assert str(first.url) == "http://collector:8080/v1/ingest"
    assert first.method == "POST"
    body = jsonlib.loads(first.read())
    assert body["source_id"] == HTTP_SOURCE_ID == "ids01"
    assert body["lines"] == ['{"a":1}', '{"a":2}']  # order preserved
    assert jsonlib.loads(reqs[1].read())["lines"] == ['{"a":3}']


def test_http_sender_counts_only_on_202():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    sender = HttpSender("http://collector:8080", batch_size=1, client=client)

    async def drive():
        n = 0
        n += await sender.send('{"a":1}')
        n += await sender.send('{"a":2}')
        await sender.close()
        return n

    assert asyncio.run(drive()) == 0  # failures counted nowhere


def test_http_sender_default_endpoint_and_batch_size():
    sender = HttpSender("http://collector:8080")
    assert sender.url == "http://collector:8080/v1/ingest"
    assert sender.batch_size == 10
    assert sender.source_id == "ids01"


# --- load_corpora ----------------------------------------------------------------

def test_load_corpora_reads_files_binds_senders_skips_missing(tmp_path, capsys):
    make_corpora(tmp_path, {"cef": "c1\nc2\n", "json": 'j1\nj2\n'})
    senders = {"cef": FakeUdp("cef", []), "json": FakeHttp("json", [])}
    corpora = load_corpora(tmp_path, senders)
    assert [c.name for c in corpora] == ["cef", "json"]
    assert corpora[0].lines == ["c1", "c2"]
    assert corpora[1].sender is senders["json"]
    # no syslog/acmegw files -> skipped with a stderr note, not an error
    assert "syslog" in capsys.readouterr().err


def test_load_corpora_skips_blank_lines(tmp_path):
    make_corpora(tmp_path, {"cef": "c1\n\n   \nc2\n"})
    corpora = load_corpora(tmp_path, {"cef": FakeUdp("cef", [])})
    assert corpora[0].lines == ["c1", "c2"]


def test_load_corpora_empty_dir_is_no_corpora(tmp_path):
    assert load_corpora(tmp_path, {}) == []


# --- load_corpora: newapp corpus is gated behind include_newapp (T10) ------------

def test_load_corpora_steady_excludes_newapp_new_appliance_includes(tmp_path):
    make_corpora(tmp_path, {"cef": "c1\n", "newapp": "n1\nn2\n"})
    senders = {"cef": FakeUdp("cef", []), "newapp": FakeUdp("newapp", [])}
    steady = load_corpora(tmp_path, senders)  # default: steady mode
    assert [c.name for c in steady] == ["cef"]
    with_newapp = load_corpora(tmp_path, senders, include_newapp=True)
    assert [c.name for c in with_newapp] == ["cef", "newapp"]
    assert with_newapp[1].lines == ["n1", "n2"]
    assert with_newapp[1].start_at == 0.0  # default joins immediately


# --- run(): pacing floor, round-robin, loop --------------------------------------

def udp_corpus(name, lines, log):
    return Corpus(name=name, lines=list(lines), sender=FakeUdp(name, log))


def test_pacing_floor_eps4_duration1_at_least_4_sends():
    log = []
    corpora = [
        udp_corpus("acmegw", ["a1", "a2", "a3"], log),
        udp_corpus("cef", ["c1", "c2", "c3"], log),
        udp_corpus("json", ["j1", "j2", "j3"], log),
        udp_corpus("syslog", ["s1", "s2", "s3"], log),
    ]
    t0 = time.monotonic()
    sent, errors = do_run(corpora, eps=4, duration=1, loop=True)
    elapsed = time.monotonic() - t0
    assert sum(sent.values()) >= 4  # brief: eps=4, duration=1 -> >=4 sends
    assert errors == 0
    assert elapsed < 5  # sanity: did not hang


def test_round_robin_interleaves_corpora_until_exhausted():
    log = []
    corpora = [
        udp_corpus("cef", ["c1", "c2", "c3"], log),
        udp_corpus("syslog", ["s1", "s2"], log),
        udp_corpus("acmegw", ["a1"], log),
    ]
    sent, errors = do_run(corpora, eps=100, duration=1, loop=False)
    assert errors == 0
    # one pass sends one line per corpus in list order; shorter corpora drop out
    assert [name for name, _ in log] == [
        "cef", "syslog", "acmegw",  # pass 0
        "cef", "syslog",            # pass 1
        "cef",                      # pass 2
    ]
    assert [line for _, line in log] == ["c1", "s1", "a1", "c2", "s2", "c3"]
    assert sent == {"cef": 3, "syslog": 2, "acmegw": 1}


def test_loop_repeats_corpora_until_duration_elapses():
    log = []
    corpora = [udp_corpus("cef", ["c1", "c2"], log)]
    sent, errors = do_run(corpora, eps=50, duration=0.25, loop=True)
    assert errors == 0
    assert sent["cef"] > 2  # wrapped past the end at least once
    assert log[0] == ("cef", "c1") and log[1] == ("cef", "c2")
    assert log[2] == ("cef", "c1")  # restarts from the top


def test_run_counts_send_failures_as_errors_not_sends():
    log = []
    flaky = FakeUdp("cef", log, fail_every=2)  # every 2nd send raises
    sent, errors = do_run([Corpus("cef", ["c1", "c2", "c3", "c4"], flaky)],
                          eps=100, duration=1, loop=False)
    assert sent == {"cef": 2}
    assert errors == 2


def test_run_json_goes_to_http_sender_only():
    log = []
    http = FakeHttp("json", log, batch_size=100)
    udp = FakeUdp("cef", log)
    sent, errors = do_run(
        [Corpus("cef", ["c1"], udp), Corpus("json", ["j1", "j2"], http)],
        eps=100, duration=1, loop=False,
    )
    assert errors == 0
    assert sent == {"cef": 1, "json": 2}
    assert http.batches == [["j1", "j2"]]  # one POST at final flush
    assert [name for name, _ in log] == ["cef", "json", "json"]


# --- Sender protocol (T11): Corpus.sender is typed, not just "object" -----------

def test_sender_protocol_accepts_transport_and_test_doubles():
    assert isinstance(UdpSender(("localhost", 5514)), Sender)
    assert isinstance(FakeUdp("x", []), Sender)
    assert isinstance(FakeHttp("x", []), Sender)
    assert not isinstance(object(), Sender)  # no send/flush -> not a Sender


# --- start_at: a corpus joins the rotation only once it is due (T10-a) ----------

def test_newapp_joins_rotation_only_after_start_at():
    log = []
    corpora = [
        udp_corpus("cef", [f"c{i}" for i in range(20)], log),
        udp_corpus("newapp", ["n1", "n2", "n3"], log),
    ]
    corpora[1].start_at = 0.1  # seconds from run start
    sent, errors = do_run(corpora, eps=100, duration=0.5, loop=True)
    assert errors == 0
    # tick = 2/100 = 0.02s; newapp must stay silent for ~5 passes. If start_at
    # were ignored it would send on pass 0 and first_newapp would be 1.
    first_newapp = log.index(("newapp", "n1"))
    assert first_newapp >= 3
    assert all(name == "cef" for name, _ in log[:first_newapp])  # nothing advanced early
    assert sent["newapp"] >= 1  # it did eventually join the rotation


def test_unstarted_corpus_does_not_block_nonloop_termination():
    # Non-loop: steady corpora exhaust while newapp waits; the run must keep
    # ticking until start_at elapses, send newapp once, then end (not hang).
    log = []
    corpora = [
        udp_corpus("cef", ["c1", "c2"], log),
        udp_corpus("newapp", ["n1"], log),
    ]
    corpora[1].start_at = 0.15
    sent, errors = do_run(corpora, eps=20, duration=5, loop=False)
    assert errors == 0
    assert sent == {"cef": 2, "newapp": 1}


# --- mid-pass deadline (T11): duration bounds sends even within one pass ---------

class SlowUdp(FakeUdp):
    """FakeUdp whose send takes real time, so a single pass can overrun."""

    def __init__(self, name, log, delay):
        super().__init__(name, log)
        self.delay = delay
        self.starts = []  # monotonic timestamp just before each send began

    async def send(self, line):
        self.starts.append(time.monotonic())
        await asyncio.sleep(self.delay)
        return await super().send(line)


def test_midpass_deadline_stops_sends_at_boundary():
    log = []
    senders = [SlowUdp(name, log, 0.03) for name in ("a", "b", "c")]
    corpora = [Corpus(name, ["x1", "x2", "x3"], s) for name, s in zip(("a", "b", "c"), senders)]
    # 3 sends/pass * 0.03s -> pass 0 ends ~0.09s; duration 0.1 elapses DURING
    # pass 1. Only the mid-pass check stops pass 1 at the boundary (4 sends);
    # a top-of-pass-only check would let the whole pass run (6 sends).
    t0 = time.monotonic()
    sent, errors = do_run(corpora, eps=10, duration=0.1, loop=False)
    assert errors == 0
    total = sum(sent.values())
    assert 3 <= total <= 4  # boundary cut inside pass 1, not a full extra pass
    for s in senders:
        for start in s.starts:  # no send may START after the deadline
            assert start - t0 <= 0.12


# --- pacing ceiling: eps*duration bounds the total from ABOVE too (T11) ----------

def test_pacing_ceiling_eps4_duration1_sends_do_not_overrun():
    log = []
    corpora = [
        udp_corpus("acmegw", ["a1", "a2", "a3"], log),
        udp_corpus("cef", ["c1", "c2", "c3"], log),
        udp_corpus("json", ["j1", "j2", "j3"], log),
        udp_corpus("syslog", ["s1", "s2", "s3"], log),
    ]
    sent, errors = do_run(corpora, eps=4, duration=1, loop=True)
    assert errors == 0
    # tick = 1s: pass 0 (4 sends) then sleep past the deadline. Jitter may add
    # a partial pass, but unbounded (no pacing sleep) would send thousands.
    assert sum(sent.values()) <= 12


# --- main(): stdout contract, exit codes, env wiring ------------------------------

def test_main_prints_one_summary_line_per_corpus_plus_total(tmp_path, capsys, monkeypatch):
    make_corpora(tmp_path, {"cef": "c1\nc2\n", "json": "j1\n"})
    log = []
    monkeypatch.setattr(
        "simulator.simulate.default_senders",
        lambda: {"cef": FakeUdp("cef", log), "json": FakeHttp("json", log, batch_size=10)},
    )
    rc = main(["--eps", "100", "--duration", "1", "--corpora", str(tmp_path)])
    out = capsys.readouterr().out.strip().splitlines()
    assert rc == 0
    assert out == ["cef sent=2", "json sent=1", "total sent=3"]
    for line in out:
        assert re.fullmatch(r"(?:\S+ sent=\d+|total sent=\d+)", line)


def test_main_exit_1_when_no_corpora(tmp_path, capsys):
    rc = main(["--eps", "10", "--duration", "1", "--corpora", str(tmp_path)])
    assert rc == 1
    assert "no corpora" in capsys.readouterr().err


# --- main(): --mode wiring (T10) ---------------------------------------------------

def test_main_steady_omits_newapp_line(tmp_path, capsys, monkeypatch):
    make_corpora(tmp_path, {"cef": "c1\n", "newapp": "n1\n"})
    log = []
    monkeypatch.setattr(
        "simulator.simulate.default_senders",
        lambda: {"cef": FakeUdp("cef", log), "newapp": FakeUdp("newapp", log)},
    )
    rc = main(["--eps", "100", "--duration", "1", "--corpora", str(tmp_path)])
    out = capsys.readouterr().out.strip().splitlines()
    assert rc == 0
    assert out == ["cef sent=1", "total sent=1"]  # M1 contract: no newapp line


def test_main_steady_ignores_new_after_flag(tmp_path, capsys, monkeypatch):
    make_corpora(tmp_path, {"cef": "c1\nc2\n"})
    log = []
    monkeypatch.setattr("simulator.simulate.default_senders",
                        lambda: {"cef": FakeUdp("cef", log)})
    rc = main(["--eps", "100", "--duration", "1", "--new-after", "999",
               "--corpora", str(tmp_path)])
    out = capsys.readouterr().out.strip().splitlines()
    assert rc == 0
    assert out == ["cef sent=2", "total sent=2"]


def test_main_new_appliance_prints_newapp_line(tmp_path, capsys, monkeypatch):
    make_corpora(tmp_path, {"cef": "c1\nc2\n", "newapp": "n1\nn2\n"})
    log = []
    monkeypatch.setattr(
        "simulator.simulate.default_senders",
        lambda: {"cef": FakeUdp("cef", log), "newapp": FakeUdp("newapp", log)},
    )
    rc = main(["--eps", "100", "--duration", "1", "--mode", "new-appliance",
               "--corpora", str(tmp_path)])
    out = capsys.readouterr().out.strip().splitlines()
    assert rc == 0
    assert out == ["cef sent=2", "newapp sent=2", "total sent=4"]


def test_main_new_appliance_delays_newapp_until_new_after(tmp_path, capsys, monkeypatch):
    make_corpora(tmp_path, {"cef": "c1\nc2\nc3\nc4\nc5\n", "newapp": "n1\n"})
    log = []
    monkeypatch.setattr(
        "simulator.simulate.default_senders",
        lambda: {"cef": FakeUdp("cef", log), "newapp": FakeUdp("newapp", log)},
    )
    rc = main(["--eps", "40", "--duration", "2", "--mode", "new-appliance",
               "--new-after", "0.15", "--loop", "--corpora", str(tmp_path)])
    out = capsys.readouterr().out.strip().splitlines()
    assert rc == 0
    assert "newapp sent=" in out[-2]  # per-corpus line for newapp, then total
    # tick = 2/40 = 0.05s; newapp must join only after ~3 ticks
    first_newapp = log.index(("newapp", "n1"))
    assert first_newapp >= 3
    assert all(name == "cef" for name, _ in log[:first_newapp])


def test_main_exit_1_on_total_send_failure_but_still_prints_summary(tmp_path, capsys, monkeypatch):
    make_corpora(tmp_path, {"cef": "c1\n"})

    class DeadUdp(FakeUdp):
        async def send(self, line):
            raise OSError("cannot resolve collector")

    monkeypatch.setattr("simulator.simulate.default_senders",
                        lambda: {"cef": DeadUdp("cef", [])})
    rc = main(["--eps", "10", "--duration", "1", "--corpora", str(tmp_path)])
    out = capsys.readouterr()
    assert rc == 1
    assert "cef sent=0" in out.out and "total sent=0" in out.out
    assert "cannot resolve collector" in out.err


def test_main_exit_0_on_partial_send_failure(tmp_path, capsys, monkeypatch):
    make_corpora(tmp_path, {"cef": "c1\nc2\n"})
    monkeypatch.setattr("simulator.simulate.default_senders",
                        lambda: {"cef": FakeUdp("cef", [], fail_every=2)})
    rc = main(["--eps", "100", "--duration", "1", "--corpora", str(tmp_path)])
    out = capsys.readouterr()
    assert rc == 0
    assert "cef sent=1" in out.out and "total sent=1" in out.out


def test_default_senders_reads_env(monkeypatch):
    monkeypatch.setenv("COLLECTOR_UDP", "collector-host:5999")
    monkeypatch.setenv("COLLECTOR_HTTP", "http://collector-host:9999")
    senders = default_senders()
    assert set(senders) == {"cef", "newapp", "syslog", "acmegw", "json"}
    assert senders["cef"].addr == ("collector-host", 5999)
    assert senders["json"].url == "http://collector-host:9999/v1/ingest"
    for s in senders.values():
        if isinstance(s, UdpSender):
            s.close()  # UDP sockets are lazy; HTTP clients close via gc (no request made)


def test_default_senders_env_defaults(monkeypatch):
    monkeypatch.delenv("COLLECTOR_UDP", raising=False)
    monkeypatch.delenv("COLLECTOR_HTTP", raising=False)
    senders = default_senders()
    assert senders["cef"].addr == ("localhost", 5514)
    assert senders["json"].url == "http://localhost:8080/v1/ingest"
